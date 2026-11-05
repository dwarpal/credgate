"""The policy editor's logic, apart from Shiny so it can be tested on its
own: roles and tabs, the signed-in user, validation, the detector form."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any

import regex
import yaml

from ..policy import Policy
from ..users import read_users

# The tabs each role sees. Without a users file everyone is an admin.
TABS: dict[str, tuple[str, ...]] = {
    "admin": (
        "Endpoints", "Rules", "Try it", "Tests", "Detectors",
        "My key", "My activity", "Users", "Changes",
    ),
    "auditor": ("Endpoints", "Rules", "Tests", "My key", "My activity", "Users", "Changes"),
    "user": ("Try it", "Tests", "Detectors", "My key", "My activity", "Changes"),
}  # fmt: skip
KEY_DURATIONS: dict[str, int] = {"1 month": 30, "3 months": 90, "6 months": 180}
ROLE_NOTES = {
    "admin": "can change the policy",
    "auditor": "read-only: sees everything, changes nothing",
    "user": "read-only: tries the saved policy",
}
WHEN_KEYS = ("destinations", "tiers", "types", "classes", "all_of")
TIERS = ("local", "internal", "frontier")
ACTIONS = ("allow", "redact", "tokenise", "block")
_NAME = re.compile(r"[A-Za-z0-9._@-]{1,100}")
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml")
_REGEX_SPECIAL = re.compile(r"([\\^$.|?*+()\[\]{}])")

DETECTORS_TEMPLATE = """kind: credgate-detectors
version: 1
detectors:
  - id: loan_account
    class: financial
    label: Loan account number
    patterns: ['LN[0-9]{10}']
    bounded: true
    context: 'loan|\\ba/c\\b'
    base: 0.6
    base_without_context: 0.4
    examples:
      match: ['Loan a/c LN0012345678']
      no_match: ['LN00123']
"""


def asset(name: str) -> Path:
    """A file shipped with the editor (styles, script, example policy)."""
    return Path(str(files("credgate.editor") / "assets" / name))


def editor_role(users: str | os.PathLike[str] | None, name: str | None) -> str | None:
    """The role of a signed-in name, or None (no access). Without a users
    file everyone is an admin; an invalid file lets no one in."""
    if users is None:
        return "admin"
    try:
        return read_users(users).role_of(name)
    except (OSError, ValueError):
        return None


def header_user(headers: Mapping[str, str] | None, header: str | None) -> str | None:
    """The signed-in user from a sign-in proxy's header, or None if the
    header is not set or is not a valid name."""
    if header is None or headers is None:
        return None
    value = headers.get(header) or headers.get(header.lower())
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _NAME.fullmatch(value) else None


def read_draft(path: str | os.PathLike[str]) -> dict[str, Any]:
    """The policy file as a plain mapping, or the example bank policy when
    the file does not exist yet."""
    p = Path(path)
    source = p if p.exists() else asset("bank-default.yaml")
    data = yaml.safe_load(source.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def policy_problem(draft: Mapping[str, Any], base: str | os.PathLike[str]) -> str | None:
    """Why a draft is not valid (the same strict check the proxy makes), or
    None when it is valid."""
    try:
        Policy.from_dict(draft, base=base)
    except Exception as e:
        return str(e)
    return None


def rename_destination(rule: dict[str, Any], old: str, new: str) -> dict[str, Any]:
    """A rule with an endpoint renamed in its conditions."""
    when = rule.get("when") or {}
    names = when.get("destinations")
    if isinstance(names, list) and old in names:
        rule = {**rule, "when": {**when, "destinations": [new if n == old else n for n in names]}}
    return rule


def detector_from_form(
    id: str,
    data_class: str,
    label: str,
    pattern: str,
    keywords: str,
    required: bool,
    match: str,
    no_match: str,
) -> dict[str, Any] | str:
    """A custom detector definition from the workbench form, or a message
    saying what is missing (the same rules as the R editor)."""
    id = (id or "").strip()
    pattern = (pattern or "").strip()
    if not re.fullmatch(r"[a-z][a-z0-9_]*", id):
        return (
            "Give an id in lower-case letters, digits and _, starting with a letter, "
            "e.g. loan_account."
        )
    if not pattern:
        return "Give a pattern, e.g. LN[0-9]{10}."
    try:
        regex.compile(pattern)
    except regex.error:
        return "The pattern is not a valid regular expression."
    words = [w.strip() for w in (keywords or "").split(",") if w.strip()]
    if required and not words:
        return 'Give at least one keyword, or untick "only with a keyword nearby".'
    det: dict[str, Any] = {
        "id": id,
        "class": data_class,
        "label": (label or "").strip() or id,
        "patterns": [pattern],
        "bounded": True,
    }
    if words:
        det["context"] = "|".join(_REGEX_SPECIAL.sub(r"\\\1", w) for w in words)
        if required:
            det["context_required"] = True
            det["base"] = 0.5
        else:
            det["base"] = 0.6
            det["base_without_context"] = 0.4
    else:
        det["base"] = 0.6

    def lines(x: str) -> list[str]:
        return [t.strip() for t in (x or "").split("\n") if t.strip()]

    examples = {k: v for k, v in (("match", lines(match)), ("no_match", lines(no_match))) if v}
    if examples:
        det["examples"] = examples
    return det


def detectors_yaml(data: Mapping[str, Any]) -> str:
    """A custom detectors file as YAML."""
    return yaml.safe_dump(dict(data), sort_keys=False, allow_unicode=True, width=1000)


def new_detectors_file_name(name: str) -> str | None:
    """A new detectors file name if it is a plain YAML file name (no folders)."""
    name = (name or "").strip()
    return name if _FILE_NAME.fullmatch(name) else None


def detector_path(policy_file: str | os.PathLike[str], name: str) -> Path:
    """A detectors file named in a policy, relative to the policy's folder."""
    p = Path(name).expanduser()
    return p if p.is_absolute() else Path(policy_file).parent / p
