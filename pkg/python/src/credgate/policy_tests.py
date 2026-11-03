"""Policy tests (spec/README.md, "Policy tests").

Sample requests and what a policy must do with them, kept beside the
policy and run whenever it changes - in the policy editor before saving and
with ``credgate policy test`` in CI.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .policy import ACTIONS, Policy
from .tokenise import Vault

KIND = "credgate-policy-tests"
_TEST_FIELDS = {"id", "description", "endpoint", "text", "texts", "expect"}
_EXPECT_FIELDS = {"allowed", "blocked_by", "actions", "absent", "output"}


@dataclass(frozen=True)
class PolicyTestResult:
    """The outcome of one policy test: ``problems`` lists every expectation
    that did not hold (empty when it passed)."""

    id: str
    passed: bool
    problems: tuple[str, ...]
    description: str | None = None


def run_policy_tests(
    policy: Policy | str | os.PathLike[str],
    tests: str | os.PathLike[str] | Mapping[str, Any] | None = None,
) -> list[PolicyTestResult]:
    """Run a policy's tests.

    Args:
        policy: A :class:`Policy`, or a policy file.
        tests: A tests file, or its contents as a mapping. By default the
            file beside the policy file with ``.tests.yaml`` in place of
            ``.yaml`` (``bank-default.tests.yaml``).

    Returns:
        One result per test, in file order.

    Raises:
        ValueError: The tests file is not valid; no test is run.
    """
    if tests is None:
        if isinstance(policy, Policy):
            raise ValueError("Give the tests file when the policy is not a file.")
        tests = tests_path(policy)
    if not isinstance(policy, Policy):
        policy = Policy.load(policy)
    if isinstance(tests, Mapping):
        data: Any = tests
        name = "policy tests"
    else:
        name = str(tests)
        with Path(tests).open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    try:
        cases = _validate(data, set(policy.detector_ids))
    except ValueError as e:
        raise ValueError(f"{name}: {e}") from None
    return [_run(policy, case) for case in cases]


def tests_path(policy_file: str | os.PathLike[str]) -> Path:
    """The tests file kept beside a policy file."""
    p = Path(policy_file)
    stem = p.name[: -len(p.suffix)] if p.suffix in (".yaml", ".yml") else p.name
    return p.with_name(f"{stem}.tests.yaml")


def _validate(data: Any, types: set[str]) -> list[Mapping[str, Any]]:
    if not isinstance(data, Mapping) or data.get("kind") != KIND:
        raise ValueError(f"not a policy tests file: `kind` must be `{KIND}`.")
    unknown = set(data) - {"kind", "version", "tests"}
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}.")
    if data.get("version") != 1:
        raise ValueError("`version` must be 1.")
    tests = data.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ValueError("`tests` must be a non-empty list.")
    seen: set[str] = set()
    for t in tests:
        if not isinstance(t, Mapping):
            raise ValueError("each test must be a mapping.")
        tid = t.get("id")
        if not isinstance(tid, str) or not tid:
            raise ValueError("every test needs an `id`.")
        if tid in seen:
            raise ValueError(f"test `{tid}` appears twice.")
        seen.add(tid)
        where = f"test `{tid}`"
        unknown = set(t) - _TEST_FIELDS
        if unknown:
            raise ValueError(f"{where}: unknown field(s): {', '.join(sorted(unknown))}.")
        if not isinstance(t.get("endpoint"), str):
            raise ValueError(f"{where}: needs an `endpoint`.")
        if ("text" in t) == ("texts" in t):
            raise ValueError(f"{where}: give exactly one of `text` or `texts`.")
        if "text" in t and not isinstance(t["text"], str):
            raise ValueError(f"{where}: `text` must be text.")
        if "texts" in t and not (
            isinstance(t["texts"], list) and all(isinstance(x, str) for x in t["texts"])
        ):
            raise ValueError(f"{where}: `texts` must be a list of texts.")
        e = t.get("expect")
        if not isinstance(e, Mapping):
            raise ValueError(f"{where}: needs `expect`.")
        unknown = set(e) - _EXPECT_FIELDS
        if unknown:
            raise ValueError(
                f"{where}: unknown field(s) in `expect`: {', '.join(sorted(unknown))}."
            )
        if not isinstance(e.get("allowed"), bool):
            raise ValueError(f"{where}: `expect.allowed` must be true or false.")
        for key in ("blocked_by", "absent"):
            if key in e and not (
                isinstance(e[key], list) and all(isinstance(x, str) for x in e[key])
            ):
                raise ValueError(f"{where}: `expect.{key}` must be a list.")
        actions = e.get("actions", {})
        if not isinstance(actions, Mapping):
            raise ValueError(f"{where}: `expect.actions` must map types to actions.")
        for typ in [*actions, *e.get("absent", [])]:
            if typ not in types:
                raise ValueError(f"{where}: unknown type `{typ}`.")
        for typ, action in actions.items():
            if action not in ACTIONS:
                raise ValueError(
                    f"{where}: `{typ}`: unknown action `{action}`; "
                    f"actions are {', '.join(ACTIONS)}."
                )
        if "output" in e:
            out = e["output"]
            ok = (
                isinstance(out, str)
                if "text" in t
                else (isinstance(out, list) and all(isinstance(x, str) for x in out))
            )
            if not ok:
                raise ValueError(
                    f"{where}: `expect.output` must be a text for `text`, a list for `texts`."
                )
    return tests


def _run(policy: Policy, t: Mapping[str, Any]) -> PolicyTestResult:
    e = t["expect"]
    problems: list[str] = []
    texts = [t["text"]] if "text" in t else list(t["texts"])
    if t["endpoint"] not in policy.destinations:
        problems.append(f"unknown endpoint `{t['endpoint']}` (not in the policy)")
    else:
        d = policy.apply(texts, t["endpoint"], vault=Vault())
        if d.allowed != e["allowed"]:
            problems.append(
                f"allowed: expected {str(e['allowed']).lower()}, got {str(d.allowed).lower()}"
            )
        if "blocked_by" in e and sorted(d.blocked_by) != sorted(e["blocked_by"]):
            problems.append(
                f"blocked_by: expected {', '.join(sorted(e['blocked_by'])) or 'none'}, "
                f"got {', '.join(sorted(d.blocked_by)) or 'none'}"
            )
        by_type: dict[str, list[str]] = {}
        for m in d.matches:
            by_type.setdefault(m.span.type, []).append(m.action)
        for typ, action in (e.get("actions") or {}).items():
            got = by_type.get(typ)
            if not got:
                problems.append(f"{typ}: expected {action}, not found")
            elif any(a != action for a in got):
                problems.append(f"{typ}: expected {action}, got {', '.join(sorted(set(got)))}")
        for typ in e.get("absent", []):
            if typ in by_type:
                problems.append(f"{typ}: expected absent, found")
        if "output" in e:
            want = [e["output"]] if "text" in t else list(e["output"])
            if not d.allowed:
                problems.append("output: expected texts, but the request was blocked")
            elif d.texts != want:
                got_out = d.texts[0] if "text" in t else d.texts
                problems.append(f"output: expected {e['output']!r}, got {got_out!r}")
    return PolicyTestResult(t["id"], not problems, tuple(problems), t.get("description"))
