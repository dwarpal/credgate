"""Save a policy, see what changed, and read its change log.

The same as R's ``policy_write()``, ``policy_diff()`` and
``policy_changes()``: the policy file is written in a fixed layout, and each
save appends a hash-chained record to ``<policy name>.changes.jsonl`` beside
it, so the R and Python policy editors can work on the same files (see the
spec, "Policy files and change log").
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .policy import _parse

_GENESIS = "0" * 64
_WHEN_KEYS = ("destinations", "tiers", "types", "classes", "all_of")
_PLAIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./:-]*")
_YAML_WORDS = frozenset({"true", "false", "yes", "no", "null", "on", "off"})


@dataclass(frozen=True)
class PolicyChange:
    """One save in a policy's change log."""

    time: str
    user: str
    policy: str
    revision: int
    note: str = ""
    changes: tuple[str, ...] = ()
    from_revision: int | None = None


@dataclass(frozen=True)
class PolicyChanges:
    """A policy's change log: the saves, oldest first, and whether the hash
    chain is unbroken (``False`` if an entry was edited or removed)."""

    entries: tuple[PolicyChange, ...] = field(default_factory=tuple)
    intact: bool = True

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[PolicyChange]:
        return iter(self.entries)


def read_policy(path: str | os.PathLike[str]) -> dict[str, Any]:
    """A policy file as a plain mapping (as read from YAML), unvalidated."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a policy file.")
    return data


def write_policy(
    policy: Mapping[str, Any], path: str | os.PathLike[str], user: str, note: str = ""
) -> dict[str, Any]:
    """Validate a policy, raise its revision by one, write it in a fixed
    layout (to a temporary file, then renamed) and append a record to its
    change log: who saved it, when, the revisions before and after, a note
    and the changes from :func:`policy_diff`.

    Comments in an existing policy file are not kept: use the
    ``description`` fields of the policy, its endpoints and its rules.

    Args:
        policy: The policy as a mapping (as read from YAML).
        path: The policy file (YAML).
        user: Who is saving it; recorded in the change log.
        note: Why, in a few words; recorded in the change log.

    Returns:
        The saved policy (a new mapping).

    Raises:
        PolicyError: The policy is not valid; nothing is written.
    """
    if not isinstance(user, str) or not user:
        raise ValueError("`user` must be a non-empty string.")
    path = Path(path)
    x = _plain(policy)
    old = read_policy(path) if path.exists() else None
    base = int(x.get("revision") or 0) if old is None else int(old["revision"])
    x["revision"] = base + 1
    _parse(x, path.parent)  # strict: never write a policy the proxy would refuse
    changes = ["new policy"] if old is None else policy_diff(old, x)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(policy_yaml(x).encode("utf-8"))
    os.replace(tmp, path)
    record: dict[str, Any] = {
        "time": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user": user,
        "policy": x["id"],
        "from_revision": None if old is None else base,
        "revision": x["revision"],
        "note": note,
        "changes": changes,
    }
    _log_change(path, record)
    return x


def policy_diff(old: Mapping[str, Any], new: Mapping[str, Any]) -> list[str]:
    """What changed between two policies, one line per change."""
    old, new = _plain(old), _plain(new)
    out: list[str] = []
    for f in ("id", "description", "default_action", "min_confidence"):
        a, b = _value(old.get(f)), _value(new.get(f))
        if a != b:
            out.append(f"{f}: {a} -> {b}")
    od_files = ", ".join(_strings(old.get("detectors")))
    nd_files = ", ".join(_strings(new.get("detectors")))
    if od_files != nd_files:
        out.append(f"detectors: {od_files or 'none'} -> {nd_files or 'none'}")
    od = old.get("destinations") or {}
    nd = new.get("destinations") or {}
    for name in nd:
        if name not in od:
            out.append(f"endpoint {name} added ({nd[name].get('tier')})")
    for name in od:
        if name not in nd:
            out.append(f"endpoint {name} removed")
    for name in od:
        if name not in nd:
            continue
        for f in ("tier", "provider", "url", "description", "blocked"):
            default = "false" if f == "blocked" else ""
            a = _value((od[name] or {}).get(f), default)
            b = _value((nd[name] or {}).get(f), default)
            if a != b:
                out.append(f"endpoint {name}: {f} {a} -> {b}")
    orules = list(old.get("rules") or [])
    nrules = list(new.get("rules") or [])
    oid = [r.get("id") for r in orules]
    nid = [r.get("id") for r in nrules]
    for rid in dict.fromkeys(nid):
        if rid not in oid:
            out.append(
                f"rule {rid} added at {nid.index(rid) + 1}: {_rule_text(nrules[nid.index(rid)])}"
            )
    for rid in dict.fromkeys(oid):
        if rid not in nid:
            out.append(f"rule {rid} removed")
    for rid in dict.fromkeys(oid):
        if rid not in nid:
            continue
        a, b = orules[oid.index(rid)], nrules[nid.index(rid)]
        if _rule_when(a) != _rule_when(b):
            out.append(f"rule {rid}: conditions {_rule_when(a)} -> {_rule_when(b)}")
        if a.get("action") != b.get("action"):
            out.append(f"rule {rid}: action {a.get('action')} -> {b.get('action')}")
        if _value(a.get("description")) != _value(b.get("description")):
            out.append(f"rule {rid}: description changed")
    kept_old = [r for r in oid if r in nid]
    kept_new = [r for r in nid if r in oid]
    if kept_old != kept_new:
        for i, rid in enumerate(kept_new):
            if rid != kept_old[i]:
                out.append(f"rule {rid} moved from {oid.index(rid) + 1} to {nid.index(rid) + 1}")
    return out


def policy_changes(path: str | os.PathLike[str]) -> PolicyChanges:
    """A policy's change log, oldest first. Reading stops at the first entry
    whose hash chain is broken, and ``intact`` is then ``False``."""
    log = changes_path(path)
    if not log.exists():
        return PolicyChanges()
    prev, intact, entries = _GENESIS, True, []
    for line in _lines(log):
        try:
            rec = json.loads(line)
        except ValueError:
            rec = None
        if not isinstance(rec, dict) or rec.get("prev") != prev:
            intact = False
            break
        prev = hashlib.sha256(line).hexdigest()
        entries.append(
            PolicyChange(
                time=rec["time"],
                user=rec["user"],
                policy=rec["policy"],
                revision=int(rec["revision"]),
                note=rec.get("note") or "",
                changes=tuple(rec.get("changes") or ()),
                from_revision=rec.get("from_revision"),
            )
        )
    return PolicyChanges(tuple(entries), intact)


def changes_path(path: str | os.PathLike[str]) -> Path:
    """The change log kept beside a policy file (``bank.changes.jsonl`` for
    ``bank.yaml``)."""
    p = Path(path)
    stem = p.name[: -len(p.suffix)] if p.suffix else p.name
    return p.with_name(f"{stem}.changes.jsonl")


def policy_yaml(x: Mapping[str, Any]) -> str:
    """A policy as YAML in the fixed layout and field order R writes."""
    out = [
        "policy: credgate-policy",
        "version: 1",
        f"id: {_q(x['id'])}",
        f"revision: {int(x['revision'])}",
    ]
    if x.get("description"):
        out.append(f"description: {_q(x['description'])}")
    if x.get("detectors"):
        out.append(f"detectors: {_qs(x['detectors'])}")
    out += ["", "destinations:"]
    for name, d in (x.get("destinations") or {}).items():
        d = d or {}
        out += [f"  {_q(name)}:", f"    tier: {_q(d.get('tier'))}"]
        for f in ("provider", "url", "description"):
            if d.get(f):
                out.append(f"    {f}: {_q(d[f])}")
        if d.get("blocked") is True:
            out.append("    blocked: true")
    if x.get("min_confidence") is not None:
        out += ["", f"min_confidence: {_num(x['min_confidence'])}"]
    rules = x.get("rules") or []
    out += ["", "rules:" if rules else "rules: []"]
    for r in rules:
        out.append(f"  - id: {_q(r['id'])}")
        if r.get("description"):
            out.append(f"    description: {_q(r['description'])}")
        when = r.get("when") or {}
        keys = [k for k in _WHEN_KEYS if k in when]
        if keys:
            out.append("    when:")
            out += [f"      {k}: {_qs(when[k])}" for k in keys]
        out.append(f"    action: {_q(r['action'])}")
    out += ["", f"default_action: {_q(x['default_action'])}", ""]
    return "\n".join(out) + "\n"


def _q(s: Any) -> str:
    s = str(s)
    if _PLAIN.fullmatch(s) and s.lower() not in _YAML_WORDS:
        return s
    # A JSON string is a valid YAML double-quoted scalar, newlines included.
    return json.dumps(s, ensure_ascii=False)


def _qs(v: Any) -> str:
    return "[" + ", ".join(_q(s) for s in _strings(v)) + "]"


def _strings(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (str, int, float)):
        return [str(v)]
    return [str(s) for s in v]


def _num(x: Any) -> str:
    """A number as R's format() writes it (7 significant digits)."""
    if isinstance(x, bool):
        return "TRUE" if x else "FALSE"
    if isinstance(x, int):
        return str(x)
    return f"{float(x):.7g}"


def _value(x: Any, default: str = "") -> str:
    if x is None or (isinstance(x, (list, tuple, str)) and len(x) == 0):
        return default
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, (list, tuple)):
        return ", ".join(_value(v) for v in x)
    if isinstance(x, (int, float)):
        return _num(x)
    return str(x)


def _rule_when(r: Mapping[str, Any]) -> str:
    when = r.get("when") or {}
    parts = [f"{k} {'/'.join(_strings(when[k]))}" for k in _WHEN_KEYS if k in when]
    return "when " + " and ".join(parts) if parts else "always"


def _rule_text(r: Mapping[str, Any]) -> str:
    return f"{_rule_when(r)}: {r.get('action')}"


def _plain(policy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(policy, Mapping):
        raise TypeError("`policy` must be a policy mapping.")
    return json.loads(json.dumps(policy))  # a deep, plain copy


def _lines(path: Path) -> list[bytes]:
    out = []
    for line in path.read_bytes().split(b"\n"):
        line = line.removesuffix(b"\r")
        if line:
            out.append(line)
    return out


def _log_change(path: Path, record: dict[str, Any]) -> None:
    log = changes_path(path)
    lines = _lines(log) if log.exists() else []
    record["prev"] = hashlib.sha256(lines[-1]).hexdigest() if lines else _GENESIS
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with open(log, "ab") as f:
        f.write(line.encode("utf-8") + b"\n")
