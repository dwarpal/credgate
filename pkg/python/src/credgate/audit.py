"""Tamper-evident audit log of policy decisions (the spec's "Audit log")."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .policy import Decision
from .tokenise import _token_key

_GENESIS = "0" * 64
_DOMAIN = b"credgate-audit-v1"
_NEVER_HASHED = frozenset({"sensitive_auth"})


def _id_hash(key: bytes, type_: str, canonical: str) -> str:
    message = _DOMAIN + b"\0" + type_.encode() + b"\0" + canonical.encode()
    return hmac.new(key, message, hashlib.sha256).digest()[:8].hex()


def _last_line(path: Path) -> bytes | None:
    """The last non-empty line of a file, read from the end."""
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        buf = b""
        pos = end
        while pos > 0:
            step = min(65536, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            stripped = buf.rstrip(b"\r\n")
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1]
        stripped = buf.rstrip(b"\r\n")
        return stripped or None


class AuditLog:
    """An append-only, hash-chained log of policy decisions.

    Each record says who sent what kind of data where, under which policy
    revision and rule - never the text or the values. With an audit key
    (``key`` or ``CREDGATE_AUDIT_KEY``; not the token key), identifiers are
    recorded as keyed hashes, so whoever holds the key can check whether a
    given identifier was involved. Card verification codes are never hashed.

    Args:
        path: The log file (JSON Lines); created if missing.
        key: Audit key (hex or bytes); ``None`` uses ``CREDGATE_AUDIT_KEY``
            if set, otherwise identifiers are not hashed.
        actor: Who makes the requests; defaults to the operating-system user.
        rotate: Start a new file each month (UTC): the active file at
            ``path`` is renamed ``<stem>.YYYY-MM.jsonl`` when the first record
            of a new month arrives, and the chain continues in a new active
            file. :func:`audit_verify` checks all of them as one chain;
            :func:`audit_prune` removes those past the retention period.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        key: str | bytes | None = None,
        actor: str | None = None,
        rotate: bool = False,
    ) -> None:
        self.path = Path(path)
        self.rotate = rotate
        if key is None and os.environ.get("CREDGATE_AUDIT_KEY"):
            key = os.environ["CREDGATE_AUDIT_KEY"]
        self._key = None if key is None else _token_key(key, "CREDGATE_AUDIT_KEY", "audit key")
        self.actor = actor or getpass.getuser()

    def __repr__(self) -> str:
        hashed = "identifiers hashed" if self._key else "identifiers not hashed"
        return f"<credgate.AuditLog {self.path} ({hashed})>"

    def record(self, decision: Decision, time: datetime | None = None) -> dict[str, Any]:
        """Append one record for a decision; returns the record."""
        items = []
        for m in decision.matches:
            item = {"type": m.span.type, "action": m.action, "rule": m.rule}
            if self._key is not None and m.span.data_class not in _NEVER_HASHED:
                item["id"] = _id_hash(self._key, m.span.type, m.span.canonical)
            items.append(item)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = _open_active(self.path)
        try:
            # The time is taken holding the lock, so records are in time order
            # even across processes (and rotation never sees an older month).
            when = (time or datetime.now(UTC)).astimezone(UTC)
            stamp = when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"
            size = os.fstat(f.fileno()).st_size
            last = _last_line(self.path) if size else None
            first_month = _month(_first_line(self.path)) if size else None
            if self.rotate and first_month is not None and stamp[:7] > first_month:
                segment = _segment_path(self.path, first_month)
                if segment.exists():
                    raise FileExistsError(f"{segment} exists; the audit log cannot rotate.")
                os.rename(self.path, segment)  # still locked: other writers wait, then reopen
                old, f = f, _open_active(self.path)
                _unlock(old)
                old.close()
            elif last is None:
                last = _predecessor(self.path)
            if last is None:
                seq, prev = 1, _GENESIS
            elif isinstance(last, tuple):  # everything before was pruned
                seq, prev = last[0] + 1, last[1]
            else:
                seq = json.loads(last)["seq"] + 1
                prev = hashlib.sha256(last).hexdigest()
            record = {
                "v": 1,
                "seq": seq,
                "time": stamp,
                "actor": self.actor,
                "policy": {"id": decision.policy_id, "revision": decision.policy_revision},
                "destination": {
                    "name": decision.destination,
                    "tier": decision.tier,
                    "provider": decision.provider,
                },
                "allowed": decision.allowed,
                "blocked_by": list(decision.blocked_by),
                "items": items,
                "prev": prev,
            }
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            f.seek(0, os.SEEK_END)
            f.write(line.encode("utf-8") + b"\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            _unlock(f)
            f.close()
        return record


def _open_active(path: Path) -> Any:
    """The active file, opened and locked; reopened if another writer rotated
    it between our open and our lock."""
    while True:
        # Private to the account writing it (0600): no values, but who sent
        # what kind of data where.
        f = os.fdopen(os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600), "a+b")
        _lock(f)
        try:
            if os.fstat(f.fileno()).st_ino == os.stat(path).st_ino:
                return f
        except FileNotFoundError:
            pass
        _unlock(f)
        f.close()


def _first_line(path: Path) -> bytes | None:
    with path.open("rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if line:
                return line
    return None


def _month(line: bytes | None) -> str | None:
    if line is None:
        return None
    try:
        return str(json.loads(line)["time"])[:7]
    except (ValueError, KeyError, TypeError):
        return None


_SEGMENT = re.compile(r"\.(\d{4}-\d{2})\.jsonl$")


def _segment_path(path: Path, month: str) -> Path:
    return path.with_name(f"{path.stem}.{month}{path.suffix}")


def _segments(path: Path) -> list[tuple[str, Path]]:
    """Closed monthly segments of a log, oldest first, as (month, path)."""
    out = []
    if path.parent.exists():
        for candidate in path.parent.iterdir():
            m = _SEGMENT.search(candidate.name)
            if m and candidate.name == f"{path.stem}.{m.group(1)}{path.suffix}":
                out.append((m.group(1), candidate))
    return sorted(out)


def _manifest_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}.pruned.json")


def _manifest(path: Path) -> dict[str, Any] | None:
    m = _manifest_path(path)
    if not m.exists():
        return None
    data = json.loads(m.read_text(encoding="utf-8"))
    if data.get("credgate_audit_pruned") != 1:
        raise ValueError(f"{m} is not a credgate pruned-segments file.")
    return data


def _manifest_problem(anchor: dict[str, Any]) -> str | None:
    """Why a pruned-segments record is inconsistent, if it is: its segments
    must run from sequence 1 without gaps, and its anchor match the last."""
    segments = anchor.get("segments") or []
    if not segments:
        return "the pruned-segments record lists no segments"
    expected = 1
    for seg in segments:
        if seg.get("first_seq") != expected or not isinstance(seg.get("last_seq"), int):
            return f"pruned segment {seg.get('name')!r} does not follow the one before"
        expected = seg["last_seq"] + 1
    last = segments[-1]
    if anchor.get("last_seq") != last["last_seq"] or anchor.get("head") != last.get("head"):
        return "the pruned-segments anchor does not match the last pruned segment"
    return None


def _predecessor(path: Path) -> bytes | tuple[int, str] | None:
    """What a record in an empty active file follows: the last line of the
    newest segment, else the anchor of pruned segments, else nothing."""
    segments = _segments(path)
    if segments:
        return _last_line(segments[-1][1])
    anchor = _manifest(path)
    if anchor is not None:
        return (int(anchor["last_seq"]), str(anchor["head"]))
    return None


def _lock(f: Any) -> None:
    try:
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    except ImportError:  # pragma: no cover - Windows: one writer per file
        pass


def _unlock(f: Any) -> None:
    try:
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except ImportError:  # pragma: no cover
        pass


@dataclass(frozen=True)
class AuditCheck:
    """The result of :func:`audit_verify`."""

    ok: bool
    records: int
    head: str | None
    line: int | None = None
    error: str | None = None
    file: str | None = None
    files: int = 1

    def __str__(self) -> str:
        if self.ok:
            where = f" in {self.files} files" if self.files > 1 else ""
            return f"Audit log intact: {self.records} records{where}; head {self.head}"
        where = f"{self.file}, line {self.line}" if self.file else f"line {self.line}"
        return f"Audit log BROKEN at {where}: {self.error}"


def _lines(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if line:
                yield line


def audit_verify(path: str | os.PathLike[str]) -> AuditCheck:
    """Check that no record was edited, deleted, inserted or reordered - in
    the log and, if it rotates, in all its monthly segments as one chain.

    Compare the returned ``head`` with a copy kept elsewhere to detect
    records removed from the end.
    """
    path = Path(path)
    anchor = _manifest(path)
    if anchor is not None and (problem := _manifest_problem(anchor)):
        return AuditCheck(False, 0, None, None, problem, _manifest_path(path).name, 0)
    seq, prev = (int(anchor["last_seq"]), str(anchor["head"])) if anchor else (0, _GENESIS)
    start = seq
    files = [(month, p) for month, p in _segments(path)]
    if path.exists():
        files.append((None, path))
    for month, file in files:
        for n, line in enumerate(_lines(file), start=1):

            def broken(
                error: str, file: Path = file, n: int = n, done: int = seq - start
            ) -> AuditCheck:
                return AuditCheck(False, done, None, n, error, file.name, len(files))

            try:
                rec = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                return broken("not a JSON record")
            if not isinstance(rec, dict) or rec.get("v") != 1:
                return broken("not an audit record (v 1)")
            if rec.get("seq") != seq + 1:
                return broken(f"sequence {rec.get('seq')!r}, expected {seq + 1}")
            if rec.get("prev") != prev:
                where = "the record before" if seq > start or anchor else "the start"
                return broken(
                    f"does not follow {where}: a record was changed, or records or "
                    "segments were removed, inserted or reordered here"
                )
            if month is not None and str(rec.get("time", ""))[:7] != month:
                return broken(f"a record of {str(rec.get('time'))[:7]} in the {month} segment")
            seq += 1
            prev = hashlib.sha256(line).hexdigest()
    if not files and anchor is None:
        return AuditCheck(True, 0, None, files=0)
    return AuditCheck(True, seq - start, prev if seq > start else None, files=len(files))


def audit_read(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """The records of an audit log, including its monthly segments, as
    dictionaries (verify it first)."""
    path = Path(path)
    files = [p for _, p in _segments(path)] + ([path] if path.exists() else [])
    return [json.loads(line) for file in files for line in _lines(file)]


def audit_prune(
    path: str | os.PathLike[str], keep_years: int = 5, now: datetime | None = None
) -> list[str]:
    """Remove monthly segments older than the retention period.

    A segment goes once all its records are more than ``keep_years`` years old
    (at least 1). Only the oldest segments go, never the active file, and only
    if the whole log verifies: a broken log is kept as evidence. The removed
    segments are recorded in ``<stem>.pruned.json`` (their sequence numbers,
    times and final hash), from which the rest of the chain still verifies.
    Returns the names of the removed files.
    """
    if isinstance(keep_years, bool) or not isinstance(keep_years, int) or keep_years < 1:
        raise ValueError("`keep_years` must be a whole number of at least 1.")
    path = Path(path)
    check = audit_verify(path)
    if not check.ok:
        raise ValueError(f"Not pruning a broken audit log (kept as evidence): {check}")
    today = (now or datetime.now(UTC)).astimezone(UTC)
    removable = []
    for month, file in _segments(path):
        year, mon = int(month[:4]), int(month[5:7])
        if (today.year, today.month) <= (year + keep_years, mon):
            break
        removable.append(file)
    if not removable:
        return []
    manifest = _manifest(path) or {"credgate_audit_pruned": 1, "segments": []}
    for file in removable:
        lines = list(_lines(file))
        first, last = json.loads(lines[0]), json.loads(lines[-1])
        head = hashlib.sha256(lines[-1]).hexdigest()
        manifest["segments"].append(
            {
                "name": file.name,
                "first_seq": first["seq"],
                "last_seq": last["seq"],
                "first_time": first["time"],
                "last_time": last["time"],
                "head": head,
            }
        )
        manifest["last_seq"], manifest["head"] = last["seq"], head
    target = _manifest_path(path)
    tmp = target.with_name(target.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest, indent=1) + "\n")
    os.replace(tmp, target)
    for file in removable:
        file.unlink()
    return [f.name for f in removable]
