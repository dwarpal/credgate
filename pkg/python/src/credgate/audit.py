"""Tamper-evident audit log of policy decisions (the spec's "Audit log")."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
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
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        key: str | bytes | None = None,
        actor: str | None = None,
    ) -> None:
        self.path = Path(path)
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
        when = (time or datetime.now(UTC)).astimezone(UTC)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+b") as f:
            _lock(f)
            try:
                last = _last_line(self.path) if self.path.stat().st_size else None
                if last is None:
                    seq, prev = 1, _GENESIS
                else:
                    seq = json.loads(last)["seq"] + 1
                    prev = hashlib.sha256(last).hexdigest()
                record = {
                    "v": 1,
                    "seq": seq,
                    "time": when.strftime("%Y-%m-%dT%H:%M:%S.")
                    + f"{when.microsecond // 1000:03d}Z",
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
        return record


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

    def __str__(self) -> str:
        if self.ok:
            return f"Audit log intact: {self.records} records; head {self.head}"
        return f"Audit log BROKEN at line {self.line}: {self.error}"


def _lines(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if line:
                yield line


def audit_verify(path: str | os.PathLike[str]) -> AuditCheck:
    """Check that no record was edited, deleted, inserted or reordered.

    Compare the returned ``head`` with a copy kept elsewhere to detect
    records removed from the end.
    """
    prev = _GENESIS
    n = 0
    for n, line in enumerate(_lines(Path(path)), start=1):
        try:
            rec = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return AuditCheck(False, n - 1, None, n, "not a JSON record")
        if not isinstance(rec, dict) or rec.get("v") != 1:
            return AuditCheck(False, n - 1, None, n, "not an audit record (v 1)")
        if rec.get("seq") != n:
            return AuditCheck(False, n - 1, None, n, f"sequence {rec.get('seq')!r}, expected {n}")
        if rec.get("prev") != prev:
            where = "the first record" if n == 1 else f"line {n - 1}"
            return AuditCheck(
                False,
                n - 1,
                None,
                n,
                f"does not follow {where}: that line was changed, or lines were "
                "removed, inserted or reordered here",
            )
        prev = hashlib.sha256(line).hexdigest()
    return AuditCheck(True, n, prev if n else None)


def audit_read(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    """The records of an audit log, as dictionaries (verify it first)."""
    return [json.loads(line) for line in _lines(Path(path))]
