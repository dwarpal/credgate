"""The proxy's keys file: who may use a shared proxy (spec/README.md,
"Proxy keys file").

Each user has one key. The file stores a SHA-256 hash of it (the key itself
is shown once, when it is made), when it was made and when it expires. A
key that has expired is refused by the proxy; rotating gives the user a new
one and voids the old. Files written before keys expired (a bare hash per
user) still load, as keys that do not expire.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

KIND = "credgate_proxy_keys"
KEY_PREFIX = "cgk_"
DEFAULT_DAYS = 90
MAX_DAYS = 180
WARN_DAYS = 7
_NAME = re.compile(r"[A-Za-z0-9._@-]{1,100}")


@dataclass(frozen=True)
class KeyEntry:
    """One user's key, as stored: its hash and its dates (ISO 8601, UTC)."""

    hash: str
    created: str | None = None
    expires: str | None = None

    def expired(self, now: _dt.datetime | None = None) -> bool:
        return self.expires is not None and _parse(self.expires) <= (now or _now())


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0)


def _iso(t: _dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> _dt.datetime:
    return _dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.UTC)


def hash_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


def read_keys(path: str | os.PathLike[str]) -> dict[str, KeyEntry]:
    """The users of a keys file; raises ValueError if it is not one."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get(KIND) != 1:
        raise ValueError(f"{path} is not a credgate proxy keys file.")
    users = data.get("users", {})
    if not isinstance(users, dict):
        raise ValueError(f"{path}: `users` must map names to keys.")
    out = {}
    for name, v in users.items():
        if isinstance(v, str):  # written before keys expired
            v = {"hash": v}
        if not isinstance(v, dict) or not str(v.get("hash", "")).startswith("sha256:"):
            raise ValueError(f"{path}: user {name!r} needs a `sha256:` key hash.")
        for field in ("created", "expires"):
            if v.get(field) is not None:
                try:
                    _parse(v[field])
                except (TypeError, ValueError):
                    raise ValueError(
                        f"{path}: user {name!r}: `{field}` must be a UTC time like "
                        "2026-11-04T10:00:00Z."
                    ) from None
        out[str(name)] = KeyEntry(v["hash"], v.get("created"), v.get("expires"))
    return out


def _write(path: Path, users: dict[str, KeyEntry]) -> None:
    """Write the whole file at once (a reader sees the old file or the new),
    readable by its owner only."""
    body = {
        KIND: 1,
        "users": {n: {k: v for k, v in vars(e).items() if v is not None} for n, e in users.items()},
    }
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(body, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def _check_days(days: int) -> None:
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
        raise ValueError(f"A key lasts 1 to {MAX_DAYS} days.")


def _new_entry(days: int) -> tuple[str, KeyEntry]:
    _check_days(days)
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    now = _now()
    return key, KeyEntry(hash_key(key), _iso(now), _iso(now + _dt.timedelta(days=days)))


def add_user(keys: str | os.PathLike[str], name: str, days: int = DEFAULT_DAYS) -> str:
    """Add a user to a keys file (created if missing) and return their new
    key, valid for `days` (1 to 180). Only a hash of the key is stored; the
    key is shown once."""
    if not _NAME.fullmatch(name):
        raise ValueError("User names may contain letters, digits, '.', '_', '@' and '-'.")
    path = Path(keys)
    users = read_keys(path) if path.exists() else {}
    if name in users:
        raise ValueError(f"User {name!r} already exists in {path}; rotate their key instead.")
    key, users[name] = _new_entry(days)
    _write(path, users)
    return key


def rotate_key(keys: str | os.PathLike[str], name: str, days: int = DEFAULT_DAYS) -> str:
    """Give a user a new key, valid for `days`; their old key stops working
    at the proxy's next reload. Returns the new key (shown once)."""
    path = Path(keys)
    users = read_keys(path)
    if name not in users:
        raise ValueError(f"No user {name!r} in {path}.")
    key, users[name] = _new_entry(days)
    _write(path, users)
    return key


def remove_user(keys: str | os.PathLike[str], name: str) -> None:
    """Remove a user; their key stops working at the proxy's next reload.
    The last user cannot be removed: a shared proxy with no users would
    refuse everyone."""
    path = Path(keys)
    users = read_keys(path)
    if name not in users:
        raise ValueError(f"No user {name!r} in {path}.")
    if len(users) == 1:
        raise ValueError(f"{name!r} is the last user in {path}; add another user first.")
    del users[name]
    _write(path, users)


def list_users(
    keys: str | os.PathLike[str], now: _dt.datetime | None = None
) -> list[dict[str, Any]]:
    """The users of a keys file with their key's dates and status (never the
    keys or their hashes): "active", "expires soon" (within 7 days),
    "expired" or "no expiry"."""
    now = now or _now()
    out = []
    for name, e in sorted(read_keys(keys).items()):
        if e.expires is None:
            status = "no expiry"
        elif e.expired(now):
            status = "expired"
        elif _parse(e.expires) - now <= _dt.timedelta(days=WARN_DAYS):
            status = "expires soon"
        else:
            status = "active"
        out.append({"name": name, "created": e.created, "expires": e.expires, "status": status})
    return out


def expire_unused(
    keys: str | os.PathLike[str],
    audit: str | os.PathLike[str],
    days: int = 60,
    now: _dt.datetime | None = None,
) -> list[str]:
    """Expire the keys of users who have not used the proxy for `days` days.

    The last use of each key is read from the proxy's audit log (its monthly
    files included): a request recorded under the user's name. A key made
    within the last `days` days is left alone. An expired key stays in the
    file, so the person can be given a new one with `rotate_key`. Returns the
    names whose keys were expired.
    """
    from .audit import audit_read

    if isinstance(days, bool) or not isinstance(days, int) or days < 1:
        raise ValueError("`days` must be a whole number of at least 1.")
    now = now or _now()
    cutoff = now - _dt.timedelta(days=days)
    last: dict[str, _dt.datetime] = {}
    for r in audit_read(audit):
        t = _dt.datetime.fromisoformat(str(r.get("time", "")).replace("Z", "+00:00"))
        who = r.get("actor")
        if who and (who not in last or t > last[who]):
            last[who] = t
    path = Path(keys)
    users = read_keys(path)
    expired = []
    for name, e in users.items():
        if e.expired(now) or (e.created is not None and _parse(e.created) > cutoff):
            continue
        if last.get(name, _dt.datetime.min.replace(tzinfo=_dt.UTC)) < cutoff:
            users[name] = KeyEntry(e.hash, e.created, _iso(now))
            expired.append(name)
    if expired:
        _write(path, users)
    return sorted(expired)


@dataclass(frozen=True)
class AccessEntry:
    """One change to who may use the proxy: a key made, rotated or removed."""

    time: str
    by: str
    action: str
    user: str
    expires: str | None = None


def access_path(keys: str | os.PathLike[str]) -> Path:
    """The access log kept beside a keys file (``keys.access.jsonl`` for
    ``keys.json``)."""
    p = Path(keys)
    stem = p.name.removesuffix(".json")
    return p.with_name(f"{stem}.access.jsonl")


def log_access(
    keys: str | os.PathLike[str], by: str, action: str, user: str, expires: str | None = None
) -> None:
    """Record a key change in the access log beside the keys file: when, by
    whom, what (``create``, ``rotate`` or ``remove``), for whom and until
    when - never the key. Hash-chained like the audit log."""
    log = access_path(keys)
    last = _last_line(log)
    record: dict[str, Any] = {"time": _iso(_now()), "by": by, "action": action, "user": user}
    if expires is not None:
        record["expires"] = expires
    record["prev"] = hashlib.sha256(last).hexdigest() if last else _GENESIS
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with open(log, "ab") as f:
        f.write(line.encode("utf-8") + b"\n")


def read_access(keys: str | os.PathLike[str]) -> tuple[list[AccessEntry], bool]:
    """The access log beside a keys file, oldest first, and whether its hash
    chain is unbroken. Reading stops at the first broken entry."""
    log = access_path(keys)
    if not log.exists():
        return [], True
    prev, out = _GENESIS, []
    for line in _lines(log):
        try:
            rec = json.loads(line)
        except ValueError:
            return out, False
        if not isinstance(rec, dict) or rec.get("prev") != prev:
            return out, False
        prev = hashlib.sha256(line).hexdigest()
        out.append(
            AccessEntry(rec["time"], rec["by"], rec["action"], rec["user"], rec.get("expires"))
        )
    return out, True


_GENESIS = "0" * 64


def _lines(path: Path) -> list[bytes]:
    return [ln.removesuffix(b"\r") for ln in path.read_bytes().split(b"\n") if ln.strip(b"\r")]


def _last_line(path: Path) -> bytes | None:
    if not path.exists():
        return None
    lines = _lines(path)
    return lines[-1] if lines else None
