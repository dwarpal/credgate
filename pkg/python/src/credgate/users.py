"""The users file: who may use the credgate app, in which role (spec/README.md,
"Users file").

Changed only from the server's command line (`credgate users ...`); whoever
can run that is the super admin. The app reads it to decide what a signed-in
person may see and do, and (later) the proxy reads it to refuse the keys of
inactive users.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

KIND = "credgate-users"
ROLES = ("admin", "auditor", "user")
SETTINGS = {  # name: (default, lowest, highest)
    "key_max_days": (90, 30, 180),
    "activity_days": (7, 1, 90),
    "activity_max": (100, 1, 1000),
}
_NAME = re.compile(r"[A-Za-z0-9._@-]{1,100}")


@dataclass(frozen=True)
class User:
    role: str
    active: bool = True


@dataclass
class Users:
    users: dict[str, User] = field(default_factory=dict)
    settings: dict[str, int] = field(default_factory=lambda: {k: v[0] for k, v in SETTINGS.items()})

    def role_of(self, name: str | None) -> str | None:
        """The role of an active user; None for anyone else (no access)."""
        u = self.users.get(name or "")
        return u.role if u is not None and u.active else None


def parse_users(data: Any) -> Users:
    """Validate a users file's contents; raises ValueError."""
    if not isinstance(data, Mapping) or data.get("kind") != KIND:
        raise ValueError(f"not a users file: `kind` must be `{KIND}`.")
    unknown = set(data) - {"kind", "version", "settings", "users"}
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}.")
    if data.get("version") != 1:
        raise ValueError("`version` must be 1.")
    out = Users()
    settings = data.get("settings") or {}
    if not isinstance(settings, Mapping):
        raise ValueError("`settings` must be a mapping.")
    for k, v in settings.items():
        if k not in SETTINGS:
            raise ValueError(f"unknown setting `{k}`.")
        _, lo, hi = SETTINGS[k]
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"setting `{k}` must be a whole number from {lo} to {hi}.")
        out.settings[k] = v
    users = data.get("users") or {}
    if not isinstance(users, Mapping):
        raise ValueError("`users` must map names to roles.")
    for name, u in users.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError(f"user name {name!r}: letters, digits, '.', '_', '@' and '-' only.")
        if not isinstance(u, Mapping):
            raise ValueError(f"user {name!r} needs a `role`.")
        unknown = set(u) - {"role", "active"}
        if unknown:
            raise ValueError(f"user {name!r}: unknown field(s): {', '.join(sorted(unknown))}.")
        if u.get("role") not in ROLES:
            raise ValueError(f"user {name!r}: role must be one of {', '.join(ROLES)}.")
        active = u.get("active", True)
        if not isinstance(active, bool):
            raise ValueError(f"user {name!r}: `active` must be true or false.")
        out.users[name] = User(u["role"], active)
    return out


def read_users(path: str | os.PathLike[str]) -> Users:
    """A users file; raises ValueError (naming the file) if it is not valid."""
    try:
        return parse_users(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from None


def write_users(path: str | os.PathLike[str], users: Users) -> None:
    """Write the whole file at once, readable by its owner only."""
    path = Path(path)
    body: dict[str, Any] = {"kind": KIND, "version": 1}
    defaults = {k: v[0] for k, v in SETTINGS.items()}
    if users.settings != defaults:
        body["settings"] = dict(users.settings)
    body["users"] = {
        n: ({"role": u.role} if u.active else {"role": u.role, "active": False})
        for n, u in sorted(users.users.items())
    }
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(body, f, sort_keys=False, allow_unicode=True)
    os.replace(tmp, path)


def _load_or_new(path: Path) -> Users:
    return read_users(path) if path.exists() else Users()


def set_user(
    path: str | os.PathLike[str],
    name: str,
    role: str | None = None,
    active: bool | None = None,
) -> Users:
    """Add a user or change their role or active flag; returns the file's users."""
    path = Path(path)
    users = _load_or_new(path)
    if not _NAME.fullmatch(name):
        raise ValueError("User names may contain letters, digits, '.', '_', '@' and '-'.")
    old = users.users.get(name)
    if old is None and role is None:
        raise ValueError(f"No user {name!r} in {path}; give a --role to add them.")
    if role is not None and role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}.")
    users.users[name] = User(
        role if role is not None else old.role,  # type: ignore[union-attr]
        active if active is not None else (old.active if old else True),
    )
    write_users(path, users)
    return users


def remove_user(path: str | os.PathLike[str], name: str) -> Users:
    path = Path(path)
    users = read_users(path)
    if name not in users.users:
        raise ValueError(f"No user {name!r} in {path}.")
    del users.users[name]
    write_users(path, users)
    return users


def set_setting(path: str | os.PathLike[str], name: str, value: int) -> Users:
    path = Path(path)
    users = _load_or_new(path)
    data = {"kind": KIND, "version": 1, "settings": {**users.settings, name: value}}
    users.settings = parse_users(data).settings  # validates name and range
    write_users(path, users)
    return users
