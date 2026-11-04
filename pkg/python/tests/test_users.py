"""The users file and `credgate users`: roles, leavers and settings."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
import yaml

from credgate.users import Users, read_users, remove_user, set_setting, set_user


def test_roles_and_leavers(tmp_path):
    path = tmp_path / "users.yaml"
    set_user(path, "priya", role="admin")
    set_user(path, "arjun", role="user")
    assert read_users(path).role_of("arjun") == "user"
    set_user(path, "arjun", active=False)  # a leaver
    users = read_users(path)
    assert users.role_of("arjun") is None
    assert users.role_of("nobody") is None
    assert users.role_of(None) is None
    set_user(path, "arjun", active=True)
    assert read_users(path).role_of("arjun") == "user"
    remove_user(path, "arjun")
    assert "arjun" not in read_users(path).users
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_settings_have_defaults_and_ranges(tmp_path):
    path = tmp_path / "users.yaml"
    set_user(path, "priya", role="admin")
    assert read_users(path).settings == {
        "key_max_days": 90,
        "activity_days": 7,
        "activity_max": 100,
    }
    assert "settings" not in yaml.safe_load(path.read_text())  # defaults are not written
    set_setting(path, "key_max_days", 30)
    assert read_users(path).settings["key_max_days"] == 30
    with pytest.raises(ValueError, match="30 to 180"):
        set_setting(path, "key_max_days", 365)
    with pytest.raises(ValueError, match="unknown setting"):
        set_setting(path, "colour", 1)


def test_bad_input_is_refused(tmp_path):
    path = tmp_path / "users.yaml"
    with pytest.raises(ValueError, match="give a --role"):
        set_user(path, "priya")
    with pytest.raises(ValueError, match="role must be"):
        set_user(path, "priya", role="owner")
    with pytest.raises(ValueError, match="letters, digits"):
        set_user(path, "a b", role="user")
    path.write_text("kind: credgate-users\nversion: 1\nusers: {x: {role: user, email: e}}\n")
    with pytest.raises(ValueError, match=r"users\.yaml: user 'x': unknown field"):
        read_users(path)


def test_the_commands(tmp_path):
    path = tmp_path / "users.yaml"

    def cli(*args):
        return subprocess.run(
            [sys.executable, "-m", "credgate.cli", "users", *args, "--file", str(path)],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
        )

    assert cli("add", "priya", "--role", "admin").returncode == 0
    assert cli("add", "arjun", "--role", "user").returncode == 0
    r = cli("add", "priya", "--role", "user")
    assert r.returncode == 2
    assert "set-role" in r.stderr
    assert cli("set-role", "arjun", "--role", "auditor").returncode == 0
    assert cli("deactivate", "arjun").returncode == 0
    assert cli("set", "key_max_days", "60").returncode == 0
    r = cli("list")
    assert r.returncode == 0
    assert "arjun" in r.stdout
    assert "inactive" in r.stdout
    assert "key_max_days 60" in r.stdout
    r = cli("deactivate", "priya")
    assert r.returncode == 0
    assert "no active admin" in r.stderr
    assert cli("remove", "nobody").returncode == 2


def test_an_empty_users_object():
    assert Users().role_of("anyone") is None
