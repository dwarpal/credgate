"""The proxy's keys file and the commands that manage it: add, rotate,
remove, list; keys expire, and the proxy refuses an expired, rotated or
removed key after a reload."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys

import pytest
import yaml

from credgate.proxy import ProxyConfig, _Exchange, _ProxyError, reload
from credgate.proxy_keys import (
    add_user,
    hash_key,
    list_users,
    read_keys,
    remove_user,
    rotate_key,
)


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "policy": "credgate-policy",
                "version": 1,
                "id": "p",
                "revision": 1,
                "destinations": {"local": {"tier": "local", "url": "http://127.0.0.1:9/v1"}},
                "rules": [],
                "default_action": "allow",
            }
        )
    )
    return path


def _who(config, key):
    """The user a request with `key` is recorded as (or the refusal)."""
    ex = _Exchange(config, "GET", "/v1/models", {"Authorization": f"Bearer {key}"}, lambda: b"")
    return ex._authenticate()


def test_a_key_is_stored_as_a_hash_with_its_dates(tmp_path):
    keys = tmp_path / "keys.json"
    key = add_user(keys, "priya", days=30)
    assert key.startswith("cgk_")
    data = json.loads(keys.read_text())
    entry = data["users"]["priya"]
    assert entry["hash"] == hash_key(key)
    assert key not in keys.read_text()
    created = dt.datetime.fromisoformat(entry["created"].replace("Z", "+00:00"))
    expires = dt.datetime.fromisoformat(entry["expires"].replace("Z", "+00:00"))
    assert expires - created == dt.timedelta(days=30)
    assert (os.stat(keys).st_mode & 0o777) == 0o600


def test_a_file_from_before_expiry_still_loads(tmp_path):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"credgate_proxy_keys": 1, "users": {"old": hash_key("cgk_x")}}))
    entry = read_keys(keys)["old"]
    assert entry.hash == hash_key("cgk_x")
    assert entry.expires is None
    assert list_users(keys)[0]["status"] == "no expiry"
    add_user(keys, "new")  # rewriting keeps the old user
    assert read_keys(keys)["old"].hash == hash_key("cgk_x")


def test_bad_files_and_arguments_are_refused(tmp_path):
    keys = tmp_path / "keys.json"
    add_user(keys, "priya")
    with pytest.raises(ValueError, match="already exists"):
        add_user(keys, "priya")
    for days in (0, 181, True):
        with pytest.raises(ValueError, match="1 to 180 days"):
            add_user(keys, "arjun", days=days)
    with pytest.raises(ValueError, match="letters, digits"):
        add_user(keys, "bad name")
    with pytest.raises(ValueError, match="No user"):
        rotate_key(keys, "nobody")
    with pytest.raises(ValueError, match="last user"):
        remove_user(keys, "priya")
    keys.write_text(json.dumps({"credgate_proxy_keys": 1, "users": {"x": {"hash": "md5:1"}}}))
    with pytest.raises(ValueError, match="sha256"):
        read_keys(keys)
    keys.write_text(
        json.dumps(
            {"credgate_proxy_keys": 1, "users": {"x": {"hash": "sha256:1", "expires": "soon"}}}
        )
    )
    with pytest.raises(ValueError, match="UTC time"):
        read_keys(keys)


def test_status_of_each_key(tmp_path):
    keys = tmp_path / "keys.json"
    add_user(keys, "long", days=90)
    add_user(keys, "short", days=3)
    later = dt.datetime.now(dt.UTC) + dt.timedelta(days=4)
    assert {r["name"]: r["status"] for r in list_users(keys)} == {
        "long": "active",
        "short": "expires soon",
    }
    assert {r["name"]: r["status"] for r in list_users(keys, now=later)}["short"] == "expired"
    assert all("hash" not in r for r in list_users(keys))  # never shown


def test_the_proxy_refuses_expired_rotated_and_removed_keys(tmp_path, policy):
    keys = tmp_path / "keys.json"
    priya = add_user(keys, "priya")
    arjun = add_user(keys, "arjun")
    config = ProxyConfig(policy=policy, audit=tmp_path / "a.jsonl", port=0, keys=keys)
    assert _who(config, priya) == "priya"

    new = rotate_key(keys, "priya")
    remove_user(keys, "arjun")
    assert reload(config, lambda line: None)
    with pytest.raises(_ProxyError) as e:
        _who(config, priya)  # the old key
    assert e.value.status == 401
    assert _who(config, new) == "priya"
    with pytest.raises(_ProxyError):
        _who(config, arjun)

    data = json.loads(keys.read_text())
    data["users"]["priya"]["expires"] = "2020-01-01T00:00:00Z"
    keys.write_text(json.dumps(data))
    assert reload(config, lambda line: None)
    with pytest.raises(_ProxyError, match="expired on 2020-01-01") as e:
        _who(config, new)
    assert e.value.status == 401


def test_the_commands(tmp_path):
    keys = tmp_path / "keys.json"

    def cli(*args):
        return subprocess.run(
            [sys.executable, "-m", "credgate.cli", "proxy", *args],
            capture_output=True,
            text=True,
            env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
        )

    r = cli("add-user", "--keys", str(keys), "priya", "--days", "30")
    assert r.returncode == 0
    assert r.stdout.strip().startswith("cgk_")
    assert "valid for 30 days" in r.stderr
    assert cli("add-user", "--keys", str(keys), "arjun").returncode == 0
    r = cli("rotate-key", "--keys", str(keys), "priya")
    assert r.returncode == 0
    assert r.stdout.strip().startswith("cgk_")
    r = cli("list-users", "--keys", str(keys))
    assert r.returncode == 0
    assert "priya" in r.stdout
    assert "arjun" in r.stdout
    assert "sha256" not in r.stdout
    assert cli("remove-user", "--keys", str(keys), "arjun").returncode == 0
    r = cli("remove-user", "--keys", str(keys), "priya")
    assert r.returncode == 2
    assert "last user" in r.stderr
    assert cli("add-user", "--keys", str(keys), "x", "--days", "365").returncode == 2
