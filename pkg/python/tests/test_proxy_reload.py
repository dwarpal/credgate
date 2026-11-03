"""Reloading a running proxy's policy, detectors and keys: only a new,
complete, tested revision replaces the running one."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request

import pytest
import yaml

import credgate
from credgate.proxy import ProxyConfig, _Exchange, add_user, reload

STAFF = {
    "kind": "credgate-detectors",
    "version": 1,
    "detectors": [
        {
            "id": "staff_code",
            "class": "personal",
            "label": "Staff code",
            "patterns": ["EMP-[0-9]{5}"],
            "bounded": True,
            "base": 0.6,
            "examples": {"match": ["Staff EMP-12345"], "no_match": ["EMP-1234"]},
        }
    ],
}


def _write_policy(path, revision, action="tokenise", detectors=True, **extra):
    data = {
        "policy": "credgate-policy",
        "version": 1,
        "id": "bank",
        "revision": revision,
        "destinations": {"claude": {"tier": "frontier", "url": "http://127.0.0.1:9/v1"}},
        "rules": [{"id": "staff", "when": {"types": ["staff_code"]}, "action": action}]
        if detectors
        else [],
        "default_action": "redact",
        **extra,
    }
    if detectors:
        data["detectors"] = ["staff.yaml"]
    path.write_text(yaml.safe_dump(data))


def _tests(path, action):
    path.write_text(
        yaml.safe_dump(
            {
                "kind": "credgate-policy-tests",
                "version": 1,
                "tests": [
                    {
                        "id": "staff-code",
                        "endpoint": "claude",
                        "text": "Staff EMP-12345",
                        "expect": {"allowed": True, "actions": {"staff_code": action}},
                    }
                ],
            }
        )
    )


@pytest.fixture
def setup(tmp_path):
    (tmp_path / "staff.yaml").write_text(yaml.safe_dump(STAFF))
    policy = tmp_path / "bank.yaml"
    _write_policy(policy, 1)
    lines = []
    config = ProxyConfig(policy=policy, audit=tmp_path / "audit.jsonl", port=0)
    return config, policy, lines.append, lines


def _action(policy, text="Staff EMP-12345"):
    d = policy.decide(text, "claude")
    return [(m.span.type, m.action) for m in d.matches]


def test_a_new_revision_replaces_the_running_one(setup):
    config, policy, log, lines = setup
    assert not reload(config, log)  # nothing changed
    _write_policy(policy, 2, action="redact")
    assert reload(config, log)
    assert config.policy.revision == 2
    assert _action(config.policy) == [("staff_code", "redact")]
    assert "revision 2 loaded" in lines[-1]


def test_a_change_without_a_new_revision_is_refused(setup):
    config, policy, log, lines = setup
    _write_policy(policy, 1, action="allow")
    assert not reload(config, log)
    assert config.policy.revision == 1
    assert _action(config.policy) == [("staff_code", "tokenise")]
    assert "revision is still 1" in lines[-1]
    # a detectors file changed alone is a change without a new revision too
    staff = dict(STAFF, detectors=[dict(STAFF["detectors"][0], patterns=["EMP-[0-9]{6}"])])
    staff["detectors"][0]["examples"] = {"match": ["Staff EMP-123456"]}
    (policy.parent / "staff.yaml").write_text(yaml.safe_dump(staff))
    assert not reload(config, log)
    assert _action(config.policy) == [("staff_code", "tokenise")]


def test_a_broken_revision_is_refused_and_the_running_one_stays(setup):
    config, policy, log, lines = setup
    policy.write_text("policy: credgate-policy\nrevision: [")  # half-written
    assert not reload(config, log)
    _write_policy(policy, 2, extra_field=True)  # unknown field
    assert not reload(config, log)
    bad = dict(STAFF)
    bad["detectors"] = [dict(STAFF["detectors"][0], examples={"match": ["EMP-1"]})]
    (policy.parent / "staff.yaml").write_text(yaml.safe_dump(bad))  # failing example
    _write_policy(policy, 2)
    assert not reload(config, log)
    assert config.policy.revision == 1
    assert "does not load" in lines[-1]


def test_failing_policy_tests_refuse_a_revision(setup):
    config, policy, log, lines = setup
    _tests(policy.parent / "bank.tests.yaml", "tokenise")
    _write_policy(policy, 2, action="redact")  # breaks the agreed behaviour
    assert not reload(config, log)
    assert config.policy.revision == 1
    assert "staff-code: staff_code: expected tokenise, got redact" in lines[-1]
    _tests(policy.parent / "bank.tests.yaml", "redact")  # the test is updated: accepted
    assert reload(config, log)
    assert config.policy.revision == 2


def test_tests_are_checked_at_start_and_can_be_required(tmp_path):
    (tmp_path / "staff.yaml").write_text(yaml.safe_dump(STAFF))
    policy = tmp_path / "bank.yaml"
    _write_policy(policy, 1)
    _tests(tmp_path / "bank.tests.yaml", "redact")
    with pytest.raises(ValueError, match="policy test"):
        ProxyConfig(policy=policy, audit=tmp_path / "a.jsonl", port=0)
    (tmp_path / "bank.tests.yaml").unlink()
    with pytest.raises(ValueError, match="required"):
        ProxyConfig(policy=policy, audit=tmp_path / "a.jsonl", port=0, require_tests=True)


def test_a_rollback_is_accepted_and_logged(setup):
    config, policy, log, lines = setup
    _write_policy(policy, 5)
    assert reload(config, log)
    _write_policy(policy, 4, action="redact")
    assert reload(config, log)
    assert config.policy.revision == 4
    assert "rollback" in lines[-1]


def test_a_policy_keeps_its_own_detectors(setup):
    """A request in progress keeps the detectors of the revision it started
    with, and a detector removed from the file is gone from the new one."""
    config, policy, log, _ = setup
    old = config.policy
    exchange = _Exchange(config, "POST", "/v1/chat/completions", {}, lambda: b"")
    _write_policy(policy, 2, detectors=False)
    (policy.parent / "staff.yaml").unlink()
    assert reload(config, log)
    assert _action(config.policy) == []  # staff_code is gone
    assert exchange.policy is old
    assert _action(old) == [("staff_code", "tokenise")]  # unchanged
    assert "staff_code" not in [d["id"] for d in credgate.detectors()]  # never global


def test_keys_are_reloaded_and_a_bad_keys_file_is_refused(tmp_path):
    policy = tmp_path / "bank.yaml"
    _write_policy(policy, 1, detectors=False)
    keys = tmp_path / "keys.json"
    add_user(keys, "priya")
    config = ProxyConfig(policy=policy, audit=tmp_path / "a.jsonl", port=0, keys=keys)
    assert reload(config, lambda line: None) is False
    add_user(keys, "arjun")
    assert reload(config, lambda line: None)
    assert set(config._users) == {"priya", "arjun"}
    keys.write_text("{}")  # no users: refused, the old keys stay
    assert reload(config, lambda line: None) is False
    assert set(config._users) == {"priya", "arjun"}


# --- running processes ---------------------------------------------------------


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _health(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
        return json.load(r)


def _serve(tmp_path, policy, port, server_kind, *extra):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from credgate.cli import main; main()",
            "proxy",
            "serve",
            "--policy",
            str(policy),
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--port",
            str(port),
            "--workers",
            "3",
            "--server",
            server_kind,
            *extra,
        ],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(150):
        try:
            _health(port)
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise AssertionError(proc.stderr.read())


def _every_worker_reports(port, revision, timeout=20):
    """Health answers come from any worker; wait until many in a row agree."""
    deadline = time.monotonic() + timeout
    streak = 0
    while time.monotonic() < deadline:
        streak = streak + 1 if _health(port)["policy"]["revision"] == revision else 0
        if streak >= 30:
            return True
        time.sleep(0.02)
    return False


@pytest.mark.parametrize("trigger", ["sighup", "watch"])
def test_every_worker_reloads(tmp_path, server_kind, trigger):
    (tmp_path / "staff.yaml").write_text(yaml.safe_dump(STAFF))
    policy = tmp_path / "bank.yaml"
    _write_policy(policy, 1)
    port = _free_port()
    extra = ("--watch", "1") if trigger == "watch" else ()
    proc = _serve(tmp_path, policy, port, server_kind, *extra)
    try:
        _write_policy(policy, 2, action="redact")
        if trigger == "sighup":
            proc.send_signal(signal.SIGHUP)
        assert _every_worker_reports(port, 2)
        # a broken revision is refused everywhere; revision 2 keeps serving
        policy.write_text("policy: credgate-policy\nrevision: [")
        if trigger == "sighup":
            proc.send_signal(signal.SIGHUP)
        time.sleep(2.5)
        assert _every_worker_reports(port, 2, timeout=5)
        assert _health(port)["last_reload"]["ok"] is False
        assert proc.poll() is None  # SIGHUP no longer stops the proxy
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
