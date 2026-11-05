"""Saving policies, the change log, the access log, own activity and test
writing - the pieces the policy editors share with R."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import credgate
from credgate.audit import own_activity
from credgate.policy_tests import test_from_decision, write_policy_tests
from credgate.policy_write import changes_path, policy_changes, read_policy, write_policy
from credgate.proxy_keys import access_path, add_user, log_access, read_access

BANK = Path(__file__).resolve().parents[3] / "examples" / "policies" / "bank-default.yaml"
pytestmark = pytest.mark.skipif(not BANK.exists(), reason="repository examples not available")


def test_save_raises_the_revision_and_logs_the_change(tmp_path):
    path = tmp_path / "bank.yaml"
    shutil.copy(BANK, path)
    x = read_policy(path)
    x["destinations"]["copilot"]["blocked"] = False
    saved = write_policy(x, path, user="priya", note="CHG-1")
    assert saved["revision"] == 2
    assert credgate.Policy.load(path).revision == 2
    log = policy_changes(path)
    assert log.intact
    assert len(log) == 1
    entry = log.entries[0]
    assert (entry.user, entry.note, entry.from_revision, entry.revision) == ("priya", "CHG-1", 1, 2)
    assert entry.changes == ("endpoint copilot: blocked true -> false",)
    # a second save chains on the first
    write_policy(read_policy(path), path, user="meera")
    assert [e.revision for e in policy_changes(path)] == [2, 3]


def test_a_new_policy_starts_the_log(tmp_path):
    path = tmp_path / "new.yaml"
    x = read_policy(BANK)
    write_policy(x, path, user="priya")
    rec = json.loads(changes_path(path).read_text().splitlines()[0])
    assert rec["from_revision"] is None
    assert rec["changes"] == ["new policy"]
    assert rec["prev"] == "0" * 64
    assert list(rec) == [
        "time",
        "user",
        "policy",
        "from_revision",
        "revision",
        "note",
        "changes",
        "prev",
    ]


def test_an_invalid_policy_is_not_written(tmp_path):
    path = tmp_path / "bank.yaml"
    shutil.copy(BANK, path)
    before = path.read_bytes()
    x = read_policy(path)
    x["default_action"] = "shred"
    with pytest.raises(credgate.PolicyError):
        write_policy(x, path, user="priya")
    assert path.read_bytes() == before
    assert not changes_path(path).exists()


def test_an_edited_change_log_is_reported(tmp_path):
    path = tmp_path / "bank.yaml"
    shutil.copy(BANK, path)
    write_policy(read_policy(path), path, user="priya", note="first")
    write_policy(read_policy(path), path, user="priya", note="second")
    log = changes_path(path)
    log.write_text(log.read_text().replace('"note":"first"', '"note":"edited"'))
    h = policy_changes(path)
    # the edit is caught at the next line, whose `prev` no longer matches
    assert not h.intact
    assert len(h) == 1


def test_access_log_is_chained_and_never_holds_keys(tmp_path):
    keys = tmp_path / "keys.json"
    key = add_user(keys, "priya", days=30)
    log_access(keys, "priya", "create", "priya", "2026-12-01T00:00:00Z")
    log_access(keys, "admin", "remove", "priya")
    entries, intact = read_access(keys)
    assert intact
    assert [e.action for e in entries] == ["create", "remove"]
    assert entries[1].expires is None
    text = access_path(keys).read_text()
    assert key not in text
    assert "sha256" not in text
    assert access_path(keys).name == "keys.access.jsonl"
    access_path(keys).write_text(text.replace('"by":"priya"', '"by":"someone"'))
    entries, intact = read_access(keys)
    assert not intact
    assert len(entries) == 1  # caught at the second line


def test_own_activity_is_recent_own_and_newest_first(tmp_path):
    policy = credgate.Policy.load(BANK)
    path = tmp_path / "audit.jsonl"
    for who in ("arjun", "priya", "arjun"):
        log = credgate.AuditLog(path, actor=who)
        policy.apply(
            "PAN ABCPE1234F, mobile 9876543210", "claude", vault=credgate.Vault(), audit=log
        )
    mine = own_activity(path, "arjun")
    assert len(mine) == 2
    assert all(a.endpoint == "claude" for a in mine)
    assert mine[0].found == "2 redact"
    assert own_activity(path, "arjun", max=1)[0].time == mine[0].time
    later = datetime.now(UTC) + timedelta(days=10)
    assert own_activity(path, "arjun", days=7, now=later) == []


def test_a_test_saved_from_a_decision_passes(tmp_path):
    policy = credgate.Policy.load(BANK)
    text = "Card 4111 1111 1111 1111, CVV 123, expiry 08/29"
    t = test_from_decision("card-blocked", text, "claude", policy.decide(text, "claude"))
    assert t["expect"] == {"allowed": False, "blocked_by": ["card-with-cvv-and-expiry"]}
    t2 = test_from_decision(
        "pan", "PAN ABCPE1234F", "claude", policy.decide("PAN ABCPE1234F", "claude")
    )
    assert t2["expect"]["allowed"] is True
    assert "pan" in t2["expect"]["actions"]
    path = tmp_path / "bank.tests.yaml"
    write_policy_tests([t, t2], path)
    results = credgate.run_policy_tests(policy, path)
    assert [r.passed for r in results] == [True, True]
    with pytest.raises(ValueError, match=r"expect\.allowed"):
        write_policy_tests([{"id": "x", "endpoint": "claude", "text": "t", "expect": {}}], path)
