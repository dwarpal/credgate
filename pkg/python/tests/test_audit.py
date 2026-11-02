import json

import credgate

POLICY = {
    "policy": "credgate-policy",
    "version": 1,
    "id": "audit-test",
    "revision": 2,
    "destinations": {"claude": {"tier": "frontier", "provider": "anthropic"}},
    "rules": [
        {"id": "card-cvv", "when": {"all_of": ["card", "card_cvv"]}, "action": "block"},
        {"id": "redact-all", "action": "redact"},
    ],
    "default_action": "redact",
}
TEXT = "Shri Ramesh Kumar, PAN ABCPE1234F, card 4111 1111 1111 1111"
KEY = "0123456789abcdef" * 4


def test_log_never_contains_text_or_values(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = credgate.AuditLog(path, key=KEY, actor="analyst1")
    policy = credgate.Policy.from_dict(POLICY)
    policy.apply([TEXT], "claude", audit=log)
    policy.apply([TEXT + " CVV 123"], "claude", audit=log)
    content = path.read_text(encoding="utf-8")
    # values that cannot occur by chance in timestamps or hex hashes
    for value in ["Ramesh", "ABCPE1234F", "4111 1111", "CVV 123", "Shri"]:
        assert value not in content
    records = credgate.audit_read(path)
    assert [r["allowed"] for r in records] == [True, False]
    assert records[1]["blocked_by"] == ["card-cvv"]
    assert records[0]["policy"] == {"id": "audit-test", "revision": 2}
    assert records[0]["destination"]["provider"] == "anthropic"
    cvv = [i for i in records[1]["items"] if i["type"] == "card_cvv"]
    assert cvv == [{"type": "card_cvv", "action": "block", "rule": "card-cvv"}]
    assert credgate.audit_verify(path).ok


def test_without_a_key_identifiers_are_not_hashed(tmp_path, monkeypatch):
    monkeypatch.delenv("CREDGATE_AUDIT_KEY", raising=False)
    path = tmp_path / "audit.jsonl"
    log = credgate.AuditLog(path, actor="analyst1")
    credgate.Policy.from_dict(POLICY).apply([TEXT], "claude", audit=log)
    assert all("id" not in i for i in credgate.audit_read(path)[0]["items"])
    assert "not hashed" in repr(log)


def test_key_from_environment_matches_explicit_key(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDGATE_AUDIT_KEY", KEY)
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    policy = credgate.Policy.from_dict(POLICY)
    policy.apply([TEXT], "claude", audit=credgate.AuditLog(a))
    policy.apply([TEXT], "claude", audit=credgate.AuditLog(b, key=KEY))
    ids = [[i.get("id") for i in credgate.audit_read(p)[0]["items"]] for p in (a, b)]
    assert ids[0] == ids[1]
    assert all(ids[0])


def test_empty_or_missing_log(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    check = credgate.audit_verify(empty)
    assert check.ok
    assert check.records == 0
    assert check.head is None


# --- rotation and retention -----------------------------------------------------

from datetime import UTC, datetime  # noqa: E402

import pytest  # noqa: E402

DECISION = credgate.Policy.from_dict(POLICY).decide([TEXT], "claude")


def _at(year, month, day=1):
    return datetime(year, month, day, 12, tzinfo=UTC)


def _write_months(path, months, per_month=3):
    log = credgate.AuditLog(path, rotate=True)
    for year, month in months:
        for day in range(1, per_month + 1):
            log.record(DECISION, time=_at(year, month, day))
    return log


def test_rotation_keeps_one_chain_across_months(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write_months(path, [(2026, 9), (2026, 10), (2026, 11)])
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "audit.2026-09.jsonl",
        "audit.2026-10.jsonl",
        "audit.jsonl",
    ]
    check = credgate.audit_verify(path)
    assert check.ok
    assert check.records == 9
    assert check.files == 3
    records = credgate.audit_read(path)
    assert [r["seq"] for r in records] == list(range(1, 10))
    assert records[3]["time"].startswith("2026-10")
    # without rotation nothing is renamed
    plain = tmp_path / "plain" / "audit.jsonl"
    log = credgate.AuditLog(plain)
    log.record(DECISION, time=_at(2026, 9))
    log.record(DECISION, time=_at(2026, 10))
    assert [p.name for p in plain.parent.iterdir()] == ["audit.jsonl"]


def test_tampering_with_segments_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write_months(path, [(2026, 9), (2026, 10), (2026, 11)])
    october = tmp_path / "audit.2026-10.jsonl"
    saved = october.read_bytes()

    october.unlink()  # a whole month removed
    check = credgate.audit_verify(path)
    assert not check.ok
    assert check.file == "audit.jsonl"

    october.write_bytes(saved.replace(b'"allowed":true', b'"allowed":false', 1))  # edited
    check = credgate.audit_verify(path)
    assert not check.ok
    assert check.file == "audit.2026-10.jsonl"
    assert "BROKEN at audit.2026-10.jsonl" in str(check)

    october.unlink()
    (tmp_path / "audit.2026-08.jsonl").write_bytes(saved)  # moved to another month
    assert not credgate.audit_verify(path).ok


def test_retention_prunes_old_months_and_the_rest_still_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write_months(path, [(2020, 1), (2020, 2), (2021, 12), (2026, 10), (2026, 11)])
    removed = credgate.audit_prune(path, keep_years=5, now=_at(2026, 11, 2))
    assert removed == ["audit.2020-01.jsonl", "audit.2020-02.jsonl"]
    manifest = json.loads((tmp_path / "audit.pruned.json").read_text())
    assert manifest["last_seq"] == 6
    assert [s["name"] for s in manifest["segments"]] == removed
    check = credgate.audit_verify(path)
    assert check.ok
    assert check.records == 9  # 2021-12, 2026-10 and 2026-11
    # the chain continues after pruning; a later prune adds to the record
    credgate.AuditLog(path, rotate=True).record(DECISION, time=_at(2026, 12))
    assert credgate.audit_read(path)[-1]["seq"] == 16
    assert credgate.audit_prune(path, keep_years=5, now=_at(2027, 1, 2)) == ["audit.2021-12.jsonl"]
    assert len(json.loads((tmp_path / "audit.pruned.json").read_text())["segments"]) == 3
    assert credgate.audit_verify(path).ok
    # an altered anchor is detected
    manifest = json.loads((tmp_path / "audit.pruned.json").read_text())
    manifest["head"] = "0" * 64
    (tmp_path / "audit.pruned.json").write_text(json.dumps(manifest))
    assert not credgate.audit_verify(path).ok


def test_pruning_is_careful(tmp_path):
    path = tmp_path / "audit.jsonl"
    _write_months(path, [(2020, 1), (2026, 10)])
    with pytest.raises(ValueError, match="at least 1"):
        credgate.audit_prune(path, keep_years=0)
    with pytest.raises(ValueError, match="at least 1"):
        credgate.audit_prune(path, keep_years=0.5)
    # within the retention period nothing goes (5 years end with December 2025's month)
    assert credgate.audit_prune(path, keep_years=5, now=_at(2025, 1, 31)) == []
    # a broken log is kept as evidence
    seg = tmp_path / "audit.2020-01.jsonl"
    seg.write_bytes(seg.read_bytes().replace(b'"seq":2', b'"seq":7'))
    with pytest.raises(ValueError, match="broken"):
        credgate.audit_prune(path, keep_years=5, now=_at(2026, 11, 2))
    assert seg.exists()


def _writer(args):
    path, barrier = args
    log = credgate.AuditLog(path, rotate=True)
    for _ in range(20):
        log.record(DECISION, time=_at(2026, 10, 15))
    barrier.wait()
    for _ in range(20):
        log.record(DECISION, time=_at(2026, 11, 15))


def test_several_processes_rotate_safely(tmp_path):
    import multiprocessing as mp

    ctx = mp.get_context("spawn")
    path = tmp_path / "audit.jsonl"
    barrier = ctx.Manager().Barrier(4)
    with ctx.Pool(4) as pool:
        pool.map(_writer, [(path, barrier)] * 4)
    check = credgate.audit_verify(path)
    assert check.ok
    assert check.records == 160
    assert check.files == 2


def test_audit_files_are_private(tmp_path):
    import os
    import stat

    path = tmp_path / "audit.jsonl"
    _write_months(path, [(2020, 1), (2026, 10)])
    credgate.audit_prune(path, keep_years=5, now=_at(2026, 11, 2))
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    for file in tmp_path.iterdir():
        assert stat.S_IMODE(file.stat().st_mode) == 0o600, file.name
