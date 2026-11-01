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
