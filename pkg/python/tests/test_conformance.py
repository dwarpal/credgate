"""Runs the shared conformance cases in spec/conformance, which every
CredGate implementation must pass."""

from __future__ import annotations

import filecmp
from pathlib import Path

import pytest
import yaml

import credgate


def conformance(name: str) -> dict:
    with open(credgate.spec_path() / "conformance" / name, encoding="utf-8") as f:
        return yaml.safe_load(f)


REPO_SPEC = Path(__file__).resolve().parents[3] / "spec"


@pytest.mark.skipif(not REPO_SPEC.is_dir(), reason="repository spec/ not available")
def test_shipped_spec_matches_repository_spec():
    cmp = filecmp.dircmp(REPO_SPEC, credgate.spec_path())

    def differences(c: filecmp.dircmp) -> list[str]:
        out = c.left_only + c.right_only + c.diff_files
        for sub in c.subdirs.values():
            out += differences(sub)
        return out

    assert differences(cmp) == [], "run tools/sync-spec.sh"


def test_checksum_vectors():
    v = conformance("checksums.yaml")
    for case in v["verhoeff"]["check_digit"]:
        assert credgate.verhoeff_check_digit(case["input"]) == case["output"], case
    for case in v["verhoeff"]["valid"]:
        assert credgate.verhoeff_valid(case["input"]) is case["valid"], case
    for case in v["luhn"]["valid"]:
        assert credgate.luhn_valid(case["input"]) is case["valid"], case
    for case in v["gstin"]["check_char"]:
        assert credgate.gstin_check_char(case["input"]) == case["output"], case
    for case in v["gstin"]["valid"]:
        assert credgate.gstin_valid(case["input"]) is case["valid"], case


DETECT_CASES = conformance("detect.yaml")["cases"]


@pytest.mark.parametrize("case", DETECT_CASES, ids=[c["id"] for c in DETECT_CASES])
def test_detect(case):
    got = credgate.detect_pii(case["text"], context=case.get("context"))
    shown = [(s.type, s.value, s.confidence) for s in got]
    assert len(got) == len(case["expect"]), shown
    for e in case["expect"]:
        rows = [s for s in got if s.type == e["type"] and s.value == e["value"]]
        assert len(rows) == 1, (e, shown)
        s = rows[0]
        if "confidence" in e:
            assert s.confidence == e["confidence"], (e, s.reasons)
        if "canonical" in e:
            assert s.canonical == e["canonical"]
        if "span" in e:
            assert [s.start, s.end] == e["span"]
        if "reason" in e:
            assert e["reason"] in s.reasons


SCAN_CASES = conformance("scan.yaml")["cases"]


@pytest.mark.parametrize("case", SCAN_CASES, ids=[c["id"] for c in SCAN_CASES])
def test_scan(case):
    got = credgate.scan_pii(
        case["columns"], sample=case.get("sample", 10000), min_rate=case.get("min_rate", 0)
    )
    rows = got.to_records()
    assert len(rows) == len(case["expect"]), rows
    for row, e in zip(rows, case["expect"], strict=True):
        for field, value in e.items():
            assert row[field] == value, (field, row)


REDACT_CASES = conformance("redact.yaml")["cases"]


@pytest.mark.parametrize("case", REDACT_CASES, ids=[c["id"] for c in REDACT_CASES])
def test_redact(case):
    kwargs = {"context": case.get("context"), "min_confidence": case.get("min_confidence", 0)}
    assert credgate.redact(case["text"], **kwargs) == case["redacted"]
    assert credgate.preview(case["text"], **kwargs).redacted == [case["redacted"]]


NEGATIVES = conformance("negatives.yaml")


@pytest.mark.parametrize("case", NEGATIVES["negatives"], ids=lambda c: c["id"])
def test_hard_negative(case):
    limit = case.get("max_confidence", 0.5)
    confident = [s for s in credgate.detect_pii(case["text"]) if s.confidence >= limit]
    assert confident == [], [(s.type, s.value, s.confidence) for s in confident]


@pytest.mark.parametrize("case", NEGATIVES["known_false_positives"], ids=lambda c: c["id"])
def test_known_false_positive_still_present(case):
    types = {s.type for s in credgate.detect_pii(case["text"])}
    assert case["type"] in types, "fixed? move this case to `negatives` in the spec"


EVALUATE_CASES = conformance("evaluate.yaml")["cases"]


@pytest.mark.parametrize("case", EVALUATE_CASES, ids=[c["id"] for c in EVALUATE_CASES])
def test_evaluate(case):
    report = credgate.evaluate(
        case["documents"],
        min_confidence=case.get("min_confidence", 0),
        match=case.get("match", "exact"),
    )
    assert report.to_records() == case["expect"]


TOKENISE_CASES = conformance("tokenise.yaml")["cases"]


@pytest.mark.parametrize("case", TOKENISE_CASES, ids=[c["id"] for c in TOKENISE_CASES])
def test_tokenise(case):
    key = case.get("key")
    if "fingerprint" in case:
        assert credgate.key_fingerprint(key) == case["fingerprint"]
    vault = credgate.Vault(key)
    for step in case["steps"]:
        if step.get("new_vault"):
            vault = credgate.Vault(key)
        elif "tokenise" in step:
            got = credgate.tokenise(
                step["tokenise"],
                vault,
                context=step.get("context"),
                min_confidence=step.get("min_confidence", 0),
            )
            assert got == step["expect"]
        elif "restore" in step:
            strict = step.get("strict", False)
            if step.get("error"):
                with pytest.raises(credgate.UnknownTokenError):
                    credgate.restore(step["restore"], vault, strict=strict)
            else:
                assert credgate.restore(step["restore"], vault, strict=strict) == step["expect"]
        else:
            got = [[e.token, e.type, e.canonical] for e in vault._entries]
            assert got == step["expect"]


VAULT_SPEC = conformance("vault.yaml")


@pytest.mark.parametrize("case", VAULT_SPEC["files"], ids=[f["file"] for f in VAULT_SPEC["files"]])
def test_vault_file(case):
    pytest.importorskip("nacl")
    path = credgate.spec_path() / "conformance" / case["file"]
    key = case.get("key")
    vault = credgate.Vault.open(path, passphrase=case["passphrase"], key=key)
    got = [[e.token, e.type, e.data_class, e.canonical, e.value] for e in vault._entries]
    assert got == case["entries"]
    with pytest.raises(credgate.VaultFileError):
        credgate.Vault.open(path, passphrase=VAULT_SPEC["wrong_passphrase"], key=key)
    if key is not None:
        with pytest.raises(credgate.VaultFileError, match="token key does not match"):
            credgate.Vault.open(path, passphrase=case["passphrase"], key=VAULT_SPEC["other_key"])
        # the reopened vault keeps making the same keyed tokens
        assert credgate.tokenise("PAN ABCPE1234F", vault) == "PAN [PAN_bpg46o6x465d4]"
    else:
        with pytest.raises(credgate.VaultFileError, match="numbered"):
            credgate.Vault.open(path, passphrase=case["passphrase"], key=VAULT_SPEC["other_key"])


POLICY_SPEC = conformance("policy.yaml")


def _policy(p):
    return credgate.Policy.from_dict(POLICY_SPEC["policies"][p] if isinstance(p, str) else p)


@pytest.mark.parametrize("case", POLICY_SPEC["cases"], ids=[c["id"] for c in POLICY_SPEC["cases"]])
def test_policy(case):
    d = _policy(case["policy"]).apply(case["texts"], case["destination"], vault=credgate.Vault())
    assert d.allowed == case["allowed"]
    assert [[m.span.type, m.action, m.rule] for m in d.matches] == case["matches"]
    assert list(d.blocked_by) == case.get("blocked_by", [])
    assert d.texts == (case["output"] if case["allowed"] else None)


@pytest.mark.parametrize(
    "case", POLICY_SPEC["invalid"], ids=[c["id"] for c in POLICY_SPEC["invalid"]]
)
def test_invalid_policy(case):
    with pytest.raises(credgate.PolicyError) as err:
        credgate.Policy.from_dict(case["policy"])
    assert case["error"].lower() in str(err.value).lower()


def test_policy_unknown_destination():
    u = POLICY_SPEC["unknown_destination"]
    with pytest.raises(credgate.PolicyError, match="Unknown destination"):
        _policy(u["policy"]).decide("PAN ABCPE1234F", u["destination"])


AUDIT_SPEC = conformance("audit.yaml")


@pytest.mark.parametrize("case", AUDIT_SPEC["id_hashes"], ids=lambda c: f"{c['type']}-{c['id']}")
def test_audit_id_hash(case):
    from credgate.audit import _id_hash

    assert _id_hash(bytes.fromhex(AUDIT_SPEC["key"]), case["type"], case["canonical"]) == case["id"]


@pytest.mark.parametrize("case", AUDIT_SPEC["logs"], ids=lambda c: c["file"])
def test_audit_log_verifies(case):
    check = credgate.audit_verify(credgate.spec_path() / "conformance" / case["file"])
    assert check.ok
    assert check.records == case["records"]
    assert check.head == case["head"]


def _tampered(lines, change, at):
    lines = list(lines)
    i = at - 1
    if change == "edit":
        lines[i] = lines[i].replace('"actor":"', '"actor":"x', 1)
    elif change == "delete":
        del lines[i]
    elif change == "swap":
        lines[i], lines[i + 1] = lines[i + 1], lines[i]
    elif change == "duplicate":
        lines.insert(i + 1, lines[i])
    return lines


@pytest.mark.parametrize("case", AUDIT_SPEC["tamper"]["cases"], ids=lambda c: c["id"])
def test_audit_tampering_is_detected(case, tmp_path):
    source = credgate.spec_path() / "conformance" / AUDIT_SPEC["tamper"]["file"]
    lines = source.read_text(encoding="utf-8").splitlines()
    path = tmp_path / "log.jsonl"
    path.write_text(
        "\n".join(_tampered(lines, case["change"], case["at"])) + "\n", encoding="utf-8"
    )
    check = credgate.audit_verify(path)
    assert not check.ok
    assert check.line == case["line"]


INVENTORY_SPEC = conformance("inventory.yaml")
INVENTORY_FIELDS = (
    "v",
    "source",
    "table",
    "column",
    "type",
    "class",
    "n_rows",
    "n_sampled",
    "n_matched",
    "n_full",
    "rate",
    "mean_confidence",
    "sample_method",
)


def _inventory(case):
    return credgate.pii_inventory(
        case["columns"],
        source=case["source"],
        table=case["table"],
        sample=case.get("sample", 10000),
        min_rate=case.get("min_rate", 0),
    )


@pytest.mark.parametrize("case", INVENTORY_SPEC["cases"], ids=lambda c: c["id"])
def test_inventory(case):
    got = [{k: r[k] for k in INVENTORY_FIELDS} for r in _inventory(case).to_records()]
    expect = [{k: e.get(k) for k in INVENTORY_FIELDS} for e in case["expect"]]
    assert got == expect


def test_inventory_file_written_by_both(tmp_path):
    import dataclasses

    spec = INVENTORY_SPEC["file"]
    case = next(c for c in INVENTORY_SPEC["cases"] if c["id"] == spec["case"])
    inv = credgate.Inventory(
        dataclasses.replace(r, scanned_at=spec["scanned_at"], credgate=spec["credgate"])
        for r in _inventory(case)
    )
    expected = credgate.spec_path() / "conformance" / spec["path"]
    assert inv.write(tmp_path / "inv.csv").read_bytes() == expected.read_bytes()
    assert credgate.read_inventory(expected) == inv


@pytest.mark.parametrize("case", conformance("bigquery.yaml")["cases"], ids=lambda c: c["id"])
def test_bigquery_query(case):
    from credgate.bigquery import sample_query

    fields = [(f["name"], f["type"], f.get("mode", "NULLABLE")) for f in case["fields"]]
    got = sample_query(
        case["table"],
        case["kind"],
        case["rows"],
        fields,
        case.get("sample", 10000),
        case.get("sampling", "tablesample"),
    )
    assert got == (case["sql"], case["read"], case["sample_method"])


@pytest.mark.parametrize("case", conformance("database.yaml")["cases"], ids=lambda c: c["id"])
def test_database_query(case):
    from credgate.database import sample_query

    columns = [(c["name"], c["type"]) for c in case["columns"]]
    got = sample_query(
        case["family"],
        case["schema"],
        case["table"],
        case["rows"],
        columns,
        case.get("sample", 10000),
    )
    assert got == (case["sql"], case["read"], case["sample_method"], case["fetch"])


ROTATED = AUDIT_SPEC["rotated"]


def _rotated_copy(tmp_path):
    import shutil

    folder = tmp_path / "rotated"
    shutil.copytree(credgate.spec_path() / "conformance" / Path(ROTATED["path"]).parent, folder)
    for file in folder.iterdir():
        file.chmod(0o644)  # installed files can be read-only
    return folder / Path(ROTATED["path"]).name


def test_rotated_log_written_by_both_verifies(tmp_path):
    check = credgate.audit_verify(_rotated_copy(tmp_path))
    assert check.ok
    assert (check.records, check.files, check.head) == (
        ROTATED["records"],
        ROTATED["files"],
        ROTATED["head"],
    )


@pytest.mark.parametrize("case", ROTATED["tamper"], ids=lambda c: c["id"])
def test_rotated_log_tampering_is_detected(case, tmp_path):
    path = _rotated_copy(tmp_path)
    folder = path.parent
    if "delete" in case:
        (folder / case["delete"]).unlink()
    if "rename" in case:
        (folder / case["rename"][0]).rename(folder / case["rename"][1])
    if "replace" in case:
        name, old, new = case["replace"]
        text = (folder / name).read_text(encoding="utf-8")
        assert old in text
        (folder / name).write_text(text.replace(old, new, 1), encoding="utf-8")
    assert not credgate.audit_verify(path).ok


CUSTOM_SPEC = conformance("custom_detectors.yaml")


@pytest.mark.parametrize("case", CUSTOM_SPEC["cases"], ids=[c["id"] for c in CUSTOM_SPEC["cases"]])
def test_custom_detectors(case):
    credgate.reset_detectors()
    try:
        credgate.load_detectors(CUSTOM_SPEC["files"][case["file"]])
        spans = credgate.detect_pii(case["text"], case["types"], context=case.get("context"))
        assert [(s.type, s.value) for s in spans] == [
            (e["type"], e["value"]) for e in case["expect"]
        ]
        for s, e in zip(spans, case["expect"], strict=True):
            if "confidence" in e:
                assert s.confidence == pytest.approx(e["confidence"])
    finally:
        credgate.reset_detectors()


@pytest.mark.parametrize(
    "case", CUSTOM_SPEC["invalid"], ids=[c["id"] for c in CUSTOM_SPEC["invalid"]]
)
def test_invalid_custom_detectors(case):
    credgate.reset_detectors()
    before = {d["id"] for d in credgate.detectors()}
    with pytest.raises(ValueError, match=r"(?i)" + __import__("re").escape(case["error"])):
        credgate.load_detectors(case["file"])
    assert {d["id"] for d in credgate.detectors()} == before  # nothing registered


POLICY_TESTS_SPEC = conformance("policy_tests.yaml")


def test_policy_tests_conformance():
    pol = credgate.Policy.from_dict(POLICY_TESTS_SPEC["policy"])
    results = {r.id: r for r in credgate.run_policy_tests(pol, POLICY_TESTS_SPEC["tests"])}
    for want in POLICY_TESTS_SPEC["results"]:
        r = results[want["id"]]
        assert r.passed == want["passed"], (want["id"], r.problems)
        for p in want.get("problems", []):
            assert any(p in got for got in r.problems), (want["id"], p, r.problems)
        assert len(r.problems) == len(want.get("problems", [])), (want["id"], r.problems)


@pytest.mark.parametrize(
    "case", POLICY_TESTS_SPEC["invalid"], ids=[c["id"] for c in POLICY_TESTS_SPEC["invalid"]]
)
def test_invalid_policy_tests(case):
    pol = credgate.Policy.from_dict(POLICY_TESTS_SPEC["policy"])
    with pytest.raises(ValueError, match=r"(?i)" + __import__("re").escape(case["error"])):
        credgate.run_policy_tests(pol, case["tests"])


PROXY_KEYS_SPEC = conformance("proxy_keys.yaml")


def test_proxy_key_hashes():
    from credgate.proxy_keys import hash_key

    for case in PROXY_KEYS_SPEC["hashes"]:
        assert hash_key(case["key"]) == case["hash"]


@pytest.mark.parametrize(
    "case", PROXY_KEYS_SPEC["files"], ids=[c["id"] for c in PROXY_KEYS_SPEC["files"]]
)
def test_proxy_keys_file(case, tmp_path):
    import datetime as dt
    import json

    from credgate.proxy_keys import list_users, read_keys

    path = tmp_path / "keys.json"
    path.write_text(json.dumps(case["file"]))
    if case.get("invalid"):
        with pytest.raises(ValueError, match=r"keys file|sha256|UTC time"):
            read_keys(path)
        return
    now = dt.datetime.strptime(case["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    assert {r["name"]: r["status"] for r in list_users(path, now=now)} == case["users"]


USERS_SPEC = conformance("users.yaml")


@pytest.mark.parametrize("case", USERS_SPEC["cases"], ids=[c["id"] for c in USERS_SPEC["cases"]])
def test_users_file(case):
    from credgate.users import parse_users

    if case.get("invalid"):
        with pytest.raises(ValueError, match=r"."):
            parse_users(case["file"])
        return
    users = parse_users(case["file"])
    assert {n: users.role_of(n) for n in case["roles"]} == case["roles"]
    assert users.settings == case["settings"]
