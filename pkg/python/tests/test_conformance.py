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
