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
