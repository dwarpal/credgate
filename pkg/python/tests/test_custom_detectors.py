"""Custom detectors from YAML files: loading rules, policies that name them,
and the command line. The detection results themselves are covered by the
shared conformance cases (spec/conformance/custom_detectors.yaml)."""

from __future__ import annotations

import json

import pytest
import yaml

import credgate
from credgate.cli import main

LOAN = {
    "kind": "credgate-detectors",
    "version": 1,
    "detectors": [
        {
            "id": "loan_account",
            "class": "financial",
            "label": "Loan account number",
            "patterns": ["LN[0-9]{10}"],
            "bounded": True,
            "context": r"loan|\ba/c\b",
            "base": 0.6,
            "base_without_context": 0.4,
            "examples": {"match": ["Loan a/c LN0012345678"], "no_match": ["LN00123"]},
        }
    ],
}


@pytest.fixture(autouse=True)
def fresh_registry():
    credgate.reset_detectors()
    yield
    credgate.reset_detectors()


def _ids():
    return {d["id"] for d in credgate.detectors()}


def test_a_file_registers_everything_or_nothing(tmp_path):
    two = json.loads(json.dumps(LOAN))
    second = dict(two["detectors"][0], id="emp_code", patterns=["EMP[0-9]{6}"])
    second["examples"] = {"match": ["EMP12345"]}  # fails: only 5 digits
    two["detectors"].append(second)
    with pytest.raises(ValueError, match="EMP12345"):
        credgate.load_detectors(two)
    assert "loan_account" not in _ids()  # the good one was not registered either


def test_loading_the_same_file_again_changes_nothing(tmp_path):
    path = tmp_path / "bank.yaml"
    path.write_text(yaml.safe_dump(LOAN))
    assert credgate.load_detectors(path) == ["loan_account"]
    assert credgate.load_detectors(path) == ["loan_account"]


def test_a_different_definition_needs_replace(tmp_path):
    credgate.load_detectors(LOAN)
    changed = json.loads(json.dumps(LOAN))
    changed["detectors"][0]["base"] = 0.7
    with pytest.raises(ValueError, match="already registered"):
        credgate.load_detectors(changed)
    assert credgate.load_detectors(changed, replace=True) == ["loan_account"]
    spans = credgate.detect_pii("Loan a/c LN0012345678", ["loan_account"])
    assert spans[0].confidence == pytest.approx(0.94)  # 0.7 + 0.3 * 0.8


def test_code_registered_detectors_cannot_be_replaced_by_a_file():
    credgate.register_detector(
        credgate.Detector(id="loan_account", data_class="financial", label="x", patterns=["Z"])
    )
    with pytest.raises(ValueError, match="already registered"):
        credgate.load_detectors(LOAN)


def test_a_policy_names_its_detector_files(tmp_path):
    (tmp_path / "detectors").mkdir()
    (tmp_path / "detectors" / "bank.yaml").write_text(yaml.safe_dump(LOAN))
    policy = {
        "policy": "credgate-policy",
        "version": 1,
        "id": "bank",
        "revision": 1,
        "detectors": ["detectors/bank.yaml"],  # relative to the policy file
        "destinations": {"claude": {"tier": "frontier"}},
        "rules": [
            {"id": "loans-tokenised", "when": {"types": ["loan_account"]}, "action": "tokenise"}
        ],
        "default_action": "allow",
    }
    (tmp_path / "bank-policy.yaml").write_text(yaml.safe_dump(policy))
    p = credgate.Policy.load(tmp_path / "bank-policy.yaml")
    d = p.apply("Loan a/c LN0012345678 overdue", "claude", vault=credgate.Vault())
    assert d.texts == ["Loan a/c [LOAN_ACCOUNT_1] overdue"]
    assert [m.rule for m in d.matches] == ["loans-tokenised"]


def test_a_policy_with_a_missing_or_bad_detector_file_does_not_load(tmp_path):
    policy = {
        "policy": "credgate-policy",
        "version": 1,
        "id": "bank",
        "revision": 1,
        "detectors": ["missing.yaml"],
        "destinations": {"claude": {"tier": "frontier"}},
        "rules": [],
        "default_action": "allow",
    }
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(policy))
    with pytest.raises(credgate.PolicyError, match=r"missing\.yaml"):
        credgate.Policy.load(tmp_path / "p.yaml")
    policy["detectors"] = "bank.yaml"
    with pytest.raises(credgate.PolicyError, match="list"):
        credgate.Policy.from_dict(policy)


def test_the_cli_loads_custom_detectors(tmp_path, capsys, monkeypatch):
    path = tmp_path / "bank.yaml"
    path.write_text(yaml.safe_dump(LOAN))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("Loan a/c LN0012345678"))
    assert main(["redact", "--detectors", str(path)]) == 0
    assert capsys.readouterr().out.strip() == "Loan a/c [LOAN_ACCOUNT]"
    assert main(["detectors", "--detectors", str(path)]) == 0
    assert "loan_account" in capsys.readouterr().out
    bad = json.loads(json.dumps(LOAN))
    bad["detectors"][0]["examples"]["no_match"] = ["Loan LN0012345678"]
    path.write_text(yaml.safe_dump(bad))
    credgate.reset_detectors()
    assert main(["detectors", "--detectors", str(path)]) == 2
    assert "should not match" in capsys.readouterr().err
