"""Policy tests: the default file beside the policy, and `credgate policy
test`. The test semantics are covered by the shared conformance cases."""

from __future__ import annotations

import yaml

import credgate
from credgate.cli import main

POLICY = {
    "policy": "credgate-policy",
    "version": 1,
    "id": "bank",
    "revision": 1,
    "destinations": {"claude": {"tier": "frontier"}},
    "rules": [
        {"id": "ids-tokenised", "when": {"classes": ["identity_strong"]}, "action": "tokenise"}
    ],
    "default_action": "redact",
}
TESTS = {
    "kind": "credgate-policy-tests",
    "version": 1,
    "tests": [
        {
            "id": "pan-tokenised",
            "endpoint": "claude",
            "text": "PAN ABCPE1234F",
            "expect": {"allowed": True, "actions": {"pan": "tokenise"}},
        }
    ],
}


def test_the_tests_file_beside_the_policy_is_found(tmp_path):
    (tmp_path / "bank.yaml").write_text(yaml.safe_dump(POLICY))
    (tmp_path / "bank.tests.yaml").write_text(yaml.safe_dump(TESTS))
    [r] = credgate.run_policy_tests(tmp_path / "bank.yaml")
    assert r.passed
    assert r.id == "pan-tokenised"


def test_the_cli_reports_and_exits_by_outcome(tmp_path, capsys):
    (tmp_path / "bank.yaml").write_text(yaml.safe_dump(POLICY))
    (tmp_path / "bank.tests.yaml").write_text(yaml.safe_dump(TESTS))
    assert main(["policy", "test", "--policy", str(tmp_path / "bank.yaml")]) == 0
    assert "PASS  pan-tokenised" in capsys.readouterr().out

    failing = dict(TESTS, tests=[dict(TESTS["tests"][0], expect={"allowed": False})])
    (tmp_path / "bank.tests.yaml").write_text(yaml.safe_dump(failing))
    assert main(["policy", "test", "--policy", str(tmp_path / "bank.yaml")]) == 1
    out = capsys.readouterr().out
    assert "FAIL  pan-tokenised" in out
    assert "allowed: expected false, got true" in out

    (tmp_path / "bank.tests.yaml").write_text("kind: something-else\n")
    assert main(["policy", "test", "--policy", str(tmp_path / "bank.yaml")]) == 2
    assert "credgate-policy-tests" in capsys.readouterr().err
