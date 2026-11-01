from __future__ import annotations

import pytest

import credgate
from credgate.cli import main


class FakeFrame:
    """Minimal pandas-like table: .columns and column access."""

    def __init__(self, data):
        self._data = data
        self.columns = list(data)

    def __getitem__(self, key):
        return self._data[key]


def test_numbers_are_scanned_when_whole():
    report = credgate.scan_pii(
        {"mobile": [9876543210, 8826781145.0, 12.5, float("nan"), None, True]}
    )
    (finding,) = report
    assert finding.type == "mobile_in"
    assert finding.n_sampled == 2  # 12.5, NaN, None and True are skipped
    assert finding.n_full == 2


def test_pandas_like_input_and_records():
    frame = FakeFrame({"cust_pan": ["ABCPE1234F", "AAACR5055K"], "n": [1, 2]})
    report = credgate.scan_pii(frame)
    assert [f.column for f in report] == ["cust_pan"]
    assert report.to_records()[0]["class"] == "identity_strong"
    assert report.n_columns == 2


def test_report_prints_masked_examples():
    report = credgate.scan_pii({"cust_pan": ["ABCPE1234F"]})
    text = str(report)
    assert "ABCPE1234F" not in text
    assert "XXXXXX234F" in text
    assert "no PII found" in str(credgate.scan_pii({"x": ["hello"]}))


def test_invalid_input():
    with pytest.raises(TypeError, match="or a mapping of column"):
        credgate.scan_pii(["not", "a", "table"])
    with pytest.raises(ValueError, match="positive whole number"):
        credgate.scan_pii({"x": ["a"]}, sample=0)


def test_cli_scan(tmp_path, capsys):
    f = tmp_path / "customers.csv"
    f.write_text(
        "cust_pan,notes\nABCPE1234F,ok\nAAACR5055K,Aadhaar 542229371182\n", encoding="utf-8"
    )
    assert main(["scan", str(f), "--fail"]) == 1
    out = capsys.readouterr().out
    assert "cust_pan" in out
    assert "ABCPE1234F" not in out
    assert main(["scan", str(f), "--json"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2


def test_custom_detector_with_column_label():
    det = credgate.Detector(
        id="staff_pin",
        data_class="sensitive_auth",
        label="Staff PIN",
        patterns=[r"(?i:staff pin)\s*(?<value>[0-9]{4})"],
        capture="value",
        base=0.9,
        column_label=r"\bstaff pin\b",
        column_patterns=[r"^[0-9]{4}$"],
    )
    credgate.register_detector(det)
    try:
        found = credgate.scan_pii({"staff_pin": ["4821", "0912"], "other": ["4821", "0912"]})
        assert [(f.column, f.type, f.n_full) for f in found] == [("staff_pin", "staff_pin", 2)]
    finally:
        credgate.reset_detectors()
    with pytest.raises(ValueError, match="go together"):
        credgate.Detector(id="x", data_class="c", label="x", patterns=["x"], column_label="x")
