from __future__ import annotations

import io
import json

from credgate.cli import main


def test_detect_file_masks_by_default(tmp_path, capsys):
    f = tmp_path / "notes.txt"
    f.write_text("Name: Priya Nair\nPAN ABCPE1234F\n", encoding="utf-8")
    assert main(["detect", str(f)]) == 0
    out = capsys.readouterr().out
    assert "ABCPE1234F" not in out
    assert "XXXXXX234F" in out
    assert "person_name" in out


def test_detect_lines_json_reveal(tmp_path, capsys):
    f = tmp_path / "data.csv"
    f.write_text("id,note\n1,PAN ABCPE1234F\n", encoding="utf-8")
    assert main(["detect", "--lines", "--json", "--reveal", str(f)]) == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    record = json.loads(line)
    assert record["line"] == 2
    assert record["type"] == "pan"
    assert record["value"] == "ABCPE1234F"
    assert record["canonical"] == "ABCPE1234F"


def test_fail_flag_and_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("Aadhaar: 542229371182"))
    assert main(["detect", "--fail"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("nothing to see"))
    assert main(["detect", "--fail"]) == 0


def test_detectors_and_spec_path(capsys):
    assert main(["detectors"]) == 0
    assert "aadhaar" in capsys.readouterr().out
    assert main(["spec-path"]) == 0
    assert capsys.readouterr().out.strip().endswith("spec")
