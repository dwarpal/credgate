from __future__ import annotations

import io
import json

import pytest

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


def test_detect_options_and_multiple_files(tmp_path, capsys):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("order no 878245671885", encoding="utf-8")
    b.write_text("ABC1234567", encoding="utf-8")
    assert main(["detect", str(a), str(b)]) == 0
    assert "aadhaar" in capsys.readouterr().out
    assert main(["detect", "--min-confidence", "0.5", str(a)]) == 0
    assert capsys.readouterr().out == ""
    assert main(["detect", "--context", "voter id", str(b)]) == 0
    assert "voter_epic" in capsys.readouterr().out


def test_scan_delimiter_sample_and_empty(tmp_path, capsys):
    f = tmp_path / "data.csv"
    f.write_text("id;pan\n1;ABCPE1234F\n2;none\n3;AAACR5055K\n", encoding="utf-8")
    assert main(["scan", "--delimiter", ";", "--json", str(f)]) == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    record = json.loads(line)
    assert (record["column"], record["n_sampled"], record["n_matched"]) == ("pan", 3, 2)
    assert main(["scan", "--delimiter", ";", "--sample", "1", "--json", str(f)]) == 0
    assert json.loads(capsys.readouterr().out)["n_sampled"] == 1
    empty = tmp_path / "empty.csv"
    empty.write_text("", encoding="utf-8")
    assert main(["scan", str(empty)]) == 0
    assert "empty file" in capsys.readouterr().out


def test_detectors_lists_every_builtin(capsys):
    assert main(["detectors"]) == 0
    assert len(capsys.readouterr().out.strip().splitlines()) == 19


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("credgate ")
