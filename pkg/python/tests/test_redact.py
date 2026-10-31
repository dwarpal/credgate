from __future__ import annotations

import io

import credgate
from credgate.cli import main


def test_redact_list_keeps_shape_and_none():
    assert credgate.redact(["PAN ABCPE1234F", None, "", "nothing"]) == [
        "PAN [PAN]",
        None,
        "",
        "nothing",
    ]
    assert credgate.redact([]) == []


def test_several_spans_in_one_text():
    assert credgate.redact("PAN ABCPE1234F and PAN XYZPQ9876R") == "PAN [PAN] and PAN [PAN]"


def test_preview_masks_values():
    p = credgate.preview("Name: Priya Nair; PAN: ABCPN1234K")
    text = str(p)
    assert "Name: [PERSON_NAME]; PAN: [PAN]" in text
    assert "ABCPN1234K" not in text
    assert "Priya" not in text
    assert "XXXXXX234K" in text
    assert str(credgate.preview("hello")) == "Nothing would be redacted."


def test_cli_redact_and_preview(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("PAN ABCPE1234F\nok\n"))
    assert main(["redact"]) == 0
    assert capsys.readouterr().out == "PAN [PAN]\nok\n"
    monkeypatch.setattr("sys.stdin", io.StringIO("PAN ABCPE1234F\n"))
    assert main(["preview"]) == 0
    out = capsys.readouterr().out
    assert "PAN [PAN]" in out
    assert "ABCPE1234F" not in out
