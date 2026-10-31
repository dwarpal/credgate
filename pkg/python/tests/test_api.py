"""Edge cases of the public API: argument handling, errors, options."""

from __future__ import annotations

import shutil

import pytest

import credgate
from credgate import Detector, detect_pii
from credgate._spec import read_spec_file
from credgate.detectors import compile_detector


def test_text_can_be_tuple_or_generator():
    assert [s.doc for s in detect_pii(("x", "PAN ABCPE1234F"))] == [1]
    assert [s.doc for s in detect_pii(t for t in ["PAN ABCPE1234F"])] == [0]


def test_detector_subset_and_min_confidence():
    text = "PAN ABCPE1234F, order no 878245671885"
    assert {s.type for s in detect_pii(text, detectors=["pan"])} == {"pan"}
    assert {s.type for s in detect_pii(text)} == {"pan", "aadhaar"}
    assert {s.type for s in detect_pii(text, min_confidence=0.5)} == {"pan"}


def test_window_controls_how_far_context_reaches():
    text = "voter" + " " * 60 + "FSO6231132"
    assert detect_pii(text) == []
    assert [s.type for s in detect_pii(text, window=80)] == ["voter_epic"]


def test_span_to_dict():
    (s,) = detect_pii("PAN ABCPE1234F")
    d = s.to_dict()
    assert d["class"] == "identity_strong"
    assert d["value"] == "XXXXXX234F"
    assert "canonical" not in d
    full = s.to_dict(reveal=True)
    assert full["value"] == full["canonical"] == "ABCPE1234F"


def test_detector_validation():
    with pytest.raises(ValueError, match="base"):
        Detector(id="x", data_class="c", label="x", patterns="x", base=1.5)
    with pytest.raises(TypeError):
        credgate.register_detector("not a detector")


def test_register_overwrite_and_reset():
    try:
        credgate.register_detector(
            Detector(id="pan", data_class="custom", label="Custom PAN", patterns="ZZZ[0-9]{3}"),
            overwrite=True,
        )
        assert [s.data_class for s in detect_pii("ZZZ123")] == ["custom"]
        assert detect_pii("ABCPE1234F") == []
    finally:
        credgate.reset_detectors()
    assert [s.type for s in detect_pii("ABCPE1234F")] == ["pan"]


def test_compiling_a_bad_detector_spec_fails_loudly():
    good = {"id": "x", "class": "c", "label": "X", "patterns": ["x"], "base": 0.5}
    with pytest.raises(ValueError, match="unknown field"):
        compile_detector({**good, "pattens": ["typo"]})
    with pytest.raises(ValueError, match="Unknown fragment"):
        compile_detector({**good, "patterns": ["{{nope}}"]})
    with pytest.raises(ValueError, match="Unknown validator"):
        compile_detector({**good, "validate": ["md5"]})
    with pytest.raises(ValueError, match="Unknown canonical"):
        compile_detector({**good, "canonical": "shout"})


def test_unsupported_spec_version_is_rejected(tmp_path):
    shutil.copy(credgate.spec_path() / "engine.yaml", tmp_path / "engine.yaml")
    text = (tmp_path / "engine.yaml").read_text(encoding="utf-8")
    (tmp_path / "engine.yaml").write_text(
        text.replace("spec_version: 1", "spec_version: 99"), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="Unsupported spec_version 99"):
        read_spec_file("engine.yaml", tmp_path)


@pytest.mark.parametrize(
    ("fn", "value", "expected"),
    [
        (credgate.verhoeff_valid, None, False),
        (credgate.verhoeff_valid, "२३६३", False),  # only ASCII digits are checksummed
        (credgate.verhoeff_check_digit, "", None),
        (credgate.luhn_valid, None, False),
        (credgate.luhn_check_digit, "x", None),
        (credgate.gstin_valid, None, False),
        (credgate.gstin_valid, "27AAPFU0939F1Z", False),
    ],
)
def test_checksum_edge_inputs(fn, value, expected):
    assert fn(value) == expected


def test_synthetic_records_are_valid_and_complete():
    records = credgate.synth_indian_pii(200, seed=5)
    assert len(records) == 200
    assert len({tuple(r) for r in records}) == 1  # same fields everywhere
    for r in records:
        assert credgate.verhoeff_valid(r["aadhaar"])
        assert r["aadhaar"][0] not in "01"
        assert credgate.verhoeff_valid(r["aadhaar_vid"])
        assert credgate.gstin_valid(r["gstin"])
        assert credgate.luhn_valid(r["card"])
        assert r["email"].endswith(("@example.com", "@example.org"))
    assert credgate.synth_indian_pii(3, seed=1) != credgate.synth_indian_pii(3, seed=2)


def test_scan_options():
    data = {"notes": ["PAN ABCPE1234F", "Aadhaar 542229371182", "x", "y"]}
    assert {f.type for f in credgate.scan_pii(data)} == {"pan", "aadhaar"}
    assert {f.type for f in credgate.scan_pii(data, detectors=["pan"])} == {"pan"}
    assert credgate.scan_pii(data, min_rate=0.5) == []
    assert credgate.scan_pii({}) == []


def test_scan_with_pandas():
    pd = pytest.importorskip("pandas")
    frame = pd.DataFrame({"cust_pan": ["ABCPE1234F", None], "mobile": [9876543210, None]})
    report = credgate.scan_pii(frame)
    assert [(f.column, f.type, f.n_sampled) for f in report] == [
        ("cust_pan", "pan", 1),
        ("mobile", "mobile_in", 1),
    ]


def test_evaluate_reads_jsonl_and_validates(tmp_path):
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        '{"id": "a", "text": "PAN: ABCPE1234F", '
        '"spans": [{"start": 5, "end": 15, "type": "pan"}]}\n'
        "\n"
        '{"id": "b", "text": "nothing here", "spans": []}\n',
        encoding="utf-8",
    )
    assert len(credgate.load_corpus(path)) == 2
    report = credgate.evaluate(path)
    assert report[-1].type == "overall"
    assert (report[-1].tp, report[-1].fp, report[-1].fn) == (1, 0, 0)
    assert "Evaluated 2 document(s)" in str(report)
    with pytest.raises(ValueError, match="exact"):
        credgate.evaluate(path, match="fuzzy")
