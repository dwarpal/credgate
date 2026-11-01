from __future__ import annotations

import random

import pytest

import credgate
from credgate import Detector, bounded, detect_pii


def test_normalise_ascii_passes_through():
    n = credgate.normalise("plain text")
    assert n.text == "plain text"
    assert n.map is None
    assert credgate.normalise(None).text == ""


def test_normalise_indic_digits_and_invisibles():
    n = credgate.normalise("आधार २३४५")
    assert n.text == "आधार 2345"
    for zero in (0x09E6, 0x0AE6, 0x0BE6, 0x0C66, 0x06F0):
        assert credgate.normalise("".join(chr(zero + d) for d in (2, 3, 4, 5))).text == "2345"
    n = credgate.normalise("AB\u200bC\u2013\uff11\uff12")  # zero-width space, en dash, fullwidth 12
    assert n.text == "ABC-12"
    assert n.map == (0, 1, 3, 4, 5, 6)


def test_verhoeff_catches_single_digit_errors_and_swaps():
    rng = random.Random(3)
    ids = [r["aadhaar"] for r in credgate.synth_indian_pii(200, seed=3)]
    assert all(credgate.verhoeff_valid(x) for x in ids)
    for x in ids:
        pos = rng.randrange(12)
        changed = x[:pos] + str((int(x[pos]) + rng.randint(1, 9)) % 10) + x[pos + 1 :]
        assert not credgate.verhoeff_valid(changed)
        if x[4] != x[5]:
            assert not credgate.verhoeff_valid(x[:4] + x[5] + x[4] + x[6:])


def test_every_synthetic_identifier_is_found():
    records = credgate.synth_indian_pii(100, seed=42)
    cases = {
        "aadhaar": ("aadhaar", "Aadhaar: ", 0.9),
        "aadhaar_vid": ("aadhaar_vid", "VID: ", 0.9),
        "pan": ("pan", "PAN: ", 0.9),
        "gstin": ("gstin", "GSTIN: ", 0.9),
        "card": ("card", "card: ", 0.9),
        "voter_epic": ("voter_epic", "Voter ID: ", 0.9),
        "passport": ("passport", "Passport: ", 0.9),
        "driving_licence": ("driving_licence", "DL no: ", 0.9),
        "mobile": ("mobile_in", "Mobile: ", 0.9),
        "email": ("email", "Email: ", 0.9),
        "upi_id": ("upi_id", "UPI: ", 0.9),
        "ifsc": ("ifsc", "IFSC: ", 0.9),
        "bank_account": ("bank_account", "A/c no: ", 0.9),
        "abha_number": ("abha_number", "ABHA: ", 0.9),
        "abha_address": ("abha_address", "ABHA address: ", 0.9),
        "pincode": ("pincode", "PIN: ", 0.9),
        "name": ("person_name", "Name: ", 0.8),
        "name_hi": ("person_name", "नाम: ", 0.8),
        "address": ("address", "lives at ", 0.8),
    }
    for column, (type_, prefix, min_conf) in cases.items():
        values = [r[column] for r in records]
        spans = [
            s for s in detect_pii([f"Customer {prefix}{v}." for v in values]) if s.type == type_
        ]
        assert [s.value for s in spans] == values, column
        assert all(s.confidence >= min_conf for s in spans), column


def test_multiple_documents_none_and_empty():
    spans = detect_pii(["nothing here", "PAN ABCPE1234F", None])
    assert [s.doc for s in spans] == [1]
    assert detect_pii([]) == []
    assert [s.doc for s in detect_pii("PAN ABCPE1234F")] == [0]


def test_context_per_document():
    spans = detect_pii(["ABC1234567", "ABC1234567"], context=["voter_id", None])
    assert [s.doc for s in spans] == [0]
    with pytest.raises(ValueError, match="one per document"):
        detect_pii(["a", "b"], context=["x"])


def test_repr_and_to_dict_mask_values():
    (s,) = detect_pii("PAN ABCPE1234F")
    assert "ABCPE1234F" not in repr(s)
    assert "XXXXXX234F" in repr(s)
    assert s.to_dict()["value"] == "XXXXXX234F"
    assert "canonical" not in s.to_dict()
    assert s.to_dict(reveal=True)["value"] == "ABCPE1234F"
    assert s.to_dict()["class"] == "identity_strong"


def test_mask_value_short_values():
    assert credgate.mask_value("AB12") == "XX12"
    assert credgate.mask_value("1") == "1"


def test_names_and_addresses_are_masked_in_full():
    assert credgate.mask_value("Mohan Lal", "personal") == "XXXXX XXX"
    spans = detect_pii("Shri Mohan Lal, House No 7, Civil Lines, Jaipur 302006")
    for s in spans:
        assert s.data_class == "personal"
        assert not any(ch.isalnum() and ch != "X" for ch in s.to_dict()["value"])
    assert "Lal" not in str(credgate.preview("Shri Mohan Lal, PAN ABCPE1234F"))
    report = credgate.scan_pii({"remarks": ["Shri Mohan Lal called"]})
    assert report[0].example == "XXXXX XXX"


@pytest.fixture
def mask_reset(monkeypatch):
    monkeypatch.delenv("CREDGATE_MASK", raising=False)
    yield monkeypatch
    credgate.set_mask(None)


def test_full_mask_mode(mask_reset):
    credgate.set_mask("full")
    assert credgate.mask_value("ABCPE1234F") == "XXXXXXXXXX"
    (s,) = detect_pii("PAN ABCPE1234F")
    assert s.to_dict()["value"] == "XXXXXXXXXX"
    assert "234F" not in repr(s)
    assert "234F" not in str(credgate.preview("PAN ABCPE1234F"))
    assert credgate.scan_pii({"cust_pan": ["ABCPE1234F"]})[0].example == "XXXXXXXXXX"
    assert s.to_dict(reveal=True)["value"] == "ABCPE1234F"
    credgate.set_mask("partial")
    assert credgate.mask_value("ABCPE1234F") == "XXXXXX234F"


def test_full_mask_from_environment(mask_reset):
    mask_reset.setenv("CREDGATE_MASK", "full")
    assert credgate.mask_value("ABCPE1234F") == "XXXXXXXXXX"
    credgate.set_mask("partial")  # explicit setting wins
    assert credgate.mask_value("ABCPE1234F") == "XXXXXX234F"
    credgate.set_mask(None)
    mask_reset.setenv("CREDGATE_MASK", "nope")
    with pytest.raises(ValueError, match="CREDGATE_MASK"):
        credgate.mask_value("ABCPE1234F")


def test_mask_mode_is_validated():
    with pytest.raises(ValueError, match="partial, full"):
        credgate.set_mask("last4")
    with pytest.raises(ValueError, match="partial, full"):
        credgate.mask_value("x", mode="none")
    assert credgate.mask_value("ABCPE1234F", mode="full") == "XXXXXXXXXX"


def test_user_detectors_can_be_registered():
    try:
        credgate.register_detector(
            Detector(
                id="emp_id",
                data_class="internal",
                label="Employee ID",
                patterns=bounded("EMP[0-9]{6}"),
            )
        )
        assert "emp_id" in [d["id"] for d in credgate.detectors()]
        assert [s.type for s in detect_pii("EMP123456")] == ["emp_id"]
        with pytest.raises(ValueError, match="already registered"):
            credgate.register_detector(
                Detector(id="emp_id", data_class="x", label="x", patterns="x")
            )
    finally:
        credgate.reset_detectors()
    assert "emp_id" not in [d["id"] for d in credgate.detectors()]


def test_unknown_detector_id():
    with pytest.raises(ValueError, match="Unknown detector"):
        detect_pii("x", detectors=["nope"])


def test_synth_is_reproducible_and_leaves_global_rng_alone():
    random.seed(7)
    before = random.random()
    random.seed(7)
    a = credgate.synth_indian_pii(5, seed=99)
    assert random.random() == before
    assert a == credgate.synth_indian_pii(5, seed=99)
