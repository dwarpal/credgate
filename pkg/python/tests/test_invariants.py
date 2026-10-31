"""Properties that must hold for any input, checked on generated text:
synthetic records in many layouts and languages, mutated identifiers, random
Unicode, and pathological inputs."""

from __future__ import annotations

import random
import time

import pytest

import credgate
from credgate import detect_pii, redact

RECORDS = credgate.synth_indian_pii(150, seed=2026)

# (field, expected type, templates); {v} is the value. Templates cover
# English, Hindi, Hinglish, CSV-, JSON- and form-like layouts.
CASES = [
    (
        "aadhaar",
        "aadhaar",
        ["Aadhaar: {v}", "आधार नंबर {v} है", "mera aadhaar {v} hai", '{{"aadhaar": "{v}"}}'],
    ),
    ("pan", "pan", ["PAN: {v}", "Mera PAN {v} hai", "pan={v};", "{v}"]),
    ("gstin", "gstin", ["GSTIN {v}", "GST no. {v} registered", "{v}"]),
    ("card", "card", ["card {v}", "Debit card number: {v}."]),
    ("mobile", "mobile_in", ["Mobile: {v}", "mobile no. {v} pe call karo", "फोन {v}", "{v},Pune"]),
    ("email", "email", ["Email {v}", "<{v}>", "mail: {v}."]),
    ("upi_id", "upi_id", ["UPI: {v}", "pay to {v} via GPay"]),
    ("ifsc", "ifsc", ["IFSC {v}", "branch code {v}"]),
    ("bank_account", "bank_account", ["A/c no {v}", "account: {v}", "खाता {v}"]),
    ("abha_number", "abha_number", ["ABHA {v}", "{v}"]),
    ("abha_address", "abha_address", ["{v}", "ABHA address: {v}"]),
    ("voter_epic", "voter_epic", ["Voter ID {v}", "EPIC no {v}"]),
    ("passport", "passport", ["Passport {v}", "passport no. {v}"]),
    ("driving_licence", "driving_licence", ["DL no {v}", "Driving licence: {v}"]),
    ("name", "person_name", ["Name: {v}", "Shri {v}", "S/o {v}"]),
    ("name_hi", "person_name", ["नाम: {v}"]),
    ("address", "address", ["lives at {v}.", "Address: {v}"]),
]


def generated_texts():
    for rec in RECORDS:
        for field, type_, templates in CASES:
            for template in templates:
                yield template.format(v=rec[field]), rec[field], type_


def check_span_invariants(text: str, spans):
    previous_end = -1
    for s in spans:
        assert 0 <= s.start < s.end <= len(text)
        assert text[s.start : s.end] == s.value
        assert 0 < s.confidence <= 1
        assert s.canonical
        assert s.reasons.startswith("matched ")
        assert s.start >= previous_end, "spans overlap or are unordered"
        previous_end = s.end


def test_every_generated_identifier_is_found_with_exact_value():
    missed = []
    for text, value, type_ in generated_texts():
        spans = detect_pii(text)
        if not any(s.type == type_ and s.value == value for s in spans):
            missed.append((type_, text))
    assert missed == []


def test_span_and_redaction_invariants_on_generated_text():
    for text, _, _ in generated_texts():
        spans = detect_pii(text)
        check_span_invariants(text, spans)
        red = redact(text)
        assert redact(red) == red, "redaction must be idempotent"
        for s in spans:
            if len(s.value) >= 4:
                assert s.value not in red
        assert credgate.preview(text).redacted == [red]


def test_multi_document_results_equal_single_document_results():
    texts = [t for t, _, _ in generated_texts()][:300]
    together = detect_pii(texts)
    for i, t in enumerate(texts):
        alone = [(s.start, s.end, s.type, s.confidence) for s in detect_pii(t)]
        mine = [(s.start, s.end, s.type, s.confidence) for s in together if s.doc == i]
        assert mine == alone


@pytest.mark.parametrize(
    ("field", "type_", "prefix"),
    [("aadhaar", "aadhaar", "Aadhaar "), ("gstin", "gstin", "GSTIN "), ("card", "card", "card ")],
)
def test_single_character_mutations_are_never_reported(field, type_, prefix):
    rng = random.Random(7)
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" if field == "gstin" else "0123456789"
    for rec in RECORDS:
        v = rec[field]
        pos = rng.randrange(len(v))
        new = rng.choice([c for c in alphabet if c != v[pos]])
        mutated = v[:pos] + new + v[pos + 1 :]
        found = [s for s in detect_pii(prefix + mutated) if s.type == type_]
        assert found == [], (v, mutated)


# Characters mixed at random: ASCII, the invisible/dash/fullwidth/Indic-digit
# code points that normalisation handles, Devanagari and Tamil letters, an
# emoji, a combining accent and currency signs.
FUZZ_POOL = [
    *"abcXYZ0123456789 .,-:/@_+#\n\t",
    *map(chr, [0x200B, 0x200D, 0xFEFF, 0x00AD, 0x2013, 0xFF11, 0x0966, 0x096F, 0x0BE6]),
    *map(chr, range(0x0905, 0x0915)),  # Devanagari vowels
    *map(chr, range(0x0B85, 0x0B8F)),  # Tamil vowels
    *map(chr, [0x1F600, 0x0301, 0x20AC, 0x20B9]),
]


def test_random_unicode_never_crashes_and_keeps_invariants():
    rng = random.Random(42)
    for _ in range(500):
        text = "".join(rng.choice(FUZZ_POOL) for _ in range(rng.randint(0, 120)))
        spans = detect_pii(text)
        check_span_invariants(text, spans)
        norm = credgate.normalise(text)
        if norm.map is not None:
            assert len(norm.map) == len(norm.text)
            assert list(norm.map) == sorted(norm.map)
            assert all(0 <= i < len(text) for i in norm.map)
        assert redact(redact(text)) == redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "1" * 50_000,
        "9876543210 " * 5_000,
        "Name: " * 10_000,
        "Shri " * 10_000,
        "A" * 100_000,
        "Address: " + "x" * 50_000,
        "House No 1, " * 5_000,
        "₹" * 20_000,
        "आधार " * 10_000,
        "@" * 20_000 + "ybl",
    ],
    ids=[
        "digits",
        "mobiles",
        "labels",
        "honorifics",
        "letters",
        "long-address",
        "house-keywords",
        "rupee",
        "devanagari",
        "at-signs",
    ],
)
def test_pathological_inputs_finish_quickly(text):
    t0 = time.perf_counter()
    spans = detect_pii(text)
    elapsed = time.perf_counter() - t0
    check_span_invariants(text, spans)
    assert elapsed < 20, f"took {elapsed:.1f}s"
