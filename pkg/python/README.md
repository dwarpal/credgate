# credgate

Detects personal data before it leaves the machine, with Indian identifiers
built in: Aadhaar (with Verhoeff checksum), Aadhaar Virtual ID, PAN, GSTIN,
voter ID, passport, driving licence, UPI IDs, IFSC, bank accounts, payment
cards, +91 mobile numbers, ABHA, and names and addresses in Latin and Indic
scripts.

The detection rules live in a shared, language-neutral spec, so this package
and the R package `credgate` find exactly the same matches. Part of the
[CredGate](https://github.com/dwarpal/credgate) project; early development.

## Installation

Python 3.11 or later; depends only on `regex` and `PyYAML`.

```sh
pip install "git+https://github.com/dwarpal/credgate#subdirectory=pkg/python"
```

With Nix: `nix build github:dwarpal/credgate#credgate`.

## Usage

```python
import credgate

spans = credgate.detect_pii("Name: Priya Nair; PAN: ABCPN1234K; UPI: priya.n@oksbi")
for s in spans:
    print(s)
# Span(doc=0, start=6, end=16, type='person_name', value='XXXXX Nair', confidence=0.8)
# Span(doc=0, start=23, end=33, type='pan', value='XXXXXX234K', confidence=0.97)
# Span(doc=0, start=40, end=53, type='upi_id', value='XXXXX.X@Xksbi', confidence=0.99)

spans[1].value    # 'ABCPN1234K' - printing masks values, the attribute does not
spans[1].reasons  # "matched PAN pattern; context 'PAN'; holder type: individual"
```

`detect_pii()` takes a string or a list of strings and returns `Span`
objects with the document index, 0-based end-exclusive positions, type, data
class, value, canonical form, confidence and reasons. `span.to_dict()` gives
a JSON-ready dict with the value masked (`reveal=True` to include it).

Context makes generic patterns trustworthy; pass a column name or similar:

```python
credgate.detect_pii("ABC1234567")                      # [] - could be anything
credgate.detect_pii("ABC1234567", context="voter_id")  # voter ID, confidence 0.97
```

Checksums, synthetic test data and your own detectors:

```python
credgate.verhoeff_valid("542229371182")
credgate.synth_indian_pii(5, seed=1)   # synthetic records; never use as anonymised data

credgate.register_detector(credgate.Detector(
    id="employee_id", data_class="internal", label="Employee ID",
    patterns=credgate.bounded("EMP[0-9]{6}"),
))
```

## Command line

```sh
credgate detect notes.txt                      # masked report
credgate detect --lines --json customers.csv   # one JSON object per match
git diff --cached | credgate detect --fail     # non-zero exit if PII is found
credgate detectors                             # list detectors
```

Values are masked unless you pass `--reveal`.

## Limits

Names and addresses are found only next to a cue: an honorific (Shri, Smt,
श्रीमती), a relation (S/o, D/o), a field label (`Name:`, `पता:`) or a
house/village keyword followed by a PIN code. A bare 12-digit number may pass
the Aadhaar checksum by chance and is reported with lower confidence.

## Licence

Apache License 2.0.
