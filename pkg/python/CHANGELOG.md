# Changelog

## Unreleased

- Documentation: using credgate with local LLMs (Ollama, vLLM and other
  OpenAI-compatible servers), with runnable examples in `examples/`.
- New `redact()`: replaces every detected identifier with a placeholder
  naming its type (`[PAN]`, `[PERSON_NAME]`); irreversible.
- New `preview()`: shows the redacted text with each identifier (value
  masked), its confidence and reasons, without sending anything.
- New `credgate redact` and `credgate preview` commands.
- Fewer false positives: digits joined to a decimal point are no longer read
  as phone numbers (0.9876543210); money words (₹, Rs, crore, balance, ...)
  lower mobile matches; order, tracking and AWB context lowers card matches;
  a number in ABHA's 2-4-4-4 layout is no longer taken for a card.
- Redaction placeholders such as `[ABHA_ADDRESS]` are not re-detected, so
  redacting twice gives the same text.
- New `evaluate()` / `cg_evaluate()`: precision, recall and F1 per type
  against labelled JSON Lines documents (exact or overlap matching), so you
  can measure credgate on your own labelled data.
- Detection fixes found by the new benchmark: names no longer run into the
  next sentence ("Smt. X Y. She ..."); labelled addresses end at their PIN
  code; an address ending in a PIN code outranks the PIN inside it; order,
  tracking and reference words lower mobile matches.
- Much larger test suite: shared hard-negative cases (30 non-PII texts) and
  documented known false positives in the spec; generated-text invariants,
  checksum mutation, Unicode fuzzing and pathological-input tests.

## 0.2.0 (2026-10-31)

- New `scan_pii()`: reports, per column of a table (a pandas DataFrame or a
  dict of column -> values), which PII types occur and in what share of
  values, using the column name as context. Whole numbers are scanned too;
  sampling is evenly spaced and reproducible. Returns a `ScanReport` that
  prints as a masked table; `to_records()` converts it for pandas.
- New `credgate scan file.csv` command, with `--json`, `--sample`,
  `--min-rate`, `--delimiter` and `--fail` (non-zero exit if any column
  contains PII).

## 0.1.0 (2026-10-31)

First release: `detect_pii()` for Indian identifiers (Aadhaar, Aadhaar VID,
PAN, GSTIN, voter ID, passport, driving licence), financial identifiers
(UPI, IFSC, bank accounts, cards), contact details (mobile, email, PIN
code), ABHA, and cue-based names and addresses; checksum validation,
context scoring, Indic-digit normalisation and masked output; the
`credgate detect` command; `synth_indian_pii()` for synthetic test data.
