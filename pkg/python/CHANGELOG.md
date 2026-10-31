# Changelog

## Unreleased

- New `redact()`: replaces every detected identifier with a placeholder
  naming its type (`[PAN]`, `[PERSON_NAME]`); irreversible.
- New `preview()`: shows the redacted text with each identifier (value
  masked), its confidence and reasons, without sending anything.
- New `credgate redact` and `credgate preview` commands.

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
