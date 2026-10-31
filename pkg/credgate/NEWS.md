# credgate (development version)

* New `scan_pii()` reports, per column of a data frame, which PII types
  occur and in what share of values, using the column name as context
  (a `voter_id` column supports Voter ID matches). Whole numbers are
  scanned too; sampling is evenly spaced and reproducible.
* New `redact()` replaces every detected identifier with a placeholder
  naming its type (`[PAN]`, `[PERSON_NAME]`); `preview()` shows the redacted
  text with each identifier (value masked), its confidence and reasons.
* Fewer false positives: digits joined to a decimal point are no longer read
  as phone numbers (0.9876543210); money words (₹, Rs, crore, balance, ...)
  lower mobile matches; order, tracking and AWB context lowers card matches;
  a number in ABHA's 2-4-4-4 layout is no longer taken for a card.
* Redaction placeholders such as `[ABHA_ADDRESS]` are not re-detected, so
  redacting twice gives the same text.
* Much larger test suite: shared hard-negative cases (30 non-PII texts) and
  documented known false positives in the spec; generated-text invariants,
  checksum mutation, Unicode fuzzing and pathological-input tests.

# credgate 0.1.0

* First release.
* `detect_pii()` finds Indian identifiers (Aadhaar, Aadhaar Virtual ID, PAN,
  GSTIN, voter ID, passport, driving licence), financial identifiers (UPI
  IDs, IFSC codes, bank accounts, payment cards), contact details (mobile
  numbers, email addresses, PIN codes), ABHA health IDs, and names and
  addresses next to an honorific, relation or field label.
* Matches are validated with checksums (Verhoeff, Luhn, GSTIN mod-36),
  scored from surrounding context, normalised across Indic digits, fullwidth
  and invisible characters, and printed with values masked.
* Detection rules are read from a specification shared with the Python
  package (`cg_spec_path()`); `new_detector()` and `register_detector()` add
  your own.
* `synth_indian_pii()` generates synthetic test records.
