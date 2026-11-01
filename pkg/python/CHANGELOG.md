# Changelog

## 0.4.0 (2026-11-01)

Reversible tokenisation with encrypted vault files, fuller masking, and
better accuracy (synthetic benchmark F1 0.947 to 0.983).

- Names in mixed scripts: a Latin honorific, relation or label before a
  Devanagari name ("Smt. सुनीता देवी", "S/o रामेश्वर प्रसाद") and a Devanagari
  one before a Latin name ("श्री Ramesh Kumar") are found. Fixes "Name:"
  followed by a Devanagari name being cut after its first letter, and
  festivals after "श्री" ("श्री राम नवमी") being taken as names.
- `Vault.save()` and `Vault.open()` save a token vault to a file encrypted
  with a passphrase (libsodium via PyNaCl, `pip install 'credgate[vault]'`:
  scrypt and XSalsa20-Poly1305) and open it again, in Python or in R. The
  file reveals nothing without the passphrase, is written readable only by
  its owner, and never replaces a file that is not a vault.
- New `tokenise()` and `restore()`, with a `Vault`: identifiers become
  numbered tokens (`[PAN_1]`, `[PERSON_NAME_1]`) and the real values can be
  put back into a model's answer. The same identifier gets the same token
  however it is written; `restore()` accepts tokens with other case, spaces
  or no brackets, and `strict=True` raises `UnknownTokenError` on unknown
  ones. The vault lives in memory and prints with values masked.
- Context scoring: the stronger cue wins. A keyword before a match (where
  labels go) beats one after it, and on the same side the nearer one wins.
  So "Aadhaar 5422... for e-KYC; order 519..." stays an Aadhaar number
  (confidence 0.97, reason "farther negative context 'order' ignored"),
  while in "order no 8782..., Aadhaar 5422..." the first number keeps its
  negative context.
- A voter ID format (3 letters, 7 digits) without a nearby keyword is now
  reported at confidence 0.3 instead of dropped; with "voter" or "EPIC"
  nearby it still scores 0.97. New `Detector` field `base_without_context`
  for such patterns.
- An IFSC code next to a number counts as evidence of a bank account, and
  phone words nearby count against it.
- "ji" after a name is a name cue ("Subhash Verma ji", "सुनीता जी").
- "Ms Word", "Shri Ram Navami" and similar software, festival and
  institution names after an honorific are no longer taken as names.
- Benchmark (synthetic test split, confidence 0.5): F1 0.947 to 0.983,
  precision 0.997 to 0.999; see `benchmark/README.md` for caveats.
- Names and addresses are now masked in full wherever values are shown
  (`repr` and `to_dict()` of spans, `preview()`, `scan_pii()` examples, the
  command line); before, their last 4 characters were kept, which could show
  part of a surname or a PIN code. Identifiers still keep their last 4
  characters, within UIDAI's and PCI DSS's display limits.
- New `set_mask("full")` (or environment variable `CREDGATE_MASK=full`)
  masks every value in full; `mask_value()` takes the value's class and an
  optional mode.

## 0.3.1 (2026-10-31)

- Documentation only: the README (shown on PyPI) lists where Microsoft
  Presidio does better than credgate, states that the benchmark corpus is
  synthetic and included in the repository, and that the comparison is
  independent. No code changes.

## 0.3.0 (2026-10-31)

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
- New `evaluate()` and `load_corpus()`: precision, recall and F1 per type
  against labelled JSON Lines documents (exact or overlap matching), so you
  can measure credgate on your own labelled data.
- Published accuracy benchmark on a synthetic Indian-context corpus and a
  comparison with Microsoft Presidio (README, "How it compares").
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
