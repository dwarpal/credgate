# credgate (development version)

* Keyed tokens: `cg_vault(key)` makes tokens derived from the identifier
  with a secret key (`[PAN_bpg46o6x465d4]`), so the same identifier gets the
  same token in every vault with that key - across sessions, datasets,
  machines, and Python as well as R. Vaults from parallel workers combine
  with `vault_merge()`; a token standing for two different values is an
  error, never merged silently. `cg_new_token_key()` makes a key and
  `cg_key_fingerprint()` identifies one without revealing it (openssl
  package); keys come from the argument or `CREDGATE_TOKEN_KEY`. Saved keyed
  vaults record the key's fingerprint, never the key, and need the key to
  open (`vault_open(path, key = ...)`). Restore accepts keyed tokens in any
  case, with or without brackets.
* Large data: `scan_pii()` accepts Arrow `Table`s and `Dataset`s and database
  tables from dbplyr (DuckDB, Postgres, SQLite and other DBI databases),
  reading one column at a time in chunks with the same sample as in memory.
  New `redact_parquet()` redacts a Parquet file batch by batch, and
  `redact_query()` redacts a query's result into a database table in
  chunks; with one connection on Postgres or SQLite it writes after reading,
  in one transaction. Tested on DuckDB, SQLite and Postgres. `redact()`, `tokenise()` and `detect_pii()` accept Arrow arrays.
  The packages are optional (Suggests). New vignette "Large data".
* Faster: context keywords, replacements and new vault entries are handled
  for all matches at once rather than one by one. Detection is 1.2-1.9x
  faster, `redact()` up to 3x and `tokenise()` 5-7x; results are unchanged.
* Names in mixed scripts: a Latin honorific, relation or label before a
  Devanagari name ("Smt. सुनीता देवी", "S/o रामेश्वर प्रसाद") and a Devanagari
  one before a Latin name ("श्री Ramesh Kumar") are found. Fixes "Name:"
  followed by a Devanagari name being cut after its first letter, and
  festivals after "श्री" ("श्री राम नवमी") being taken as names.
* `vault_save()` and `vault_open()` save a token vault to a file encrypted
  with a passphrase (libsodium via the sodium package: scrypt and
  XSalsa20-Poly1305) and open it again, in R or in Python. The file reveals
  nothing without the passphrase, is written readable only by its owner,
  and never replaces a file that is not a vault.
* New `tokenise()` and `restore()`, with a vault from `cg_vault()`:
  identifiers become numbered tokens (`[PAN_1]`, `[PERSON_NAME_1]`) and the
  real values can be put back into a model's answer. The same identifier
  gets the same token however it is written; `restore()` accepts tokens with
  other case, spaces or no brackets, and `strict = TRUE` stops on unknown
  ones. The vault lives in memory and prints with values masked.
* Context scoring: the stronger cue wins. A keyword before a match (where
  labels go) beats one after it, and on the same side the nearer one wins.
  So "Aadhaar 5422... for e-KYC; order 519..." stays an Aadhaar number
  (confidence 0.97, reason "farther negative context 'order' ignored"),
  while in "order no 8782..., Aadhaar 5422..." the first number keeps its
  negative context.
* A voter ID format (3 letters, 7 digits) without a nearby keyword is now
  reported at confidence 0.3 instead of dropped; with "voter" or "EPIC"
  nearby it still scores 0.97. New `new_detector()` argument
  `base_without_context` for such patterns.
* An IFSC code next to a number counts as evidence of a bank account, and
  phone words nearby count against it.
* "ji" after a name is a name cue ("Subhash Verma ji", "सुनीता जी").
* "Ms Word", "Shri Ram Navami" and similar software, festival and
  institution names after an honorific are no longer taken as names.
* Benchmark (synthetic test split, confidence 0.5): F1 0.947 to 0.983,
  precision 0.997 to 0.999; see `benchmark/README.md` for caveats.
* Names and addresses are now masked in full wherever values are shown
  (printed spans, `preview()`, `scan_pii()` examples); before, their last
  4 characters were kept, which could show part of a surname or a PIN code.
  Identifiers still keep their last 4 characters, within UIDAI's and PCI
  DSS's display limits.
* New option `credgate.mask = "full"` (or environment variable
  `CREDGATE_MASK=full`) masks every value in full. See `?credgate`.
* New vignette "Using credgate with local LLMs (Ollama, vLLM)", with
  runnable R, Python and shell examples in the repository's `examples/`.
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
* New `cg_evaluate()` and `cg_read_corpus()`: precision, recall and F1 per type
  against labelled JSON Lines documents (exact or overlap matching), so you
  can measure credgate on your own labelled data.
* Detection fixes found by the new benchmark: names no longer run into the
  next sentence ("Smt. X Y. She ..."); labelled addresses end at their PIN
  code; an address ending in a PIN code outranks the PIN inside it; order,
  tracking and reference words lower mobile matches.
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
