# Changelog

## 0.6.0 (2026-11-02)

Governance and discovery: policies per model endpoint, a tamper-evident
audit log, keyed tokens, and a PII inventory across data frames, Spark and
BigQuery. Documentation: https://dwarpal.github.io/credgate/

- Documentation site with the Python API reference, the R package site,
  guides and the shared specification.
- Column names count as labels for card verification codes and ration card
  numbers, which are otherwise found only after a label in the text: in a
  scan, a column named `card_cvv`, `cvv` or `cvc2` reports values that are
  only a 3-4 digit code, and a column named for ration cards reports values
  that are only the number - instead of nothing, or of reading 12-digit
  ration card numbers as Aadhaar numbers. A new detector field,
  `column_label`, defines this (shared spec, R and Python). Found by running
  the inventory against real BigQuery data.
- BigQuery: `TABLESAMPLE` queries are no longer sent with BigQuery's
  `maximumBytesBilled`, which BigQuery checks against the whole table and so
  refused cheap samples of large tables. The dry-run check still applies;
  measured against real BigQuery, it estimates sampled queries to within
  about 1 MB.
- BigQuery: `credgate.bigquery.scan_pii()`, `pii_inventory()` and
  `inventory_dataset()` (every table in a dataset), with the
  google-cloud-bigquery client you pass. BigQuery samples the table
  (`TABLESAMPLE`, billing only the sampled blocks; `sampling="rand"` for
  views) and only the sample is downloaded; only scannable columns are read.
  A dry run checks the cost of every query first and anything estimated
  above `max_bytes` (default 1 GB) is refused before it runs; the limit is
  also sent to BigQuery. New extras: `bigquery`, and `spark` (not in `all`).
- Spark: `scan_pii()` and `pii_inventory()` accept PySpark DataFrames. The
  table is sampled inside the cluster (a seeded random sample of up to
  `sample` rows, `seed = 42` by default) and only the sample reaches the
  driver; the row count is recorded and `sample_method` is `spark-sample`.
  Whole-number columns are cast to text in Spark so long identifiers keep
  every digit; nested columns are recorded but not read. Tested against a
  local Spark (no network).
- PII inventory: `pii_inventory()` scans a table with the `scan_pii()` rules
  and records where PII is - every column, also those where nothing was
  found, with source, table, row count, sample size and method, scan time
  and credgate version; never values. Inventories combine with `+` and are
  saved with `Inventory.write()` as a CSV file that R and Python write
  byte for byte the same; `read_inventory()` reads it. The first step of
  discovery at scale.
- Audit log: an append-only, hash-chained JSON Lines log of policy
  decisions - who, when, which endpoint, policy revision, allowed or blocked,
  and per identifier its type, action and rule; never text or values. With an
  audit key (`CREDGATE_AUDIT_KEY`), identifiers are recorded as keyed hashes;
  card verification codes never are. Verification detects edited, deleted,
  inserted or reordered records and returns the head hash to keep elsewhere.
  R and Python write and verify the same files. `AuditLog`,
  `audit_verify()`, `audit_read()`; `Policy.apply(..., audit=log)`.
- Policies: a YAML policy (the same file in R and Python) decides, per
  destination tier (local, internal, frontier), whether each identifier is
  allowed, redacted or tokenised, or the whole request is blocked; rules can
  target particular endpoints and require combinations (card + CVV + expiry).
  Destinations form the register of model endpoints (tier, provider, URL)
  and can be `blocked`; endpoints not listed receive nothing. Loading is strict - unknown
  fields, tiers, actions or types are errors - and each decision names the
  policy revision and the rule behind every action. `Policy.load()`,
  `Policy.decide()`, `Policy.apply()`, `PolicyError`.
- New detectors: card verification codes (`card_cvv`, a new data class
  `sensitive_auth` that is always masked in full and must never be stored),
  card expiry dates (`card_expiry`), CKYC numbers (`ckyc`, only with a cue such
  as "CKYC" or "KIN"), ration card numbers (`ration_card`, after a ration-card
  label in English or Hindi) and NREGA job card numbers (`nrega_job_card`).
  Card verification codes are recognised only right after their label; dates
  such as "valid till 31/12/2026" are not taken as expiry dates; "RC no."
  (vehicle registration) is not a ration card.
- `synth_indian_pii()` adds `ckyc`, `ration_card`, `nrega_job_card`,
  `card_cvv` and `card_expiry`; existing fields keep their values for a given
  seed.
- Benchmark corpus version 2 includes the new identifiers (test split: F1
  0.980, precision 1.000).
- Keyed tokens: `Vault(key)` makes tokens derived from the identifier with a
  secret key (`[PAN_bpg46o6x465d4]`), so the same identifier gets the same
  token in every vault with that key - across sessions, datasets, machines,
  and R as well as Python. Vaults from parallel workers combine with
  `Vault.merge()`; a token standing for two different values is an error
  (`TokenCollisionError`), never merged silently. `new_token_key()` makes a
  key and `key_fingerprint()` identifies one without revealing it; keys come
  from the argument or `CREDGATE_TOKEN_KEY`. Saved keyed vaults record the
  key's fingerprint, never the key, and need the key to open
  (`Vault.open(path, key=...)`). Restore accepts keyed tokens in any case,
  with or without brackets.

## 0.5.0 (2026-11-01)

Large data - pandas, Polars, Arrow, DuckDB and Parquet - faster detection,
and a fix for a race when credgate is first used from several threads at
once. Upgrade if you call credgate from parallel code.

- **Fixed: detection could silently miss identifiers when its first calls
  ran on several threads at once** (for example inside DuckDB or Polars, or
  a multi-threaded server): the detector registry was visible while still
  being built. It is now built completely before use. Single-threaded use
  was not affected.
- Large data: `redact()`, `tokenise()` and `detect_pii()` accept pandas and
  Polars Series and Arrow arrays and return the same type. New
  `credgate.polars` (`pl.col(...).credgate.redact()` / `.has_pii()`),
  `credgate.duckdb` (`register(con)` adds `cg_redact()` and `cg_has_pii()`)
  and `credgate.arrow` (tables, record-batch streams, `redact_parquet()`),
  with extras `credgate[polars]`, `[arrow]` and `[duckdb]` (which includes
  numpy, needed by DuckDB's Python functions).
- `pip install 'credgate[all]'` installs every optional integration (vault,
  Arrow, Polars, DuckDB).
- `scan_pii()` accepts Polars frames (eager and lazy), Arrow tables and
  datasets and DuckDB relations, reading one column at a time with the same
  sampling as in memory.
- Command line: `credgate redact --parquet IN --column NAME -o OUT` and
  `credgate scan file.parquet`.
- Examples for pandas, Polars, DuckDB, Arrow/Parquet and the command line,
  and a large-data guide (`docs/large-data.md`).
- Faster: all documents in a call are searched in one pass per pattern,
  and text whose characters each normalise to one character skips the
  position map. Detection is 1.1-1.5x faster depending on text length
  (short values gain most); results are identical, which a new test checks
  against searching each document on its own. `normalise()` now also
  returns `map=None` when positions are unchanged (not only when the text
  is unchanged).

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
