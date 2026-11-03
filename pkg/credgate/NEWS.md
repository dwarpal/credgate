# credgate (development version)

* A policy owns its custom detectors: `cg_policy()` compiles the files a
  policy names for that policy and no longer registers them for other calls
  (use `load_detectors()` for that), as in Python, so another revision
  never changes what a loaded policy detects.

* The policy editor has a Detectors tab, a workbench for custom detector
  files: write a detector with a form or edit a file the policy names (or
  a new one beside it), see live
  what it finds in sample text and whether each example holds, and save -
  only a file that loads, which is then loaded and, if new, added to the
  policy's `detectors` list.

* The policy editor's Try it explains its result: the confidence of each
  match and why it was found, and the text that looked like an identifier
  but was not reported, with the reason (a failed checksum, a missing
  keyword the type needs, a confidence below the minimum, a more confident
  overlapping match). A slider changes the policy's minimum confidence from
  there.

* Policy tests: `run_policy_tests()` runs sample requests kept beside a
  policy (`bank-default.tests.yaml`) and checks what the policy does with
  them - allowed or blocked, the blocking rules, the action for each type,
  types that must not be found, the exact text sent. The policy editor has a
  Tests tab that runs them against the draft on every change, a "Save as a
  test" button in Try it, and refuses to save while a test fails unless
  "Save anyway" is ticked with a reason, which the change log records.
  Python reads the same files (`credgate policy test` for CI).

* Columns named for names (`customer_name`, `nominee`, `नाम`, ...) and for
  addresses (`permanent_address`, `addr_line1`, `पता`, ...) - or values given
  `context = "customer name"` - are read as names and addresses, in any
  letter case or script. Only whole labels count: `product_name` and
  `email_address` do not.

* Custom detectors from a YAML file: `load_detectors()` reads an
  organisation's own formats in the same fields as the built-in detectors,
  with `examples` that must and must not match, checked whenever the file is
  loaded; a file is refused, and nothing registered, if anything is wrong.
  A policy's `detectors` list loads files relative to the policy, and
  `cg_policy()` takes `dir` for a policy given as a list. The policy editor
  keeps the list when saving. Python reads the same files.

* `audit_record()` (and `policy_apply(..., audit = )`) creates the audit
  log's folder if it does not exist yet, as the Python package does; it
  failed with "cannot open the connection" before.
* `cg_audit_log()` documents that one R process at a time should write a
  given log: R has no file locks. Give each process its own file; Python
  processes (such as the proxy's workers) can share one.
* Policy editor: `policy_editor()` is a Shiny app for InfoSec to change a
  policy without editing YAML. It edits endpoints and rules (in order, since
  the first matching rule decides), tries sample text against the unsaved
  policy, shows the changes before saving, and saves only a policy that
  loads. `policy_write()` saves a policy in a fixed layout, raises its
  revision and appends to a hash-chained change log
  (`<stem>.changes.jsonl`): who, when, why and what changed.
  `policy_diff()` lists the changes between two policies and
  `policy_changes()` reads the log and checks its chain. Comments in a
  policy file are not kept when it is saved. `shiny` and `bslib` are
  suggested, not required.
* Audit log rotation and retention: with rotation, each month's records go
  to their own file (`<stem>.YYYY-MM.jsonl`) and the hash chain runs on
  across files; `audit_verify()` and `audit_read()` cover all of them, and a
  removed, renamed or altered month is detected. `audit_prune()` removes
  months past the retention period (default 5 years, at least 1): only from
  the oldest end, never the active file, never from a log that fails
  verification; removed months are recorded in `<stem>.pruned.json`, from
  which the rest still verifies. Several writers rotate safely. R and
  Python write and verify the same rotated logs. Audit files are created
  private to the account writing them (`0600`).
  `cg_audit_log(..., rotate = TRUE)`; `audit_record()` takes a `time`.
* Whole-database inventories: `inventory_database()` scans every table of a
  database through a connection (SQLAlchemy in Python, DBI in R): Postgres,
  DuckDB, SQLite, MySQL, IBM Db2 and others. Each table is sampled by the
  database where it can (`TABLESAMPLE SYSTEM` in Postgres and Db2, a
  reservoir sample in DuckDB), otherwise its first rows are read (`sample_method`
  `first-rows`); only text and number columns are read. With an inventory
  file, an interrupted run continues where it stopped and later runs rescan
  only tables whose row count changed or whose scan is older than
  `max_age` days. Tables that cannot be read are reported, not fatal.
* `n_rows` in R inventories is now a double: tables can have more rows
  than an R integer holds. `BIGINT` values from databases (`integer64`) are
  scanned with every digit.
* Column names count as labels for card verification codes and ration card
  numbers, which are otherwise found only after a label in the text: in a
  scan, a column named `card_cvv`, `cvv` or `cvc2` reports values that are
  only a 3-4 digit code, and a column named for ration cards reports values
  that are only the number - instead of nothing, or of reading 12-digit
  ration card numbers as Aadhaar numbers. A new detector field,
  `column_label`, defines this (shared spec, R and Python). Found by running
  the inventory against real BigQuery data.
* BigQuery: `TABLESAMPLE` queries are no longer sent with BigQuery's
  `maximumBytesBilled`, which BigQuery checks against the whole table and so
  refused cheap samples of large tables. The dry-run check still applies;
  measured against real BigQuery, it estimates sampled queries to within
  about 1 MB.
* BigQuery: `bq_scan_pii()`, `bq_pii_inventory()` and
  `bq_inventory_dataset()` (every table in a dataset), through bigrquery.
  BigQuery samples the table (`TABLESAMPLE`, billing only the sampled
  blocks; `sampling = "rand"` for views) and only the sample is downloaded;
  only scannable columns are read. A dry run checks the cost of every query
  first and anything estimated above `max_bytes` (default 1 GB) is refused
  before it runs; the limit is also sent to BigQuery.
* Spark: `scan_pii()` and `pii_inventory()` accept sparklyr tables. The
  table is sampled inside the cluster (a seeded random sample of up to
  `sample` rows, `seed = 42L` by default) and only the sample reaches the
  driver; the row count is recorded and `sample_method` is `spark-sample`.
  Whole-number columns are cast to text in Spark so long identifiers keep
  every digit; nested columns are recorded but not read. With a local Spark, set
  `sparklyr.connect.enablehivesupport = FALSE` if your Spark has no Hive.
* PII inventory: `pii_inventory()` scans a table with the `scan_pii()` rules
  and records where PII is - every column, also those where nothing was
  found, with source, table, row count, sample size and method, scan time
  and credgate version; never values. Inventories combine with `rbind()` and are
  saved with `write_inventory()` as a CSV file that R and Python write
  byte for byte the same; `read_inventory()` reads it. The first step of
  discovery at scale.
* Audit log: an append-only, hash-chained JSON Lines log of policy
  decisions - who, when, which endpoint, policy revision, allowed or blocked,
  and per identifier its type, action and rule; never text or values. With an
  audit key (`CREDGATE_AUDIT_KEY`), identifiers are recorded as keyed hashes;
  card verification codes never are. Verification detects edited, deleted,
  inserted or reordered records and returns the head hash to keep elsewhere.
  R and Python write and verify the same files. `cg_audit_log()`,
  `audit_record()`, `audit_verify()`, `audit_read()`;
  `policy_apply(..., audit = log)`. Needs the openssl package.
* Policies: a YAML policy (the same file in R and Python) decides, per
  destination tier (local, internal, frontier), whether each identifier is
  allowed, redacted or tokenised, or the whole request is blocked; rules can
  target particular endpoints and require combinations (card + CVV + expiry).
  Destinations form the register of model endpoints (tier, provider, URL)
  and can be `blocked`; endpoints not listed receive nothing. Loading is strict - unknown
  fields, tiers, actions or types are errors - and each decision names the
  policy revision and the rule behind every action. `cg_policy()`,
  `policy_decide()`, `policy_apply()`.
* New detectors: card verification codes (`card_cvv`, a new data class
  `sensitive_auth` that is always masked in full and must never be stored),
  card expiry dates (`card_expiry`), CKYC numbers (`ckyc`, only with a cue such
  as "CKYC" or "KIN"), ration card numbers (`ration_card`, after a ration-card
  label in English or Hindi) and NREGA job card numbers (`nrega_job_card`).
  Card verification codes are recognised only right after their label; dates
  such as "valid till 31/12/2026" are not taken as expiry dates; "RC no."
  (vehicle registration) is not a ration card.
* `synth_indian_pii()` adds `ckyc`, `ration_card`, `nrega_job_card`,
  `card_cvv` and `card_expiry`; existing fields keep their values for a given
  seed.
* Benchmark corpus version 2 includes the new identifiers (test split: F1
  0.980, precision 1.000).
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
