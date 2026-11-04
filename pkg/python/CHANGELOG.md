# Changelog

## Unreleased

- **Managing proxy users**: `credgate proxy rotate-key`, `remove-user` and
  `list-users` join `add-user` (and `rotate_key`, `remove_user`,
  `list_users` in Python). **Keys now expire**: valid for 1 to 180 days
  (`--days`, default 90); the proxy refuses an expired key with a message
  saying when it expired, and `list-users` shows keys expiring within 7
  days. The keys file records each key's creation and expiry; files from
  earlier versions still load, as keys without expiry. The last user cannot
  be removed. The file format is in the spec, with conformance cases.

## 0.10.0 (2026-11-04)

Better detection of Indian addresses, voter IDs and phone numbers, found
by running public Indian PII datasets, and an audit log fix. Detection is
about 15-20% slower than in 0.9.0 because of the city list for addresses.

- **Addresses without a label**: a house number, the locality, then a known
  Indian city or district and a PIN code ("210 Hauz Khas, Ahmedabad
  380015") is an address. The cities come from India Post's All India
  Pincode Directory (Department of Posts, data.gov.in, Government Open Data
  License - India): 1,194 district and head post office town names, built
  by `tools/build_india_places.py`. Every word of the locality must start
  with a capital or a digit, and the number must not follow a reference
  word ("Ticket 4471 ..."), so sentences and reference numbers are not
  taken for addresses. "Address" in Bengali, Tamil, Punjabi, Gujarati,
  Marathi, Telugu and Kannada is now a label too. On the public Ylemis
  dataset, address recall rises from 26% to 100% with no new false
  positives; credgate's own benchmark is unchanged.
- **Voter IDs in Indian languages**: "voter" and "elector" in Hindi,
  Marathi, Bengali, Tamil, Telugu, Gujarati, Kannada and Punjabi now count
  as context, so "वोटर आईडी QMF1202883" scores 0.97 instead of 0.3.
- **"Contact Number:" marks a phone**: a mobile number written with the
  leading 0 under "Contact Number:" was reported as a bank account when an
  IFSC was on the line before; "contact" and "संपर्क" now count against a
  bank account, as other phone words do. Both found by running the
  Ylemis India-PII and IndiaPII-Bench datasets; credgate's own benchmark
  tables are unchanged.
- **Audit log**: `Policy.apply()` with `audit=` no longer records a request
  as allowed when it then raises because the policy tokenises and no
  `vault` was given; it raises first and nothing is recorded, since nothing
  is sent. The proxy always passes a vault and was not affected. R had the
  same order and is fixed too.

## 0.9.0 (2026-11-03)

Build, test and roll out policies from the policy editor: custom detectors,
policy tests, explanations, and a proxy that reloads a new revision only
when it passes.

- **The proxy reloads a new policy revision without a restart**, on SIGHUP
  or with `--watch SECONDS` (also the keys file, so a user added or removed
  takes effect at once). Nothing broken goes live: the new revision must
  load completely - policy, custom detector files with their examples,
  endpoints - and pass its policy tests, or the running revision stays and
  `/healthz` says why. A change without a new revision is refused; a
  rollback is accepted and logged. Each request is checked by one revision,
  recorded in the audit log. The same checks run at start, and
  `--require-tests` refuses a policy without tests. With several workers,
  each reloads; SIGHUP no longer stops the proxy.
- **A policy owns its custom detectors**: `Policy.load()` compiles the files
  it names for itself and no longer registers them globally (use
  `load_detectors()` for that), so another revision never changes what a
  loaded policy detects. `Policy.detector_ids` and `Policy.sources` (each
  file with its SHA-256) are new.

- **Policy editor** (R): Try it shows each match's confidence and reasons,
  and what looked like an identifier but was not reported, and why; a
  Detectors tab is a workbench for custom detector files with live matches
  and example checks. The files it writes are the same ones Python reads.

- **Policy tests**: sample requests and what a policy must do with them
  (allowed or blocked, the blocking rules, the action for each type, types
  that must not be found, the exact text sent), in a `<policy>.tests.yaml`
  file beside the policy. `credgate policy test --policy FILE` runs them for
  CI (exit 1 on a failure, 2 for an invalid file);
  `credgate.run_policy_tests()` from code. R reads the same files, with
  shared conformance cases, and the policy editor runs them before every
  save.

- **Columns named for names and addresses**: every value of a column named
  `customer_name`, `first_name`, `nominee`, `borrower`, `नाम` (and similar)
  that is only a name is reported as `person_name`, in any letter case or
  script; every value of a column named `address`, `permanent_address`,
  `addr_line1`, `पता` (and similar) that has letters is an `address` (not
  e-mail addresses or links). The same works for values given
  `context="customer name"`. Only whole labels count: `product_name`,
  `user_name` and `email_address` do not.

- **Custom detectors from a YAML file** (`credgate.load_detectors()`): an
  organisation's own formats in the same fields as the built-in detectors,
  with its own fragments and lists, and `examples` that must and must not
  match, checked every time the file loads. A file is refused, and nothing
  registered, if anything is wrong: an unknown field, a built-in id, a
  class policies do not know, a failing example. `--detectors FILE` on every
  command, including `proxy serve`; a policy's `detectors` list loads files
  relative to the policy. R reads the same files (`load_detectors()`), with
  shared conformance cases. Guide, with a name detector that finds names from
  the words around them: docs/custom-detectors.md.

## 0.8.2 (2026-11-03)

A proxy fix, and credgate is now marked alpha.

- Proxy, standard server: up to the system's maximum of connections (not
  Python's default of 5) wait to be accepted, so a burst of requests on a
  busy Linux machine is not left waiting for the kernel's retries until
  clients time out. Found when a concurrency test timed out in CI.
- Status: alpha (PyPI classifier "3 - Alpha"; was pre-alpha). The main
  path is built and tested, but formats and APIs may still change.

## 0.8.1 (2026-11-02)

Tests only; the package behaves as 0.8.0. Three proxy tests waited a fixed
time for something that takes longer on a busy machine, and one failed once
in a Nix build of 0.8.0 (it passed on every rerun). They now wait for the
condition itself:

- audit retention: the first pass may take seconds;
- the load-balancer drain: `/healthz` turns to "draining" when the signal
  is handled, within a longer drain window;
- uvicorn noticing a client that leaves: a wider margin.

A slowed-down retention pass made the old test fail and the new one pass.

## 0.8.0 (2026-11-02)

The proxy, phase 2: answers stream as the model writes them, Claude Code
and the Anthropic SDKs, Ollama clients and VS Code Copilot Chat can use it,
and a shared proxy can run on uvicorn, a production HTTP server. The audit
log rotates monthly and keeps 5 years by default. Documentation:
https://dwarpal.github.io/credgate/

- Fix: with audit rotation, a writer arriving just as another started the
  new month's file could give its record the same sequence number as the
  other's (seen once in CI with four processes; `audit_verify()` reported
  it). After rotating, a writer now reads the new file before numbering.
- Proxy, phase 2:
  - **Streaming**: answers are passed on as the model writes them, in each
    API's own format, with tokens put back as they arrive. A piece ending in
    what could be the start of a token is held back until it is complete, so
    a token split across pieces is restored like any other. A client that
    leaves stops the endpoint's stream. An endpoint that fails mid-answer
    ends the stream with an error event.
  - **Anthropic API** (`/v1/messages`, `/v1/messages/count_tokens`), for
    Claude Code and the Anthropic SDKs: system prompts, text, tool inputs and
    tool results are governed. Thinking signatures pass unchanged. Images,
    documents and unknown block types are refused. The endpoint's key is sent
    as `x-api-key`, and errors come back in Anthropic's shape.
  - **Ollama API** (`/api/chat`, `/api/generate`, `/api/show`, `/api/tags`,
    `/api/version`), for Ollama clients and VS Code Copilot Chat's Ollama
    models. Ollama's own settings (`num_ctx`, `context`) pass unchanged, and
    images are refused.
  - `--default-endpoint` routes models asked for without an endpoint, as
    Claude Code does.
  - In localhost mode, a client's own key goes on to endpoints the proxy
    holds no key for. Shared mode never passes client keys on.
  - Clients authenticate with `Authorization: Bearer` or `x-api-key`.
- The proxy can run on **uvicorn**, a production HTTP server (BSD-3):
  `credgate proxy serve --server uvicorn`, with `pip install
  'credgate[server]'` (uvicorn, httptools and uvloop; all BSD-3 or MIT).
  Policy, audit and streaming are the same code on both servers, and every
  proxy test runs on both.
  - `--concurrency` limits requests in progress per worker (default 256).
    More get `503` with `Retry-After`; health checks are never refused.
  - A client that leaves is noticed even while the model is still thinking.
  - Chunked request bodies are read.
  - Workers and the load-balancer drain work as on the standard server.
  The standard-library server stays the default, with nothing to install.

- Audit log rotation and retention: with rotation, each month's records go
  to their own file (`<stem>.YYYY-MM.jsonl`) and the hash chain runs on
  across files; `audit_verify()` and `audit_read()` cover all of them, and a
  removed, renamed or altered month is detected. `audit_prune()` removes
  months past the retention period (default 5 years, at least 1): only from
  the oldest end, never the active file, never from a log that fails
  verification; removed months are recorded in `<stem>.pruned.json`, from
  which the rest still verifies. Several writers rotate safely. R and
  Python write and verify the same rotated logs. Audit files are created
  private to the account writing them (`0600`).
  `AuditLog(..., rotate=True)`. The proxy rotates monthly and prunes at
  start and daily (`--audit-retention-years`, default 5; `--no-audit-rotate`).

## 0.7.0 (2026-11-02)

The proxy and whole-database inventories. The proxy puts the policy between
people's tools and model endpoints, with the audit log and tokens restored
in answers; whole databases are inventoried table by table. Documentation:
https://dwarpal.github.io/credgate/

- Proxy (phase 1): `credgate proxy serve` puts the policy between tools and
  OpenAI-compatible model endpoints (`/v1/chat/completions`, `/v1/models`).
  Each request is allowed, redacted, tokenised or blocked per endpoint and
  recorded in the audit log; tokenised values are restored in the answer
  (never in tool calls). Localhost mode by default; shared mode with
  per-user keys (`credgate proxy add-user`) and TLS. Fails closed, refuses
  content it cannot check, keeps endpoint keys from clients. Every value
  in a request is checked (not just messages), redirects are not followed,
  and an attack test suite with a leak oracle covers hidden fields,
  obfuscation, hostile HTTP and endpoints, and concurrency. Standard
  library only. See docs/proxy.md.
- Proxy scaling: `--workers N` runs N processes on one port (one core each;
  Linux, macOS); within a process the policy step takes turns, which keeps
  throughput steady under parallel load. Load balancers: `GET /healthz`
  (no key), graceful drain on SIGTERM (`--drain-seconds`), `X-Request-ID`
  in the log and the answer. Load benchmark (benchmark/proxy_load.py): on a
  4-core laptop, 4 workers handle 757 short or 139 5-KB requests per
  second, with every answer correct and no leaks across 47,410 requests.
- Whole-database inventories: `inventory_database()` scans every table of a
  database through a connection (SQLAlchemy in Python, DBI in R): Postgres,
  DuckDB, SQLite, MySQL, IBM Db2 and others. Each table is sampled by the
  database where it can (`TABLESAMPLE SYSTEM` in Postgres and Db2, a
  reservoir sample in DuckDB), otherwise its first rows are read (`sample_method`
  `first-rows`); only text and number columns are read. With an inventory
  file, an interrupted run continues where it stopped and later runs rescan
  only tables whose row count changed or whose scan is older than
  `max_age` days. Tables that cannot be read are reported, not fatal.
  New extra: `database` (SQLAlchemy).

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
