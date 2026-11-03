# CredGate detection spec

This folder is the single source of truth for CredGate's PII detection. The R
package (`pkg/credgate`) and the Python package read these files instead of
defining detectors in code, and both must pass the conformance cases. A
compliance reviewer can read and approve one set of rules for every language.

| File | Contents |
|---|---|
| `engine.yaml` | Normalisation, token boundaries, scoring constants |
| `detectors.yaml` | Lists, tables, regex fragments and the built-in detectors |
| `conformance/detect.yaml` | Input texts and the exact matches expected |
| `conformance/checksums.yaml` | Verhoeff, Luhn and GSTIN test vectors |
| `conformance/scan.yaml`, `conformance/redact.yaml` | Column scan and redaction cases |
| `conformance/negatives.yaml` | Hard negatives (no confident match allowed) and documented false positives |

`spec_version` changes only on breaking changes to this schema. Implementations
refuse a spec version they do not know.

Packages ship a copy of this folder (`tools/sync-spec.sh` copies it into the R
package's `inst/spec`); a test fails when the copy is stale.

## Regular expressions

Patterns must work identically in ICU (R, via stringi) and the Python `regex`
module (not `re`). Use only this common subset:

- Unicode properties `\p{L}`, `\p{Lu}`, `\p{N}`, `\p{M}` and scripts as
  `\p{Script=Devanagari}` (full script names).
- Scoped flags `(?i:...)`; a leading `(?i)` applies to the whole pattern.
- Named groups `(?<name>...)`; fixed- or bounded-length lookbehind.
- No possessive quantifiers, atomic groups, `\K`, `\X` or inline comments.

Write patterns in single-quoted YAML strings: backslashes stay literal, and a
single quote is written `''`.

`{{name}}` in a pattern, `context`, `negative`, rule `match` or
`match_stripped` is replaced by fragment `name` (fragments may themselves use
`{{...}}`), or by list `name` joined with `|`. List entries are literal words
and must not contain regex metacharacters.

## Detection algorithm

For a vector of documents:

1. **Normalise** each document code point by code point: drop `remove` code
   points, map `dash` code points to `-`, map a digit from any `digit_zeros`
   block to its ASCII digit, otherwise apply NFKC to the single code point.
   Keep a map from each normalised code point to the original one.
2. For each detector, **find candidates** with each of its `patterns` in the
   normalised text (case-insensitively when `ignore_case`). With
   `bounded: true`, each pattern is wrapped as
   `boundary.before (?:pattern) boundary.after`. With `capture: value`, the
   reported span is the named group, not the whole match. Matches of all
   patterns are combined. With `column_label`, in each document whose extra
   context (step 4) matches `column_label.label`, the `column_label.patterns`
   also find candidates, reporting the whole match and coming after the
   detector's own patterns in pattern order.
3. **Validate**: every entry of `validate` must pass on the matched text:
   - `verhoeff`, `luhn`: checksum over the digits after removing `separators`.
   - `gstin`: upper-cased; structure, state code in list `gst_state_codes`,
     and the mod-36 check character.
   - `{match_stripped: regex}`: the regex matches after removing `separators`.
4. **Context**: take up to `scoring.context_window` code points before the
   match (`before`) and after it (`after`) in the normalised text, and the
   caller's extra context (`extra`, e.g. a column name). Search each,
   case-insensitively, for `context` and for `negative`, and keep the
   **strongest** keyword of each kind, with its side and distance:
   - in `before` (side 0): the last match; distance = code points between
     the end of the word containing it (extended over following letters and
     marks, `[\p{L}\p{M}]`) and the match;
   - otherwise in `after` (side 1): the first match; distance = code points
     between the match and the start of the word containing it;
   - otherwise in `extra` (side 2): the first match; distance 0.
   For a candidate of `column_label.patterns`, the context keyword is the
   label's match in `extra` (side 2, distance 0).
   With `context_required: true`, drop matches without context.
5. **Score**: start from `base` - a number, or `{default, rules}` where the
   first rule whose `match` regex matches the matched text sets the value -
   or from `base_without_context` when it is set and no context keyword was
   found. With context: `score + (1 - score) * context_boost`. With negative
   context: `score * negative_factor`, **unless** the context keyword is
   stronger: on a lower side, or on the same side and strictly nearer.
   Labels come before values, so "Aadhaar 5422... for e-KYC; order 519..."
   is an Aadhaar number, while in "order no 8782..., Aadhaar 5422..." the
   first number keeps its negative context. Round to
   `scoring.digits` decimal places.
6. **Reasons** (free text, for people): `matched <label> pattern`, then
   `checks` if set, `context '<keyword>'`, then `negative context
   '<keyword>'` or, when it was outweighed, `farther negative context
   '<keyword>' ignored`, then
   `describe`: either `{position, table, template}` (1-based character of the
   matched text, upper-cased, looked up in the table and substituted for `{}`)
   or `{default, rules: [{match, text}]}`.
7. **Canonical form**, used for consistent tokenisation:
   `strip_upper` (default: remove `separators`, upper-case), `lower`,
   `last10_digits`, `collapse_upper` (trim, collapse whitespace, upper-case).
8. **Resolve overlaps** within each document: among overlapping spans, keep
   the highest confidence, then the longest; repeat with the rest.
9. Report spans against the **original** text via the normalisation map.

Conformance compares `type`, `value`, and when given `confidence`,
`canonical`, `span` (0-based, end-exclusive code-point offsets) and `reason`
(substring). Implementations may expose positions in their own convention
(R uses 1-based inclusive).

## Detector fields

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique id, reported as `type` |
| `class` | yes | Data class used by policies (`identity_strong`, `financial`, `sensitive_auth`, `health`, `contact`, `personal`, `quasi`). `sensitive_auth` is card verification data, which PCI DSS forbids storing after authorisation: implementations must never write it anywhere, including audit logs |
| `label` | yes | Human-readable name |
| `patterns` | yes | List of regexes |
| `bounded` | no | Wrap patterns with `boundary` (default false) |
| `capture` | no | Named group to report instead of the whole match |
| `ignore_case` | no | Case-insensitive patterns (default false) |
| `validate` | no | List of validators (see above) |
| `checks` | no | Reason text describing what `validate` checked |
| `base` | yes | Confidence without context: number or `{default, rules}` |
| `context` | no | Regex of supporting keywords |
| `negative` | no | Regex of keywords that lower confidence |
| `context_required` | no | Drop matches without context (default false) |
| `base_without_context` | no | Confidence instead of `base` when no context keyword is found; needs `context`, excludes `context_required` |
| `describe` | no | Extra reason per match |
| `canonical` | no | Canonical form (default `strip_upper`) |
| `column_label` | no | `{label, patterns}`: when `label` (a regex, case-insensitive) matches the caller's extra context, such as a column name, `patterns` also find candidates (see the detection algorithm). For detectors whose `patterns` need a label in the text, so that a column named `card_cvv` labels its values |

Unknown fields are an error, so a typo cannot silently disable a rule.

## Custom detectors (`credgate-detectors`)

Organisations add detectors for their own formats - loan account numbers,
customer ids, employee codes - in a YAML file that every implementation
loads the same way, so R, Python, the command line and the proxy detect
the same things:

```yaml
kind: credgate-detectors
version: 1
fragments:                     # optional, as in detectors.yaml
  loan_context: 'loan|\ba/c\b|account'
lists:                         # optional, as in detectors.yaml
  loan_branches: ['MUM', 'PUN', 'DEL']
detectors:
  - id: loan_account
    class: financial
    label: Loan account number
    patterns: ['LN(?:{{loan_branches}})[0-9]{7}']
    bounded: true
    context: '{{loan_context}}'
    base: 0.6
    base_without_context: 0.4
    examples:
      match: ['Loan a/c LNMUM0012345 is overdue']
      no_match: ['Order LNXYZ0012345', 'LNMUM00123']
```

- Top-level fields are exactly `kind` (`credgate-detectors`), `version`
  (1), `fragments`, `lists` and `detectors`; anything else is an error.
- `detectors` is a non-empty list. Each entry has the fields of a built-in
  detector (see "Detector fields") and may add `examples`.
- `id` matches `^[a-z][a-z0-9_]*$`, is unique in the file and is not the id
  of a built-in detector: a custom file cannot change or weaken a built-in
  one.
- `class` is one of the seven data classes, so policies can act on it.
- `{{name}}` refers to the file's own fragments and lists first, then the
  built-in ones; a file may not define a fragment or list with a built-in
  name. Validators, canonical forms and `describe` work as for built-in
  detectors (`describe.table` names a built-in table).
- `examples.match`: each text must give at least one span of this detector,
  run on its own with no extra context and no minimum confidence.
  `examples.no_match`: none. If any example fails, the file is refused.
- Loading registers every detector of the file or none. Loading a file
  again with the same definitions changes nothing; a different definition
  under an id a custom file already registered is an error unless the
  caller asks to replace it.

A policy may name custom detector files in a top-level `detectors` list of
paths, relative to the policy file; they are loaded before the policy's
rules are checked, so rules can name their types. They belong to the
policy: it decides with the detectors registered when it was loaded plus its
own files, and loading it registers nothing. So a policy loaded later -
another revision, after a file changed - never changes what an earlier one
detects, and two files may not define the same id. Policy tests check type
names against the policy's own detectors.

Custom patterns run on every text, like the built-in ones: avoid nested
quantifiers such as `(a+)+`, which can be slow on long inputs.

## Masking

Wherever an implementation shows a detected value (printed spans, previews,
column-scan examples, command-line output), it masks it:

- **`partial`** (default): replace every letter and digit with `X`, except
  the last 4 characters (the last 2 for values shorter than 8), the same
  convention as UIDAI's masked Aadhaar. Values of the `personal` class
  (names, addresses) keep nothing: their end identifies a person, unlike the
  last digits of an identifier. Neither do values of the `sensitive_auth`
  class (card verification codes), which are short enough that keeping two
  digits would show most of the code.
- **`full`**: replace every letter and digit of every value with `X`.

Other characters (spaces, `.`, `@`, `-`, `+`) are kept, so the shape stays
readable. The mode is chosen by the environment variable `CREDGATE_MASK`
(`partial` or `full`), which an implementation may let users override in
its own way; any other value is an error. Masking applies to display only,
never to detected values. Keeping the last 4 characters stays within the
display limits of UIDAI (Aadhaar) and PCI DSS 4.0.1 requirement 3.4.1
(cards); use `full` where a policy allows no part of a value to be shown.

## Column scan (`scan_pii`)

Reports, per column of a table, which PII types occur and how often. Defaults:
`sample = 10000`, `min_rate = 0`.

1. **Values.** Strings are used as they are; categorical values as their
   labels. Numbers that are whole are rendered as integers without exponent
   or decimals (`9876543210`); other numbers, booleans, dates and missing
   values are skipped. Each value is trimmed of surrounding whitespace, and
   empty strings are skipped. A column with no remaining values is skipped.
2. **Sampling.** With `n` values and `n > sample`, use the values at 0-based
   positions `floor(i * n / sample)` for `i = 0 .. sample - 1` (evenly spaced,
   deterministic). Otherwise use all `n`.
3. **Context.** Each sampled value is one document for detection, with the
   column name - after replacing `_`, `.` and `-` with spaces - as extra
   context, so a column named `voter_id` or `cust_pan` supports those types.
4. **Per type found in the column:**
   - `n_sampled`: number of sampled values;
   - `n_matched`: values with at least one match of the type;
   - `n_full`: values where a match of the type covers the whole value;
   - `rate`: `n_matched / n_sampled`, rounded to 4 decimal places;
   - `mean_confidence`: mean confidence of each matched value's first match
     of the type, rounded to 2 decimal places;
   - `example`: the first matched value's first match, masked.
5. Keep types with `rate >= min_rate`. Order by column (table order), then
   `rate` descending, then `type`.

Conformance cases are in `conformance/scan.yaml`; each lists the complete
expected result.

## Inventory (`pii_inventory`)

A record of where PII is, across many tables: the result of discovery, kept
for InfoSec, compliance and the policy editor. It never contains values, not
even masked ones.

An inventory is a table with one row per **table, column and PII type
found**, and one row with no type for each scanned column where no type was
found (or none reached `min_rate`), so that it shows what was covered as
well as what was found. `pii_inventory(data, source, table)` scans one table
with the column-scan rules above (same `sample`, `min_rate` and `detectors`)
and returns its rows; inventories of several tables are combined by
appending rows.

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | inventory format version, `1` |
| `source` | text | the data source, named by the user (e.g. `bigquery:prod`, `hive`, `lake`) |
| `table` | text | the table within the source (e.g. `dataset.customers`, or a file path) |
| `column` | text | column name |
| `type` | text or empty | PII type; empty when none was found |
| `class` | text or empty | its data class |
| `n_rows` | integer or empty | rows in the table, when known without reading it |
| `n_sampled` | integer | values checked (0 when the column has no usable values) |
| `n_matched` | integer | values with a match of the type (0 with no type) |
| `n_full` | integer | values entirely the identifier (0 with no type) |
| `rate` | number | `n_matched / n_sampled`, 4 decimals (0 with no type) |
| `mean_confidence` | number or empty | 2 decimals; empty with no type |
| `sample_method` | text | `all` (every usable value checked), `even` (evenly spaced sample); integrations may add their own (e.g. a database's sampling clause) |
| `scanned_at` | text | when the scan of this table started, UTC, `YYYY-MM-DDThh:mm:ssZ` |
| `credgate` | text | the implementation and version that scanned, e.g. `python/0.6.0`, `r/0.2.0` |

Rows are in table order, then column order, then `rate` descending, then
`type`. `n_rows` is the table's row count when the input knows it without a
scan (a data frame or an Arrow table), otherwise empty; integrations fill it
from table metadata.

**Spark tables** (PySpark and sparklyr DataFrames) are sampled inside the
cluster; only the sampled rows reach the driver. This replaces step 2 of
the column scan, as Spark tables have no stable row order:

1. `n` is the table's row count; `n_rows = n`.
2. If `n <= sample`, all rows are used and `sample_method` is `all`.
   Otherwise a Bernoulli sample without replacement with fraction
   `min(1, 1.2 * sample / n)` and the given `seed` (default 42), then its
   first `sample` rows; `sample_method` is `spark-sample`. By chance the
   sample can have fewer than `sample` rows.
3. Whole-number columns (byte, short, integer, long, and decimal with
   scale 0) are cast to text in Spark, so long identifiers keep every
   digit; other decimals become doubles. Columns of arrays, maps, structs
   and binary data are not read and are recorded with `n_sampled = 0`.
4. The column-scan rules (values, context, per-type summary) then apply to
   the sampled rows, without further sampling.

The same data, partitioning and seed give the same sample in PySpark and
sparklyr, as both use Spark's own sampling.

**BigQuery tables** are sampled by BigQuery; only the sample is
downloaded. BigQuery bills by the bytes of the columns a query reads, so
credgate reads only the columns it can scan and checks the cost first:

1. `n` is the table's row count from its metadata, or `SELECT COUNT(*)`
   when the metadata has none; `n_rows = n`.
2. Columns read (`INTEGER` and `FLOAT`, the API's older names, are the
   same as `INT64` and `FLOAT64`): `STRING`; `INT64` as text; `NUMERIC` and `BIGNUMERIC` as
   text when whole, otherwise not at all; `FLOAT64` as it is. Repeated
   columns and all other types (records, bytes, dates, JSON, geography,
   ...) are not read and are recorded with `n_sampled = 0`. With no column
   to read, no query is run.
3. The query, with identifiers in backticks (inner backticks escaped with
   a backslash) and the table as `` `project.dataset.table` ``:
   - `n <= sample`: all rows; `sample_method` is `all`.
   - otherwise, with fraction `f = max(0.000001, min(1, 1.2 * sample / n))`:
     - `sampling = "tablesample"` (the default, for tables): BigQuery's
       block sampling, `TABLESAMPLE SYSTEM (p PERCENT)` with `p = 100 * f`,
       then `LIMIT sample`; only the sampled blocks are billed.
       `sample_method` is `bigquery-tablesample`.
     - `sampling = "rand"`: `WHERE RAND() < f LIMIT sample`, which reads
       (and bills) the whole columns. `sample_method` is `bigquery-rand`.
       Only tables can use `TABLESAMPLE`, so views and external tables
       always use this.
   - `p` and `f` are written with up to 6 decimal places, trailing zeros
     removed (e.g. `0.012`, `1.2`, `100`).
4. **Cost limit.** Before each query (the count too: counting a view runs
   it), a dry run estimates the bytes it would process; if the estimate
   exceeds `max_bytes` (default 10^9, 1 GB) nothing runs and it is an
   error that names the estimate. Queries without `TABLESAMPLE` are also
   sent with `maximumBytesBilled = max_bytes`, which BigQuery enforces.
   `TABLESAMPLE` queries are not: BigQuery checks that limit against the
   whole table, though it bills only the sampled blocks, which the dry
   run estimates to within about 1 MB (measured on a 3.2 GB table: a 1%
   sample was estimated at 32.0 MB and billed 32.5 MB; see
   `benchmark/bigquery_tablesample_cost.py`).
5. The column-scan rules then apply to the downloaded rows, without
   further sampling.

BigQuery's samples are random and not reproducible. The query for each
case is in `conformance/bigquery.yaml`; implementations must build exactly
these queries.

**Databases** (`inventory_database`) are inventoried table by table
through a connection (SQLAlchemy in Python, DBI in R); each table is
sampled by the database where it can, and only the sample is read.

1. **Tables**: every table in the given schemas (default: all schemas
   except the database's own: `information_schema`, `pg_catalog`,
   `pg_toast`, `sys`, `syscat`, `sysibm`, `sysstat`, `mysql`,
   `performance_schema`, and names starting with `pg_temp`, `pg_toast_temp`,
   or DuckDB's `system.` and `temp.` catalogs).
   Views only on request, as reading one runs its query. `include` and
   `exclude` are shell-style patterns matched against `schema.table`. Tables
   are scanned in schema, then table name order; the inventory names each
   `schema.table`.
2. **Columns read**: all, except those whose type name (lower-cased)
   contains `blob`, `binary`, `bytea`, `image`, `json`, `xml`, `geometry`,
   `geography`, `array`, `struct`, `map`, `interval`, `date`, `time`,
   `bool`, `uuid`, or ends with `[]`. Those are recorded with
   `n_sampled = 0` and not read. With no column to read, no query runs.
3. **Row count** `n`: for `postgresql`, the planner's estimate
   (`pg_class.reltuples`) when it is 0 or more, otherwise `SELECT COUNT(*)`;
   for other databases `SELECT COUNT(*)`. `n_rows = n` (for Postgres an
   estimate, as exact counts need a full scan).
4. **Query** for each database family, with identifiers in double quotes
   (inner `"` doubled; backticks for `mysql`), the table as
   `"schema"."table"` (DuckDB's driver names schemas `catalog.schema`: each
   part is quoted), and `f = max(0.000001, min(1, 1.2 * sample / n))`,
   `p = 100 * f` written as for BigQuery:

   | Family | `n <= sample` | `n > sample` | `sample_method` |
   |---|---|---|---|
   | `postgresql` | `SELECT cols FROM t` | `... TABLESAMPLE SYSTEM (p) LIMIT sample` | `tablesample` |
   | `db2` | `SELECT cols FROM t` | `... TABLESAMPLE SYSTEM (p) FETCH FIRST sample ROWS ONLY` | `tablesample` |
   | `duckdb` | `SELECT cols FROM t` | `... USING SAMPLE sample ROWS (reservoir)` | `reservoir` |
   | `sqlite`, `mysql` | `SELECT cols FROM t` | `... LIMIT sample` | `first-rows` |
   | any other | `SELECT cols FROM t` | `SELECT cols FROM t`, reading only the first `sample` rows | `first-rows` |

   With `n <= sample`, `sample_method` is `all`. DuckDB uses a reservoir
   sample (exactly `sample` rows, uniformly), not its block sampling: its
   blocks hold about 2,000 rows, so a small fraction of a medium-sized
   table is often no block at all. `first-rows` is not a
   random sample: identifiers that appear only later in the table can be
   missed, and the inventory says so.
5. The column-scan rules then apply to the rows read, without further
   sampling.
6. **Resume and change detection**: with an inventory file, its rows are
   read first, and the file is rewritten (to a temporary file, then
   renamed) after each table. A table is skipped, keeping its rows, when
   the file has rows for it (same `source` and `table`) scanned within
   `max_age` days (default 30) and with the same `n_rows` as now (both
   known). So an interrupted run continues where it stopped, and a later
   run rescans only tables that changed or are stale. Rows of tables no
   longer in the database are dropped at the end.
7. **Errors**: a table that cannot be read (for example without
   permission) is reported as a warning and skipped, unless errors are
   asked to stop the run; the returned inventory lists the tables that
   failed, so gaps in coverage are visible.

The query for each case is in `conformance/database.yaml`.

**Inventory files** are CSV, written identically by every implementation so
that files can be compared and diffed:

- UTF-8 without byte-order mark, `\n` line endings, a final newline;
- a header line with the field names in the order above;
- fields separated by `,`; a field containing `,`, `"`, `\r` or `\n` is
  enclosed in `"` with inner `"` doubled; no other quoting;
- empty values as nothing between the separators;
- integers in plain decimal; `rate` and `mean_confidence` with 4 and 2
  decimals, then trailing zeros and a trailing `.` removed (`1`, `0.25`,
  `0.3333`, `0`).

Reading a file checks the header, turns empty fields into missing values and
numbers into numbers; anything else is an error.

Conformance cases are in `conformance/inventory.yaml`, and
`conformance/inventory/written-by-both.csv` is the file both
implementations must write for its case.

## Redaction (`redact`, `preview`)

Irreversible masking of a text before it is shared:

1. Detect with the given options (`min_confidence`, default 0; detectors;
   context).
2. Replace every reported span, in the original text, by `[` + the
   upper-cased type + `]` - for example `[PAN]`, `[PERSON_NAME]`. Spans never
   overlap (overlaps are resolved during detection), so replacements are
   independent; everything outside the spans is kept exactly.

`preview` shows the redacted text together with the spans that caused each
replacement (values masked), without sending anything. Reversible
tokenisation (`[PAN_1]` restored later, see below) builds on the same spans.

Conformance cases are in `conformance/redact.yaml`.

## Tokenisation (`tokenise`, `restore`)

Reversible masking: identifiers become numbered tokens that a model can
reason about ("[PAN_1] and [PAN_2] are different customers"), and the real
values are put back into its answer. The mapping is kept in a **vault**.

**Vault.** An ordered list of entries `(token, type, canonical, value)`,
starting empty, in one of two modes. `value` is the original text of the
first occurrence.

- **Numbered** (default): `token` is `[` + upper-cased type + `_` + n + `]`,
  where n counts entries of that type from 1 in order of creation
  (`[PAN_1]`, `[PAN_2]`, `[MOBILE_IN_1]`). Readable, but the same customer
  gets different tokens in different vaults.
- **Keyed**: `token` is `[` + upper-cased type + `_` + id + `]`, where id is
  derived from a secret key (below). The same identifier gets the same token
  in every vault with the same key - across sessions, datasets, machines and
  parallel workers - so tokenised tables can still be joined and counted.

Tokens are compared ignoring case.

**Keyed token id.** With a key of at least 32 bytes:

1. `message` = the UTF-8 bytes of `credgate-token-v1`, a zero byte, the
   type, a zero byte, the canonical form.
2. `mac` = HMAC-SHA256(key, message).
3. id = the first 8 bytes of `mac` in base32 (RFC 4648 alphabet, lower
   case, no padding): 13 characters from `a-z` and `2-7`.

64 bits keep collisions negligible (expected far below one for a billion
distinct values of one type); two different values that do get the same
token are reported as an error, never merged silently. A key is given as
hex (at least 64 hex digits) or as raw bytes, by the caller or in the
environment variable `CREDGATE_TOKEN_KEY`. Implementations provide a helper
that makes a new random key. The **key fingerprint** - the first 8 bytes of
HMAC-SHA256(key, `credgate-key-check-v1`), as 16 hex digits - identifies a
key without revealing it.

Whoever holds the key can confirm a guessed value by computing its token
(Indian mobile numbers have only about 10^10 values), so the key needs the
same care as a vault: see `docs/threat-model.md`.

**merge(vault, other)**: adds the other vault's entries that are not yet
present, in its order. Both must be keyed with the same key (same
fingerprint); it is an error if a token stands for a different
`(type, canonical)` in the two vaults. Parallel workers each tokenise with
their own keyed vault and merge the results.

**tokenise(texts, vault)**:

1. Detect with the given options, as for redaction.
2. Visit spans by document, then position. Look up `(type, canonical)` in
   the vault; if absent, append a new entry. The same identifier therefore
   gets the same token however it is written (`ABCPE1234F` and
   `abcpe1234f`; `+91 98765 43210` and `9876543210`), across documents and
   across calls with the same vault.
3. Replace each span by its token; everything else is kept exactly.

**restore(text, vault, strict)** puts values back, tolerating how models
copy tokens:

1. Find token candidates, left to right, without overlap, ignoring case:
   - bracketed: `\[\s*T_N\s*\]`;
   - bare: `(?<![\p{L}\p{N}_])T_N(?![\p{L}\p{N}_])`;

   where `T` is `[A-Za-z]+(?:_[A-Za-z]+)*` and `N` is `[0-9]+` or 13
   characters from `[A-Za-z2-7]` (a keyed id); bracketed form first at each
   position.
2. If the vault has the token `[T_N]` (ignoring case), replace the whole
   candidate by its `value`. Otherwise leave it unchanged.
3. With `strict`, it is an error if any **bracketed** candidate is not in
   the vault (a token the model invented or altered). Bare unknown
   candidates are ordinary text (`file_2`) and never an error.

Restoring text that was never tokenised changes nothing unless it contains
token-shaped text that is in the vault.

Conformance cases are in `conformance/tokenise.yaml`.

### Saved vaults (`.cgvault` files)

A vault can be saved to a file and opened later, in either language. The
file is encrypted with a key derived from a passphrase; without the
passphrase it reveals nothing about its contents (not even how many
entries it holds). Both implementations use libsodium (R `sodium`, Python
`PyNaCl`).

**Layout** (binary):

| Bytes | Content |
|---|---|
| 8 | magic `CGVAULT` followed by the format version, `0x01` |
| 1 | key derivation: `0x01` = `crypto_pwhash_scryptsalsa208sha256` with opslimit 524288 and memlimit 16777216 (libsodium's "interactive" limits) |
| 32 | salt, random |
| 24 | nonce, random |
| rest | `crypto_secretbox` (XSalsa20-Poly1305) of the payload: 16-byte tag, then ciphertext |

The 32-byte key is derived from the passphrase's UTF-8 bytes and the salt.
Every save draws a new salt and nonce.

**Payload**: UTF-8 JSON
`{"format": "credgate-vault", "version": 1, "saved_at": "<UTC, ISO 8601>",
"mode": "numbered" | "keyed", "key_fingerprint": "<16 hex digits, keyed
only>", "entries": [{"token", "type", "class", "canonical", "value"}, ...]}`,
with entries in vault order; a payload without `mode` is numbered. Opening
rebuilds the vault exactly, so tokenising continues the numbering. The key
itself is **never** stored: opening a keyed vault needs the key again (from
the caller or `CREDGATE_TOKEN_KEY`), and it is an error if its fingerprint
differs from the one saved.

**Rules**:

- The passphrase comes from the caller, else the environment variable
  `CREDGATE_VAULT_PASSPHRASE`, else an interactive prompt; it must have at
  least 12 characters. It is never stored.
- A wrong passphrase and a damaged or altered file give the same error
  (authentication fails); a file without the magic, or with an unknown
  version or key derivation, is reported as such.
- Saving writes a temporary file readable only by its owner (mode 0600)
  and renames it into place; an existing file is replaced only if it is
  itself a vault file.

Fixtures written by each implementation are in `conformance/vaults/`, listed
with their passphrase and expected entries in `conformance/vault.yaml`; every
implementation must open all of them.

## Policies (`policy`)

A policy decides, for one request to one destination, what happens to each
identifier found in it: let it through, redact it, tokenise it, or block the
whole request. Policies are YAML files, read the same way by every
implementation; they are written by InfoSec and compliance, not in code.

**Format**:

```yaml
policy: credgate-policy        # required marker
version: 1                     # format version
id: bank-default               # name of this policy
revision: 3                    # whole number, raised on every change
description: free text         # optional
detectors: [bank-detectors.yaml]  # optional: custom detector files, relative to this file
destinations:                  # the endpoints InfoSec has set up
  ollama-local: {tier: local, provider: ollama, url: 'http://localhost:11434/v1'}
  vllm-gpu: {tier: internal, provider: vllm, url: 'https://llm.bank.internal/v1'}
  claude-gateway: {tier: frontier, provider: anthropic, url: 'https://ai-gw.bank.internal/claude'}
  copilot: {tier: frontier, provider: github, blocked: true}
min_confidence: 0.5            # optional, default 0
rules:
  - id: card-with-cvv-and-expiry
    description: free text     # optional
    when: {tiers: [frontier], all_of: [card, card_cvv, card_expiry]}
    action: block
  - id: no-personal-data-to-frontier
    when: {tiers: [frontier], classes: [identity_strong, financial]}
    action: redact
default_action: redact
```

- **Custom detectors** (`detectors`, optional): files in the format of
  "Custom detectors", loaded before the rules are checked, so rules can
  name their types and classes.
- **Destinations** are the endpoints requests may go to. Each has a `tier`;
  optionally `provider` and `url` (recorded with decisions; the proxy routes
  by `url`), a `description`, and `blocked: true` to refuse every request to
  it while keeping it on record.
- **Tiers** say where the data ends up: `local` (the same machine),
  `internal` (models the organisation runs itself, such as open models on
  vLLM or SGLang in its data centre), `frontier` (an external model
  provider - also when reached through the organisation's own gateway,
  since the data still reaches the provider). No others.
- **Actions**: `allow`, `redact`, `tokenise`, `block`.
- **Conditions** in `when`, all optional; a rule matches an identifier when
  every condition given holds:
  - `destinations`: the destination is one of these (names from
    `destinations`), for rules about particular models;
  - `tiers`: the destination's tier is one of these;
  - `types`: the identifier's type is one of these;
  - `classes`: the identifier's data class is one of these;
  - `all_of`: every one of these types was found somewhere in the request.
- A destination that is not listed cannot receive anything: requests to it
  are refused. To stop a model getting a kind of data, add a rule for it;
  to stop it getting anything, leave it out.
- Rule ids are unique. Unknown fields, destinations, tiers, actions, types
  and classes, a
  missing required field, or a `revision` that is not a positive whole number
  are errors when the policy is loaded: a policy that cannot be read
  correctly is never applied.

**Deciding** (`decide(policy, texts, destination)`), for a request made of
one or more texts (for example the messages of a chat):

1. An unknown `destination` is an error.
2. Detect in all texts, keeping matches with confidence at least
   `min_confidence`.
3. For each match, in document then position order, the first rule that
   matches decides its action; with no matching rule, `default_action`.
4. If the destination is `blocked`, or any match's action is `block`, the
   request is **blocked**: nothing may be sent. The decision lists what
   blocked it: `destination-blocked` first, then every rule.

The decision reports the policy id and revision, the destination and its
tier, whether the request is allowed, and for each match its type, class,
span, action and deciding rule (or `default`). Implementations must also
block, not send, if detection itself fails.

**Applying** (`apply`): if the decision allows the request, each text is
rewritten as for redaction, replacing each match by its placeholder
(`redact`), its token (`tokenise`, which needs a vault) or nothing (`allow`).
A blocked request has no output texts.

Conformance cases are in `conformance/policy.yaml`.

### Policy tests (`credgate-policy-tests`)

Test cases written by the people who own a policy: sample requests and what
the policy must do with them. They are kept beside the policy
(`bank-default.tests.yaml` for `bank-default.yaml`), run whenever the policy
changes - in the policy editor before saving, and with `credgate policy
test` in CI - so a change that breaks an agreed behaviour is caught before
it is used.

```yaml
kind: credgate-policy-tests
version: 1
tests:
  - id: card-with-cvv-blocked-for-claude
    description: PCI DSS - never to an external model   # optional
    endpoint: claude
    text: 'Card 4111 1111 1111 1111, CVV 123, expiry 08/29'
    expect:
      allowed: false
      blocked_by: [card-with-cvv-and-expiry]
  - id: pan-tokenised-for-claude
    endpoint: claude
    texts: ['Customer PAN ABCPE1234F', 'mobile 9876543210']
    expect:
      allowed: true
      actions: {pan: tokenise, mobile_in: redact}
      absent: [card]
      output: ['Customer PAN [PAN_1]', 'mobile [MOBILE_IN]']
```

- Top-level fields are exactly `kind`, `version` (1) and `tests`, a
  non-empty list. Each test has a unique `id`, an `endpoint`, exactly one of
  `text` (one text) or `texts` (a list), an `expect`, and optionally a
  `description`. Unknown fields are an error.
- `expect.allowed` (required): whether the request may be sent.
- `expect.blocked_by` (optional): the rules that block it, in any order.
- `expect.actions` (optional): for each type listed, at least one match of
  that type is found, and every match of it gets that action.
- `expect.absent` (optional): types that must not be found.
- `expect.output` (optional, allowed requests only): the exact texts sent,
  a string for `text` or a list for `texts`. Tokens are numbered from 1 in
  each test, as with a new vault.
- Types and actions named in `expect` must be known; an endpoint the policy
  does not have makes that test fail, not the file.

A test runs the policy on its texts for its endpoint, with a new vault, and
**passes** when every expectation holds; otherwise it **fails**, with one
problem per expectation that does not hold (for example
`allowed: expected false, got true`, or `pan: expected tokenise, got
redact`). An invalid file is an error, and runs no test.

## Audit log (`audit`)

Evidence of what was decided, for regulators, internal audit and DPDP
reviews - without holding the personal data itself.

**File**: UTF-8 JSON Lines, one record per line, appended. Each record is
one JSON object:

| Field | Content |
|---|---|
| `v` | record format, `1` |
| `seq` | 1 for the first record, then +1 |
| `time` | UTC, `YYYY-MM-DDTHH:MM:SS.sssZ` |
| `actor` | who made the request (by default the operating-system user) |
| `policy` | `{"id", "revision"}` |
| `destination` | `{"name", "tier", "provider"}` (`provider` may be null) |
| `allowed` | true or false |
| `blocked_by` | list of rule ids (and `destination-blocked`), empty if allowed |
| `items` | one object per match, in order: `{"type", "action", "rule"}`, plus `"id"` (below) except for the `sensitive_auth` class |
| `prev` | SHA-256 (lower-case hex) of the previous line's bytes, without its line ending; 64 zeros for the first record |

**Identifier hashes.** With an audit key (at least 32 bytes, from the caller
or `CREDGATE_AUDIT_KEY`; a different key from the token key), each item's
`id` is the first 8 bytes, as 16 lower-case hex digits, of
HMAC-SHA256(key, `credgate-audit-v1` ∖0 type ∖0 canonical). Whoever holds
the key can check whether a given identifier was involved; the log alone
reveals nothing. Without a key, items carry no `id`. Card verification data
(class `sensitive_auth`) is never hashed or otherwise recorded beyond its
type, action and rule (PCI DSS: it must not be stored).

The log never contains text, values, tokens or vault contents.

**Writing.** A writer reads the last line of an existing log (if any),
continues `seq`, and sets `prev` to the SHA-256 of that line. One writer per
file at a time.

**Verifying** (`audit_verify(path)`): reading line by line, every line must
be a JSON object with `v` 1, `seq` equal to its position (1-based), and
`prev` equal to the SHA-256 of the previous line (64 zeros for the first).
The result reports whether the log is intact, the number of records, the
first failing line and why, and the SHA-256 of the last line - the **head**.
Editing, deleting, inserting or reordering records breaks the chain;
removing records from the end does not, so keep copies of the head
somewhere else (another system, a ticket, a signed report) and compare.

**Rotation** (optional, monthly). The log at `<dir>/<stem>.jsonl` is the
*active* file. Before a record is written, if the active file is not empty
and the new record's month (UTC, from `time`) is later than the month of its
first record, the active file is renamed to `<dir>/<stem>.YYYY-MM.jsonl`
(the month of its records; an existing file of that name is an error, never
overwritten) and the record starts a new active file. The chain continues
across files: the new record's `seq` follows, and its `prev` is the SHA-256
of the last line of the renamed file. Each closed segment so holds the
records of exactly one month. Writers that share a log (several processes)
lock the active file, and after taking the lock check that it is still the
file at the path (if it was rotated meanwhile, they open the new one); they
take the record's time while holding the lock, so records are in time order.

**Verifying a rotated log** (`audit_verify` on the active file's path): the
segments, in month order, then the active file form one chain, checked as
above with `seq` and `prev` continuing across files; failures name the file
and line. A missing or altered segment breaks the chain.

**Retention** (`audit_prune(path, keep_years)`, `keep_years` at least 1,
default 5): removes closed segments whose month ended more than `keep_years`
years ago (at whole months: a segment for month M may go once the date is
past the end of month M plus `keep_years` years), only from the oldest end,
never the active file, and only if the whole log verifies - a broken log is
kept as evidence. Before deleting, it writes `<dir>/<stem>.pruned.json`:

```json
{"credgate_audit_pruned": 1, "last_seq": 41250, "head": "<SHA-256 of the last pruned line>",
 "segments": [{"name": "audit.2021-10.jsonl", "first_seq": 1, "last_seq": 40112,
               "first_time": "...", "last_time": "...", "head": "..."}]}
```

(`segments` lists every pruned segment, oldest first; the file is written to
a temporary name, then renamed). Verification then starts from it: the
first remaining record must have `seq = last_seq + 1` and `prev = head`.

Conformance cases are in `conformance/audit.yaml`, with logs written by each
implementation in `conformance/audit/`.

## Evaluation (`evaluate`)

Measures detection against labelled text.

**Labelled data** is JSON Lines, one document per line:

```json
{"id": "kyc-0001", "text": "PAN: ABCPE1234F", "spans": [{"start": 5, "end": 15, "type": "pan"}]}
```

`start`/`end` are 0-based, end-exclusive code-point offsets into `text`.
Every PII span in a document must be labelled (a document with no spans is
a negative). Optional fields (`category`, `lang`) are carried through.

**Scoring**, for each document, with detection run as usual
(`min_confidence` filters predictions):

1. A prediction *matches* a gold span of the same type when the offsets are
   equal (`match = "exact"`, the default) or when the two spans overlap
   (`match = "overlap"`). Each gold span and each prediction is used at most
   once: go through predictions in order of `start`, and pair each with the
   first unused matching gold span in order of `start`.
2. Matched pairs are true positives; unpaired predictions are false
   positives; unpaired gold spans are false negatives.
3. Per type and overall (micro-averaged): `precision = tp / (tp + fp)`,
   `recall = tp / (tp + fn)`, `f1 = 2pr / (p + r)`; each is reported as
   missing (NA / None) when its denominator is 0. Rates are rounded to 4
   decimal places. Rows are the types present in gold or predictions, in
   alphabetical order, then `overall`.

Conformance cases are in `conformance/evaluate.yaml`.

## Known limits

Names and addresses are found only next to a cue (honorific, relation, field
label, house/village keyword followed by a PIN code). Names in running text
without a cue are not detected; a statistical NER detector can be registered
alongside these rules.
