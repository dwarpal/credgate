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
   patterns are combined.
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

Unknown fields are an error, so a typo cannot silently disable a rule.

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
