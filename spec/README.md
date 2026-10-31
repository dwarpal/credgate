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
4. **Context**: take up to `scoring.context_window` code points before and
   after the match in the normalised text, plus the caller's extra context
   (e.g. a column name). Search them, case-insensitively, for `context` and
   `negative`. With `context_required: true`, drop matches without context.
5. **Score**: start from `base` - a number, or `{default, rules}` where the
   first rule whose `match` regex matches the matched text sets the value.
   With context: `score + (1 - score) * context_boost`. With negative context:
   `score * negative_factor`. Round to `scoring.digits` decimal places.
6. **Reasons** (free text, for people): `matched <label> pattern`, then
   `checks` if set, `context '<keyword>'`, `negative context '<keyword>'`, then
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
| `class` | yes | Data class used by policies (`identity_strong`, `financial`, `health`, `contact`, `personal`, `quasi`) |
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
| `describe` | no | Extra reason per match |
| `canonical` | no | Canonical form (default `strip_upper`) |

Unknown fields are an error, so a typo cannot silently disable a rule.

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
tokenisation (`[PAN_1]` restored later) builds on the same spans.

Conformance cases are in `conformance/redact.yaml`.

## Known limits

Names and addresses are found only next to a cue (honorific, relation, field
label, house/village keyword followed by a PIN code). Names in running text
without a cue are not detected; a statistical NER detector can be registered
alongside these rules.
