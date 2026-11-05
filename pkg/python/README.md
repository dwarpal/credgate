# credgate

Detects personal data before it leaves the machine, with Indian identifiers
built in: Aadhaar (with Verhoeff checksum), Aadhaar Virtual ID, PAN, GSTIN,
voter ID, passport, driving licence, CKYC, ration card and NREGA job card
numbers, UPI IDs, IFSC, bank accounts, payment cards with expiry dates and
verification codes, +91 mobile numbers, ABHA, and names and addresses in
Latin and Indic scripts.

The detection rules live in a shared, language-neutral spec, so this package
and the R package `credgate` find exactly the same matches. Part of the
[CredGate](https://github.com/dwarpal/credgate) project; alpha.

## Use it with local LLMs (Ollama, vLLM)

Redact before the prompt reaches the model; the model only ever sees
placeholders such as `[PAN]` and `[PERSON_NAME]`.

```python
import credgate, ollama

note = "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210, wants the EMI date moved."
print(credgate.preview(note, min_confidence=0.5))   # what will be masked, and why
safe = credgate.redact(note, min_confidence=0.5)    # "Customer name: [PERSON_NAME]. PAN [PAN], mobile [MOBILE_IN], ..."
reply = ollama.chat(model="gemma3:1b", messages=[{"role": "user", "content": f"Summarise: {safe}"}])
```

With **vLLM** (or Ollama's `/v1`, LM Studio, any OpenAI-compatible server):

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
client.chat.completions.create(model="<served model>",
                               messages=[{"role": "user", "content": credgate.redact(note, min_confidence=0.5)}])
```

From the shell: `credgate redact notes.txt | ollama run gemma3:1b "Summarise:"`.
More runnable examples (ticket classification, RAG ingestion) are in the
[examples folder](https://github.com/dwarpal/credgate/tree/main/examples).

> **Check the preview.** Names are found next to an honorific, relation or
> field label (`Shri`, `S/o`, `Name:`, `नाम:`); a name in running text
> without such a cue ("Customer Priya Nair called") is not detected yet.
> Redaction is irreversible; to get the real values back in the model's
> answer, tokenise instead (see below), or let the
> [proxy](#proxy) do it for every request.

## How it compares

credgate, MaskFlow, Microsoft Presidio and Kavach PII on two public Indian
PII datasets and on credgate's own corpus - every tool at its default
settings, the same scoring rules for all:

| F1 (overlap) | Ylemis India-PII | IndiaPII-Bench | credgate corpus | PII-free documents flagged | Docs/s | Memory |
|---|---:|---:|---:|---:|---:|---:|
| **credgate** | 67.0 | **95.9** | **98.0** | **0%** | 1,050-2,800 | 35 MB |
| MaskFlow | **79.6** | 77.0 | 71.3 | 8% | 50-130 | 175 MB |
| Presidio, India-configured | 63.6 | 43.6 | 47.9 | 62% | 63-120 | 750 MB |
| Presidio, default | 52.6 | 35.6 | 41.0 | 38% | 57-114 | 670-750 MB |
| Kavach PII | 52.8 | 69.2 | 56.9 | **0%** | 3,000-8,700 | 20 MB |

<sub>All three datasets are synthetic, and each was written by someone with
a stake in the result: [Ylemis India-PII](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark)
by a PII model vendor, [IndiaPII-Bench](https://huggingface.co/datasets/maskflow-ai/indiapii-bench)
by MaskFlow's authors, the credgate corpus by us - so read the columns
together. Method, per-type results and how to rerun:
[benchmark/external/](https://github.com/dwarpal/credgate/blob/main/benchmark/external/README.md). The comparison is
independent and not affiliated with any of the projects compared.</sub>

**Where credgate is strong**: Indian identifiers found at or near 100% on
every dataset, almost without false alarms; addresses in the usual Indian
shape with or without a label; 15-25 times the speed of the tools that run
a language model.

**Where others do better**: names in running text without a cue (MaskFlow
and Presidio use a named-entity model; that is why credgate trails on
Ylemis), vehicle registration numbers, and breadth - Presidio covers
international identifiers, IP addresses, dates and images, and has years in
production. credgate is alpha and India-first. More in
[the benchmark post](https://dwarpal.github.io/credgate/blog/indian-pii-benchmarks/).

## Installation

Python 3.11 or later; depends only on `regex` and `PyYAML`.

```sh
pip install credgate
```

The development version: `pip install "git+https://github.com/dwarpal/credgate#subdirectory=pkg/python"`.

With Nix: `nix build github:dwarpal/credgate#credgate`.

## Usage

```python
import credgate

spans = credgate.detect_pii("Name: Priya Nair; PAN: ABCPN1234K; UPI: priya.n@oksbi")
for s in spans:
    print(s)
# Span(doc=0, start=6, end=16, type='person_name', value='XXXXX XXXX', confidence=0.8)
# Span(doc=0, start=23, end=33, type='pan', value='XXXXXX234K', confidence=0.97)
# Span(doc=0, start=40, end=53, type='upi_id', value='XXXXX.X@Xksbi', confidence=0.99)

spans[1].value    # 'ABCPN1234K' - printing masks values, the attribute does not
spans[1].reasons  # "matched PAN pattern; context 'PAN'; holder type: individual"
```

`detect_pii()` takes a string or a list of strings and returns `Span`
objects with the document index, 0-based end-exclusive positions, type, data
class, value, canonical form, confidence and reasons. `span.to_dict()` gives
a JSON-ready dict with the value masked (`reveal=True` to include it).

Redact identifiers, or preview what would be redacted and why:

```python
credgate.redact("Name: Priya Nair; PAN: ABCPN1234K")
# 'Name: [PERSON_NAME]; PAN: [PAN]'

print(credgate.preview("Name: Priya Nair; PAN: ABCPN1234K; order no 878245671885"))
# 3 items would be redacted:
#   Name: [PERSON_NAME]; PAN: [PAN]; order no [AADHAAR]
#
#   [PERSON_NAME]  XXXXX XXXX    0.80  matched Person name pattern
#   [PAN]          XXXXXX234K    0.97  matched PAN pattern; context 'PAN'; ...
#   [AADHAAR]      XXXXXXXX1885  0.42  ...; negative context 'order'
```

Tokenise instead, to get the real values back in a model's answer: the
vault keeps the mapping, and `restore()` puts the values back:

```python
vault = credgate.Vault()
credgate.tokenise([
    "Shri Ramesh Kumar, PAN ABCPE1234F, mobile +91 98765 43210",
    "pan abcpe1234f called again from 9876543210",
], vault)
# ['Shri [PERSON_NAME_1], PAN [PAN_1], mobile [MOBILE_IN_1]',
#  'pan [PAN_1] called again from [MOBILE_IN_1]']

credgate.restore("[PERSON_NAME_1] (PAN [pan_1]) will be called on MOBILE_IN_1.", vault)
# 'Ramesh Kumar (PAN ABCPE1234F) will be called on +91 98765 43210.'
```

The same identifier gets the same token however it is written, so the model
can still tell customers apart. `restore()` accepts tokens as models tend to
copy them (other case, spaces, missing brackets); `strict=True` raises
`UnknownTokenError` on a token the vault does not know. The vault prints
with values masked.

To restore tokens in a later session - or in R - save the vault to a file
encrypted with a passphrase (at least 12 characters; from the argument, the
`CREDGATE_VAULT_PASSPHRASE` environment variable, or a prompt):

```python
vault.save("loans.cgvault")                    # pip install 'credgate[vault]'
vault = credgate.Vault.open("loans.cgvault")   # later: same tokens, numbering continues
```

The passphrase is never stored: without it the file cannot be opened. Keep
`*.cgvault` files out of version control.

**Keyed tokens** make the same identifier get the same token everywhere -
across sessions, datasets, machines and R or Python - so tokenised tables
can still be joined and counted, and parallel workers agree:

```python
key = credgate.new_token_key()          # store it like a password, e.g. in CREDGATE_TOKEN_KEY
a, b = credgate.Vault(key), credgate.Vault(key)
a.tokenise("PAN ABCPE1234F")            # 'PAN [PAN_bpg46o6x465d4]' (depends on the key)
b.tokenise("pan abcpe1234f")            # the same token
a.merge(b)                              # combine vaults from parallel workers
```

Whoever holds the key can confirm a guessed value by computing its token,
so keep it out of code and project files. The key is never saved in a vault
file; opening a keyed vault needs it again (`Vault.open(path, key=...)`).


Scan a table (a pandas DataFrame, or a dict of column -> values) to see
which columns hold PII; column names count as context:

```python
report = credgate.scan_pii({
    "cust_pan": ["ABCPE1234F", "AAACR5055K", "XYZPQ9876R"],
    "notes": ["Called, Aadhaar 542229371182", "no issues", "mobile 9876543210"],
})
print(report)
# Scanned 2 column(s); PII found in 2: cust_pan, notes
#   cust_pan  pan              100% of 3 (3 whole value)  confidence 0.97  e.g. XXXXXX234F
#   notes     aadhaar           33% of 3 (0 whole value)  confidence 0.97  e.g. XXXXXXXX1182
#   notes     mobile_in         33% of 3 (0 whole value)  confidence 0.93  e.g. XXXXXX3210
pandas.DataFrame(report.to_records())  # as a table
```

Context makes generic patterns trustworthy; pass a column name or similar:

```python
credgate.detect_pii("ABC1234567")                      # [] - could be anything
credgate.detect_pii("ABC1234567", context="voter_id")  # voter ID, confidence 0.97
```

Checksums, synthetic test data and your own detectors:

```python
credgate.verhoeff_valid("542229371182")
credgate.synth_indian_pii(5, seed=1)   # synthetic records; never use as anonymised data

credgate.register_detector(credgate.Detector(
    id="employee_id", data_class="internal", label="Employee ID",
    patterns=credgate.bounded("EMP[0-9]{6}"),
))
```

## Large data: pandas, Polars, Arrow, DuckDB, Parquet

`redact()`, `tokenise()` and `detect_pii()` accept a pandas or Polars Series
or an Arrow array and return the same type (a Series keeps its index and
name; missing values stay missing). For tables, install the extra you need:
`pip install 'credgate[polars]'`, `'credgate[arrow]'` or `'credgate[duckdb]'`,
or everything (these, plus encrypted vaults) with `pip install 'credgate[all]'`.

```python
import polars as pl
import credgate.polars  # adds the .credgate namespace

df.with_columns(pl.col("notes").credgate.redact(min_confidence=0.5))
df.filter(pl.col("notes").credgate.has_pii())
```

```python
import duckdb, credgate.duckdb

con = duckdb.connect()
credgate.duckdb.register(con, min_confidence=0.5)   # adds cg_redact() and cg_has_pii()
con.sql("COPY (SELECT id, cg_redact(notes) AS notes FROM 'calls.parquet') TO 'safe.parquet'")
```

```python
import credgate.arrow
credgate.arrow.redact_parquet("calls.parquet", "safe.parquet", columns=["notes"])
```

```sh
credgate redact --parquet calls.parquet --column notes -o safe.parquet
credgate scan calls.parquet
```

See the [large-data guide](https://github.com/dwarpal/credgate/blob/main/docs/large-data.md)
for the approach and runnable examples. Parquet files, DuckDB queries and
Polars lazy frames are processed in
batches, so the data may be larger than memory. `scan_pii()` also accepts
Polars frames (eager or lazy), Arrow tables and datasets, and DuckDB
relations; it reads one column at a time and samples exactly as it does in
memory, so the report is the same at any size. Numbered tokens are not
offered inside Polars and DuckDB, which process batches in parallel and in
no fixed order; tokenise a Series or Arrow array instead.

## Command line

```sh
credgate detect notes.txt                      # masked report
credgate detect --lines --json customers.csv   # one JSON object per match
git diff --cached | credgate detect --fail     # non-zero exit if PII is found
credgate redact notes.txt > notes.redacted.txt  # replace PII with [PAN] etc.
credgate preview notes.txt                     # what would be redacted, and why
credgate scan customers.csv                    # which columns hold PII
credgate detectors                             # list detectors
```

Values are masked unless you pass `--reveal`.

## Policies

A policy decides, per destination, what happens to each identifier: allow,
redact, tokenise, or block the whole request. The same YAML file works in R:

```python
policy = credgate.Policy.load("bank-default.yaml")
decision = policy.apply(["Card 4111 1111 1111 1111 exp 12/27", "CVV 123"], "claude")
decision.allowed       # False
decision.blocked_by    # ('card-with-cvv-and-expiry',)
```

`policy.decide()` reports the decision without rewriting; `apply()` also
rewrites allowed requests (pass `vault=` when the policy tokenises). Loading
checks everything: an unknown field, tier, action or type raises
`PolicyError`. An example policy is in the repository's
`examples/policies/bank-default.yaml`.

## Audit log

Policy decisions can be recorded in an append-only, hash-chained log: who
sent which kinds of data to which endpoint, under which policy revision and
rule - never the text or the values. Editing, deleting or reordering records
is detected; with an audit key, identifiers are kept as keyed hashes; card
verification codes are never recorded. R and Python share the format.

```python
log = credgate.AuditLog("audit.jsonl")          # key from CREDGATE_AUDIT_KEY, if set
policy.apply(messages, "claude", audit=log)    # recorded, allowed or blocked
credgate.audit_verify("audit.jsonl")           # intact? and the head hash
credgate.audit_read("audit.jsonl")             # the records
```

## Proxy

The proxy puts the policy between people's tools and the model endpoints:
Claude Code, Copilot Chat, Open WebUI and the SDKs talk to it as to an
OpenAI, Anthropic or Ollama server; every request is allowed, redacted,
tokenised or blocked, recorded in the audit log, and tokenised values are
put back into the answer as it streams.

```sh
credgate proxy serve --policy bank-default.yaml --audit audit.jsonl
ANTHROPIC_BASE_URL=http://127.0.0.1:8790 claude          # Claude Code through it
```

As a shared server, each person has their own key that expires, and a users
file says who still has access:

```sh
credgate proxy add-user priya --keys keys.json --days 90   # the key is shown once
credgate users add priya --role admin --file users.yaml
credgate proxy serve --policy bank-default.yaml --audit audit.jsonl \
  --keys keys.json --users users.yaml --watch 10 --host 0.0.0.0
```

A new policy revision, keys file or users file is picked up without a
restart, and a revision whose tests fail is refused. InfoSec edits the
policy in the policy editor (below). See the
[proxy guide](https://dwarpal.github.io/credgate/proxy/) and the [deployment guide](https://dwarpal.github.io/credgate/deployment/).

## Policy editor

InfoSec can change a policy in a browser instead of editing YAML:

```sh
pip install 'credgate[editor]'
credgate editor --policy bank-default.yaml
```

It edits endpoints and rules, tries sample text against the unsaved policy,
runs the policy's tests before every save, and records who saved what and
why in a hash-chained change log. With a users file it shows each person
what their role allows (admin, auditor, user) and lets everyone manage their
own proxy key; behind single sign-on it serves a whole team. The R package
has the same app, and both work on the same files. See the
[policy editor guide](https://dwarpal.github.io/credgate/policy-editor/) and the
[deployment guide](https://dwarpal.github.io/credgate/deployment/).

## Masked output

Wherever credgate *shows* a detected value (printed matches, `preview()`,
`scan_pii()` examples, the command line), it masks it:

| Value | Shown as |
|---|---|
| Identifiers (Aadhaar, PAN, mobile, account, card, ...) | last 4 characters kept: `XXXX XXXX 1182`, `XXXXXX234F` |
| Names and addresses | masked in full: `XXXXX XXX` |

Keeping the last 4 characters lets you check which value matched, and stays
within the display limits of UIDAI's masked Aadhaar and PCI DSS (cards). If
your policy allows no part of a value to be shown, mask everything:

```python
credgate.set_mask("full")   # or the environment variable CREDGATE_MASK=full
```

Masking changes only what is displayed; detection and `redact()`
(`[AADHAAR]`, `[PERSON_NAME]`) are unaffected.

## Limits

Names are found only next to a cue: an honorific (Shri, Smt, श्रीमती, or
"ji" after the name), a relation (S/o, D/o) or a field label (`Name:`,
`नाम:`); for others, load the example custom detector `names-by-cue.yaml` or
your own. Addresses are found after a label (`Address:`, `पता:`), after a
house or village keyword, or in the usual shape - house number, locality, a
known Indian city or district, PIN code. A deity addressed with "ji" ("Ram
ji") is taken as a name. A bare 12-digit number may pass
the Aadhaar checksum by chance and is reported with lower confidence.

## Citing credgate

If you use credgate in your work, please cite it, with the version you
used (`credgate.__version__`):

Sikka B, Bais A (2026). *credgate: Detect Indian Personal Data Before It
Reaches Language Models.* Python package version 0.5.0.
https://github.com/dwarpal/credgate

```bibtex
@Manual{credgate,
  title  = {{credgate}: Detect Indian Personal Data Before It Reaches Language Models},
  author = {Bharat Sikka and Aishwarya Bais},
  year   = {2026},
  note   = {Python package version 0.5.0},
  url    = {https://github.com/dwarpal/credgate},
}
```

## Licence

Apache License 2.0.
