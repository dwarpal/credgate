# CredGate

**Governance-first PII detection for LLM requests, with Indian identifiers built in.**

CredGate finds personal data in text and data frames *before* it leaves the
machine for a language model. It is built for data scientists in regulated
Indian environments - banking, insurance, fintech and healthcare - working
under the DPDP Act 2023 and RBI, SEBI and IRDAI expectations, including
fully air-gapped setups.

It ships as an R package and a Python package (with a CLI) that read the same
detection rules, so both languages find exactly the same matches.

**Documentation:** <https://dwarpal.github.io/credgate/> - the Python API,
the [R package site](https://dwarpal.github.io/credgate/r/), guides and the
shared specification.

> **Status: early development (pre-alpha).** PII detection, column
> scanning (`scan_pii()`), redaction (`redact()`, `preview()`),
> reversible tokenisation (`tokenise()`, `restore()`, with an encrypted
> vault file), policies, the audit log and the PII inventory (data frames,
> Spark, BigQuery) work today. Proxy mode and the IDE assistant are planned;
> see [DESIGN.md](DESIGN.md) for the roadmap.

## Use it with local LLMs (Ollama, vLLM)

Redact before the prompt reaches the model, whether it runs on Ollama, vLLM
or any OpenAI-compatible server - the model only ever sees placeholders
such as `[PAN]` and `[PERSON_NAME]`.

**Python**

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

**R** (with [ellmer](https://ellmer.tidyverse.org))

```r
library(credgate); library(ellmer)

note <- "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210, wants the EMI date moved."
safe <- redact(note, min_confidence = 0.5)
chat_ollama(model = "gemma3:1b")$chat(paste("Summarise:", safe))
# vLLM: chat_vllm(base_url = "http://localhost:8000/v1", model = "<served model>")
```

**Shell**: `credgate redact notes.txt | ollama run gemma3:1b "Summarise:"`

**Need the real values in the answer?** Tokenise instead of redacting: the
model sees `[PAN_1]`, `[PERSON_NAME_1]`, and `restore()` puts the values back
into its reply.

```python
vault = credgate.Vault()
safe = credgate.tokenise(note, vault, min_confidence=0.5)   # "Customer name: [PERSON_NAME_1]. PAN [PAN_1], ..."
reply = ollama.chat(model="gemma3:1b", messages=[{"role": "user", "content": f"Draft a reply to: {safe}"}])
print(credgate.restore(reply.message.content, vault))      # real name and PAN back in the draft
```

In R: `vault <- cg_vault(); safe <- tokenise(note, vault); restore(answer, vault)`.

Runnable examples (call notes, ticket classification, RAG ingestion, data
frames, shell pipelines) are in [`examples/`](examples/); the R vignette
[Using credgate with local LLMs](pkg/credgate/vignettes/local-llms.Rmd)
walks through the workflow and why it matters even when the model is local
(shared GPU servers, logs, RAG indexes, DPDP data minimisation).

> **Check the preview.** Names are found next to an honorific, relation or
> field label (`Shri`, `S/o`, `Name:`, `नाम:`); a name in running text
> without such a cue ("Customer Priya Nair called") is not detected yet.
> Save the vault (`vault.save(path)`, R `vault_save()`) to restore tokens in
> a later session; it is encrypted with a passphrase. An automatic proxy
> that tokenises and restores for you is next on the roadmap.

## What it detects

| Category | Identifiers |
|---|---|
| Government ID | Aadhaar (Verhoeff checksum), masked Aadhaar, Aadhaar Virtual ID, PAN (with holder type), voter ID (EPIC), passport, driving licence, CKYC number (KIN), ration card number, NREGA job card number |
| Financial | GSTIN (mod-36 check character), payment cards (Luhn + network prefix), card expiry dates, card verification codes (CVV/CVC; always masked in full), UPI IDs, IFSC, bank account numbers |
| Contact | +91 mobile numbers, email addresses, PIN codes |
| Health | ABHA number, ABHA address |
| Personal | Names and postal addresses in Latin and Indic scripts (rule-based, see limits below) |

Every match comes with a confidence score and the reasons for it (checksum
passed, nearby keyword such as "Aadhaar" or "आधार", negative context such as
"order no"). Detection also works through Indic digits (`५४२२ २९३७ ११८२`),
fullwidth characters and zero-width characters hidden inside identifiers.

## Quick start

**R**

```r
library(credgate)

x <- detect_pii("Name: Priya Nair; PAN: ABCPN1234K; UPI: priya.n@oksbi")
x
#> 3 PII matches (values masked; use `x$value` to see them):
#>  doc start end        type         value confidence
#>    1     7  16 person_name    XXXXX XXXX       0.80
#>    1    24  33         pan    XXXXXX234K       0.97
#>    1    41  53      upi_id XXXXX.X@Xksbi       0.99
```

**Python**

```python
import credgate

for span in credgate.detect_pii("आधार: ५४२२ २९३७ ११८२, मोबाइल 9468451273"):
    print(span)
# Span(doc=0, start=6, end=20, type='aadhaar', value='XXXX XXXX ११८२', confidence=0.97)
# Span(doc=0, start=29, end=39, type='mobile_in', value='XXXXXX1273', confidence=0.93)
```

**Scanning a table** (R `scan_pii(df)`, Python `credgate.scan_pii(df)`)
reports which columns hold PII without sending anything anywhere:

```text
Scanned 2 columns; PII found in 2: cust_pan and notes
   column      type rate matched whole confidence      example
 cust_pan       pan 100%  3 of 3     3       0.97   XXXXXX234F
    notes   aadhaar  33%  1 of 3     0       0.97 XXXXXXXX1182
```

**Command line**

```sh
credgate detect notes.txt                      # masked report
credgate detect --lines --json customers.csv   # one JSON object per match
credgate scan customers.csv                    # which columns hold PII
credgate redact notes.txt > notes.redacted.txt  # replace PII with [PAN] etc.
credgate preview notes.txt                     # what would be redacted, and why
git diff --cached | credgate detect --fail     # non-zero exit if PII is found
```

Values are masked whenever results are printed; the real values are only
available programmatically (`x$value`, `span.value`) or with `--reveal`.

## Policies

A policy says, per destination, what happens to each kind of identifier:
let it through, redact it, tokenise it, or block the whole request. It is a
YAML file owned by InfoSec and compliance, and the same file works in R and
Python. It is also the register of model endpoints: each has a tier -
`local` (the analyst's machine), `internal` (open models the organisation
runs, such as vLLM or SGLang) or `frontier` (Claude, OpenAI, Gemini, also
through the organisation's own gateway) - a provider and URL, and can be
`blocked`; an endpoint that is not listed receives nothing. Rules can target
tiers or particular endpoints. See
[`examples/policies/bank-default.yaml`](examples/policies/bank-default.yaml):
in-house models may see customer data (but not government IDs on the shared
GPU server), frontier models may not, a card number with its CVV and expiry
is never sent to a frontier model, card verification codes never leave, and
Copilot is blocked.

```python
policy = credgate.Policy.load("bank-default.yaml")
decision = policy.apply(messages, "claude")   # destination named in the policy
if decision.allowed:
    send(decision.texts)
else:
    print(decision.blocked_by)                # e.g. ('card-with-cvv-and-expiry',)
```

In R: `policy_apply(cg_policy("bank-default.yaml"), messages, "claude")`.
Everything is checked when the policy is loaded - an unknown field, tier,
action or identifier type is an error, never a silent "allow" - and every
decision names the policy revision and the rule behind each action, ready
for the audit log. The format is specified in [spec/README.md](spec/README.md#policies-policy).

## Audit log

Every policy decision can be recorded in an append-only audit log: who sent
which kinds of data to which endpoint, under which policy revision and rule,
allowed or blocked - never the text or the values. Each record holds the
hash of the one before, so editing, deleting, inserting or reordering
records is detected; keep copies of the latest hash (the head) elsewhere to
detect records removed from the end. With an audit key, identifiers are
recorded as keyed hashes, so an investigator with the key can check whether
a given PAN went to a given model; card verification codes are never
recorded in any form.

```python
log = credgate.AuditLog("audit.jsonl")             # key from CREDGATE_AUDIT_KEY, if set
policy.apply(messages, "claude", audit=log)       # recorded, allowed or blocked
credgate.audit_verify("audit.jsonl")              # intact? and the head hash
```

In R: `log <- cg_audit_log("audit.jsonl")`, `policy_apply(..., audit = log)`,
`audit_verify()`, `audit_read()`. R and Python write and verify the same
files. Rotation and retention (default 5 years, at least 1, per the
[threat model](docs/threat-model.md)) come with the proxy.

## PII inventory

Discovery at scale starts with an inventory: which tables and columns hold
which kinds of personal data. `pii_inventory()` scans a table with the
`scan_pii()` rules and records every column - also those where nothing was
found, so the inventory shows what was covered - with the source, table,
sample size and when it was scanned. It never records values, not even
masked ones. Inventories of many tables are combined and saved as a CSV
file that R and Python write identically.

```python
inv = credgate.pii_inventory(customers, source="crm", table="customers")
inv += credgate.pii_inventory(calls, source="crm", table="calls")
inv.write("inventory.csv")                       # credgate.read_inventory() reads it back
```

In R: `pii_inventory(customers, source = "crm", table = "customers")`,
combined with `rbind()`, saved with `write_inventory()` and read with
`read_inventory()`.

Spark tables work the same way, from PySpark and sparklyr: the table is
sampled inside the cluster and only the sample reaches the driver, so
Hadoop and Hive data can be inventoried where it lives.

```python
df = spark.table("crm.customers")
inv = credgate.pii_inventory(df, source="hive", table="crm.customers")
```

```r
customers <- dplyr::tbl(sc, "customers")              # sc from sparklyr::spark_connect()
inv <- pii_inventory(customers, source = "hive", table = "crm.customers")
```

BigQuery tables are sampled by BigQuery itself, and only the sample is
downloaded. Only the columns credgate can scan are read, and a dry run
checks every query's cost first: anything estimated above `max_bytes`
(default 1 GB) is refused before it runs.

```python
from credgate import bigquery as cgbq
inv = cgbq.inventory_dataset(client, "my-project.crm")     # every table in a dataset
```

In R, with bigrquery: `bq_pii_inventory("my-project.crm.customers")`,
`bq_inventory_dataset("my-project.crm")`, `bq_scan_pii()`. A script to
check it against real BigQuery, in the free sandbox, is in
[`examples/bigquery/`](examples/bigquery/).

## Large data

credgate works on tables too big for memory, in both languages and on the
command line:

| | Python | R |
|---|---|---|
| Parquet | `credgate.arrow.redact_parquet()` | `redact_parquet()` |
| DuckDB | SQL: `SELECT cg_redact(notes) FROM 'calls.parquet'` | `redact_query()`, `scan_pii(dplyr::tbl(con, ...))` |
| Polars | `pl.col("notes").credgate.redact()` | - |
| Arrow, pandas | Series, arrays, tables, datasets | arrays, tables, datasets |
| Other databases | - | any DBI database via dbplyr |
| Spark | `scan_pii(df)`, `pii_inventory(df, ...)` | `scan_pii(tbl)`, `pii_inventory(tbl, ...)` (sparklyr) |
| BigQuery | `credgate.bigquery.pii_inventory()`, `inventory_dataset()` | `bq_pii_inventory()`, `bq_inventory_dataset()` |

```sh
credgate scan calls.parquet
credgate redact --parquet calls.parquet --column notes -o calls_safe.parquet
```

`scan_pii()` reads big tables one column at a time and gives the same report
as in memory. The [large-data guide](docs/large-data.md) explains the
approach with Python, R and command-line examples; runnable versions are in
[`examples/`](examples/README.md#large-data-parquet-polars-duckdb-arrow), and
the R vignette `vignette("large-data", package = "credgate")` walks through
it. Throughput is measured in [benchmark/README.md](benchmark/README.md#throughput).

## Installation

**Python** is on PyPI; the **R** package is under CRAN review, so install it
from [R-universe](https://dwarpal.r-universe.dev) or GitHub for now.

**Nix** (recommended; works offline once built):

```sh
nix build github:dwarpal/credgate#credgate      # CLI + Python package
nix build github:dwarpal/credgate#credgate-r    # R package
nix develop github:dwarpal/credgate             # R + Python dev shell
```

**R**

```r
# Development version, prebuilt for Windows, macOS and Linux (R-universe):
install.packages("credgate",
  repos = c("https://dwarpal.r-universe.dev", "https://cloud.r-project.org"))

# or from GitHub (needs build tools on Windows and macOS):
# install.packages("remotes")
remotes::install_github("dwarpal/credgate", subdir = "pkg/credgate")
```

**Python** (3.11+)

```sh
pip install credgate
```

## Accuracy, and how it compares

On a labelled benchmark of 700 held-out **synthetic** Indian-context
documents (KYC forms, bank messages, call-centre notes, Hinglish chats, Hindi
text, hospital summaries - generated by a script and included in
[`benchmark/corpus/`](benchmark/corpus/); no real personal data), compared
with Microsoft Presidio on the same data and the same scoring rules:

| On 700 held-out synthetic documents | Precision | Recall | **F1** | Time |
|---|---:|---:|---:|---:|
| **credgate** | 1.000 | 0.961 | **0.980** | 0.3 s |
| Presidio, India-configured | 0.609 | 0.754 | 0.674 | 11.6 s |
| Presidio, default | 0.565 | 0.498 | 0.529 | 12.1 s |

<sub>**About the data:** the 700 documents are **synthetic** - KYC forms, bank
messages, call-centre notes, Hinglish chats, Hindi text and hospital
summaries generated by
[`benchmark/generate_corpus.py`](https://github.com/dwarpal/credgate/blob/main/benchmark/generate_corpus.py)
and included in the repository under
[`benchmark/corpus/`](https://github.com/dwarpal/credgate/tree/main/benchmark/corpus).
No real personal data was used.
Types both tools cover, exact span matching, thresholds tuned on a
separate dev split for every system; time is for 1,400 documents. Synthetic
data generated by us, so read with that in mind.</sub>

**Where Presidio does better.** credgate is built for Indian identifiers
and Indian-language context, and that is what this benchmark measures.
Presidio is broader and more mature:

- **Voter IDs without context**: Presidio scores 1.000 here, credgate 0.679
  (credgate reports a bare voter ID format at low confidence, 0.3, because
  it could equally be a product code).
- **Many more entity types**: international IDs (US, UK, EU, ...), IBAN, IP
  and MAC addresses, URLs, crypto wallets, dates, nationality and religion -
  credgate detects none of these.
- **Names in running text**: Presidio's NER finds names without an honorific,
  field label or "ji"; credgate does not yet.
- **Anonymisation**: Presidio can mask, hash or encrypt with a key, and
  add custom operators; credgate redacts, or tokenises with an in-memory
  vault that can be saved encrypted (no hashing or encryption operators).
- **Beyond text**: image (OCR) and structured-data redaction, a REST service
  and Docker images.
- **Maturity and extensibility**: years in production, many languages and
  NLP back-ends, custom recognisers; credgate is pre-alpha.
- **The corpus favours credgate**: we generated it; on general English text
  Presidio may well do better.

Full method, per-type results and how to reproduce:
[benchmark/README.md](https://github.com/dwarpal/credgate/blob/main/benchmark/README.md).
The comparison is independent and not affiliated with Microsoft.

Across all 22 types credgate covers (including UPI, IFSC, ABHA, driving
licence, PIN code, CKYC, ration card and NREGA job card numbers, card
verification codes and expiry dates, which Presidio has no recogniser for),
credgate's F1 is 0.980 with precision 1.000 at its default
`min_confidence = 0.5`. The corpus and its templates are ours, and rules
were refined on its dev split, so expect lower numbers on unseen text. R and
Python give identical results.

## Repository layout

| Path | Contents |
|---|---|
| [`spec/`](spec/) | The shared detection spec: every detector, engine parameters and the conformance cases both packages must pass. A compliance reviewer reads and approves these rules once, for every language. |
| [`pkg/credgate/`](pkg/credgate/) | R package |
| [`pkg/python/`](pkg/python/) | Python package and `credgate` CLI |
| [`benchmark/`](benchmark/) | Synthetic labelled corpus, generator and accuracy report |
| [`flake.nix`](flake.nix) | Nix packages, sandboxed test checks and dev shell |
| [`DESIGN.md`](DESIGN.md) | Architecture, roadmap and design decisions |
| [`tools/sync-spec.sh`](tools/sync-spec.sh) | Copies `spec/` into both packages after an edit |

## Development

```sh
nix develop                 # R, Python, ruff, test tools
nix flake check             # R tests, Python tests (3.11/3.13/3.14), ruff, spec sync
```

After editing anything in `spec/`, run `tools/sync-spec.sh` and add a
conformance case in `spec/conformance/detect.yaml`; both test suites run
those cases. All test data is synthetic (`synth_indian_pii()`); never commit
real personal data.

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

```r
options(credgate.mask = "full")   # R
```

```python
credgate.set_mask("full")         # Python
```

or the environment variable `CREDGATE_MASK=full` for both, and the command
line.

Masking changes only what is displayed; detection and `redact()`
(`[AADHAAR]`, `[PERSON_NAME]`) are unaffected.

## Security

credgate runs entirely offline: no network calls, telemetry or downloads.
Secrets (vault passphrases) come only from arguments, environment variables
or a prompt, and detected values are masked whenever credgate shows them.
The [threat model](docs/threat-model.md) sets out what credgate protects,
against whom, what it trusts and where it does not protect, for InfoSec and
compliance reviews. Please report security issues privately, as described
in [SECURITY.md](SECURITY.md), rather than in a public issue.

## Known limits

- Names and addresses are found only next to a cue: an honorific (Shri, Smt,
  श्रीमती, or "ji" after the name), a relation (S/o, D/o), a field label
  (`Name:`, `पता:`) or a house/village keyword followed by a PIN code. Names
  in running text without such a cue are not detected yet, and a deity
  addressed with "ji" ("Ram ji") is taken as a name.
- CKYC numbers are found only next to a cue ("CKYC", "KIN"), since any
  14-digit number could be one. Ration card numbers have no national format
  and NREGA job card numbers vary by state: those detectors follow the
  published structure and the labels people use, and should be checked
  against samples of your own data.
- A voter ID format (3 letters, 7 digits) without a nearby cue such as
  "voter" or "EPIC" is reported with low confidence (0.3): it could equally
  be a product code.
- A random number can pass a checksum by chance, so a bare 12-digit number is
  reported as a possible Aadhaar with lower confidence; use the confidence
  and reasons to decide.
- The mapping to DPDP, RBI, SEBI and IRDAI obligations (planned for policies)
  is informational, not legal advice.

## Maintainers

- Bharat Sikka ([@bharatsikka](https://github.com/bharatsikka))
- Aishwarya Bais ([@aishwaryabais](https://github.com/aishwaryabais))

## Citing credgate

If you use credgate in your work, please cite it, and say which package
(R or Python) and version you used. GitHub's **Cite this repository**
button (from [CITATION.cff](CITATION.cff)) gives APA and BibTeX; in R,
`citation("credgate")` prints the reference.

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

Apache License 2.0; see [LICENSE](LICENSE).
