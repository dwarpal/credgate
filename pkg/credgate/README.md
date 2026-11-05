# credgate

Detects personal data before it leaves the machine, with Indian identifiers
built in: Aadhaar (with Verhoeff checksum), Aadhaar Virtual ID, PAN, GSTIN,
voter ID, passport, driving licence, CKYC, ration card and NREGA job card
numbers, UPI IDs, IFSC, bank accounts, payment cards with expiry dates and
verification codes, +91 mobile numbers, ABHA, and names and addresses in
Latin and Indic scripts.

The detection rules live in a shared, language-neutral spec, so this package
and the Python package `credgate` find exactly the same matches. Part of the
[CredGate](https://github.com/dwarpal/credgate) project; alpha.

## Use it with local LLMs (Ollama, vLLM)

Redact before the prompt reaches the model; the model only ever sees
placeholders such as `[PAN]` and `[PERSON_NAME]`:

```r
note <- "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210, wants the EMI date moved."
preview(note, min_confidence = 0.5)   # what will be masked, and why
```

```r
library(credgate); library(ellmer)

safe <- redact(note, min_confidence = 0.5)
chat_ollama(model = "gemma3:1b")$chat(paste("Summarise:", safe))
# vLLM: chat_vllm(base_url = "http://localhost:8000/v1", model = "<served model>")
```

The vignette `vignette("local-llms", package = "credgate")` walks through
Ollama, vLLM, data frames and evaluation; runnable scripts are in the
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

CRAN submission of 0.1.0 is under review. Until it is accepted, install
the development version from R-universe or GitHub:

```r
# Development version, prebuilt for Windows, macOS and Linux (R-universe):
install.packages("credgate",
  repos = c("https://dwarpal.r-universe.dev", "https://cloud.r-project.org"))

# or from GitHub (needs build tools on Windows and macOS):
# install.packages("remotes")
remotes::install_github("dwarpal/credgate", subdir = "pkg/credgate")
```

With Nix: `nix build github:dwarpal/credgate#credgate-r`.

## Usage

```r
library(credgate)

x <- detect_pii("Name: Priya Nair; PAN: ABCPN1234K; UPI: priya.n@oksbi")
x
#> 3 PII matches (values masked; use `x$value` to see them):
#>  doc start end        type         value confidence
#>    1     7  16 person_name    XXXXX XXXX       0.80
#>    1    24  33         pan    XXXXXX234K       0.97
#>    1    41  53      upi_id XXXXX.X@Xksbi       0.99

x$reasons[2]
#> [1] "matched PAN pattern; context 'PAN'; holder type: individual"
```

`detect_pii()` takes a character vector and returns one row per match with
the document index, character positions, type, data class, value, canonical
form (for consistent tokenisation), confidence and reasons. Printing masks
the values.

Context makes generic patterns trustworthy. Pass extra context, such as a
column name, with `context`:

```r
detect_pii("ABC1234567")                       # nothing: could be anything
detect_pii("ABC1234567", context = "voter_id") # Voter ID, confidence 0.97
```

Indic digits, fullwidth characters and zero-width characters are normalised
before matching, and positions refer to your original text:

```r
detect_pii("आधार: ५४२२ २९३७ ११८२")$type
#> [1] "aadhaar"
```

### Redacting and previewing

`redact()` replaces each identifier with a placeholder naming its type;
`preview()` shows what would be redacted and why, before anything is sent:

```r
redact("Name: Priya Nair; PAN: ABCPN1234K")
#> [1] "Name: [PERSON_NAME]; PAN: [PAN]"

preview("Name: Priya Nair; PAN: ABCPN1234K; order no 878245671885")
#> 3 items would be redacted:
#>   Name: [PERSON_NAME]; PAN: [PAN]; order no [AADHAAR]
```

followed by a table of each placeholder, the masked value, its confidence
and the reasons (here the order number scores only 0.42 because of the
word "order"; use `min_confidence` to leave such matches alone). Both are
new after 0.1.0: install the GitHub version to use them.

### Tokenising and restoring

Redaction is one-way. To get the real values back in a model's answer,
`tokenise()` replaces identifiers with numbered tokens and keeps the
mapping in a vault; `restore()` puts the values back:

```r
vault <- cg_vault()
tokenise(c(
  "Shri Ramesh Kumar, PAN ABCPE1234F, mobile +91 98765 43210",
  "pan abcpe1234f called again from 9876543210"
), vault)
#> [1] "Shri [PERSON_NAME_1], PAN [PAN_1], mobile [MOBILE_IN_1]"
#> [2] "pan [PAN_1] called again from [MOBILE_IN_1]"

restore("[PERSON_NAME_1] (PAN [pan_1]) will be called on MOBILE_IN_1.", vault)
#> [1] "Ramesh Kumar (PAN ABCPE1234F) will be called on +91 98765 43210."
```

The same identifier gets the same token however it is written, so the model
can still tell customers apart. `restore()` accepts tokens as models tend to
copy them (other case, spaces, missing brackets); `strict = TRUE` stops on a
token the vault does not know. The vault prints with values masked.

To restore tokens in a later session - or in Python - save the vault to a
file encrypted with a passphrase (at least 12 characters; from the argument,
the `CREDGATE_VAULT_PASSPHRASE` environment variable, or a prompt):

```r
vault_save(vault, "loans.cgvault")      # needs the sodium package
vault <- vault_open("loans.cgvault")    # later: same tokens, numbering continues
```

The passphrase is never stored: without it the file cannot be opened. Keep
`*.cgvault` files out of version control.

**Keyed tokens** make the same identifier get the same token everywhere -
across sessions, datasets, machines and R or Python - so tokenised tables
can still be joined and counted, and parallel workers agree (needs the
openssl package):

```r
key <- cg_new_token_key()   # store it like a password, e.g. in CREDGATE_TOKEN_KEY
a <- cg_vault(key)
b <- cg_vault(key)
tokenise("PAN ABCPE1234F", a)   # "PAN [PAN_bpg46o6x465d4]" (depends on the key)
tokenise("pan abcpe1234f", b)   # the same token
vault_merge(a, b)               # combine vaults from parallel workers
```

Whoever holds the key can confirm a guessed value by computing its token,
so keep it out of code and project files. The key is never saved in a vault
file; `vault_open(path, key = ...)` needs it again.


### Scanning data frames

`scan_pii()` reports which columns hold PII and how much, without sending
anything anywhere. (New after 0.1.0: until the next CRAN release, install
the GitHub version to use it.) Column names count as context, so a column called
`voter_id` or `cust_pan` supports those types:

```r
customers <- data.frame(
  cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R"),
  notes = c("Called, Aadhaar 542229371182", "no issues", "mobile 9876543210")
)
scan_pii(customers)
#> Scanned 2 columns; PII found in 2: cust_pan and notes
#>    column      type rate matched whole confidence      example
#>  cust_pan       pan 100%  3 of 3     3       0.97   XXXXXX234F
#>     notes   aadhaar  33%  1 of 3     0       0.97 XXXXXXXX1182
#>     notes mobile_in  33%  1 of 3     0       0.93   XXXXXX3210
```

`whole` counts values that are entirely the identifier (an ID column)
rather than containing it (free text). Large columns are sampled
(`sample = 10000` values by default).

### Checksums and test data

```r
verhoeff_valid("542229371182")    # Aadhaar / VID checksum
luhn_valid("4111 1111 1111 1111") # payment cards
gstin_valid("27AAPFU0939F1ZV")    # GSTIN check character

synth_indian_pii(5, seed = 1)     # synthetic records for tests and demos
```

Synthetic values pass the same validation as real ones but are random; use
them for tests, never as anonymised data.

### Your own detectors

```r
register_detector(new_detector(
  id = "employee_id", class = "internal", label = "Employee ID",
  pattern = bounded("EMP[0-9]{6}")
))
cg_detectors() # all registered detectors
```

### Large data: Arrow, Parquet, DuckDB

Tables too big for memory are read in chunks. Install the packages you use
(`arrow`, `duckdb`, `DBI`, `dbplyr`):

```r
scan_pii(arrow::open_dataset("calls.parquet"))           # one column at a time
redact_parquet("calls.parquet", "calls_safe.parquet", columns = "notes")

con <- DBI::dbConnect(duckdb::duckdb())
scan_pii(dplyr::tbl(con, "calls"))                       # any dbplyr table
redact_query(con, "SELECT call_id, notes FROM calls", "calls_safe")
```

Any DBI database works the same way, for example Postgres:

```r
con <- DBI::dbConnect(RPostgres::Postgres(), dbname = "lending", host = "db.internal")
scan_pii(dplyr::tbl(con, "loan_notes"))                     # needs dbplyr
redact_query(con, "SELECT id, notes FROM loan_notes", "loan_notes_safe")
```

`redact()`, `tokenise()` and `detect_pii()` also accept Arrow arrays. See
`vignette("large-data")` and the
[large-data guide](https://github.com/dwarpal/credgate/blob/main/docs/large-data.md).

## Policies

A policy decides, per destination, what happens to each identifier: allow,
redact, tokenise, or block the whole request. The same YAML file works in
Python:

```r
policy <- cg_policy("bank-default.yaml")
d <- policy_apply(policy, c("Card 4111 1111 1111 1111 exp 12/27", "CVV 123"), "claude")
d$allowed      # FALSE
d$blocked_by   # "card-with-cvv-and-expiry"
```

`policy_decide()` reports the decision without rewriting; `policy_apply()`
also rewrites allowed requests (pass `vault =` when the policy tokenises).
Loading checks everything: an unknown field, tier, action or type is an
error. An example policy is in the repository's
`examples/policies/bank-default.yaml`.

## Audit log

Policy decisions can be recorded in an append-only, hash-chained log: who
sent which kinds of data to which endpoint, under which policy revision and
rule - never the text or the values. Editing, deleting or reordering records
is detected; with an audit key, identifiers are kept as keyed hashes; card
verification codes are never recorded. R and Python share the format.

```r
log <- cg_audit_log("audit.jsonl")                  # key from CREDGATE_AUDIT_KEY, if set
policy_apply(policy, messages, "claude", audit = log)  # recorded, allowed or blocked
audit_verify("audit.jsonl")                         # intact? and the head hash
audit_read("audit.jsonl")                           # the records, as a data frame
```

## Policy editor

InfoSec can change a policy in a browser instead of editing YAML (needs
`shiny` and `bslib`):

```r
policy_editor("bank-default.yaml")
```

It edits endpoints and rules, tries sample text against the unsaved policy,
runs the policy's tests before every save, and records who saved what and
why in a hash-chained change log. With a users file it shows each person
what their role allows (admin, auditor, user) and lets everyone manage their
own proxy key; behind single sign-on it serves a whole team. The Python
package has the same app (`credgate editor`), and both work on the same
files. See the
[policy editor guide](https://dwarpal.github.io/credgate/policy-editor/) and the
[deployment guide](https://dwarpal.github.io/credgate/deployment/).

## Proxy

The proxy (in the Python package) puts the policy between people's tools
and the model endpoints: Claude Code, Copilot Chat, Open WebUI, the SDKs and
R's `ellmer` talk to it as to an OpenAI, Anthropic or Ollama server, and
every request is allowed, redacted, tokenised or blocked, and audited. From
R, point a client at it, and manage who may use a shared proxy:

```r
key <- proxy_add_user("keys.json", "priya", days = 90)   # shown once
proxy_users("keys.json")                                  # who, and when keys expire
```

See the [proxy guide](https://dwarpal.github.io/credgate/proxy/).

## Masked output

Wherever credgate *shows* a detected value (printed matches, `preview()`,
`scan_pii()` examples), it masks it:

| Value | Shown as |
|---|---|
| Identifiers (Aadhaar, PAN, mobile, account, card, ...) | last 4 characters kept: `XXXX XXXX 1182`, `XXXXXX234F` |
| Names and addresses | masked in full: `XXXXX XXX` |

Keeping the last 4 characters lets you check which value matched, and stays
within the display limits of UIDAI's masked Aadhaar and PCI DSS (cards). If
your policy allows no part of a value to be shown, mask everything:

```r
options(credgate.mask = "full")   # or CREDGATE_MASK=full in ~/.Renviron
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

If you use credgate in your work, please cite it. In R:

```r
citation("credgate")
```

## Licence

Apache License 2.0.
