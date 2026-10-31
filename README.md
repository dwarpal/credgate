# CredGate

**Governance-first PII detection for LLM requests, with Indian identifiers built in.**

CredGate finds personal data in text and data frames *before* it leaves the
machine for a language model. It is built for data scientists in regulated
Indian environments - banking, insurance, fintech and healthcare - working
under the DPDP Act 2023 and RBI, SEBI and IRDAI expectations, including
fully air-gapped setups.

It ships as an R package and a Python package (with a CLI) that read the same
detection rules, so both languages find exactly the same matches.

> **Status: early development (pre-alpha).** PII detection, column
> scanning (`scan_pii()`) and irreversible redaction (`redact()`,
> `preview()`) work today.
> Redaction/restore, policies, the audit log, proxy mode and the IDE
> assistant are planned; see [DESIGN.md](DESIGN.md) for the roadmap.

## What it detects

| Category | Identifiers |
|---|---|
| Government ID | Aadhaar (Verhoeff checksum), masked Aadhaar, Aadhaar Virtual ID, PAN (with holder type), voter ID (EPIC), passport, driving licence |
| Financial | GSTIN (mod-36 check character), payment cards (Luhn + network prefix), UPI IDs, IFSC, bank account numbers |
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
#>    1     7  16 person_name    XXXXX Nair       0.80
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

## Installation

**Python** is on PyPI; the **R** package is under CRAN review, so install it
from GitHub for now.

**Nix** (recommended; works offline once built):

```sh
nix build github:dwarpal/credgate#credgate      # CLI + Python package
nix build github:dwarpal/credgate#credgate-r    # R package
nix develop github:dwarpal/credgate             # R + Python dev shell
```

**R**

```r
# install.packages("remotes")
remotes::install_github("dwarpal/credgate", subdir = "pkg/credgate")
```

**Python** (3.11+)

```sh
pip install credgate
```

## Repository layout

| Path | Contents |
|---|---|
| [`spec/`](spec/) | The shared detection spec: every detector, engine parameters and the conformance cases both packages must pass. A compliance reviewer reads and approves these rules once, for every language. |
| [`pkg/credgate/`](pkg/credgate/) | R package |
| [`pkg/python/`](pkg/python/) | Python package and `credgate` CLI |
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

## Known limits

- Names and addresses are found only next to a cue: an honorific (Shri, Smt,
  श्रीमती), a relation (S/o, D/o), a field label (`Name:`, `पता:`) or a
  house/village keyword followed by a PIN code. Names in running text without
  such a cue are not detected yet.
- A random number can pass a checksum by chance, so a bare 12-digit number is
  reported as a possible Aadhaar with lower confidence; use the confidence
  and reasons to decide.
- The mapping to DPDP, RBI, SEBI and IRDAI obligations (planned for policies)
  is informational, not legal advice.

## Maintainers

- Bharat Sikka ([@bharatsikka](https://github.com/bharatsikka))
- Aishwarya Bais ([@aishwaryabais](https://github.com/aishwaryabais))

## Licence

Apache License 2.0; see [LICENSE](LICENSE).
