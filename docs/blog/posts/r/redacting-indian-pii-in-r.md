---
date:
  created: 2026-11-06
authors:
  - bharat
  - aishwarya
categories:
  - R
  - Detection
slug: redacting-indian-pii-in-r
draft: false
description: Find Aadhaar, PAN, mobile numbers and other Indian personal data in R text and data frames, and redact or tokenise it before a prompt reaches a language model - with ellmer, Ollama or any provider.
---

# Redacting Indian personal data in R before it reaches an LLM

R users are wiring language models into their work quickly: summarising
call notes with [ellmer](https://ellmer.tidyverse.org), classifying
tickets, drafting replies. In a bank, an insurer or a hospital those notes
are full of Aadhaar numbers, PANs and mobile numbers, and the DPDP Act, RBI
guidance and plain caution all say they should not go to a model that does
not need them - often not even to one running in-house on a shared server.

[credgate](https://github.com/dwarpal/credgate) is an R package (with a
Python twin) that finds Indian personal data and takes it out before the
prompt leaves your session. This post shows the R side.

<!-- more -->

## Find it

```r
# install.packages("credgate", repos = c("https://dwarpal.r-universe.dev", "https://cloud.r-project.org"))
library(credgate)

note <- "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210, wants the EMI date moved."
detect_pii(note)
#> 3 PII matches (values masked; use `x$value` to see them):
#>  doc start end        type           value confidence
#>    1    16  25 person_name      XXXXX XXXX       0.80
#>    1    32  41         pan      XXXXXX234K       0.97
#>    1    51  65   mobile_in +XX XXXXX X3210       0.97
```

Every match has a confidence and, if you ask, the reasons for it. These are
not just patterns: an Aadhaar number must pass its Verhoeff checksum, a card
number its Luhn check, a GSTIN its check character, so a mistyped or
made-up number is not reported. Words nearby raise or lower the confidence:
"PAN" next to a PAN-shaped value makes it near certain, "order no" next to a
12-digit number makes it unlikely to be an Aadhaar. Values are masked
whenever credgate prints them, so a console log or a knitted report does not
leak them either.

It reads Indian text as it is written, Devanagari digits included:

```r
detect_pii("आधार: ५४२२ २९३७ ११८२, मोबाइल 9468451273")
#> 2 PII matches (values masked; use `x$value` to see them):
#>  doc start end      type          value confidence
#>    1     7  20   aadhaar XXXX XXXX ११८२       0.97
#>    1    30  39 mobile_in     XXXXXX1273       0.93
```

## Look before you send

`preview()` shows exactly what would be replaced, and why:

```r
preview(note, min_confidence = 0.5)
#> 3 items would be redacted:
#>   Customer name: [PERSON_NAME]. PAN [PAN], mobile [MOBILE_IN], wants the EMI date moved.
#>
#>  placeholder   value           confidence reasons
#>  [PERSON_NAME] XXXXX XXXX      0.80       matched Person name pattern
#>  [PAN]         XXXXXX234K      0.97       matched PAN pattern; context 'PAN'; holder type: individual
#>  [MOBILE_IN]   +XX XXXXX X3210 0.97       matched Indian mobile number pattern; context 'mob'
```

## Redact, then ask the model

```r
library(ellmer)

safe <- redact(note, min_confidence = 0.5)
safe
#> [1] "Customer name: [PERSON_NAME]. PAN [PAN], mobile [MOBILE_IN], wants the EMI date moved."

chat_ollama(model = "gemma3:1b")$chat(paste("Summarise in one line:", safe))
```

The model only ever sees `[PAN]` and `[MOBILE_IN]`. The same works with
`chat_openai()`, `chat_anthropic()`, `chat_vllm()` or any other provider:
credgate runs before the request, in your R session, and makes no network
calls of its own.

## Need the real values back? Tokenise

Redaction is one-way. When the answer should contain the real values - a
drafted reply to the customer, say - tokenise instead: the model sees
numbered tokens, and `restore()` puts the values back into its answer.

```r
vault <- cg_vault()
tokenise(note, vault, min_confidence = 0.5)
#> [1] "Customer name: [PERSON_NAME_1]. PAN [PAN_1], mobile [MOBILE_IN_1], wants the EMI date moved."

answer <- "Dear [PERSON_NAME_1], your request to move the EMI date for PAN [PAN_1] is noted."
restore(answer, vault)
#> [1] "Dear Priya Nair, your request to move the EMI date for PAN ABCPN1234K is noted."
```

The vault stays in your session; `vault_save()` writes it encrypted with a
passphrase if you need it later.

## Data frames

Before a table goes into a prompt, a RAG index or a shared file, find out
which columns hold personal data:

```r
calls <- data.frame(
  id = 1:4,
  cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R", "BNZPM2501F"),
  notes = c("Called, Aadhaar 2345 6789 0124", "no issues", "mobile 9876543210", "asked about EMI")
)
scan_pii(calls)
#> Scanned 3 columns; PII found in 2: cust_pan and notes
#>    column      type rate matched whole confidence        example
#>  cust_pan       pan 100%  4 of 4     4       0.97     XXXXXX234F
#>     notes   aadhaar  25%  1 of 4     0       0.97 XXXX XXXX 0124
#>     notes mobile_in  25%  1 of 4     0       0.93     XXXXXX3210
```

For tables too big for memory, the same functions work on Arrow datasets,
Parquet files, DuckDB and other databases through DBI, and Spark through
sparklyr, sampling where the data lives. See
[large data](../../../large-data.md).

## What it does not do (yet)

- **Names in running text.** credgate finds names after a title, label or
  relation ("Smt.", "Name:", "S/o"), not in a sentence like "Delivery to
  Sandeep Pillai". If you know a column holds names, say so and every value
  is read as one; for notes, add your own name list or cues as a
  [custom detector](../../../custom-detectors.md).
- **Evasion.** It handles accidental variation - Indic digits, hidden
  characters, mixed case - not someone deliberately spelling a PAN out letter
  by letter.

## Going further

- **Policies**: which models may see what, decided by InfoSec in one YAML
  file and applied with `policy_apply()`; every decision can go to a
  tamper-evident audit log.
- **A proxy** (from the Python package) applies the same policy to every
  request from Claude Code, Copilot Chat or ellmer pointed at it.
- [How a match is scored](../../../how-it-works.md), step by step.

credgate is open source (Apache-2.0) and alpha: we are looking for people to
try it and tell us what it misses. [Report a detection problem](https://github.com/dwarpal/credgate/issues/new?template=detection.yml)
with a synthetic example, or start a [discussion](https://github.com/dwarpal/credgate/discussions).

All values in this post are synthetic.
