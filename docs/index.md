# credgate

**Governance-first PII detection for LLM requests, with Indian identifiers built in.**

credgate finds personal data in text and tables *before* it leaves the
machine for a language model, and proves that it did. It is built for data
scientists in regulated Indian environments - banking, insurance, fintech
and healthcare - under the DPDP Act 2023 and RBI, SEBI and IRDAI
expectations, including fully air-gapped setups.

It ships as an **R package** and a **Python package** (with a command line)
that read one shared specification, so both languages find exactly the same
matches, write the same vault, audit and inventory files, and build the
same queries.

<div class="grid cards" markdown>

- **Python** - [get started](python/index.md) and the API reference
- **R** - [the R package site](https://dwarpal.github.io/credgate/r/), with reference and articles
- **Guides** - [large data](large-data.md) and the [threat model](threat-model.md)
- **[Specification](spec.md)** - the rules both implementations follow

</div>

## What it does

| | |
|---|---|
| **Detect** | 24 Indian identifiers - Aadhaar, PAN, GSTIN, cards, accounts, UPI, mobile numbers, voter ID, passport, driving licence, ABHA, CKYC, ration card, NREGA job card, names, addresses and more - with checksums and context, every match explained |
| **Scan and inventory** | Which columns hold which identifiers, in data frames, Arrow, Parquet, DuckDB, databases, Spark and BigQuery, sampled where the data lives |
| **Redact and tokenise** | Replace identifiers before text reaches a model; keyed tokens give the same token for the same customer everywhere; encrypted vaults restore them afterwards |
| **Policies** | Per endpoint (local, internal, frontier), what may be sent, redacted or blocked - for example card number with CVV and expiry never reaching a frontier model |
| **Audit log** | A tamper-evident record of every decision, with no values in it |

Everything runs offline; credgate makes no network calls of its own.

## Install

```sh
pip install credgate              # Python 3.11+
```

```r
install.packages("credgate",
  repos = c("https://dwarpal.r-universe.dev", "https://cloud.r-project.org"))
```

With Nix: `nix build github:dwarpal/credgate#credgate` (command line and
Python) or `#credgate-r`.

The source, issues and changelogs are on
[GitHub](https://github.com/dwarpal/credgate).
