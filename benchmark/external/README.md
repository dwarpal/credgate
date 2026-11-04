# credgate and other tools on public datasets

credgate, [MaskFlow](https://github.com/maskflow/maskflow),
[Microsoft Presidio](https://github.com/microsoft/presidio) and
[Kavach PII](https://github.com/harshita1615/kavach-pii) on two public Indian
PII datasets and on credgate's own test corpus, with one set of scoring
rules. Full tables for every configuration and metric:
[results.md](results.md).

Measured on 2026-11-04 with credgate from `main` after
[#56](https://github.com/dwarpal/credgate/pull/56) and the address rule
built on India Post's city list (Python package version 0.9.0 plus those
changes), on a 2019 MacBook Pro (Intel Core i5-8257U, 4 cores,
8 GB), macOS 15.8.

## Summary

F1 (overlap matching, all of each dataset's types; every tool at its default
settings, credgate at its recommended `min_confidence = 0.5`):

| Tool | Ylemis India-PII | IndiaPII-Bench | credgate corpus | PII-free documents flagged (Ylemis) | Docs/s | Memory |
|---|---:|---:|---:|---:|---:|---:|
| **credgate** | 67.0 | **95.9** | **98.0** | **0%** | 1,050-2,800 | 35 MB |
| credgate + [names-by-cue](../../examples/detectors/names-by-cue.yaml) | 67.7 | **95.9** | **98.7** | **0%** | 860-2,400 | 35 MB |
| MaskFlow 0.9.2 | **79.6** | 77.0 | 71.3 | 8% | 50-130 | 175 MB |
| Presidio 2.2.366, India-configured | 63.6 | 43.6 | 47.9 | 62% | 63-120 | 750 MB |
| Presidio 2.2.366, default | 52.6 | 35.6 | 41.0 | 38% | 57-114 | 670-750 MB |
| Kavach PII 0.2.0 | 52.8 | 69.2 | 56.9 | **0%** | 3,000-8,700 | 20 MB |

Who wrote each dataset matters: **Ylemis** is written by a PII model vendor,
**IndiaPII-Bench** by the MaskFlow project (and labelled with MaskFlow's type
names), the **credgate corpus** by us. Each favours its author's tool's
approach to some degree, so read the three columns together.

**Where credgate is strong.** Indian identifiers - Aadhaar, PAN, GSTIN, IFSC,
UPI, ABHA, passport, driving licence, bank accounts, phones and email - are
found at or near 100% recall and precision on all three datasets, and so are
voter IDs written with a word such as "voter" and addresses (100% on all
three, with or without a label). (A bare voter ID or CKYC number
with no such word is reported below 0.5 by design, since the format alone
could be a product code: 51% and 67% recall on credgate's corpus.) Precision is the clearest difference: at 0.5, credgate flagged
none of Ylemis's 1,756 PII-free documents (810 ordinary, 946 deliberately
PII-shaped), against 8% for MaskFlow and 38-62% for Presidio; it hit 7% of
IndiaPII-Bench's 1,403 PII-shaped decoys, against 66-74% for Presidio. It is
15-25 times faster than the tools that run a language model, and uses about
35 MB of memory, against 175 MB for MaskFlow and 670-750 MB for Presidio.

**Where it is weak.** Names written without a cue. Ylemis's text mostly has
none ("Delivery to Sandeep Pillai"): credgate finds 1.6% of its 8,244 names
(4.9% with names-by-cue), where MaskFlow and Presidio, which run spaCy's
named-entity models (and MaskFlow a list of 114,000 Indian names), find
90-99%. That is the whole reason credgate trails on Ylemis. Also not detected: vehicle registration
numbers, and types no tool covers - Ylemis's internal reference numbers
(`policy_5628203_824`), organisations and medical record numbers, which an
organisation adds as [custom detectors](../../docs/custom-detectors.md).

**Fixed because of this benchmark** ([#56](https://github.com/dwarpal/credgate/pull/56)):
voter IDs after "वोटर आईडी" or "ভোটার আইডি" (Ylemis voter ID recall at 0.5:
50% to 100%), and a mobile number under "Contact Number:" taken for a bank
account when an IFSC was nearby (IndiaPII phone recall: 96% to 100%).
Then addresses without a label: a house number, the locality, a known Indian
city or district (from India Post's directory, data.gov.in, Government Open
Data License - India) and a PIN code, and "address" in seven more Indian
languages (Ylemis address recall: 26% to 100%, with no new false positives).
credgate's own benchmark tables did not change.

## Datasets

| | Documents | PII spans | Types | Languages | Licence |
|---|---:|---:|---:|---|---|
| [Ylemis India-PII Benchmark](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark) | 10,000 (1,756 without PII) | 32,030 | 16 | English, Hindi, Hinglish and 7 other Indian languages | CC0 1.0 |
| [IndiaPII-Bench v1.0](https://huggingface.co/datasets/maskflow-ai/indiapii-bench) | 2,000 (plus 1,403 labelled decoys) | 12,065 | 17 | English, Hinglish | CC BY 4.0 |
| credgate corpus, [test split](../corpus/test.jsonl) | 700 | 1,320 | 22 | English, Hindi, Hinglish | Apache-2.0 (this repository) |

All three are synthetic. IndiaPII-Bench: Sodani, S. (2026), *IndiaPII-Bench
v1.0*, Hugging Face, MaskFlow project, CC BY 4.0. The datasets are
downloaded by `fetch_data.py` and checked against their published SHA-256;
they are not copied into this repository. AI4Privacy's PII-Masking-200K was
considered and left out: its licence requires a paid licence for larger
companies, and it has no Indian identifiers.

## Method

- **Settings**: every tool at its documented defaults - Presidio's
  `AnalyzerEngine()` with `en_core_web_lg` (and, as "India-configured", its
  Aadhaar, PAN, GSTIN, voter ID, passport and vehicle registration
  recognisers plus Indian phone numbers, as in the
  [Presidio comparison](../README.md#comparison-with-microsoft-presidio)),
  MaskFlow's `detect()` (minimum confidence 0.5) with `en_core_web_sm`,
  Kavach's `scan()` (threshold 0.5). credgate at 0.5, its recommended
  setting; results at 0 are in [results.md](results.md). Nothing was tuned on
  these datasets.
- **Types**: each tool's types and each dataset's labels map onto one list
  (in [`score.py`](score.py)). A dataset is scored only on its own types; a
  prediction of a type the dataset does not label is set aside and counted,
  not scored as wrong. Presidio's US-specific types (`US_DRIVER_LICENSE`,
  `US_SSN`, ...) and dates are not mapped.
- **Matching**: a prediction counts when it overlaps an unused labelled span
  of the same type; exact-span results are in [results.md](results.md). On
  credgate's corpus this scorer gives exactly what `credgate.evaluate()`
  reports (precision 1.000, recall 0.961, F1 0.980 at 0.5, exact matching).
- **Speed**: a fixed sample (2,000 documents of each public dataset, all 700
  of the corpus) run three times, one process at a time, after 20 warm-up
  documents; the median of the three runs. Model loading is timed separately.
  Each tool runs in its own Python environment.
- **Untrusted code**: MaskFlow and Kavach PII were read before installation
  (no network access, process execution or dynamic code); no script from a
  dataset repository was run.

## Caveats

- **Email-shaped decoys**: IndiaPII-Bench labels values such as
  `name@bluepeak` as email-shaped decoys. Without a domain ending they are
  indistinguishable from UPI IDs; credgate reports them as UPI IDs, which
  counts against it here although masking them is the safe choice.
- **Kavach PII** covers 8 types and scores 99-100% on those it covers; its low
  overall F1 reflects its scope, not its accuracy.
- **Ylemis "address" and "location"** are separate labels; a tool that marks
  a city inside an address as an address, or the reverse, is scored as wrong
  by type but right in the "any PII" column of [results.md](results.md).
- **One machine, synthetic text.** Real documents differ; run the scripts on
  your own data before relying on any of these numbers.

## Reproduce

```sh
python benchmark/external/fetch_data.py          # downloads and verifies the datasets
PYTHON312=python3.12 benchmark/external/setup_envs.sh   # one environment per other tool
PYTHON=python3 benchmark/external/run_all.sh     # about 30 minutes on the machine above
python benchmark/external/score.py > benchmark/external/results.md
```

`PYTHON` needs credgate's dependencies (`nix develop` provides them); credgate
itself is taken from `pkg/python/src`. The comparison is independent and not
affiliated with any of the projects compared.
