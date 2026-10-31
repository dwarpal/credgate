# CredGate benchmark

Accuracy of credgate's PII detection on a **synthetic, labelled corpus** of
Indian-context documents. Results are for the held-out `test` split; the
`dev` split was used to find and fix bugs, so `test` was not tuned against.
The R and Python packages produce identical numbers.

Measured on 2026-10-31 at commit `main` after the benchmark was added
(Python 0.3.0.dev0, R 0.1.0.9000).

## Summary

At the recommended threshold (`min_confidence = 0.5`):

- **Overall: precision 0.997, recall 0.902, F1 0.947** - 4 false positives
  in 700 documents.
- 11 of 17 types are perfect: PAN, GSTIN, IFSC, email, UPI, passport,
  driving licence, ABHA number, ABHA address, postal address, PIN code
  (and Aadhaar, card, mobile and names have precision of 0.95-1.00).
- Weakest: **voter ID** (recall 0.51) and **bank account** (recall 0.75)
  are missed without nearby context by design (both patterns are too
  generic alone); **names** (recall 0.83) are missed in running text without
  an honorific or label; **Aadhaar** and **mobile** lose recall when a
  negative word for a *neighbouring* item ("order", "ticket") is within the
  context window.
- Without a threshold, low-confidence matches on order and reference numbers
  that pass the Aadhaar checksum by chance cut Aadhaar precision to 0.52;
  they are reported (at 0.42-0.48) so callers can decide.

## Caveats

- **Synthetic data.** Documents are generated from templates (KYC forms,
  bank messages, call-centre notes, Hinglish chats, Hindi text, hospital
  summaries, bare records, and documents with no PII). The numbers describe
  realistic-looking synthetic text, not any real customer data, and real
  text will be messier. No real personal data was used.
- **Templates are known.** Fixes made on `dev` can generalise to `test`
  more easily than to unseen layouts. More template families and an
  independently written corpus are on the roadmap.
- **Home advantage.** We wrote the corpus generator, so its documents suit
  credgate's design. See the comparison below for how Presidio fares on the
  same data, and read it with this in mind.

## How to reproduce

```sh
nix develop
PYTHONPATH=pkg/python/src python benchmark/generate_corpus.py   # regenerates the corpus (deterministic)
PYTHONPATH=pkg/python/src python benchmark/run_benchmark.py test
```

or in R: `cg_evaluate("benchmark/corpus/test.jsonl", min_confidence = 0.5)`.
To evaluate on your own labelled data, use the same JSON Lines format
(see `spec/README.md`, "Evaluation").

## Results: test split: 700 documents, 1260 labelled spans

### min_confidence = 0.5, exact matching

| Type | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `aadhaar` | 83 | 0 | 21 | 1.000 | 0.798 | 0.888 |
| `abha_address` | 40 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `abha_number` | 80 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `address` | 63 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `bank_account` | 62 | 0 | 21 | 1.000 | 0.747 | 0.855 |
| `card` | 41 | 2 | 0 | 0.954 | 1.000 | 0.976 |
| `driving_licence` | 21 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `email` | 62 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `gstin` | 41 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `ifsc` | 62 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `mobile_in` | 165 | 2 | 21 | 0.988 | 0.887 | 0.935 |
| `pan` | 83 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `passport` | 21 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `person_name` | 207 | 0 | 41 | 1.000 | 0.835 | 0.910 |
| `pincode` | 21 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `upi_id` | 63 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `voter_epic` | 21 | 0 | 20 | 1.000 | 0.512 | 0.677 |
| **overall** | 1136 | 4 | 124 | 0.997 | 0.902 | 0.947 |

### min_confidence = 0.0, exact matching

| Type | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `aadhaar` | 104 | 97 | 0 | 0.517 | 1.000 | 0.682 |
| `abha_address` | 40 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `abha_number` | 80 | 2 | 0 | 0.976 | 1.000 | 0.988 |
| `address` | 63 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `bank_account` | 62 | 0 | 21 | 1.000 | 0.747 | 0.855 |
| `card` | 41 | 3 | 0 | 0.932 | 1.000 | 0.965 |
| `driving_licence` | 21 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `email` | 62 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `gstin` | 41 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `ifsc` | 62 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `mobile_in` | 186 | 10 | 0 | 0.949 | 1.000 | 0.974 |
| `pan` | 83 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `passport` | 21 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `person_name` | 207 | 0 | 41 | 1.000 | 0.835 | 0.910 |
| `pincode` | 21 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `upi_id` | 63 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| `voter_epic` | 21 | 0 | 20 | 1.000 | 0.512 | 0.677 |
| **overall** | 1178 | 112 | 82 | 0.913 | 0.935 | 0.924 |

### By category (min_confidence = 0.5)

| Category | Documents | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| bank | 126 | 0.992 | 0.992 | 0.992 |
| callcentre | 105 | 1.000 | 0.727 | 0.842 |
| chat | 103 | 1.000 | 0.862 | 0.926 |
| health | 60 | 1.000 | 1.000 | 1.000 |
| kyc | 126 | 1.000 | 1.000 | 1.000 |
| negative | 100 | - | - | - |
| record | 80 | 0.984 | 0.818 | 0.893 |

## Comparison with Microsoft Presidio

[Presidio](https://github.com/microsoft/presidio) (MIT) is the most widely
used open-source PII detector and ships recognisers for Indian identifiers,
so it is the natural reference. Other tools we were asked about (MaskFlow,
PII Shield, Kavach) are not compared yet: we first need to confirm that each
is a runnable open-source tool whose licence allows publishing results.

### Method

- **Same data, same rules.** The held-out `test` split, scored by the spec's
  evaluation rules; the comparison script's scorer is checked to reproduce
  `credgate.evaluate()` exactly before anything is reported.
- **Thresholds tuned on `dev` for every system** (best overall F1 on the
  types both tools cover), including credgate, then applied to `test`.
- **Two Presidio configurations.** *Default* is `AnalyzerEngine()` as
  installed - it loads **none** of Presidio's Indian recognisers.
  *India-configured* adds all six (Aadhaar, PAN, GSTIN, voter ID, passport,
  vehicle registration) and parses phone numbers with India as a region; it
  is the main comparison.
- **Entity mapping.** `IN_AADHAAR`, `IN_PAN`, `IN_GSTIN`, `IN_VOTER`,
  `IN_PASSPORT`, `EMAIL_ADDRESS`, `PHONE_NUMBER` (mobile), `CREDIT_CARD`
  (card), `PERSON` (name), `LOCATION` (address) and `US_BANK_NUMBER` (bank
  account). Other Presidio entities (dates, URLs, US identifiers, ...) are
  listed separately, not counted as errors.
- **Two views.** *Common types* (types both tools have a recogniser for) is
  the like-for-like comparison; *all 17 types* also counts types Presidio has
  no recogniser for (UPI, IFSC, ABHA, driving licence, PIN code).

Versions: credgate 0.3.0.dev0; presidio-analyzer 2.2.366, spaCy 3.8.18, en_core_web_lg 3.8.0.

Test split: 700 documents, 1260 labelled spans. Thresholds tuned on dev for best overall F1 on the types both tools cover.

### Overall

| System | Threshold (tuned on dev) | Common types: P / R / F1 (exact) | Common types: F1 (overlap) | All 17 types: P / R / F1 (exact) | Seconds for dev+test |
|---|---:|---|---:|---|---:|
| credgate | 0.45 | 0.985 / 0.916 / **0.949** | 0.949 | 0.988 / 0.935 / 0.961 | 0.3 |
| Presidio (default) | 0.1 | 0.555 / 0.472 / **0.510** | 0.607 | 0.555 / 0.364 / 0.440 | 15.6 |
| Presidio (India-configured) | 0.1 | 0.600 / 0.748 / **0.666** | 0.745 | 0.600 / 0.578 / 0.589 | 12.1 |

### F1 per type (exact matching, tuned thresholds)

| Type | Labelled spans | credgate | Presidio (default) | Presidio (India-configured) |
|---|---:|---:|---:|---:|
| `aadhaar` | 104 | 0.959 | 0.000 | 0.561 |
| `abha_address` * | 40 | 1.000 | 0.000 | 0.000 |
| `abha_number` * | 80 | 1.000 | 0.000 | 0.000 |
| `address` | 63 | 1.000 | 0.000 | 0.000 |
| `bank_account` | 83 | 0.855 | 0.388 | 0.388 |
| `card` | 41 | 0.965 | 0.954 | 0.954 |
| `driving_licence` * | 21 | 1.000 | 0.000 | 0.000 |
| `email` | 62 | 1.000 | 1.000 | 1.000 |
| `gstin` | 41 | 1.000 | 0.000 | 1.000 |
| `ifsc` * | 62 | 1.000 | 0.000 | 0.000 |
| `mobile_in` | 186 | 0.995 | 0.855 | 0.875 |
| `pan` | 83 | 1.000 | 0.000 | 0.897 |
| `passport` | 21 | 1.000 | 0.000 | 1.000 |
| `person_name` | 248 | 0.910 | 0.466 | 0.466 |
| `pincode` * | 21 | 1.000 | 0.000 | 0.000 |
| `upi_id` * | 63 | 1.000 | 0.000 | 0.000 |
| `voter_epic` | 41 | 0.677 | 0.000 | 1.000 |

\* No Presidio recogniser for this type.

### Presidio entities outside the comparison (test split, counts)

- Presidio (default): US_DRIVER_LICENSE 720, DATE_TIME 326, URL 104, UK_NHS 16, US_PASSPORT 8, US_SSN 8, MEDICAL_LICENSE 7, NRP 2
- Presidio (India-configured): US_DRIVER_LICENSE 720, DATE_TIME 326, URL 104, UK_NHS 16, US_PASSPORT 8, US_SSN 8, MEDICAL_LICENSE 7, NRP 2

### Reading the results

- **credgate is far ahead on Indian data** (F1 0.949 vs 0.666 on common
  types, India-configured Presidio). The gaps are genuine, not scoring
  artefacts - exact and overlap matching agree except for names and
  addresses, where Presidio's spans are shorter or include the honorific:
  - *Aadhaar*: Presidio misses every Aadhaar written in Devanagari digits and
    flags order and transaction numbers that pass the checksum (it has no
    negative context such as "order", "txn").
  - *PAN*: it also labels 10-digit mobile numbers as PAN.
  - *Names*: the English NER misses Hindi names and flags phrases such as
    "Mera aadhaar" or "Anna Salai" (a road).
  - *Mobile*: it flags amounts and bank account numbers.
  - *Addresses*: Presidio finds place names, not addresses (`LOCATION`), so
    it scores 0 with exact matching and 0.63 with overlap.
- **Presidio wins on voter IDs without context** (F1 1.000 vs 0.677). It
  reports bare `ABC1234567` patterns at a low score; credgate requires a
  nearby keyword and drops them. Reporting them at low confidence instead is
  on our list.
- **Speed**: credgate processed both splits (1,400 documents) in about 0.3
  seconds; Presidio took 12-16 seconds, mostly in spaCy's NER (same machine,
  single process).
- **Presidio is general-purpose and extensible.** It can be given custom
  recognisers for UPI, IFSC or ABHA; this comparison is of what it ships.

### Reproducing the comparison

```sh
python -m venv presidio-env && presidio-env/bin/pip install presidio-analyzer regex pyyaml
presidio-env/bin/python -m spacy download en_core_web_lg
PYTHONPATH=pkg/python/src presidio-env/bin/python benchmark/compare_presidio.py
```

## Next improvements

1. Let closer positive context outweigh a more distant negative word, so
   "Aadhaar ... ; order ..." keeps the Aadhaar (recovers 21 Aadhaar and 21
   mobile matches at 0.5 on `test`).
2. Names in running text without a cue (41 misses): Hinglish/transliterated
   cues ("ji", "bhai", "sahab"), and an optional statistical detector.
3. Voter ID and bank account without context: column-level context
   (`scan_pii`) already helps; consider structural cues in records.
4. Report voter IDs without context at low confidence instead of dropping
   them (Presidio's advantage above).
5. More template families; comparisons with other tools once verified.
