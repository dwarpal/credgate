---
date:
  created: 2026-11-05
authors:
  - bharat
  - aishwarya
categories:
  - Benchmarks
  - Detection
slug: indian-pii-benchmarks
draft: false
description: credgate, MaskFlow, Microsoft Presidio and Kavach PII on two public Indian PII datasets and credgate's own corpus - where each one is strong, where credgate trails, and what running other people's data taught us.
---

# Four Indian PII detectors on three datasets, including ones we did not write

Every PII tool looks good on its own test data. credgate's benchmark has
always been a corpus we generated ourselves, and our rules were refined on
part of it - so its numbers say more about our templates than about the
notes, logs and chat transcripts a bank actually has.

So we ran credgate, MaskFlow, Microsoft Presidio and Kavach PII on two
public Indian PII datasets written by other people, alongside our own, with
the same scoring for every tool. This post is what we found: where credgate
is strong, where it clearly trails, and the three detection fixes the
public data led to.

<!-- more -->

## The datasets and the tools

All three datasets are synthetic, and each was written by someone with a
stake in the result:

| Dataset | Documents | Written by | Licence |
|---|---:|---|---|
| [Ylemis India-PII Benchmark](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark) | 10,000, in 9 Indian languages | a PII model vendor | CC0 |
| [IndiaPII-Bench](https://huggingface.co/datasets/maskflow-ai/indiapii-bench) | 2,000 | MaskFlow's authors | CC BY 4.0 |
| [credgate corpus](https://github.com/dwarpal/credgate/tree/main/benchmark/corpus) (test split) | 700 | us | Apache-2.0 |

Each favours its author's approach, which is the point of running all
three: a tool that only does well on its own data has told you little.

The tools, each at its default settings:

- **credgate** - rules, checksums and context words for Indian identifiers;
  at its recommended `min_confidence = 0.5`.
- **MaskFlow** - Indian identifiers plus spaCy's named-entity model and a
  list of 114,000 Indian names.
- **Microsoft Presidio** - the widely used general-purpose tool, run twice:
  as it comes, and with its Indian recognisers switched on.
- **Kavach PII** - a small, fast pattern library for Indian identifiers.

Every tool's output is mapped to the dataset's types the same way, a match
counts if it overlaps the labelled span, and types a dataset does not label
are set aside rather than counted as false alarms.

## The results

| F1 (overlap) | Ylemis India-PII | IndiaPII-Bench | credgate corpus | PII-free documents flagged | Docs/s | Memory |
|---|---:|---:|---:|---:|---:|---:|
| **credgate** | 67.0 | **95.9** | **98.0** | **0%** | 1,050-2,800 | 35 MB |
| MaskFlow | **79.6** | 77.0 | 71.3 | 8% | 50-130 | 175 MB |
| Presidio, India-configured | 63.6 | 43.6 | 47.9 | 62% | 63-120 | 750 MB |
| Presidio, default | 52.6 | 35.6 | 41.0 | 38% | 57-114 | 670-750 MB |
| Kavach PII | 52.8 | 69.2 | 56.9 | **0%** | 3,000-8,700 | 20 MB |

"PII-free documents flagged" is on Ylemis's 1,756 documents that contain no
PII, more than half of them deliberately tricky. Speed is the median of three runs on
one 2019 laptop.

**MaskFlow wins on Ylemis**, and by a clear margin. **credgate wins on
IndiaPII-Bench** - MaskFlow's own authors' dataset - and on its own corpus.
Neither result means much alone; together they say something specific.

## Where credgate is strong

**Indian identifiers, almost without false alarms.** On both public
datasets credgate finds Aadhaar, PAN, GSTIN, IFSC, UPI IDs, phones, e-mail,
voter IDs, driving licences, ABHA numbers and bank accounts at or near 100%.
Precision is 100% for nearly every type; the exceptions are Aadhaar (93%)
and UPI IDs (86%) on IndiaPII-Bench. Checksums do much of this work: a 12-digit number
whose last digit fails Aadhaar's Verhoeff check is not an Aadhaar, however
much it looks like one.

**No PII where there is none.** On Ylemis's PII-free documents credgate
flags nothing at its recommended threshold. MaskFlow flags 8% of them, and
the India-configured Presidio 62%. In a bank, every false alarm is
a redacted sentence an analyst has to work around, or a blocked request.

**Speed and memory.** credgate runs at 1,000 to 2,800 documents a second in
35 MB, 15 to 25 times the speed of the tools that run a language model, in
a fraction of the memory. That matters when the data is a few hundred
million rows in Hadoop or BigQuery, not a handful of notes. Kavach is faster
still, and on the seven types it covers it is perfect on Ylemis - it simply
covers fewer.

## Where others do better

**Names without a cue.** This is the whole Ylemis gap. MaskFlow and Presidio
run spaCy's named-entity model, and MaskFlow adds its name list; they find
90-99% of Ylemis's names, as in "Delivery to Sandeep Pillai". credgate finds
names after a title, label or relation ("Smt.", "Name:", "S/o") and in
columns named for names - but only 1.6% of Ylemis's names, because most of
them have no such cue. Names are a quarter of Ylemis's labels, so that one
type costs credgate the dataset. (On IndiaPII-Bench, where more names come
with a cue, credgate finds 71% of them.)

We have not closed this gap, on purpose for now. A name list large enough to
matter has to come from somewhere, and its licence and its bias (whose
names are on it?) are decisions for the organisation using it. credgate's
[custom detectors](../../custom-detectors.md) let a bank add its own
list, or cue words, without changing credgate; the example
`names-by-cue.yaml` raises recall to 4.9%.

**Vehicle registration numbers.** MaskFlow and Presidio find them; credgate
does not yet.

**Breadth.** Presidio covers international identifiers, IBANs, IP addresses,
URLs and dates, can hash or encrypt values, redacts text in images, and has
years in production. credgate is alpha and India-first.

## What the public data taught us

Running other people's data found three problems our own corpus never
showed, and all three are fixed in credgate 0.10:

- **Addresses without a label.** Our corpus always wrote "Address:" before
  an address; Ylemis mostly does not ("210 Hauz Khas, Ahmedabad 380015").
  credgate now recognises the usual Indian shape - house number, locality,
  a known city or district, PIN code - using the town names in India Post's
  All India Pincode Directory (Government Open Data License - India).
  Address recall on Ylemis went from 26% to 100%, with no new false alarms.
- **Voter IDs in Indian languages.** "वोटर आईडी QMF1202883" scored 0.3,
  below the threshold, because "voter" was only understood in English. The
  word in eight Indian languages now counts, and the same ID scores 0.97.
- **"Contact Number:"** next to an IFSC was read as a bank account. Now it
  is a phone.

None of these changed credgate's numbers on its own corpus. That is the
best argument we have for running data you did not write.

## How much to trust these numbers

- **All three datasets are synthetic.** Real call-centre notes are messier
  than any of them. Treat the numbers as a comparison between tools, not a
  prediction for your data.
- **Defaults only.** Every tool can be tuned; we tuned none, including
  credgate beyond its documented threshold. A team that tunes Presidio
  carefully will get more from it than the default column shows.
- **We wrote one of the datasets, and credgate.** We have tried to be fair -
  the same mapping and scoring for everyone, every script published - but
  you should check rather than take our word for it.

The method, per-type tables, and the scripts to rerun everything (fetch the
data, set up each tool in its own environment, run, score) are in
[`benchmark/external/`](https://github.com/dwarpal/credgate/tree/main/benchmark/external).
This comparison is independent and not affiliated with any of the projects
in it.

## Try it

credgate is open source (Apache-2.0), in Python and R with identical
results, and runs fully offline:

- Install: `pip install credgate`, or in R from
  [R-universe](https://dwarpal.r-universe.dev)
- Guide: [Custom detectors](../../custom-detectors.md), to add your own
  names or identifiers
- Code and issues: [github.com/dwarpal/credgate](https://github.com/dwarpal/credgate)

All values in this post are synthetic.
