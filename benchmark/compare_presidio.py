# ruff: noqa: E501  (table rows read better unwrapped)
"""Compare credgate with Microsoft Presidio on the benchmark corpus.

Both tools are scored by the same rules (spec, "Evaluation"); the scorer
here is checked against credgate.evaluate() before anything is reported.
Thresholds are tuned on `dev` for every system, results are reported on the
held-out `test` split.

Presidio is evaluated in two configurations:
  default         AnalyzerEngine() as installed (no Indian recognisers load)
  india           default + all of Presidio's Indian recognisers (Aadhaar,
                  PAN, GSTIN, voter ID, passport, vehicle registration) and
                  phone numbers parsed with India as a region

Usage (in an environment with presidio-analyzer and en_core_web_lg; credgate
from this repository on PYTHONPATH):
  PYTHONPATH=pkg/python/src python benchmark/compare_presidio.py > results.md
"""

from __future__ import annotations

import time
from collections import Counter
from importlib.metadata import version
from pathlib import Path

import credgate

CORPUS = Path(__file__).parent / "corpus"

# Presidio entity -> credgate type. Unmapped entities are reported separately.
PRESIDIO_MAP = {
    "IN_AADHAAR": "aadhaar",
    "IN_PAN": "pan",
    "IN_GSTIN": "gstin",
    "IN_VOTER": "voter_epic",
    "IN_PASSPORT": "passport",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "mobile_in",
    "CREDIT_CARD": "card",
    "PERSON": "person_name",
    "LOCATION": "address",
    "US_BANK_NUMBER": "bank_account",
}
COMMON_TYPES = sorted(set(PRESIDIO_MAP.values()))


# --- Scoring (spec "Evaluation"), shared by every system --------------------


def score(docs, predictions, match="exact", types=None):
    """predictions: per document, a list of (start, end, type)."""
    counts: dict[str, list[int]] = {}

    def bump(t, i):
        if types is None or t in types:
            counts.setdefault(t, [0, 0, 0])[i] += 1

    for doc, preds in zip(docs, predictions, strict=True):
        gold = sorted(doc["spans"], key=lambda g: (g["start"], g["end"]))
        used = [False] * len(gold)
        for start, end, typ in sorted(preds):
            hit = None
            for j, g in enumerate(gold):
                if used[j] or g["type"] != typ:
                    continue
                same = g["start"] == start and g["end"] == end
                if same if match == "exact" else g["start"] < end and start < g["end"]:
                    hit = j
                    break
            if hit is None:
                bump(typ, 1)
            else:
                used[hit] = True
                bump(typ, 0)
        for j, g in enumerate(gold):
            if not used[j]:
                bump(g["type"], 2)
    rows = {t: rates(*c) for t, c in sorted(counts.items())}
    rows["overall"] = rates(*(sum(c[i] for c in counts.values()) for i in range(3)))
    return rows


def rates(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and p + r else None
    rnd = lambda x: None if x is None else round(x, 4)  # noqa: E731
    return {"tp": tp, "fp": fp, "fn": fn, "precision": rnd(p), "recall": rnd(r), "f1": rnd(f1)}


# --- Systems -------------------------------------------------------------------


def credgate_predict(docs):
    spans = credgate.detect_pii([d["text"] for d in docs])
    out = [[] for _ in docs]
    for s in spans:
        out[s.doc].append((s.start, s.end, s.type, s.confidence))
    return out


def presidio_engine(india: bool):
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.predefined_recognizers import (
        InAadhaarRecognizer,
        InGstinRecognizer,
        InPanRecognizer,
        InPassportRecognizer,
        InVehicleRegistrationRecognizer,
        InVoterRecognizer,
        PhoneRecognizer,
    )

    engine = AnalyzerEngine()
    if india:
        for rec in (
            InAadhaarRecognizer,
            InGstinRecognizer,
            InPanRecognizer,
            InPassportRecognizer,
            InVehicleRegistrationRecognizer,
            InVoterRecognizer,
        ):
            engine.registry.add_recognizer(rec())
        engine.registry.remove_recognizer("PhoneRecognizer")
        engine.registry.add_recognizer(
            PhoneRecognizer(supported_regions=("IN", "US", "UK", "DE", "FE", "IL"))
        )
    return engine


def presidio_predict(engine, docs):
    out, unmapped = [], Counter()
    for d in docs:
        preds = []
        for r in engine.analyze(d["text"], language="en"):
            typ = PRESIDIO_MAP.get(r.entity_type)
            if typ is None:
                unmapped[r.entity_type] += 1
            else:
                preds.append((r.start, r.end, typ, r.score))
        out.append(preds)
    return out, unmapped


def keep(predictions, threshold):
    return [[(s, e, t) for s, e, t, c in doc if c >= threshold] for doc in predictions]


def best_threshold(docs, predictions, types):
    grid = [round(x * 0.05, 2) for x in range(20)]
    return max(
        grid,
        key=lambda th: (score(docs, keep(predictions, th), types=types)["overall"]["f1"] or 0, -th),
    )


# --- Report ----------------------------------------------------------------------


def fmt(x):
    return "-" if x is None else f"{x:.3f}"


def main():
    dev = credgate.load_corpus(CORPUS / "dev.jsonl")
    test = credgate.load_corpus(CORPUS / "test.jsonl")

    # The shared scorer must reproduce credgate.evaluate() exactly.
    for split in (dev, test):
        mine = score(split, keep(credgate_predict(split), 0.5))
        theirs = {
            r.type: {k: getattr(r, k) for k in ("tp", "fp", "fn", "precision", "recall", "f1")}
            for r in credgate.evaluate(split, min_confidence=0.5)
        }
        assert mine == theirs, "scorer differs from credgate.evaluate()"

    systems = {}
    t0 = time.perf_counter()
    systems["credgate"] = (credgate_predict(dev), credgate_predict(test), Counter())
    timing = {"credgate": time.perf_counter() - t0}
    for name, india in (("Presidio (default)", False), ("Presidio (India-configured)", True)):
        engine = presidio_engine(india)
        t0 = time.perf_counter()
        dev_p, _ = presidio_predict(engine, dev)
        test_p, unmapped = presidio_predict(engine, test)
        timing[name] = time.perf_counter() - t0
        systems[name] = (dev_p, test_p, unmapped)

    print(
        f"Versions: credgate {credgate.__version__}; presidio-analyzer {version('presidio-analyzer')}, "
        f"spaCy {version('spacy')}, en_core_web_lg {version('en_core_web_lg')}.\n"
    )
    print(
        f"Test split: {len(test)} documents, {sum(len(d['spans']) for d in test)} labelled spans. "
        "Thresholds tuned on dev for best overall F1 on the types both tools cover.\n"
    )

    results = {}
    for name, (dev_p, test_p, unmapped) in systems.items():
        th = best_threshold(dev, dev_p, COMMON_TYPES)
        results[name] = {
            "threshold": th,
            "common_exact": score(test, keep(test_p, th), types=COMMON_TYPES),
            "common_overlap": score(test, keep(test_p, th), "overlap", types=COMMON_TYPES),
            "all_exact": score(test, keep(test_p, th)),
            "unmapped": unmapped,
        }

    print("### Overall\n")
    print(
        f"| System | Threshold (tuned on dev) | Common types: P / R / F1 (exact) | Common types: F1 (overlap) | All {len({s['type'] for d in test for s in d['spans']})} types: P / R / F1 (exact) | Seconds for dev+test |"
    )
    print("|---|---:|---|---:|---|---:|")
    for name, r in results.items():
        c, o, a = (
            r["common_exact"]["overall"],
            r["common_overlap"]["overall"],
            r["all_exact"]["overall"],
        )
        print(
            f"| {name} | {r['threshold']} | {fmt(c['precision'])} / {fmt(c['recall'])} / **{fmt(c['f1'])}** | {fmt(o['f1'])} | "
            f"{fmt(a['precision'])} / {fmt(a['recall'])} / {fmt(a['f1'])} | {timing[name]:.1f} |"
        )

    gold_types = sorted({s["type"] for d in test for s in d["spans"]})
    print("\n### F1 per type (exact matching, tuned thresholds)\n")
    print("| Type | Labelled spans | " + " | ".join(results) + " |")
    print("|---|---:|" + "---:|" * len(results))
    n_gold = Counter(s["type"] for d in test for s in d["spans"])
    for t in gold_types:
        cells = []
        for r in results.values():
            row = r["all_exact"].get(t)
            cells.append(
                "-" if row is None else fmt(row["f1"]) if row["f1"] is not None else "0.000"
            )
        marker = "" if t in COMMON_TYPES else " *"
        print(f"| `{t}`{marker} | {n_gold[t]} | " + " | ".join(cells) + " |")
    print("\n\\* No Presidio recogniser for this type.\n")

    print("### Presidio entities outside the comparison (test split, counts)\n")
    for name, r in results.items():
        if r["unmapped"]:
            items = ", ".join(f"{k} {v}" for k, v in r["unmapped"].most_common())
            print(f"- {name}: {items}")


if __name__ == "__main__":
    main()
