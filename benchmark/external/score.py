# ruff: noqa: E501  (table rows read better unwrapped)
"""Score every run on both datasets with one set of rules.

Every tool's types and every dataset's labels map onto one list of
canonical types. Each dataset is scored only on its own canonical types:
a prediction of another type is set aside (counted, not scored), so no tool
is penalised for finding something the dataset does not label.

Matching: a prediction matches an unused gold span of the same canonical
type, exactly (same start and end) or by overlap. "Any PII" ignores the
type, as a redaction would. Metrics: precision, recall, F1, F2 (pooled over
spans: micro), macro-F1 over the dataset's types, per-type recall, missed
spans (false negatives), over-detections (false positives); on Ylemis the
share of PII-free documents with any prediction; on IndiaPII the share of
labelled decoys hit; latency and throughput from the run summaries.

Usage: python score.py > results.md
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from pathlib import Path

B = Path(__file__).parent
CONFIGS = [
    "credgate",
    "credgate-0.5",
    "credgate-names-0.5",
    "kavach",
    "maskflow",
    "presidio",
    "presidio-india",
]

# --- canonical types ---------------------------------------------------------

GOLD = {
    "ylemis": {
        "person": "person",
        "address": "address",
        "location": "location",
        "organization": "organization",
        "account_id": "account_ref",
        "medical_id": "medical_id",
        "email": "email",
        "indian_phone": "phone",
        "pan": "pan",
        "aadhaar": "aadhaar",
        "gstin": "gstin",
        "ifsc": "ifsc",
        "upi_id": "upi",
        "voter_id": "voter_id",
        "vehicle_registration": "vehicle_reg",
        "indian_passport": "passport",
    },
    "indiapii": {
        "PERSON_NAME": "person",
        "INDIAN_MOBILE": "phone",
        "INDIAN_ADDRESS": "address",
        "BANK_ACCOUNT_IN": "bank_account",
        "IFSC": "ifsc",
        "PAN": "pan",
        "AADHAAR": "aadhaar",
        "AADHAAR_MASKED": "aadhaar_masked",
        "PIN_CODE": "pin_code",
        "UPI_VPA": "upi",
        "VEHICLE_REG": "vehicle_reg",
        "DRIVING_LICENCE": "driving_licence",
        "ABHA_NUMBER": "abha_number",
        "ABHA_ADDRESS": "abha_address",
        "VOTER_ID": "voter_id",
        "GSTIN": "gstin",
        "INDIAN_PASSPORT": "passport",
    },
}
# credgate's own corpus is labelled with credgate's type names.
GOLD["corpus"] = {
    "person_name": "person",
    "mobile_in": "phone",
    "aadhaar": "aadhaar",
    "pan": "pan",
    "bank_account": "bank_account",
    "abha_number": "abha_number",
    "card": "card",
    "address": "address",
    "email": "email",
    "ifsc": "ifsc",
    "ckyc": "ckyc",
    "nrega_job_card": "nrega_job_card",
    "upi_id": "upi",
    "voter_epic": "voter_id",
    "abha_address": "abha_address",
    "ration_card": "ration_card",
    "card_expiry": "card_expiry",
    "card_cvv": "card_cvv",
    "gstin": "gstin",
    "passport": "passport",
    "pincode": "pin_code",
    "driving_licence": "driving_licence",
}

TOOL = {
    "credgate": {
        "aadhaar": "aadhaar",
        "aadhaar_masked": "aadhaar_masked",
        "abha_address": "abha_address",
        "abha_number": "abha_number",
        "address": "address",
        "bank_account": "bank_account",
        "driving_licence": "driving_licence",
        "email": "email",
        "gstin": "gstin",
        "ifsc": "ifsc",
        "mobile_in": "phone",
        "pan": "pan",
        "passport": "passport",
        "person_name": "person",
        "pincode": "pin_code",
        "upi_id": "upi",
        "voter_epic": "voter_id",
        "name_by_cue": "person",
        "card": "card",
        "card_cvv": "card_cvv",
        "card_expiry": "card_expiry",
        "ckyc": "ckyc",
        "nrega_job_card": "nrega_job_card",
        "ration_card": "ration_card",
    },
    "kavach": {
        "AADHAAR": "aadhaar",
        "PAN": "pan",
        "UPI": "upi",
        "IFSC": "ifsc",
        "BANK_ACCOUNT": "bank_account",
        "PHONE": "phone",
        "GSTIN": "gstin",
        "EMAIL": "email",
    },
    "maskflow": {
        "PERSON_NAME": "person",
        "INDIAN_ADDRESS": "address",
        "ADDRESS": "address",
        "VEHICLE_REG": "vehicle_reg",
        "PIN_CODE": "pin_code",
        "PAN": "pan",
        "EMAIL": "email",
        "UPI_VPA": "upi",
        "IFSC": "ifsc",
        "GSTIN": "gstin",
        "AADHAAR": "aadhaar",
        "AADHAAR_MASKED": "aadhaar_masked",
        "ABHA_ADDRESS": "abha_address",
        "ABHA_NUMBER": "abha_number",
        "BANK_ACCOUNT_IN": "bank_account",
        "DRIVING_LICENCE": "driving_licence",
        "INDIAN_MOBILE": "phone",
        "PHONE": "phone",
        "INDIAN_PASSPORT": "passport",
        "VOTER_ID": "voter_id",
        "CREDIT_CARD": "card",
    },
    # US_DRIVER_LICENSE, DATE_TIME, NRP, URL and IP_ADDRESS are not mapped:
    # nothing in the datasets corresponds to them.
    "presidio": {
        "PERSON": "person",
        "LOCATION": "location",
        "ORGANIZATION": "organization",
        "EMAIL_ADDRESS": "email",
        "PHONE_NUMBER": "phone",
        "US_BANK_NUMBER": "bank_account",
        "IN_AADHAAR": "aadhaar",
        "IN_PAN": "pan",
        "IN_GSTIN": "gstin",
        "IN_PASSPORT": "passport",
        "IN_VOTER": "voter_id",
        "IN_VEHICLE_REGISTRATION": "vehicle_reg",
        "CREDIT_CARD": "card",
    },
}


def tool_of(cfg: str) -> str:
    return (
        "credgate"
        if cfg.startswith("credgate")
        else "presidio"
        if cfg.startswith("presidio")
        else cfg
    )


# --- data ----------------------------------------------------------------------


def load_gold(ds: str):
    if ds == "ylemis":
        rows = [json.loads(x) for x in (B / "data/ylemis.raw.jsonl").open(encoding="utf-8")]
        docs = []
        for r in rows:
            docs.append(
                {
                    "id": r["id"],
                    "text": r["text"],
                    "group": r["category"],
                    "gold": [(e["start"], e["end"], GOLD[ds][e["type"]]) for e in r["entities"]],
                    "decoys": [],
                }
            )
        return docs
    if ds == "corpus":
        rows = [json.loads(x) for x in (B.parent / "corpus/test.jsonl").open(encoding="utf-8")]
        return [
            {
                "id": r["id"],
                "text": r["text"],
                "group": r["category"],
                "gold": [(g["start"], g["end"], GOLD[ds][g["type"]]) for g in r["spans"]],
                "decoys": [],
            }
            for r in rows
        ]
    rows = [json.loads(x) for x in (B / "data/indiapii.raw.jsonl").open(encoding="utf-8")]
    docs = []
    for r in rows:
        docs.append(
            {
                "id": r["id"],
                "text": r["text"],
                "group": r["domain"],
                "gold": [
                    (e["start"], e["end"], GOLD[ds][e["label"]])
                    for e in r["entities"]
                    if e["value_class"] == "positive"
                ],
                "decoys": [
                    (e["start"], e["end"], e["label"])
                    for e in r["entities"]
                    if e["value_class"] == "hard_negative"
                ],
            }
        )
    return docs


def load_run(ds: str, cfg: str, types: set[str]):
    path = B / f"runs/{ds}.{cfg}.jsonl"
    if not (B / f"runs/{ds}.{cfg}.summary.json").exists():  # not run, or still running
        return None
    mapping = TOOL[tool_of(cfg)]
    preds, ms, aside = {}, [], Counter()
    for line in path.open(encoding="utf-8"):
        r = json.loads(line)
        ms.append(r["ms"])
        keep = []
        for s, e, t in r["spans"]:
            c = mapping.get(t)
            if c in types:
                keep.append((s, e, c))
            else:
                aside[t] += 1
        preds[r["id"]] = keep
    summary = json.loads((B / f"runs/{ds}.{cfg}.summary.json").read_text())
    return preds, ms, aside, summary


# --- scoring -------------------------------------------------------------------


def match(gold, preds, exact: bool, typed: bool):
    """(tp, fp, fn) counters by type; greedy in position order."""
    tp, fp, fn = Counter(), Counter(), Counter()
    used = [False] * len(gold)
    for s, e, t in sorted(preds):
        hit = None
        for j, (gs, ge, gt) in enumerate(gold):
            if used[j] or (typed and gt != t):
                continue
            if (gs == s and ge == e) if exact else (gs < e and s < ge):
                hit = j
                break
        if hit is None:
            fp[t] += 1
        else:
            used[hit] = True
            tp[gold[hit][2] if typed else t] += 1
    for j, g in enumerate(gold):
        if not used[j]:
            fn[g[2]] += 1
    return tp, fp, fn


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    f2 = 5 * p * r / (4 * p + r) if p + r else 0.0
    return p, r, f1, f2


def evaluate(docs, preds, exact, typed, only=None):
    TP, FP, FN = Counter(), Counter(), Counter()
    for d in docs:
        gold = [g for g in d["gold"] if only is None or g[2] in only]
        pr = [p for p in preds[d["id"]] if only is None or p[2] in only]
        tp, fp, fn = match(gold, pr, exact, typed)
        TP += tp
        FP += fp
        FN += fn
    return TP, FP, FN


def pct(x):
    return f"{100 * x:.1f}"


def main() -> None:
    out = []
    w = out.append
    names = {
        "ylemis": "Ylemis India-PII",
        "indiapii": "IndiaPII-Bench v1.0",
        "corpus": "credgate's own corpus (test split)",
    }
    for ds in ("ylemis", "indiapii", "corpus"):
        docs = load_gold(ds)
        types = set(GOLD[ds].values())
        gold_n = Counter(g[2] for d in docs for g in d["gold"])
        runs = {c: r for c in CONFIGS if (r := load_run(ds, c, types))}
        w(f"## {names[ds]}\n")
        w(
            f"{len(docs)} documents, {sum(gold_n.values())} labelled PII spans of {len(types)} types.\n"
        )

        w("### Detection quality, all of the dataset's types\n")
        w(
            "| Configuration | P (overlap) | R (overlap) | F1 (overlap) | F2 (overlap) | F1 (exact) | Macro-F1 (overlap) | Any-PII F1 | Missed | Over-detected |"
        )
        w("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for c, (preds, _, _, _) in runs.items():
            TP, FP, FN = evaluate(docs, preds, exact=False, typed=True)
            p, r, f1, f2 = prf(sum(TP.values()), sum(FP.values()), sum(FN.values()))
            eTP, eFP, eFN = evaluate(docs, preds, exact=True, typed=True)
            ef1 = prf(sum(eTP.values()), sum(eFP.values()), sum(eFN.values()))[2]
            macro = statistics.mean(prf(TP[t], FP[t], FN[t])[2] for t in types)
            aTP, aFP, aFN = evaluate(docs, preds, exact=False, typed=False)
            af1 = prf(sum(aTP.values()), sum(aFP.values()), sum(aFN.values()))[2]
            w(
                f"| {c} | {pct(p)} | {pct(r)} | {pct(f1)} | {pct(f2)} | {pct(ef1)} | {pct(macro)} | {pct(af1)} | {sum(FN.values())} | {sum(FP.values())} |"
            )
        w("")

        w("### Only the types each tool claims to detect\n")
        w(
            "Gold spans of types a tool has no detector for are left out, so a narrow tool is judged on what it covers.\n"
        )
        w("| Configuration | Types covered | P | R | F1 | F2 |")
        w("|---|---:|---:|---:|---:|---:|")
        for c, (preds, _, _, _) in runs.items():
            covered = set(TOOL[tool_of(c)].values()) & types
            TP, FP, FN = evaluate(docs, preds, exact=False, typed=True, only=covered)
            p, r, f1, f2 = prf(sum(TP.values()), sum(FP.values()), sum(FN.values()))
            w(
                f"| {c} | {len(covered)} of {len(types)} | {pct(p)} | {pct(r)} | {pct(f1)} | {pct(f2)} |"
            )
        w("")

        w("### Recall by type (overlap)\n")
        order = sorted(types, key=lambda t: -gold_n[t])
        w("| Type | Spans | " + " | ".join(runs) + " |")
        w("|---|---:|" + "---:|" * len(runs))
        per = {c: evaluate(docs, r[0], exact=False, typed=True) for c, r in runs.items()}
        for t in order:
            cells = []
            for c in runs:
                TP, FP, FN = per[c]
                cells.append(pct(TP[t] / (TP[t] + FN[t])) if TP[t] + FN[t] else "-")
            w(f"| {t} | {gold_n[t]} | " + " | ".join(cells) + " |")
        w("")
        w("### Precision by type (overlap; '-' = the tool reported none)\n")
        w("| Type | " + " | ".join(runs) + " |")
        w("|---|" + "---:|" * len(runs))
        for t in order:
            cells = []
            for c in runs:
                TP, FP, FN = per[c]
                cells.append(pct(TP[t] / (TP[t] + FP[t])) if TP[t] + FP[t] else "-")
            w(f"| {t} | " + " | ".join(cells) + " |")
        w("")

        if ds == "corpus":
            neg = [d for d in docs if not d["gold"]]
            w("### False positives on PII-free documents\n")
            w(
                f"Share of the {len(neg)} documents with no PII on which the tool reported anything of the corpus's types.\n"
            )
            w("| Configuration | Documents with a false positive |")
            w("|---|---:|")
            for c, (preds, _, _, _) in runs.items():
                w(f"| {c} | {pct(sum(1 for d in neg if preds[d['id']]) / len(neg))} |")
        elif ds == "ylemis":
            w("### False positives on PII-free documents\n")
            w(
                "Share of documents with no PII on which the tool reported anything of the dataset's types.\n"
            )
            groups = {
                "benign": [d for d in docs if not d["gold"] and d["group"] == "benign"],
                "hard_negative": [
                    d for d in docs if not d["gold"] and d["group"] == "hard_negative"
                ],
            }
            w(
                f"| Configuration | Benign ({len(groups['benign'])}) | Hard negatives ({len(groups['hard_negative'])}) |"
            )
            w("|---|---:|---:|")
            for c, (preds, _, _, _) in runs.items():
                cells = [pct(sum(1 for d in g if preds[d["id"]]) / len(g)) for g in groups.values()]
                w(f"| {c} | " + " | ".join(cells) + " |")
        else:
            w("### Decoys hit\n")
            w(
                "Share of labelled PII-shaped decoys that a prediction of the dataset's types overlaps.\n"
            )
            labels = sorted({x[2] for d in docs for x in d["decoys"]})
            dn = Counter(x[2] for d in docs for x in d["decoys"])
            w(
                "| Configuration | "
                + " | ".join(f"{lab} ({dn[lab]})" for lab in labels)
                + " | All |"
            )
            w("|---|" + "---:|" * (len(labels) + 1))
            for c, (preds, _, _, _) in runs.items():
                hit = Counter()
                for d in docs:
                    for s, e, lab in d["decoys"]:
                        if any(ps < e and s < pe for ps, pe, _ in preds[d["id"]]):
                            hit[lab] += 1
                cells = [pct(hit[lab] / dn[lab]) for lab in labels]
                w(
                    f"| {c} | "
                    + " | ".join(cells)
                    + f" | {pct(sum(hit.values()) / sum(dn.values()))} |"
                )
        w("")

        w("### Speed and resources\n")
        w(
            "A fixed sample of 2,000 documents, run three times; the median of the three runs. One process, one run at a time, after 20 warm-up documents; model loading timed separately.\n"
        )
        w(
            "| Configuration | Version | p50 ms | p95 ms | Docs/s | MB/s | CPU use | Peak memory MB | Load s |"
        )
        w("|---|---|---:|---:|---:|---:|---:|---:|---:|")
        for c in runs:
            reps = []
            for rep in (1, 2, 3):
                f = B / f"runs/timing/{ds}.{c}.{rep}.jsonl"
                sf = B / f"runs/timing/{ds}.{c}.{rep}.summary.json"
                if sf.exists():
                    ms = [json.loads(x)["ms"] for x in f.open(encoding="utf-8")]
                    q = statistics.quantiles(ms, n=100)
                    reps.append((q[49], q[94], json.loads(sf.read_text())))
            if not reps:
                continue
            med = lambda xs: statistics.median(xs)  # noqa: E731
            s0 = reps[0][2]
            w(
                f"| {c} | {s0.get('version')} | {med([r[0] for r in reps]):.2f} | {med([r[1] for r in reps]):.2f} | "
                f"{med([r[2]['docs_per_s'] for r in reps]):.0f} | {med([r[2]['mb_per_s'] for r in reps]):.3f} | "
                f"{pct(med([r[2]['cpu_utilisation'] for r in reps]))}% | {med([r[2]['peak_rss_mb'] for r in reps]):.0f} | "
                f"{med([r[2]['load_s'] for r in reps]):.2f} |"
            )
        w("")
        w("### Predictions set aside (types this dataset does not label)\n")
        for c, (_, _, aside, _) in runs.items():
            if aside:
                w(f"- {c}: " + ", ".join(f"{t} {n}" for t, n in aside.most_common(8)))
        w("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
