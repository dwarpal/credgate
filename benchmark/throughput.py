# ruff: noqa: E501  (table rows read better unwrapped)
"""Measure how fast credgate processes text, on one CPU core.

Inputs are built deterministically from the synthetic corpus
(corpus/test.jsonl), so the R script (throughput.R) measures the same text:

  field  one identifier per value (PAN, mobile, ...), as in a structured column
  note   one corpus document (KYC form, call note, chat message, ...)
  long   12 consecutive corpus documents joined by newlines (~2,000 characters)
  clean  the corpus documents that contain no PII

Usage (from the repository root):
  PYTHONPATH=pkg/python/src python benchmark/throughput.py [--profile]
"""

from __future__ import annotations

import cProfile
import json
import pstats
import statistics
import sys
import time
from pathlib import Path

import credgate

CORPUS = Path(__file__).parent / "corpus" / "test.jsonl"
FIELDS = ["pan", "mobile", "aadhaar", "email", "upi_id", "gstin", "voter_epic", "ifsc"]


def inputs() -> dict[str, list[str]]:
    docs = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines()]
    texts = [d["text"] for d in docs]
    records = credgate.synth_indian_pii(500, seed=7)
    return {
        "field": [r[f] for r in records for f in FIELDS],
        "note": texts,
        "long": ["\n".join(texts[i : i + 12]) for i in range(0, len(texts) - 11, 12)],
        "clean": [d["text"] for d in docs if not d["spans"]],
    }


def best_time(fn, repeat: int = 3) -> float:
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return min(times)


def main() -> None:
    sets = inputs()
    if "--profile" in sys.argv:
        prof = cProfile.Profile()
        prof.enable()
        credgate.detect_pii(sets["note"])
        prof.disable()
        pstats.Stats(prof).sort_stats("cumulative").print_stats(18)
        return

    credgate.detect_pii("warm up PAN ABCPE1234F")
    print(f"credgate {credgate.__version__} (Python {sys.version.split()[0]}), one core\n")
    print("| Input | Values | Mean characters | detect_pii values/s | redact values/s | tokenise values/s | MB/s (detect) |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for name, texts in sets.items():
        chars = sum(len(t) for t in texts)
        d = best_time(lambda t=texts: credgate.detect_pii(t))
        r = best_time(lambda t=texts: credgate.redact(t))
        k = best_time(lambda t=texts: credgate.tokenise(t, credgate.Vault()))
        print(
            f"| {name} | {len(texts):,} | {statistics.mean(len(t) for t in texts):,.0f} "
            f"| {len(texts) / d:,.0f} | {len(texts) / r:,.0f} | {len(texts) / k:,.0f} "
            f"| {chars / d / 1e6:.2f} |"
        )

    table = {f: [r[f] for r in credgate.synth_indian_pii(20_000, seed=11)] for f in FIELDS}
    s = best_time(lambda: credgate.scan_pii(table), repeat=1)
    print(
        f"\nscan_pii on a table of {len(FIELDS)} columns x 20,000 rows "
        f"(samples up to 10,000 values per column): {s:.1f} s"
    )


if __name__ == "__main__":
    main()
