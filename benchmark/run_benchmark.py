# ruff: noqa: E501  (templates and table rows read better unwrapped)
"""Evaluate credgate on the benchmark corpus and print Markdown tables.

Usage (from the repository root, inside `nix develop`):
  PYTHONPATH=pkg/python/src python benchmark/run_benchmark.py [dev|test]

The R package gives identical numbers: cg_evaluate("benchmark/corpus/test.jsonl").
"""

from __future__ import annotations

import sys
from pathlib import Path

import credgate


def fmt(x: float | None) -> str:
    return "-" if x is None else f"{x:.3f}"


def table(report: credgate.EvaluationReport) -> str:
    lines = [
        "| Type | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in report:
        name = f"**{r.type}**" if r.type == "overall" else f"`{r.type}`"
        lines.append(
            f"| {name} | {r.tp} | {r.fp} | {r.fn} | {fmt(r.precision)} | {fmt(r.recall)} | {fmt(r.f1)} |"
        )
    return "\n".join(lines)


def main() -> None:
    split = sys.argv[1] if len(sys.argv) > 1 else "test"
    docs = credgate.load_corpus(Path(__file__).parent / "corpus" / f"{split}.jsonl")
    print(
        f"## {split} split: {len(docs)} documents, {sum(len(d['spans']) for d in docs)} labelled spans\n"
    )
    for mc in (0.5, 0.0):
        print(f"### min_confidence = {mc}, exact matching\n")
        print(table(credgate.evaluate(docs, min_confidence=mc)))
        print()
    print("### By category (min_confidence = 0.5)\n")
    print("| Category | Documents | Precision | Recall | F1 |\n|---|---:|---:|---:|---:|")
    for cat in sorted({d["category"] for d in docs}):
        subset = [d for d in docs if d["category"] == cat]
        o = credgate.evaluate(subset, min_confidence=0.5)[-1]
        print(f"| {cat} | {len(subset)} | {fmt(o.precision)} | {fmt(o.recall)} | {fmt(o.f1)} |")


if __name__ == "__main__":
    main()
