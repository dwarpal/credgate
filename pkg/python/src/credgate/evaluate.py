"""Evaluate detection against labelled text (the spec's "Evaluation" rules)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from os import PathLike
from typing import Any

from .detect import detect_pii


@dataclass(frozen=True)
class TypeScore:
    """Counts and rates for one type (or ``overall``)."""

    type: str
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None


class EvaluationReport(list[TypeScore]):
    """Rows of :func:`evaluate`, one per type then ``overall``."""

    def __init__(self, rows: Iterable[TypeScore], n_documents: int, match: str) -> None:
        super().__init__(rows)
        self.n_documents = n_documents
        self.match = match

    def to_records(self) -> list[dict[str, Any]]:
        return [asdict(r) for r in self]

    def __str__(self) -> str:
        def rate(x: float | None) -> str:
            return "  -  " if x is None else f"{x:.3f}"

        lines = [
            f"Evaluated {self.n_documents} document(s), {self.match} matching:",
            f"  {'type':<16} {'tp':>6} {'fp':>6} {'fn':>6}  precision  recall     f1",
        ]
        for r in self:
            lines.append(
                f"  {r.type:<16} {r.tp:>6} {r.fp:>6} {r.fn:>6}  "
                f"{rate(r.precision):>9}  {rate(r.recall):>6}  {rate(r.f1):>5}"
            )
        return "\n".join(lines)


def load_corpus(path: str | PathLike[str]) -> list[dict[str, Any]]:
    """Read labelled documents from a JSON Lines file."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def evaluate(
    documents: Iterable[Mapping[str, Any]] | str | PathLike[str],
    min_confidence: float = 0.0,
    match: str = "exact",
    detectors: Sequence[str] | None = None,
) -> EvaluationReport:
    """Measure detection against labelled documents.

    Each document is a mapping with ``text`` and ``spans`` (a list of
    ``{"start", "end", "type"}`` with 0-based, end-exclusive offsets); every
    PII span must be labelled. Returns per-type and overall true positives,
    false positives, false negatives, precision, recall and F1.

    Args:
        documents: Labelled documents, or a path to a JSON Lines file.
        min_confidence: Ignore predictions scoring below this value.
        match: ``"exact"`` (same type and offsets) or ``"overlap"`` (same type,
            overlapping spans).
        detectors: Detector ids to run; ``None`` runs all registered ones.
    """
    if match not in ("exact", "overlap"):
        raise ValueError('`match` must be "exact" or "overlap".')
    if isinstance(documents, (str, PathLike)):
        documents = load_corpus(documents)
    docs = list(documents)
    texts = [d["text"] for d in docs]
    predictions = detect_pii(texts, detectors=detectors, min_confidence=min_confidence)

    counts: dict[str, list[int]] = {}

    def bump(type_: str, i: int) -> None:
        counts.setdefault(type_, [0, 0, 0])[i] += 1

    by_doc: dict[int, list[Any]] = {}
    for p in predictions:
        by_doc.setdefault(p.doc, []).append(p)

    for i, d in enumerate(docs):
        gold = sorted(d.get("spans", []), key=lambda g: (g["start"], g["end"]))
        used = [False] * len(gold)
        for p in sorted(by_doc.get(i, []), key=lambda p: (p.start, p.end)):
            hit = None
            for j, g in enumerate(gold):
                if used[j] or g["type"] != p.type:
                    continue
                if match == "exact":
                    ok = g["start"] == p.start and g["end"] == p.end
                else:
                    ok = g["start"] < p.end and p.start < g["end"]
                if ok:
                    hit = j
                    break
            if hit is None:
                bump(p.type, 1)
            else:
                used[hit] = True
                bump(p.type, 0)
        for j, g in enumerate(gold):
            if not used[j]:
                bump(g["type"], 2)

    rows = [_score(t, *counts[t]) for t in sorted(counts)]
    total = [sum(c[i] for c in counts.values()) for i in range(3)]
    rows.append(_score("overall", *total))
    return EvaluationReport(rows, n_documents=len(docs), match=match)


def _ratio(a: int, b: int) -> float | None:
    return None if b == 0 else round(a / b, 4)


def _score(type_: str, tp: int, fp: int, fn: int) -> TypeScore:
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    p = None if tp + fp == 0 else tp / (tp + fp)
    r = None if tp + fn == 0 else tp / (tp + fn)
    f1 = None if p is None or r is None or p + r == 0 else round(2 * p * r / (p + r), 4)
    return TypeScore(type_, tp, fp, fn, precision, recall, f1)
