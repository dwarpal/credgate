"""Column-level PII scan of tables (the spec's "Column scan" rules)."""

from __future__ import annotations

import numbers
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from .detect import Span, detect_pii, mask_value


@dataclass(frozen=True)
class ColumnFinding:
    """One PII type found in one column."""

    column: str
    type: str
    data_class: str
    n_sampled: int
    n_matched: int
    n_full: int
    rate: float
    mean_confidence: float
    example: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["class"] = d.pop("data_class")
        return d


class ScanReport(list[ColumnFinding]):
    """Findings of :func:`scan_pii`; prints as a readable table."""

    def __init__(self, findings: Iterable[ColumnFinding], n_columns: int) -> None:
        super().__init__(findings)
        self.n_columns = n_columns

    def to_records(self) -> list[dict[str, Any]]:
        """One dict per finding, e.g. for ``pandas.DataFrame(report.to_records())``."""
        return [f.to_dict() for f in self]

    def __str__(self) -> str:
        if not self:
            return f"Scanned {self.n_columns} column(s): no PII found."
        columns = list(dict.fromkeys(f.column for f in self))
        lines = [
            f"Scanned {self.n_columns} column(s); PII found in {len(columns)}: "
            + ", ".join(columns)
        ]
        width = max(len(f.column) for f in self)
        for f in self:
            lines.append(
                f"  {f.column:<{width}}  {f.type:<16} {f.rate:>4.0%} of {f.n_sampled}"
                f" ({f.n_full} whole value)  confidence {f.mean_confidence:.2f}  e.g. {f.example}"
            )
        return "\n".join(lines)


def scan_pii(
    data: Any,
    sample: int = 10000,
    min_rate: float = 0.0,
    detectors: Sequence[str] | None = None,
) -> ScanReport:
    """Scan the columns of a table for PII.

    Reports, per column, which PII types occur and in what share of values -
    for example that ``cust_id`` looks like a PAN in 98% of rows. Each column
    is sampled (evenly spaced, so results are reproducible) and every sampled
    value is checked with :func:`detect_pii`, using the column name as
    context. Whole numbers are checked too; other numbers, booleans and
    dates are skipped.

    Args:
        data: A pandas DataFrame, or a mapping of column name to values.
        sample: Maximum number of values checked per column.
        min_rate: Report a type only if it occurs in at least this share of
            sampled values.
        detectors: Detector ids to run; ``None`` runs all registered ones.
    """
    if not isinstance(sample, numbers.Integral) or sample < 1:
        raise ValueError("`sample` must be a positive whole number.")
    columns = _columns(data)
    findings: list[ColumnFinding] = []
    for name, raw in columns:
        values = _scan_values(raw)
        n = len(values)
        if n == 0:
            continue
        if n > sample:
            values = [values[i * n // sample] for i in range(sample)]
        context = name.replace("_", " ").replace(".", " ").replace("-", " ")
        spans = detect_pii(values, detectors=detectors, context=context)
        by_type: dict[str, list[Span]] = {}
        for s in spans:
            by_type.setdefault(s.type, []).append(s)
        found = [_summarise(name, group, values) for group in by_type.values()]
        found = [f for f in found if f.rate >= min_rate]
        found.sort(key=lambda f: (-f.rate, f.type))
        findings.extend(found)
    return ScanReport(findings, n_columns=len(columns))


def _columns(data: Any) -> list[tuple[str, list[Any]]]:
    if hasattr(data, "columns") and hasattr(data, "__getitem__"):  # pandas-like
        return [(str(c), list(data[c])) for c in data.columns]
    if isinstance(data, Mapping):
        return [(str(k), list(v)) for k, v in data.items()]
    raise TypeError("`data` must be a pandas DataFrame or a mapping of column -> values.")


def _scan_values(raw: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for x in raw:
        if isinstance(x, str):
            v = x
        elif isinstance(x, bool):
            continue
        elif isinstance(x, numbers.Integral):
            v = str(int(x))
        elif isinstance(x, numbers.Real):
            f = float(x)
            if f != f or f in (float("inf"), float("-inf")) or not f.is_integer():
                continue
            v = str(int(f))
        else:  # None, missing markers, dates and other types
            continue
        v = v.strip()
        if v:
            out.append(v)
    return out


def _summarise(column: str, spans: list[Span], values: list[str]) -> ColumnFinding:
    first: dict[int, Span] = {}
    full: set[int] = set()
    for s in spans:
        first.setdefault(s.doc, s)
        if s.start == 0 and s.end == len(values[s.doc]):
            full.add(s.doc)
    firsts = list(first.values())
    n_sampled = len(values)
    return ColumnFinding(
        column=column,
        type=firsts[0].type,
        data_class=firsts[0].data_class,
        n_sampled=n_sampled,
        n_matched=len(firsts),
        n_full=len(full),
        rate=round(len(firsts) / n_sampled, 4),
        mean_confidence=round(sum(s.confidence for s in firsts) / len(firsts), 2),
        example=mask_value(firsts[0].value),
    )
