"""Column-level PII scan of tables (the spec's "Column scan" rules)."""

from __future__ import annotations

import numbers
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from . import _spark
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
    seed: int = 42,
) -> ScanReport:
    """Scan the columns of a table for PII.

    Reports, per column, which PII types occur and in what share of values -
    for example that ``cust_id`` looks like a PAN in 98% of rows. Each column
    is sampled (evenly spaced, so results are reproducible) and every sampled
    value is checked with :func:`detect_pii`, using the column name as
    context. Whole numbers are checked too; other numbers, booleans and
    dates are skipped.

    Args:
        data: A pandas or Polars DataFrame, a Polars LazyFrame, an Arrow table
            or dataset, a DuckDB relation, or a mapping of column name to
            values. Lazy frames, datasets and relations are read one column
            at a time, so the table may be larger than memory. A PySpark
            DataFrame is sampled inside the cluster (up to ``sample`` rows,
            randomly with ``seed``) and only the sample is collected.
        sample: Maximum number of values checked per column.
        min_rate: Report a type only if it occurs in at least this share of
            sampled values.
        detectors: Detector ids to run; ``None`` runs all registered ones.
        seed: Random seed for sampling Spark DataFrames; ignored otherwise.
    """
    columns, _ = _scan_columns(data, sample, min_rate, detectors, seed)
    findings = [f for c in columns for f in c.findings]
    return ScanReport(findings, n_columns=len(columns))


@dataclass(frozen=True)
class _ColumnScan:
    name: str
    n_sampled: int
    sampled: bool  # True when only a sample of the usable values was checked
    findings: list[ColumnFinding]


@dataclass(frozen=True)
class _Sampled:
    """Rows already sampled by an engine (Spark, BigQuery), as column -> values."""

    columns: dict[str, list[Any]]
    n_rows: int | None
    sample_method: str


@dataclass(frozen=True)
class _TableInfo:
    n_rows: int | None
    sample_method: str | None  # None: per column, "all" or "even"


def _scan_columns(
    data: Any, sample: int, min_rate: float, detectors: Sequence[str] | None, seed: int = 42
) -> tuple[list[_ColumnScan], _TableInfo]:
    """Every column of ``data``, with the types found in it (see the spec's
    "Column scan"); columns without usable values have no findings. Spark
    DataFrames are sampled in the cluster first ("Spark tables")."""
    if not isinstance(sample, numbers.Integral) or sample < 1:
        raise ValueError("`sample` must be a positive whole number.")
    if _spark.is_spark(data):
        data = _spark.sample_rows(data, sample, seed)
    if isinstance(data, _Sampled):
        info = _TableInfo(data.n_rows, data.sample_method)
        data = data.columns
    else:
        info = _TableInfo(_n_rows(data), None)
    out = []
    for name, chunks in _columns(data):
        values, n_usable = _sampled_values(chunks, sample)
        found: list[ColumnFinding] = []
        if values:
            context = name.replace("_", " ").replace(".", " ").replace("-", " ")
            spans = detect_pii(values, detectors=detectors, context=context)
            by_type: dict[str, list[Span]] = {}
            for s in spans:
                by_type.setdefault(s.type, []).append(s)
            found = [_summarise(name, group, values) for group in by_type.values()]
            found = [f for f in found if f.rate >= min_rate]
            found.sort(key=lambda f: (-f.rate, f.type))
        out.append(_ColumnScan(name, len(values), n_usable > sample, found))
    return out, info


def _n_rows(data: Any) -> int | None:
    """The number of rows, when known without reading the table."""
    module = type(data).__module__.split(".")[0].lstrip("_")
    kind = type(data).__name__
    if module == "pyarrow" and kind == "Table":
        return int(data.num_rows)
    if module in ("pandas", "polars") and kind == "DataFrame":
        return len(data)
    if isinstance(data, Mapping):
        first = next(iter(data.values()), None)
        return len(first) if hasattr(first, "__len__") else None
    return None


# A column is a function returning its values in chunks; it is called again
# for a second pass, so tables larger than memory are read one column and one
# chunk at a time.
Chunks = Callable[[], Iterator[list[Any]]]


def _columns(data: Any) -> list[tuple[str, Chunks]]:
    module = type(data).__module__.split(".")[0].lstrip("_")  # DuckDB 1.x: "_duckdb"
    kind = type(data).__name__
    if module == "pyarrow" and kind == "Table":
        return [
            (c, lambda c=c: (a.to_pylist() for a in data.column(c).chunks))
            for c in data.column_names
        ]
    if module == "pyarrow" and hasattr(data, "to_batches") and hasattr(data, "schema"):  # Dataset
        return [
            (c, lambda c=c: (b.column(0).to_pylist() for b in data.to_batches(columns=[c])))
            for c in data.schema.names
        ]
    if module == "polars" and kind == "LazyFrame":
        return [
            (c, lambda c=c: iter([data.select(c).collect().to_series().to_list()]))
            for c in data.collect_schema().names()
        ]
    if module == "duckdb" and hasattr(data, "columns") and hasattr(data, "select"):  # relation
        return [(c, lambda c=c: _duckdb_chunks(data, c)) for c in data.columns]
    if hasattr(data, "columns") and hasattr(data, "__getitem__"):  # pandas or Polars DataFrame
        return [(str(c), lambda c=c: iter([list(data[c])])) for c in data.columns]
    if isinstance(data, Mapping):
        return [(str(k), lambda v=v: iter([list(v)])) for k, v in data.items()]
    raise TypeError(
        "`data` must be a pandas or Polars DataFrame, a Polars LazyFrame, an Arrow table "
        "or dataset, a DuckDB relation, or a mapping of column -> values."
    )


def _duckdb_chunks(rel: Any, column: str) -> Iterator[list[Any]]:
    quoted = '"' + column.replace('"', '""') + '"'
    projected = rel.select(quoted)
    if hasattr(projected, "to_arrow_reader"):  # DuckDB 1.4+
        batches = projected.to_arrow_reader(100_000)
    else:
        batches = projected.fetch_record_batch(100_000)
    for batch in batches:
        yield batch.column(0).to_pylist()


def _sampled_values(chunks: Chunks, sample: int) -> tuple[list[str], int]:
    """The column's usable values, sampled as the spec says: with n > sample
    values, those at positions floor(i * n / sample). Also returns n."""
    first = chunks()
    head = next(first, None)
    if head is None:
        return [], 0
    rest = next(first, None)
    if rest is None:  # one chunk, already in memory
        values = _scan_values(head)
        n = len(values)
        return ([values[i * n // sample] for i in range(sample)] if n > sample else values), n
    # Several chunks: count, then pick the sampled positions in a second pass.
    n = len(_scan_values(head)) + len(_scan_values(rest)) + sum(len(_scan_values(c)) for c in first)
    wanted = [i * n // sample for i in range(sample)] if n > sample else list(range(n))
    out: list[str] = []
    seen = 0
    k = 0
    for chunk in chunks():
        values = _scan_values(chunk)
        while k < len(wanted) and wanted[k] < seen + len(values):
            out.append(values[wanted[k] - seen])
            k += 1
        seen += len(values)
        if k == len(wanted):
            break
    return out, n


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
        example=mask_value(firsts[0].value, firsts[0].data_class),
    )
