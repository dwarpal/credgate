"""Inventory: where PII is across many tables (the spec's "Inventory" rules)."""

from __future__ import annotations

import csv
import os
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .scan import _n_rows, _scan_columns

FORMAT_VERSION = 1
_FIELDS = (
    "v",
    "source",
    "table",
    "column",
    "type",
    "class",
    "n_rows",
    "n_sampled",
    "n_matched",
    "n_full",
    "rate",
    "mean_confidence",
    "sample_method",
    "scanned_at",
    "credgate",
)
_INTS = {"v", "n_rows", "n_sampled", "n_matched", "n_full"}
_NUMBERS = {"rate": 4, "mean_confidence": 2}
_OPTIONAL = {"type", "class", "n_rows", "mean_confidence"}


@dataclass(frozen=True)
class InventoryRow:
    """One column of one table, and one PII type found in it (``type`` is
    ``None`` for a column scanned without finding any)."""

    source: str
    table: str
    column: str
    type: str | None
    data_class: str | None
    n_rows: int | None
    n_sampled: int
    n_matched: int
    n_full: int
    rate: float
    mean_confidence: float | None
    sample_method: str
    scanned_at: str
    credgate: str
    v: int = FORMAT_VERSION

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["class"] = d.pop("data_class")
        return {k: d[k] for k in _FIELDS}


class Inventory(list[InventoryRow]):
    """Rows of an inventory; combine inventories with ``+`` and save them with
    :meth:`write`. Prints as a summary per table."""

    def __init__(self, rows: Iterable[InventoryRow] = ()) -> None:
        super().__init__(rows)

    def __add__(self, other: Iterable[InventoryRow]) -> Inventory:  # type: ignore[override]
        return Inventory([*self, *other])

    def to_records(self) -> list[dict[str, Any]]:
        """One dict per row, e.g. for ``pandas.DataFrame(inventory.to_records())``."""
        return [r.to_dict() for r in self]

    def write(self, path: str | os.PathLike[str]) -> Path:
        """Write the inventory as a CSV file, exactly as the spec describes."""
        lines = [",".join(_FIELDS)]
        for row in self:
            d = row.to_dict()
            lines.append(",".join(_format(k, d[k]) for k in _FIELDS))
        path = Path(path)
        path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
        return path

    def __str__(self) -> str:
        if not self:
            return "Empty inventory."
        tables = list(dict.fromkeys((r.source, r.table) for r in self))
        lines = [f"Inventory of {len(tables)} table(s):"]
        for source, table in tables:
            rows = [r for r in self if (r.source, r.table) == (source, table)]
            columns = list(dict.fromkeys(r.column for r in rows))
            found = list(dict.fromkeys(r.column for r in rows if r.type is not None))
            types = list(dict.fromkeys(r.type for r in rows if r.type is not None))
            line = f"  {source}: {table} - {len(columns)} column(s) scanned"
            line += f", PII in {len(found)}" + (f" ({', '.join(types)})" if types else "")
            lines.append(line)
        return "\n".join(lines)


def pii_inventory(
    data: Any,
    source: str,
    table: str,
    sample: int = 10000,
    min_rate: float = 0.0,
    detectors: Sequence[str] | None = None,
) -> Inventory:
    """Scan a table and record where PII is, for an inventory.

    Uses the same rules as :func:`scan_pii`, but records every column -
    including those where nothing was found - with the source and table
    names, the sample size and method, and when and by what it was scanned.
    No values are recorded, not even masked ones. Combine the inventories of
    several tables with ``+`` and save them with :meth:`Inventory.write`.

    Args:
        data: Any table :func:`scan_pii` accepts.
        source: Name of the data source, chosen by you (e.g. ``"bigquery:prod"``).
        table: Name of the table within the source (e.g. ``"crm.customers"``).
        sample, min_rate, detectors: As for :func:`scan_pii`.
    """
    from . import __version__

    for name, value in (("source", source), ("table", table)):
        if not isinstance(value, str) or not value:
            raise ValueError(f"`{name}` must be a non-empty string.")
    scanned_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    n_rows = _n_rows(data)
    common = {
        "source": source,
        "table": table,
        "n_rows": n_rows,
        "scanned_at": scanned_at,
        "credgate": f"python/{__version__}",
    }
    rows = []
    for col in _scan_columns(data, sample, min_rate, detectors):
        method = "even" if col.sampled else "all"
        if not col.findings:
            rows.append(
                InventoryRow(
                    column=col.name,
                    type=None,
                    data_class=None,
                    n_sampled=col.n_sampled,
                    n_matched=0,
                    n_full=0,
                    rate=0.0,
                    mean_confidence=None,
                    sample_method=method,
                    **common,
                )
            )
        for f in col.findings:
            rows.append(
                InventoryRow(
                    column=col.name,
                    type=f.type,
                    data_class=f.data_class,
                    n_sampled=f.n_sampled,
                    n_matched=f.n_matched,
                    n_full=f.n_full,
                    rate=f.rate,
                    mean_confidence=f.mean_confidence,
                    sample_method=method,
                    **common,
                )
            )
    return Inventory(rows)


def read_inventory(path: str | os.PathLike[str]) -> Inventory:
    """Read an inventory CSV file written by :meth:`Inventory.write` (in R or
    Python)."""
    with Path(path).open(encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header is None or tuple(header) != _FIELDS:
            raise ValueError(f"{path} is not a credgate inventory: unexpected header.")
        names = {f.name for f in fields(InventoryRow)}
        rows = []
        for line, record in enumerate(reader, start=2):
            if len(record) != len(_FIELDS):
                raise ValueError(f"{path}, line {line}: expected {len(_FIELDS)} fields.")
            d: dict[str, Any] = {}
            for key, text in zip(_FIELDS, record, strict=True):
                try:
                    d[key] = _parse(key, text)
                except ValueError:
                    raise ValueError(f"{path}, line {line}: bad value for `{key}`.") from None
            if d["v"] != FORMAT_VERSION:
                raise ValueError(f"{path}, line {line}: unsupported inventory version {d['v']}.")
            d["data_class"] = d.pop("class")
            rows.append(InventoryRow(**{k: v for k, v in d.items() if k in names}))
    return Inventory(rows)


def _format(key: str, value: Any) -> str:
    if value is None:
        return ""
    if key in _NUMBERS:
        return f"{value:.{_NUMBERS[key]}f}".rstrip("0").rstrip(".")
    text = str(value)
    if any(c in text for c in ',"\r\n'):
        return '"' + text.replace('"', '""') + '"'
    return text


def _parse(key: str, text: str) -> Any:
    if text == "":
        if key not in _OPTIONAL:
            raise ValueError(key)
        return None
    if key in _INTS:
        return int(text)
    if key in _NUMBERS:
        return float(text)
    return text
