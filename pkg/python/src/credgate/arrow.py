"""Redact Arrow tables and streams, and Parquet files larger than memory.

Requires pyarrow (``pip install 'credgate[arrow]'``). Text columns are
processed batch by batch, so memory use depends on the batch size, not the
size of the data. :func:`credgate.redact` and :func:`credgate.tokenise` also
accept Arrow arrays directly.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from typing import Any

from .redact import redact

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:  # pragma: no cover - exercised without pyarrow
    raise ImportError("credgate.arrow needs pyarrow: pip install 'credgate[arrow]'") from None


def text_columns(schema: pa.Schema) -> list[str]:
    """Names of the string columns in a schema."""
    return [
        f.name for f in schema if pa.types.is_string(f.type) or pa.types.is_large_string(f.type)
    ]


def _columns(schema: pa.Schema, columns: Sequence[str] | None) -> list[str]:
    if columns is None:
        return text_columns(schema)
    unknown = [c for c in columns if c not in schema.names]
    if unknown:
        raise KeyError(f"Unknown column(s): {', '.join(unknown)}")
    return list(columns)


def redact_batch(
    batch: pa.RecordBatch, columns: Sequence[str] | None = None, **options: Any
) -> pa.RecordBatch:
    """Redact the given columns (default: all string columns) of one record batch.

    ``options`` are passed to :func:`credgate.redact` (``detectors``,
    ``min_confidence``)."""
    names = _columns(batch.schema, columns)
    arrays = [
        redact(batch.column(i), **options) if name in names else batch.column(i)
        for i, name in enumerate(batch.schema.names)
    ]
    return pa.RecordBatch.from_arrays(arrays, schema=batch.schema)


def redact_table(table: pa.Table, columns: Sequence[str] | None = None, **options: Any) -> pa.Table:
    """Redact the given columns (default: all string columns) of a table."""
    batches = [redact_batch(b, columns, **options) for b in table.to_batches()]
    return pa.Table.from_batches(batches, schema=table.schema)


def redact_batches(
    batches: Any, columns: Sequence[str] | None = None, **options: Any
) -> Iterator[pa.RecordBatch]:
    """Redact a stream of record batches (for example a ``RecordBatchReader``),
    yielding redacted batches one at a time."""
    for batch in batches:
        yield redact_batch(batch, columns, **options)


def redact_parquet(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    columns: Sequence[str] | None = None,
    batch_size: int = 10_000,
    **options: Any,
) -> int:
    """Redact a Parquet file into a new one, ``batch_size`` rows at a time.

    The source may be larger than memory. Columns not redacted are copied
    unchanged; the schema is kept. Returns the number of rows written.
    """
    if os.path.abspath(source) == os.path.abspath(destination):
        raise ValueError("`destination` must differ from `source`.")
    reader = pq.ParquetFile(source)
    names = _columns(reader.schema_arrow, columns)
    rows = 0
    with pq.ParquetWriter(destination, reader.schema_arrow) as writer:
        for batch in reader.iter_batches(batch_size=batch_size):
            writer.write_batch(redact_batch(batch, names, **options))
            rows += batch.num_rows
    return rows
