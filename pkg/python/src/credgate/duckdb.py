"""DuckDB integration: ``SELECT cg_redact(notes) FROM 'big.parquet'``.

:func:`register` adds SQL functions to a DuckDB connection
(``pip install 'credgate[duckdb]'``)::

    import duckdb
    import credgate.duckdb

    con = duckdb.connect()
    credgate.duckdb.register(con, min_confidence=0.5)
    con.sql("COPY (SELECT id, cg_redact(notes) AS notes FROM 'calls.parquet') "
            "TO 'calls_redacted.parquet'")

The functions run on Arrow batches, so DuckDB streams data through them and
the input may be larger than memory. Numbered tokens are not offered: DuckDB
processes batches in parallel, so token numbers would depend on scheduling.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .detect import detect_pii
from .redact import redact

try:
    import duckdb
    import pyarrow as pa
except ImportError:  # pragma: no cover - exercised without duckdb
    raise ImportError(
        "credgate.duckdb needs duckdb and pyarrow: pip install 'credgate[duckdb]'"
    ) from None


def register(
    con: Any,
    detectors: Sequence[str] | None = None,
    min_confidence: float = 0.0,
    prefix: str = "cg_",
) -> None:
    """Add ``<prefix>redact(text)`` and ``<prefix>has_pii(text)`` to ``con``.

    ``detectors`` and ``min_confidence`` apply to every call of the functions.
    """

    def redact_udf(text: pa.Array) -> pa.Array:
        return redact(text, detectors, min_confidence=min_confidence)

    def has_pii_udf(text: pa.Array) -> pa.Array:
        values = text.to_pylist()
        docs = ["" if v is None else v for v in values]
        found = {s.doc for s in detect_pii(docs, detectors, min_confidence=min_confidence)}
        return pa.array([None if v is None else (i in found) for i, v in enumerate(values)])

    types = getattr(duckdb, "sqltypes", None) or duckdb.typing  # renamed in DuckDB 2.0
    varchar = types.VARCHAR
    con.create_function(f"{prefix}redact", redact_udf, [varchar], varchar, type="arrow")
    con.create_function(f"{prefix}has_pii", has_pii_udf, [varchar], types.BOOLEAN, type="arrow")
