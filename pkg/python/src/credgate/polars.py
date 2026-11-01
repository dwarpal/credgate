"""Polars integration: ``pl.col("notes").credgate.redact()``.

Importing this module registers a ``credgate`` namespace on Polars
expressions and Series (``pip install 'credgate[polars]'``)::

    import polars as pl
    import credgate.polars  # noqa: F401

    df.with_columns(pl.col("notes").credgate.redact(min_confidence=0.5))
    df.filter(pl.col("notes").credgate.has_pii())

Numbered tokens (:func:`credgate.tokenise`) are not offered here: Polars may
process batches in parallel and in any order, so token numbers would depend
on scheduling. Tokenise a Series directly instead.
"""

from __future__ import annotations

from collections.abc import Sequence

from .detect import detect_pii
from .redact import redact as _redact

try:
    import polars as pl
except ImportError:  # pragma: no cover - exercised without polars
    raise ImportError("credgate.polars needs polars: pip install 'credgate[polars]'") from None


def _has_pii(s: pl.Series, detectors: Sequence[str] | None, min_confidence: float) -> pl.Series:
    found = {span.doc for span in detect_pii(s, detectors, min_confidence=min_confidence)}
    missing = s.is_null().to_list()
    return pl.Series(
        s.name,
        [None if m else (i in found) for i, m in enumerate(missing)],
        dtype=pl.Boolean,
    )


@pl.api.register_expr_namespace("credgate")
class CredgateExpr:
    def __init__(self, expr: pl.Expr) -> None:
        self._expr = expr

    def redact(
        self, detectors: Sequence[str] | None = None, min_confidence: float = 0.0
    ) -> pl.Expr:
        """Replace identifiers with placeholders such as ``[PAN]``."""
        return self._expr.map_batches(
            lambda s: _redact(s, detectors, min_confidence=min_confidence),
            return_dtype=pl.String,
        )

    def has_pii(
        self, detectors: Sequence[str] | None = None, min_confidence: float = 0.0
    ) -> pl.Expr:
        """Whether each value contains a detected identifier."""
        return self._expr.map_batches(
            lambda s: _has_pii(s, detectors, min_confidence), return_dtype=pl.Boolean
        )


@pl.api.register_series_namespace("credgate")
class CredgateSeries:
    def __init__(self, s: pl.Series) -> None:
        self._s = s

    def redact(
        self, detectors: Sequence[str] | None = None, min_confidence: float = 0.0
    ) -> pl.Series:
        """Replace identifiers with placeholders such as ``[PAN]``."""
        return _redact(self._s, detectors, min_confidence=min_confidence)

    def has_pii(
        self, detectors: Sequence[str] | None = None, min_confidence: float = 0.0
    ) -> pl.Series:
        """Whether each value contains a detected identifier."""
        return _has_pii(self._s, detectors, min_confidence)
