"""Text columns from pandas, Polars and Arrow, and back.

`redact()`, `tokenise()` and `detect_pii()` accept a plain string or sequence,
a pandas Series, a Polars Series, or an Arrow array; results come back in the
caller's type. None of these libraries is required: each is recognised by its
module name, without importing it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any


def _kind(x: Any) -> str | None:
    module = type(x).__module__.split(".")[0]
    name = type(x).__name__
    if module == "pandas" and name == "Series":
        return "pandas"
    if module == "polars" and name == "Series":
        return "polars"
    if module == "pyarrow" and name.endswith("Array"):  # any Arrow array or ChunkedArray
        return "arrow"
    return None


def texts(
    text: str | Sequence[str | None] | Any,
) -> tuple[list[str], list[bool], Callable[[list[str]], Any]]:
    """The documents (missing values as ""), which were missing, and a function
    that wraps outputs for those documents in the caller's type, keeping
    missing values as they were."""
    if isinstance(text, str):
        return [text], [False], lambda out: out[0]
    kind = _kind(text)
    if kind == "pandas":
        items = text.tolist()
    elif kind == "polars":
        items = text.to_list()
    elif kind == "arrow":
        items = text.to_pylist()
    else:
        items = list(text)
    missing = [not isinstance(t, str) for t in items]
    docs = ["" if m else t for t, m in zip(items, missing, strict=True)]

    def wrap(out: list[str]) -> Any:
        merged = [orig if m else o for orig, o, m in zip(items, out, missing, strict=True)]
        if kind == "pandas":
            import pandas as pd

            string = pd.api.types.is_string_dtype(text.dtype)
            categorical = isinstance(text.dtype, pd.CategoricalDtype)
            dtype = text.dtype if string and not categorical else object
            return pd.Series(merged, index=text.index, name=text.name, dtype=dtype)
        if kind == "polars":
            import polars as pl

            return pl.Series(text.name, merged, dtype=pl.String)
        if kind == "arrow":
            import pyarrow as pa

            t = text.type
            stringlike = pa.types.is_string(t) or pa.types.is_large_string(t)
            return pa.array(merged, type=t if stringlike else pa.string())
        return merged

    return docs, missing, wrap
