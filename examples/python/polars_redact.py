"""Polars: redact text columns with an expression, eagerly or lazily.

Requires: pip install 'credgate[polars,arrow]'
Run:      python examples/python/make_synthetic_calls.py   # creates examples/data/calls.parquet
          python examples/python/polars_redact.py

All data is synthetic.
"""

import credgate
import credgate.polars  # adds the .credgate namespace to Polars expressions
import polars as pl

PATH = "examples/data/calls.parquet"

# Lazy: Polars reads only what the query needs.
calls = pl.scan_parquet(PATH)

# 1. Scan the PII columns without loading the table: one column at a time.
print(credgate.scan_pii(calls, sample=5_000), end="\n\n")

# 2. How many notes mention personal data at all?
counts = calls.select(pl.col("notes").credgate.has_pii(min_confidence=0.5).alias("has_pii"))
print(counts.group_by("has_pii").len().collect(), end="\n\n")

# 3. Redact the notes, drop the structured PII columns, write Parquet.
safe = calls.with_columns(pl.col("notes").credgate.redact(min_confidence=0.5)).drop(
    "cust_pan", "mobile"
)
safe.sink_parquet("examples/data/calls_redacted_polars.parquet")
print(pl.read_parquet("examples/data/calls_redacted_polars.parquet").head(3))
