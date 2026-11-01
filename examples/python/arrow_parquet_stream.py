"""Arrow: redact a Parquet file larger than memory, batch by batch.

Requires: pip install 'credgate[arrow]'
Run:      python examples/python/make_synthetic_calls.py   # creates examples/data/calls.parquet
          python examples/python/arrow_parquet_stream.py

All data is synthetic.
"""

import credgate
import credgate.arrow
import pyarrow.dataset as ds
import pyarrow.parquet as pq

PATH = "examples/data/calls.parquet"
OUT = "examples/data/calls_redacted_arrow.parquet"

# 1. Scan: a dataset is read one column at a time, so memory stays small,
#    and the report is the same as for the whole table in memory.
print(credgate.scan_pii(ds.dataset(PATH), sample=5_000), end="\n\n")

# 2. Redact only the free-text column, 10,000 rows at a time; other columns
#    and the schema are copied unchanged.
rows = credgate.arrow.redact_parquet(PATH, OUT, columns=["notes"], min_confidence=0.5)
print(f"{rows:,} rows written to {OUT}")
print(pq.read_table(OUT, columns=["call_id", "notes"]).slice(0, 3).to_pandas().to_string())
