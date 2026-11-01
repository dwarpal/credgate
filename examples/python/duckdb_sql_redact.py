"""DuckDB: redact in SQL, straight from and to Parquet.

`credgate.duckdb.register()` adds two SQL functions, `cg_redact(text)` and
`cg_has_pii(text)`. DuckDB streams the data through them, so the file may be
larger than memory.

Requires: pip install 'credgate[duckdb]'
Run:      python examples/python/make_synthetic_calls.py   # creates examples/data/calls.parquet
          python examples/python/duckdb_sql_redact.py

All data is synthetic.
"""

import credgate
import credgate.duckdb
import duckdb

PATH = "examples/data/calls.parquet"
OUT = "examples/data/calls_redacted_duckdb.parquet"

con = duckdb.connect()
credgate.duckdb.register(con, min_confidence=0.5)

# 1. Which columns hold PII? scan_pii reads one column at a time.
print(credgate.scan_pii(con.sql(f"FROM '{PATH}'"), sample=5_000), end="\n\n")

# 2. Look before you send: rows with PII in the notes, redacted side by side.
print(
    con.sql(
        f"SELECT notes, cg_redact(notes) AS redacted FROM '{PATH}' WHERE cg_has_pii(notes) LIMIT 3"
    )
)

# 3. Write a redacted copy without the structured PII columns.
con.sql(
    f"COPY (SELECT call_id, amount, cg_redact(notes) AS notes FROM '{PATH}') "
    f"TO '{OUT}' (FORMAT parquet)"
)
print(con.sql(f"SELECT count(*) AS rows FROM '{OUT}'"))
