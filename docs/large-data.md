# Large data with credgate

Bank, insurance and fintech data is usually too big for a data frame. This
guide shows how to find and remove personal data in large tables with
credgate, in Python, in R and on the command line. Every example uses
synthetic data; runnable versions are in [`examples/`](../examples/).

## The approach

1. **Scan first.** `scan_pii()` tells you which columns hold personal data
   and how much, from a sample. It reads big tables one column at a time and
   samples exactly as it does in memory, so the report is the same at any
   size.
2. **Treat structured columns as a whole.** A column that *is* a PAN or a
   mobile number (`cust_pan`, `mobile`) is best dropped, or tokenised as a
   column; it does not need detection row by row.
3. **Redact free text in batches.** Notes, complaints and chat logs are
   redacted in batches (Arrow record batches, database chunks), so memory
   use does not grow with the data.

## What works where

| | Python | R | Command line |
|---|---|---|---|
| In-memory columns | pandas / Polars Series, Arrow arrays | character vectors, Arrow arrays | text files, standard input |
| Polars | `pl.col("notes").credgate.redact()` | - | - |
| Arrow tables, datasets | `credgate.arrow`, `scan_pii(dataset)` | `scan_pii(arrow::open_dataset(...))` | - |
| Parquet larger than memory | `credgate.arrow.redact_parquet()` | `redact_parquet()` | `credgate redact --parquet` |
| DuckDB | SQL: `cg_redact(notes)`, `cg_has_pii(notes)` | `redact_query()`, `scan_pii(dplyr::tbl(con, ...))` | - |
| Other databases (DBI) | - | `redact_query()`, `scan_pii()` on dbplyr tables | - |
| Scan a file | `scan_pii()` | `scan_pii()` | `credgate scan file.parquet` |

Numbered tokens (`[PAN_1]`) are available for in-memory columns. Inside
Polars and DuckDB, which process batches in parallel and in no fixed order,
use redaction; keyed tokens that work in parallel are planned.

## Python

```sh
pip install 'credgate[polars,duckdb]'      # or [arrow] for Parquet only
```

```python
import credgate, polars as pl
import credgate.polars                       # adds .credgate to expressions

calls = pl.scan_parquet("calls.parquet")     # lazy: nothing loaded yet
credgate.scan_pii(calls)                     # one column at a time
calls.with_columns(pl.col("notes").credgate.redact(min_confidence=0.5)) \
     .drop("cust_pan", "mobile").sink_parquet("calls_safe.parquet")
```

```python
import duckdb, credgate.duckdb

con = duckdb.connect()
credgate.duckdb.register(con, min_confidence=0.5)
con.sql("COPY (SELECT call_id, cg_redact(notes) AS notes FROM 'calls.parquet') "
        "TO 'calls_safe.parquet'")
```

Examples: [`pandas_scan_redact.py`](../examples/python/pandas_scan_redact.py),
[`polars_redact.py`](../examples/python/polars_redact.py),
[`duckdb_sql_redact.py`](../examples/python/duckdb_sql_redact.py),
[`arrow_parquet_stream.py`](../examples/python/arrow_parquet_stream.py).

## R

```r
install.packages(c("arrow", "duckdb", "DBI", "dbplyr", "dplyr"))  # the ones you use
library(credgate)

scan_pii(arrow::open_dataset("calls.parquet"))
redact_parquet("calls.parquet", "calls_safe.parquet", columns = "notes", min_confidence = 0.5)

con <- DBI::dbConnect(duckdb::duckdb())
scan_pii(dplyr::tbl(con, dplyr::sql("SELECT * FROM 'calls.parquet'")))
redact_query(con, "SELECT call_id, notes FROM 'calls.parquet'", "calls_safe")
```

The same works on any database with a DBI driver (Postgres, SQL Server via
odbc, Oracle, Snowflake, ...): `redact_query()` needs only DBI, and
`scan_pii()` takes a dbplyr table. For example, Postgres:

```r
con <- DBI::dbConnect(RPostgres::Postgres(), dbname = "lending", host = "db.internal")
scan_pii(dplyr::tbl(con, "loan_notes"))                     # needs dbplyr
redact_query(con, "SELECT id, notes FROM loan_notes", "loan_notes_safe")
```

Tested with DuckDB, SQLite and Postgres (a real Postgres server runs in the
test suite). `scan_pii()` reads each column twice (to count, then to sample),
so the sample matches the in-memory one only if the database returns rows in
the same order both times, as these do for plain tables. Postgres and SQLite
cannot write on a connection while a query is open on it, so with one
connection `redact_query()` keeps redacted chunks in temporary files until
the query has been read and then writes them in one transaction; give it a
second connection (`to_con`) to write as it reads.

The vignette `vignette("large-data", package = "credgate")` walks through
both. Examples: [`arrow_parquet.R`](../examples/r/arrow_parquet.R),
[`duckdb_dbplyr.R`](../examples/r/duckdb_dbplyr.R).

## Command line

```sh
pip install 'credgate[arrow]'
credgate scan calls.parquet
credgate redact --parquet calls.parquet --column notes --min-confidence 0.5 -o calls_safe.parquet
```

Example: [`parquet_pipeline.sh`](../examples/shell/parquet_pipeline.sh).

## Speed

On one core of a 2019 laptop credgate processes about 0.4 MB of text per
second in Python and 0.2-0.3 MB in R ([throughput](../benchmark/README.md#throughput)).
Detection is independent per row, so it scales with cores and machines.
Spark support and faster matching are on the roadmap.
