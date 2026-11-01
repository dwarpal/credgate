# DuckDB (and other databases): scan with dbplyr, redact with redact_query().
#
# Requires: install.packages(c("credgate", "duckdb", "DBI", "dbplyr", "dplyr"))
# Run:      python examples/python/make_synthetic_calls.py   # creates examples/data/calls.parquet
#           Rscript examples/r/duckdb_dbplyr.R
#
# All data is synthetic.

library(credgate)

con <- DBI::dbConnect(duckdb::duckdb())

# A view over the Parquet file: nothing is loaded into R.
DBI::dbExecute(con, "CREATE VIEW calls AS SELECT * FROM 'examples/data/calls.parquet'")

# 1. Which columns hold PII? The query runs once per column, in chunks.
print(scan_pii(dplyr::tbl(con, "calls"), sample = 5000))

# 2. Redact the notes into a new table, 10,000 rows at a time, leaving out
#    the structured identifier columns.
redact_query(con, "SELECT call_id, amount, notes FROM calls", "calls_safe", min_confidence = 0.5)
print(DBI::dbGetQuery(con, "SELECT * FROM calls_safe LIMIT 3"))

# 3. Write it back out as Parquet.
DBI::dbExecute(con, "COPY calls_safe TO 'examples/data/calls_redacted_duckdb_r.parquet' (FORMAT parquet)")
DBI::dbDisconnect(con, shutdown = TRUE)
