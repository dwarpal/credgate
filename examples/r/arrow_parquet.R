# Arrow and Parquet: scan and redact a file larger than memory.
#
# Requires: install.packages(c("credgate", "arrow"))
# Run:      python examples/python/make_synthetic_calls.py   # creates examples/data/calls.parquet
#           Rscript examples/r/arrow_parquet.R
#
# All data is synthetic.

library(credgate)

path <- "examples/data/calls.parquet"
out <- "examples/data/calls_redacted_r.parquet"

# 1. Scan without loading the file: one column at a time, same sample as in memory.
print(scan_pii(arrow::open_dataset(path), sample = 5000))

# 2. Redact the free-text column, 10,000 rows at a time; other columns unchanged.
rows <- redact_parquet(path, out, columns = "notes", min_confidence = 0.5)
cat(format(rows, big.mark = ","), "rows written to", out, "\n")
print(head(arrow::read_parquet(out, col_select = c("call_id", "notes")), 3))
