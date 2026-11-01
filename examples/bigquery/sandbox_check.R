# Check credgate's BigQuery support against real BigQuery (R half).
#
# Run sandbox_check.py first: it creates the dataset `credgate_check` with
# synthetic data. This script then checks, from R with bigrquery:
#   1. the cost limit refuses a query before it runs;
#   2. block sampling (TABLESAMPLE) and RAND() sampling both work;
#   3. the inventory, written to credgate_check_r.csv - compare it with
#      credgate_check_python.csv (samples are random, so rates differ a
#      little; the types found should match).
#
#   Rscript examples/bigquery/sandbox_check.R YOUR-PROJECT-ID
#
# Needs: install.packages(c("credgate", "bigrquery")); bigrquery asks you to
# sign in to Google the first time.

library(credgate)

project <- commandArgs(trailingOnly = TRUE)[1]
if (is.na(project)) stop("Usage: Rscript sandbox_check.R YOUR-PROJECT-ID")
table <- paste0(project, ".credgate_check.customers")

# 1. The cost limit.
res <- tryCatch(bq_scan_pii(table, max_bytes = 1), credgate_cost_limit = function(e) "refused")
cat("Cost limit:", if (identical(res, "refused")) "refused before running, as expected.\n" else "NOT enforced - please report this.\n")

# 2. Both sampling modes.
for (sampling in c("tablesample", "rand")) {
  inv <- bq_pii_inventory(table, sample = 500L, sampling = sampling)
  cat(sprintf("%-12s %s, up to %d values per column\n", sampling, unique(inv$sample_method), max(inv$n_sampled)))
}

# 3. The inventory.
inv <- bq_pii_inventory(table, sample = 500L)
write_inventory(inv, "credgate_check_r.csv")
print(inv)
print(inv[!is.na(inv$type), c("column", "type", "rate", "n_sampled", "sample_method")], row.names = FALSE)

if (file.exists("credgate_check_python.csv")) {
  py <- read_inventory("credgate_check_python.csv")
  same <- identical(sort(unique(paste(py$column, py$type))), sort(unique(paste(inv$column, inv$type))))
  cat("\nTypes found per column, R vs Python:", if (same) "the same.\n" else "DIFFERENT - please share both CSVs.\n")
}
