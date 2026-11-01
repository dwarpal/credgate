# BigQuery logic with the three calls that reach BigQuery (table metadata,
# dry run, query) replaced: cost limit, sampling, columns read, inventory.
# The queries themselves are checked by the conformance cases, and the
# Python package runs the same flow against the BigQuery emulator.

customers <- data.frame(
  pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R", "BNZPM2501F"),
  acct = c("50100012345678", "50100012345679", "50100012345680", "50100012345681"),
  notes = c("Called, Aadhaar 542229371182", "no issues", "ok", "no issues")
)
info <- function(n = 4, kind = "TABLE") {
  list(
    project = "test", dataset = "crm", table = "customers", kind = kind, n = n,
    fields = data.frame(
      name = c("pan", "acct", "notes", "tags"),
      type = c("STRING", "INT64", "STRING", "STRING"),
      mode = c("NULLABLE", "NULLABLE", "NULLABLE", "REPEATED")
    )
  )
}

fake_bigquery <- function(n = 4, kind = "TABLE", bytes = 1000, env = parent.frame()) {
  queries <- character()
  local_mocked_bindings(
    bq_table_info = function(table) info(n, kind),
    bq_dry_run = function(sql, billing) bytes,
    bq_fetch = function(sql, billing, max_bytes) {
      queries <<- c(queries, sql)
      if (startsWith(sql, "SELECT COUNT(*)")) data.frame(f0_ = 4) else customers
    },
    bq_list_tables = function(dataset) list("test.crm.customers", "test.crm.customers"),
    .env = env
  )
  function() queries
}

test_that("small tables are read whole and match the in-memory inventory", {
  queries <- fake_bigquery()
  inv <- bq_pii_inventory("test.crm.customers")
  expect_identical(unique(inv$source), "bigquery:test")
  expect_identical(unique(inv$table), "crm.customers")
  expect_identical(unique(inv$sample_method), "all")
  in_memory <- pii_inventory(cbind(customers, tags = NA_character_), source = "bigquery:test", table = "crm.customers")
  keep <- setdiff(names(inv), c("scanned_at", "sample_method"))
  expect_equal(as.data.frame(inv)[keep], as.data.frame(in_memory)[keep])
  expect_identical(inv$n_sampled[inv$column == "tags"], 0L)
  expect_length(queries(), 1)
  expect_identical(bq_scan_pii("test.crm.customers")$type, c("pan", "bank_account", "aadhaar"))
})

test_that("large tables are sampled by BigQuery; views use RAND()", {
  queries <- fake_bigquery(n = 1e6)
  inv <- bq_pii_inventory("test.crm.customers", sample = 1000)
  expect_identical(unique(inv$sample_method), "bigquery-tablesample")
  expect_identical(unique(inv$n_rows), 1000000L)
  expect_match(queries(), "TABLESAMPLE SYSTEM \\(0.12 PERCENT\\) LIMIT 1000$")
})

test_that("views use RAND(), and a missing row count is counted", {
  queries <- fake_bigquery(n = NA, kind = "VIEW")
  inv <- bq_pii_inventory("test.crm.customers", sample = 2)
  expect_identical(unique(inv$sample_method), "bigquery-rand")
  expect_match(queries()[1], "^SELECT COUNT\\(\\*\\) FROM `test.crm.customers`$")
  expect_match(queries()[2], "WHERE RAND\\(\\) < 0.6 LIMIT 2$")
})

test_that("the cost limit stops before anything runs", {
  queries <- fake_bigquery(bytes = 5e9)
  expect_error(bq_scan_pii("test.crm.customers"), class = "credgate_cost_limit")
  expect_error(bq_scan_pii("test.crm.customers"), "nothing was run")
  expect_length(queries(), 0)
  expect_no_error(bq_scan_pii("test.crm.customers", max_bytes = 1e10))
})

test_that("a dataset inventory covers every table", {
  fake_bigquery()
  inv <- bq_inventory_dataset("test.crm")
  expect_s3_class(inv, "cg_inventory")
  expect_identical(nrow(inv), 2L * nrow(bq_pii_inventory("test.crm.customers")))
})
