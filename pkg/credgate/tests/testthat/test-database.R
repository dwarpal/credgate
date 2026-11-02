# Whole-database inventories (spec: "Databases") on SQLite, DuckDB and
# Postgres, where their DBI packages (and for Postgres a server: PGHOST)
# are available. The R integration job provides all three.

pans <- c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R", "BNZPM2501F")
customers <- function(n = 40) {
  data.frame(
    pan = pans[(seq_len(n) - 1) %% 4 + 1],
    account_no = 50100012345678 + seq_len(n),
    notes = ifelse(seq_len(n) %% 2 == 0, "Aadhaar 542229371182", "ok"),
    dob = as.Date("1990-01-01")
  )
}
strip <- function(inv) as.data.frame(inv)[, setdiff(names(inv), c("scanned_at", "credgate"))]

test_that("SQLite: every table, sampling, resume and errors", {
  skip_if_not_installed("RSQLite")
  con <- DBI::dbConnect(RSQLite::SQLite(), withr::local_tempfile(fileext = ".db"))
  withr::defer(DBI::dbDisconnect(con))
  DBI::dbWriteTable(con, "customers", customers())
  DBI::dbWriteTable(con, "calls", data.frame(note = "mobile 9876543210"))

  inv <- inventory_database(con, source = "sqlite:crm")
  expect_identical(sort(unique(inv$table)), c("main.calls", "main.customers"))
  in_memory <- pii_inventory(
    DBI::dbReadTable(con, "customers"), source = "sqlite:crm", table = "main.customers"
  )
  expect_equal(strip(inv[inv$table == "main.customers", ]), strip(in_memory), ignore_attr = TRUE)

  big <- inventory_database(con, source = "sqlite:crm", sample = 10L, include = "*.customers")
  expect_identical(unique(big$sample_method), "first-rows")
  expect_identical(max(big$n_sampled), 10L)

  path <- withr::local_tempfile(fileext = ".csv")
  first <- inventory_database(con, source = "sqlite:crm", path = path)
  expect_equal(strip(read_inventory(path)), strip(first), ignore_attr = TRUE)
  again <- inventory_database(con, source = "sqlite:crm", path = path)
  expect_identical(attr(again, "skipped"), c("main.calls", "main.customers"))
  DBI::dbAppendTable(con, "calls", data.frame(note = "PAN ABCPE1234F"))
  changed <- inventory_database(con, source = "sqlite:crm", path = path)
  expect_identical(attr(changed, "skipped"), "main.customers")
  expect_true(any(changed$table == "main.calls" & changed$type %in% "pan"))

  DBI::dbExecute(con, "CREATE VIEW broken AS SELECT missing FROM nowhere")
  DBI::dbExecute(con, "DROP TABLE calls")
  expect_warning(
    inv <- inventory_database(con, source = "sqlite:crm", views = TRUE, path = path),
    "main.broken not scanned"
  )
  expect_identical(names(attr(inv, "failed")), "main.broken")
  expect_output(suppressMessages(print(inv)), "Not scanned \\(1\\): main.broken")
  expect_false("main.calls" %in% read_inventory(path)$table)
  expect_error(inventory_database(con, source = "sqlite:crm", views = TRUE, on_error = "stop"))
})

test_that("DuckDB: sampled in the database", {
  skip_if_not_installed("duckdb")
  con <- DBI::dbConnect(duckdb::duckdb())
  withr::defer(DBI::dbDisconnect(con, shutdown = TRUE))
  DBI::dbExecute(con, "CREATE SCHEMA crm")
  DBI::dbExecute(con, "CREATE TABLE crm.calls AS SELECT 'PAN ABCPE1234F' AS note FROM range(200000)")
  inv <- inventory_database(con, source = "duckdb", sample = 1000L)
  rows <- inv[endsWith(inv$table, "crm.calls"), ]
  expect_identical(unique(rows$sample_method), "tablesample")
  expect_equal(unique(rows$n_rows), 200000)
  expect_identical(unique(rows$type), "pan")
  expect_true(all(rows$n_sampled > 0 & rows$n_sampled <= 1000))
})

test_that("Postgres: block sampling, row estimates, BIGINT kept whole", {
  skip_if_not_installed("RPostgres")
  skip_if(!nzchar(Sys.getenv("PGHOST")), "no Postgres server (PGHOST)")
  con <- DBI::dbConnect(RPostgres::Postgres())
  withr::defer(DBI::dbDisconnect(con))
  DBI::dbExecute(con, "DROP SCHEMA IF EXISTS cg_inv CASCADE")
  DBI::dbExecute(con, "CREATE SCHEMA cg_inv")
  withr::defer(DBI::dbExecute(con, "DROP SCHEMA IF EXISTS cg_inv CASCADE"), priority = "first")
  DBI::dbExecute(con, "CREATE TABLE cg_inv.cards (card_no BIGINT, note TEXT)")
  DBI::dbExecute(con, "INSERT INTO cg_inv.cards VALUES (4111111111111111, 'ok'), (5555555555554444, 'ok')")
  DBI::dbExecute(con, paste(
    "CREATE TABLE cg_inv.calls AS SELECT 'call ' || g || ': PAN ABCPE1234F, mobile 9876543210' AS note",
    "FROM generate_series(1, 200000) g"
  ))
  DBI::dbExecute(con, "ANALYZE cg_inv.calls")
  inv <- inventory_database(con, source = "postgres", schemas = "cg_inv", sample = 1000L)
  calls <- inv[inv$table == "cg_inv.calls", ]
  expect_identical(unique(calls$sample_method), "tablesample")
  expect_true(abs(unique(calls$n_rows) - 200000) < 20000) # planner estimate
  expect_setequal(calls$type, c("pan", "mobile_in"))
  expect_true(all(calls$n_sampled > 0 & calls$n_sampled <= 1000))
  cards <- inv[inv$table == "cg_inv.cards" & inv$column == "card_no", ]
  expect_identical(cards$type, "card")
  expect_identical(cards$n_full, 2L)
})
