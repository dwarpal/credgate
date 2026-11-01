notes <- c("PAN ABCPE1234F", NA, "Name: Priya Nair", "nothing here")
redacted <- c("PAN [PAN]", NA, "Name: [PERSON_NAME]", "nothing here")

scan_key <- function(x) {
  x <- as.data.frame(unclass(x))
  rownames(x) <- NULL
  x
}

table_columns <- function() {
  recs <- synth_indian_pii(1200, seed = 5)
  i <- seq_len(1200)
  data.frame(
    cust_pan = recs$pan,
    mobile = ifelse(i %% 7 == 1, NA, as.numeric(recs$mobile)),
    notes = ifelse(i %% 4 == 1, paste0("Shri ", recs$name, ", PAN ", recs$pan),
      paste("Customer", recs$name, "called")
    ),
    amount = i + 0.5,
    stringsAsFactors = FALSE
  )
}

test_that("chunked sampling equals sampling in memory", {
  df <- table_columns()
  for (sample in c(7L, 500L, 5000L)) {
    for (size in c(1L, 99L, 250L, 1200L)) {
      for (col in names(df)) {
        x <- df[[col]]
        starts <- seq(1L, length(x), by = size)
        chunks <- function(f) for (s in starts) f(x[s:min(length(x), s + size - 1L)])
        single <- structure(function(f) f(x), single = TRUE)
        expect_identical(sampled_values(chunks, sample), sampled_values(single, sample),
          info = paste(col, sample, size)
        )
      }
    }
  }
})

test_that("scan_pii rejects unsupported input", {
  expect_error(scan_pii(list(a = 1)), "data frame, an Arrow")
})

# --- databases (DBI, dbplyr) ------------------------------------------------

for (driver in c("RSQLite", "duckdb", "RPostgres")) {
  test_that(paste("database tables:", driver), {
    skip_if_not_installed(driver)
    skip_if_not_installed("DBI")
    skip_if_not_installed("dbplyr")
    skip_if_not_installed("dplyr")
    if (driver == "duckdb") {
      con <- DBI::dbConnect(duckdb::duckdb())
      writer <- con
      withr::defer(DBI::dbDisconnect(con, shutdown = TRUE))
    } else if (driver == "RPostgres") {
      # A server named by the standard PG* environment variables (the Nix
      # integration build starts one; see flake.nix).
      skip_if(!nzchar(Sys.getenv("PGHOST")), "no Postgres server (set PGHOST)")
      con <- DBI::dbConnect(RPostgres::Postgres())
      writer <- DBI::dbConnect(RPostgres::Postgres())
      for (table in c("t", "calls", "calls_safe", "empty_safe", "big", "one_con")) {
        DBI::dbExecute(con, paste("DROP TABLE IF EXISTS", table))
      }
      withr::defer({
        DBI::dbDisconnect(writer)
        DBI::dbDisconnect(con)
      })
    } else {
      # SQLite cannot write while a result is open on the same connection.
      file <- withr::local_tempfile(fileext = ".sqlite")
      con <- DBI::dbConnect(RSQLite::SQLite(), file)
      DBI::dbExecute(con, "PRAGMA journal_mode = WAL") # a reader and a writer at once
      writer <- DBI::dbConnect(RSQLite::SQLite(), file)
      withr::defer({
        DBI::dbDisconnect(writer)
        DBI::dbDisconnect(con)
      })
    }

    df <- table_columns()
    DBI::dbWriteTable(con, "t", df)
    expect_identical(
      scan_key(scan_pii(dplyr::tbl(con, "t"), sample = 500)),
      scan_key(scan_pii(df, sample = 500))
    )
    filtered <- dplyr::filter(dplyr::tbl(con, "t"), amount < 600)
    expect_identical(
      scan_key(scan_pii(filtered, sample = 100)),
      scan_key(scan_pii(df[df$amount < 600, ], sample = 100))
    )

    DBI::dbWriteTable(con, "calls", data.frame(id = 1:4, notes = notes, pan = "ABCPE1234F"))
    n <- redact_query(con, "SELECT * FROM calls ORDER BY id", "calls_safe",
      columns = "notes", chunk_size = 3, to_con = writer
    )
    expect_equal(n, 4)
    out <- DBI::dbGetQuery(con, "SELECT * FROM calls_safe ORDER BY id")
    expect_identical(out$notes, redacted)
    expect_identical(out$pan, rep("ABCPE1234F", 4))
    expect_error(
      redact_query(con, "SELECT * FROM calls", "calls_safe", to_con = writer),
      "append = TRUE"
    )
    # All text columns by default; appended after the first four rows.
    redact_query(con, "SELECT * FROM calls ORDER BY id", "calls_safe",
      append = TRUE, to_con = writer
    )
    all <- DBI::dbGetQuery(con, "SELECT pan FROM calls_safe")$pan
    expect_equal(length(all), 8)
    expect_identical(sort(all), c(rep("ABCPE1234F", 4), rep("[PAN]", 4)))
    redact_query(con, "SELECT * FROM calls WHERE id > 99", "empty_safe", to_con = writer)
    expect_true(DBI::dbExistsTable(con, "empty_safe"))

    # One connection, as most people call it.
    DBI::dbExecute(con, "DROP TABLE IF EXISTS one_con")
    big <- data.frame(id = 1:2500, notes = rep(notes, length.out = 2500))
    DBI::dbWriteTable(con, "big", big, overwrite = TRUE)
    expect_equal(redact_query(con, "SELECT * FROM big ORDER BY id", "one_con", chunk_size = 1000), 2500)
    got <- DBI::dbGetQuery(con, "SELECT * FROM one_con ORDER BY id")
    expect_identical(got$notes, rep(redacted, length.out = 2500))
  })
}

# --- Arrow ------------------------------------------------------------------

test_that("Arrow arrays, Parquet files and tables", {
  skip_if_not_installed("arrow")
  arr <- arrow::Array$create(notes)
  out <- redact(arr)
  expect_true(inherits(out, "Array"))
  expect_identical(as.vector(out), redacted)
  expect_identical(as.vector(redact(arrow::chunked_array(notes[1:2], notes[3:4]))), redacted)
  expect_equal(detect_pii(arr)$doc, c(1L, 3L))
  expect_identical(as.vector(tokenise(arr, cg_vault()))[1], "PAN [PAN_1]")

  src <- withr::local_tempfile(fileext = ".parquet")
  dst <- withr::local_tempfile(fileext = ".parquet")
  arrow::write_parquet(data.frame(id = 1:4, notes = notes, pan = "ABCPE1234F"), src)
  expect_equal(redact_parquet(src, dst, columns = "notes", batch_size = 1L), 4)
  back <- arrow::read_parquet(dst)
  expect_identical(back$notes, redacted)
  expect_identical(back$pan, rep("ABCPE1234F", 4))
  # Schemas are external pointers: compare them with Arrow's own Equals().
  expect_true(arrow::read_parquet(dst, as_data_frame = FALSE)$schema$Equals(arrow::open_dataset(src)$schema))
  redact_parquet(src, dst)
  expect_identical(arrow::read_parquet(dst)$pan, rep("[PAN]", 4))
  expect_error(redact_parquet(src, src), "must differ")
  expect_error(redact_parquet(src, dst, columns = "nope"), "Unknown column")

  df <- table_columns()
  ref <- scan_key(scan_pii(df, sample = 500))
  table <- arrow::as_arrow_table(df)
  expect_identical(scan_key(scan_pii(table, sample = 500)), ref)
  file <- withr::local_tempfile(fileext = ".parquet")
  arrow::write_parquet(df, file, chunk_size = 100)
  expect_identical(scan_key(scan_pii(arrow::open_dataset(file), sample = 500)), ref)
})
