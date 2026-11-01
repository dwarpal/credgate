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

for (driver in c("RSQLite", "duckdb")) {
  test_that(paste("database tables:", driver), {
    skip_if_not_installed(driver)
    skip_if_not_installed("DBI")
    skip_if_not_installed("dbplyr")
    skip_if_not_installed("dplyr")
    con <- if (driver == "duckdb") {
      DBI::dbConnect(duckdb::duckdb())
    } else {
      DBI::dbConnect(RSQLite::SQLite(), ":memory:")
    }
    withr::defer(DBI::dbDisconnect(con))

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
      columns = "notes", chunk_size = 3
    )
    expect_equal(n, 4)
    out <- DBI::dbGetQuery(con, "SELECT * FROM calls_safe ORDER BY id")
    expect_identical(out$notes, redacted)
    expect_identical(out$pan, rep("ABCPE1234F", 4))
    expect_error(redact_query(con, "SELECT * FROM calls", "calls_safe"), "append = TRUE")
    redact_query(con, "SELECT * FROM calls", "calls_safe", append = TRUE)
    expect_equal(DBI::dbGetQuery(con, "SELECT count(*) AS n FROM calls_safe")$n, 8)
    expect_identical(
      DBI::dbGetQuery(con, "SELECT pan FROM calls_safe LIMIT 1")$pan,
      "[PAN]"
    )
    redact_query(con, "SELECT * FROM calls WHERE id > 99", "empty_safe")
    expect_true(DBI::dbExistsTable(con, "empty_safe"))
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
  expect_identical(arrow::read_parquet(dst, as_data_frame = FALSE)$schema, arrow::open_dataset(src)$schema)
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
