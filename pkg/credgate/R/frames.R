# Arrow, Parquet and database tables. None of these packages is required:
# each is used only when its kind of object is passed in.

# Text from an Arrow array, and a function that wraps results back into one
# of the same string type. Other inputs pass through unchanged.
from_arrow <- function(x) {
  if (!inherits(x, "ArrowObject") || !inherits(x, c("Array", "ChunkedArray"))) {
    return(list(text = x, wrap = identity))
  }
  type <- x$type
  stringlike <- type$ToString() %in% c("string", "large_string", "utf8", "large_utf8")
  list(
    text = as.character(as.vector(x)),
    wrap = function(out) arrow::Array$create(out, type = if (stringlike) type else arrow::utf8())
  )
}

#' Redact a Parquet file, batch by batch
#'
#' Writes a copy of a Parquet file with identifiers in the chosen text
#' columns replaced by placeholders such as `[PAN]`. The file is read in
#' record batches, so it may be larger than memory; other columns and the
#' schema are kept.
#'
#' @param source,destination Parquet files to read and write; they must differ.
#' @param columns Columns to redact; `NULL` redacts every string column.
#' @param batch_size Rows per batch.
#' @param ... Passed to [redact()]: `detectors`, `min_confidence`.
#' @return The number of rows written, invisibly.
#' @seealso [redact_query()] for database tables, including DuckDB.
#' @export
#' @examplesIf requireNamespace("arrow", quietly = TRUE)
#' src <- tempfile(fileext = ".parquet")
#' dst <- tempfile(fileext = ".parquet")
#' arrow::write_parquet(data.frame(id = 1:2, notes = c("PAN ABCPE1234F", "no PII")), src)
#' redact_parquet(src, dst)
#' arrow::read_parquet(dst)
redact_parquet <- function(source, destination, columns = NULL, batch_size = 10000L, ...) {
  check_installed("arrow")
  stopifnot(rlang::is_string(source), rlang::is_string(destination))
  if (normalizePath(source, mustWork = TRUE) == normalizePath(destination, mustWork = FALSE)) {
    rlang::abort("`destination` must differ from `source`.")
  }
  dataset <- arrow::open_dataset(source, format = "parquet")
  schema <- dataset$schema
  columns <- arrow_text_columns(schema, columns)
  reader <- arrow::Scanner$create(dataset, batch_size = batch_size)$ToRecordBatchReader()
  sink <- arrow::FileOutputStream$create(destination)
  on.exit(sink$close(), add = TRUE)
  writer <- arrow::ParquetFileWriter$create(
    schema, sink,
    properties = arrow::ParquetWriterProperties$create(names(schema))
  )
  rows <- 0
  while (!is.null(batch <- reader$read_next_batch())) {
    table <- arrow::as_arrow_table(batch)
    for (col in columns) {
      table[[col]] <- redact(table[[col]], ...)
    }
    writer$WriteTable(table, chunk_size = batch_size)
    rows <- rows + batch$num_rows
  }
  writer$Close()
  invisible(rows)
}

arrow_text_columns <- function(schema, columns) {
  if (is.null(columns)) {
    types <- vapply(schema$fields, function(f) f$type$ToString(), character(1))
    return(schema$names[types %in% c("string", "large_string", "utf8", "large_utf8")])
  }
  unknown <- setdiff(columns, schema$names)
  if (length(unknown) > 0) {
    rlang::abort(paste0("Unknown column(s): ", paste(unknown, collapse = ", ")))
  }
  columns
}

#' Redact the result of a database query into a table
#'
#' Runs `query` on a DBI connection, fetches the result `chunk_size` rows at
#' a time, redacts the chosen text columns and appends each chunk to the
#' table `to`. The result may be larger than memory. Works with any DBI
#' database; with DuckDB, `query` can read files directly
#' (`"SELECT * FROM 'calls.parquet'"`), and `COPY to TO 'out.parquet'`
#' writes the redacted table back out.
#'
#' @param con A DBI connection.
#' @param query SQL query whose result is redacted.
#' @param to Name of the table to create (or, with `append = TRUE`, add to).
#' @param columns Columns to redact; `NULL` redacts every text column.
#' @param chunk_size Rows fetched at a time.
#' @param append Append to an existing table `to` instead of creating it.
#' @param to_con Connection to write `to` with; by default `con`, which works
#'   with DuckDB. SQLite cannot write while a query result is open: pass a
#'   second connection to the same database file, opened in WAL mode
#'   (`PRAGMA journal_mode = WAL`), or a connection to another database.
#' @param ... Passed to [redact()]: `detectors`, `min_confidence`.
#' @return The number of rows written, invisibly.
#' @export
#' @examplesIf requireNamespace("duckdb", quietly = TRUE)
#' con <- DBI::dbConnect(duckdb::duckdb())
#' DBI::dbWriteTable(con, "calls", data.frame(id = 1:2, notes = c("PAN ABCPE1234F", "no PII")))
#' redact_query(con, "SELECT * FROM calls", "calls_redacted")
#' DBI::dbReadTable(con, "calls_redacted")
#' DBI::dbDisconnect(con, shutdown = TRUE)
redact_query <- function(con, query, to, columns = NULL, chunk_size = 10000L,
                         append = FALSE, to_con = con, ...) {
  check_installed("DBI")
  stopifnot(rlang::is_string(query), rlang::is_string(to))
  if (!append && DBI::dbExistsTable(to_con, to)) {
    rlang::abort(paste0("Table `", to, "` exists; use `append = TRUE` to add to it."))
  }
  res <- DBI::dbSendQuery(con, query)
  on.exit(DBI::dbClearResult(res), add = TRUE)
  rows <- 0
  first <- TRUE
  repeat {
    chunk <- DBI::dbFetch(res, n = chunk_size)
    if (first) {
      text <- names(chunk)[vapply(chunk, is.character, logical(1))]
      columns <- columns %||% text
      unknown <- setdiff(columns, names(chunk))
      if (length(unknown) > 0) {
        rlang::abort(paste0("Unknown column(s): ", paste(unknown, collapse = ", ")))
      }
    }
    if (nrow(chunk) == 0 && !first) {
      break
    }
    for (col in columns) {
      chunk[[col]] <- redact(as.character(chunk[[col]]), ...)
    }
    if (first && !append) {
      DBI::dbCreateTable(to_con, to, chunk)
    }
    if (nrow(chunk) > 0) {
      DBI::dbAppendTable(to_con, to, chunk)
    }
    rows <- rows + nrow(chunk)
    first <- FALSE
    if (DBI::dbHasCompleted(res)) {
      break
    }
  }
  invisible(rows)
}

# Columns of a table as functions that call `f` on each chunk of values, so
# tables larger than memory are read one column and one chunk at a time.
# Each function can be called again for a second pass.
scan_columns <- function(data) {
  if (is.data.frame(data) && !inherits(data, "tbl_sql")) {
    return(lapply(stats::setNames(names(data), names(data)), function(col) {
      structure(function(f) f(data[[col]]), single = TRUE)
    }))
  }
  if (inherits(data, "ArrowObject") && inherits(data, c("Table", "RecordBatch"))) {
    return(lapply(stats::setNames(names(data), names(data)), function(col) {
      function(f) {
        values <- data[[col]]
        chunks <- if (inherits(values, "ChunkedArray")) values$chunks else list(values)
        for (chunk in chunks) f(as.vector(chunk))
      }
    }))
  }
  if (inherits(data, "ArrowObject") && inherits(data, "Dataset")) {
    return(lapply(stats::setNames(names(data), names(data)), function(col) {
      function(f) {
        reader <- arrow::Scanner$create(data, projection = col, batch_size = 100000L)$ToRecordBatchReader()
        while (!is.null(batch <- reader$read_next_batch())) f(as.vector(batch[[col]]))
      }
    }))
  }
  if (inherits(data, "tbl_sql")) {
    check_installed("dbplyr")
    con <- dbplyr::remote_con(data)
    sql <- dbplyr::sql_render(data)
    cols <- colnames(data)
    return(lapply(stats::setNames(cols, cols), function(col) {
      query <- paste0(
        "SELECT ", DBI::dbQuoteIdentifier(con, col), " FROM (", sql, ") AS credgate_scan"
      )
      function(f) {
        res <- DBI::dbSendQuery(con, query)
        on.exit(DBI::dbClearResult(res))
        repeat {
          chunk <- DBI::dbFetch(res, n = 100000L)
          if (nrow(chunk) > 0) f(chunk[[1]])
          if (DBI::dbHasCompleted(res) || nrow(chunk) == 0) break
        }
      }
    }))
  }
  rlang::abort(paste(
    "`data` must be a data frame, an Arrow Table or Dataset,",
    "or a database table from dbplyr (e.g. `dplyr::tbl(con, \"calls\")`)."
  ))
}

# The column's usable values, sampled as the spec says: with n > sample
# values, those at 0-based positions floor(i * n / sample).
sampled_values <- function(chunks, sample) {
  if (isTRUE(attr(chunks, "single"))) {
    values <- NULL
    chunks(function(x) values <<- scan_values(x))
    n <- length(values)
    return(if (n > sample) values[floor((seq_len(sample) - 1) * n / sample) + 1] else values)
  }
  n <- 0
  chunks(function(x) n <<- n + length(scan_values(x)))
  if (n == 0) {
    return(character())
  }
  wanted <- if (n > sample) floor((seq_len(sample) - 1) * n / sample) + 1 else seq_len(n)
  out <- character(length(wanted))
  seen <- 0
  chunks(function(x) {
    values <- scan_values(x)
    here <- wanted > seen & wanted <= seen + length(values)
    out[here] <<- values[wanted[here] - seen]
    seen <<- seen + length(values)
  })
  out
}

check_installed <- function(pkg) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    rlang::abort(paste0("This needs the ", pkg, " package: install.packages(\"", pkg, "\")"))
  }
}
