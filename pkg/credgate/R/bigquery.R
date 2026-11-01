#' Scan and inventory BigQuery tables
#'
#' BigQuery samples the table and only the sample is downloaded; only the
#' columns credgate can scan are read, and a dry run checks the cost of
#' every query first. credgate makes no network calls of its own: it uses
#' bigrquery, with your credentials (`bigrquery::bq_auth()`). The rules are
#' shared with the Python package (`credgate.bigquery`; see the spec's
#' "BigQuery tables").
#'
#' @param table A table: `"project.dataset.table"` or a
#'   `bigrquery::bq_table()`.
#' @param dataset A dataset: `"project.dataset"` or a
#'   `bigrquery::bq_dataset()`. Every table and view in it is scanned.
#' @param source Source name for the inventory; defaults to
#'   `"bigquery:<project>"`. The table is recorded as `"dataset.table"`.
#' @param billing Project billed for the queries; defaults to the table's
#'   project.
#' @param sample Maximum number of rows sampled.
#' @param min_rate,detectors As for [scan_pii()].
#' @param sampling `"tablesample"` (BigQuery's block sampling; only the
#'   sampled blocks are billed) or `"rand"` (reads and bills whole columns).
#'   Views and external tables always use `"rand"`.
#' @param max_bytes Refuse any query estimated to process more bytes than
#'   this (default 1 GB). Also sent to BigQuery as the billing limit, except
#'   with TABLESAMPLE, where BigQuery would check it against the whole table.
#' @return `bq_scan_pii()` a scan report as from [scan_pii()];
#'   `bq_pii_inventory()` and `bq_inventory_dataset()` an inventory as from
#'   [pii_inventory()], with the table's row count and `sample_method`
#'   `"all"`, `"bigquery-tablesample"` or `"bigquery-rand"`.
#' @export
#' @examples
#' \dontrun{
#' bigrquery::bq_auth()
#' bq_scan_pii("my-project.crm.customers")
#' inv <- bq_inventory_dataset("my-project.crm")
#' write_inventory(inv, "inventory.csv")
#' }
bq_scan_pii <- function(table, billing = NULL, sample = 10000L, min_rate = 0, detectors = NULL,
                        sampling = "tablesample", max_bytes = 1e9) {
  rows <- bq_sample(table, billing, sample, sampling, max_bytes)
  scan_pii(rows, sample = sample, min_rate = min_rate, detectors = detectors)
}

#' @rdname bq_scan_pii
#' @export
bq_pii_inventory <- function(table, source = NULL, billing = NULL, sample = 10000L, min_rate = 0,
                             detectors = NULL, sampling = "tablesample", max_bytes = 1e9) {
  rows <- bq_sample(table, billing, sample, sampling, max_bytes)
  ref <- attr(rows, "table")
  pii_inventory(
    rows,
    source = source %||% paste0("bigquery:", ref$project),
    table = paste0(ref$dataset, ".", ref$table),
    sample = sample, min_rate = min_rate, detectors = detectors
  )
}

#' @rdname bq_scan_pii
#' @export
bq_inventory_dataset <- function(dataset, source = NULL, billing = NULL, sample = 10000L,
                                 min_rate = 0, detectors = NULL, sampling = "tablesample",
                                 max_bytes = 1e9) {
  invs <- lapply(bq_list_tables(dataset), function(table) {
    bq_pii_inventory(
      table,
      source = source, billing = billing, sample = sample, min_rate = min_rate,
      detectors = detectors, sampling = sampling, max_bytes = max_bytes
    )
  })
  new_inventory(do.call(rbind, c(list(empty_inventory()), invs)))
}

# The query that samples a table, the columns it reads and the sample
# method (spec: "BigQuery tables"). `fields` has columns name, type, mode.
bq_sample_query <- function(table, kind, n, fields, sample = 10000L, sampling = "tablesample") {
  if (!sampling %in% c("tablesample", "rand")) {
    rlang::abort('`sampling` must be "tablesample" or "rand".')
  }
  exprs <- character()
  read <- character()
  for (i in seq_len(nrow(fields))) {
    name <- fields$name[i]
    type <- fields$type[i]
    if (identical(fields$mode[i], "REPEATED")) {
      next
    }
    col <- bq_ident(name)
    expr <- if (type %in% c("STRING", "FLOAT64", "FLOAT")) {
      col
    } else if (type %in% c("INT64", "INTEGER")) {
      paste0("CAST(", col, " AS STRING) AS ", col)
    } else if (type %in% c("NUMERIC", "BIGNUMERIC")) {
      paste0("IF(", col, " = TRUNC(", col, "), CAST(", col, " AS STRING), NULL) AS ", col)
    }
    if (!is.null(expr)) {
      exprs <- c(exprs, expr)
      read <- c(read, name)
    }
  }
  if (length(read) == 0) {
    return(list(sql = NULL, read = character(), method = "all"))
  }
  sql <- paste0("SELECT ", paste(exprs, collapse = ", "), " FROM ", bq_ident(table))
  if (n <= sample) {
    return(list(sql = sql, read = read, method = "all"))
  }
  f <- max(0.000001, min(1, 1.2 * sample / n))
  if (sampling == "tablesample" && kind == "TABLE") {
    list(
      sql = paste0(sql, " TABLESAMPLE SYSTEM (", bq_num(100 * f), " PERCENT) LIMIT ", sample),
      read = read, method = "bigquery-tablesample"
    )
  } else {
    list(
      sql = paste0(sql, " WHERE RAND() < ", bq_num(f), " LIMIT ", sample),
      read = read, method = "bigquery-rand"
    )
  }
}

bq_sample <- function(table, billing, sample, sampling, max_bytes) {
  if (!rlang::is_scalar_integerish(sample) || sample < 1) {
    rlang::abort("`sample` must be a positive whole number.")
  }
  info <- bq_table_info(table)
  full <- paste(info$project, info$dataset, info$table, sep = ".")
  billing <- billing %||% info$project
  n <- info$n
  if (is.na(n)) {
    n <- as.numeric(bq_run(paste0("SELECT COUNT(*) FROM ", bq_ident(full)), billing, max_bytes)[[1]][1])
  }
  query <- bq_sample_query(full, info$kind, n, info$fields, sample, sampling)
  rows <- if (is.null(query$sql)) {
    data.frame(row.names = integer())
  } else {
    # BigQuery checks maximumBytesBilled against the whole table for
    # TABLESAMPLE; the dry run's estimate is the accurate one there.
    enforce <- query$method != "bigquery-tablesample"
    stats::setNames(as.data.frame(bq_run(query$sql, billing, max_bytes, enforce)), query$read)
  }
  structure(
    sampled_rows(rows, info$fields$name, n, query$method),
    table = info[c("project", "dataset", "table")]
  )
}

# Runs a query after a dry run shows it stays within `max_bytes`; with
# `enforce`, BigQuery also enforces the limit (maximumBytesBilled).
bq_run <- function(sql, billing, max_bytes, enforce = TRUE) {
  estimate <- bq_dry_run(sql, billing)
  if (estimate > max_bytes) {
    rlang::abort(
      c(
        sprintf(
          "This query would process about %s bytes, more than `max_bytes` = %s; nothing was run.",
          format(estimate, big.mark = ",", scientific = FALSE),
          format(max_bytes, big.mark = ",", scientific = FALSE)
        ),
        i = "Raise `max_bytes`, or use a smaller sample (with `sampling = \"tablesample\"` only sampled blocks are billed).",
        i = sql
      ),
      class = "credgate_cost_limit"
    )
  }
  bq_fetch(sql, billing, if (enforce) max_bytes)
}

# --- the only calls to BigQuery (through bigrquery) --------------------------

bq_table_info <- function(table) {
  check_installed("bigrquery")
  table <- bigrquery::as_bq_table(table)
  meta <- bigrquery::bq_table_meta(table, fields = "numRows,schema,type")
  fields <- meta$schema$fields
  list(
    project = table$project, dataset = table$dataset, table = table$table,
    kind = meta$type %||% "TABLE",
    n = if (is.null(meta$numRows)) NA_real_ else as.numeric(meta$numRows),
    fields = data.frame(
      name = vapply(fields, function(f) f$name, ""),
      type = vapply(fields, function(f) f$type, ""),
      mode = vapply(fields, function(f) f$mode %||% "NULLABLE", "")
    )
  )
}

bq_dry_run <- function(sql, billing) {
  as.numeric(bigrquery::bq_perform_query_dry_run(sql, billing = billing))
}

bq_fetch <- function(sql, billing, max_bytes) {
  limit <- if (!is.null(max_bytes)) {
    list(configuration = list(query = list(
      maximumBytesBilled = jsonlite::unbox(format(max_bytes, scientific = FALSE))
    )))
  }
  job <- do.call(bigrquery::bq_project_query, c(list(billing, sql), limit, list(quiet = TRUE)))
  bigrquery::bq_table_download(job, quiet = TRUE)
}

bq_list_tables <- function(dataset) {
  check_installed("bigrquery")
  bigrquery::bq_dataset_tables(bigrquery::as_bq_dataset(dataset))
}

bq_ident <- function(name) {
  paste0("`", gsub("`", "\\`", gsub("\\", "\\\\", name, fixed = TRUE), fixed = TRUE), "`")
}

bq_num <- function(x) sub("\\.?0+$", "", sprintf("%.6f", x))
