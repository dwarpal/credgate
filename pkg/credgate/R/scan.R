#' Scan the columns of a data frame for PII
#'
#' Reports, per column, which PII types occur and in what share of values -
#' for example that `cust_id` looks like a PAN in 98% of rows. Useful on its
#' own, before any data is shared, to find which columns need protection.
#'
#' Each column is sampled (evenly spaced, so results are reproducible), and
#' every sampled value is checked with [detect_pii()] using the column name as
#' context: a column named `voter_id` supports Voter ID matches that would
#' otherwise need a keyword in the text. Whole numbers are checked too
#' (mobile and account numbers are often stored as numbers); other numbers,
#' logicals and dates are skipped. The rules are shared with the Python
#' package (see the spec's "Column scan" section).
#'
#' @param data A data frame, an Arrow `Table` or `Dataset` (for example from
#'   `arrow::open_dataset()`), or a database table from dbplyr
#'   (`dplyr::tbl(con, "calls")`, for DuckDB, Postgres and other DBI
#'   databases). Arrow and database tables are read one column at a time, in
#'   chunks, so they may be larger than memory; the sample is the same as for
#'   the table in memory. For a database, rows must come back in the same order
#'   on each read (DuckDB and SQLite do for a plain table).
#'   A Spark table from sparklyr is sampled inside the cluster (up to
#'   `sample` rows, randomly with `seed`) and only the sample is collected.
#' @param sample Maximum number of values checked per column.
#' @param min_rate Report a type only if it occurs in at least this share of
#'   sampled values (0 reports every type found).
#' @param detectors Detector ids to run; `NULL` runs all registered ones.
#' @param seed Random seed for sampling Spark tables; ignored otherwise.
#' @return A data frame of class `cg_scan` with one row per column and type:
#'   `column`, `type`, `class`, `n_sampled`, `n_matched` (values with a
#'   match), `n_full` (values that are entirely the identifier), `rate`
#'   (`n_matched / n_sampled`), `mean_confidence` and a masked `example`.
#' @export
#' @examples
#' customers <- data.frame(
#'   cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R"),
#'   notes = c("Called, Aadhaar 542229371182", "no issues", "mobile 9876543210")
#' )
#' scan_pii(customers)
scan_pii <- function(data, sample = 10000L, min_rate = 0, detectors = NULL, seed = 42L) {
  columns <- scan_table(data, sample, min_rate, detectors, seed)
  out <- do.call(rbind, c(list(empty_scan()), lapply(columns, `[[`, "findings")))
  rownames(out) <- NULL
  structure(out, class = c("cg_scan", "data.frame"), n_columns = length(columns))
}

# Every column of `data` with the types found in it (spec: "Column scan"):
# a list of list(name, n_sampled, sampled, findings), where `sampled` is TRUE
# when only a sample of the usable values was checked. Attributes `n_rows`
# and `sample_method` (NULL: per column) describe the table. Spark tables
# are sampled in the cluster first (spec: "Spark tables").
scan_table <- function(data, sample, min_rate, detectors, seed = 42L) {
  if (!rlang::is_scalar_integerish(sample) || sample < 1) {
    rlang::abort("`sample` must be a positive whole number.")
  }
  method <- NULL
  if (inherits(data, "tbl_spark")) {
    spark <- spark_sample(data, sample, seed)
    data <- spark$rows
    n_rows <- spark$n_rows
    method <- spark$method
  } else {
    n_rows <- table_rows(data)
  }
  columns <- scan_columns(data)
  out <- lapply(names(columns), function(col) {
    values <- sampled_values(columns[[col]], sample)
    rows <- list()
    if (length(values) > 0) {
      context <- gsub("[_.-]", " ", col)
      spans <- detect_pii(values, detectors = detectors, context = context)
      for (type in unique(spans$type)) {
        rows[[length(rows) + 1]] <- summarise_type(spans[spans$type == type, ], values, col)
      }
    }
    found <- do.call(rbind, c(list(empty_scan()), rows))
    found <- found[found$rate >= min_rate, , drop = FALSE]
    found <- found[order(-found$rate, found$type), , drop = FALSE]
    list(
      name = col, n_sampled = length(values),
      sampled = attr(values, "n_usable") > sample, findings = found
    )
  })
  structure(out, n_rows = n_rows, sample_method = method)
}

# Sample a sparklyr table inside the cluster; only the sample is collected.
spark_sample <- function(data, sample, seed) {
  check_installed("sparklyr")
  schema <- sparklyr::sdf_schema(data)
  types <- vapply(schema, function(f) f$type, "")
  names <- vapply(schema, function(f) f$name, "")
  skipped <- grepl("^(Array|Map|Struct|Binary)Type", types)
  whole <- grepl("^(Byte|Short|Integer|Long)Type$|^DecimalType\\([0-9]+, ?0\\)$", types)
  decimal <- grepl("^DecimalType", types) & !whole
  read <- names[!skipped]
  n <- sparklyr::sdf_nrow(data)
  method <- "all"
  rows <- NULL
  if (length(read) > 0) {
    x <- dplyr::select(data, dplyr::all_of(read))
    x <- dplyr::mutate(
      x,
      dplyr::across(dplyr::all_of(names[whole]), as.character),
      dplyr::across(dplyr::all_of(names[decimal]), as.double)
    )
    if (n > sample) {
      x <- sparklyr::sdf_sample(x, fraction = min(1, 1.2 * sample / n), replacement = FALSE, seed = seed)
      x <- utils::head(x, sample)
      method <- "spark-sample"
    }
    rows <- as.data.frame(dplyr::collect(x))
  }
  if (is.null(rows)) {
    rows <- data.frame(row.names = integer())
  }
  out <- lapply(stats::setNames(names, names), function(name) {
    if (name %in% read) rows[[name]] else rep(NA_character_, nrow(rows))
  })
  list(
    rows = as.data.frame(out, check.names = FALSE, optional = TRUE),
    n_rows = n, method = method
  )
}

# The number of rows, when known without reading the table.
table_rows <- function(data) {
  if (is.data.frame(data) && !inherits(data, "tbl_sql")) {
    return(nrow(data))
  }
  if (inherits(data, "ArrowObject") && inherits(data, c("Table", "RecordBatch"))) {
    return(data$num_rows)
  }
  NA_integer_
}

# Values of one column as trimmed, non-empty strings (see spec, step 1).
scan_values <- function(x) {
  if (is.factor(x)) {
    x <- as.character(x)
  } else if (is.numeric(x)) {
    whole <- !is.na(x) & is.finite(x) & x == floor(x)
    x <- format(x[whole], scientific = FALSE, trim = TRUE)
  } else if (!is.character(x)) {
    return(character())
  }
  x <- stringi::stri_trim_both(x[!is.na(x)])
  x[x != ""]
}

summarise_type <- function(spans, values, column) {
  first <- spans[!duplicated(spans$doc), , drop = FALSE]
  full <- spans$start == 1L & spans$end == nchar(values[spans$doc])
  n_sampled <- length(values)
  data.frame(
    column = column,
    type = first$type[1],
    class = first$class[1],
    n_sampled = n_sampled,
    n_matched = nrow(first),
    n_full = length(unique(spans$doc[full])),
    rate = round(nrow(first) / n_sampled, 4),
    mean_confidence = round(mean(first$confidence), 2),
    example = mask_value(first$value[1], first$class[1])
  )
}

empty_scan <- function() {
  data.frame(
    column = character(), type = character(), class = character(),
    n_sampled = integer(), n_matched = integer(), n_full = integer(),
    rate = numeric(), mean_confidence = numeric(), example = character()
  )
}

#' @export
print.cg_scan <- function(x, ...) {
  n_columns <- attr(x, "n_columns")
  needed <- c("column", "type", "rate", "n_matched", "n_sampled", "n_full", "mean_confidence", "example")
  if (is.null(n_columns) || !all(needed %in% names(x))) {
    # A subset such as report[1:2, 1:3]: print it as a plain data frame.
    print(as.data.frame(unclass(x)), ...)
    return(invisible(x))
  }
  found <- unique(x$column)
  if (nrow(x) == 0) {
    cli::cli_text("Scanned {n_columns} column{?s}: no PII found.")
    return(invisible(x))
  }
  cli::cli_text(
    "Scanned {n_columns} column{?s}; PII found in {length(found)}: {.field {found}}"
  )
  shown <- data.frame(
    column = x$column,
    type = x$type,
    rate = sprintf("%.0f%%", 100 * x$rate),
    matched = paste(x$n_matched, "of", x$n_sampled),
    whole = x$n_full,
    confidence = x$mean_confidence,
    example = x$example
  )
  print(shown, row.names = FALSE)
  invisible(x)
}
