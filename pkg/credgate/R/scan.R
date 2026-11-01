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
#' @param data A data frame.
#' @param sample Maximum number of values checked per column.
#' @param min_rate Report a type only if it occurs in at least this share of
#'   sampled values (0 reports every type found).
#' @param detectors Detector ids to run; `NULL` runs all registered ones.
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
scan_pii <- function(data, sample = 10000L, min_rate = 0, detectors = NULL) {
  if (!is.data.frame(data)) {
    rlang::abort("`data` must be a data frame.")
  }
  if (!rlang::is_scalar_integerish(sample) || sample < 1) {
    rlang::abort("`sample` must be a positive whole number.")
  }
  rows <- list()
  for (col in names(data)) {
    values <- scan_values(data[[col]])
    n <- length(values)
    if (n == 0) {
      next
    }
    if (n > sample) {
      values <- values[floor((seq_len(sample) - 1) * n / sample) + 1]
    }
    context <- gsub("[_.-]", " ", col)
    spans <- detect_pii(values, detectors = detectors, context = context)
    for (type in unique(spans$type)) {
      rows[[length(rows) + 1]] <- summarise_type(spans[spans$type == type, ], values, col)
    }
  }

  out <- do.call(rbind, c(list(empty_scan()), rows))
  out <- out[out$rate >= min_rate, , drop = FALSE]
  out <- out[order(match(out$column, names(data)), -out$rate, out$type), , drop = FALSE]
  rownames(out) <- NULL
  structure(out, class = c("cg_scan", "data.frame"), n_columns = ncol(data))
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
