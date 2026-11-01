inventory_fields <- c(
  "v", "source", "table", "column", "type", "class", "n_rows", "n_sampled",
  "n_matched", "n_full", "rate", "mean_confidence", "sample_method",
  "scanned_at", "credgate"
)
inventory_ints <- c("v", "n_rows", "n_sampled", "n_matched", "n_full")
inventory_optional <- c("type", "class", "n_rows", "mean_confidence")

#' Record where PII is, for an inventory
#'
#' Scans a table with the same rules as [scan_pii()], but records every
#' column - including those where nothing was found - with the source and
#' table names, the sample size and method, and when and by what it was
#' scanned. No values are recorded, not even masked ones. Combine the
#' inventories of several tables with `rbind()` and save them with
#' [write_inventory()]; the file format is shared with the Python package
#' (see the spec's "Inventory" section).
#'
#' @inheritParams scan_pii
#' @param source Name of the data source, chosen by you (e.g.
#'   `"bigquery:prod"`, `"hive"`).
#' @param table Name of the table within the source (e.g. `"crm.customers"`,
#'   or a file path).
#' @return A data frame of class `cg_inventory` with one row per column and
#'   PII type found, and one row with `type = NA` for each column where none
#'   was found: `v`, `source`, `table`, `column`, `type`, `class`, `n_rows`
#'   (when known without reading the table), `n_sampled`, `n_matched`,
#'   `n_full`, `rate`, `mean_confidence`, `sample_method` (`"all"` or
#'   `"even"`, or `"spark-sample"` for Spark tables), `scanned_at` (UTC) and
#'   `credgate` (the version that scanned).
#' @export
#' @examples
#' customers <- data.frame(
#'   cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R"),
#'   notes = c("Called, Aadhaar 542229371182", "no issues", "mobile 9876543210"),
#'   balance = c(1520.5, 99.75, 0.25)
#' )
#' inv <- pii_inventory(customers, source = "crm", table = "customers")
#' inv
#' path <- tempfile(fileext = ".csv")
#' write_inventory(inv, path)
#' read_inventory(path)
pii_inventory <- function(data, source, table, sample = 10000L, min_rate = 0,
                          detectors = NULL, seed = 42L) {
  for (arg in c("source", "table")) {
    value <- get(arg)
    if (!rlang::is_string(value) || !nzchar(value)) {
      rlang::abort(paste0("`", arg, "` must be a non-empty string."))
    }
  }
  scanned_at <- format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
  columns <- scan_table(data, sample, min_rate, detectors, seed)
  n_rows <- as.integer(attr(columns, "n_rows"))
  method <- attr(columns, "sample_method")
  rows <- lapply(columns, function(col) {
    found <- col$findings
    if (nrow(found) == 0) {
      found <- data.frame(
        column = col$name, type = NA_character_, class = NA_character_,
        n_sampled = col$n_sampled, n_matched = 0L, n_full = 0L, rate = 0,
        mean_confidence = NA_real_
      )
    }
    data.frame(
      v = 1L, source = source, table = table, column = found$column,
      type = found$type, class = found$class, n_rows = n_rows,
      n_sampled = as.integer(found$n_sampled), n_matched = as.integer(found$n_matched),
      n_full = as.integer(found$n_full), rate = found$rate,
      mean_confidence = found$mean_confidence,
      sample_method = method %||% if (col$sampled) "even" else "all",
      scanned_at = scanned_at,
      credgate = paste0("r/", utils::packageVersion("credgate"))
    )
  })
  new_inventory(do.call(rbind, c(list(empty_inventory()), rows)))
}

#' Write and read inventory files
#'
#' `write_inventory()` saves an inventory from [pii_inventory()] as a CSV
#' file, written exactly as the spec describes, so that R and Python write
#' identical files for the same inventory. `read_inventory()` reads a file
#' written by either and checks its format.
#'
#' @param x An inventory from [pii_inventory()] (or several combined with
#'   `rbind()`).
#' @param path File path.
#' @return `write_inventory()` returns `path` invisibly; `read_inventory()`
#'   an inventory.
#' @export
write_inventory <- function(x, path) {
  if (!all(inventory_fields %in% names(x))) {
    rlang::abort("`x` must be an inventory from `pii_inventory()`.")
  }
  cells <- lapply(inventory_fields, function(field) inventory_format(field, x[[field]]))
  lines <- c(
    paste(inventory_fields, collapse = ","),
    if (nrow(x) > 0) do.call(paste, c(cells, sep = ","))
  )
  writeBin(charToRaw(enc2utf8(paste0(paste(lines, collapse = "\n"), "\n"))), path)
  invisible(path)
}

#' @rdname write_inventory
#' @export
read_inventory <- function(path) {
  raw <- utils::read.csv(
    path,
    colClasses = "character", na.strings = character(), check.names = FALSE,
    encoding = "UTF-8", strip.white = FALSE
  )
  if (!identical(names(raw), inventory_fields)) {
    rlang::abort(paste0(path, " is not a credgate inventory: unexpected header."))
  }
  out <- lapply(stats::setNames(inventory_fields, inventory_fields), function(field) {
    text <- raw[[field]]
    empty <- text == ""
    if (any(empty) && !field %in% inventory_optional) {
      rlang::abort(paste0(path, ": `", field, "` is empty on line ", which(empty)[1] + 1, "."))
    }
    text[empty] <- NA
    if (field %in% c(inventory_ints, "rate", "mean_confidence")) {
      value <- suppressWarnings(as.numeric(text))
      bad <- !is.na(text) & is.na(value)
      if (any(bad)) {
        rlang::abort(paste0(path, ": bad value for `", field, "` on line ", which(bad)[1] + 1, "."))
      }
      text <- if (field %in% inventory_ints) as.integer(value) else value
    }
    text
  })
  if (any(out$v != 1L)) {
    rlang::abort(paste0(path, ": unsupported inventory version."))
  }
  new_inventory(as.data.frame(out, check.names = FALSE))
}

inventory_format <- function(field, x) {
  if (field %in% c("rate", "mean_confidence")) {
    out <- sub("\\.?0+$", "", sprintf(if (field == "rate") "%.4f" else "%.2f", x))
  } else {
    out <- as.character(x)
    quote <- grepl("[,\"\r\n]", out)
    out[quote] <- paste0("\"", gsub("\"", "\"\"", out[quote], fixed = TRUE), "\"")
  }
  out[is.na(x)] <- ""
  out
}

empty_inventory <- function() {
  data.frame(
    v = integer(), source = character(), table = character(), column = character(),
    type = character(), class = character(), n_rows = integer(), n_sampled = integer(),
    n_matched = integer(), n_full = integer(), rate = numeric(),
    mean_confidence = numeric(), sample_method = character(), scanned_at = character(),
    credgate = character()
  )
}

new_inventory <- function(x) {
  rownames(x) <- NULL
  structure(x, class = c("cg_inventory", "data.frame"))
}

#' @export
print.cg_inventory <- function(x, ...) {
  if (!all(c("source", "table", "column", "type") %in% names(x))) {
    print(as.data.frame(unclass(x)), ...)
    return(invisible(x))
  }
  if (nrow(x) == 0) {
    cli::cli_text("Empty inventory.")
    return(invisible(x))
  }
  key <- paste(x$source, x$table, sep = "\r")
  tables <- unique(key)
  cli::cli_text("Inventory of {length(tables)} table{?s}:")
  for (k in tables) {
    rows <- x[key == k, , drop = FALSE]
    found <- unique(rows$column[!is.na(rows$type)])
    types <- unique(rows$type[!is.na(rows$type)])
    cat(sprintf(
      "  %s: %s - %d column(s) scanned, PII in %d%s\n",
      rows$source[1], rows$table[1], length(unique(rows$column)), length(found),
      if (length(types)) paste0(" (", paste(types, collapse = ", "), ")") else ""
    ))
  }
  invisible(x)
}
