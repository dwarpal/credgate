#' Record where PII is in every table of a database
#'
#' Scans every table of a database through a DBI connection and returns an
#' inventory (see [pii_inventory()]). Each table is sampled by the database
#' where it can - Postgres and IBM Db2 with `TABLESAMPLE SYSTEM`, DuckDB with
#' `USING SAMPLE` - and only the sample is read; other databases are read
#' from their first rows, and the inventory says so (`sample_method`
#' `"first-rows"`). Only text and number columns are read. The rules are
#' shared with the Python package (`credgate.database`; see the spec's
#' "Databases").
#'
#' With an inventory file (`path`), the scan can be interrupted and run
#' again: tables scanned within `max_age` days whose row count has not
#' changed are kept rather than scanned again, and the file is rewritten
#' after each table.
#'
#' @param con A DBI connection: Postgres (RPostgres), DuckDB, SQLite
#'   (RSQLite), MySQL/MariaDB, IBM Db2 (odbc), or another DBI backend.
#' @param source Name of the data source for the inventory, e.g.
#'   `"postgres:crm"`.
#' @param path Optional inventory file (CSV); see Details.
#' @param schemas Schemas to scan; `NULL` scans all except the database's own.
#' @param include,exclude Shell-style patterns for `schema.table` to scan or
#'   leave out, e.g. `"crm.*"`.
#' @param views Also scan views (reading a view runs its query).
#' @param sample Maximum number of rows read per table.
#' @param min_rate,detectors As for [scan_pii()].
#' @param max_age Days after which a table is scanned again even if unchanged.
#' @param on_error `"warn"` (skip a table that cannot be read and list it in
#'   the `failed` attribute) or `"stop"`.
#' @return An inventory, with attributes `failed` (named character vector:
#'   table -> error message) and `skipped` (tables kept from an earlier run).
#' @export
#' @examples
#' \dontrun{
#' con <- DBI::dbConnect(RPostgres::Postgres(), dbname = "crm")
#' inv <- inventory_database(con, source = "postgres:crm", path = "inventory.csv")
#' inv
#' }
inventory_database <- function(con, source, path = NULL, schemas = NULL, include = NULL,
                               exclude = NULL, views = FALSE, sample = 10000L, min_rate = 0,
                               detectors = NULL, max_age = 30, on_error = c("warn", "stop")) {
  check_installed("DBI")
  on_error <- match.arg(on_error)
  family <- db_family(con)
  previous <- db_previous(path, source)
  rows <- list()
  failed <- character()
  skipped <- character()
  seen <- character()

  for (t in db_tables(con, family, schemas, include, exclude, views)) {
    name <- paste0(t$schema, ".", t$table)
    seen <- c(seen, name)
    result <- tryCatch(
      {
        n <- db_row_count(con, family, t$schema, t$table)
        old <- previous[[name]]
        if (!is.null(old) && db_unchanged(old, n, max_age)) {
          skipped <- c(skipped, name)
          old
        } else {
          columns <- db_columns(con, family, t$schema, t$table)
          query <- db_sample_query(family, t$schema, t$table, n, columns, sample)
          got <- if (is.null(query$sql)) {
            data.frame(row.names = integer())
          } else {
            res <- DBI::dbSendQuery(con, query$sql)
            out <- DBI::dbFetch(res, n = query$fetch %||% -1)
            DBI::dbClearResult(res)
            stats::setNames(as.data.frame(out), query$read)
          }
          data <- sampled_rows(got, columns$name, n, query$method)
          pii_inventory(data, source = source, table = name, sample = sample,
                        min_rate = min_rate, detectors = detectors)
        }
      },
      error = function(e) {
        if (on_error == "stop") {
          stop(e)
        }
        msg <- strsplit(conditionMessage(e), "\n", fixed = TRUE)[[1]][1]
        failed[[name]] <<- msg
        rlang::warn(paste0("credgate: ", name, " not scanned: ", msg))
        NULL
      }
    )
    if (!is.null(result)) {
      rows[[name]] <- result
      if (!is.null(path)) {
        pending <- previous[setdiff(names(previous), seen)]
        db_write(path, c(rows, pending))
      }
    }
  }
  if (!is.null(path)) {
    # Tables no longer in the database are dropped; those that failed keep
    # their earlier rows.
    db_write(path, c(rows, previous[intersect(names(previous), names(failed))]))
  }
  inv <- new_inventory(do.call(rbind, c(list(empty_inventory()), unname(rows))))
  structure(inv, failed = failed, skipped = skipped)
}

# The query that samples a table, the columns it reads, the sample method
# and how many rows to read (NULL: all the query returns), as the spec's
# "Databases" rules say. `columns` has columns name and type.
db_sample_query <- function(family, schema, table, n, columns, sample = 10000L) {
  unread <- "blob|binary|bytea|image|json|xml|geometry|geography|array|struct|map|interval|date|time|bool|uuid|\\[\\]$"
  read <- columns$name[!grepl(unread, tolower(columns$type))]
  if (length(read) == 0) {
    return(list(sql = NULL, read = character(), method = "all", fetch = NULL))
  }
  q <- db_quote(family)
  sql <- paste0("SELECT ", paste(q(read), collapse = ", "), " FROM ", db_table_name(family, schema, table))
  if (n <= sample) {
    return(list(sql = sql, read = read, method = "all", fetch = NULL))
  }
  p <- bq_num(100 * max(0.000001, min(1, 1.2 * sample / n)))
  out <- switch(family,
    postgresql = list(paste0(sql, " TABLESAMPLE SYSTEM (", p, ") LIMIT ", sample), "tablesample", NULL),
    db2 = list(paste0(sql, " TABLESAMPLE SYSTEM (", p, ") FETCH FIRST ", sample, " ROWS ONLY"), "tablesample", NULL),
    duckdb = list(paste0(sql, " USING SAMPLE ", p, " PERCENT (system) LIMIT ", sample), "tablesample", NULL),
    sqlite = ,
    mysql = list(paste0(sql, " LIMIT ", sample), "first-rows", NULL),
    list(sql, "first-rows", as.integer(sample))
  )
  list(sql = out[[1]], read = read, method = out[[2]], fetch = out[[3]])
}

db_family <- function(con) {
  cls <- class(con)
  if (any(cls %in% c("PqConnection", "PostgreSQLConnection", "RedshiftConnection"))) {
    return("postgresql")
  }
  if (any(grepl("duckdb", cls))) {
    return("duckdb")
  }
  if ("SQLiteConnection" %in% cls) {
    return("sqlite")
  }
  if (any(cls %in% c("MySQLConnection", "MariaDBConnection"))) {
    return("mysql")
  }
  dbms <- tolower(tryCatch(DBI::dbGetInfo(con)$dbms.name, error = function(e) "") %||% "")
  if (grepl("db2", dbms)) {
    return("db2")
  }
  if (grepl("postgres", dbms)) {
    return("postgresql")
  }
  "other"
}

db_quote <- function(family) {
  if (family == "mysql") {
    function(x) paste0("`", gsub("`", "``", x, fixed = TRUE), "`")
  } else {
    function(x) paste0("\"", gsub("\"", "\"\"", x, fixed = TRUE), "\"")
  }
}

# The quoted table name. DuckDB schemas are named `catalog.schema`.
db_table_name <- function(family, schema, table) {
  parts <- if (family == "duckdb") strsplit(schema, ".", fixed = TRUE)[[1]] else schema
  if (family == "duckdb" && length(parts) > 2) {
    parts <- c(parts[1], paste(parts[-1], collapse = "."))
  }
  paste(db_quote(family)(c(parts, table)), collapse = ".")
}

db_tables <- function(con, family, schemas, include, exclude, views) {
  system <- c(
    "information_schema", "pg_catalog", "pg_toast", "sys", "syscat", "sysibm",
    "sysstat", "mysql", "performance_schema"
  )
  if (family == "sqlite") {
    found <- DBI::dbGetQuery(
      con,
      "SELECT 'main' AS schema, name AS tab, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'"
    )
    found$is_view <- found$type == "view"
  } else if (family == "db2") {
    found <- DBI::dbGetQuery(
      con,
      "SELECT TRIM(TABSCHEMA) AS schema, TABNAME AS tab, TYPE AS type FROM SYSCAT.TABLES WHERE TYPE IN ('T', 'V')"
    )
    found$is_view <- found$type == "V"
  } else {
    found <- DBI::dbGetQuery(
      con,
      paste(
        "SELECT table_catalog AS catalog, table_schema AS schema, table_name AS tab, table_type AS type",
        "FROM information_schema.tables WHERE table_type IN ('BASE TABLE', 'VIEW')"
      )
    )
    found$is_view <- found$type == "VIEW"
    if (family == "duckdb") {
      found$schema <- paste0(found$catalog, ".", found$schema)
    }
  }
  if (is.null(schemas)) {
    s <- tolower(found$schema)
    found <- found[!s %in% system & !startsWith(s, "pg_temp") & !startsWith(s, "pg_toast_temp") &
      !startsWith(s, "system.") & !startsWith(s, "temp.") &
      !(family == "duckdb" & sub("^[^.]*[.]", "", s) %in% system), , drop = FALSE]
  } else {
    found <- found[found$schema %in% schemas, , drop = FALSE]
  }
  if (!views) {
    found <- found[!found$is_view, , drop = FALSE]
  }
  name <- paste0(found$schema, ".", found$tab)
  keep <- rep(TRUE, length(name))
  if (length(include) > 0) {
    keep <- keep & Reduce(`|`, lapply(include, function(p) grepl(utils::glob2rx(p), name)))
  }
  if (length(exclude) > 0) {
    keep <- keep & !Reduce(`|`, lapply(exclude, function(p) grepl(utils::glob2rx(p), name)))
  }
  found <- found[keep, , drop = FALSE]
  found <- found[order(found$schema, found$tab, method = "radix"), , drop = FALSE]
  lapply(seq_len(nrow(found)), function(i) list(schema = found$schema[i], table = found$tab[i]))
}

db_columns <- function(con, family, schema, table) {
  if (family == "sqlite") {
    info <- DBI::dbGetQuery(con, paste0("PRAGMA table_info(", db_quote(family)(table), ")"))
    return(data.frame(name = info$name, type = info$type))
  }
  if (family == "db2") {
    info <- DBI::dbGetQuery(
      con,
      "SELECT COLNAME AS name, TYPENAME AS type FROM SYSCAT.COLUMNS WHERE TABSCHEMA = ? AND TABNAME = ? ORDER BY COLNO",
      params = list(schema, table)
    )
    return(data.frame(name = info$name, type = info$type))
  }
  catalog <- NULL
  if (family == "duckdb") {
    catalog <- sub("[.].*$", "", schema)
    schema <- sub("^[^.]*[.]", "", schema)
  }
  sql <- paste0(
    "SELECT column_name AS name, data_type AS type FROM information_schema.columns ",
    "WHERE table_schema = ", DBI::dbQuoteString(con, schema),
    " AND table_name = ", DBI::dbQuoteString(con, table),
    if (!is.null(catalog)) paste0(" AND table_catalog = ", DBI::dbQuoteString(con, catalog)),
    " ORDER BY ordinal_position"
  )
  info <- DBI::dbGetQuery(con, sql)
  data.frame(name = info$name, type = as.character(info$type))
}

db_row_count <- function(con, family, schema, table) {
  if (family == "postgresql") {
    estimate <- DBI::dbGetQuery(
      con,
      paste0(
        "SELECT c.reltuples FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace ",
        "WHERE s.nspname = ", DBI::dbQuoteString(con, schema),
        " AND c.relname = ", DBI::dbQuoteString(con, table)
      )
    )
    if (nrow(estimate) == 1 && !is.na(estimate[[1]]) && estimate[[1]] >= 0) {
      return(as.numeric(estimate[[1]]))
    }
  }
  as.numeric(DBI::dbGetQuery(con, paste0("SELECT COUNT(*) FROM ", db_table_name(family, schema, table)))[[1]])
}

db_previous <- function(path, source) {
  if (is.null(path) || !file.exists(path)) {
    return(list())
  }
  old <- read_inventory(path)
  old <- old[old$source == source, , drop = FALSE]
  split(old, factor(old$table, levels = unique(old$table)))
}

db_unchanged <- function(rows, n, max_age) {
  scanned <- as.POSIXct(rows$scanned_at[1], format = "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
  age <- as.numeric(difftime(Sys.time(), scanned, units = "days"))
  !is.na(rows$n_rows[1]) && rows$n_rows[1] == n && age <= max_age
}

db_write <- function(path, parts) {
  inv <- new_inventory(do.call(rbind, c(list(empty_inventory()), unname(parts))))
  tmp <- paste0(path, ".tmp")
  write_inventory(inv, tmp)
  file.rename(tmp, path)
}
