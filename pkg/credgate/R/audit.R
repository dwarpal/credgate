# Tamper-evident audit log of policy decisions (the spec's "Audit log").

audit_genesis <- strrep("0", 64)
audit_never_hashed <- "sensitive_auth"

#' Audit log of policy decisions
#'
#' `cg_audit_log()` opens an append-only, hash-chained log; pass it to
#' [policy_apply()] (`audit = log`) to record every decision, allowed or
#' blocked, or record a decision yourself with `audit_record()`. Each record
#' says who sent what kind of data where, under which policy revision and
#' rule - never the text or the values. With an audit key (`key` or
#' `CREDGATE_AUDIT_KEY`; not the token key), identifiers are recorded as keyed
#' hashes, so whoever holds the key can check whether a given identifier was
#' involved. Card verification codes are never hashed.
#'
#' `audit_verify()` checks that no record was edited, deleted, inserted or
#' reordered; keep copies of the returned `head` elsewhere to detect records
#' removed from the end. `audit_read()` returns the records. The same files
#' are written and verified by the Python package. Needs the openssl package.
#'
#' With `rotate = TRUE` the log starts a new file each month (UTC): the active
#' file at `path` is renamed `<stem>.YYYY-MM.jsonl` when the first record of a
#' new month arrives, and the chain continues in a new active file;
#' `audit_verify()` and `audit_read()` cover all of them. `audit_prune()`
#' removes monthly files older than the retention period (at least 1 year),
#' only from the oldest end and only if the log verifies, and records them in
#' `<stem>.pruned.json`, from which the rest still verifies.
#'
#' One R process at a time should write a given log: R has no file locks, so
#' two R processes writing the same file could give two records the same
#' sequence number (which `audit_verify()` then reports). Give each process
#' its own file (for example with `Sys.getpid()` in the name). The Python
#' package locks the file, so several Python processes - such as the
#' proxy's workers - can share one.
#'
#' @param path The log file (JSON Lines); created if missing.
#' @param key Audit key (64+ hex digits or raw); `NULL` uses
#'   `CREDGATE_AUDIT_KEY` if set, otherwise identifiers are not hashed.
#' @param actor Who makes the requests; defaults to the operating-system user.
#' @param rotate Start a new file each month (see Details).
#' @param log A log from `cg_audit_log()`.
#' @param decision A decision from [policy_decide()] or [policy_apply()].
#' @param time The record's time (`POSIXct`); defaults to now.
#' @param keep_years Years to keep monthly files (at least 1).
#' @param now The current time, for `audit_prune()`.
#' @return `cg_audit_log()`: a log. `audit_record()`: the record (a list),
#'   invisibly. `audit_verify()`: a list with `ok`, `records`, `head`, and for
#'   a broken log the failing `line` and the `error`. `audit_read()`: a data
#'   frame, one row per record, with the `items` as a list column.
#'   `audit_prune()`: the names of the removed files, invisibly.
#' @export
#' @examplesIf requireNamespace("openssl", quietly = TRUE)
#' policy <- cg_policy(list(
#'   policy = "credgate-policy", version = 1L, id = "example", revision = 1L,
#'   destinations = list(claude = list(tier = "frontier", provider = "anthropic")),
#'   rules = list(list(
#'     id = "no-ids", action = "redact", when = list(classes = list("identity_strong"))
#'   )),
#'   default_action = "redact"
#' ))
#' path <- tempfile(fileext = ".jsonl")
#' log <- cg_audit_log(path, actor = "analyst1")
#' policy_apply(policy, "PAN ABCPE1234F", "claude", audit = log)
#' audit_verify(path)
#' audit_read(path)[, c("seq", "actor", "destination", "allowed")]
cg_audit_log <- function(path, key = NULL, actor = NULL, rotate = FALSE) {
  check_installed("openssl")
  stopifnot(rlang::is_string(path))
  if (is.null(key) && nzchar(Sys.getenv("CREDGATE_AUDIT_KEY"))) {
    key <- Sys.getenv("CREDGATE_AUDIT_KEY")
  }
  log <- new.env(parent = emptyenv())
  log$path <- path
  log$key <- if (is.null(key)) NULL else token_key(key)
  log$actor <- actor %||% Sys.info()[["user"]]
  log$rotate <- isTRUE(rotate)
  structure(log, class = "cg_audit_log")
}

#' @rdname cg_audit_log
#' @export
audit_record <- function(log, decision, time = NULL) {
  if (!inherits(log, "cg_audit_log")) {
    rlang::abort("`log` must be an audit log from `cg_audit_log()`.")
  }
  m <- decision$matches
  items <- lapply(seq_len(nrow(m)), function(i) {
    item <- list(type = m$type[i], action = m$action[i], rule = m$rule[i])
    if (!is.null(log$key) && !m$class[i] %in% audit_never_hashed) {
      item$id <- audit_id_hash(log$key, m$type[i], m$canonical[i])
    }
    item
  })
  stamp <- format(time %||% Sys.time(), "%Y-%m-%dT%H:%M:%OS3Z", tz = "UTC")
  # As in Python: the log's folder is created if it does not exist yet.
  dir.create(dirname(log$path), recursive = TRUE, showWarnings = FALSE)
  last <- if (file.exists(log$path)) audit_last_line(log$path) else NULL
  first_month <- if (is.null(last)) NULL else substr(audit_first_record(log$path)$time, 1, 7)
  if (log$rotate && !is.null(first_month) && substr(stamp, 1, 7) > first_month) {
    segment <- audit_segment_path(log$path, first_month)
    if (file.exists(segment)) {
      rlang::abort(paste0(segment, " exists; the audit log cannot rotate."))
    }
    file.rename(log$path, segment)
  } else if (is.null(last)) {
    last <- audit_predecessor(log$path)
  }
  if (is.null(last)) {
    seq <- 1L
    prev <- audit_genesis
  } else if (is.list(last)) { # everything before was pruned
    seq <- as.integer(last$last_seq) + 1L
    prev <- last$head
  } else {
    seq <- jsonlite::fromJSON(last)$seq + 1L
    prev <- audit_sha256(last)
  }
  record <- list(
    v = 1L,
    seq = as.integer(seq),
    time = stamp,
    actor = log$actor,
    policy = list(id = decision$policy_id, revision = decision$policy_revision),
    destination = list(name = decision$destination, tier = decision$tier, provider = decision$provider),
    allowed = decision$allowed,
    blocked_by = I(as.character(decision$blocked_by)),
    items = items,
    prev = prev
  )
  line <- as.character(jsonlite::toJSON(record, auto_unbox = TRUE, null = "null", na = "null", digits = NA))
  new_file <- !file.exists(log$path)
  con <- file(log$path, open = "ab")
  on.exit(close(con), add = TRUE)
  if (new_file) {
    # Private to the account writing it: no values, but who sent what kind of
    # data where.
    Sys.chmod(log$path, "600")
  }
  writeBin(c(charToRaw(enc2utf8(line)), as.raw(10L)), con)
  invisible(record)
}

#' @rdname cg_audit_log
#' @export
audit_verify <- function(path) {
  check_installed("openssl")
  anchor <- audit_manifest(path)
  problem <- if (is.null(anchor)) NULL else audit_manifest_problem(anchor)
  if (!is.null(problem)) {
    return(structure(
      list(ok = FALSE, records = 0L, head = NULL, line = NULL, error = problem,
           file = basename(audit_manifest_path(path)), files = 0L),
      class = "cg_audit_check"
    ))
  }
  seq <- if (is.null(anchor)) 0L else as.integer(anchor$last_seq)
  prev <- if (is.null(anchor)) audit_genesis else anchor$head
  start <- seq
  segments <- audit_segments(path)
  files <- c(segments$path, if (file.exists(path)) path)
  months <- c(segments$month, if (file.exists(path)) NA_character_)
  result <- function(ok, n, head = NULL, line = NULL, error = NULL, file = NULL) {
    structure(
      list(ok = ok, records = n, head = head, line = line, error = error, file = file, files = length(files)),
      class = "cg_audit_check"
    )
  }
  for (f in seq_along(files)) {
    lines <- audit_lines(files[f])
    for (n in seq_along(lines)) {
      broken <- function(error) result(FALSE, seq - start, line = n, error = error, file = basename(files[f]))
      rec <- tryCatch(jsonlite::fromJSON(lines[n], simplifyVector = FALSE), error = function(e) NULL)
      if (is.null(rec)) {
        return(broken("not a JSON record"))
      }
      if (!is.list(rec) || !identical(rec$v, 1L)) {
        return(broken("not an audit record (v 1)"))
      }
      if (!identical(rec$seq, as.integer(seq + 1L))) {
        return(broken(paste0("sequence ", format(rec$seq), ", expected ", seq + 1L)))
      }
      if (!identical(rec$prev, prev)) {
        where <- if (seq > start || !is.null(anchor)) "the record before" else "the start"
        return(broken(paste0(
          "does not follow ", where, ": a record was changed, or records or ",
          "segments were removed, inserted or reordered here"
        )))
      }
      if (!is.na(months[f]) && !identical(substr(rec$time %||% "", 1, 7), months[f])) {
        return(broken(paste0("a record of ", substr(rec$time %||% "", 1, 7), " in the ", months[f], " segment")))
      }
      seq <- seq + 1L
      prev <- audit_sha256(lines[n])
    }
  }
  result(TRUE, seq - start, head = if (seq > start) prev else NULL)
}

#' @rdname cg_audit_log
#' @export
audit_read <- function(path) {
  files <- c(audit_segments(path)$path, if (file.exists(path)) path)
  recs <- lapply(unlist(lapply(files, audit_lines)), jsonlite::fromJSON, simplifyVector = FALSE)
  field <- function(f) vapply(recs, f, character(1))
  data.frame(
    seq = vapply(recs, function(r) as.integer(r$seq), integer(1)),
    time = field(function(r) r$time),
    actor = field(function(r) r$actor),
    policy_id = field(function(r) r$policy$id),
    policy_revision = vapply(recs, function(r) as.integer(r$policy$revision), integer(1)),
    destination = field(function(r) r$destination$name),
    tier = field(function(r) r$destination$tier),
    provider = field(function(r) r$destination$provider %||% NA_character_),
    allowed = vapply(recs, function(r) isTRUE(r$allowed), logical(1)),
    blocked_by = field(function(r) paste(unlist(r$blocked_by), collapse = ", ")),
    items = I(lapply(recs, `[[`, "items"))
  )
}

#' @rdname cg_audit_log
#' @export
audit_prune <- function(path, keep_years = 5L, now = Sys.time()) {
  if (!rlang::is_scalar_integerish(keep_years) || keep_years < 1) {
    rlang::abort("`keep_years` must be a whole number of at least 1.")
  }
  check <- audit_verify(path)
  if (!isTRUE(check$ok)) {
    rlang::abort(paste0(
      "Not pruning a broken audit log (kept as evidence): ", check$file, ", line ", check$line, ": ", check$error
    ))
  }
  today <- as.POSIXlt(now, tz = "UTC")
  current <- (today$year + 1900) * 12 + today$mon + 1
  segments <- audit_segments(path)
  removable <- character()
  for (i in seq_len(nrow(segments))) {
    year <- as.integer(substr(segments$month[i], 1, 4))
    month <- as.integer(substr(segments$month[i], 6, 7))
    if (current <= (year + keep_years) * 12 + month) {
      break
    }
    removable <- c(removable, segments$path[i])
  }
  if (length(removable) == 0) {
    return(invisible(character()))
  }
  manifest <- audit_manifest(path) %||% list(credgate_audit_pruned = 1L, segments = list())
  for (file in removable) {
    lines <- audit_lines(file)
    first <- jsonlite::fromJSON(lines[1], simplifyVector = FALSE)
    last <- jsonlite::fromJSON(lines[length(lines)], simplifyVector = FALSE)
    head <- audit_sha256(lines[length(lines)])
    manifest$segments[[length(manifest$segments) + 1]] <- list(
      name = basename(file), first_seq = first$seq, last_seq = last$seq,
      first_time = first$time, last_time = last$time, head = head
    )
    manifest$last_seq <- last$seq
    manifest$head <- head
  }
  target <- audit_manifest_path(path)
  tmp <- paste0(target, ".tmp")
  writeLines(jsonlite::toJSON(manifest, auto_unbox = TRUE, pretty = TRUE), tmp, useBytes = TRUE)
  Sys.chmod(tmp, "600")
  file.rename(tmp, target)
  unlink(removable)
  invisible(basename(removable))
}

#' @export
print.cg_audit_check <- function(x, ...) {
  if (isTRUE(x$ok)) {
    files <- if (isTRUE(x$files > 1)) paste0(" in ", x$files, " files") else ""
    cli::cli_text("Audit log intact: {x$records} record{?s}{files}; head {x$head}")
  } else {
    where <- if (is.null(x$file)) paste("line", x$line) else paste0(x$file, ", line ", x$line)
    cli::cli_text("Audit log BROKEN at {where}: {x$error}")
  }
  invisible(x)
}

#' @export
print.cg_audit_log <- function(x, ...) {
  hashed <- if (is.null(x$key)) "identifiers not hashed" else "identifiers hashed"
  cli::cli_text("Audit log {.file {x$path}} ({hashed})")
  invisible(x)
}

audit_id_hash <- function(key, type, canonical) {
  message <- c(
    charToRaw("credgate-audit-v1"), as.raw(0L), charToRaw(enc2utf8(type)),
    as.raw(0L), charToRaw(enc2utf8(canonical))
  )
  paste(format(as.raw(openssl::sha256(message, key = key))[1:8]), collapse = "")
}

audit_sha256 <- function(line) {
  paste(format(as.raw(openssl::sha256(charToRaw(enc2utf8(line))))), collapse = "")
}

audit_lines <- function(path) {
  lines <- readLines(path, encoding = "UTF-8", warn = FALSE)
  Encoding(lines) <- "UTF-8"
  lines <- sub("\r$", "", lines)
  lines[nzchar(lines)]
}

audit_last_line <- function(path) {
  size <- file.size(path)
  if (is.na(size) || size == 0) {
    return(NULL)
  }
  con <- file(path, open = "rb")
  on.exit(close(con), add = TRUE)
  chunk <- 65536
  buf <- raw(0)
  pos <- size
  repeat {
    step <- min(chunk, pos)
    pos <- pos - step
    seek(con, pos)
    buf <- c(readBin(con, "raw", step), buf)
    while (length(buf) && buf[length(buf)] %in% as.raw(c(10L, 13L))) {
      buf <- buf[-length(buf)]
    }
    nl <- which(buf == as.raw(10L))
    if (length(nl)) {
      line <- rawToChar(buf[(max(nl) + 1L):length(buf)])
      break
    }
    if (pos == 0) {
      line <- rawToChar(buf)
      break
    }
  }
  Encoding(line) <- "UTF-8"
  if (nzchar(line)) line else NULL
}

audit_first_record <- function(path) {
  con <- file(path, open = "r", encoding = "UTF-8")
  on.exit(close(con), add = TRUE)
  repeat {
    line <- readLines(con, n = 1L, warn = FALSE)
    if (length(line) == 0) {
      return(list())
    }
    line <- sub("\r$", "", line)
    if (nzchar(line)) {
      return(jsonlite::fromJSON(line, simplifyVector = FALSE))
    }
  }
}

audit_stem <- function(path) {
  name <- basename(path)
  ext <- regmatches(name, regexpr("[.][^.]*$", name))
  list(stem = if (length(ext)) substr(name, 1, nchar(name) - nchar(ext)) else name, ext = if (length(ext)) ext else "")
}

audit_segment_path <- function(path, month) {
  parts <- audit_stem(path)
  file.path(dirname(path), paste0(parts$stem, ".", month, parts$ext))
}

# Closed monthly segments of a log, oldest first.
audit_segments <- function(path) {
  parts <- audit_stem(path)
  names <- list.files(dirname(path))
  month <- regmatches(names, regexpr("[.][0-9]{4}-[0-9]{2}[.][^.]*$|[.][0-9]{4}-[0-9]{2}$", names))
  keep <- names %in% paste0(parts$stem, ".", substr(month, 2, 8), parts$ext)
  names <- names[keep]
  months <- substr(names, nchar(parts$stem) + 2, nchar(parts$stem) + 8)
  ord <- order(months)
  data.frame(month = months[ord], path = file.path(dirname(path), names[ord]))
}

audit_manifest_path <- function(path) {
  file.path(dirname(path), paste0(audit_stem(path)$stem, ".pruned.json"))
}

audit_manifest <- function(path) {
  m <- audit_manifest_path(path)
  if (!file.exists(m)) {
    return(NULL)
  }
  data <- jsonlite::fromJSON(m, simplifyVector = FALSE)
  if (!identical(data$credgate_audit_pruned, 1L)) {
    rlang::abort(paste0(m, " is not a credgate pruned-segments file."))
  }
  data
}

# What a record in an empty active file follows: the last line of the newest
# segment, else the anchor of pruned segments, else nothing.
audit_predecessor <- function(path) {
  segments <- audit_segments(path)
  if (nrow(segments)) {
    return(audit_last_line(segments$path[nrow(segments)]))
  }
  audit_manifest(path)
}

# Why a pruned-segments record is inconsistent, if it is: its segments must
# run from sequence 1 without gaps, and its anchor match the last.
audit_manifest_problem <- function(anchor) {
  segments <- anchor$segments
  if (length(segments) == 0) {
    return("the pruned-segments record lists no segments")
  }
  expected <- 1L
  for (seg in segments) {
    if (!identical(seg$first_seq, expected) || !rlang::is_scalar_integerish(seg$last_seq)) {
      return(paste0("pruned segment '", seg$name, "' does not follow the one before"))
    }
    expected <- as.integer(seg$last_seq) + 1L
  }
  last <- segments[[length(segments)]]
  if (!identical(anchor$last_seq, last$last_seq) || !identical(anchor$head, last$head)) {
    return("the pruned-segments anchor does not match the last pruned segment")
  }
  NULL
}

# One person's recent proxy requests, newest first: at most `max` from the
# last `days` days. Only the monthly files that can hold them are read.
own_activity <- function(path, actor, days = 7L, max = 100L, now = Sys.time()) {
  since <- now - days * 86400
  segs <- audit_segments(path)
  keep <- segs$path[segs$month >= format(since, "%Y-%m", tz = "UTC")]
  files <- c(keep, if (file.exists(path)) path)
  recs <- lapply(unlist(lapply(files, audit_lines)), jsonlite::fromJSON, simplifyVector = FALSE)
  when <- function(t) as.POSIXct(substr(t, 1, 19), format = "%Y-%m-%dT%H:%M:%S", tz = "UTC")
  recs <- Filter(function(r) identical(r$actor, actor) && when(r$time) >= since, recs)
  recs <- utils::head(rev(recs), max)
  data.frame(
    time = vapply(recs, function(r) r$time, ""),
    endpoint = vapply(recs, function(r) r$destination$name, ""),
    allowed = vapply(recs, function(r) isTRUE(r$allowed), TRUE),
    blocked_by = vapply(recs, function(r) paste(unlist(r$blocked_by), collapse = ", "), ""),
    found = vapply(recs, function(r) {
      a <- vapply(r$items %||% list(), function(i) i$action, "")
      if (length(a)) paste(sprintf("%d %s", as.vector(table(a)), names(table(a))), collapse = ", ") else "nothing"
    }, ""),
    stringsAsFactors = FALSE
  )
}
