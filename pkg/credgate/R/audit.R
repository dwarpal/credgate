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
#' @param path The log file (JSON Lines); created if missing.
#' @param key Audit key (64+ hex digits or raw); `NULL` uses
#'   `CREDGATE_AUDIT_KEY` if set, otherwise identifiers are not hashed.
#' @param actor Who makes the requests; defaults to the operating-system user.
#' @param log A log from `cg_audit_log()`.
#' @param decision A decision from [policy_decide()] or [policy_apply()].
#' @return `cg_audit_log()`: a log. `audit_record()`: the record (a list),
#'   invisibly. `audit_verify()`: a list with `ok`, `records`, `head`, and for
#'   a broken log the failing `line` and the `error`. `audit_read()`: a data
#'   frame, one row per record, with the `items` as a list column.
#' @export
#' @examplesIf requireNamespace("openssl", quietly = TRUE)
#' policy <- cg_policy(list(
#'   policy = "credgate-policy", version = 1L, id = "example", revision = 1L,
#'   destinations = list(claude = list(tier = "frontier", provider = "anthropic")),
#'   rules = list(list(id = "no-ids", action = "redact", when = list(classes = list("identity_strong")))),
#'   default_action = "redact"
#' ))
#' path <- tempfile(fileext = ".jsonl")
#' log <- cg_audit_log(path, actor = "analyst1")
#' policy_apply(policy, "PAN ABCPE1234F", "claude", audit = log)
#' audit_verify(path)
#' audit_read(path)[, c("seq", "actor", "destination", "allowed")]
cg_audit_log <- function(path, key = NULL, actor = NULL) {
  check_installed("openssl")
  stopifnot(rlang::is_string(path))
  if (is.null(key) && nzchar(Sys.getenv("CREDGATE_AUDIT_KEY"))) {
    key <- Sys.getenv("CREDGATE_AUDIT_KEY")
  }
  log <- new.env(parent = emptyenv())
  log$path <- path
  log$key <- if (is.null(key)) NULL else token_key(key)
  log$actor <- actor %||% Sys.info()[["user"]]
  structure(log, class = "cg_audit_log")
}

#' @rdname cg_audit_log
#' @export
audit_record <- function(log, decision) {
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
  last <- if (file.exists(log$path)) audit_last_line(log$path) else NULL
  if (is.null(last)) {
    seq <- 1L
    prev <- audit_genesis
  } else {
    seq <- jsonlite::fromJSON(last)$seq + 1L
    prev <- audit_sha256(last)
  }
  record <- list(
    v = 1L,
    seq = as.integer(seq),
    time = format(Sys.time(), "%Y-%m-%dT%H:%M:%OS3Z", tz = "UTC"),
    actor = log$actor,
    policy = list(id = decision$policy_id, revision = decision$policy_revision),
    destination = list(name = decision$destination, tier = decision$tier, provider = decision$provider),
    allowed = decision$allowed,
    blocked_by = I(as.character(decision$blocked_by)),
    items = items,
    prev = prev
  )
  line <- as.character(jsonlite::toJSON(record, auto_unbox = TRUE, null = "null", na = "null", digits = NA))
  con <- file(log$path, open = "ab")
  on.exit(close(con), add = TRUE)
  writeBin(c(charToRaw(enc2utf8(line)), as.raw(10L)), con)
  invisible(record)
}

#' @rdname cg_audit_log
#' @export
audit_verify <- function(path) {
  check_installed("openssl")
  lines <- audit_lines(path)
  prev <- audit_genesis
  result <- function(ok, n, head = NULL, line = NULL, error = NULL) {
    structure(list(ok = ok, records = n, head = head, line = line, error = error), class = "cg_audit_check")
  }
  for (n in seq_along(lines)) {
    rec <- tryCatch(jsonlite::fromJSON(lines[n], simplifyVector = FALSE), error = function(e) NULL)
    if (is.null(rec)) {
      return(result(FALSE, n - 1L, line = n, error = "not a JSON record"))
    }
    if (!is.list(rec) || !identical(rec$v, 1L)) {
      return(result(FALSE, n - 1L, line = n, error = "not an audit record (v 1)"))
    }
    if (!identical(rec$seq, as.integer(n))) {
      return(result(FALSE, n - 1L, line = n, error = paste0("sequence ", format(rec$seq), ", expected ", n)))
    }
    if (!identical(rec$prev, prev)) {
      where <- if (n == 1) "the first record" else paste("line", n - 1)
      return(result(FALSE, n - 1L, line = n, error = paste0(
        "does not follow ", where, ": that line was changed, or lines were ",
        "removed, inserted or reordered here"
      )))
    }
    prev <- audit_sha256(lines[n])
  }
  result(TRUE, length(lines), head = if (length(lines)) prev else NULL)
}

#' @rdname cg_audit_log
#' @export
audit_read <- function(path) {
  recs <- lapply(audit_lines(path), jsonlite::fromJSON, simplifyVector = FALSE)
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

#' @export
print.cg_audit_check <- function(x, ...) {
  if (isTRUE(x$ok)) {
    cli::cli_text("Audit log intact: {x$records} record{?s}; head {x$head}")
  } else {
    cli::cli_text("Audit log BROKEN at line {x$line}: {x$error}")
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
