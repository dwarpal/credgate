#' Proxy keys: who may use a shared proxy
#'
#' The proxy's keys file holds, for each user, a SHA-256 hash of their key
#' and when it was made and expires (see the spec, "Proxy keys file"). These
#' functions manage it from R, as `credgate proxy add-user` and friends do
#' from the command line; the policy editor uses them for each person's own
#' key. A key is shown once, when it is made, and never stored.
#'
#' @param keys The keys file.
#' @param name A user name (letters, digits, `.`, `_`, `@` and `-`).
#' @param days How long a new key is valid: 1 to 180 days.
#' @param now The time to judge expiry at (for `proxy_users()`).
#' @return `proxy_add_user()` and `proxy_rotate_key()`: the new key.
#'   `proxy_users()`: a data frame of `name`, `created`, `expires` and
#'   `status` ("active", "expires soon", "expired", "no expiry") - never keys
#'   or hashes. `proxy_remove_user()`: `keys`, invisibly.
#' @export
#' @examples
#' keys <- tempfile(fileext = ".json")
#' key <- proxy_add_user(keys, "priya", days = 30)
#' proxy_users(keys)
proxy_add_user <- function(keys, name, days = 90) {
  check_installed("openssl")
  if (!rlang::is_string(name) || !grepl("^[A-Za-z0-9._@-]{1,100}$", name)) {
    rlang::abort("User names may contain letters, digits, '.', '_', '@' and '-'.")
  }
  users <- if (file.exists(keys)) read_proxy_keys(keys) else list()
  if (name %in% names(users)) {
    rlang::abort(sprintf("User '%s' already exists in %s; rotate their key instead.", name, keys))
  }
  new <- new_proxy_key(days)
  users[[name]] <- new$entry
  write_proxy_keys(keys, users)
  new$key
}

#' @rdname proxy_add_user
#' @export
proxy_rotate_key <- function(keys, name, days = 90) {
  check_installed("openssl")
  users <- read_proxy_keys(keys)
  if (!name %in% names(users)) rlang::abort(sprintf("No user '%s' in %s.", name, keys))
  new <- new_proxy_key(days)
  users[[name]] <- new$entry
  write_proxy_keys(keys, users)
  new$key
}

#' @rdname proxy_add_user
#' @export
proxy_remove_user <- function(keys, name) {
  users <- read_proxy_keys(keys)
  if (!name %in% names(users)) rlang::abort(sprintf("No user '%s' in %s.", name, keys))
  if (length(users) == 1) {
    rlang::abort(sprintf("'%s' is the last user in %s; add another user first.", name, keys))
  }
  users[[name]] <- NULL
  write_proxy_keys(keys, users)
  invisible(keys)
}

#' @rdname proxy_add_user
#' @export
proxy_users <- function(keys, now = Sys.time()) {
  users <- if (file.exists(keys)) read_proxy_keys(keys) else list()
  rows <- lapply(sort(names(users)), function(n) {
    e <- users[[n]]
    status <- if (is.null(e$expires)) {
      "no expiry"
    } else {
      left <- difftime(key_time(e$expires), now, units = "days")
      if (left <= 0) "expired" else if (left <= 7) "expires soon" else "active"
    }
    data.frame(
      name = n, created = e$created %||% NA_character_, expires = e$expires %||% NA_character_,
      status = status, stringsAsFactors = FALSE
    )
  })
  do.call(rbind, c(
    list(data.frame(name = character(), created = character(), expires = character(), status = character())),
    rows
  ))
}

proxy_key_hash <- function(key) {
  paste0("sha256:", paste(format(as.raw(openssl::sha256(charToRaw(enc2utf8(key))))), collapse = ""))
}

key_time <- function(x) as.POSIXct(x, format = "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")

key_stamp <- function(t) format(t, "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")

new_proxy_key <- function(days) {
  if (!rlang::is_scalar_integerish(days) || is.logical(days) || days < 1 || days > 180) {
    rlang::abort("A key lasts 1 to 180 days.")
  }
  # cgk_ and 32 random bytes in URL-safe base64 without padding (43 characters).
  b64 <- openssl::base64_encode(openssl::rand_bytes(32))
  key <- paste0("cgk_", chartr("+/", "-_", sub("=+$", "", b64)))
  now <- as.POSIXct(floor(as.numeric(Sys.time())), origin = "1970-01-01", tz = "UTC")
  list(key = key, entry = list(
    hash = proxy_key_hash(key), created = key_stamp(now), expires = key_stamp(now + days * 86400)
  ))
}

read_proxy_keys <- function(keys) {
  data <- jsonlite::fromJSON(paste(read_utf8_lines(keys), collapse = "\n"), simplifyVector = FALSE)
  fail <- function(...) rlang::abort(paste0(keys, ": ", ...), class = "credgate_keys_error")
  if (!is.list(data) || !identical(data$credgate_proxy_keys, 1L)) fail("not a credgate proxy keys file.")
  users <- data$users %||% list()
  out <- list()
  for (n in names(users)) {
    v <- users[[n]]
    if (rlang::is_string(v)) v <- list(hash = v) # written before keys expired
    if (!is.list(v) || !rlang::is_string(v$hash) || !startsWith(v$hash, "sha256:")) {
      fail("user '", n, "' needs a `sha256:` key hash.")
    }
    for (f in c("created", "expires")) {
      if (!is.null(v[[f]]) && (!rlang::is_string(v[[f]]) ||
        !grepl("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", v[[f]]) || is.na(key_time(v[[f]])))) {
        fail("user '", n, "': `", f, "` must be a UTC time like 2026-11-04T10:00:00Z.")
      }
    }
    out[[n]] <- v[c("hash", intersect(c("created", "expires"), names(v)))]
  }
  out
}

# The whole file at once (a reader sees the old file or the new), owner-only.
write_proxy_keys <- function(keys, users) {
  body <- list(credgate_proxy_keys = 1L, users = if (length(users)) users[sort(names(users))] else structure(list(), names = character()))
  json <- jsonlite::toJSON(body, auto_unbox = TRUE, pretty = TRUE)
  tmp <- paste0(keys, ".tmp")
  old <- Sys.umask("077")
  on.exit(Sys.umask(old), add = TRUE)
  writeLines(json, tmp, useBytes = TRUE)
  Sys.chmod(tmp, "0600", use_umask = FALSE)
  file.rename(tmp, keys)
  invisible(keys)
}

#' Who changed proxy access, and when
#'
#' Every key made, rotated or removed from the policy editor is recorded in
#' an access log beside the keys file (`keys.access.jsonl` for `keys.json`):
#' when, by whom, what, for which user and until when. Like the audit log it
#' is hash-chained, so an entry edited or removed afterwards breaks the
#' chain. Keys themselves are never recorded.
#'
#' @param keys The keys file.
#' @return A data frame of `time`, `by`, `action`, `user` and `expires`,
#'   with attribute `intact` (`TRUE` if the chain is unbroken).
#' @export
proxy_access <- function(keys) {
  log <- proxy_access_path(keys)
  empty <- data.frame(time = character(), by = character(), action = character(),
                      user = character(), expires = character())
  if (!file.exists(log)) {
    return(structure(empty, intact = TRUE))
  }
  prev <- audit_genesis
  intact <- TRUE
  recs <- list()
  for (line in audit_lines(log)) {
    rec <- tryCatch(jsonlite::fromJSON(line, simplifyVector = FALSE), error = function(e) NULL)
    if (is.null(rec) || !identical(rec$prev, prev)) {
      intact <- FALSE
      break
    }
    prev <- audit_sha256(line)
    recs[[length(recs) + 1]] <- rec
  }
  if (length(recs) == 0) {
    return(structure(empty, intact = intact))
  }
  out <- data.frame(
    time = vapply(recs, function(r) r$time, ""),
    by = vapply(recs, function(r) r$by, ""),
    action = vapply(recs, function(r) r$action, ""),
    user = vapply(recs, function(r) r$user, ""),
    expires = vapply(recs, function(r) r$expires %||% NA_character_, ""),
    stringsAsFactors = FALSE
  )
  structure(out, intact = intact)
}

proxy_access_path <- function(keys) {
  file.path(dirname(keys), paste0(sub("\\.json$", "", basename(keys)), ".access.jsonl"))
}

log_access <- function(keys, by, action, user, expires = NULL) {
  check_installed("openssl")
  log <- proxy_access_path(keys)
  last <- if (file.exists(log)) audit_last_line(log) else NULL
  record <- list(time = key_stamp(Sys.time()), by = by, action = action, user = user, expires = expires)
  record$prev <- if (is.null(last)) audit_genesis else audit_sha256(last)
  line <- as.character(jsonlite::toJSON(record[!vapply(record, is.null, TRUE)], auto_unbox = TRUE))
  con <- file(log, open = "ab")
  on.exit(close(con), add = TRUE)
  writeBin(c(charToRaw(enc2utf8(line)), as.raw(10L)), con)
}
