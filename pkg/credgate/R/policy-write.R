#' Save a policy, and see what changed
#'
#' `policy_write()` validates a policy (as [cg_policy()] does), raises its
#' revision by one, writes it as YAML in a fixed layout (to a temporary file,
#' then renamed), and appends a record to the policy's change log - who saved
#' it, when, the revisions before and after, a note, and the list of changes
#' from [policy_diff()]. The change log (`<policy name>.changes.jsonl` next to
#' the policy) is hash-chained like the audit log, so edited or removed
#' entries are detected by `policy_changes()`. The policy editor
#' ([policy_editor()]) saves with it.
#'
#' Comments in an existing policy file are not kept: use the `description`
#' fields of the policy, its endpoints and its rules instead.
#'
#' @param policy The policy as a list (as read from YAML), or a policy from
#'   [cg_policy()].
#' @param path The policy file (YAML).
#' @param user Who is saving it; recorded in the change log.
#' @param note Why, in a few words; recorded in the change log.
#' @param old,new Two policies (lists or from [cg_policy()]).
#' @return `policy_write()`: the saved policy (a list), invisibly.
#'   `policy_diff()`: a character vector, one line per change.
#'   `policy_changes()`: a data frame of the change log, with an attribute
#'   `intact` (`TRUE` if the chain is unbroken).
#' @export
#' @examples
#' path <- tempfile(fileext = ".yaml")
#' file.copy(system.file("policies", "bank-default.yaml", package = "credgate"), path)
#' policy <- yaml::read_yaml(path)
#' policy$destinations$copilot$blocked <- FALSE
#' policy_diff(yaml::read_yaml(path), policy)
#' policy_write(policy, path, user = "infosec-1", note = "Copilot approved for code")
#' policy_changes(path)[, c("revision", "user", "note")]
policy_write <- function(policy, path, user, note = "") {
  stopifnot(rlang::is_string(path), rlang::is_string(user), nzchar(user), rlang::is_string(note))
  x <- policy_list(policy)
  old <- if (file.exists(path)) yaml::yaml.load(paste(read_utf8_lines(path), collapse = "\n")) else NULL
  base <- if (is.null(old)) as.integer(x$revision %||% 0L) else as.integer(old$revision)
  x$revision <- base + 1L
  parse_policy(x, dirname(path)) # strict: never write a policy the proxy would refuse
  changes <- if (is.null(old)) "new policy" else policy_diff(old, x)
  tmp <- paste0(path, ".tmp")
  writeLines(enc2utf8(policy_yaml(x)), tmp, useBytes = TRUE)
  file.rename(tmp, path)
  policy_log_change(path, list(
    time = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
    user = user, policy = x$id, from_revision = if (is.null(old)) NULL else base,
    revision = x$revision, note = note, changes = I(changes)
  ))
  invisible(x)
}

#' @rdname policy_write
#' @export
policy_diff <- function(old, new) {
  old <- policy_list(old)
  new <- policy_list(new)
  out <- character()
  for (field in c("id", "description", "default_action", "min_confidence")) {
    if (!identical(policy_value(old[[field]]), policy_value(new[[field]]))) {
      out <- c(out, sprintf("%s: %s -> %s", field, policy_value(old[[field]]), policy_value(new[[field]])))
    }
  }
  od_files <- paste(unlist(old$detectors), collapse = ", ")
  nd_files <- paste(unlist(new$detectors), collapse = ", ")
  if (!identical(od_files, nd_files)) {
    out <- c(out, sprintf(
      "detectors: %s -> %s",
      if (nzchar(od_files)) od_files else "none", if (nzchar(nd_files)) nd_files else "none"
    ))
  }
  od <- old$destinations %||% list()
  nd <- new$destinations %||% list()
  for (name in setdiff(names(nd), names(od))) out <- c(out, sprintf("endpoint %s added (%s)", name, nd[[name]]$tier))
  for (name in setdiff(names(od), names(nd))) out <- c(out, sprintf("endpoint %s removed", name))
  for (name in intersect(names(od), names(nd))) {
    for (field in c("tier", "provider", "url", "description", "blocked")) {
      a <- policy_value(od[[name]][[field]], if (field == "blocked") "false" else "")
      b <- policy_value(nd[[name]][[field]], if (field == "blocked") "false" else "")
      if (!identical(a, b)) out <- c(out, sprintf("endpoint %s: %s %s -> %s", name, field, a, b))
    }
  }
  oid <- vapply(old$rules %||% list(), function(r) r$id, "")
  nid <- vapply(new$rules %||% list(), function(r) r$id, "")
  for (id in setdiff(nid, oid)) {
    r <- new$rules[[match(id, nid)]]
    out <- c(out, sprintf("rule %s added at %d: %s", id, match(id, nid), policy_rule_text(r)))
  }
  for (id in setdiff(oid, nid)) out <- c(out, sprintf("rule %s removed", id))
  for (id in intersect(oid, nid)) {
    a <- old$rules[[match(id, oid)]]
    b <- new$rules[[match(id, nid)]]
    if (!identical(policy_rule_when(a), policy_rule_when(b))) {
      out <- c(out, sprintf("rule %s: conditions %s -> %s", id, policy_rule_when(a), policy_rule_when(b)))
    }
    if (!identical(a$action, b$action)) {
      out <- c(out, sprintf("rule %s: action %s -> %s", id, a$action, b$action))
    }
    if (!identical(policy_value(a$description), policy_value(b$description))) {
      out <- c(out, sprintf("rule %s: description changed", id))
    }
  }
  kept_old <- oid[oid %in% nid]
  kept_new <- nid[nid %in% oid]
  if (!identical(kept_old, kept_new)) {
    for (id in kept_new[kept_new != kept_old]) {
      out <- c(out, sprintf("rule %s moved from %d to %d", id, match(id, oid), match(id, nid)))
    }
  }
  out
}

#' @rdname policy_write
#' @export
policy_changes <- function(path) {
  log <- policy_changes_path(path)
  empty <- data.frame(
    time = character(), user = character(), policy = character(), revision = integer(),
    note = character(), changes = I(list())
  )
  if (!file.exists(log)) {
    return(structure(empty, intact = TRUE))
  }
  lines <- audit_lines(log)
  prev <- audit_genesis
  intact <- TRUE
  recs <- list()
  for (line in lines) {
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
    user = vapply(recs, function(r) r$user, ""),
    policy = vapply(recs, function(r) r$policy, ""),
    revision = vapply(recs, function(r) as.integer(r$revision), 1L),
    note = vapply(recs, function(r) r$note %||% "", ""),
    changes = I(lapply(recs, function(r) unlist(r$changes) %||% character()))
  )
  structure(out, intact = intact)
}

policy_changes_path <- function(path) {
  file.path(dirname(path), paste0(audit_stem(path)$stem, ".changes.jsonl"))
}

policy_log_change <- function(path, record) {
  check_installed("openssl")
  log <- policy_changes_path(path)
  last <- if (file.exists(log)) audit_last_line(log) else NULL
  record$prev <- if (is.null(last)) audit_genesis else audit_sha256(last)
  line <- as.character(jsonlite::toJSON(record, auto_unbox = TRUE, null = "null", digits = NA))
  con <- file(log, open = "ab")
  on.exit(close(con), add = TRUE)
  writeBin(c(charToRaw(enc2utf8(line)), as.raw(10L)), con)
}

# A policy as a plain list, as read from YAML.
policy_list <- function(policy) {
  if (inherits(policy, "cg_policy")) {
    policy <- attr(policy, "source") %||% rlang::abort("This policy was not loaded from a list or file.")
  }
  if (!is.list(policy)) {
    rlang::abort("`policy` must be a policy list or a policy from `cg_policy()`.")
  }
  policy
}

policy_value <- function(x, default = "") {
  if (is.null(x) || length(x) == 0) {
    return(default)
  }
  if (is.logical(x)) tolower(format(x)) else paste(format(x), collapse = ", ")
}

policy_rule_when <- function(r) {
  when <- r$when %||% list()
  parts <- vapply(
    intersect(c("destinations", "tiers", "types", "classes", "all_of"), names(when)),
    function(k) sprintf("%s %s", k, paste(unlist(when[[k]]), collapse = "/")), ""
  )
  if (length(parts)) paste0("when ", paste(parts, collapse = " and ")) else "always"
}

policy_rule_text <- function(r) paste0(policy_rule_when(r), ": ", r$action)

# The policy as YAML, in a fixed layout and field order.
policy_yaml <- function(x) {
  q <- function(s) {
    s <- as.character(s)
    if (grepl("^[A-Za-z0-9_][A-Za-z0-9_./:-]*$", s) && !tolower(s) %in% c("true", "false", "yes", "no", "null", "on", "off")) {
      s
    } else {
      # A JSON string is a valid YAML double-quoted scalar, newlines included.
      as.character(jsonlite::toJSON(s, auto_unbox = TRUE))
    }
  }
  qs <- function(v) paste0("[", paste(vapply(unlist(v), q, ""), collapse = ", "), "]")
  out <- c(
    "policy: credgate-policy", "version: 1",
    paste0("id: ", q(x$id)), paste0("revision: ", as.integer(x$revision))
  )
  if (!is.null(x$description) && nzchar(x$description)) out <- c(out, paste0("description: ", q(x$description)))
  if (length(x$detectors)) out <- c(out, paste0("detectors: ", qs(x$detectors)))
  out <- c(out, "", "destinations:")
  for (name in names(x$destinations)) {
    d <- x$destinations[[name]]
    out <- c(out, paste0("  ", q(name), ":"), paste0("    tier: ", q(d$tier)))
    for (field in c("provider", "url", "description")) {
      if (!is.null(d[[field]]) && nzchar(d[[field]])) out <- c(out, paste0("    ", field, ": ", q(d[[field]])))
    }
    if (isTRUE(d$blocked)) out <- c(out, "    blocked: true")
  }
  if (!is.null(x$min_confidence)) out <- c(out, "", paste0("min_confidence: ", format(x$min_confidence)))
  out <- c(out, "", if (length(x$rules)) "rules:" else "rules: []")
  for (r in x$rules) {
    out <- c(out, paste0("  - id: ", q(r$id)))
    if (!is.null(r$description) && nzchar(r$description)) out <- c(out, paste0("    description: ", q(r$description)))
    when <- r$when %||% list()
    keys <- intersect(c("destinations", "tiers", "types", "classes", "all_of"), names(when))
    if (length(keys)) {
      out <- c(out, "    when:", paste0("      ", keys, ": ", vapply(keys, function(k) qs(when[[k]]), "")))
    }
    out <- c(out, paste0("    action: ", q(r$action)))
  }
  c(out, "", paste0("default_action: ", q(x$default_action)), "")
}
