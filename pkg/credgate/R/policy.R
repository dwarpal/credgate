# Policies: what happens to each identifier in a request to a destination
# (the spec's "Policies" rules).

policy_tiers <- c("local", "internal", "frontier")
policy_actions <- c("allow", "redact", "tokenise", "block")
policy_classes <- c(
  "identity_strong", "financial", "sensitive_auth", "health", "contact",
  "personal", "quasi"
)

#' Load a policy
#'
#' A policy decides, for one request to one destination, what happens to
#' each identifier found in it: let it through, redact it, tokenise it, or
#' block the whole request. Policies are YAML files written by InfoSec and
#' compliance; the same file works in R and Python. Everything is checked
#' when the policy is loaded - unknown fields, tiers, actions, types or
#' classes are errors - so a policy that cannot be read correctly is never
#' applied.
#'
#' Destinations have a tier: `local` (this machine), `internal` (the
#' organisation's own network or hosting) or `frontier` (an external model
#' provider). Rules are tried in order and the first that matches an
#' identifier decides its action; a rule's `when` can name particular
#' `destinations`, `tiers`, `types`, `classes`, and `all_of` - types that must
#' all occur in the request (for example a card number with its CVV and expiry
#' date). Any `block` blocks the whole request. A destination that is not
#' listed receives nothing: requests to it are refused.
#'
#' A policy can name custom detector files in a `detectors` list (see
#' [load_detectors()]), relative to the policy file; they are loaded first,
#' so its rules can name their types.
#'
#' @param x Path to a policy file (YAML), or the policy as a list.
#' @param dir When `x` is a list: the folder its custom detector files are
#'   relative to (default: the working directory).
#' @return An object of class `cg_policy`.
#' @seealso [policy_decide()], [policy_apply()]; the format is described in
#'   the spec (`cg_spec_path()`, README, "Policies").
#' @export
#' @examples
#' policy <- cg_policy(list(
#'   policy = "credgate-policy", version = 1L, id = "example", revision = 1L,
#'   destinations = list(ollama = list(tier = "local"), claude = list(tier = "frontier")),
#'   rules = list(
#'     list(
#'       id = "card-with-cvv", action = "block",
#'       when = list(tiers = list("frontier"), all_of = list("card", "card_cvv"))
#'     ),
#'     list(id = "in-house", action = "allow", when = list(tiers = list("local")))
#'   ),
#'   default_action = "redact"
#' ))
#' policy_apply(policy, "Card 4111 1111 1111 1111, CVV 123", "claude")
#' policy_apply(policy, "PAN ABCPE1234F", "claude")
cg_policy <- function(x, dir = NULL) {
  if (rlang::is_string(x)) {
    dir <- dirname(x)
    x <- yaml::yaml.load(paste(read_utf8_lines(x), collapse = "\n"))
  }
  structure(parse_policy(x, dir %||% getwd()), source = x)
}

# Custom detector files named by a policy, compiled for the policy alone (not
# registered), so rules can name their types and a policy loaded later never
# changes what this one detects. A named list of detectors.
load_policy_detectors <- function(files, dir) {
  if (is.null(files)) {
    return(list())
  }
  files <- unlist(files)
  if (!is.character(files) || any(!nzchar(files)) || is.list(files)) {
    policy_fail("`detectors` must be a list of custom detector files.")
  }
  out <- list()
  for (f in files) {
    path <- if (grepl("^(/|~|[A-Za-z]:)", f)) f else file.path(dir, f)
    if (!file.exists(path)) {
      policy_fail("Custom detectors ", f, ": file not found (", path, ").")
    }
    compiled <- tryCatch(
      compile_detector_file(yaml::yaml.load(paste(read_utf8_lines(path), collapse = "\n"))),
      error = function(e) policy_fail("Custom detectors ", f, ": ", conditionMessage(e))
    )
    for (c in compiled) {
      id <- c$detector$id
      if (id %in% the$builtin_ids) {
        policy_fail("Custom detectors ", f, ": `", id, "` is the id of a built-in detector.")
      }
      if (id %in% names(out)) {
        policy_fail("Custom detectors ", f, ": `", id, "` is also in another file.")
      }
      out[[id]] <- c$detector
    }
  }
  out
}

read_utf8_lines <- function(path) {
  lines <- readLines(path, encoding = "UTF-8", warn = FALSE)
  Encoding(lines) <- "UTF-8"
  lines
}

policy_fail <- function(...) {
  rlang::abort(paste0(...), class = "credgate_policy_error")
}

check_policy_fields <- function(x, allowed, where) {
  unknown <- sort(setdiff(names(x), allowed))
  if (length(unknown) > 0) {
    policy_fail("Unknown field(s) in ", where, ": ", paste(unknown, collapse = ", "), ".")
  }
}

parse_policy <- function(x, dir = getwd()) {
  if (!is.list(x) || !identical(x$policy, "credgate-policy")) {
    policy_fail("Not a credgate policy: it must start with `policy: credgate-policy`.")
  }
  check_policy_fields(x, c(
    "policy", "version", "id", "revision", "description", "detectors", "destinations",
    "min_confidence", "rules", "default_action"
  ), "policy")
  if (!identical(as.numeric(x$version), 1)) {
    policy_fail("Unsupported policy format version ", format(x$version), ".")
  }
  # The detectors this policy decides with: those registered now, and its own.
  detectors <- the$detectors
  own <- load_policy_detectors(x$detectors, dir)
  detectors[names(own)] <- own
  if (!rlang::is_string(x$id) || !nzchar(x$id)) {
    policy_fail("The policy needs an `id`.")
  }
  rev <- x$revision
  if (is.logical(rev) || !rlang::is_scalar_integerish(rev) || rev < 1) {
    policy_fail("`revision` must be a positive whole number.")
  }
  min_conf <- x$min_confidence %||% 0
  if (!is.numeric(min_conf) || length(min_conf) != 1 || is.na(min_conf) ||
    min_conf < 0 || min_conf > 1) {
    policy_fail("`min_confidence` must be a number from 0 to 1.")
  }

  dests <- x$destinations
  if (!is.list(dests) || length(dests) == 0 || is.null(names(dests))) {
    policy_fail("The policy needs at least one destination.")
  }
  destinations <- lapply(names(dests), function(name) {
    d <- dests[[name]]
    if (!is.list(d)) {
      policy_fail("Destination '", name, "' must be a mapping with a `tier`.")
    }
    check_policy_fields(
      d, c("tier", "provider", "url", "description", "blocked"),
      paste0("destination '", name, "'")
    )
    if (!rlang::is_string(d$tier) || !d$tier %in% policy_tiers) {
      policy_fail(
        "Destination '", name, "': unknown tier '", format(d$tier), "'; tiers are ",
        paste(policy_tiers, collapse = ", "), "."
      )
    }
    if (!is.null(d$blocked) && !rlang::is_bool(d$blocked)) {
      policy_fail("Destination '", name, "': `blocked` must be true or false.")
    }
    for (key in c("provider", "url", "description")) {
      if (!is.null(d[[key]]) && !rlang::is_string(d[[key]])) {
        policy_fail("Destination '", name, "': `", key, "` must be text.")
      }
    }
    list(
      name = name, tier = d$tier, provider = d$provider, url = d$url,
      description = d$description, blocked = isTRUE(d$blocked)
    )
  })
  names(destinations) <- names(dests)
  tiers <- vapply(destinations, `[[`, character(1), "tier")

  known_types <- names(detectors)
  known_classes <- union(policy_classes, vapply(detectors, `[[`, "", "class"))
  raw_rules <- x$rules
  if (!is.list(raw_rules)) {
    policy_fail("`rules` must be a list (it may be empty).")
  }
  ids <- character()
  rules <- lapply(raw_rules, function(r) {
    if (!is.list(r) || !rlang::is_string(r$id)) {
      policy_fail("Every rule needs an `id`.")
    }
    if (r$id %in% ids) {
      policy_fail("Duplicate rule id '", r$id, "'.")
    }
    ids <<- c(ids, r$id)
    check_policy_fields(r, c("id", "description", "when", "action"), paste0("rule '", r$id, "'"))
    if (!rlang::is_string(r$action) || !r$action %in% policy_actions) {
      policy_fail(
        "Rule '", r$id, "': unknown action '", format(r$action), "'; actions are ",
        paste(policy_actions, collapse = ", "), "."
      )
    }
    when <- r$when %||% list()
    if (!is.list(when)) {
      policy_fail("Rule '", r$id, "': `when` must be a mapping.")
    }
    check_policy_fields(
      when, c("destinations", "tiers", "types", "classes", "all_of"),
      paste0("rule '", r$id, "' `when`")
    )
    condition <- function(key, allowed, what) {
      if (is.null(when[[key]])) {
        return(NULL)
      }
      values <- unlist(when[[key]])
      if (!is.character(values) || length(values) == 0) {
        policy_fail("Rule '", r$id, "': `", key, "` must be a non-empty list.")
      }
      unknown <- setdiff(values, allowed)
      if (length(unknown) > 0) {
        policy_fail("Rule '", r$id, "': unknown ", what, " ", paste(unknown, collapse = ", "), ".")
      }
      values
    }
    list(
      id = r$id, action = r$action, description = r$description,
      destinations = condition("destinations", names(tiers), "destination"),
      tiers = condition("tiers", policy_tiers, "tier"),
      types = condition("types", known_types, "type"),
      classes = condition("classes", known_classes, "class"),
      all_of = condition("all_of", known_types, "type")
    )
  })

  default <- x$default_action
  if (!rlang::is_string(default) || !default %in% policy_actions) {
    policy_fail(
      "`default_action` must be one of ", paste(policy_actions, collapse = ", "),
      ", not '", format(default), "'."
    )
  }
  structure(
    list(
      id = x$id, revision = as.integer(rev), description = x$description,
      destinations = destinations, min_confidence = as.numeric(min_conf),
      rules = rules, default_action = default, detectors = detectors
    ),
    class = "cg_policy"
  )
}

#' Decide and apply a policy to a request
#'
#' `policy_decide()` works out what the policy does with each identifier in a
#' request to `destination`, without changing the text. `policy_apply()` also
#' rewrites the text when the request is allowed: identifiers to redact become
#' placeholders such as `[PAN]`, identifiers to tokenise become tokens from
#' `vault`. A blocked request gets no text: nothing may be sent.
#'
#' @param policy A policy from [cg_policy()].
#' @param text The texts of one request (for example the messages of a chat).
#' @param destination Name of a destination in the policy; an unknown one is
#'   an error.
#' @param vault A vault from [cg_vault()], needed when the policy tokenises.
#' @param audit An audit log from [cg_audit_log()]: the decision is recorded,
#'   blocked or not. A request that cannot be applied (a policy that
#'   tokenises, without a vault) fails before anything is recorded, since
#'   nothing is sent.
#' @return An object of class `cg_decision`: a list with `policy_id`,
#'   `policy_revision`, `destination`, `tier`, `provider`, `url`, `allowed`,
#'   `blocked_by` (`"destination-blocked"` and rule ids), `matches` (a data frame of the identifiers with their `action` and
#'   deciding `rule`, `"default"` when no rule matched) and `text` (the
#'   rewritten texts, or `NULL`).
#' @export
policy_decide <- function(policy, text, destination) {
  check_policy(policy)
  dest <- policy_destination(policy, destination)
  tier <- dest$tier
  text <- from_arrow(text)$text
  docs <- ifelse(is.na(text), "", text)
  spans <- detect_with(policy$detectors %||% get_detectors(NULL), docs, min_confidence = policy$min_confidence)
  found <- unique(spans$type)
  action <- rep(NA_character_, nrow(spans))
  rule <- rep(NA_character_, nrow(spans))
  for (r in policy$rules) {
    hit <- is.na(action) &
      (is.null(r$destinations) || destination %in% r$destinations) &
      (is.null(r$tiers) || tier %in% r$tiers) &
      (if (is.null(r$types)) TRUE else spans$type %in% r$types) &
      (if (is.null(r$classes)) TRUE else spans$class %in% r$classes) &
      (is.null(r$all_of) || all(r$all_of %in% found))
    action[hit] <- r$action
    rule[hit] <- r$id
  }
  rule[is.na(action)] <- "default"
  action[is.na(action)] <- policy$default_action
  matches <- as.data.frame(unclass(spans))
  matches$action <- action
  matches$rule <- rule
  blocked <- c(if (dest$blocked) "destination-blocked", unique(rule[action == "block"]))
  structure(
    list(
      policy_id = policy$id, policy_revision = policy$revision,
      destination = destination, tier = tier, provider = dest$provider, url = dest$url,
      allowed = length(blocked) == 0, blocked_by = as.character(blocked),
      matches = matches, text = NULL
    ),
    class = "cg_decision"
  )
}

#' @rdname policy_decide
#' @export
policy_apply <- function(policy, text, destination, vault = NULL, audit = NULL) {
  decision <- policy_decide(policy, text, destination)
  m <- decision$matches
  # Checked before recording: a request that cannot be applied is never
  # sent, so it must not appear in the audit log as allowed.
  if (decision$allowed && is.null(vault) && any(m$action == "tokenise")) {
    policy_fail("This policy tokenises; pass a vault to apply it.")
  }
  if (!is.null(audit)) {
    audit_record(audit, decision)
  }
  if (!decision$allowed) {
    return(decision)
  }
  text <- from_arrow(text)$text
  docs <- ifelse(is.na(text), "", text)
  change <- m[m$action %in% c("redact", "tokenise"), , drop = FALSE]
  value <- placeholder(change$type)
  tok <- change$action == "tokenise"
  if (any(tok)) {
    value[tok] <- tokens_for(vault, change[tok, , drop = FALSE])
  }
  out <- replace_spans(docs, change, value)
  out[is.na(text)] <- NA_character_
  decision$text <- out
  decision
}

policy_destination <- function(policy, destination) {
  stopifnot(rlang::is_string(destination))
  dest <- policy$destinations[[destination]]
  if (is.null(dest)) {
    known <- if (length(policy$destinations)) paste(sort(names(policy$destinations)), collapse = ", ") else "none"
    policy_fail("Unknown destination '", destination, "' for policy ", policy$id, "; known: ", known, ".")
  }
  dest
}

check_policy <- function(policy) {
  if (!inherits(policy, "cg_policy")) {
    rlang::abort("`policy` must be a policy from `cg_policy()`.")
  }
}

#' @export
print.cg_policy <- function(x, ...) {
  cli::cli_text(
    "Policy {.strong {x$id}} revision {x$revision}: {length(x$rules)} rule{?s}, ",
    "{length(x$destinations)} destination{?s}"
  )
  invisible(x)
}

#' @export
print.cg_decision <- function(x, ...) {
  status <- if (x$allowed) "allowed" else paste("BLOCKED by", paste(x$blocked_by, collapse = ", "))
  cli::cli_text(
    "Policy {x$policy_id} (revision {x$policy_revision}), destination {x$destination} ",
    "({x$tier}): {status}"
  )
  if (nrow(x$matches) > 0) {
    print(data.frame(
      placeholder = placeholder(x$matches$type), action = x$matches$action,
      rule = x$matches$rule
    ), row.names = FALSE)
  }
  invisible(x)
}
