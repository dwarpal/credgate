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
#' identifier decides its action; a rule's `when` can name `tiers`, `types`,
#' `classes`, and `all_of` - types that must all occur in the request (for
#' example a card number with its CVV and expiry date). Any `block` blocks
#' the whole request.
#'
#' @param x Path to a policy file (YAML), or the policy as a list.
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
cg_policy <- function(x) {
  if (rlang::is_string(x)) {
    x <- yaml::yaml.load(paste(read_utf8_lines(x), collapse = "\n"))
  }
  parse_policy(x)
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

parse_policy <- function(x) {
  if (!is.list(x) || !identical(x$policy, "credgate-policy")) {
    policy_fail("Not a credgate policy: it must start with `policy: credgate-policy`.")
  }
  check_policy_fields(x, c(
    "policy", "version", "id", "revision", "description", "destinations",
    "min_confidence", "rules", "default_action"
  ), "policy")
  if (!identical(as.numeric(x$version), 1)) {
    policy_fail("Unsupported policy format version ", format(x$version), ".")
  }
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
  tiers <- vapply(names(dests), function(name) {
    d <- dests[[name]]
    if (!is.list(d)) {
      policy_fail("Destination '", name, "' must be a mapping with a `tier`.")
    }
    check_policy_fields(d, c("tier", "description"), paste0("destination '", name, "'"))
    if (!rlang::is_string(d$tier) || !d$tier %in% policy_tiers) {
      policy_fail(
        "Destination '", name, "': unknown tier '", format(d$tier), "'; tiers are ",
        paste(policy_tiers, collapse = ", "), "."
      )
    }
    d$tier
  }, character(1))

  known_types <- cg_detectors()$id
  known_classes <- union(policy_classes, cg_detectors()$class)
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
    check_policy_fields(when, c("tiers", "types", "classes", "all_of"), paste0("rule '", r$id, "' `when`"))
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
      destinations = tiers, min_confidence = as.numeric(min_conf),
      rules = rules, default_action = default
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
#' @return An object of class `cg_decision`: a list with `policy_id`,
#'   `policy_revision`, `destination`, `tier`, `allowed`, `blocked_by` (rule
#'   ids), `matches` (a data frame of the identifiers with their `action` and
#'   deciding `rule`, `"default"` when no rule matched) and `text` (the
#'   rewritten texts, or `NULL`).
#' @export
policy_decide <- function(policy, text, destination) {
  check_policy(policy)
  tier <- policy_tier(policy, destination)
  text <- from_arrow(text)$text
  docs <- ifelse(is.na(text), "", text)
  spans <- detect_pii(docs, min_confidence = policy$min_confidence)
  found <- unique(spans$type)
  action <- rep(NA_character_, nrow(spans))
  rule <- rep(NA_character_, nrow(spans))
  for (r in policy$rules) {
    hit <- is.na(action) &
      (is.null(r$tiers) | tier %in% r$tiers) &
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
  blocked <- unique(rule[action == "block"])
  structure(
    list(
      policy_id = policy$id, policy_revision = policy$revision,
      destination = destination, tier = tier,
      allowed = length(blocked) == 0, blocked_by = blocked,
      matches = matches, text = NULL
    ),
    class = "cg_decision"
  )
}

#' @rdname policy_decide
#' @export
policy_apply <- function(policy, text, destination, vault = NULL) {
  decision <- policy_decide(policy, text, destination)
  if (!decision$allowed) {
    return(decision)
  }
  m <- decision$matches
  if (is.null(vault) && any(m$action == "tokenise")) {
    policy_fail("This policy tokenises; pass a vault to apply it.")
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

policy_tier <- function(policy, destination) {
  stopifnot(rlang::is_string(destination))
  tier <- policy$destinations[destination]
  if (is.na(tier)) {
    known <- if (length(policy$destinations)) paste(sort(names(policy$destinations)), collapse = ", ") else "none"
    policy_fail("Unknown destination '", destination, "' for policy ", policy$id, "; known: ", known, ".")
  }
  unname(tier)
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
