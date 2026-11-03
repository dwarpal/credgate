#' Run a policy's tests
#'
#' Policy tests are sample requests and what the policy must do with them -
#' allow or block, which rules block, the action for each type, the exact
#' text sent - written by the people who own the policy and kept beside it
#' (`bank-default.tests.yaml` for `bank-default.yaml`). They run in the
#' policy editor before every save and with `credgate policy test` in CI, so
#' a change that breaks an agreed behaviour is caught before it is used. The
#' format is in the spec ("Policy tests"); Python reads the same files.
#'
#' @param policy A policy from [cg_policy()], or a policy file.
#' @param tests A tests file, or its contents as a list. By default the file
#'   beside the policy file, with `.tests.yaml` in place of `.yaml`.
#' @return A data frame with one row per test: `id`, `passed`, `problems`
#'   (a list of character vectors: every expectation that did not hold) and
#'   `description`.
#' @export
#' @examples
#' policy <- cg_policy(system.file("policies", "bank-default.yaml", package = "credgate"))
#' run_policy_tests(policy, list(
#'   kind = "credgate-policy-tests", version = 1,
#'   tests = list(list(
#'     id = "card-blocked-for-claude", endpoint = "claude",
#'     text = "Card 4111 1111 1111 1111, CVV 123, expiry 08/29",
#'     expect = list(allowed = FALSE, blocked_by = list("card-with-cvv-and-expiry"))
#'   ))
#' ))
run_policy_tests <- function(policy, tests = NULL) {
  if (is.null(tests)) {
    if (!rlang::is_string(policy)) {
      rlang::abort("Give the tests file when the policy is not a file.")
    }
    tests <- policy_tests_path(policy)
  }
  if (rlang::is_string(policy)) {
    policy <- cg_policy(policy)
  }
  name <- if (rlang::is_string(tests)) tests else "policy tests"
  data <- if (rlang::is_string(tests)) {
    yaml::yaml.load(paste(read_utf8_lines(tests), collapse = "\n"))
  } else {
    tests
  }
  cases <- tryCatch(validate_policy_tests(data), error = function(e) {
    rlang::abort(paste0(name, ": ", conditionMessage(e)), call = NULL)
  })
  results <- lapply(cases, run_one_policy_test, policy = policy)
  data.frame(
    id = vapply(results, `[[`, "", "id"),
    passed = vapply(results, `[[`, TRUE, "passed"),
    problems = I(lapply(results, `[[`, "problems")),
    description = vapply(results, function(r) r$description %||% NA_character_, ""),
    stringsAsFactors = FALSE
  )
}

policy_tests_path <- function(policy_file) {
  file.path(dirname(policy_file), paste0(sub("\\.ya?ml$", "", basename(policy_file)), ".tests.yaml"))
}

validate_policy_tests <- function(data) {
  fail <- function(...) stop(..., call. = FALSE)
  if (!is.list(data) || !identical(data$kind, "credgate-policy-tests")) {
    fail("not a policy tests file: `kind` must be `credgate-policy-tests`.")
  }
  unknown <- setdiff(names(data), c("kind", "version", "tests"))
  if (length(unknown) > 0) fail("unknown field(s): ", paste(sort(unknown), collapse = ", "), ".")
  if (!identical(as.numeric(data$version), 1)) fail("`version` must be 1.")
  tests <- data$tests
  if (!is.list(tests) || length(tests) == 0) fail("`tests` must be a non-empty list.")
  types <- cg_detectors()$id
  seen <- character()
  for (t in tests) {
    id <- t$id
    if (!rlang::is_string(id) || !nzchar(id)) fail("every test needs an `id`.")
    if (id %in% seen) fail("test `", id, "` appears twice.")
    seen <- c(seen, id)
    where <- paste0("test `", id, "`")
    unknown <- setdiff(names(t), c("id", "description", "endpoint", "text", "texts", "expect"))
    if (length(unknown) > 0) fail(where, ": unknown field(s): ", paste(sort(unknown), collapse = ", "), ".")
    if (!rlang::is_string(t$endpoint)) fail(where, ": needs an `endpoint`.")
    if (is.null(t[["text"]]) == is.null(t[["texts"]])) fail(where, ": give exactly one of `text` or `texts`.")
    if (!is.null(t[["text"]]) && !rlang::is_string(t[["text"]])) fail(where, ": `text` must be text.")
    if (!is.null(t[["texts"]]) && !is.character(unlist(t[["texts"]]))) fail(where, ": `texts` must be a list of texts.")
    e <- t$expect
    if (!is.list(e)) fail(where, ": needs `expect`.")
    unknown <- setdiff(names(e), c("allowed", "blocked_by", "actions", "absent", "output"))
    if (length(unknown) > 0) {
      fail(where, ": unknown field(s) in `expect`: ", paste(sort(unknown), collapse = ", "), ".")
    }
    if (!rlang::is_bool(e$allowed)) fail(where, ": `expect.allowed` must be true or false.")
    for (typ in c(names(e$actions), unlist(e$absent))) {
      if (!typ %in% types) fail(where, ": unknown type `", typ, "`.")
    }
    for (typ in names(e$actions)) {
      a <- e$actions[[typ]]
      if (!rlang::is_string(a) || !a %in% policy_actions) {
        fail(
          where, ": `", typ, "`: unknown action `", format(a), "`; actions are ",
          paste(policy_actions, collapse = ", "), "."
        )
      }
    }
    if (!is.null(e$output)) {
      ok <- if (!is.null(t[["text"]])) rlang::is_string(e$output) else is.character(unlist(e$output))
      if (!ok) fail(where, ": `expect.output` must be a text for `text`, a list for `texts`.")
    }
  }
  tests
}

run_one_policy_test <- function(t, policy) {
  e <- t$expect
  problems <- character()
  texts <- if (!is.null(t[["text"]])) t[["text"]] else unlist(t[["texts"]])
  if (!t$endpoint %in% names(policy$destinations)) {
    problems <- c(problems, paste0("unknown endpoint `", t$endpoint, "` (not in the policy)"))
  } else {
    d <- policy_apply(policy, texts, t$endpoint, vault = cg_vault())
    if (!identical(d$allowed, e$allowed)) {
      problems <- c(problems, sprintf("allowed: expected %s, got %s", tolower(e$allowed), tolower(d$allowed)))
    }
    if (!is.null(e$blocked_by)) {
      want <- sort(unlist(e$blocked_by))
      got <- sort(as.character(d$blocked_by))
      if (!identical(want, got)) {
        problems <- c(problems, sprintf(
          "blocked_by: expected %s, got %s",
          if (length(want)) paste(want, collapse = ", ") else "none",
          if (length(got)) paste(got, collapse = ", ") else "none"
        ))
      }
    }
    m <- d$matches
    for (typ in names(e$actions)) {
      want <- e$actions[[typ]]
      got <- m$action[m$type == typ]
      if (length(got) == 0) {
        problems <- c(problems, sprintf("%s: expected %s, not found", typ, want))
      } else if (any(got != want)) {
        problems <- c(problems, sprintf("%s: expected %s, got %s", typ, want, paste(sort(unique(got)), collapse = ", ")))
      }
    }
    for (typ in unlist(e$absent)) {
      if (typ %in% m$type) problems <- c(problems, sprintf("%s: expected absent, found", typ))
    }
    if (!is.null(e$output)) {
      want <- unlist(e$output)
      if (!isTRUE(d$allowed)) {
        problems <- c(problems, "output: expected texts, but the request was blocked")
      } else if (!identical(as.character(d$text), as.character(want))) {
        problems <- c(problems, sprintf(
          "output: expected '%s', got '%s'",
          paste(want, collapse = "', '"), paste(d$text, collapse = "', '")
        ))
      }
    }
  }
  list(id = t$id, passed = length(problems) == 0, problems = problems, description = t$description)
}

# Writes a tests file (from the policy editor). Logicals as true/false, which
# Python and other YAML 1.2 readers read the same way.
write_policy_tests <- function(tests, file) {
  data <- list(kind = "credgate-policy-tests", version = 1L, tests = tests)
  validate_policy_tests(data)
  text <- yaml::as.yaml(data, indent.mapping.sequence = TRUE, handlers = list(
    logical = function(x) structure(ifelse(x, "true", "false"), class = "verbatim")
  ))
  tmp <- paste0(file, ".tmp")
  writeLines(enc2utf8(text), tmp, useBytes = TRUE, sep = "")
  file.rename(tmp, file)
  invisible(file)
}

# A test that pins what the policy does with a request now: whether it is
# allowed, the rules that block it and the action for each type found.
policy_test_from_decision <- function(id, text, endpoint, d) {
  m <- d$matches
  types <- unique(m$type)
  actions <- lapply(types, function(t) {
    a <- unique(m$action[m$type == t])
    if (length(a) == 1) a
  })
  names(actions) <- types
  actions <- Filter(Negate(is.null), actions)
  expect <- list(allowed = isTRUE(d$allowed))
  if (!isTRUE(d$allowed)) {
    expect$blocked_by <- as.list(as.character(d$blocked_by))
  } else if (length(actions)) {
    expect$actions <- actions # in a blocked request every match is blocked
  }
  list(id = id, endpoint = endpoint, text = text, expect = expect)
}
