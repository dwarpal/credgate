#' Load custom detectors from a YAML file
#'
#' Organisations describe their own formats - loan account numbers, customer
#' ids - in a YAML file with the fields of the built-in detectors (see the
#' spec, "Custom detectors"), with its own `fragments` and `lists` and, per
#' detector, `examples` that must (`match`) and must not (`no_match`) be
#' found. R, Python, the command line and the proxy load the same file the
#' same way.
#'
#' Everything is checked before anything is registered: unknown fields, ids
#' (not a built-in one), data classes, patterns and every example. A file
#' is registered completely or not at all; loading it again changes nothing.
#' A policy can name its custom detector files in a `detectors` list (see
#' [cg_policy()]).
#'
#' @param source A YAML file, or its contents as a list.
#' @param replace Allow a different definition under an id that a custom
#'   file already registered.
#' @return The ids of the file's detectors, invisibly.
#' @export
#' @examples
#' path <- tempfile(fileext = ".yaml")
#' writeLines(c(
#'   "kind: credgate-detectors",
#'   "version: 1",
#'   "detectors:",
#'   "  - id: loan_account",
#'   "    class: financial",
#'   "    label: Loan account number",
#'   "    patterns: ['LN[0-9]{10}']",
#'   "    bounded: true",
#'   "    context: 'loan|\\ba/c\\b'",
#'   "    base: 0.6",
#'   "    base_without_context: 0.4",
#'   "    examples:",
#'   "      match: ['Loan a/c LN0012345678']",
#'   "      no_match: ['LN00123']"
#' ), path)
#' load_detectors(path)
#' detect_pii("Loan a/c LN0012345678 is overdue")
load_detectors <- function(source, replace = FALSE) {
  name <- if (rlang::is_string(source)) source else "custom detectors"
  data <- if (rlang::is_string(source)) {
    yaml::yaml.load(paste(read_utf8_lines(source), collapse = "\n"))
  } else {
    source
  }
  compiled <- tryCatch(compile_detector_file(data), error = function(e) {
    rlang::abort(paste0(name, ": ", conditionMessage(e)), call = NULL)
  })
  for (c in compiled) {
    id <- c$detector$id
    if (id %in% the$builtin_ids) {
      rlang::abort(paste0(name, ": `", id, "` is the id of a built-in detector."))
    }
    if (id %in% names(the$detectors) && !identical(the$custom[[id]], c$digest) && !replace) {
      rlang::abort(paste0(
        name, ": a different detector `", id, "` is already registered; ",
        "use replace = TRUE to replace it."
      ))
    }
  }
  for (c in compiled) {
    the$detectors[[c$detector$id]] <- c$detector
    the$custom[[c$detector$id]] <- c$digest
  }
  invisible(vapply(compiled, function(c) c$detector$id, character(1)))
}

custom_classes <- c(
  "identity_strong", "financial", "sensitive_auth", "health", "contact", "personal", "quasi"
)

compile_detector_file <- function(data) {
  if (!is.list(data) || !identical(data$kind, "credgate-detectors")) {
    stop("not a custom detectors file: `kind` must be `credgate-detectors`.", call. = FALSE)
  }
  unknown <- setdiff(names(data), c("kind", "version", "fragments", "lists", "detectors"))
  if (length(unknown) > 0) {
    stop("unknown field(s): ", paste(sort(unknown), collapse = ", "), ".", call. = FALSE)
  }
  if (!identical(as.numeric(data$version), 1)) {
    stop("`version` must be 1.", call. = FALSE)
  }
  fragments <- data$fragments %||% list()
  lists <- data$lists %||% list()
  for (key in names(fragments)) {
    if (key %in% names(the$fragments)) {
      stop("fragment `", key, "` is a built-in name; choose another.", call. = FALSE)
    }
  }
  for (key in names(lists)) {
    if (key %in% names(the$lists)) {
      stop("list `", key, "` is a built-in name; choose another.", call. = FALSE)
    }
    words <- unlist(lists[[key]])
    if (!is.character(words) || any(grepl("[\\\\^$.|?*+()\\[\\]{}]", words, perl = TRUE))) {
      stop("list `", key, "` must be literal words, without regex characters.", call. = FALSE)
    }
  }
  defs <- data$detectors
  if (!is.list(defs) || length(defs) == 0) {
    stop("`detectors` must be a non-empty list.", call. = FALSE)
  }

  # The file's fragments and lists, over the built-in ones, while compiling
  # (names cannot clash, so a built-in is never shadowed).
  saved <- list(fragments = the$fragments, lists = the$lists)
  on.exit({
    the$fragments <- saved$fragments
    the$lists <- saved$lists
  }, add = TRUE)
  the$fragments <- c(fragments, saved$fragments)
  the$lists <- c(lapply(lists, as.character), saved$lists)

  seen <- character()
  lapply(defs, function(def) {
    id <- def$id
    if (!rlang::is_string(id) || !grepl("^[a-z][a-z0-9_]*$", id)) {
      stop(
        "detector id `", format(id), "` must be lower-case letters, digits and `_`, ",
        "starting with a letter.",
        call. = FALSE
      )
    }
    if (id %in% seen) {
      stop("detector `", id, "` appears twice.", call. = FALSE)
    }
    seen <<- c(seen, id)
    if (!rlang::is_string(def$class) || !def$class %in% custom_classes) {
      stop(
        "detector `", id, "`: class `", format(def$class), "` must be one of ",
        paste(custom_classes, collapse = ", "), ".",
        call. = FALSE
      )
    }
    definition <- def[setdiff(names(def), "examples")]
    det <- tryCatch(compile_detector(definition), error = function(e) {
      stop("detector `", id, "`: ", conditionMessage(e), call. = FALSE)
    })
    check_detector_examples(det, def$examples)
    list(
      detector = det,
      digest = as.character(jsonlite::toJSON(
        list(definition, fragments, lists),
        auto_unbox = TRUE, digits = NA
      ))
    )
  })
}

check_detector_examples <- function(det, examples) {
  if (is.null(examples)) {
    return(invisible())
  }
  if (!is.list(examples) || length(setdiff(names(examples), c("match", "no_match"))) > 0) {
    stop("detector `", det$id, "`: `examples` has `match` and `no_match`.", call. = FALSE)
  }
  for (want in c("match", "no_match")) {
    texts <- unlist(examples[[want]])
    if (is.null(texts)) next
    if (!is.character(texts)) {
      stop("detector `", det$id, "`: examples `", want, "` must be a list of texts.", call. = FALSE)
    }
    found <- detect_with(list(det), texts)
    hit <- seq_along(texts) %in% found$doc
    bad <- if (want == "match") which(!hit) else which(hit)
    if (length(bad) > 0) {
      stop(
        "detector `", det$id, "`: example '", texts[bad[1]], "' ",
        if (want == "match") "should match but does not" else "should not match but does", ".",
        call. = FALSE
      )
    }
  }
}
