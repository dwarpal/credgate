# Detector registry.
#
# A detector finds candidate spans with a regex, validates them (checksums,
# code tables), and scores them using surrounding context. Built-in detectors
# are defined in the shared spec (inst/spec/detectors.yaml) and compiled when
# the package loads; users can add their own with register_detector().

the <- new.env(parent = emptyenv())
the$detectors <- list()

#' Define a PII detector
#'
#' @param id Unique identifier, e.g. `"aadhaar"`.
#' @param class Data class used by policies, e.g. `"identity_strong"`.
#' @param label Human-readable name.
#' @param pattern ICU regular expression for candidates, or several (their
#'   matches are combined). Wrap it with [bounded()] so it does not match
#'   inside a longer token.
#' @param capture Name of a capture group whose span is reported instead of
#'   the whole match, or `NULL`. Lets a pattern match a cue such as `"Name:"`
#'   without reporting it; much faster than a lookbehind.
#' @param validate Function taking the matched strings (normalised text) and
#'   returning a logical vector; candidates returning `FALSE` are dropped.
#' @param checks Short description of what `validate` checks, reported as a
#'   reason for each match (e.g. `"Verhoeff checksum valid"`).
#' @param base Confidence (0-1) of a validated match without supporting
#'   context, or a function taking the matched strings and returning one
#'   confidence per match (e.g. higher for a mobile number written with
#'   `+91`).
#' @param base_without_context Confidence (0-1) used instead of `base` when no
#'   context keyword is found, or `NULL`. For patterns that are strong
#'   evidence with context but weak without it (a voter ID format alone could
#'   be a product code).
#' @param context Regex (case-insensitive) of keywords that raise confidence
#'   when they appear near the match, or `NULL`.
#' @param negative Regex (case-insensitive) of keywords that lower confidence,
#'   or `NULL`.
#' @param context_required If `TRUE`, matches without supporting context are
#'   dropped. Use for patterns too generic to trust on their own.
#' @param canonical Function mapping matched strings to a canonical form
#'   (used for consistent tokenisation). Defaults to removing spaces and
#'   hyphens and upper-casing.
#' @param describe Optional function returning extra reasons per match
#'   (e.g. the PAN holder type).
#' @param ignore_case Match the pattern case-insensitively.
#' @return An object of class `cg_detector`.
#' @export
#' @examples
#' employee_id <- new_detector(
#'   id = "employee_id", class = "internal", label = "Employee ID",
#'   pattern = bounded("EMP[0-9]{6}"),
#'   context = "employee|staff"
#' )
#' employee_id$label
new_detector <- function(id, class, label, pattern,
                         capture = NULL,
                         validate = NULL,
                         checks = NULL,
                         base = 0.8,
                         base_without_context = NULL,
                         context = NULL,
                         negative = NULL,
                         context_required = FALSE,
                         canonical = NULL,
                         describe = NULL,
                         ignore_case = FALSE) {
  stopifnot(
    rlang::is_string(id), rlang::is_string(class), rlang::is_string(label),
    is.character(pattern), length(pattern) >= 1, !anyNA(pattern),
    is.null(capture) || rlang::is_string(capture),
    is.function(base) || (rlang::is_scalar_double(base) && base > 0 && base <= 1),
    is.null(base_without_context) || (rlang::is_scalar_double(base_without_context) &&
      base_without_context > 0 && base_without_context <= 1)
  )
  if (!is.null(base_without_context) && isTRUE(context_required)) {
    rlang::abort("`base_without_context` and `context_required` exclude each other.")
  }
  if (!is.null(base_without_context) && is.null(context)) {
    rlang::abort("`base_without_context` needs `context`.")
  }
  structure(
    list(
      id = id, class = class, label = label, pattern = pattern, capture = capture,
      validate = validate %||% function(x) rep(TRUE, length(x)),
      checks = checks,
      base = base, base_without_context = base_without_context,
      context = context, negative = negative,
      context_required = context_required,
      canonical = canonical %||% canonical_default,
      describe = describe, ignore_case = ignore_case
    ),
    class = "cg_detector"
  )
}

canonical_default <- function(x) toupper(strip_separators(x))

#' Wrap a pattern so it only matches whole tokens
#'
#' The match may not be preceded or followed by a letter or digit, nor by a
#' digit joined with a space or hyphen (so a 12-digit window inside a
#' 16-digit card number is not reported as an Aadhaar number).
#'
#' @param core An ICU regular expression.
#' @return A regular expression.
#' @export
#' @examples
#' p <- bounded("[0-9]{4}")
#' stringi::stri_detect_regex(c("PIN 1234", "card 12345678"), p)
bounded <- function(core) {
  paste0(the$engine$boundary$before, "(?:", core, ")", the$engine$boundary$after)
}

#' Register a detector
#'
#' @param detector A detector created with [new_detector()].
#' @param overwrite Replace an existing detector with the same id.
#' @return The detector id, invisibly.
#' @export
#' @examples
#' register_detector(new_detector(
#'   id = "employee_id", class = "internal", label = "Employee ID",
#'   pattern = bounded("EMP[0-9]{6}")
#' ))
#' detect_pii("Approved by EMP123456")$type
register_detector <- function(detector, overwrite = FALSE) {
  if (!inherits(detector, "cg_detector")) {
    rlang::abort("`detector` must be created with `new_detector()`.")
  }
  if (!overwrite && detector$id %in% names(the$detectors)) {
    rlang::abort(paste0("Detector `", detector$id, "` is already registered."))
  }
  the$detectors[[detector$id]] <- detector
  invisible(detector$id)
}

#' List registered detectors
#'
#' @return A data frame with one row per detector.
#' @export
#' @examples
#' cg_detectors()
cg_detectors <- function() {
  d <- the$detectors
  data.frame(
    id = names(d),
    class = vapply(d, `[[`, character(1), "class"),
    label = vapply(d, `[[`, character(1), "label"),
    base = vapply(d, function(x) if (is.function(x$base)) NA_real_ else x$base, numeric(1)),
    context_required = vapply(d, `[[`, logical(1), "context_required"),
    row.names = NULL
  )
}

get_detectors <- function(ids = NULL) {
  if (is.null(ids)) {
    return(the$detectors)
  }
  unknown <- setdiff(ids, names(the$detectors))
  if (length(unknown) > 0) {
    rlang::abort(paste0("Unknown detector(s): ", paste(unknown, collapse = ", ")))
  }
  the$detectors[ids]
}

register_builtin_detectors <- function() {
  load_spec()
}
