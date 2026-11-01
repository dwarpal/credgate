#' @section Masking:
#' Wherever credgate shows a detected value - printed spans, [preview()],
#' the examples in [scan_pii()] - it masks letters and digits with `X`.
#' Identifiers keep their last 4 characters (2 for values shorter than 8),
#' as in UIDAI's masked Aadhaar, so you can tell which value matched. Names
#' and addresses are masked in full.
#'
#' To mask every value in full, for policies that allow no part of a value
#' to be shown, set `options(credgate.mask = "full")` or the environment
#' variable `CREDGATE_MASK=full` (the option wins). The default is
#' `"partial"`. Masking never changes the detected values themselves.
#' @keywords internal
"_PACKAGE"

#' @importFrom rlang %||%
NULL
