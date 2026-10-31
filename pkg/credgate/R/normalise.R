# Text normalisation before detection.
#
# Detectors run on a normalised copy of the text so that trivial variations
# (Devanagari digits, fullwidth characters, zero-width joiners inside an
# identifier) cannot hide PII. Every normalised code point remembers which
# original code point it came from, so spans are always reported against the
# text the user actually passed in.

# The digit blocks, invisible characters and dashes handled here are listed
# in the spec (engine.yaml, `normalisation`).

#' Normalise text for PII detection
#'
#' Applies NFKC normalisation, maps Indic and Arabic-Indic digits to ASCII,
#' maps dash variants to `-` and removes invisible characters (zero-width
#' space/joiners, BOM, soft hyphen). Returns the normalised text together
#' with an offset map back to the original.
#'
#' @param x A character vector.
#' @return A list with one element per element of `x`, each a list with
#'   `text` (the normalised string) and `map` (an integer vector giving, for
#'   each code point of `text`, the index of the original code point it came
#'   from, or `NULL` when the text is unchanged).
#' @export
#' @examples
#' cg_normalise("Aadhaar: \u0968\u0969\u096a\u096b")
cg_normalise <- function(x) {
  if (!is.character(x)) {
    rlang::abort("`x` must be a character vector.")
  }
  x[is.na(x)] <- ""
  ascii <- stringi::stri_enc_isascii(x)
  out <- vector("list", length(x))
  for (i in seq_along(x)) {
    if (ascii[[i]]) {
      out[[i]] <- list(text = x[[i]], map = NULL)
    } else {
      out[[i]] <- normalise_one(x[[i]])
    }
  }
  out
}

normalise_one <- function(s) {
  cps <- utf8ToInt(s)
  pieces <- intToUtf8(cps, multiple = TRUE)

  special <- unique(cps[cps >= 128L])
  if (length(special) > 0) {
    replacement <- vapply(special, normalise_code_point, character(1))
    idx <- cps >= 128L
    pieces[idx] <- replacement[match(cps[idx], special)]
  }

  lens <- nchar(pieces, type = "chars")
  text <- paste0(pieces, collapse = "")
  map <- rep.int(seq_along(cps), lens)
  if (identical(text, s) && length(map) == length(cps)) {
    map <- NULL
  }
  list(text = text, map = map)
}

normalise_code_point <- function(cp) {
  if (cp %in% the$engine$remove) {
    return("")
  }
  if (cp %in% the$engine$dash) {
    return("-")
  }
  zeros <- the$engine$digit_zeros
  zero <- zeros[cp >= zeros & cp <= zeros + 9L]
  if (length(zero) == 1) {
    return(as.character(cp - zero))
  }
  stringi::stri_trans_nfkc(intToUtf8(cp))
}

# Map [start, end] code-point positions in normalised text back to the
# original text.
map_span <- function(map, start, end) {
  if (is.null(map)) {
    return(list(start = start, end = end))
  }
  list(start = map[start], end = map[end])
}
