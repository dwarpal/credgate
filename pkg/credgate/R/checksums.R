# Checksum algorithms used to validate identifier candidates. All functions
# are vectorised over character vectors and ignore spaces and hyphens.

verhoeff_d <- matrix(c(
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
  1, 2, 3, 4, 0, 6, 7, 8, 9, 5,
  2, 3, 4, 0, 1, 7, 8, 9, 5, 6,
  3, 4, 0, 1, 2, 8, 9, 5, 6, 7,
  4, 0, 1, 2, 3, 9, 5, 6, 7, 8,
  5, 9, 8, 7, 6, 0, 4, 3, 2, 1,
  6, 5, 9, 8, 7, 1, 0, 4, 3, 2,
  7, 6, 5, 9, 8, 2, 1, 0, 4, 3,
  8, 7, 6, 5, 9, 3, 2, 1, 0, 4,
  9, 8, 7, 6, 5, 4, 3, 2, 1, 0
), nrow = 10, byrow = TRUE)

verhoeff_p <- matrix(c(
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
  1, 5, 7, 6, 2, 8, 3, 0, 9, 4,
  5, 8, 0, 3, 7, 9, 6, 1, 4, 2,
  8, 9, 1, 6, 0, 4, 3, 5, 2, 7,
  9, 4, 5, 3, 1, 2, 6, 8, 7, 0,
  4, 2, 8, 6, 5, 7, 3, 9, 0, 1,
  2, 7, 9, 3, 8, 0, 6, 4, 1, 5,
  7, 0, 4, 6, 9, 1, 3, 2, 5, 8
), nrow = 8, byrow = TRUE)

verhoeff_inv <- c(0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

strip_separators <- function(x) {
  stringi::stri_replace_all_regex(x, the$engine$separators, "")
}

# Runs the Verhoeff accumulator over each string; `offset` is 0 when
# validating a full number and 1 when computing a check digit.
verhoeff_accumulate <- function(digits, offset) {
  n <- length(digits)
  c <- integer(n)
  rev_digits <- stringi::stri_reverse(digits)
  len <- nchar(rev_digits)
  for (i in seq_len(max(c(0L, len)))) {
    active <- len >= i
    d <- as.integer(substr(rev_digits[active], i, i))
    p <- verhoeff_p[((i - 1L + offset) %% 8L) + 1L, d + 1L]
    c[active] <- verhoeff_d[cbind(c[active] + 1L, p + 1L)]
  }
  c
}

#' Verhoeff checksum (used by Aadhaar and Aadhaar Virtual ID)
#'
#' `verhoeff_valid()` checks whether a number (including its final check
#' digit) passes the Verhoeff checksum. `verhoeff_check_digit()` computes the
#' check digit to append to a number.
#'
#' @param x A character vector of digit strings. Spaces and hyphens are
#'   ignored.
#' @return `verhoeff_valid()`: a logical vector (`FALSE` for anything that is
#'   not all digits). `verhoeff_check_digit()`: a character vector of single
#'   digits (`NA` for invalid input).
#' @export
#' @examples
#' verhoeff_check_digit("236")
#' verhoeff_valid("2363")
verhoeff_valid <- function(x) {
  x <- strip_separators(as.character(x))
  ok <- !is.na(x) & stringi::stri_detect_regex(x, "^[0-9]+$")
  out <- logical(length(x))
  out[ok] <- verhoeff_accumulate(x[ok], 0L) == 0L
  out
}

#' @rdname verhoeff_valid
#' @export
verhoeff_check_digit <- function(x) {
  x <- strip_separators(as.character(x))
  ok <- !is.na(x) & stringi::stri_detect_regex(x, "^[0-9]+$")
  out <- rep(NA_character_, length(x))
  out[ok] <- as.character(verhoeff_inv[verhoeff_accumulate(x[ok], 1L) + 1L])
  out
}

#' Luhn checksum (payment cards)
#'
#' @inheritParams verhoeff_valid
#' @return A logical vector.
#' @export
#' @examples
#' luhn_valid("4111 1111 1111 1111")
luhn_valid <- function(x) {
  x <- strip_separators(as.character(x))
  ok <- !is.na(x) & stringi::stri_detect_regex(x, "^[0-9]+$")
  out <- logical(length(x))
  out[ok] <- luhn_sum(x[ok], with_check = TRUE) %% 10L == 0L
  out
}

luhn_sum <- function(digits, with_check) {
  rev_digits <- stringi::stri_reverse(digits)
  len <- nchar(rev_digits)
  total <- integer(length(digits))
  # With the check digit present, every second digit from the right (2nd,
  # 4th, ...) is doubled; when computing a check digit it is the 1st, 3rd, ...
  doubled_parity <- if (with_check) 0L else 1L
  for (i in seq_len(max(c(0L, len)))) {
    active <- len >= i
    d <- as.integer(substr(rev_digits[active], i, i))
    if (i %% 2L == doubled_parity) {
      d <- d * 2L
      d <- ifelse(d > 9L, d - 9L, d)
    }
    total[active] <- total[active] + d
  }
  total
}

luhn_check_digit <- function(x) {
  as.character((10L - luhn_sum(x, with_check = FALSE) %% 10L) %% 10L)
}

gstin_alphabet <- c(0:9, LETTERS)

#' GSTIN checksum
#'
#' A GSTIN is 15 characters: a 2-digit state code, the holder's PAN, an
#' entity number, the letter `Z` and a mod-36 check character.
#' `gstin_valid()` checks structure and check character;
#' `gstin_check_char()` computes the check character for the first 14
#' characters.
#'
#' @param x A character vector. Case is ignored.
#' @return `gstin_valid()`: a logical vector. `gstin_check_char()`: a
#'   character vector (`NA` for invalid input).
#' @export
#' @examples
#' gstin_check_char("27AAPFU0939F1Z")
gstin_valid <- function(x) {
  x <- toupper(as.character(x))
  ok <- !is.na(x) & stringi::stri_detect_regex(x, gstin_regex_full)
  out <- logical(length(x))
  out[ok] <- substr(x[ok], 15, 15) == gstin_check_char(substr(x[ok], 1, 14)) &
    substr(x[ok], 1, 2) %in% the$lists$gst_state_codes
  out
}

#' @rdname gstin_valid
#' @export
gstin_check_char <- function(x) {
  x <- toupper(as.character(x))
  ok <- !is.na(x) & stringi::stri_detect_regex(x, "^[0-9A-Z]{14}$")
  out <- rep(NA_character_, length(x))
  if (!any(ok)) {
    return(out)
  }
  total <- integer(sum(ok))
  for (i in 1:14) {
    v <- match(substr(x[ok], i, i), gstin_alphabet) - 1L
    # Counting from the right, the last character has factor 2, then 1, 2...
    addend <- v * if (i %% 2L == 0L) 2L else 1L
    total <- total + addend %/% 36L + addend %% 36L
  }
  out[ok] <- gstin_alphabet[(36L - total %% 36L) %% 36L + 1L]
  out
}

gstin_regex_full <- "^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$"
