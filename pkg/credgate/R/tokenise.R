# Reversible tokenisation (the spec's "Tokenisation" rules).

token_name <- "[A-Za-z]+(?:_[A-Za-z]+)*_[0-9]+"
token_candidate <- paste0(
  "\\[\\s*(", token_name, ")\\s*\\]|(?<![\\p{L}\\p{N}_])(", token_name, ")(?![\\p{L}\\p{N}_])"
)

#' Create a token vault
#'
#' A vault holds the mapping between tokens such as `[PAN_1]` and the values
#' they stand for. It starts empty and grows as [tokenise()] meets new
#' identifiers; the same identifier always gets the same token. The vault
#' lives in memory only, and printing it masks the values.
#'
#' @return An object of class `cg_vault`. It is modified in place by
#'   [tokenise()], so it does not need to be reassigned.
#' @export
#' @examples
#' vault <- cg_vault()
#' tokenise("PAN ABCPE1234F", vault)
#' vault
cg_vault <- function() {
  vault <- new.env(parent = emptyenv())
  vault$entries <- data.frame(
    token = character(), type = character(), class = character(),
    canonical = character(), value = character()
  )
  structure(vault, class = "cg_vault")
}

#' Replace identifiers with tokens that can be restored
#'
#' Replaces every detected identifier with a numbered token such as
#' `[PAN_1]` or `[PERSON_NAME_2]`, and records in `vault` which value each
#' token stands for, so [restore()] can put the values back into a model's
#' answer. The same identifier gets the same token however it is written
#' (`ABCPE1234F` and `abcpe1234f`; `+91 98765 43210` and `9876543210`),
#' across texts and across calls with the same vault.
#'
#' @inheritParams detect_pii
#' @param vault A vault from [cg_vault()].
#' @return A character vector like `text`, with identifiers replaced by
#'   tokens. `NA` stays `NA`.
#' @seealso [restore()], [redact()] for irreversible placeholders.
#' @export
#' @examples
#' vault <- cg_vault()
#' safe <- tokenise(c("PAN ABCPE1234F, mobile 9876543210", "pan abcpe1234f again"), vault)
#' safe
#' restore("The customer with [PAN_1] can be reached on [MOBILE_IN_1].", vault)
tokenise <- function(text, vault, detectors = NULL, context = NULL, min_confidence = 0) {
  check_vault(vault)
  if (!is.character(text)) {
    rlang::abort("`text` must be a character vector.")
  }
  docs <- ifelse(is.na(text), "", text)
  spans <- detect_pii(docs, detectors = detectors, context = context, min_confidence = min_confidence)
  if (nrow(spans) == 0) {
    return(text)
  }
  tokens <- vapply(seq_len(nrow(spans)), function(i) token_for(vault, spans[i, ]), character(1))
  out <- docs
  for (i in order(spans$doc, -spans$start)) {
    d <- spans$doc[i]
    out[d] <- paste0(
      stringi::stri_sub(out[d], 1L, spans$start[i] - 1L),
      tokens[i],
      stringi::stri_sub(out[d], spans$end[i] + 1L)
    )
  }
  out[is.na(text)] <- NA_character_
  out
}

#' Put the values behind tokens back into text
#'
#' Replaces tokens made by [tokenise()] - for example in a model's answer -
#' with the values they stand for. Tokens are recognised with any letter
#' case, with spaces inside the brackets (`[ pan_1 ]`) and without brackets
#' (`PAN_1`), because models do not always copy them exactly. Tokens the
#' vault does not know are left unchanged.
#'
#' @param text A character vector.
#' @param vault The vault used by [tokenise()].
#' @param strict If `TRUE`, it is an error when `text` contains a bracketed
#'   token the vault does not know (one the model invented or altered).
#' @return A character vector like `text`.
#' @export
#' @examples
#' vault <- cg_vault()
#' tokenise("Name: Priya Nair, PAN ABCPE1234F", vault)
#' restore("[PERSON_NAME_1] holds [pan_1].", vault)
restore <- function(text, vault, strict = FALSE) {
  check_vault(vault)
  if (!is.character(text)) {
    rlang::abort("`text` must be a character vector.")
  }
  values <- stats::setNames(vault$entries$value, vault$entries$token)
  unknown <- character()
  out <- vapply(text, function(t) {
    if (is.na(t)) {
      return(NA_character_)
    }
    m <- stringi::stri_match_all_regex(
      t, token_candidate,
      opts_regex = stringi::stri_opts_regex(case_insensitive = TRUE)
    )[[1]]
    if (is.na(m[1, 1])) {
      return(t)
    }
    loc <- stringi::stri_locate_all_regex(
      t, token_candidate,
      opts_regex = stringi::stri_opts_regex(case_insensitive = TRUE)
    )[[1]]
    bracketed <- !is.na(m[, 2])
    name <- toupper(ifelse(bracketed, m[, 2], m[, 3]))
    value <- values[paste0("[", name, "]")]
    unknown <<- c(unknown, m[bracketed & is.na(value), 1])
    for (i in rev(which(!is.na(value)))) {
      t <- paste0(
        stringi::stri_sub(t, 1L, loc[i, 1] - 1L),
        value[[i]],
        stringi::stri_sub(t, loc[i, 2] + 1L)
      )
    }
    t
  }, character(1), USE.NAMES = FALSE)
  if (strict && length(unknown) > 0) {
    rlang::abort(
      paste0("Unknown token(s): ", paste(unique(unknown), collapse = ", ")),
      class = "credgate_unknown_token"
    )
  }
  out
}

token_for <- function(vault, span) {
  entries <- vault$entries
  hit <- which(entries$type == span$type & entries$canonical == span$canonical)
  if (length(hit) > 0) {
    return(entries$token[hit[1]])
  }
  n <- sum(entries$type == span$type) + 1L
  token <- paste0("[", toupper(span$type), "_", n, "]")
  vault$entries <- rbind(entries, data.frame(
    token = token, type = span$type, class = span$class,
    canonical = span$canonical, value = span$value
  ))
  token
}

check_vault <- function(vault) {
  if (!inherits(vault, "cg_vault")) {
    rlang::abort("`vault` must be a vault from `cg_vault()`.")
  }
}

#' @export
length.cg_vault <- function(x) {
  nrow(x$entries)
}

#' @export
print.cg_vault <- function(x, ..., reveal = FALSE) {
  n <- nrow(x$entries)
  if (n == 0) {
    cli::cli_text("Empty vault.")
    return(invisible(x))
  }
  if (reveal) {
    cli::cli_text("Vault with {n} token{?s}:")
  } else {
    cli::cli_text("Vault with {n} token{?s} (values masked; use {.code print(x, reveal = TRUE)} to see them):")
  }
  shown <- as.data.frame(x, reveal = reveal)[c("token", "value")]
  print(shown, row.names = FALSE)
  invisible(x)
}

#' @export
as.data.frame.cg_vault <- function(x, row.names = NULL, optional = FALSE, ..., reveal = FALSE) {
  out <- x$entries[c("token", "type", "class", "value")]
  if (!reveal) {
    out$value <- mask_value(out$value, out$class)
  }
  rownames(out) <- row.names
  out
}
