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
  arrow <- from_arrow(text)
  text <- arrow$text
  if (!is.character(text)) {
    rlang::abort("`text` must be a character vector.")
  }
  docs <- ifelse(is.na(text), "", text)
  spans <- detect_pii(docs, detectors = detectors, context = context, min_confidence = min_confidence)
  if (nrow(spans) == 0) {
    return(arrow$wrap(text))
  }
  tokens <- tokens_for(vault, spans)
  out <- replace_spans(docs, spans, tokens)
  out[is.na(text)] <- NA_character_
  arrow$wrap(out)
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

# Tokens for spans (in document, then position order), adding new entries
# to the vault in that order.
tokens_for <- function(vault, spans) {
  entries <- vault$entries
  key <- paste(spans$type, spans$canonical, sep = "\r")
  known <- paste(entries$type, entries$canonical, sep = "\r")
  new <- !duplicated(key) & !key %in% known
  if (any(new)) {
    type <- spans$type[new]
    n <- as.vector(table(factor(entries$type, levels = unique(type)))[type]) +
      stats::ave(seq_along(type), type, FUN = seq_along)
    vault$entries <- rbind(entries, data.frame(
      token = paste0("[", toupper(type), "_", n, "]"), type = type,
      class = spans$class[new], canonical = spans$canonical[new], value = spans$value[new]
    ))
  }
  entries <- vault$entries
  entries$token[match(key, paste(entries$type, entries$canonical, sep = "\r"))]
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

# Saved vault layout (spec, "Saved vaults").
vault_magic <- c(charToRaw("CGVAULT"), as.raw(1L))
vault_kdf_scrypt_interactive <- as.raw(1L)
vault_header_bytes <- 8L + 1L + 32L + 24L
vault_min_passphrase <- 12L

#' Save a vault to an encrypted file, and open it again
#'
#' `vault_save()` writes the vault to a file encrypted with a passphrase, so
#' tokens can be restored in a later session - in R or in Python, which read
#' the same file. `vault_open()` reads it back; tokenising with the opened
#' vault continues its numbering.
#'
#' The passphrase comes from `passphrase`, else the environment variable
#' `CREDGATE_VAULT_PASSPHRASE`, else a prompt (in an interactive session with
#' the askpass package). It needs at least 12 characters and is never
#' stored: without it the file cannot be opened. The file is written readable
#' only by you; an existing file is replaced only if it is itself a vault
#' file. Encryption uses libsodium (scrypt key derivation, XSalsa20-Poly1305)
#' through the sodium package.
#'
#' @param vault A vault from [cg_vault()] or `vault_open()`.
#' @param path File to write or read, conventionally ending in `.cgvault`.
#' @param passphrase The passphrase, or `NULL` to use
#'   `CREDGATE_VAULT_PASSPHRASE` or a prompt.
#' @return `vault_save()` returns `path` invisibly; `vault_open()` returns a
#'   vault.
#' @export
#' @examplesIf requireNamespace("sodium", quietly = TRUE)
#' vault <- cg_vault()
#' tokenise("PAN ABCPE1234F", vault)
#' path <- tempfile(fileext = ".cgvault")
#' vault_save(vault, path, passphrase = "an example passphrase")
#'
#' # later, possibly in another session or in Python:
#' vault <- vault_open(path, passphrase = "an example passphrase")
#' restore("Customer [PAN_1] called.", vault)
vault_save <- function(vault, path, passphrase = NULL) {
  check_vault(vault)
  check_sodium()
  stopifnot(rlang::is_string(path))
  existed <- file.exists(path)
  if (existed && !identical(readBin(path, "raw", 7L), vault_magic[1:7])) {
    rlang::abort(paste0("`", path, "` exists and is not a vault file; not replacing it."),
      class = "credgate_vault_file"
    )
  }
  passphrase <- vault_passphrase(passphrase, confirm = !existed)
  entries <- vault$entries
  payload <- jsonlite::toJSON(
    list(
      format = "credgate-vault",
      version = 1L,
      saved_at = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
      entries = entries[c("token", "type", "class", "canonical", "value")]
    ),
    auto_unbox = TRUE, dataframe = "rows"
  )
  salt <- sodium::random(32L)
  nonce <- sodium::random(24L)
  key <- sodium::scrypt(charToRaw(enc2utf8(passphrase)), salt, 32L)
  sealed <- sodium::data_encrypt(charToRaw(enc2utf8(as.character(payload))), key, nonce)
  data <- c(vault_magic, vault_kdf_scrypt_interactive, salt, nonce, as.vector(sealed))

  tmp <- tempfile(pattern = paste0(".", basename(path), "."), tmpdir = dirname(path), fileext = ".tmp")
  old_umask <- Sys.umask("077")
  on.exit(Sys.umask(old_umask), add = TRUE)
  on.exit(if (file.exists(tmp)) unlink(tmp), add = TRUE)
  writeBin(data, tmp)
  Sys.chmod(tmp, "600")
  if (!file.rename(tmp, path)) {
    rlang::abort(paste0("Could not write `", path, "`."), class = "credgate_vault_file")
  }
  invisible(path)
}

#' @rdname vault_save
#' @export
vault_open <- function(path, passphrase = NULL) {
  check_sodium()
  stopifnot(rlang::is_string(path))
  data <- readBin(path, "raw", file.size(path))
  fail <- function(msg) rlang::abort(msg, class = "credgate_vault_file")
  if (length(data) < vault_header_bytes || !identical(data[1:7], vault_magic[1:7])) {
    fail("Not a credgate vault file.")
  }
  if (data[8] != vault_magic[8]) {
    fail(paste0("Unsupported vault file version ", as.integer(data[8]), "."))
  }
  if (data[9] != vault_kdf_scrypt_interactive) {
    fail(paste0("Unsupported key derivation ", as.integer(data[9]), "."))
  }
  salt <- data[10:41]
  nonce <- data[42:65]
  key <- sodium::scrypt(charToRaw(enc2utf8(vault_passphrase(passphrase, confirm = FALSE))), salt, 32L)
  plain <- tryCatch(
    sodium::data_decrypt(data[-seq_len(vault_header_bytes)], key, nonce),
    error = function(e) fail("Wrong passphrase, or the file is damaged or altered.")
  )
  json <- rawToChar(plain)
  Encoding(json) <- "UTF-8"
  payload <- jsonlite::fromJSON(json, simplifyVector = FALSE)
  if (!identical(payload$format, "credgate-vault") || !identical(payload$version, 1L)) {
    fail("Unsupported vault contents.")
  }
  vault <- cg_vault()
  field <- function(name) vapply(payload$entries, function(e) e[[name]], character(1))
  if (length(payload$entries) > 0) {
    vault$entries <- data.frame(
      token = field("token"), type = field("type"), class = field("class"),
      canonical = field("canonical"), value = field("value")
    )
  }
  vault
}

vault_passphrase <- function(passphrase, confirm) {
  if (is.null(passphrase)) {
    env <- Sys.getenv("CREDGATE_VAULT_PASSPHRASE")
    passphrase <- if (nzchar(env)) env else NULL
  }
  if (is.null(passphrase)) {
    if (!interactive() || !requireNamespace("askpass", quietly = TRUE)) {
      rlang::abort(
        "No passphrase: pass `passphrase` or set CREDGATE_VAULT_PASSPHRASE.",
        class = "credgate_vault_file"
      )
    }
    passphrase <- askpass::askpass("Vault passphrase: ")
    if (confirm && !identical(askpass::askpass("Repeat passphrase: "), passphrase)) {
      rlang::abort("The passphrases do not match.", class = "credgate_vault_file")
    }
  }
  if (!rlang::is_string(passphrase) || nchar(passphrase) < vault_min_passphrase) {
    rlang::abort(
      paste0("The passphrase must have at least ", vault_min_passphrase, " characters."),
      class = "credgate_vault_file"
    )
  }
  passphrase
}

check_sodium <- function() {
  if (!requireNamespace("sodium", quietly = TRUE)) {
    rlang::abort('Saving and opening vaults needs the sodium package: install.packages("sodium")')
  }
}
