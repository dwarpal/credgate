# Reversible tokenisation (the spec's "Tokenisation" rules).

# TYPE_n (numbered) or TYPE_<13 base32 characters> (keyed).
token_name <- "[A-Za-z]+(?:_[A-Za-z]+)*_(?:[0-9]+|[A-Za-z2-7]{13})"
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
#' With a token `key`, tokens are **keyed** (`[PAN_4qzm7k2x9tbc3]`): the same
#' identifier gets the same token in every vault with that key - across
#' sessions, datasets, R and Python, and parallel workers, whose vaults can be
#' combined with [vault_merge()]. Without a key, tokens are numbered
#' (`[PAN_1]`) and belong to this vault only. Keyed tokens need the openssl
#' package.
#'
#' Whoever holds the key can confirm a guessed value by computing its token,
#' so keep the key like a password: from a key store or the environment
#' variable, never in code or project files.
#'
#' @param key A token key: at least 64 hex digits (32 bytes), or a raw
#'   vector. Make one with [cg_new_token_key()].
#' @param keyed Use keyed tokens with the key from `CREDGATE_TOKEN_KEY`.
#' @return An object of class `cg_vault`. It is modified in place by
#'   [tokenise()], so it does not need to be reassigned.
#' @export
#' @examples
#' vault <- cg_vault()
#' tokenise("PAN ABCPE1234F", vault)
#' vault
#' @examplesIf requireNamespace("openssl", quietly = TRUE)
#' key <- cg_new_token_key()
#' a <- cg_vault(key)
#' b <- cg_vault(key)
#' tokenise("PAN ABCPE1234F", a) == tokenise("pan abcpe1234f", b)
cg_vault <- function(key = NULL, keyed = FALSE) {
  vault <- new.env(parent = emptyenv())
  vault$key <- if (!is.null(key) || keyed) token_key(key) else NULL
  vault$entries <- data.frame(
    token = character(), type = character(), class = character(),
    canonical = character(), value = character()
  )
  structure(vault, class = "cg_vault")
}

#' Token keys for keyed tokens
#'
#' `cg_new_token_key()` makes a new random key (64 hex digits) for
#' [cg_vault()]. `cg_key_fingerprint()` returns 16 hex digits that identify a
#' key without revealing it; saved keyed vaults record it, so opening one with
#' the wrong key fails. Both need the openssl package.
#'
#' @param key A key as hex digits or a raw vector; `NULL` uses
#'   `CREDGATE_TOKEN_KEY`.
#' @return A string.
#' @export
#' @examplesIf requireNamespace("openssl", quietly = TRUE)
#' key <- cg_new_token_key()
#' cg_key_fingerprint(key)
cg_new_token_key <- function() {
  check_installed("openssl")
  paste(format(openssl::rand_bytes(token_key_min_bytes)), collapse = "")
}

#' @rdname cg_new_token_key
#' @export
cg_key_fingerprint <- function(key = NULL) {
  check_installed("openssl")
  mac <- openssl::sha256(charToRaw("credgate-key-check-v1"), key = token_key(key))
  paste(format(as.raw(mac)[1:8]), collapse = "")
}

token_key_min_bytes <- 32L

token_key <- function(key) {
  if (is.null(key)) {
    env <- Sys.getenv("CREDGATE_TOKEN_KEY")
    if (!nzchar(env)) {
      rlang::abort("No token key: pass `key` or set CREDGATE_TOKEN_KEY.")
    }
    key <- env
  }
  if (is.character(key)) {
    hex <- trimws(key)
    if (length(hex) != 1 || !grepl("^([0-9A-Fa-f]{2})+$", hex)) {
      rlang::abort("A token key given as text must be hex digits.")
    }
    key <- as.raw(strtoi(substring(hex, seq(1, nchar(hex), 2), seq(2, nchar(hex), 2)), 16L))
  }
  if (!is.raw(key)) {
    rlang::abort("A token key must be hex text or a raw vector.")
  }
  if (length(key) < token_key_min_bytes) {
    rlang::abort(paste0(
      "A token key needs at least ", token_key_min_bytes, " bytes (",
      2 * token_key_min_bytes, " hex digits); make one with cg_new_token_key()."
    ))
  }
  key
}

# The keyed token id (spec, "Keyed token id"): HMAC-SHA256 of
# "credgate-token-v1" \0 type \0 canonical; first 8 bytes in base32.
keyed_id <- function(key, type, canonical) {
  check_installed("openssl")
  vapply(seq_along(type), function(i) {
    message <- c(
      charToRaw("credgate-token-v1"), as.raw(0L), charToRaw(enc2utf8(type[i])),
      as.raw(0L), charToRaw(enc2utf8(canonical[i]))
    )
    base32_lower(as.raw(openssl::sha256(message, key = key))[1:8])
  }, character(1))
}

# RFC 4648 base32, lower case, no padding.
base32_lower <- function(bytes) {
  bits <- as.integer(unlist(lapply(bytes, function(b) rev(as.integer(rawToBits(b))))))
  bits <- c(bits, integer((5 - length(bits) %% 5) %% 5))
  groups <- matrix(bits, nrow = 5)
  values <- colSums(groups * c(16L, 8L, 4L, 2L, 1L))
  paste(strsplit("abcdefghijklmnopqrstuvwxyz234567", "")[[1]][values + 1L], collapse = "")
}

#' Combine keyed vaults
#'
#' Adds the entries of `other` that `vault` does not have yet, for example
#' from parallel workers that each tokenised part of a table with the same
#' key. Both vaults must be keyed with the same key; it is an error if a
#' token stands for different values in the two.
#'
#' @param vault,other Keyed vaults from [cg_vault()].
#' @return `vault`, modified in place, invisibly.
#' @export
vault_merge <- function(vault, other) {
  check_vault(vault)
  check_vault(other)
  if (is.null(vault$key) || is.null(other$key)) {
    rlang::abort("Only keyed vaults can be merged: numbered tokens belong to one vault.")
  }
  if (!identical(vault$key, other$key)) {
    rlang::abort("The vaults were made with different token keys.")
  }
  add_entries(vault, other$entries)
  invisible(vault)
}

# Append entries not yet in the vault, checking that no token stands for two
# different values (spec: collisions are errors, never merged silently).
add_entries <- function(vault, new) {
  entries <- vault$entries
  key_of <- function(e) paste(e$type, e$canonical, sep = "\r")
  new <- new[!duplicated(key_of(new)) & !key_of(new) %in% key_of(entries), , drop = FALSE]
  all <- rbind(entries, new)
  token <- toupper(all$token)
  clash <- duplicated(token) & !duplicated(key_of(all))
  if (any(clash)) {
    rlang::abort(
      paste0(
        "Token ", all$token[clash][1], " would stand for two different values; ",
        "use a different key, or keep these values in separate vaults."
      ),
      class = "credgate_token_collision"
    )
  }
  vault$entries <- all
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
  values <- stats::setNames(vault$entries$value, toupper(vault$entries$token))
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
    value <- values[toupper(paste0("[", name, "]"))]
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
    id <- if (is.null(vault$key)) {
      as.vector(table(factor(entries$type, levels = unique(type)))[type]) +
        stats::ave(seq_along(type), type, FUN = seq_along)
    } else {
      keyed_id(vault$key, type, spans$canonical[new])
    }
    add_entries(vault, data.frame(
      token = paste0("[", toupper(type), "_", id, "]"), type = type,
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
#' @param key For a keyed vault: its token key, or `NULL` to use
#'   `CREDGATE_TOKEN_KEY`. The key is never saved; opening fails if it differs
#'   from the one the vault was saved with.
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
      mode = if (is.null(vault$key)) "numbered" else "keyed",
      key_fingerprint = if (is.null(vault$key)) NULL else cg_key_fingerprint(vault$key),
      entries = entries[c("token", "type", "class", "canonical", "value")]
    ),
    auto_unbox = TRUE, dataframe = "rows"
  )
  salt <- sodium::random(32L)
  nonce <- sodium::random(24L)
  box_key <- sodium::scrypt(charToRaw(enc2utf8(passphrase)), salt, 32L)
  sealed <- sodium::data_encrypt(charToRaw(enc2utf8(as.character(payload))), box_key, nonce)
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
vault_open <- function(path, passphrase = NULL, key = NULL) {
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
  box_key <- sodium::scrypt(charToRaw(enc2utf8(vault_passphrase(passphrase, confirm = FALSE))), salt, 32L)
  plain <- tryCatch(
    sodium::data_decrypt(data[-seq_len(vault_header_bytes)], box_key, nonce),
    error = function(e) fail("Wrong passphrase, or the file is damaged or altered.")
  )
  json <- rawToChar(plain)
  Encoding(json) <- "UTF-8"
  payload <- jsonlite::fromJSON(json, simplifyVector = FALSE)
  if (!identical(payload$format, "credgate-vault") || !identical(payload$version, 1L)) {
    fail("Unsupported vault contents.")
  }
  mode <- payload$mode %||% "numbered"
  if (identical(mode, "keyed")) {
    vault <- cg_vault(key, keyed = TRUE)
    if (!identical(cg_key_fingerprint(vault$key), payload$key_fingerprint)) {
      fail("The token key does not match the one this vault was saved with.")
    }
  } else if (identical(mode, "numbered")) {
    if (!is.null(key)) {
      fail("This vault has numbered tokens; it does not use a token key.")
    }
    vault <- cg_vault()
  } else {
    fail(paste0("Unsupported vault mode '", mode, "'."))
  }
  field <- function(name) vapply(payload$entries, function(e) e[[name]], character(1))
  if (length(payload$entries) > 0) {
    add_entries(vault, data.frame(
      token = field("token"), type = field("type"), class = field("class"),
      canonical = field("canonical"), value = field("value")
    ))
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
