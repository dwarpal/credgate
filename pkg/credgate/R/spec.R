# Loading the shared detection spec (inst/spec, copied from the repository's
# spec/ folder) and compiling its detectors into `cg_detector` objects.

spec_version_supported <- 1L

detector_fields <- c(
  "id", "class", "label", "patterns", "bounded", "capture", "ignore_case",
  "validate", "checks", "base", "base_without_context", "context", "negative",
  "context_required", "describe", "canonical"
)

#' Path to the detection spec shipped with the package
#'
#' The spec (detectors, engine parameters and conformance cases) is shared
#' by every CredGate implementation. See its `README.md` for the schema.
#'
#' @return The path of the `spec` directory.
#' @export
#' @examples
#' list.files(cg_spec_path())
cg_spec_path <- function() {
  system.file("spec", package = "credgate", mustWork = TRUE)
}

read_spec_file <- function(dir, file) {
  x <- read_yaml_utf8(file.path(dir, file))
  if (!identical(as.integer(x$spec_version), spec_version_supported)) {
    rlang::abort(paste0(
      "Unsupported spec_version ", x$spec_version, " in ", file,
      " (this credgate supports ", spec_version_supported, ")."
    ))
  }
  x
}

# Spec files are UTF-8 (they contain Indic keywords). Read the bytes and mark
# them UTF-8 instead of going through a connection, which re-encodes from
# the session locale and breaks under C/POSIX locales common on servers.
read_yaml_utf8 <- function(path) {
  bytes <- readBin(path, "raw", file.size(path))
  text <- rawToChar(bytes)
  Encoding(text) <- "UTF-8"
  yaml::yaml.load(text)
}

load_spec <- function(dir = cg_spec_path()) {
  engine <- read_spec_file(dir, "engine.yaml")
  detectors <- read_spec_file(dir, "detectors.yaml")
  norm <- engine$normalisation
  the$engine <- list(
    digit_zeros = parse_code_points(norm$digit_zeros),
    remove = parse_code_points(norm$remove),
    dash = parse_code_points(norm$dash),
    boundary = engine$boundary,
    separators = engine$separators,
    scoring = engine$scoring
  )
  the$lists <- lapply(detectors$lists, as.character)
  the$tables <- lapply(detectors$tables, unlist)
  the$fragments <- detectors$fragments
  the$detectors <- list()
  for (def in detectors$detectors) {
    register_detector(compile_detector(def))
  }
  invisible()
}

parse_code_points <- function(x) {
  strtoi(sub("^U\\+", "", unlist(x)), base = 16L)
}

# Replace {{name}} with the fragment or the list joined by "|".
expand_fragments <- function(x, depth = 0L) {
  if (is.null(x)) {
    return(NULL)
  }
  if (depth > 10L) {
    rlang::abort("Fragments nested more than 10 deep (circular reference?).")
  }
  refs <- unique(unlist(stringi::stri_match_all_regex(x, "\\{\\{([A-Za-z0-9_]+)\\}\\}")[[1]][, 2]))
  refs <- refs[!is.na(refs)]
  for (ref in refs) {
    value <- if (!is.null(the$fragments[[ref]])) {
      expand_fragments(the$fragments[[ref]], depth + 1L)
    } else if (!is.null(the$lists[[ref]])) {
      paste(the$lists[[ref]], collapse = "|")
    } else {
      rlang::abort(paste0("Unknown fragment or list `{{", ref, "}}`."))
    }
    x <- stringi::stri_replace_all_fixed(x, paste0("{{", ref, "}}"), value)
  }
  x
}

compile_detector <- function(def) {
  unknown <- setdiff(names(def), detector_fields)
  if (length(unknown) > 0) {
    rlang::abort(paste0(
      "Detector `", def$id, "` has unknown field(s): ",
      paste(unknown, collapse = ", ")
    ))
  }
  patterns <- vapply(unlist(def$patterns), expand_fragments, character(1), USE.NAMES = FALSE)
  if (isTRUE(def$bounded)) {
    patterns <- bounded(patterns)
  }
  new_detector(
    id = def$id,
    class = def$class,
    label = def$label,
    pattern = patterns,
    capture = def$capture,
    validate = compile_validators(def$validate),
    checks = def$checks,
    base = compile_base(def$base),
    base_without_context = def$base_without_context,
    context = expand_fragments(def$context),
    negative = expand_fragments(def$negative),
    context_required = isTRUE(def$context_required),
    canonical = compile_canonical(def$canonical),
    describe = compile_describe(def$describe),
    ignore_case = isTRUE(def$ignore_case)
  )
}

compile_validators <- function(defs) {
  if (length(defs) == 0) {
    return(NULL)
  }
  checks <- lapply(defs, function(v) {
    if (is.character(v)) {
      switch(v,
        verhoeff = verhoeff_valid,
        luhn = luhn_valid,
        gstin = gstin_valid,
        rlang::abort(paste0("Unknown validator `", v, "`."))
      )
    } else if (!is.null(v$match_stripped)) {
      pattern <- expand_fragments(v$match_stripped)
      function(x) stringi::stri_detect_regex(strip_separators(x), pattern)
    } else {
      rlang::abort(paste0("Unknown validator: ", paste(names(v), collapse = ", ")))
    }
  })
  function(x) {
    ok <- rep(TRUE, length(x))
    for (check in checks) ok <- ok & check(x)
    ok
  }
}

# Apply `rules` (first `match` wins) over a default; used by `base` and
# `describe`.
rule_lookup <- function(default, rules, field) {
  patterns <- vapply(rules, function(r) expand_fragments(r$match), character(1))
  values <- lapply(rules, `[[`, field)
  function(x) {
    out <- rep(default, length(x))
    done <- logical(length(x))
    for (i in seq_along(rules)) {
      hit <- !done & stringi::stri_detect_regex(x, patterns[[i]])
      out[hit] <- values[[i]]
      done <- done | hit
    }
    out
  }
}

compile_base <- function(def) {
  if (is.numeric(def)) {
    return(as.double(def))
  }
  rule_lookup(as.double(def$default), def$rules, "value")
}

compile_describe <- function(def) {
  if (is.null(def)) {
    return(NULL)
  }
  if (!is.null(def$position)) {
    table <- the$tables[[def$table]]
    parts <- strsplit(def$template, "{}", fixed = TRUE)[[1]]
    return(function(x) {
      key <- toupper(substr(x, def$position, def$position))
      paste0(parts[1], unname(table[key]), if (length(parts) > 1) parts[2] else "")
    })
  }
  rule_lookup(def$default, def$rules, "text")
}

compile_canonical <- function(name) {
  if (is.null(name)) {
    return(canonical_default)
  }
  switch(name,
    strip_upper = canonical_default,
    lower = tolower,
    last10_digits = function(x) {
      d <- gsub("[^0-9]", "", x)
      substr(d, nchar(d) - 9L, nchar(d))
    },
    collapse_upper = function(x) {
      toupper(stringi::stri_replace_all_regex(stringi::stri_trim_both(x), "\\s+", " "))
    },
    rlang::abort(paste0("Unknown canonical form `", name, "`."))
  )
}
