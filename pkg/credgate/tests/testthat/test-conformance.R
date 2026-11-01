# Runs the shared conformance cases in inst/spec/conformance, which every
# CredGate implementation must pass.

conformance <- function(file) {
  credgate:::read_yaml_utf8(file.path(cg_spec_path(), "conformance", file))
}

test_that("the shipped spec is in sync with the repository spec", {
  repo <- test_path("..", "..", "..", "..", "spec")
  skip_if_not(dir.exists(repo), "repository spec/ not available (installed package)")
  shipped <- cg_spec_path()
  files <- list.files(repo, recursive = TRUE)
  expect_setequal(list.files(shipped, recursive = TRUE), files)
  for (f in files) {
    expect_identical(
      readLines(file.path(shipped, f), encoding = "UTF-8"),
      readLines(file.path(repo, f), encoding = "UTF-8"),
      info = paste(f, "differs; run tools/sync-spec.sh")
    )
  }
})

test_that("checksum vectors", {
  v <- conformance("checksums.yaml")
  na_if_null <- function(x) if (is.null(x)) NA_character_ else x
  for (case in v$verhoeff$check_digit) {
    expect_identical(verhoeff_check_digit(case$input), na_if_null(case$output), info = case$input)
  }
  for (case in v$verhoeff$valid) {
    expect_identical(verhoeff_valid(case$input), case$valid, info = case$input)
  }
  for (case in v$luhn$valid) {
    expect_identical(luhn_valid(case$input), case$valid, info = case$input)
  }
  for (case in v$gstin$check_char) {
    expect_identical(gstin_check_char(case$input), na_if_null(case$output), info = case$input)
  }
  for (case in v$gstin$valid) {
    expect_identical(gstin_valid(case$input), case$valid, info = case$input)
  }
})

for (case in conformance("detect.yaml")$cases) {
  test_that(paste("detect:", case$id), {
    got <- detect_pii(case$text, context = case$context)
    shown <- paste0(got$type, "=", got$value, " (", got$confidence, ")", collapse = ", ")
    expect_equal(nrow(got), length(case$expect), info = paste("got:", shown))
    for (e in case$expect) {
      row <- got[got$type == e$type & got$value == e$value, , drop = FALSE]
      expect_equal(nrow(row), 1, info = paste(e$type, e$value, "| got:", shown))
      if (nrow(row) != 1) next
      if (!is.null(e$confidence)) {
        expect_equal(row$confidence, e$confidence, info = e$type)
      }
      if (!is.null(e$canonical)) {
        expect_identical(row$canonical, e$canonical, info = e$type)
      }
      if (!is.null(e$span)) {
        # spec spans are 0-based, end-exclusive; R spans are 1-based, inclusive
        expect_identical(c(row$start - 1L, row$end), as.integer(unlist(e$span)), info = e$type)
      }
      if (!is.null(e$reason)) {
        expect_true(grepl(e$reason, row$reasons, fixed = TRUE), info = row$reasons)
      }
    }
  })
}

for (case in conformance("scan.yaml")$cases) {
  test_that(paste("scan:", case$id), {
    as_column <- function(v) vapply(v, function(x) if (is.null(x)) NA_character_ else x, "")
    data <- as.data.frame(lapply(case$columns, as_column), check.names = FALSE)
    got <- scan_pii(data, sample = case$sample %||% 10000L, min_rate = case$min_rate %||% 0)
    got <- as.data.frame(unclass(got))
    expect_equal(nrow(got), length(case$expect))
    for (i in seq_along(case$expect)) {
      e <- case$expect[[i]]
      for (field in names(e)) {
        expect_equal(got[[field]][i], e[[field]], info = paste("row", i, field))
      }
    }
  })
}

for (case in conformance("redact.yaml")$cases) {
  test_that(paste("redact:", case$id), {
    got <- redact(case$text, context = case$context, min_confidence = case$min_confidence %||% 0)
    expect_identical(got, case$redacted)
    expect_identical(preview(case$text, context = case$context, min_confidence = case$min_confidence %||% 0)$redacted, case$redacted)
  })
}

negatives <- conformance("negatives.yaml")

for (case in negatives$negatives) {
  test_that(paste("hard negative:", case$id), {
    limit <- case$max_confidence %||% 0.5
    got <- detect_pii(case$text)
    confident <- got[got$confidence >= limit, , drop = FALSE]
    expect_equal(nrow(confident), 0, info = paste(confident$type, confident$value, confident$confidence))
  })
}

for (case in negatives$known_false_positives) {
  test_that(paste("known false positive still present:", case$id), {
    expect_true(case$type %in% detect_pii(case$text)$type,
      info = "fixed? move this case to `negatives` in the spec"
    )
  })
}

for (case in conformance("evaluate.yaml")$cases) {
  test_that(paste("evaluate:", case$id), {
    got <- cg_evaluate(case$documents,
      min_confidence = case$min_confidence %||% 0,
      match = case$match %||% "exact"
    )
    got <- as.data.frame(unclass(got))
    expect_equal(nrow(got), length(case$expect))
    for (i in seq_along(case$expect)) {
      e <- case$expect[[i]]
      for (field in names(e)) {
        want <- e[[field]] %||% NA_real_
        expect_equal(got[[field]][i], want, info = paste(case$id, "row", i, field))
      }
    }
  })
}

for (case in conformance("tokenise.yaml")$cases) {
  test_that(paste("tokenise:", case$id), {
    vault <- cg_vault()
    for (step in case$steps) {
      if (!is.null(step$tokenise)) {
        got <- tokenise(unlist(step$tokenise), vault,
          context = step$context, min_confidence = step$min_confidence %||% 0
        )
        expect_identical(got, unlist(step$expect))
      } else if (!is.null(step$restore)) {
        strict <- isTRUE(step$strict)
        if (isTRUE(step$error)) {
          expect_error(restore(step$restore, vault, strict = strict), class = "credgate_unknown_token")
        } else {
          expect_identical(restore(step$restore, vault, strict = strict), step$expect)
        }
      } else {
        entries <- vault$entries
        got <- lapply(seq_len(nrow(entries)), function(i) {
          c(entries$token[i], entries$type[i], entries$canonical[i])
        })
        expect_identical(got, lapply(step$expect, unlist))
      }
    }
  })
}

vault_spec <- conformance("vault.yaml")
for (f in vault_spec$files) {
  test_that(paste("vault file:", f$file), {
    skip_if_not_installed("sodium")
    path <- file.path(cg_spec_path(), "conformance", f$file)
    vault <- vault_open(path, passphrase = f$passphrase)
    e <- vault$entries
    got <- lapply(seq_len(nrow(e)), function(i) {
      c(e$token[i], e$type[i], e$class[i], e$canonical[i], e$value[i])
    })
    expect_identical(got, lapply(f$entries, unlist))
    expect_error(
      vault_open(path, passphrase = vault_spec$wrong_passphrase),
      class = "credgate_vault_file"
    )
  })
}
