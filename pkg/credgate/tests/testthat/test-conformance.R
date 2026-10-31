# Runs the shared conformance cases in inst/spec/conformance, which every
# CredGate implementation must pass.

conformance <- function(file) {
  yaml::read_yaml(file.path(cg_spec_path(), "conformance", file))
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
