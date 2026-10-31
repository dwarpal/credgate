test_that("ASCII text passes through without a map", {
  n <- cg_normalise(c("plain text", NA))
  expect_equal(n[[1]]$text, "plain text")
  expect_null(n[[1]]$map)
  expect_equal(n[[2]]$text, "")
})

test_that("Indic digits become ASCII and positions map back", {
  dev <- "आधार २३४५" # "आधार २३४५"
  n <- cg_normalise(dev)[[1]]
  expect_equal(n$text, "आधार 2345")
  expect_equal(n$map, 1:9)

  for (zero in c(0x09E6, 0x0AE6, 0x0BE6, 0x0C66, 0x06F0)) {
    digits <- intToUtf8(zero + c(2, 3, 4, 5))
    expect_equal(cg_normalise(digits)[[1]]$text, "2345")
  }
})

test_that("invisible characters are removed and dashes and fullwidth normalised", {
  n <- cg_normalise("AB​C–１２")[[1]]
  expect_equal(n$text, "ABC-12")
  # the zero-width space (position 3) is skipped in the map
  expect_equal(n$map, c(1L, 2L, 4L, 5L, 6L, 7L))
})
