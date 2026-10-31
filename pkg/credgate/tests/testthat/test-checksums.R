test_that("Verhoeff matches published test vectors", {
  expect_equal(verhoeff_check_digit(c("236", "12345", "142857")), c("3", "1", "0"))
  expect_equal(verhoeff_valid(c("2363", "123451", "1428570")), c(TRUE, TRUE, TRUE))
  expect_equal(verhoeff_valid(c("2364", "123452")), c(FALSE, FALSE))
})

test_that("Verhoeff catches every single-digit error and adjacent swap", {
  withr::local_seed(3)
  ids <- credgate:::synth_aadhaar(200)
  expect_true(all(verhoeff_valid(ids)))
  pos <- sample(1:12, 200, replace = TRUE)
  old <- substr(ids, pos, pos)
  new <- as.character((as.integer(old) + sample(1:9, 200, replace = TRUE)) %% 10)
  mutated <- ids
  substr(mutated, pos, pos) <- new
  expect_false(any(verhoeff_valid(mutated)))

  swapped <- ids[substr(ids, 5, 5) != substr(ids, 6, 6)]
  swapped <- paste0(substr(swapped, 1, 4), substr(swapped, 6, 6), substr(swapped, 5, 5), substr(swapped, 7, 12))
  expect_false(any(verhoeff_valid(swapped)))
})

test_that("checksums ignore separators and reject non-digits", {
  expect_true(verhoeff_valid("2363"))
  expect_true(luhn_valid("4111-1111-1111-1111"))
  expect_equal(verhoeff_valid(c("abc", NA, "")), c(FALSE, FALSE, FALSE))
  expect_equal(luhn_valid(c("abc", NA)), c(FALSE, FALSE))
  expect_equal(verhoeff_check_digit(c("12a", NA)), c(NA_character_, NA_character_))
})

test_that("Luhn matches known numbers", {
  expect_equal(luhn_valid(c("4111 1111 1111 1111", "79927398713", "4111111111111112")), c(TRUE, TRUE, FALSE))
  expect_true(all(luhn_valid(credgate:::synth_card(100))))
})

test_that("GSTIN check character matches the published sample", {
  expect_equal(gstin_check_char("27AAPFU0939F1Z"), "V")
  expect_true(gstin_valid("27AAPFU0939F1ZV"))
  expect_true(gstin_valid("27aapfu0939f1zv"))
  expect_false(gstin_valid("27AAPFU0939F1ZA")) # wrong check char
  expect_false(gstin_valid("00AAPFU0939F1ZH")) # invalid state code
  expect_true(all(gstin_valid(credgate:::synth_gstin(100))))
})
