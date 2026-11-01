test_that("whole numbers and factors are scanned, other types skipped", {
  data <- data.frame(
    mobile = c(9876543210, 8826781145, 12.5, NA),
    pan = factor(c("ABCPE1234F", "AAACR5055K", NA, "ABCPE1234F")),
    flag = c(TRUE, FALSE, TRUE, NA),
    when = as.Date("2026-01-01") + 0:3
  )
  report <- scan_pii(data)
  expect_equal(report$column, c("mobile", "pan"))
  expect_equal(report$n_sampled, c(2L, 3L))
  expect_equal(report$n_full, c(2L, 3L))
})

test_that("a data frame without PII gives an empty report", {
  report <- scan_pii(data.frame(x = c("hello", "world")))
  expect_s3_class(report, "cg_scan")
  expect_equal(nrow(report), 0)
  expect_message(print(report), "no PII found")
})

test_that("printing masks examples", {
  report <- scan_pii(data.frame(cust_pan = "ABCPE1234F"))
  out <- suppressMessages(capture.output(print(report), type = "output"))
  expect_false(any(grepl("ABCPE1234F", out, fixed = TRUE)))
  expect_true(any(grepl("XXXXXX234F", out, fixed = TRUE)))
  expect_true(any(grepl("100%", out, fixed = TRUE)))
})

test_that("invalid input is rejected", {
  expect_error(scan_pii(c("a", "b")), "must be a data frame")
  expect_error(scan_pii(data.frame(x = "a"), sample = 0), "positive whole number")
})

test_that("sampling caps the values checked per column", {
  # First half PANs, second half not: evenly spaced positions 0, 10, ..., 90
  # take five from each half.
  data <- data.frame(id = rep(c("ABCPE1234F", "none"), each = 50))
  report <- scan_pii(data, sample = 10)
  expect_equal(report$n_sampled, 10L)
  expect_equal(report$rate, 0.5)
})

test_that("a subset of a scan report still prints", {
  report <- scan_pii(data.frame(pan = c("ABCPE1234F", "AAACR5055K")))
  out <- capture.output(print(report[1, c("column", "type")]))
  expect_true(any(grepl("pan", out)))
})


test_that("custom detectors can use a column label", {
  det <- new_detector(
    id = "staff_pin", class = "sensitive_auth", label = "Staff PIN",
    pattern = "(?i:staff pin)\\s*([0-9]{4})", base = 0.9,
    column_label = "\\bstaff pin\\b", column_pattern = "^[0-9]{4}$"
  )
  register_detector(det)
  withr::defer(credgate:::register_builtin_detectors())
  found <- scan_pii(data.frame(staff_pin = c("4821", "0912"), other = c("4821", "0912")))
  expect_identical(found$column, "staff_pin")
  expect_identical(found$n_full, 2L)
  expect_error(
    new_detector(id = "x", class = "c", label = "x", pattern = "x", column_label = "x"),
    "go together"
  )
})
