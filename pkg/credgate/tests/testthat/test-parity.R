# Functions R shares with the Python package.

test_that("reset_detectors removes registered and loaded detectors", {
  withr::defer(reset_detectors())
  register_detector(new_detector(
    id = "employee_id", class = "internal", label = "Employee ID",
    pattern = bounded("EMP[0-9]{6}")
  ))
  expect_true("employee_id" %in% cg_detectors()$id)
  expect_null(reset_detectors())
  expect_false("employee_id" %in% cg_detectors()$id)
  expect_identical(detect_pii("Approved by EMP123456")$type, character())
  expect_true("aadhaar" %in% cg_detectors()$id)
})

test_that("luhn_check_digit and mask_value are exported, as in Python", {
  expect_identical(luhn_check_digit(c("411111111111111", "7992739871")), c("1", "3"))
  expect_true(luhn_valid(paste0("411111111111111", luhn_check_digit("411111111111111"))))
  expect_identical(mask_value("2345 6789 0124"), "XXXX XXXX 0124")
  expect_identical(mask_value("Lakshmi Verma", class = "personal"), "XXXXXXX XXXXX")
  expect_identical(mask_value("ABCPE1234F", mode = "full"), "XXXXXXXXXX")
  expect_error(mask_value("x", mode = "none"), "partial")
})
