test_that("redact keeps vector shape and NA", {
  out <- redact(c("PAN ABCPE1234F", NA, "", "nothing"))
  expect_identical(out, c("PAN [PAN]", NA, "", "nothing"))
  expect_identical(redact(character()), character())
})

test_that("several spans in one text are all replaced", {
  expect_identical(
    redact("PAN ABCPE1234F and PAN XYZPQ9876R"),
    "PAN [PAN] and PAN [PAN]"
  )
})

test_that("preview prints the redacted text and masks values", {
  p <- preview("Name: Priya Nair; PAN: ABCPN1234K")
  expect_s3_class(p, "cg_preview")
  out <- suppressMessages(capture.output(print(p), type = "output"))
  expect_true(any(grepl("Name: [PERSON_NAME]; PAN: [PAN]", out, fixed = TRUE)))
  expect_false(any(grepl("ABCPN1234K", out, fixed = TRUE)))
  expect_false(any(grepl("Priya", out, fixed = TRUE)))
  expect_true(any(grepl("XXXXXX234K", out, fixed = TRUE)))
})

test_that("preview with nothing to redact", {
  expect_message(print(preview("hello")), "Nothing would be redacted")
})
