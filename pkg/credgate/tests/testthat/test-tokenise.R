test_that("tokenise keeps NA and modifies the vault in place", {
  vault <- cg_vault()
  expect_identical(
    tokenise(c("PAN ABCPE1234F", NA, ""), vault),
    c("PAN [PAN_1]", NA, "")
  )
  expect_equal(length(vault), 1)
  expect_identical(restore(c("[PAN_1]", NA), vault), c("ABCPE1234F", NA))
})

test_that("printing a vault masks values unless asked", {
  vault <- cg_vault()
  expect_message(print(vault), "Empty vault")
  tokenise("Shri Ramesh Kumar, PAN ABCPE1234F", vault)
  out <- capture.output(suppressMessages(print(vault)))
  expect_false(any(grepl("Ramesh|ABCPE", out)))
  expect_true(any(grepl("XXXXXX234F", out, fixed = TRUE)))
  revealed <- as.data.frame(vault, reveal = TRUE)
  expect_identical(revealed$value, c("Ramesh Kumar", "ABCPE1234F"))
  expect_identical(revealed$token, c("[PERSON_NAME_1]", "[PAN_1]"))
})

test_that("tokenise and restore check their arguments", {
  expect_error(tokenise("PAN ABCPE1234F", list()), "cg_vault")
  expect_error(restore("x", NULL), "cg_vault")
  expect_error(tokenise(123, cg_vault()), "character vector")
  expect_error(restore(1, cg_vault()), "character vector")
})

test_that("strict restore names the unknown tokens", {
  vault <- cg_vault()
  tokenise("PAN ABCPE1234F", vault)
  expect_error(restore("[PAN_1] [PAN_7] [pan_7]", vault, strict = TRUE), "\\[PAN_7\\], \\[pan_7\\]")
})

test_that("tokenise and redact replace the same spans", {
  text <- "Name: Priya Nair; PAN: ABCPN1234K; UPI priya.n@oksbi"
  tokens <- tokenise(text, cg_vault())
  expect_identical(
    gsub("_[0-9]+\\]", "]", tokens),
    redact(text)
  )
})
