customers <- data.frame(
  cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R"),
  notes = c("Called, Aadhaar 542229371182", "no issues", "mobile 9876543210"),
  balance = c(1520.5, 99.75, 0.25)
)

test_that("every column is recorded, and no values", {
  inv <- pii_inventory(customers, source = "crm", table = "customers")
  expect_s3_class(inv, "cg_inventory")
  expect_identical(unique(inv$column), c("cust_pan", "notes", "balance"))
  path <- withr::local_tempfile(fileext = ".csv")
  write_inventory(inv, path)
  text <- paste(readLines(path, encoding = "UTF-8"), collapse = "\n")
  for (value in c("ABCPE1234F", "1234F", "542229371182", "1182", "9876543210", "3210")) {
    expect_false(grepl(value, text, fixed = TRUE), info = value)
  }
  expect_match(inv$scanned_at[1], "^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ$")
  expect_identical(inv$credgate[1], paste0("r/", utils::packageVersion("credgate")))
})

test_that("inventories combine, and files read back", {
  inv <- rbind(
    pii_inventory(customers, source = "crm", table = "customers"),
    pii_inventory(data.frame(x = "ok"), source = "lake", table = "a,b")
  )
  expect_s3_class(inv, "cg_inventory")
  path <- withr::local_tempfile(fileext = ".csv")
  write_inventory(inv, path)
  expect_equal(as.data.frame(read_inventory(path)), as.data.frame(inv))
  expect_output(suppressMessages(print(inv)), "crm: customers - 3 column\\(s\\) scanned, PII in 2")
})

test_that("source and table are required", {
  expect_error(pii_inventory(customers, source = "", table = "t"), "source")
  expect_error(pii_inventory(customers, source = "crm", table = NULL), "table")
})

test_that("other files are rejected", {
  path <- withr::local_tempfile(fileext = ".csv")
  writeLines(c("a,b", "1,2"), path)
  expect_error(read_inventory(path), "not a credgate inventory")
  write_inventory(pii_inventory(customers, source = "crm", table = "t"), path)
  lines <- readLines(path)
  lines[2] <- sub(",3,", ",three,", lines[2], fixed = TRUE)
  writeLines(lines[1:2], path)
  expect_error(read_inventory(path), "line 2")
})
