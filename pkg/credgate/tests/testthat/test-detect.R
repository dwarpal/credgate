test_that("every synthetic identifier is found with supporting context", {
  withr::local_seed(42)
  ids <- synth_indian_pii(100)
  # column -> detector type, text before the value, minimum confidence
  cases <- list(
    aadhaar = list("aadhaar", "Aadhaar: ", 0.9),
    aadhaar_vid = list("aadhaar_vid", "VID: ", 0.9),
    pan = list("pan", "PAN: ", 0.9),
    gstin = list("gstin", "GSTIN: ", 0.9),
    card = list("card", "card: ", 0.9),
    voter_epic = list("voter_epic", "Voter ID: ", 0.9),
    passport = list("passport", "Passport: ", 0.9),
    driving_licence = list("driving_licence", "DL no: ", 0.9),
    mobile = list("mobile_in", "Mobile: ", 0.9),
    email = list("email", "Email: ", 0.9),
    upi_id = list("upi_id", "UPI: ", 0.9),
    ifsc = list("ifsc", "IFSC: ", 0.9),
    bank_account = list("bank_account", "A/c no: ", 0.9),
    abha_number = list("abha_number", "ABHA: ", 0.9),
    abha_address = list("abha_address", "ABHA address: ", 0.9),
    pincode = list("pincode", "PIN: ", 0.9),
    name = list("person_name", "Name: ", 0.8),
    name_hi = list("person_name", "नाम: ", 0.8),
    address = list("address", "lives at ", 0.8)
  )
  for (col in names(cases)) {
    type <- cases[[col]][[1]]
    text <- paste0("Customer ", cases[[col]][[2]], ids[[col]], ".")
    spans <- detect_pii(text)
    found <- spans[spans$type == type, ]
    expect_equal(nrow(found), 100, info = col)
    expect_equal(found$value, ids[[col]], info = col)
    expect_true(all(found$confidence >= cases[[col]][[3]]), info = col)
  }
})

test_that("checksum failures are never reported", {
  withr::local_seed(1)
  good <- credgate:::synth_aadhaar(300)
  bad <- paste0(substr(good, 1, 11), (as.integer(substr(good, 12, 12)) + 1) %% 10)
  spans <- detect_pii(paste("Aadhaar", bad))
  expect_equal(sum(spans$type == "aadhaar"), 0)

  bad_gstin <- paste0(substr("27AAPFU0939F1ZV", 1, 14), "A")
  expect_false("gstin" %in% detect_pii(bad_gstin)$type)
})

test_that("matches do not start or end inside longer numbers", {
  a <- credgate:::synth_aadhaar(1)
  expect_equal(nrow(detect_pii(paste0("9", a))), 0)
  expect_equal(nrow(detect_pii(paste0(a, "1"))), 0)
  # A Visa test number contains 12-digit windows; only the card is reported.
  spans <- detect_pii("4111 1111 1111 1111")
  expect_equal(spans$type, "card")
})

test_that("GSTIN wins over the PAN embedded in it", {
  spans <- detect_pii("GSTIN 27AAPFU0939F1ZV")
  expect_equal(spans$type, "gstin")
  expect_match(spans$reasons, "embeds PAN of firm")
})

test_that("context comes from the text or the context argument", {
  expect_equal(detect_pii("ABC1234567")$confidence, 0.3)
  expect_equal(detect_pii("voter id ABC1234567")$confidence, 0.97)
  expect_equal(detect_pii("ABC1234567", context = "voter_id")$confidence, 0.97)
  expect_equal(detect_pii("मतदाता ABC1234567")$confidence, 0.97)
})

test_that("negative context lowers confidence", {
  a <- credgate:::synth_aadhaar(1)
  plain <- detect_pii(a)$confidence
  order <- detect_pii(paste("order no", a))$confidence
  expect_lt(order, plain)
  expect_equal(nrow(detect_pii(paste("order no", a), min_confidence = 0.5)), 0)
})

test_that("Devanagari digits are detected and positions refer to the original", {
  a <- credgate:::synth_aadhaar(1)
  # Built from code points: chartr() mangles multi-byte text in a C locale.
  dev <- intToUtf8(0x0966 + utf8ToInt(a) - utf8ToInt("0"))
  text <- paste0("आधार ", dev, " है")
  spans <- detect_pii(text)
  expect_equal(spans$type, "aadhaar")
  expect_equal(spans$value, dev)
  expect_equal(spans$canonical, a)
  expect_equal(c(spans$start, spans$end), c(6L, 17L))
})

test_that("zero-width characters inside an identifier do not hide it", {
  spans <- detect_pii("PAN ABC​PE1234F")
  expect_equal(spans$type, "pan")
  expect_equal(spans$canonical, "ABCPE1234F")
})

test_that("multiple documents and empty input", {
  spans <- detect_pii(c("nothing here", "PAN ABCPE1234F", NA))
  expect_equal(spans$doc, 2L)
  expect_s3_class(detect_pii(character()), "cg_spans")
  expect_equal(nrow(detect_pii(character())), 0)
})

test_that("printing masks values", {
  spans <- detect_pii("PAN ABCPE1234F")
  out <- suppressMessages(capture.output(print(spans), type = "output"))
  expect_false(any(grepl("ABCPE1234F", out, fixed = TRUE)))
  expect_true(any(grepl("XXXXXX234F", out, fixed = TRUE)))
})

test_that("names and addresses are masked in full", {
  expect_equal(credgate:::mask_value("Mohan Lal", "personal"), "XXXXX XXX")
  spans <- detect_pii("Shri Mohan Lal, House No 7, Civil Lines, Jaipur 302006")
  expect_true(all(spans$class == "personal"))
  out <- suppressMessages(capture.output(print(spans), type = "output"))
  expect_false(any(grepl("Lal|Jaipur|302006|2006", out)))
  out <- capture.output(print(preview("Shri Mohan Lal, PAN ABCPE1234F")))
  expect_false(any(grepl("Lal", out, fixed = TRUE)))
  expect_true(any(grepl("XXXXXX234F", out, fixed = TRUE)))
  report <- scan_pii(data.frame(remarks = "Shri Mohan Lal called"))
  expect_equal(report$example, "XXXXX XXX")
})

test_that("the full mask mode hides every character", {
  withr::local_options(credgate.mask = "full")
  expect_equal(credgate:::mask_value("ABCPE1234F"), "XXXXXXXXXX")
  out <- suppressMessages(capture.output(print(detect_pii("PAN ABCPE1234F")), type = "output"))
  expect_false(any(grepl("234F", out, fixed = TRUE)))
  out <- capture.output(print(preview("PAN ABCPE1234F")))
  expect_false(any(grepl("234F", out, fixed = TRUE)))
  expect_equal(scan_pii(data.frame(cust_pan = "ABCPE1234F"))$example, "XXXXXXXXXX")
  expect_equal(detect_pii("PAN ABCPE1234F")$value, "ABCPE1234F")
})

test_that("the mask mode comes from the option, then CREDGATE_MASK", {
  withr::local_options(credgate.mask = NULL)
  withr::local_envvar(CREDGATE_MASK = "full")
  expect_equal(credgate:::mask_value("ABCPE1234F"), "XXXXXXXXXX")
  withr::local_options(credgate.mask = "partial")
  expect_equal(credgate:::mask_value("ABCPE1234F"), "XXXXXX234F")
  withr::local_options(credgate.mask = "last4")
  expect_error(credgate:::mask_value("ABCPE1234F"), "partial")
  withr::local_options(credgate.mask = NULL)
  withr::local_envvar(CREDGATE_MASK = "")
  expect_equal(credgate:::mask_value("ABCPE1234F"), "XXXXXX234F")
})

test_that("user detectors can be registered", {
  withr::defer(credgate:::register_builtin_detectors())
  register_detector(new_detector(
    id = "emp_id", class = "internal", label = "Employee ID",
    pattern = bounded("EMP[0-9]{6}")
  ))
  expect_true("emp_id" %in% cg_detectors()$id)
  expect_equal(detect_pii("EMP123456")$type, "emp_id")
  expect_error(register_detector(new_detector(
    id = "emp_id", class = "internal", label = "x", pattern = "x"
  )), "already registered")
})

test_that("synth_indian_pii is reproducible and restores the RNG", {
  set.seed(7)
  before <- runif(1)
  set.seed(7)
  a <- synth_indian_pii(5, seed = 99)
  after <- runif(1)
  expect_equal(before, after)
  expect_equal(a, synth_indian_pii(5, seed = 99))
})
