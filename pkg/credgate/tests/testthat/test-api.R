test_that("detect_pii validates input and handles NA", {
  expect_error(detect_pii(123), "character vector")
  expect_equal(detect_pii(c(NA, "PAN ABCPE1234F"))$doc, 2L)
})

test_that("detector subset, min_confidence and window", {
  text <- "PAN ABCPE1234F, order no 878245671885"
  expect_setequal(detect_pii(text, detectors = "pan")$type, "pan")
  expect_setequal(detect_pii(text)$type, c("pan", "aadhaar"))
  expect_setequal(detect_pii(text, min_confidence = 0.5)$type, "pan")
  expect_error(detect_pii(text, detectors = "nope"), "Unknown detector")

  far <- paste0("voter", strrep(" ", 60), "FSO6231132")
  expect_equal(detect_pii(far)$confidence, 0.3)
  expect_equal(detect_pii(far, window = 80)$confidence, 0.97)
})

test_that("text cues outweigh extra context", {
  # Extra context (a column name) counts as farther than any cue in the text.
  expect_equal(detect_pii("order 542229371182", context = "aadhaar")$confidence, 0.48)
  s <- detect_pii("Aadhaar 542229371182", context = "order id")
  expect_equal(s$confidence, 0.97)
  expect_match(s$reasons, "farther negative context 'order' ignored", fixed = TRUE)
})

test_that("context is recycled across documents", {
  spans <- detect_pii(c("ABC1234567", "ABC1234567"), context = c("voter_id", NA))
  expect_equal(spans$doc, 1:2)
  expect_equal(spans$confidence, c(0.97, 0.3))
  expect_equal(detect_pii(c("ABC1234567", "ABC1234567"), context = "voter")$doc, 1:2)
})

test_that("print can reveal values when asked", {
  spans <- detect_pii("PAN ABCPE1234F")
  out <- suppressMessages(capture.output(print(spans, reveal = TRUE), type = "output"))
  expect_true(any(grepl("ABCPE1234F", out, fixed = TRUE)))
})

test_that("new_detector validates base_without_context", {
  args <- list(id = "x", class = "c", label = "X", pattern = "X[0-9]+")
  expect_error(do.call(new_detector, c(args, base_without_context = 0.3)), "needs `context`")
  expect_error(
    do.call(new_detector, c(args, base_without_context = 0.3, context = "x", context_required = TRUE)),
    "exclude each other"
  )
  expect_error(do.call(new_detector, c(args, base_without_context = 0, context = "x")))
})

test_that("new_detector validates its arguments", {
  expect_error(new_detector(id = "x", class = "c", label = "x", pattern = "x", base = 1.5))
  expect_error(new_detector(id = 1, class = "c", label = "x", pattern = "x"))
  expect_error(new_detector(id = "x", class = "c", label = "x", pattern = NA_character_))
  expect_error(register_detector(list(id = "x")), "new_detector")
})

test_that("a detector can be overwritten and the built-ins restored", {
  withr::defer(credgate:::register_builtin_detectors())
  register_detector(
    new_detector(id = "pan", class = "custom", label = "Custom PAN", pattern = "ZZZ[0-9]{3}"),
    overwrite = TRUE
  )
  expect_equal(detect_pii("ZZZ123")$class, "custom")
  expect_equal(nrow(detect_pii("ABCPE1234F")), 0)
  credgate:::register_builtin_detectors()
  expect_equal(detect_pii("ABCPE1234F")$type, "pan")
})

test_that("compiling a bad detector spec fails loudly", {
  good <- list(id = "x", class = "c", label = "X", patterns = list("x"), base = 0.5)
  expect_error(credgate:::compile_detector(c(good, list(pattens = "typo"))), "unknown field")
  bad <- good
  bad$patterns <- list("{{nope}}")
  expect_error(credgate:::compile_detector(bad), "Unknown fragment")
  expect_error(credgate:::compile_detector(c(good, list(validate = list("md5")))), "Unknown validator")
  expect_error(credgate:::compile_detector(c(good, list(canonical = "shout"))), "Unknown canonical")
})

test_that("an unsupported spec version is rejected", {
  dir <- withr::local_tempdir()
  lines <- readLines(file.path(cg_spec_path(), "engine.yaml"), encoding = "UTF-8")
  writeLines(sub("spec_version: 1", "spec_version: 99", lines, fixed = TRUE), file.path(dir, "engine.yaml"))
  expect_error(credgate:::read_spec_file(dir, "engine.yaml"), "Unsupported spec_version 99")
})

test_that("the shipped spec contains every file", {
  files <- list.files(cg_spec_path(), recursive = TRUE)
  expect_true(all(c(
    "engine.yaml", "detectors.yaml", "README.md", "conformance/detect.yaml",
    "conformance/checksums.yaml", "conformance/scan.yaml", "conformance/redact.yaml",
    "conformance/negatives.yaml"
  ) %in% files))
  expect_equal(nrow(cg_detectors()), 19)
})

test_that("checksums handle edge inputs and Indic digits", {
  expect_false(verhoeff_valid("२३६३")) # only ASCII digits are checksummed
  expect_identical(verhoeff_check_digit(""), NA_character_)
  expect_identical(luhn_valid(c("4111111111111111", NA, "")), c(TRUE, FALSE, FALSE))
  expect_false(gstin_valid("27AAPFU0939F1Z"))
  expect_identical(gstin_check_char(NA), NA_character_)
})

test_that("synthetic records are valid and seeds differ", {
  r <- synth_indian_pii(200, seed = 5)
  expect_equal(nrow(r), 200)
  expect_true(all(verhoeff_valid(r$aadhaar)))
  expect_false(any(substr(r$aadhaar, 1, 1) %in% c("0", "1")))
  expect_true(all(verhoeff_valid(r$aadhaar_vid)))
  expect_true(all(gstin_valid(r$gstin)))
  expect_true(all(luhn_valid(r$card)))
  expect_true(all(grepl("@example\\.(com|org)$", r$email)))
  expect_false(identical(synth_indian_pii(3, seed = 1), synth_indian_pii(3, seed = 2)))
})

test_that("scan_pii options", {
  data <- data.frame(notes = c("PAN ABCPE1234F", "Aadhaar 542229371182", "x", "y"))
  expect_setequal(scan_pii(data)$type, c("pan", "aadhaar"))
  expect_setequal(scan_pii(data, detectors = "pan")$type, "pan")
  expect_equal(nrow(scan_pii(data, min_rate = 0.5)), 0)
  expect_equal(nrow(scan_pii(data.frame())), 0)
})

test_that("cg_normalise validates input", {
  expect_error(cg_normalise(1:3), "character vector")
  expect_identical(cg_normalise(character()), list())
})
