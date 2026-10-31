test_that("cg_evaluate reads JSON Lines files", {
  path <- withr::local_tempfile(fileext = ".jsonl")
  writeLines(c(
    '{"id": "a", "text": "PAN: ABCPE1234F", "spans": [{"start": 5, "end": 15, "type": "pan"}]}',
    "",
    '{"id": "b", "text": "\\u0906\\u0927\\u093e\\u0930 542229371182", "spans": [{"start": 5, "end": 17, "type": "aadhaar"}]}'
  ), path, useBytes = TRUE)
  docs <- cg_read_corpus(path)
  expect_length(docs, 2)
  report <- cg_evaluate(path)
  expect_s3_class(report, "cg_evaluation")
  expect_equal(report$tp[report$type == "overall"], 2L)
  expect_equal(report$fp[report$type == "overall"], 0L)
})

test_that("cg_evaluate validates `match` and prints", {
  docs <- list(list(text = "PAN ABCPE1234F", spans = list(list(start = 4, end = 14, type = "pan"))))
  expect_error(cg_evaluate(docs, match = "fuzzy"))
  expect_message(print(cg_evaluate(docs)), "Evaluated 1 document")
})

test_that("documents without spans are negatives", {
  report <- cg_evaluate(list(list(text = "nothing here")))
  expect_equal(report$type, "overall")
  expect_equal(c(report$tp, report$fp, report$fn), c(0L, 0L, 0L))
  expect_true(is.na(report$precision))
})
