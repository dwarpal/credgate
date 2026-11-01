audit_policy <- function() {
  cg_policy(list(
    policy = "credgate-policy", version = 1L, id = "audit-test", revision = 2L,
    destinations = list(claude = list(tier = "frontier", provider = "anthropic")),
    rules = list(
      list(id = "card-cvv", when = list(all_of = list("card", "card_cvv")), action = "block"),
      list(id = "redact-all", action = "redact")
    ),
    default_action = "redact"
  ))
}
text <- "Shri Ramesh Kumar, PAN ABCPE1234F, card 4111 1111 1111 1111"
key <- strrep("0123456789abcdef", 4)

test_that("the log never contains text or values", {
  skip_if_not_installed("openssl")
  path <- withr::local_tempfile(fileext = ".jsonl")
  log <- cg_audit_log(path, key = key, actor = "analyst1")
  policy_apply(audit_policy(), text, "claude", audit = log)
  policy_apply(audit_policy(), paste(text, "CVV 123"), "claude", audit = log)
  content <- paste(readLines(path, encoding = "UTF-8"), collapse = "\n")
  # values that cannot occur by chance in timestamps or hex hashes
  for (value in c("Ramesh", "ABCPE1234F", "4111 1111", "CVV 123", "Shri")) {
    expect_false(grepl(value, content, fixed = TRUE), info = value)
  }
  recs <- audit_read(path)
  expect_identical(recs$allowed, c(TRUE, FALSE))
  expect_identical(recs$blocked_by[2], "card-cvv")
  expect_identical(recs$provider[1], "anthropic")
  cvv <- Filter(function(i) i$type == "card_cvv", recs$items[[2]])
  expect_identical(cvv, list(list(type = "card_cvv", action = "block", rule = "card-cvv")))
  expect_true(audit_verify(path)$ok)
})

test_that("without a key identifiers are not hashed", {
  skip_if_not_installed("openssl")
  withr::local_envvar(CREDGATE_AUDIT_KEY = "")
  path <- withr::local_tempfile(fileext = ".jsonl")
  policy_apply(audit_policy(), text, "claude", audit = cg_audit_log(path, actor = "analyst1"))
  expect_true(all(vapply(audit_read(path)$items[[1]], function(i) is.null(i$id), logical(1))))
})

test_that("an empty log is intact", {
  skip_if_not_installed("openssl")
  path <- withr::local_tempfile(fileext = ".jsonl")
  file.create(path)
  check <- audit_verify(path)
  expect_true(check$ok)
  expect_equal(check$records, 0)
  expect_null(check$head)
})
