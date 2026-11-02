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

# --- rotation and retention ---------------------------------------------------

at <- function(year, month, day = 1) as.POSIXct(sprintf("%d-%02d-%02d 12:00:00", year, month, day), tz = "UTC")

write_months <- function(path, months, per_month = 3) {
  log <- cg_audit_log(path, rotate = TRUE)
  decision <- policy_decide(audit_policy(), text, "claude")
  for (m in months) {
    for (day in seq_len(per_month)) audit_record(log, decision, time = at(m[1], m[2], day))
  }
  log
}

test_that("rotation keeps one chain across months", {
  skip_if_not_installed("openssl")
  dir <- withr::local_tempdir()
  path <- file.path(dir, "audit.jsonl")
  write_months(path, list(c(2026, 9), c(2026, 10), c(2026, 11)))
  expect_setequal(list.files(dir), c("audit.2026-09.jsonl", "audit.2026-10.jsonl", "audit.jsonl"))
  check <- audit_verify(path)
  expect_true(check$ok)
  expect_identical(check$records, 9L)
  expect_identical(check$files, 3L)
  expect_identical(audit_read(path)$seq, 1:9)
})

test_that("tampering with segments is detected", {
  skip_if_not_installed("openssl")
  dir <- withr::local_tempdir()
  path <- file.path(dir, "audit.jsonl")
  write_months(path, list(c(2026, 9), c(2026, 10), c(2026, 11)))
  october <- file.path(dir, "audit.2026-10.jsonl")
  saved <- readBin(october, "raw", 1e6)
  unlink(october)
  expect_false(audit_verify(path)$ok)
  edited <- sub('"allowed":true', '"allowed":false', rawToChar(saved), fixed = TRUE)
  writeBin(charToRaw(edited), october)
  check <- audit_verify(path)
  expect_false(check$ok)
  expect_identical(check$file, "audit.2026-10.jsonl")
})

test_that("retention prunes old months and the rest still verifies", {
  skip_if_not_installed("openssl")
  dir <- withr::local_tempdir()
  path <- file.path(dir, "audit.jsonl")
  write_months(path, list(c(2020, 1), c(2020, 2), c(2021, 12), c(2026, 10), c(2026, 11)))
  removed <- audit_prune(path, keep_years = 5, now = at(2026, 11, 2))
  expect_identical(removed, c("audit.2020-01.jsonl", "audit.2020-02.jsonl"))
  manifest <- jsonlite::fromJSON(file.path(dir, "audit.pruned.json"))
  expect_identical(manifest$last_seq, 6L)
  check <- audit_verify(path)
  expect_true(check$ok)
  expect_identical(check$records, 9L)
  audit_record(cg_audit_log(path, rotate = TRUE), policy_decide(audit_policy(), text, "claude"), time = at(2026, 12))
  expect_identical(utils::tail(audit_read(path)$seq, 1), 16L)
  expect_true(audit_verify(path)$ok)
})

test_that("pruning is careful", {
  skip_if_not_installed("openssl")
  dir <- withr::local_tempdir()
  path <- file.path(dir, "audit.jsonl")
  write_months(path, list(c(2020, 1), c(2026, 10)))
  expect_error(audit_prune(path, keep_years = 0), "at least 1")
  expect_identical(audit_prune(path, keep_years = 5, now = at(2025, 1, 31)), character())
  segment <- file.path(dir, "audit.2020-01.jsonl")
  writeLines(sub('"seq":2', '"seq":7', readLines(segment), fixed = TRUE), segment)
  expect_error(audit_prune(path, keep_years = 5, now = at(2026, 11, 2)), "broken")
  expect_true(file.exists(segment))
})

test_that("audit files are private", {
  skip_if_not_installed("openssl")
  skip_on_os("windows")
  dir <- withr::local_tempdir()
  path <- file.path(dir, "audit.jsonl")
  write_months(path, list(c(2020, 1), c(2026, 10)))
  audit_prune(path, keep_years = 5, now = at(2026, 11, 2))
  for (f in list.files(dir, full.names = TRUE)) {
    expect_identical(format(file.mode(f)), "600", info = basename(f))
  }
})
