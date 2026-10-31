# Properties that must hold for any input, checked on generated text:
# synthetic records in many layouts and languages, mutated identifiers,
# random Unicode and pathological inputs.

records <- synth_indian_pii(150, seed = 2026)

# column, expected type, templates ({v} is the value): English, Hindi,
# Hinglish, CSV-, JSON- and form-like layouts.
cases <- list(
  list("aadhaar", "aadhaar", c("Aadhaar: {v}", "आधार नंबर {v} है", "mera aadhaar {v} hai", "{\"aadhaar\": \"{v}\"}")),
  list("pan", "pan", c("PAN: {v}", "Mera PAN {v} hai", "pan={v};", "{v}")),
  list("gstin", "gstin", c("GSTIN {v}", "GST no. {v} registered", "{v}")),
  list("card", "card", c("card {v}", "Debit card number: {v}.")),
  list("mobile", "mobile_in", c("Mobile: {v}", "mobile no. {v} pe call karo", "फोन {v}", "{v},Pune")),
  list("email", "email", c("Email {v}", "<{v}>", "mail: {v}.")),
  list("upi_id", "upi_id", c("UPI: {v}", "pay to {v} via GPay")),
  list("ifsc", "ifsc", c("IFSC {v}", "branch code {v}")),
  list("bank_account", "bank_account", c("A/c no {v}", "account: {v}", "खाता {v}")),
  list("abha_number", "abha_number", c("ABHA {v}", "{v}")),
  list("abha_address", "abha_address", c("{v}", "ABHA address: {v}")),
  list("voter_epic", "voter_epic", c("Voter ID {v}", "EPIC no {v}")),
  list("passport", "passport", c("Passport {v}", "passport no. {v}")),
  list("driving_licence", "driving_licence", c("DL no {v}", "Driving licence: {v}")),
  list("name", "person_name", c("Name: {v}", "Shri {v}", "S/o {v}")),
  list("name_hi", "person_name", c("नाम: {v}")),
  list("address", "address", c("lives at {v}.", "Address: {v}"))
)

generated <- do.call(rbind, lapply(cases, function(case) {
  values <- records[[case[[1]]]]
  do.call(rbind, lapply(case[[3]], function(template) {
    data.frame(
      text = vapply(values, function(v) sub("{v}", v, template, fixed = TRUE), ""),
      value = values,
      type = case[[2]],
      row.names = NULL
    )
  }))
}))

check_span_invariants <- function(text, spans) {
  for (d in unique(spans$doc)) {
    s <- spans[spans$doc == d, , drop = FALSE]
    expect_true(all(s$start >= 1 & s$start <= s$end & s$end <= nchar(text[d])))
    expect_identical(stringi::stri_sub(text[d], s$start, s$end), s$value)
    expect_true(all(s$confidence > 0 & s$confidence <= 1))
    expect_true(all(nzchar(s$canonical)))
    expect_true(all(startsWith(s$reasons, "matched ")))
    expect_true(all(s$start[-1] > s$end[-nrow(s)]), info = "spans overlap or are unordered")
  }
}

test_that("every generated identifier is found with its exact value", {
  spans <- detect_pii(generated$text)
  found <- vapply(seq_len(nrow(generated)), function(i) {
    any(spans$doc == i & spans$type == generated$type[i] & spans$value == generated$value[i])
  }, logical(1))
  expect_true(all(found), info = paste(generated$type[!found], generated$text[!found], collapse = "; "))
})

test_that("span and redaction invariants hold on generated text", {
  spans <- detect_pii(generated$text)
  check_span_invariants(generated$text, spans)
  red <- redact(generated$text)
  expect_identical(redact(red), red)
  long <- spans[nchar(spans$value) >= 4, , drop = FALSE]
  leaked <- mapply(function(d, v) grepl(v, red[d], fixed = TRUE), long$doc, long$value)
  expect_false(any(leaked))
  expect_identical(preview(generated$text)$redacted, red)
})

test_that("multi-document results equal single-document results", {
  texts <- generated$text[seq(1, nrow(generated), by = 7)]
  together <- detect_pii(texts)
  for (i in seq_along(texts)) {
    alone <- detect_pii(texts[i])
    mine <- together[together$doc == i, , drop = FALSE]
    expect_identical(mine$start, alone$start)
    expect_identical(mine$type, alone$type)
    expect_identical(mine$confidence, alone$confidence)
  }
})

test_that("single-character mutations of checksummed identifiers are never reported", {
  withr::local_seed(7)
  for (case in list(c("aadhaar", "Aadhaar "), c("gstin", "GSTIN "), c("card", "card "))) {
    field <- case[[1]]
    alphabet <- if (field == "gstin") c(0:9, LETTERS) else as.character(0:9)
    mutated <- vapply(records[[field]], function(v) {
      pos <- sample(nchar(v), 1)
      old <- substr(v, pos, pos)
      substr(v, pos, pos) <- sample(setdiff(alphabet, old), 1)
      v
    }, "")
    found <- detect_pii(paste0(case[[2]], mutated))
    expect_equal(sum(found$type == field), 0, info = field)
  }
})

fuzz_pool <- c(
  strsplit("abcXYZ0123456789 .,-:/@_+#\n\t", "")[[1]],
  intToUtf8(c(0x200B, 0x200D, 0xFEFF, 0x00AD, 0x2013, 0xFF11, 0x0966, 0x096F, 0x0BE6), multiple = TRUE),
  intToUtf8(0x0905:0x0914, multiple = TRUE),
  intToUtf8(0x0B85:0x0B8E, multiple = TRUE),
  intToUtf8(c(0x1F600, 0x0301, 0x20AC, 0x20B9), multiple = TRUE)
)

test_that("random Unicode never crashes and keeps the invariants", {
  withr::local_seed(42)
  texts <- vapply(1:500, function(i) {
    paste(sample(fuzz_pool, sample(0:120, 1), replace = TRUE), collapse = "")
  }, "")
  spans <- detect_pii(texts)
  check_span_invariants(texts, spans)
  for (n in cg_normalise(texts)) {
    if (!is.null(n$map)) {
      expect_equal(length(n$map), nchar(n$text))
      expect_false(is.unsorted(n$map))
    }
  }
  red <- redact(texts)
  expect_identical(redact(red), red)
})

pathological <- c(
  digits = strrep("1", 50000),
  mobiles = strrep("9876543210 ", 5000),
  labels = strrep("Name: ", 10000),
  honorifics = strrep("Shri ", 10000),
  letters = strrep("A", 100000),
  long_address = paste0("Address: ", strrep("x", 50000)),
  house_keywords = strrep("House No 1, ", 5000),
  rupee = strrep("₹", 20000),
  devanagari = strrep("आधार ", 10000),
  at_signs = paste0(strrep("@", 20000), "ybl")
)

for (name in names(pathological)) {
  test_that(paste("pathological input finishes quickly:", name), {
    elapsed <- system.time(spans <- detect_pii(pathological[[name]]))[["elapsed"]]
    check_span_invariants(pathological[[name]], spans)
    expect_lt(elapsed, 30)
  })
}
