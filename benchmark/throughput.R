# Measure how fast credgate processes text in R, on one CPU core.
#
# Builds the same inputs as throughput.py from corpus/test.jsonl, except the
# `field` set, which uses R's own synthetic generator (same field types).
#
# Usage (from the repository root, with credgate installed or via pkgload):
#   Rscript benchmark/throughput.R

if (requireNamespace("pkgload", quietly = TRUE) && dir.exists("pkg/credgate")) {
  pkgload::load_all("pkg/credgate", quiet = TRUE)
} else {
  library(credgate)
}

docs <- lapply(readLines("benchmark/corpus/test.jsonl", encoding = "UTF-8"), jsonlite::fromJSON)
texts <- vapply(docs, `[[`, character(1), "text")
fields <- c("pan", "mobile", "aadhaar", "email", "upi_id", "gstin", "voter_epic", "ifsc")
records <- synth_indian_pii(500, seed = 7)
starts <- seq(1, length(texts) - 11, by = 12)
sets <- list(
  field = unlist(records[fields], use.names = FALSE),
  note = texts,
  long = vapply(starts, function(i) paste(texts[i:(i + 11)], collapse = "\n"), character(1)),
  clean = texts[vapply(docs, function(d) length(d$spans) == 0, logical(1))]
)

best_time <- function(f, repeat_ = 3) {
  min(vapply(seq_len(repeat_), function(i) system.time(f())[["elapsed"]], numeric(1)))
}

invisible(detect_pii("warm up PAN ABCPE1234F"))
cat(sprintf("credgate %s (%s), one core\n\n", packageVersion("credgate"), R.version.string))
cat("| Input | Values | Mean characters | detect_pii values/s | redact values/s | tokenise values/s | MB/s (detect) |\n")
cat("|---|---:|---:|---:|---:|---:|---:|\n")
for (name in names(sets)) {
  x <- sets[[name]]
  d <- best_time(function() detect_pii(x))
  r <- best_time(function() redact(x))
  k <- best_time(function() tokenise(x, cg_vault()))
  cat(sprintf(
    "| %s | %s | %.0f | %s | %s | %s | %.2f |\n", name,
    format(length(x), big.mark = ","), mean(nchar(x)),
    format(round(length(x) / d), big.mark = ","), format(round(length(x) / r), big.mark = ","),
    format(round(length(x) / k), big.mark = ","), sum(nchar(x)) / d / 1e6
  ))
}
