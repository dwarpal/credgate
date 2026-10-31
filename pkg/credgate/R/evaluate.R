#' Evaluate detection against labelled text
#'
#' Measures how well [detect_pii()] finds the PII in documents where every
#' PII span has been labelled: true positives, false positives, false
#' negatives, precision, recall and F1, per type and overall. Use it to
#' check credgate on your own (labelled) data. The rules are shared with the
#' Python package (see the spec's "Evaluation" section).
#'
#' @param documents Labelled documents: a list of lists with `text` and
#'   `spans` (each span a list with `start`, `end` - 0-based, end-exclusive
#'   character offsets - and `type`), or the path of a JSON Lines file in
#'   that format.
#' @param min_confidence Ignore predictions scoring below this value.
#' @param match `"exact"` (same type and offsets) or `"overlap"` (same type,
#'   overlapping spans).
#' @param detectors Detector ids to run; `NULL` runs all registered ones.
#' @return A data frame of class `cg_evaluation` with columns `type`, `tp`,
#'   `fp`, `fn`, `precision`, `recall` and `f1`: one row per type, then
#'   `overall` (micro-averaged). Rates are `NA` when undefined.
#' @export
#' @examples
#' docs <- list(
#'   list(text = "PAN: ABCPE1234F", spans = list(list(start = 5, end = 15, type = "pan"))),
#'   list(text = "order no 878245671885", spans = list())
#' )
#' cg_evaluate(docs)
#' cg_evaluate(docs, min_confidence = 0.5)
cg_evaluate <- function(documents, min_confidence = 0, match = c("exact", "overlap"),
                        detectors = NULL) {
  match <- rlang::arg_match(match)
  if (rlang::is_string(documents)) {
    documents <- cg_read_corpus(documents)
  }
  texts <- vapply(documents, function(d) d$text, character(1))
  pred <- detect_pii(texts, detectors = detectors, min_confidence = min_confidence)
  # R positions are 1-based inclusive; labels are 0-based end-exclusive.
  pred$start0 <- pred$start - 1L

  counts <- list()
  bump <- function(type, i) {
    if (is.null(counts[[type]])) counts[[type]] <<- c(0L, 0L, 0L)
    counts[[type]][i] <<- counts[[type]][i] + 1L
  }

  for (d in seq_along(documents)) {
    gold <- documents[[d]]$spans %||% list()
    if (length(gold) > 0) {
      gold <- gold[order(vapply(gold, `[[`, numeric(1), "start"), vapply(gold, `[[`, numeric(1), "end"))]
    }
    used <- logical(length(gold))
    p <- pred[pred$doc == d, , drop = FALSE]
    p <- p[order(p$start0, p$end), , drop = FALSE]
    for (i in seq_len(nrow(p))) {
      hit <- 0L
      for (j in seq_along(gold)) {
        g <- gold[[j]]
        if (used[j] || g$type != p$type[i]) next
        ok <- if (match == "exact") {
          g$start == p$start0[i] && g$end == p$end[i]
        } else {
          g$start < p$end[i] && p$start0[i] < g$end
        }
        if (ok) {
          hit <- j
          break
        }
      }
      if (hit == 0L) {
        bump(p$type[i], 2L)
      } else {
        used[hit] <- TRUE
        bump(p$type[i], 1L)
      }
    }
    for (j in which(!used)) bump(gold[[j]]$type, 3L)
  }

  types <- sort(names(counts))
  rows <- lapply(types, function(t) score_row(t, counts[[t]]))
  total <- Reduce(`+`, counts, c(0L, 0L, 0L))
  out <- do.call(rbind, c(rows, list(score_row("overall", total))))
  rownames(out) <- NULL
  structure(out, class = c("cg_evaluation", "data.frame"),
    n_documents = length(documents), match = match
  )
}

score_row <- function(type, n) {
  tp <- n[1]
  fp <- n[2]
  fn <- n[3]
  p <- if (tp + fp == 0) NA_real_ else tp / (tp + fp)
  r <- if (tp + fn == 0) NA_real_ else tp / (tp + fn)
  f1 <- if (is.na(p) || is.na(r) || p + r == 0) NA_real_ else 2 * p * r / (p + r)
  data.frame(
    type = type, tp = tp, fp = fp, fn = fn,
    precision = round(p, 4), recall = round(r, 4), f1 = round(f1, 4)
  )
}

#' Read labelled documents from a JSON Lines file
#'
#' @param path Path of a JSON Lines file with one labelled document per
#'   line (see [cg_evaluate()]).
#' @return A list of documents.
#' @export
cg_read_corpus <- function(path) {
  lines <- readLines(path, encoding = "UTF-8", warn = FALSE)
  lines <- lines[nzchar(trimws(lines))]
  lapply(lines, function(l) {
    d <- jsonlite::fromJSON(l, simplifyVector = FALSE)
    Encoding(d$text) <- "UTF-8"
    d
  })
}

#' @export
print.cg_evaluation <- function(x, ...) {
  cli::cli_text(
    "Evaluated {attr(x, 'n_documents')} document{?s}, {attr(x, 'match')} matching:"
  )
  print(as.data.frame(unclass(x)), row.names = FALSE)
  invisible(x)
}
