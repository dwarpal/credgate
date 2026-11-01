#' Redact PII from text
#'
#' Replaces every detected identifier with a placeholder naming its type, for
#' example `[PAN]` or `[PERSON_NAME]`. Everything else in the text is kept
#' exactly. Redaction is irreversible; the rules are shared with the Python
#' package (see the spec's "Redaction" section).
#'
#' @inheritParams detect_pii
#' @return A character vector the same length as `text`, with PII replaced.
#'   `NA` stays `NA`.
#' @seealso [preview()] to see what would be redacted and why.
#' @export
#' @examples
#' redact("Name: Priya Nair; PAN: ABCPN1234K")
#' redact(c("UPI priya.n@oksbi", "nothing here"))
redact <- function(text, detectors = NULL, context = NULL, min_confidence = 0) {
  spans <- detect_pii(text, detectors = detectors, context = context, min_confidence = min_confidence)
  apply_redaction(text, spans)
}

apply_redaction <- function(text, spans) {
  out <- text
  for (d in unique(spans$doc)) {
    s <- spans[spans$doc == d, , drop = FALSE]
    s <- s[order(s$start, decreasing = TRUE), , drop = FALSE]
    value <- out[[d]]
    for (i in seq_len(nrow(s))) {
      stringi::stri_sub(value, s$start[i], s$end[i]) <- placeholder(s$type[i])
    }
    out[[d]] <- value
  }
  out
}

placeholder <- function(type) paste0("[", toupper(type), "]")

#' Preview what would be redacted
#'
#' Shows the redacted text together with each detected identifier (value
#' masked), its confidence and the reasons it was detected - so you can check
#' exactly what would leave the machine before sending anything.
#'
#' @inheritParams detect_pii
#' @return An object of class `cg_preview`: a list with `text` (the input),
#'   `redacted` (as from [redact()]) and `spans` (as from [detect_pii()]).
#'   Printing shows the redacted text and a masked table of the spans.
#' @export
#' @examples
#' preview("Name: Priya Nair; PAN: ABCPN1234K; order no 878245671885")
preview <- function(text, detectors = NULL, context = NULL, min_confidence = 0) {
  spans <- detect_pii(text, detectors = detectors, context = context, min_confidence = min_confidence)
  structure(
    list(text = text, redacted = apply_redaction(text, spans), spans = spans),
    class = "cg_preview"
  )
}

#' @export
print.cg_preview <- function(x, ...) {
  spans <- x$spans
  if (nrow(spans) == 0) {
    cli::cli_text("Nothing would be redacted.")
    return(invisible(x))
  }
  cli::cli_text("{nrow(spans)} item{?s} would be redacted:")
  for (i in seq_along(x$redacted)) {
    if (i %in% spans$doc) {
      prefix <- if (length(x$redacted) > 1) paste0("[", i, "] ") else ""
      cat("  ", prefix, x$redacted[[i]], "\n", sep = "")
    }
  }
  cat("\n")
  shown <- data.frame(
    doc = spans$doc,
    placeholder = placeholder(spans$type),
    value = mask_value(spans$value, spans$class),
    confidence = spans$confidence,
    reasons = spans$reasons
  )
  if (length(x$redacted) == 1) {
    shown$doc <- NULL
  }
  print(shown, row.names = FALSE, right = FALSE)
  invisible(x)
}
