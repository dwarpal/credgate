#' Detect PII in text
#'
#' Runs every registered detector over normalised text, validates candidates
#' (checksums, code tables), scores them from nearby context and resolves
#' overlapping matches (the more confident, then the longer, span wins - so
#' a GSTIN is reported once, not also as the PAN inside it).
#'
#' @param text A character vector.
#' @param detectors Detector ids to run; `NULL` runs all registered
#'   detectors (see [cg_detectors()]).
#' @param context Optional extra context per element of `text` (recycled),
#'   treated as if it appeared next to every match. `scan_pii()` (planned) passes column
#'   names here, so a column called `voter_id` supports Voter ID matches.
#' @param min_confidence Drop matches scoring below this value.
#' @param window Number of characters either side of a match searched for
#'   context keywords; `NULL` uses the spec's `context_window`.
#' @return A data frame of class `cg_spans` with one row per match:
#'   `doc` (index into `text`), `start`, `end` (character positions in the
#'   original text), `type`, `class`, `value`, `canonical`, `confidence` and
#'   `reasons`. Printing masks the values.
#' @export
#' @examples
#' detect_pii("Customer PAN ABCPE1234F, GSTIN 27AAPFU0939F1ZV")
detect_pii <- function(text, detectors = NULL, context = NULL,
                       min_confidence = 0, window = NULL) {
  if (!is.character(text)) {
    rlang::abort("`text` must be a character vector.")
  }
  if (!is.null(context)) {
    context <- rep_len(as.character(context), length(text))
    context[is.na(context)] <- ""
  }
  window <- window %||% the$engine$scoring$context_window
  norm <- cg_normalise(text)
  ntext <- vapply(norm, `[[`, character(1), "text")

  found <- lapply(get_detectors(detectors), run_detector,
    text = text, norm = norm, ntext = ntext, context = context,
    window = window
  )
  spans <- do.call(rbind, c(list(empty_spans()), found))
  spans <- resolve_overlaps(spans)
  spans <- spans[spans$confidence >= min_confidence, , drop = FALSE]
  spans <- spans[order(spans$doc, spans$start), , drop = FALSE]
  rownames(spans) <- NULL
  structure(spans, class = c("cg_spans", "data.frame"))
}

run_detector <- function(det, text, norm, ntext, context, window) {
  locs <- lapply(det$pattern, function(pattern) {
    loc <- stringi::stri_locate_all_regex(
      ntext, pattern,
      omit_no_match = TRUE,
      capture_groups = !is.null(det$capture),
      opts_regex = stringi::stri_opts_regex(case_insensitive = det$ignore_case)
    )
    if (!is.null(det$capture)) {
      loc <- lapply(loc, function(m) attr(m, "capture_groups")[[det$capture]])
    }
    loc
  })
  loc <- Reduce(function(a, b) Map(rbind, a, b), locs)
  counts <- vapply(loc, nrow, integer(1))
  if (sum(counts) == 0) {
    return(NULL)
  }
  doc <- rep(seq_along(ntext), counts)
  m <- do.call(rbind, loc)
  s <- m[, 1]
  e <- m[, 2]
  matched <- stringi::stri_sub(ntext[doc], s, e)

  ok <- det$validate(matched)
  doc <- doc[ok]
  s <- s[ok]
  e <- e[ok]
  matched <- matched[ok]
  if (length(doc) == 0) {
    return(NULL)
  }

  n <- nchar(ntext[doc])
  before <- stringi::stri_sub(ntext[doc], pmax(1L, s - window), s - 1L)
  after <- stringi::stri_sub(ntext[doc], e + 1L, pmin(n, e + window))
  extra <- if (is.null(context)) rep("", length(doc)) else context[doc]
  ctx <- nearest_keyword(det$context, before, after, extra, window)
  neg <- nearest_keyword(det$negative, before, after, extra, window)

  if (det$context_required) {
    keep <- !is.na(ctx$hit)
    doc <- doc[keep]
    s <- s[keep]
    e <- e[keep]
    matched <- matched[keep]
    ctx <- ctx[keep, , drop = FALSE]
    neg <- neg[keep, , drop = FALSE]
    if (length(doc) == 0) {
      return(NULL)
    }
  }
  has_ctx <- !is.na(ctx$hit)
  has_neg <- !is.na(neg$hit)
  # The closer cue wins: a negative keyword farther away than a supporting
  # one is ignored.
  neg_ignored <- has_ctx & has_neg & neg$distance > ctx$distance

  scoring <- the$engine$scoring
  score <- if (is.function(det$base)) det$base(matched) else rep(det$base, length(doc))
  if (!is.null(det$base_without_context)) {
    score[!has_ctx] <- det$base_without_context
  }
  score[has_ctx] <- score[has_ctx] + (1 - score[has_ctx]) * scoring$context_boost
  apply_neg <- has_neg & !neg_ignored
  score[apply_neg] <- score[apply_neg] * scoring$negative_factor

  reasons <- paste0("matched ", det$label, " pattern")
  if (!is.null(det$checks)) {
    reasons <- paste0(reasons, "; ", det$checks)
  }
  reasons <- paste0(
    reasons,
    ifelse(has_ctx, paste0("; context '", ctx$hit, "'"), ""),
    ifelse(!has_neg, "",
      ifelse(neg_ignored,
        paste0("; farther negative context '", neg$hit, "' ignored"),
        paste0("; negative context '", neg$hit, "'")
      )
    )
  )
  if (!is.null(det$describe)) {
    reasons <- paste0(reasons, "; ", det$describe(matched))
  }

  orig <- map_spans(norm, doc, s, e)
  data.frame(
    doc = doc,
    start = orig$start,
    end = orig$end,
    type = det$id,
    class = det$class,
    value = stringi::stri_sub(text[doc], orig$start, orig$end),
    canonical = det$canonical(matched),
    confidence = round(score, scoring$digits),
    reasons = reasons
  )
}

# The keyword nearest each match and its distance: the characters between the
# match and the word containing the keyword. Keywords in the caller's extra
# context count as `window` away, farther than any in the text.
nearest_keyword <- function(pattern, before, after, extra, window) {
  n <- length(before)
  hit <- rep(NA_character_, n)
  distance <- rep(NA_integer_, n)
  if (is.null(pattern)) {
    return(data.frame(hit = hit, distance = distance))
  }
  opts <- stringi::stri_opts_regex(case_insensitive = TRUE)
  consider <- function(i, h, d) {
    if (is.na(distance[i]) || d < distance[i]) {
      hit[i] <<- h
      distance[i] <<- d
    }
  }
  loc_before <- stringi::stri_locate_all_regex(before, pattern, opts_regex = opts)
  loc_after <- stringi::stri_locate_first_regex(after, pattern, opts_regex = opts)
  loc_extra <- stringi::stri_locate_first_regex(extra, pattern, opts_regex = opts)
  for (i in seq_len(n)) {
    lb <- loc_before[[i]]
    if (!is.na(lb[1, 1])) {
      last <- lb[nrow(lb), ]
      rest <- stringi::stri_sub(before[i], last[2] + 1L)
      word_end <- last[2] + letters_run(rest, "^[\\p{L}\\p{M}]+")
      consider(i, stringi::stri_sub(before[i], last[1], last[2]), nchar(before[i]) - word_end)
    }
    if (!is.na(loc_after[i, 1])) {
      lead <- stringi::stri_sub(after[i], 1L, loc_after[i, 1] - 1L)
      word_start <- nchar(lead) - letters_run(lead, "[\\p{L}\\p{M}]+$")
      consider(i, stringi::stri_sub(after[i], loc_after[i, 1], loc_after[i, 2]), word_start)
    }
    if (!is.na(loc_extra[i, 1])) {
      consider(i, stringi::stri_sub(extra[i], loc_extra[i, 1], loc_extra[i, 2]), window)
    }
  }
  data.frame(hit = hit, distance = distance)
}

# Length of the match of `pattern` in `x` (0 if none).
letters_run <- function(x, pattern) {
  m <- stringi::stri_extract_first_regex(x, pattern)
  if (is.na(m)) 0L else nchar(m)
}

map_spans <- function(norm, doc, s, e) {
  start <- s
  end <- e
  for (i in which(!vapply(norm[doc], function(n) is.null(n$map), logical(1)))) {
    mapped <- map_span(norm[[doc[i]]]$map, s[i], e[i])
    start[i] <- mapped$start
    end[i] <- mapped$end
  }
  list(start = start, end = end)
}

empty_spans <- function() {
  data.frame(
    doc = integer(), start = integer(), end = integer(),
    type = character(), class = character(), value = character(),
    canonical = character(), confidence = numeric(), reasons = character()
  )
}

resolve_overlaps <- function(spans) {
  if (nrow(spans) < 2) {
    return(spans)
  }
  # Group spans into clusters of mutually overlapping spans (per document);
  # most clusters have one span and are kept as is.
  spans <- spans[order(spans$doc, spans$start), , drop = FALSE]
  n <- nrow(spans)
  running_end <- stats::ave(spans$end, spans$doc, FUN = cummax)
  new_doc <- c(TRUE, spans$doc[-1] != spans$doc[-n])
  cluster <- cumsum(new_doc | spans$start > c(-Inf, running_end[-n]))
  size <- tabulate(cluster)
  keep <- size[cluster] == 1

  # Within a cluster, the more confident, then the longer, span wins.
  for (rows in split(seq_len(n), cluster)[size > 1]) {
    rows <- rows[order(-spans$confidence[rows], -(spans$end[rows] - spans$start[rows]))]
    taken_start <- integer()
    taken_end <- integer()
    for (r in rows) {
      if (!any(spans$start[r] <= taken_end & spans$end[r] >= taken_start)) {
        keep[r] <- TRUE
        taken_start <- c(taken_start, spans$start[r])
        taken_end <- c(taken_end, spans$end[r])
      }
    }
  }
  spans[keep, , drop = FALSE]
}

#' @export
print.cg_spans <- function(x, ..., reveal = FALSE) {
  if (nrow(x) == 0) {
    cli::cli_text("No PII detected.")
    return(invisible(x))
  }
  shown <- as.data.frame(unclass(x))[c("doc", "start", "end", "type", "value", "confidence")]
  if (!reveal) {
    shown$value <- mask_value(shown$value, x$class)
  }
  cli::cli_text("{nrow(x)} PII match{?es} (values masked; use {.code x$value} to see them):")
  print(shown, row.names = FALSE)
  invisible(x)
}

# Replace letters and digits with "X", keeping the last 4 characters (2 for
# short values) - the same convention as UIDAI's masked Aadhaar. Values of the
# "personal" class (names, addresses) keep nothing: their end identifies a
# person, unlike the last digits of an ID number.
# The option `credgate.mask` (or the environment variable `CREDGATE_MASK`)
# set to "full" keeps nothing for any value; see ?credgate-package.
full_mask_classes <- "personal"
mask_modes <- c("partial", "full")

current_mask <- function() {
  mode <- getOption("credgate.mask")
  if (is.null(mode)) {
    mode <- Sys.getenv("CREDGATE_MASK", "partial")
    if (!nzchar(mode)) mode <- "partial"
  }
  if (!rlang::is_string(mode) || !mode %in% mask_modes) {
    rlang::abort('The credgate mask mode (option `credgate.mask` or CREDGATE_MASK) must be "partial" or "full".')
  }
  mode
}

mask_value <- function(x, class = NULL, mode = current_mask()) {
  n <- nchar(x)
  keep <- ifelse(n >= 8, 4L, 2L)
  if (!is.null(class)) keep[class %in% full_mask_classes] <- 0L
  if (identical(mode, "full")) keep[] <- 0L
  prefix <- stringi::stri_sub(x, 1L, n - keep)
  prefix <- stringi::stri_replace_all_regex(prefix, "[\\p{L}\\p{N}]", "X")
  paste0(prefix, stringi::stri_sub(x, n - keep + 1L, n))
}
