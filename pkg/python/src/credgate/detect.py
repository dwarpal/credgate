"""PII detection over text."""

from __future__ import annotations

import os
from bisect import bisect_right
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from typing import Any

import regex

from ._frames import texts
from ._spec import engine
from .detectors import Detector, get_detectors
from .normalise import Normalised, normalise


@dataclass(frozen=True)
class Span:
    """One detected PII match.

    ``start`` and ``end`` are 0-based, end-exclusive code-point offsets into
    the original text of document ``doc``. The representation masks
    ``value``; read the attribute to see it.
    """

    doc: int
    start: int
    end: int
    type: str
    data_class: str
    value: str
    canonical: str
    confidence: float
    reasons: str

    def __repr__(self) -> str:
        return (
            f"Span(doc={self.doc}, start={self.start}, end={self.end}, type={self.type!r}, "
            f"value={mask_value(self.value, self.data_class)!r}, confidence={self.confidence})"
        )

    def to_dict(self, reveal: bool = False) -> dict[str, Any]:
        """A JSON-ready dict; ``value`` is masked and ``canonical`` omitted unless ``reveal``."""
        d = asdict(self)
        d["class"] = d.pop("data_class")
        if not reveal:
            d["value"] = mask_value(self.value, self.data_class)
            del d["canonical"]
        return d


@dataclass(frozen=True)
class Miss:
    """A candidate that looked like an identifier but was not reported, and
    why: a failed check, a keyword the type needs, a confidence below the
    minimum, or a more confident overlapping match. Offsets as in
    :class:`Span`."""

    doc: int
    start: int
    end: int
    type: str
    data_class: str
    value: str
    why: str

    def __repr__(self) -> str:
        return (
            f"Miss(doc={self.doc}, start={self.start}, end={self.end}, type={self.type!r}, "
            f"value={mask_value(self.value, self.data_class)!r}, why={self.why!r})"
        )


def detect_pii(
    text: str | Sequence[str | None] | Any,
    detectors: Sequence[str] | None = None,
    context: str | Sequence[str | None] | None = None,
    min_confidence: float = 0.0,
    window: int | None = None,
) -> list[Span]:
    """Detect PII in one or more documents.

    Runs every registered detector over normalised text, validates
    candidates (checksums, code tables), scores them from nearby context and
    resolves overlapping matches (the more confident, then the longer, span
    wins - so a GSTIN is reported once, not also as the PAN inside it).

    Args:
        text: A string, a sequence of strings, a pandas or Polars Series, or
            an Arrow array; missing values count as empty. Span ``doc`` is
            the position in this sequence.
        detectors: Detector ids to run; ``None`` runs all registered ones.
        context: Extra context per document (one string for all), treated as
            if it appeared next to every match - e.g. a column name, so a
            column called ``voter_id`` supports Voter ID matches.
        min_confidence: Drop matches scoring below this value.
        window: Characters either side of a match searched for context
            keywords; ``None`` uses the spec's ``context_window``.

    Returns:
        Spans ordered by document and position.
    """
    docs = texts(text)[0]
    if context is None or isinstance(context, str):
        contexts = [context or ""] * len(docs)
    else:
        contexts = ["" if c is None else c for c in context]
        if len(contexts) != len(docs):
            raise ValueError("`context` must be one string or one per document.")
    return _detect_with(get_detectors(detectors), docs, contexts, min_confidence, window)


def _detect_with(
    dets: Sequence[Detector],
    docs: Sequence[str],
    contexts: Sequence[str],
    min_confidence: float = 0.0,
    window: int | None = None,
    misses: list[Miss] | None = None,
) -> list[Span]:
    """Detection with the given detectors (registered or not). With
    ``misses`` (a list), candidates that were dropped are added to it, with
    the reason, for explaining a result (see :func:`explain_pii`)."""
    if window is None:
        window = engine()["scoring"]["context_window"]
    norms = [normalise(t) for t in docs]
    joined = _join(norms)
    spans: list[Span] = []
    for det in dets:
        spans.extend(_run_detector(det, docs, norms, contexts, window, joined, misses))
    candidates = spans
    spans = _resolve_overlaps(spans)
    if misses is not None:
        kept = {(s.doc, s.start, s.type) for s in spans}
        misses.extend(
            _miss(c, "a more confident match overlaps it")
            for c in candidates
            if (c.doc, c.start, c.type) not in kept
        )
        misses.extend(
            _miss(s, f"confidence {_num(s.confidence)} is below the minimum {_num(min_confidence)}")
            for s in spans
            if s.confidence < min_confidence
        )
    spans = [s for s in spans if s.confidence >= min_confidence]
    spans.sort(key=lambda s: (s.doc, s.start))
    return spans


# Documents are searched together, joined by a separator no pattern can
# cross (a pattern that would is searched per document instead), so each
# pattern runs once rather than once per document. Results are identical.
_SEPARATOR = "\n\x00\n"


def _join(norms: list[Normalised]) -> tuple[str, list[int]] | None:
    if len(norms) < 2 or any("\x00" in n.text for n in norms):
        return None
    starts, pos = [], 0
    for n in norms:
        starts.append(pos)
        pos += len(n.text) + len(_SEPARATOR)
    return _SEPARATOR.join(n.text for n in norms), starts


def _locate(
    pattern: regex.Pattern[str],
    capture: str | None,
    norms: list[Normalised],
    joined: tuple[str, list[int]] | None,
) -> Iterator[tuple[int, int, int]]:
    """(document, start, end) of each match, in document then position order."""
    if joined is not None:
        text, starts = joined
        found = []
        for m in pattern.finditer(text):
            doc = bisect_right(starts, m.start()) - 1
            if m.end() > starts[doc] + len(norms[doc].text):
                break  # crosses into the next document: search one by one
            s, e = m.span(capture) if capture else m.span()
            if s >= 0:
                found.append((doc, s - starts[doc], e - starts[doc]))
        else:
            yield from found
            return
    for doc, norm in enumerate(norms):
        for m in pattern.finditer(norm.text):
            s, e = m.span(capture) if capture else m.span()
            if s >= 0:
                yield doc, s, e


def _run_detector(
    det: Detector,
    docs: list[str],
    norms: list[Normalised],
    contexts: list[str],
    window: int,
    joined: tuple[str, list[int]] | None = None,
    misses: list[Miss] | None = None,
) -> list[Span]:
    patterns, context_re, negative_re, column_re, column_patterns = det._compiled
    scoring = engine()["scoring"]
    out: list[tuple[int, int, Span]] = []
    candidates = _candidates(det, patterns, column_re, column_patterns, norms, contexts, joined)
    for p, doc, s, e, label in candidates:
        original, norm = docs[doc], norms[doc]
        ntext = norm.text
        matched = ntext[s:e]
        if det.validate is not None and not det.validate(matched):
            if misses is not None:
                check = det.checks.removesuffix(" valid") if det.checks else "validation"
                misses.append(_miss_at(det, docs, norms, doc, s, e, f"fails the check: {check}"))
            continue

        before = ntext[max(0, s - window) : s]
        after = ntext[e : e + window]
        ctx_hit = label or _nearest_keyword(context_re, before, after, contexts[doc])
        neg_hit = _nearest_keyword(negative_re, before, after, contexts[doc])
        if det.context_required and ctx_hit is None:
            if misses is not None:
                keyword = _example_keyword(det.context)
                why = f"needs a keyword such as '{keyword}' within {window} characters"
                misses.append(_miss_at(det, docs, norms, doc, s, e, why))
            continue
        # The stronger cue wins: one before the match (where labels
        # go) beats one after it; on the same side, the nearer wins.
        neg_ignored = ctx_hit is not None and neg_hit is not None and neg_hit[1:] > ctx_hit[1:]

        if ctx_hit is None and det.base_without_context is not None:
            score = det.base_without_context
        else:
            score = det.base(matched) if callable(det.base) else det.base
        if ctx_hit is not None:
            score += (1 - score) * scoring["context_boost"]
        if neg_hit is not None and not neg_ignored:
            score *= scoring["negative_factor"]

        reasons = f"matched {det.label} pattern"
        if det.checks:
            reasons += f"; {det.checks}"
        if ctx_hit is not None:
            reasons += f"; context '{ctx_hit[0]}'"
        if neg_hit is not None:
            if neg_ignored:
                reasons += f"; farther negative context '{neg_hit[0]}' ignored"
            else:
                reasons += f"; negative context '{neg_hit[0]}'"
        if det.describe is not None:
            reasons += f"; {det.describe(matched)}"

        if norm.map is None:
            start, end = s, e
        else:
            start, end = norm.map[s], norm.map[e - 1] + 1
        out.append(
            (
                doc,
                p,
                Span(
                    doc=doc,
                    start=start,
                    end=end,
                    type=det.id,
                    data_class=det.data_class,
                    value=original[start:end],
                    canonical=det.canonical(matched),
                    confidence=round(score, scoring["digits"]),
                    reasons=reasons,
                ),
            )
        )
    # Document, then pattern, then position order, as when searching each
    # document separately (ties in overlap resolution keep this order).
    return [span for _, _, span in sorted(out, key=lambda t: (t[0], t[1]))]


def _miss(span: Span, why: str) -> Miss:
    return Miss(span.doc, span.start, span.end, span.type, span.data_class, span.value, why)


def _miss_at(
    det: Detector, docs: list[str], norms: list[Normalised], doc: int, s: int, e: int, why: str
) -> Miss:
    norm = norms[doc]
    start, end = (s, e) if norm.map is None else (norm.map[s], norm.map[e - 1] + 1)
    return Miss(doc, start, end, det.id, det.data_class, docs[doc][start:end], why)


def _num(x: float) -> str:
    """A number as R's format() shows it (7 significant digits)."""
    return f"{x:.7g}"


_KEYWORD_SYNTAX = regex.compile(r"\\b|\(\?[:!=<]*|[()?^$\\]")
_KEYWORD_CLASS = regex.compile(r"\[[^]]*\][*+?]?")


def _example_keyword(pattern: str | None) -> str:
    """A readable keyword from a context pattern, for messages: its first
    alternative, without regex syntax."""
    first = (pattern or "").split("|")[0]
    return _KEYWORD_CLASS.sub("", _KEYWORD_SYNTAX.sub("", first))


def explain_pii(
    text: str | Sequence[str | None] | Any,
    min_confidence: float = 0.0,
    detectors: Sequence[Detector] | None = None,
) -> tuple[list[Span], list[Miss]]:
    """The matches of :func:`detect_pii`, and the near misses: candidates
    that looked like an identifier but were dropped - a failed checksum, a
    missing keyword the type needs, a confidence below the minimum, or a more
    confident overlapping match. Used by the policy editor's Try it.

    Args:
        text: As for :func:`detect_pii`.
        min_confidence: Drop matches scoring below this value.
        detectors: Detector objects to run (a policy's own, say); ``None``
            runs all registered ones.

    Returns:
        ``(matches, misses)``; a candidate inside a reported match is
        explained by it and not listed as a miss.
    """
    docs = texts(text)[0]
    dets = list(detectors) if detectors is not None else get_detectors(None)
    found: list[Miss] = []
    matches = _detect_with(dets, docs, [""] * len(docs), min_confidence, None, found)
    out: list[Miss] = []
    seen: set[tuple[int, int, int, str]] = set()
    for m in found:
        key = (m.doc, m.start, m.end, m.type)
        inside = any(s.doc == m.doc and s.start < m.end and s.end > m.start for s in matches)
        if inside or key in seen:
            continue
        seen.add(key)
        out.append(m)
    out.sort(key=lambda m: (m.doc, m.start))
    return matches, out


def _candidates(
    det: Detector,
    patterns: tuple[regex.Pattern[str], ...],
    column_re: regex.Pattern[str] | None,
    column_patterns: tuple[regex.Pattern[str], ...],
    norms: list[Normalised],
    contexts: list[str],
    joined: tuple[str, list[int]] | None,
) -> Iterator[tuple[int, int, int, int, tuple[str, int, int] | None]]:
    """(pattern, document, start, end, label) of each candidate. ``label`` is
    the column label keyword for matches of the column patterns, which are
    used only in documents whose extra context matches ``column_label``."""
    for p, pattern in enumerate(patterns):
        for doc, s, e in _locate(pattern, det.capture, norms, joined):
            yield p, doc, s, e, None
    if column_re is None:
        return
    for doc, norm in enumerate(norms):
        m = column_re.search(contexts[doc])
        if m is None:
            continue
        for i, pattern in enumerate(column_patterns):
            for c in pattern.finditer(norm.text):
                yield len(patterns) + i, doc, c.start(), c.end(), (m.group(0), 2, 0)


_WORD_END = regex.compile(r"[\p{L}\p{M}]*")
_WORD_START = regex.compile(r"[\p{L}\p{M}]*$")


def _nearest_keyword(
    pattern: regex.Pattern[str] | None, before: str, after: str, extra: str
) -> tuple[str, int, int] | None:
    """The strongest keyword for a match as (keyword, side, distance): side 0
    (before the match) beats 1 (after it), which beats 2 (the caller's extra
    context); on the same side, the smaller distance - the characters between
    the match and the word containing the keyword - wins."""
    if pattern is None:
        return None
    last = None
    for m in pattern.finditer(before):
        last = m
    if last is not None:
        word_end = _WORD_END.match(before, last.end()).end()
        return (last.group(0), 0, len(before) - word_end)
    m = pattern.search(after)
    if m is not None:
        return (m.group(0), 1, _WORD_START.search(after[: m.start()]).start())
    m = pattern.search(extra)
    if m is not None:
        return (m.group(0), 2, 0)
    return None


def _resolve_overlaps(spans: list[Span]) -> list[Span]:
    """Within each cluster of overlapping spans, keep the most confident, then
    the longest, span; repeat with what remains."""
    spans = sorted(spans, key=lambda s: (s.doc, s.start))
    kept: list[Span] = []
    cluster: list[Span] = []
    running_end = -1
    for s in [*spans, None]:
        if s is not None and cluster and s.doc == cluster[0].doc and s.start < running_end:
            cluster.append(s)
            running_end = max(running_end, s.end)
            continue
        if len(cluster) == 1:
            kept.extend(cluster)
        elif cluster:
            taken: list[Span] = []
            for c in sorted(cluster, key=lambda c: (-c.confidence, -(c.end - c.start))):
                if not any(c.start < t.end and c.end > t.start for t in taken):
                    taken.append(c)
            kept.extend(taken)
        if s is not None:
            cluster = [s]
            running_end = s.end
    return kept


_ALNUM = regex.compile(r"[\p{L}\p{N}]")


# Classes whose values are masked in full: the end of a name or an address
# identifies a person, unlike the last digits of an ID number.
FULL_MASK_CLASSES = frozenset({"personal", "sensitive_auth"})
MASK_MODES = ("partial", "full")
_mask_mode: str | None = None


def set_mask(mode: str | None) -> None:
    """Choose how values are masked wherever credgate shows them (printed
    spans, previews, column-scan examples, the command line).

    Args:
        mode: ``"partial"`` (default) keeps the last 4 characters of
            identifiers, as in UIDAI's masked Aadhaar; ``"full"`` keeps
            nothing, for policies that allow no part of a value to be shown.
            ``None`` falls back to the ``CREDGATE_MASK`` environment
            variable, then to ``"partial"``.
    """
    global _mask_mode
    if mode is not None and mode not in MASK_MODES:
        raise ValueError(f"`mode` must be one of {', '.join(MASK_MODES)}, or None.")
    _mask_mode = mode


def _current_mask() -> str:
    mode = _mask_mode or os.environ.get("CREDGATE_MASK") or "partial"
    if mode not in MASK_MODES:
        raise ValueError(f"CREDGATE_MASK must be one of {', '.join(MASK_MODES)}, not {mode!r}.")
    return mode


def mask_value(x: str, data_class: str | None = None, mode: str | None = None) -> str:
    """Replace letters and digits with ``X``, keeping the last 4 characters
    (2 for values shorter than 8) - the same convention as UIDAI's masked
    Aadhaar. Values of the ``personal`` class (names, addresses) and the
    ``sensitive_auth`` class (card verification codes) keep nothing, and
    neither does any value when the mask mode is ``"full"`` (see
    :func:`set_mask`)."""
    if mode is not None and mode not in MASK_MODES:
        raise ValueError(f"`mode` must be one of {', '.join(MASK_MODES)}, or None.")
    if (mode or _current_mask()) == "full" or data_class in FULL_MASK_CLASSES:
        return _ALNUM.sub("X", x)
    keep = 4 if len(x) >= 8 else 2
    cut = max(0, len(x) - keep)
    return _ALNUM.sub("X", x[:cut]) + x[cut:]
