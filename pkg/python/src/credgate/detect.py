"""PII detection over text."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

import regex

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


def detect_pii(
    text: str | Sequence[str | None],
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
        text: A string, or a sequence of strings (``None`` counts as empty).
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
    docs = [text] if isinstance(text, str) else ["" if t is None else t for t in text]
    if context is None or isinstance(context, str):
        contexts = [context or ""] * len(docs)
    else:
        contexts = ["" if c is None else c for c in context]
        if len(contexts) != len(docs):
            raise ValueError("`context` must be one string or one per document.")
    if window is None:
        window = engine()["scoring"]["context_window"]

    norms = [normalise(t) for t in docs]
    spans: list[Span] = []
    for det in get_detectors(detectors):
        spans.extend(_run_detector(det, docs, norms, contexts, window))
    spans = _resolve_overlaps(spans)
    spans = [s for s in spans if s.confidence >= min_confidence]
    spans.sort(key=lambda s: (s.doc, s.start))
    return spans


def _run_detector(
    det: Detector,
    docs: list[str],
    norms: list[Normalised],
    contexts: list[str],
    window: int,
) -> list[Span]:
    patterns, context_re, negative_re = det._compiled
    scoring = engine()["scoring"]
    out: list[Span] = []
    for doc, (original, norm) in enumerate(zip(docs, norms, strict=True)):
        ntext = norm.text
        for pattern in patterns:
            for m in pattern.finditer(ntext):
                s, e = m.span(det.capture) if det.capture else m.span()
                if s < 0:
                    continue
                matched = ntext[s:e]
                if det.validate is not None and not det.validate(matched):
                    continue

                around = f"{ntext[max(0, s - window) : s]} {ntext[e : e + window]} {contexts[doc]}"
                ctx_hit = _keyword(context_re, around)
                neg_hit = _keyword(negative_re, around)
                if det.context_required and ctx_hit is None:
                    continue

                score = det.base(matched) if callable(det.base) else det.base
                if ctx_hit is not None:
                    score += (1 - score) * scoring["context_boost"]
                if neg_hit is not None:
                    score *= scoring["negative_factor"]

                reasons = f"matched {det.label} pattern"
                if det.checks:
                    reasons += f"; {det.checks}"
                if ctx_hit is not None:
                    reasons += f"; context '{ctx_hit}'"
                if neg_hit is not None:
                    reasons += f"; negative context '{neg_hit}'"
                if det.describe is not None:
                    reasons += f"; {det.describe(matched)}"

                if norm.map is None:
                    start, end = s, e
                else:
                    start, end = norm.map[s], norm.map[e - 1] + 1
                out.append(
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
                    )
                )
    return out


def _keyword(pattern: regex.Pattern[str] | None, text: str) -> str | None:
    if pattern is None:
        return None
    m = pattern.search(text)
    return m.group(0) if m else None


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
FULL_MASK_CLASSES = frozenset({"personal"})
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
    Aadhaar. Values of the ``personal`` class (names, addresses) keep
    nothing, and neither does any value when the mask mode is ``"full"``
    (see :func:`set_mask`)."""
    if mode is not None and mode not in MASK_MODES:
        raise ValueError(f"`mode` must be one of {', '.join(MASK_MODES)}, or None.")
    if (mode or _current_mask()) == "full" or data_class in FULL_MASK_CLASSES:
        return _ALNUM.sub("X", x)
    keep = 4 if len(x) >= 8 else 2
    cut = max(0, len(x) - keep)
    return _ALNUM.sub("X", x[:cut]) + x[cut:]
