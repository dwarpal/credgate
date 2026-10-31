"""Irreversible redaction and previews (the spec's "Redaction" rules)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .detect import Span, detect_pii, mask_value


def placeholder(type_: str) -> str:
    """The placeholder that replaces a span of this type, e.g. ``[PAN]``."""
    return f"[{type_.upper()}]"


def _apply(docs: list[str], spans: list[Span]) -> list[str]:
    out = list(docs)
    for s in sorted(spans, key=lambda s: (s.doc, -s.start)):
        t = out[s.doc]
        out[s.doc] = t[: s.start] + placeholder(s.type) + t[s.end :]
    return out


def redact(
    text: str | Sequence[str | None],
    detectors: Sequence[str] | None = None,
    context: str | Sequence[str | None] | None = None,
    min_confidence: float = 0.0,
) -> str | list[str | None]:
    """Replace every detected identifier with a placeholder naming its type.

    For example ``"PAN ABCPE1234F"`` becomes ``"PAN [PAN]"``; everything else
    is kept exactly. Redaction is irreversible.

    Returns a string for a string input, otherwise a list of the same length
    (``None`` stays ``None``).
    """
    if isinstance(text, str):
        return _apply([text], detect_pii(text, detectors, context, min_confidence))[0]
    items = list(text)
    docs = ["" if t is None else t for t in items]
    out = _apply(docs, detect_pii(docs, detectors, context, min_confidence))
    return [None if orig is None else red for orig, red in zip(items, out, strict=True)]


@dataclass(frozen=True)
class Preview:
    """What :func:`redact` would do: the redacted texts and the spans behind them."""

    text: list[str]
    redacted: list[str]
    spans: list[Span]

    def __str__(self) -> str:
        if not self.spans:
            return "Nothing would be redacted."
        n = len(self.spans)
        lines = [f"{n} item{'s' if n != 1 else ''} would be redacted:"]
        docs = sorted({s.doc for s in self.spans})
        for d in docs:
            prefix = f"[{d}] " if len(self.text) > 1 else ""
            lines.append(f"  {prefix}{self.redacted[d].rstrip()}")
        lines.append("")
        width = max(len(placeholder(s.type)) for s in self.spans)
        value_width = max(len(mask_value(s.value)) for s in self.spans)
        for s in self.spans:
            doc = f"[{s.doc}] " if len(self.text) > 1 else ""
            lines.append(
                f"  {doc}{placeholder(s.type):<{width}}  {mask_value(s.value):<{value_width}}"
                f"  {s.confidence:.2f}  {s.reasons}"
            )
        return "\n".join(lines)


def preview(
    text: str | Sequence[str | None],
    detectors: Sequence[str] | None = None,
    context: str | Sequence[str | None] | None = None,
    min_confidence: float = 0.0,
) -> Preview:
    """Show what would be redacted and why, without sending anything.

    Printing the result shows the redacted text and each detected identifier
    (value masked) with its confidence and reasons.
    """
    docs = [text] if isinstance(text, str) else ["" if t is None else t for t in text]
    spans = detect_pii(docs, detectors, context, min_confidence)
    return Preview(text=docs, redacted=_apply(docs, spans), spans=spans)
