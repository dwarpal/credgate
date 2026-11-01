"""Text normalisation before detection.

Detectors run on a normalised copy of the text so that trivial variations
(Devanagari digits, fullwidth characters, zero-width joiners inside an
identifier) cannot hide PII. Every normalised code point remembers which
original code point it came from, so spans are always reported against the
text the caller passed in. The handled code points are listed in the spec
(engine.yaml, ``normalisation``).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from ._spec import engine


@dataclass(frozen=True)
class Normalised:
    """Normalised text and, per code point, the index of the original one.

    ``map`` is ``None`` when every code point maps to exactly one, so
    positions are unchanged.
    """

    text: str
    map: tuple[int, ...] | None


def normalise(text: str | None) -> Normalised:
    """Normalise ``text`` for PII detection.

    Applies NFKC per code point, maps Indic and Arabic-Indic digits to ASCII,
    maps dash variants to ``-`` and removes invisible characters.
    """
    if text is None:
        text = ""
    if text.isascii():
        return Normalised(text, None)

    # Usually every code point maps to exactly one (Devanagari letters stay,
    # Indic digits become ASCII digits): positions do not move, so translate
    # in one call and keep no map.
    table = {cp: _normalise_cached(cp) for cp in {ord(ch) for ch in text if ord(ch) >= 128}}
    if all(len(rep) == 1 for rep in table.values()):
        return Normalised(text.translate(table), None)

    pieces: list[str] = []
    mapping: list[int] = []
    cache: dict[str, str] = {}
    for i, ch in enumerate(text):
        if ord(ch) < 128:
            rep = ch
        else:
            rep = cache.get(ch)
            if rep is None:
                rep = cache[ch] = _normalise_code_point(ord(ch))
        pieces.append(rep)
        mapping.extend([i] * len(rep))

    out = "".join(pieces)
    if out == text and len(mapping) == len(text):
        return Normalised(out, None)
    return Normalised(out, tuple(mapping))


_CACHE: dict[int, str] = {}


def _normalise_cached(cp: int) -> str:
    rep = _CACHE.get(cp)
    if rep is None:
        rep = _CACHE[cp] = _normalise_code_point(cp)
    return rep


def _normalise_code_point(cp: int) -> str:
    e = engine()
    if cp in e["remove"]:
        return ""
    if cp in e["dash"]:
        return "-"
    for zero in e["digit_zeros"]:
        if zero <= cp <= zero + 9:
            return str(cp - zero)
    return unicodedata.normalize("NFKC", chr(cp))
