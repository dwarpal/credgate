"""Checksum algorithms used to validate identifier candidates.

All functions ignore spaces and hyphens and treat anything else that is not
the expected characters as invalid.
"""

from __future__ import annotations

import regex

from ._spec import detector_spec, engine

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

_DIGITS = regex.compile(r"[0-9]+")
_GSTIN_BODY = regex.compile(r"[0-9A-Z]{14}")
_GSTIN_FULL = regex.compile(r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]")
_GSTIN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def strip_separators(x: str) -> str:
    """Remove the spec's separator characters (spaces and hyphens)."""
    return engine()["separators"].sub("", x)


def _digits(x: str | None) -> str | None:
    if x is None:
        return None
    d = strip_separators(x)
    return d if _DIGITS.fullmatch(d) else None


def _verhoeff_accumulate(digits: str, offset: int) -> int:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + offset) % 8][int(ch)]]
    return c


def verhoeff_valid(x: str | None) -> bool:
    """Whether a number (with its final check digit) passes Verhoeff.

    Used by Aadhaar and Aadhaar Virtual ID.
    """
    d = _digits(x)
    return d is not None and _verhoeff_accumulate(d, 0) == 0


def verhoeff_check_digit(x: str | None) -> str | None:
    """The Verhoeff check digit to append to ``x``, or ``None`` if invalid."""
    d = _digits(x)
    if d is None:
        return None
    return str(_VERHOEFF_INV[_verhoeff_accumulate(d, 1)])


def _luhn_sum(digits: str, with_check: bool) -> int:
    # With the check digit present, every second digit from the right is
    # doubled; when computing a check digit it is the first, third, ...
    doubled = 1 if with_check else 0
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == doubled:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total


def luhn_valid(x: str | None) -> bool:
    """Whether a number passes the Luhn checksum (payment cards)."""
    d = _digits(x)
    return d is not None and _luhn_sum(d, with_check=True) % 10 == 0


def luhn_check_digit(x: str | None) -> str | None:
    """The Luhn check digit to append to ``x``, or ``None`` if invalid."""
    d = _digits(x)
    if d is None:
        return None
    return str((10 - _luhn_sum(d, with_check=False) % 10) % 10)


def gstin_check_char(x: str | None) -> str | None:
    """The mod-36 check character for the first 14 characters of a GSTIN."""
    if x is None:
        return None
    x = x.upper()
    if not _GSTIN_BODY.fullmatch(x):
        return None
    total = 0
    for i, ch in enumerate(x, start=1):
        # Counting from the right, the last character has factor 2, then 1, 2...
        addend = _GSTIN_ALPHABET.index(ch) * (2 if i % 2 == 0 else 1)
        total += addend // 36 + addend % 36
    return _GSTIN_ALPHABET[(36 - total % 36) % 36]


def gstin_valid(x: str | None) -> bool:
    """Whether ``x`` is a structurally valid GSTIN with a correct check character.

    A GSTIN is a 2-digit state code, the holder's PAN, an entity number, the
    letter ``Z`` and the check character.
    """
    if x is None:
        return False
    x = x.upper()
    return (
        _GSTIN_FULL.fullmatch(x) is not None
        and x[:2] in detector_spec()["lists"]["gst_state_codes"]
        and x[14] == gstin_check_char(x[:14])
    )
