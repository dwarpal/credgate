"""Synthetic Indian identifiers for tests, demos and detector benchmarks."""

from __future__ import annotations

import random

from ._spec import detector_spec
from .checksums import gstin_check_char, luhn_check_digit, verhoeff_check_digit

FIRST_NAMES = (
    "Aarav", "Vivaan", "Aditya", "Priya", "Ananya", "Lakshmi", "Rohan", "Sneha",
    "Arjun", "Kavya", "Imran", "Fatima", "Gurpreet", "Harpreet", "Joseph",
    "Mary", "Venkatesh", "Meenakshi", "Subhash", "Anjali",
)  # fmt: skip
LAST_NAMES = (
    "Sharma", "Verma", "Patel", "Reddy", "Iyer", "Nair", "Singh", "Khan", "Das",
    "Banerjee", "Gupta", "Joshi", "Kulkarni", "Menon", "Fernandes",
    "Chatterjee", "Rao", "Yadav", "Mishra", "Pillai",
)  # fmt: skip
FIRST_NAMES_HI = ("रमेश", "सुनीता", "अनिल", "प्रिया", "राजेश", "पूजा", "विकास", "नेहा")
LAST_NAMES_HI = ("कुमार", "शर्मा", "वर्मा", "सिंह", "यादव", "गुप्ता", "देवी")
LOCALITIES = (
    "Laxmi Nagar", "Shanti Colony", "MG Road", "Sector 21", "Gandhi Marg",
    "Shivaji Park", "Anna Salai", "Civil Lines",
)  # fmt: skip
CITIES = ("Pune", "Delhi", "Chennai", "Kolkata", "Lucknow", "Jaipur", "Bengaluru", "Indore")
EMAIL_DOMAINS = ("example.com", "example.org")  # reserved for documentation (RFC 2606)
UPI_HANDLES = ("okaxis", "ybl", "oksbi", "paytm", "ibl")
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def synth_indian_pii(n: int = 10, seed: int | None = None) -> list[dict[str, str]]:
    """Generate ``n`` synthetic records of Indian identifiers.

    Values pass the same structural and checksum validation as real ones.
    They are random, not taken from any real record, but a random number
    with a valid checksum can still coincide with a real one by chance, so
    treat generated data as test data and never as anonymised data. Names
    combine common Indian first names and surnames; email addresses use the
    reserved ``example.com``/``example.org`` domains.

    Uses its own random generator; the global ``random`` state is untouched.
    """
    rng = random.Random(seed)
    # Fields added later come from a second generator, so every earlier field
    # keeps its value for a given seed.
    extra = random.Random(None if seed is None else f"credgate-synth-extra-{seed}")
    return [{**_record(rng), **_extra(extra)} for _ in range(n)]


def _extra(rng: random.Random) -> dict[str, str]:
    states = detector_spec()["lists"]["india_state_codes"]
    state = rng.choice(states)
    return {
        "ckyc": str(rng.randint(1, 9)) + _digits(rng, 13),
        "ration_card": (state + _digits(rng, 10) if rng.random() < 0.5 else _digits(rng, 12)),
        "nrega_job_card": (
            f"{state}-{rng.randint(1, 75):02d}-{rng.randint(1, 999):03d}-"
            f"{rng.randint(1, 999):03d}-{rng.randint(1, 999):03d}/{rng.randint(1, 9999)}"
        ),
        "card_cvv": _digits(rng, 3),
        "card_expiry": f"{rng.randint(1, 12):02d}/{rng.randint(27, 32)}",
    }


def _digits(rng: random.Random, k: int) -> str:
    return "".join(rng.choice("0123456789") for _ in range(k))


def _letters(rng: random.Random, k: int, alphabet: str = UPPER) -> str:
    return "".join(rng.choice(alphabet) for _ in range(k))


def _pan(rng: random.Random, holder: str = "P") -> str:
    return _letters(rng, 3) + holder + _letters(rng, 1) + _digits(rng, 4) + _letters(rng, 1)


def _record(rng: random.Random) -> dict[str, str]:
    spec = detector_spec()
    first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
    tag = rng.randint(10, 99)
    pincode = str(rng.randint(1, 8)) + _digits(rng, 5)

    aadhaar = str(rng.randint(2, 9)) + _digits(rng, 10)
    vid = _digits(rng, 15)
    gstin = (
        f"{rng.randint(1, 37):02d}"
        + _pan(rng, rng.choice(list(spec["tables"]["pan_holder_types"])))
        + str(rng.randint(1, 9))
        + "Z"
    )
    card = "4" + _digits(rng, 14)
    passport_first = "".join(c for c in UPPER if c not in "QXZ")

    return {
        "name": f"{first} {last}",
        "name_hi": f"{rng.choice(FIRST_NAMES_HI)} {rng.choice(LAST_NAMES_HI)}",
        "aadhaar": aadhaar + verhoeff_check_digit(aadhaar),
        "aadhaar_vid": vid + verhoeff_check_digit(vid),
        "pan": _pan(rng),
        "gstin": gstin + gstin_check_char(gstin),
        "card": card + luhn_check_digit(card),
        "voter_epic": _letters(rng, 3) + _digits(rng, 7),
        "passport": (
            _letters(rng, 1, passport_first)
            + str(rng.randint(1, 9))
            + _digits(rng, 5)
            + str(rng.randint(1, 9))
        ),
        "driving_licence": (
            rng.choice(spec["lists"]["india_state_codes"])
            + _digits(rng, 2)
            + str(rng.randint(1990, 2025))
            + _digits(rng, 7)
        ),
        "mobile": str(rng.randint(6, 9)) + _digits(rng, 9),
        "email": f"{first.lower()}.{last.lower()}{tag}@{rng.choice(EMAIL_DOMAINS)}",
        "upi_id": f"{first.lower()}{tag}@{rng.choice(UPI_HANDLES)}",
        "ifsc": rng.choice(["HDFC", "ICIC", "SBIN", "UTIB", "PUNB", "KKBK"])
        + "0"
        + _digits(rng, 6),
        "bank_account": _digits(rng, rng.randint(9, 18)),
        "abha_number": f"{_digits(rng, 2)}-{_digits(rng, 4)}-{_digits(rng, 4)}-{_digits(rng, 4)}",
        "abha_address": f"{first.lower()}.{last[0].lower()}{rng.randint(10, 99)}@abdm",
        "pincode": pincode,
        "address": (
            f"House No {rng.randint(1, 250)}, {rng.choice(LOCALITIES)}, "
            f"{rng.choice(CITIES)} {pincode}"
        ),
    }
