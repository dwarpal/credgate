"""CredGate: governance layer for LLM requests with Indian PII detection.

Detection rules come from the shared spec (see :func:`spec_path`), so this
package and the R package find exactly the same matches.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("credgate")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.1.0"

from ._spec import spec_path
from .checksums import (
    gstin_check_char,
    gstin_valid,
    luhn_check_digit,
    luhn_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)
from .detect import Span, detect_pii, mask_value
from .detectors import Detector, bounded, detectors, register_detector, reset_detectors
from .normalise import Normalised, normalise
from .synth import synth_indian_pii

__all__ = [
    "Detector",
    "Normalised",
    "Span",
    "bounded",
    "detect_pii",
    "detectors",
    "gstin_check_char",
    "gstin_valid",
    "luhn_check_digit",
    "luhn_valid",
    "mask_value",
    "normalise",
    "register_detector",
    "reset_detectors",
    "spec_path",
    "synth_indian_pii",
    "verhoeff_check_digit",
    "verhoeff_valid",
]
