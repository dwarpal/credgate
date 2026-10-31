"""CredGate: governance layer for LLM requests with Indian PII detection.

Detection rules come from the shared spec (see :func:`spec_path`), so this
package and the R package find exactly the same matches.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("credgate")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.3.1"

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
from .evaluate import EvaluationReport, TypeScore, evaluate, load_corpus
from .normalise import Normalised, normalise
from .redact import Preview, preview, redact
from .scan import ColumnFinding, ScanReport, scan_pii
from .synth import synth_indian_pii

__all__ = [
    "ColumnFinding",
    "Detector",
    "EvaluationReport",
    "Normalised",
    "Preview",
    "ScanReport",
    "Span",
    "TypeScore",
    "bounded",
    "detect_pii",
    "detectors",
    "evaluate",
    "gstin_check_char",
    "gstin_valid",
    "load_corpus",
    "luhn_check_digit",
    "luhn_valid",
    "mask_value",
    "normalise",
    "preview",
    "redact",
    "register_detector",
    "reset_detectors",
    "scan_pii",
    "spec_path",
    "synth_indian_pii",
    "verhoeff_check_digit",
    "verhoeff_valid",
]
