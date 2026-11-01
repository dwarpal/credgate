"""CredGate: governance layer for LLM requests with Indian PII detection.

Detection rules come from the shared spec (see :func:`spec_path`), so this
package and the R package find exactly the same matches.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("credgate")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.5.0"

from ._spec import spec_path
from .checksums import (
    gstin_check_char,
    gstin_valid,
    luhn_check_digit,
    luhn_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)
from .detect import Span, detect_pii, mask_value, set_mask
from .detectors import Detector, bounded, detectors, register_detector, reset_detectors
from .evaluate import EvaluationReport, TypeScore, evaluate, load_corpus
from .normalise import Normalised, normalise
from .policy import Decision, Policy, PolicyError, PolicyMatch
from .redact import Preview, preview, redact
from .scan import ColumnFinding, ScanReport, scan_pii
from .synth import synth_indian_pii
from .tokenise import (
    TokenCollisionError,
    UnknownTokenError,
    Vault,
    VaultFileError,
    key_fingerprint,
    new_token_key,
    restore,
    tokenise,
)

__all__ = [
    "ColumnFinding",
    "Decision",
    "Detector",
    "EvaluationReport",
    "Normalised",
    "Policy",
    "PolicyError",
    "PolicyMatch",
    "Preview",
    "ScanReport",
    "Span",
    "TokenCollisionError",
    "TypeScore",
    "UnknownTokenError",
    "Vault",
    "VaultFileError",
    "bounded",
    "detect_pii",
    "detectors",
    "evaluate",
    "gstin_check_char",
    "gstin_valid",
    "key_fingerprint",
    "load_corpus",
    "luhn_check_digit",
    "luhn_valid",
    "mask_value",
    "new_token_key",
    "normalise",
    "preview",
    "redact",
    "register_detector",
    "reset_detectors",
    "restore",
    "scan_pii",
    "set_mask",
    "spec_path",
    "synth_indian_pii",
    "tokenise",
    "verhoeff_check_digit",
    "verhoeff_valid",
]
