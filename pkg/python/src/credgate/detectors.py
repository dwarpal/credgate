"""Detector registry.

A detector finds candidate spans with a regex, validates them (checksums,
code tables), and scores them using surrounding context. Built-in detectors
are defined in the shared spec (detectors.yaml) and compiled on first use;
users can add their own with :func:`register_detector`.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import regex

from ._spec import detector_spec, engine
from .checksums import gstin_valid, luhn_valid, strip_separators, verhoeff_valid

_DETECTOR_FIELDS = {
    "id", "class", "label", "patterns", "bounded", "capture", "ignore_case",
    "validate", "checks", "base", "base_without_context", "context", "negative",
    "context_required", "describe", "canonical", "column_label",
}  # fmt: skip


def canonical_default(x: str) -> str:
    """Remove spaces and hyphens and upper-case."""
    return strip_separators(x).upper()


@dataclass(frozen=True)
class Detector:
    """A PII detector.

    Args:
        id: Unique identifier, reported as the span ``type``.
        data_class: Data class used by policies, e.g. ``"identity_strong"``.
        label: Human-readable name.
        patterns: Regular expressions (Python ``regex`` syntax) for
            candidates; matches of all patterns are combined. Wrap them with
            :func:`bounded` so they do not match inside a longer token.
        capture: Name of a capture group whose span is reported instead of
            the whole match.
        validate: Called with each matched string (normalised text);
            candidates returning ``False`` are dropped.
        checks: Short description of what ``validate`` checks, added to the
            reasons.
        base: Confidence (0-1) without supporting context, or a function of
            the matched string returning it.
        base_without_context: Confidence (0-1) used instead of ``base`` when no
            context keyword is found; for patterns that are strong evidence
            with context but weak without it.
        context: Regex (case-insensitive) of keywords that raise confidence
            when they appear near the match.
        negative: Regex (case-insensitive) of keywords that lower confidence.
        context_required: Drop matches without supporting context.
        canonical: Maps a match to its canonical form (used for consistent
            tokenisation).
        describe: Returns an extra reason for a match.
        ignore_case: Match the patterns case-insensitively.
        column_label: Regex (case-insensitive) that, when it matches the
            caller's extra context (a column name), makes that context the
            label for ``column_patterns``: for detectors whose ``patterns``
            need a label in the text, so a column named ``card_cvv`` labels
            its values.
        column_patterns: Patterns used, reporting the whole match, only when
            ``column_label`` matches the extra context.
    """

    id: str
    data_class: str
    label: str
    patterns: Sequence[str]
    capture: str | None = None
    validate: Callable[[str], bool] | None = None
    checks: str | None = None
    base: float | Callable[[str], float] = 0.8
    base_without_context: float | None = None
    context: str | None = None
    negative: str | None = None
    context_required: bool = False
    canonical: Callable[[str], str] = canonical_default
    describe: Callable[[str], str] | None = None
    ignore_case: bool = False
    column_label: str | None = None
    column_patterns: Sequence[str] = ()
    _compiled: tuple[Any, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if isinstance(self.patterns, str):
            object.__setattr__(self, "patterns", (self.patterns,))
        if not callable(self.base) and not 0 < self.base <= 1:
            raise ValueError("`base` must be in (0, 1] or a function.")
        if self.base_without_context is not None:
            if not 0 < self.base_without_context <= 1:
                raise ValueError("`base_without_context` must be in (0, 1].")
            if self.context_required:
                raise ValueError(
                    "`base_without_context` and `context_required` exclude each other."
                )
            if not self.context:
                raise ValueError("`base_without_context` needs `context`.")
        if isinstance(self.column_patterns, str):
            object.__setattr__(self, "column_patterns", (self.column_patterns,))
        if bool(self.column_label) != bool(self.column_patterns):
            raise ValueError("`column_label` and `column_patterns` go together.")
        flags = regex.IGNORECASE if self.ignore_case else 0
        compiled = (
            tuple(regex.compile(p, flags) for p in self.patterns),
            regex.compile(self.context, regex.IGNORECASE) if self.context else None,
            regex.compile(self.negative, regex.IGNORECASE) if self.negative else None,
            regex.compile(self.column_label, regex.IGNORECASE) if self.column_label else None,
            tuple(regex.compile(p, flags) for p in self.column_patterns),
        )
        object.__setattr__(self, "_compiled", compiled)


def bounded(core: str) -> str:
    """Wrap a pattern so it only matches whole tokens.

    The match may not be preceded or followed by a letter or digit, nor by a
    digit joined with a space or hyphen (so a 12-digit window inside a
    16-digit card number is not reported as an Aadhaar number).
    """
    b = engine()["boundary"]
    return f"{b['before']}(?:{core}){b['after']}"


_registry: dict[str, Detector] | None = None
_registry_lock = threading.Lock()


def _detectors() -> dict[str, Detector]:
    # Built completely before it is published: callers on other threads
    # (DuckDB and Polars run functions in parallel) must never see a
    # partly filled registry, which would silently skip detectors.
    global _registry
    registry = _registry
    if registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = {d.id: d for d in builtin_detectors()}
            registry = _registry
    return registry


def register_detector(detector: Detector, overwrite: bool = False) -> str:
    """Register a detector; returns its id."""
    if not isinstance(detector, Detector):
        raise TypeError("`detector` must be a Detector.")
    global _registry
    registry = _detectors()
    with _registry_lock:
        if detector.id in registry and not overwrite:
            raise ValueError(f"Detector `{detector.id}` is already registered.")
        _registry = {**registry, detector.id: detector}
    return detector.id


def reset_detectors() -> None:
    """Restore the built-in detectors, removing user-registered ones."""
    global _registry
    with _registry_lock:
        _registry = None


def detectors() -> list[dict[str, Any]]:
    """Registered detectors, one dict per detector."""
    return [
        {
            "id": d.id,
            "class": d.data_class,
            "label": d.label,
            "base": None if callable(d.base) else d.base,
            "context_required": d.context_required,
        }
        for d in _detectors().values()
    ]


def get_detectors(ids: Sequence[str] | None = None) -> list[Detector]:
    registry = _detectors()
    if ids is None:
        return list(registry.values())
    unknown = [i for i in ids if i not in registry]
    if unknown:
        raise ValueError(f"Unknown detector(s): {', '.join(unknown)}")
    return [registry[i] for i in ids]


# --- Compiling the spec ---------------------------------------------------

_FRAGMENT_REF = regex.compile(r"\{\{([A-Za-z0-9_]+)\}\}")


def expand_fragments(x: str | None, depth: int = 0) -> str | None:
    """Replace ``{{name}}`` with the fragment, or the list joined by ``|``."""
    if x is None:
        return None
    if depth > 10:
        raise ValueError("Fragments nested more than 10 deep (circular reference?).")
    spec = detector_spec()
    for ref in dict.fromkeys(_FRAGMENT_REF.findall(x)):
        if ref in spec.get("fragments", {}):
            value = expand_fragments(spec["fragments"][ref], depth + 1)
        elif ref in spec["lists"]:
            value = "|".join(spec["lists"][ref])
        else:
            raise ValueError(f"Unknown fragment or list `{{{{{ref}}}}}`.")
        x = x.replace("{{" + ref + "}}", value)
    return x


def _rule_lookup(default: Any, rules: list[dict[str, Any]], key: str) -> Callable[[str], Any]:
    compiled = [(regex.compile(expand_fragments(r["match"])), r[key]) for r in rules]

    def lookup(x: str) -> Any:
        for pattern, value in compiled:
            if pattern.search(x):
                return value
        return default

    return lookup


def _compile_validators(defs: list[Any] | None) -> Callable[[str], bool] | None:
    if not defs:
        return None
    checks: list[Callable[[str], bool]] = []
    for v in defs:
        if isinstance(v, str):
            try:
                checks.append(
                    {"verhoeff": verhoeff_valid, "luhn": luhn_valid, "gstin": gstin_valid}[v]
                )
            except KeyError:
                raise ValueError(f"Unknown validator `{v}`.") from None
        elif "match_stripped" in v:
            pattern = regex.compile(expand_fragments(v["match_stripped"]))
            checks.append(lambda x, p=pattern: p.search(strip_separators(x)) is not None)
        else:
            raise ValueError(f"Unknown validator: {', '.join(v)}")
    return lambda x: all(check(x) for check in checks)


def _compile_base(spec: Any) -> float | Callable[[str], float]:
    if isinstance(spec, (int, float)):
        return float(spec)
    return _rule_lookup(float(spec["default"]), spec["rules"], "value")


def _compile_describe(spec: dict[str, Any] | None) -> Callable[[str], str] | None:
    if spec is None:
        return None
    if "position" in spec:
        table = detector_spec()["tables"][spec["table"]]
        pos = spec["position"] - 1
        template = spec["template"]
        return lambda x: template.replace("{}", table.get(x[pos].upper(), "NA"), 1)
    return _rule_lookup(spec["default"], spec["rules"], "text")


_WHITESPACE = regex.compile(r"\s+")
_NON_DIGITS = regex.compile(r"[^0-9]")

_CANONICAL: dict[str, Callable[[str], str]] = {
    "strip_upper": canonical_default,
    "lower": str.lower,
    "last10_digits": lambda x: _NON_DIGITS.sub("", x)[-10:],
    "collapse_upper": lambda x: _WHITESPACE.sub(" ", x.strip()).upper(),
}


def compile_detector(spec: dict[str, Any]) -> Detector:
    """Build a :class:`Detector` from one entry of detectors.yaml."""
    unknown = set(spec) - _DETECTOR_FIELDS
    if unknown:
        raise ValueError(
            f"Detector `{spec.get('id')}` has unknown field(s): {', '.join(sorted(unknown))}"
        )
    patterns = [expand_fragments(p) for p in spec["patterns"]]
    if spec.get("bounded"):
        patterns = [bounded(p) for p in patterns]
    canonical = spec.get("canonical", "strip_upper")
    if canonical not in _CANONICAL:
        raise ValueError(f"Unknown canonical form `{canonical}`.")
    column = spec.get("column_label") or {}
    if set(column) - {"label", "patterns"}:
        raise ValueError(f"Detector `{spec['id']}`: `column_label` has `label` and `patterns`.")
    return Detector(
        id=spec["id"],
        data_class=spec["class"],
        label=spec["label"],
        patterns=tuple(patterns),
        capture=spec.get("capture"),
        validate=_compile_validators(spec.get("validate")),
        checks=spec.get("checks"),
        base=_compile_base(spec["base"]),
        base_without_context=spec.get("base_without_context"),
        context=expand_fragments(spec.get("context")),
        negative=expand_fragments(spec.get("negative")),
        context_required=bool(spec.get("context_required", False)),
        canonical=_CANONICAL[canonical],
        describe=_compile_describe(spec.get("describe")),
        ignore_case=bool(spec.get("ignore_case", False)),
        column_label=expand_fragments(column.get("label")),
        column_patterns=tuple(expand_fragments(p) for p in column.get("patterns", ())),
    )


def builtin_detectors() -> list[Detector]:
    """The built-in detectors, compiled from the spec."""
    return [compile_detector(d) for d in detector_spec()["detectors"]]
