"""Custom detectors from a YAML file (spec/README.md, "Custom detectors").

Organisations describe their own formats - loan account numbers, customer
ids - in the same fields as the built-in detectors, so R, Python, the
command line and the proxy all detect them the same way. Each detector can
carry examples that must and must not match; a file whose examples fail is
refused, and a file is registered completely or not at all.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import regex
import yaml

from . import detectors as _reg
from ._spec import detector_spec
from .detect import _detect_with

KIND = "credgate-detectors"
CLASSES = (
    "identity_strong",
    "financial",
    "sensitive_auth",
    "health",
    "contact",
    "personal",
    "quasi",
)
_TOP_FIELDS = {"kind", "version", "fragments", "lists", "detectors"}
_ID = regex.compile(r"^[a-z][a-z0-9_]*$")
# List entries are literal words, joined with "|" into a pattern.
_LIST_ENTRY = regex.compile(r"^[^\\^$.|?*+()\[\]{}]+$")


def load_detectors(
    source: str | os.PathLike[str] | Mapping[str, Any], replace: bool = False
) -> list[str]:
    """Load custom detectors from a YAML file and register them.

    The file has the fields of the built-in detectors (see the spec,
    "Custom detectors"), with its own ``fragments`` and ``lists`` and, per
    detector, ``examples`` that must (``match``) and must not
    (``no_match``) be found. Everything is checked before anything is
    registered: unknown fields, ids (not a built-in one), data classes,
    patterns and every example. Loading the same file again changes
    nothing.

    Args:
        source: A YAML file, or its contents as a mapping.
        replace: Allow a different definition under an id that a custom
            file already registered.

    Returns:
        The ids of the file's detectors.

    Raises:
        ValueError: The file is not valid, or an example fails; nothing is
            registered.
    """
    name = str(source) if not isinstance(source, Mapping) else "custom detectors"
    if isinstance(source, Mapping):
        data: Any = source
    else:
        with Path(source).open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    try:
        compiled = _compile_file(data)
    except ValueError as e:
        raise ValueError(f"{name}: {e}") from None

    builtin = {d["id"] for d in detector_spec()["detectors"]}
    registry = _reg._detectors()
    for det, digest in compiled:
        if det.id in builtin:  # also registered under that id by code
            raise ValueError(f"{name}: `{det.id}` is the id of a built-in detector.")
        if det.id in registry and _reg._custom.get(det.id) != digest and not replace:
            raise ValueError(
                f"{name}: a different detector `{det.id}` is already registered; "
                "pass replace=True to replace it."
            )
    with _reg._registry_lock:
        merged = dict(_reg._registry or registry)
        for det, digest in compiled:
            merged[det.id] = det
            _reg._custom[det.id] = digest
        _reg._registry = merged
    return [det.id for det, _ in compiled]


def _compile_file(data: Any) -> list[tuple[_reg.Detector, str]]:
    if not isinstance(data, Mapping) or data.get("kind") != KIND:
        raise ValueError(f"not a custom detectors file: `kind` must be `{KIND}`.")
    unknown = set(data) - _TOP_FIELDS
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}.")
    if data.get("version") != 1:
        raise ValueError("`version` must be 1.")
    spec = detector_spec()
    fragments = dict(data.get("fragments") or {})
    lists = dict(data.get("lists") or {})
    for kind, own, theirs in (
        ("fragment", fragments, spec.get("fragments", {})),
        ("list", lists, spec["lists"]),
    ):
        for key in own:
            if key in theirs:
                raise ValueError(f"{kind} `{key}` is a built-in name; choose another.")
    for key, words in lists.items():
        if not isinstance(words, list) or not all(
            isinstance(w, str) and _LIST_ENTRY.match(w) for w in words
        ):
            raise ValueError(f"list `{key}` must be literal words, without regex characters.")
    defs = data.get("detectors")
    if not isinstance(defs, list) or not defs:
        raise ValueError("`detectors` must be a non-empty list.")

    scope = {"fragments": fragments, "lists": lists}
    seen: set[str] = set()
    out = []
    for entry in defs:
        if not isinstance(entry, Mapping):
            raise ValueError("each detector must be a mapping.")
        did = entry.get("id")
        if not isinstance(did, str) or not _ID.match(did):
            raise ValueError(
                f"detector id `{did}` must be lower-case letters, digits and `_`, "
                "starting with a letter."
            )
        if did in seen:
            raise ValueError(f"detector `{did}` appears twice.")
        seen.add(did)
        if entry.get("class") not in CLASSES:
            raise ValueError(
                f"detector `{did}`: class `{entry.get('class')}` must be one of "
                f"{', '.join(CLASSES)}."
            )
        definition = {k: v for k, v in entry.items() if k != "examples"}
        try:
            det = _reg.compile_detector(definition, scope)
        except (KeyError, TypeError) as e:
            raise ValueError(f"detector `{did}`: missing or invalid field {e}.") from None
        except (ValueError, regex.error) as e:
            raise ValueError(f"detector `{did}`: {e}") from None
        _check_examples(det, entry.get("examples"))
        digest = hashlib.sha256(
            json.dumps([definition, fragments, lists], sort_keys=True, default=str).encode()
        ).hexdigest()
        out.append((det, digest))
    return out


def _check_examples(det: _reg.Detector, examples: Any) -> None:
    if examples is None:
        return
    if not isinstance(examples, Mapping) or set(examples) - {"match", "no_match"}:
        raise ValueError(f"detector `{det.id}`: `examples` has `match` and `no_match`.")
    for want, texts in (("match", examples.get("match")), ("no_match", examples.get("no_match"))):
        if texts is None:
            continue
        if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
            raise ValueError(f"detector `{det.id}`: examples `{want}` must be a list of texts.")
        found = _detect_with([det], texts, [""] * len(texts))
        hit = {s.doc for s in found}
        for i, text in enumerate(texts):
            if want == "match" and i not in hit:
                raise ValueError(
                    f"detector `{det.id}`: example {text!r} should match but does not."
                )
            if want == "no_match" and i in hit:
                raise ValueError(
                    f"detector `{det.id}`: example {text!r} should not match but does."
                )
