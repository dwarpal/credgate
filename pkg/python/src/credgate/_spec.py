"""Reading the shared detection spec shipped inside the package.

The spec (``spec/`` in the repository, copied here by ``tools/sync-spec.sh``)
is shared with the R package; see its README.md for the schema.
"""

from __future__ import annotations

import functools
from importlib import resources
from pathlib import Path
from typing import Any

import regex
import yaml

SPEC_VERSION_SUPPORTED = 1


def spec_path() -> Path:
    """Path of the ``spec`` directory shipped with the package."""
    return Path(str(resources.files("credgate") / "spec"))


def read_spec_file(name: str, directory: Path | None = None) -> dict[str, Any]:
    path = (directory or spec_path()) / name
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data.get("spec_version") != SPEC_VERSION_SUPPORTED:
        raise ValueError(
            f"Unsupported spec_version {data.get('spec_version')} in {name} "
            f"(this credgate supports {SPEC_VERSION_SUPPORTED})."
        )
    return data


def _code_points(values: list[str]) -> frozenset[int]:
    return frozenset(int(v.removeprefix("U+"), 16) for v in values)


@functools.cache
def engine() -> dict[str, Any]:
    """Engine parameters from engine.yaml, with code points parsed."""
    spec = read_spec_file("engine.yaml")
    norm = spec["normalisation"]
    return {
        "digit_zeros": sorted(_code_points(norm["digit_zeros"])),
        "remove": _code_points(norm["remove"]),
        "dash": _code_points(norm["dash"]),
        "boundary": spec["boundary"],
        "separators": regex.compile(spec["separators"]),
        "scoring": spec["scoring"],
    }


@functools.cache
def detector_spec() -> dict[str, Any]:
    """The parsed detectors.yaml."""
    spec = read_spec_file("detectors.yaml")
    spec["lists"] = {k: [str(x) for x in v] for k, v in spec.get("lists", {}).items()}
    spec["tables"] = {
        k: {str(key): str(val) for key, val in v.items()} for k, v in spec.get("tables", {}).items()
    }
    return spec
