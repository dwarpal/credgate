"""Command-line interface: ``credgate detect``, ``credgate detectors``."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from ._spec import spec_path
from .detect import detect_pii, mask_value
from .detectors import detectors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="credgate",
        description="Detect Indian PII before it leaves the machine.",
    )
    parser.add_argument("--version", action="version", version=f"credgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("detect", help="detect PII in files or standard input")
    p.add_argument("files", nargs="*", help="files to scan (default: standard input)")
    p.add_argument("--lines", action="store_true", help="treat each line as a separate document")
    p.add_argument("--json", action="store_true", help="write one JSON object per match")
    p.add_argument(
        "--reveal",
        action="store_true",
        help="show detected values and canonical forms (masked by default)",
    )
    p.add_argument("--min-confidence", type=float, default=0.0, metavar="X")
    p.add_argument("--context", default=None, help="extra context applied to every match")
    p.add_argument(
        "--fail",
        action="store_true",
        help="exit with status 1 if anything is detected (for CI and pre-commit hooks)",
    )

    sub.add_parser("detectors", help="list the registered detectors")
    sub.add_parser("spec-path", help="print the path of the shipped detection spec")

    args = parser.parse_args(argv)
    if args.command == "detectors":
        for d in detectors():
            print(f"{d['id']:<16} {d['class']:<16} {d['label']}")
        return 0
    if args.command == "spec-path":
        print(spec_path())
        return 0
    return _detect(args)


def _detect(args: argparse.Namespace) -> int:
    sources = args.files or ["-"]
    found = 0
    for source in sources:
        if source == "-":
            content = sys.stdin.read()
        else:
            with open(source, encoding="utf-8") as f:
                content = f.read()
        docs = content.splitlines() if args.lines else [content]
        spans = detect_pii(docs, context=args.context, min_confidence=args.min_confidence)
        found += len(spans)
        for s in spans:
            location = s.doc + 1 if args.lines else None
            if args.json:
                record = {"source": source, "line": location, **s.to_dict(reveal=args.reveal)}
                print(json.dumps(record, ensure_ascii=False))
            else:
                where = f"{source}:{location}" if location else source
                value = s.value if args.reveal else mask_value(s.value)
                print(f"{where}\t{s.start}-{s.end}\t{s.type}\t{s.confidence:.2f}\t{value}")
    return 1 if args.fail and found else 0


if __name__ == "__main__":
    sys.exit(main())
