"""Command-line interface: ``credgate detect``, ``redact``, ``preview``, ``scan``,
``detectors``, ``spec-path``."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Sequence

from . import __version__
from ._spec import spec_path
from .detect import detect_pii, mask_value
from .detectors import detectors
from .redact import preview, redact
from .scan import ScanReport, scan_pii


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

    for name, text in (
        ("redact", "write the input with PII replaced by placeholders such as [PAN]"),
        ("preview", "show what would be redacted and why (values masked)"),
    ):
        r = sub.add_parser(name, help=text)
        r.add_argument("files", nargs="*", help="files to read (default: standard input)")
        r.add_argument("--min-confidence", type=float, default=0.0, metavar="X")
        r.add_argument("--context", default=None, help="extra context applied to every match")
        if name == "redact":
            r.add_argument(
                "--parquet",
                metavar="FILE",
                help="redact a Parquet file (may be larger than memory) into --output",
            )
            r.add_argument("-o", "--output", metavar="FILE", help="output Parquet file")
            r.add_argument(
                "--column",
                action="append",
                metavar="NAME",
                help="column to redact (repeatable; default: all text columns)",
            )
            r.add_argument("--batch-size", type=int, default=10_000, metavar="ROWS")

    s = sub.add_parser("scan", help="report which columns of a CSV or Parquet file contain PII")
    s.add_argument("file", help="CSV file with a header row, or a Parquet file (.parquet)")
    s.add_argument("--sample", type=int, default=10000, help="values checked per column")
    s.add_argument("--min-rate", type=float, default=0.0, metavar="X")
    s.add_argument("--json", action="store_true", help="write one JSON object per finding")
    s.add_argument("--delimiter", default=",", help="field delimiter (default: ,)")
    s.add_argument(
        "--fail",
        action="store_true",
        help="exit with status 1 if any column contains PII",
    )

    px = sub.add_parser("proxy", help="run the policy-enforcing proxy for model endpoints")
    px_sub = px.add_subparsers(dest="proxy_command", required=True)
    ps = px_sub.add_parser("serve", help="run the proxy (OpenAI, Anthropic and Ollama APIs)")
    ps.add_argument("--policy", required=True, help="policy file (YAML)")
    ps.add_argument("--audit", required=True, help="audit log file (JSON Lines)")
    ps.add_argument("--host", default="127.0.0.1", help="address to listen on (default: localhost)")
    ps.add_argument("--port", type=int, default=8790)
    ps.add_argument("--keys", help="keys file; required unless listening on localhost")
    ps.add_argument("--certfile", help="TLS certificate (PEM)")
    ps.add_argument("--keyfile", help="TLS private key (PEM)")
    ps.add_argument("--timeout", type=float, default=300, help="seconds to wait for an endpoint")
    ps.add_argument(
        "--workers", type=int, default=1, help="worker processes (one core each; Linux, macOS)"
    )
    ps.add_argument(
        "--no-audit-rotate",
        action="store_true",
        help="keep one audit file (default: a new file each month)",
    )
    ps.add_argument(
        "--audit-retention-years",
        type=int,
        default=5,
        help="remove monthly audit files older than this (min 1; 0 keeps all; default 5)",
    )
    ps.add_argument(
        "--default-endpoint",
        help="endpoint for models asked for without one (e.g. claude, for Claude Code)",
    )
    ps.add_argument(
        "--drain-seconds",
        type=float,
        default=5,
        help="on SIGTERM, keep serving this long while /healthz reports draining",
    )
    pa = px_sub.add_parser("add-user", help="add a user to a keys file and print their key")
    pa.add_argument("name", help="user name, recorded in the audit log")
    pa.add_argument("--keys", required=True, help="keys file (created if missing)")

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
    if args.command == "scan":
        return _scan(args)
    if args.command == "proxy":
        return _proxy(args)
    if args.command in ("redact", "preview"):
        return _redact(args)
    return _detect(args)


def _proxy(args: argparse.Namespace) -> int:
    from .proxy import ProxyConfig, add_user, serve

    if args.proxy_command == "add-user":
        key = add_user(args.keys, args.name)
        print(f"Added {args.name} to {args.keys}. Their key (shown only once):", file=sys.stderr)
        print(key)
        return 0
    try:
        config = ProxyConfig(
            policy=args.policy,
            audit=args.audit,
            host=args.host,
            port=args.port,
            keys=args.keys,
            certfile=args.certfile,
            keyfile=args.keyfile,
            timeout=args.timeout,
            workers=args.workers,
            drain_seconds=args.drain_seconds,
            default_endpoint=args.default_endpoint,
            audit_rotate=not args.no_audit_rotate,
            audit_retention_years=args.audit_retention_years,
        )
    except (ValueError, OSError) as e:
        print(f"credgate proxy: {e}", file=sys.stderr)
        return 2
    serve(config)
    return 0


def _read(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    with open(source, encoding="utf-8") as f:
        return f.read()


def _redact(args: argparse.Namespace) -> int:
    if getattr(args, "parquet", None):
        if not args.output or args.files:
            print("credgate: --parquet needs --output and no other input files", file=sys.stderr)
            return 2
        from .arrow import redact_parquet

        rows = redact_parquet(
            args.parquet,
            args.output,
            columns=args.column,
            batch_size=args.batch_size,
            context=args.context,
            min_confidence=args.min_confidence,
        )
        print(f"{rows} rows written to {args.output}", file=sys.stderr)
        return 0
    for source in args.files or ["-"]:
        content = _read(source)
        if args.command == "redact":
            sys.stdout.write(
                redact(content, context=args.context, min_confidence=args.min_confidence)
            )
        else:
            print(preview(content, context=args.context, min_confidence=args.min_confidence))
    return 0


def _scan(args: argparse.Namespace) -> int:
    if args.file.endswith(".parquet"):
        import pyarrow.dataset as ds

        return _report(
            args, scan_pii(ds.dataset(args.file), sample=args.sample, min_rate=args.min_rate)
        )
    with open(args.file, encoding="utf-8", newline="") as f:
        rows = list(csv.reader(f, delimiter=args.delimiter))
    if not rows:
        print(f"{args.file}: empty file")
        return 0
    header, body = rows[0], rows[1:]
    columns = {
        name: [row[i] if i < len(row) else None for row in body] for i, name in enumerate(header)
    }
    return _report(args, scan_pii(columns, sample=args.sample, min_rate=args.min_rate))


def _report(args: argparse.Namespace, report: ScanReport) -> int:
    if args.json:
        for record in report.to_records():
            print(json.dumps({"source": args.file, **record}, ensure_ascii=False))
    else:
        print(report)
    return 1 if args.fail and report else 0


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
                value = s.value if args.reveal else mask_value(s.value, s.data_class)
                print(f"{where}\t{s.start}-{s.end}\t{s.type}\t{s.confidence:.2f}\t{value}")
    return 1 if args.fail and found else 0


if __name__ == "__main__":
    sys.exit(main())
