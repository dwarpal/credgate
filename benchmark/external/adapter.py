"""Run one PII detector over a dataset, inside that detector's own environment.

Reads documents (JSON Lines with `id` and `text`), writes one line per
document: {"id", "spans": [[start, end, native_type], ...], "ms"}; and a
summary with the run's CPU time, wall time and peak memory. Every tool runs
at its own documented default settings; nothing is tuned on the data.

Usage: python adapter.py TOOL DATA OUT [--min-confidence X]
TOOL: credgate | credgate-names | presidio | presidio-india | maskflow | kavach
"""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from pathlib import Path

WARMUP = 20  # documents run first and not timed, so model loading is excluded


def make(tool: str, min_confidence: float | None):
    if tool in ("credgate", "credgate-names"):
        import credgate

        mc = 0.0 if min_confidence is None else min_confidence
        if tool == "credgate-names":  # the documented remedy for names without a cue
            credgate.load_detectors(
                Path(__file__).parents[2] / "examples/detectors/names-by-cue.yaml"
            )

        def run(text):
            return [(s.start, s.end, s.type) for s in credgate.detect_pii(text, min_confidence=mc)]

        return run, {"version": credgate.__version__, "min_confidence": mc}

    if tool in ("presidio", "presidio-india"):
        from importlib.metadata import version

        from presidio_analyzer import AnalyzerEngine

        engine = AnalyzerEngine()
        if tool == "presidio-india":  # as benchmark/compare_presidio.py
            from presidio_analyzer.predefined_recognizers import (
                InAadhaarRecognizer,
                InGstinRecognizer,
                InPanRecognizer,
                InPassportRecognizer,
                InVehicleRegistrationRecognizer,
                InVoterRecognizer,
                PhoneRecognizer,
            )

            for rec in (
                InAadhaarRecognizer,
                InGstinRecognizer,
                InPanRecognizer,
                InPassportRecognizer,
                InVehicleRegistrationRecognizer,
                InVoterRecognizer,
            ):
                engine.registry.add_recognizer(rec())
            engine.registry.remove_recognizer("PhoneRecognizer")
            engine.registry.add_recognizer(
                PhoneRecognizer(supported_regions=("IN", "US", "UK", "DE", "FE", "IL"))
            )

        def run(text):
            return [(r.start, r.end, r.entity_type) for r in engine.analyze(text, language="en")]

        return run, {"version": version("presidio-analyzer"), "score_threshold": "default (0)"}

    if tool == "maskflow":
        from importlib.metadata import version

        import maskflow

        def run(text):
            return [(s.start, s.end, str(s.entity_type)) for s in maskflow.detect(text)]

        return run, {"version": version("maskflow-sdk"), "min_confidence": "default (0.5)"}

    if tool == "kavach":
        from importlib.metadata import version

        from kavach import Kavach

        k = Kavach()

        def run(text):
            return [(d.start, d.end, str(d.entity_type)) for d in k.scan(text)]

        return run, {"version": version("kavach-pii"), "threshold": "default (0.5)"}

    raise SystemExit(f"unknown tool {tool}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("tool")
    ap.add_argument("data")
    ap.add_argument("out")
    ap.add_argument("--min-confidence", type=float)
    a = ap.parse_args()

    docs = [json.loads(line) for line in Path(a.data).read_text(encoding="utf-8").splitlines()]
    t_load = time.perf_counter()
    run, info = make(a.tool, a.min_confidence)
    load_s = time.perf_counter() - t_load
    for d in docs[:WARMUP]:
        run(d["text"])

    cpu0, wall0 = time.process_time(), time.perf_counter()
    nbytes = 0
    errors = 0
    with open(a.out, "w", encoding="utf-8") as f:
        for d in docs:
            t = time.perf_counter()
            try:
                spans = run(d["text"])
            except Exception as e:  # a tool that fails on a document finds nothing there
                spans, errors = [], errors + 1
                print(f"{a.tool}: {d['id']}: {type(e).__name__}: {e}", file=sys.stderr)
            ms = (time.perf_counter() - t) * 1000
            nbytes += len(d["text"].encode("utf-8"))
            f.write(json.dumps({"id": d["id"], "spans": spans, "ms": round(ms, 4)}) + "\n")
    wall = time.perf_counter() - wall0
    cpu = time.process_time() - cpu0
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mb = (
        rss / 1024 / 1024 if sys.platform == "darwin" else rss / 1024
    )  # bytes on macOS, KiB on Linux
    summary = {
        "tool": a.tool,
        **info,
        "python": sys.version.split()[0],
        "docs": len(docs),
        "errors": errors,
        "load_s": round(load_s, 2),
        "wall_s": round(wall, 3),
        "cpu_s": round(cpu, 3),
        "cpu_utilisation": round(cpu / wall, 3),
        "docs_per_s": round(len(docs) / wall, 1),
        "mb_per_s": round(nbytes / 1e6 / wall, 4),
        "peak_rss_mb": round(peak_mb, 1),
    }
    Path(a.out).with_suffix(".summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
