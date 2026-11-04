"""Download the two public datasets and check them against their published hashes.

Only the data files are downloaded (no scripts from the dataset repositories
are run). They go to `data/`, which is not committed.

- Ylemis India-PII Benchmark (CC0 1.0):
  https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark
- IndiaPII-Bench v1.0 (CC BY 4.0, MaskFlow project):
  https://huggingface.co/datasets/maskflow-ai/indiapii-bench

Usage: python benchmark/external/fetch_data.py
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE / "data"

FILES = {
    "ylemis": (
        "https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark/resolve/main/benchmark.jsonl",
        "7003719c62f451b68ec68280fbccaca12990718ad9ee7aacbcaba66c4c43f914",
    ),
    "indiapii": (
        "https://huggingface.co/datasets/maskflow-ai/indiapii-bench/resolve/main/indiapii-v1.0.jsonl",
        "93f7058c16909541c3c769e2456baa4f461eb20f75ece7ab8c21b94fc42531b0",
    ),
}
# The fixed sample timed three times for speed figures: every fifth Ylemis
# document (2,000), all of IndiaPII (2,000) and all of credgate's test
# split (700).
SAMPLE_EVERY = {"ylemis": 5, "indiapii": 1}


def main() -> None:
    DATA.mkdir(exist_ok=True)
    for name, (url, sha256) in FILES.items():
        raw = DATA / f"{name}.raw.jsonl"
        if not raw.exists() or hashlib.sha256(raw.read_bytes()).hexdigest() != sha256:
            with urllib.request.urlopen(url, timeout=120) as r:
                raw.write_bytes(r.read())
        got = hashlib.sha256(raw.read_bytes()).hexdigest()
        if got != sha256:
            raw.unlink()
            raise SystemExit(f"{name}: SHA-256 {got} is not the published {sha256}; not used.")
        rows = [json.loads(line) for line in raw.read_text(encoding="utf-8").splitlines()]
        with (DATA / f"{name}.docs.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps({"id": r["id"], "text": r["text"]}, ensure_ascii=False) + "\n")
        with (DATA / f"{name}.timing.jsonl").open("w", encoding="utf-8") as f:
            for r in rows[:: SAMPLE_EVERY[name]]:
                f.write(json.dumps({"id": r["id"], "text": r["text"]}, ensure_ascii=False) + "\n")
        print(f"{name}: {len(rows)} documents, SHA-256 verified")

    # credgate's own held-out test split, from this repository.
    rows = [
        json.loads(line)
        for line in (HERE.parent / "corpus/test.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    for kind in ("docs", "timing"):
        with (DATA / f"corpus.{kind}.jsonl").open("w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps({"id": r["id"], "text": r["text"]}, ensure_ascii=False) + "\n")
    print(f"corpus: {len(rows)} documents (benchmark/corpus/test.jsonl)")


if __name__ == "__main__":
    main()
