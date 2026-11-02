"""Load test of the credgate proxy: throughput, latency and correctness under
parallel load, with synthetic customer records of growing size.

Three processes, so they do not slow each other down:

- a fake OpenAI-compatible endpoint that answers at once by echoing the text
  it received, and counts identifier-shaped strings (PAN, Aadhaar, mobile,
  card, e-mail) in what it receives - each one a leak;
- the proxy (``credgate proxy serve``), with a policy that tokenises every
  identifier for that endpoint;
- this load generator: clients in several processes, each sending requests
  over a kept-alive connection.

Every answer is checked: the proxy must restore the echoed text exactly to
the original. After each run the audit chain is verified.

    python benchmark/proxy_load.py                      # the full matrix
    python benchmark/proxy_load.py --quick              # a short check
    python benchmark/proxy_load.py --workers 4          # proxy worker processes
    python benchmark/proxy_load.py --stream             # answers streamed in pieces
    python benchmark/proxy_load.py --server uvicorn     # the production server

With ``--stream`` the endpoint streams its echo in 8-character pieces (one
event each, as models do), every token is split across pieces, and the time
to the first piece is measured as well.

Writes benchmark/results/proxy_load.json and prints a Markdown table.
"""

from __future__ import annotations

import argparse
import http.client
import json
import multiprocessing as mp
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pkg" / "python" / "src"))

import credgate  # noqa: E402

# Identifier shapes; tokens look like [PAN_abcd...] (lower-case base32) and
# never match these.
LEAK = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"  # PAN
    r"|(?<![0-9])[2-9][0-9]{11}(?![0-9])"  # Aadhaar
    r"|(?<![0-9])[6-9][0-9]{9}(?![0-9])"  # mobile
    r"|(?<![0-9])4[0-9]{15}(?![0-9])"  # card
    r"|[A-Za-z0-9._%+-]+@example\.(?:com|org)"  # e-mail
)
SIZES = {"1 record": 1, "20 records": 20, "200 records": 200, "1,000 records": 1000}
CONCURRENCY = [1, 8, 32]


# --- the fake endpoint ---------------------------------------------------------


class Endpoint(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    stats: ClassVar[dict] = {"requests": 0, "leaks": 0, "examples": []}
    lock = threading.Lock()

    def do_GET(self):
        if self.path == "/stats":
            with self.lock:
                self._json(dict(self.stats))
        else:
            self._json({"object": "list", "data": [{"id": "m"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        text = body["messages"][-1]["content"]
        leaks = LEAK.findall(json.dumps(body, ensure_ascii=False))
        with self.lock:
            self.stats["requests"] += 1
            self.stats["leaks"] += len(leaks)
            if leaks and len(self.stats["examples"]) < 5:
                self.stats["examples"].append(leaks[0][:4] + "...")
        if body.get("stream"):
            self._stream("echo: " + text, body["model"])
            return
        self._json(
            {
                "id": "x",
                "object": "chat.completion",
                "created": 1,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "echo: " + text},
                    }
                ],
            }
        )

    def _stream(self, text, model):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        base = {"id": "x", "object": "chat.completion.chunk", "created": 1, "model": model}
        events = [
            base | {"choices": [{"index": 0, "delta": {"content": text[i : i + 8]}}]}
            for i in range(0, len(text), 8)
        ]
        events.append(base | {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        data = "".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n"
        self.wfile.write(data.encode())

    def _json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def run_endpoint(port: int) -> None:
    ThreadingHTTPServer(("127.0.0.1", port), Endpoint).serve_forever()


# --- data --------------------------------------------------------------------------


def make_notes(n: int, seed: int) -> str:
    lines = []
    for r in credgate.synth_indian_pii(n, seed=seed):
        lines.append(
            f"Name: {r['name']}. PAN {r['pan']}, Aadhaar {r['aadhaar']}, mobile +91 {r['mobile']}, "
            f"email {r['email']}, account no {r['bank_account']} (IFSC {r['ifsc']}), "
            f"card {r['card']}. Address: {r['address']}. Wants the EMI date moved."
        )
    return "\n".join(lines)


# --- load generator ----------------------------------------------------------------


def read_stream(response: http.client.HTTPResponse, start: float) -> tuple[str, float]:
    """The streamed answer's text, and the seconds to its first piece."""
    parts, first = [], 0.0
    for line in response:
        if not line.startswith(b"data: ") or line.startswith(b"data: [DONE]"):
            continue
        for choice in json.loads(line[6:])["choices"]:
            content = choice.get("delta", {}).get("content")
            if content:
                first = first or time.perf_counter() - start
                parts.append(content)
    return "".join(parts), first


def client(args: tuple) -> list[tuple[float, int, bool, int, float]]:
    """One client process: `threads` threads sending requests until `until`."""
    port, payloads, threads, until, stream = args
    out: list[tuple[float, int, bool, int, float]] = []
    lock = threading.Lock()

    def worker(t: int) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        i = t
        local = []
        while time.time() < until:
            text = payloads[i % len(payloads)]
            request = {"model": "frontier/m", "messages": [{"role": "user", "content": text}]}
            body = json.dumps(request | {"stream": True} if stream else request)
            start = time.perf_counter()
            try:
                conn.request(
                    "POST", "/v1/chat/completions", body, {"Content-Type": "application/json"}
                )
                response = conn.getresponse()
                first = 0.0
                if stream and response.status == 200:
                    answer, first = read_stream(response, start)
                else:
                    data = response.read()
                    answer = json.loads(data)["choices"][0]["message"]["content"]
                ok = response.status == 200 and answer == "echo: " + text
                status = response.status
            except Exception:
                conn.close()
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
                ok, status, first = False, 0, 0.0
            local.append((time.perf_counter() - start, status, ok, len(text.encode()), first))
            i += threads
        with lock:
            out.extend(local)

    pool = [threading.Thread(target=worker, args=(t,)) for t in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()
    return out


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(port: int) -> None:
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listening on {port}")


def stats(port: int) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.request("GET", "/stats")
    return json.loads(conn.getresponse().read())


def rss_mb(pid: int) -> float:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return round(int(out.stdout.strip() or 0) / 1024, 1)


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    return values[min(len(values) - 1, round(p / 100 * (len(values) - 1)))]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seconds", type=float, default=15, help="duration of each run")
    parser.add_argument("--workers", type=int, default=1, help="proxy worker processes")
    parser.add_argument("--quick", action="store_true", help="a short check")
    parser.add_argument("--stream", action="store_true", help="streamed answers")
    parser.add_argument("--server", default="standard", choices=["standard", "uvicorn"])
    parser.add_argument("--out", default=None, help="results file (JSON)")
    args = parser.parse_args()
    name = "proxy_load" + ("_stream" if args.stream else "")
    name += "" if args.server == "standard" else f"_{args.server}"
    name += f"_workers{args.workers}" if args.workers > 1 else ""
    args.out = args.out or str(ROOT / "benchmark" / "results" / f"{name}.json")
    sizes = {"20 records": 20} if args.quick else SIZES
    concurrency = [1, 8] if args.quick else CONCURRENCY
    seconds = 3 if args.quick else args.seconds

    tmp = Path(tempfile.mkdtemp(prefix="credgate-load-"))
    endpoint_port, proxy_port = free_port(), free_port()
    endpoint = mp.get_context("spawn").Process(
        target=run_endpoint, args=(endpoint_port,), daemon=True
    )
    endpoint.start()
    wait_for(endpoint_port)
    policy = {
        "policy": "credgate-policy",
        "version": 1,
        "id": "load-test",
        "revision": 1,
        "destinations": {
            "frontier": {"tier": "frontier", "url": f"http://127.0.0.1:{endpoint_port}/v1"}
        },
        "rules": [
            {"id": "tokenise-everything", "when": {"tiers": ["frontier"]}, "action": "tokenise"}
        ],
        "default_action": "tokenise",
    }
    (tmp / "policy.json").write_text(json.dumps(policy))
    audit = tmp / "audit.jsonl"
    env = dict(os.environ, PYTHONPATH=str(ROOT / "pkg" / "python" / "src"))
    command = [
        sys.executable,
        "-c",
        "from credgate.cli import main; main()",
        "proxy",
        "serve",
        "--policy",
        str(tmp / "policy.json"),
        "--audit",
        str(audit),
        "--port",
        str(proxy_port),
    ]
    if args.workers > 1:
        command += ["--workers", str(args.workers)]
    command += ["--server", args.server]
    proxy = subprocess.Popen(command, env=env, stderr=subprocess.DEVNULL)
    wait_for(proxy_port)

    results = []
    try:
        for label, n in sizes.items():
            payloads = [make_notes(n, seed) for seed in range(8)]
            for c in concurrency:
                processes = min(c, 4)
                threads = c // processes
                before = stats(endpoint_port)
                until = time.time() + seconds
                with mp.get_context("spawn").Pool(processes) as pool:
                    started = time.time()
                    parts = pool.map(
                        client, [(proxy_port, payloads, threads, until, args.stream)] * processes
                    )
                    elapsed = time.time() - started
                rows = [r for part in parts for r in part]
                after = stats(endpoint_port)
                latencies = [r[0] for r in rows if r[1] == 200]
                firsts = [r[4] for r in rows if r[1] == 200 and r[4]]
                result = {
                    "size": label,
                    "records_per_request": n,
                    "kb_per_request": round(len(payloads[0].encode()) / 1024, 1),
                    "clients": c,
                    "requests": len(rows),
                    "requests_per_second": round(len(rows) / elapsed, 1),
                    "mb_per_second": round(sum(r[3] for r in rows) / elapsed / 1e6, 2),
                    "records_per_second": round(len(rows) * n / elapsed, 1),
                    "p50_ms": round(1000 * percentile(latencies, 50), 1) if latencies else None,
                    "p95_ms": round(1000 * percentile(latencies, 95), 1) if latencies else None,
                    "p99_ms": round(1000 * percentile(latencies, 99), 1) if latencies else None,
                    "pieces_per_second": (
                        round(sum((r[3] + 6) / 8 for r in rows) / elapsed) if args.stream else None
                    ),
                    "first_piece_p50_ms": (
                        round(1000 * percentile(firsts, 50), 1) if firsts else None
                    ),
                    "first_piece_p95_ms": (
                        round(1000 * percentile(firsts, 95), 1) if firsts else None
                    ),
                    "errors": sum(1 for r in rows if r[1] != 200),
                    "wrong_answers": sum(1 for r in rows if r[1] == 200 and not r[2]),
                    "leaks": after["leaks"] - before["leaks"],
                    "proxy_rss_mb": rss_mb(proxy.pid),
                }
                results.append(result)
                print(json.dumps(result), flush=True)
        check = credgate.audit_verify(audit)
    finally:
        proxy.terminate()
        proxy.wait(timeout=30)
        endpoint.terminate()

    meta = {
        "date": time.strftime("%Y-%m-%d"),
        "machine": platform.platform(),
        "cpu": subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True
        ).stdout.strip()
        or platform.processor(),
        "cores": os.cpu_count(),
        "python": platform.python_version(),
        "credgate": credgate.__version__,
        "proxy_workers": args.workers,
        "streaming": args.stream,
        "server": args.server,
        "seconds_per_run": seconds,
        "audit_records": check.records,
        "audit_chain_intact": check.ok,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps({"meta": meta, "results": results}, indent=2) + "\n")
    print(f"\n{meta}\n")
    first = " | Pieces/s | First piece p50 ms" if args.stream else ""
    print(
        "| Request size | Clients | Requests/s | Records/s | MB/s"
        f" | p50 ms | p95 ms | p99 ms{first} | Errors | Wrong | Leaks |"
    )
    print(
        "|---|---:|---:|---:|---:|---:|---:|---:|"
        + ("---:|---:|" if args.stream else "")
        + "---:|---:|---:|"
    )
    for r in results:
        cell = f" | {r['pieces_per_second']} | {r['first_piece_p50_ms']}" if args.stream else ""
        print(
            f"| {r['size']} ({r['kb_per_request']} KB) | {r['clients']} | "
            f"{r['requests_per_second']} | "
            f"{r['records_per_second']} | {r['mb_per_second']} | {r['p50_ms']} | {r['p95_ms']} | "
            f"{r['p99_ms']}{cell} | {r['errors']} | {r['wrong_answers']} | {r['leaks']} |"
        )


if __name__ == "__main__":
    main()
