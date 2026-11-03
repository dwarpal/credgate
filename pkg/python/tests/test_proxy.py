"""The proxy against a fake OpenAI-compatible model server that records what
it receives: what leaves the machine, what comes back, and what is recorded."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import credgate
from credgate.cli import main
from credgate.proxy import ProxyConfig, add_user, make_server

PAN = "ABCPE1234F"


class FakeModel(BaseHTTPRequestHandler):
    """Answers with the last user message echoed, and a tool call echoing it."""

    received: ClassVar[list] = []

    def do_GET(self):
        self._json({"object": "list", "data": [{"id": "llama-3.1-70b"}, {"id": "qwen"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).received.append({"body": body, "auth": self.headers.get("Authorization")})
        last = body["messages"][-1]["content"]
        self._json(
            {
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "created": 1,
                "model": body["model"],
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": f"Noted: {last}",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": json.dumps({"q": last}),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        )

    def _json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def _start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


@pytest.fixture
def upstream():
    FakeModel.received = []
    server = _start(ThreadingHTTPServer(("127.0.0.1", 0), FakeModel))
    yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()


def _policy(url):
    return credgate.Policy.from_dict(
        {
            "policy": "credgate-policy",
            "version": 1,
            "id": "test",
            "revision": 3,
            "destinations": {
                "local": {"tier": "local", "url": url},
                "frontier": {"tier": "frontier", "url": url},
                "down": {"tier": "local", "url": "http://127.0.0.1:9/v1"},
                "copilot": {"tier": "frontier", "blocked": True},
            },
            "rules": [
                {
                    "id": "card-with-cvv-and-expiry",
                    "when": {"tiers": ["frontier"], "all_of": ["card", "card_cvv", "card_expiry"]},
                    "action": "block",
                },
                {
                    "id": "ids-tokenised",
                    "when": {"tiers": ["frontier"], "classes": ["identity_strong"]},
                    "action": "tokenise",
                },
                {
                    "id": "contact-redacted",
                    "when": {"tiers": ["frontier"], "classes": ["contact"]},
                    "action": "redact",
                },
                {"id": "local-ok", "when": {"tiers": ["local"]}, "action": "allow"},
            ],
            "default_action": "redact",
        }
    )


@pytest.fixture
def proxy(upstream, tmp_path, server_kind):
    def start(**kwargs):
        kwargs.setdefault("server", server_kind)
        config = ProxyConfig(
            policy=_policy(upstream), audit=tmp_path / "audit.jsonl", port=0, **kwargs
        )
        server = _start(make_server(config, log=lambda line: None))
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/v1", config

    servers = []
    yield start
    for s in servers:
        s.shutdown()


def _call(base, payload=None, key=None, path="/chat/completions", raw=None):
    data = raw if raw is not None else (None if payload is None else json.dumps(payload).encode())
    req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read()
            return r.status, r.headers["Content-Type"], body
    except urllib.error.HTTPError as e:
        return e.code, e.headers["Content-Type"], e.read()


def _chat(model, text, **extra):
    return {"model": model, "messages": [{"role": "user", "content": text}], **extra}


def test_identifiers_are_tokenised_out_and_restored_in(proxy, upstream, tmp_path):
    base, _ = proxy()
    status, _, body = _call(base, _chat("frontier/gpt", f"PAN {PAN}, mobile 9876543210"))
    assert status == 200
    sent = FakeModel.received[-1]["body"]
    text = sent["messages"][0]["content"]
    assert PAN not in text
    assert "9876543210" not in text
    assert "[PAN_" in text
    assert "[MOBILE_IN]" in text
    assert sent["model"] == "gpt"
    answer = json.loads(body)
    assert answer["model"] == "frontier/gpt"
    assert answer["choices"][0]["message"]["content"] == f"Noted: PAN {PAN}, mobile [MOBILE_IN]"
    # Never restored into tool calls: the token stays a token.
    args = answer["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert PAN not in args
    assert "[PAN_" in args


def test_local_endpoints_get_the_text_as_the_policy_allows(proxy):
    base, _ = proxy()
    status, _, _ = _call(base, _chat("local/llama-3.1-70b", f"PAN {PAN}"))
    assert status == 200
    assert FakeModel.received[-1]["body"]["messages"][0]["content"] == f"PAN {PAN}"


def test_blocked_requests_never_leave(proxy, tmp_path):
    base, _ = proxy()
    card = "Card 4111 1111 1111 1111, CVV 123, expiry 08/29"
    status, _, body = _call(base, _chat("frontier/gpt", card))
    assert status == 403
    error = json.loads(body)["error"]
    assert error["code"] == "policy_blocked"
    assert "card-with-cvv-and-expiry" in error["message"]
    status, _, body = _call(base, _chat("copilot/gpt-4o", "hello"))
    assert status == 403
    assert "destination-blocked" in json.loads(body)["error"]["message"]
    assert FakeModel.received == []
    records = credgate.audit_read(tmp_path / "audit.jsonl")
    assert [r["allowed"] for r in records] == [False, False]
    assert credgate.audit_verify(tmp_path / "audit.jsonl").ok
    assert "4111" not in (tmp_path / "audit.jsonl").read_text()


def test_every_request_is_audited_without_values(proxy, tmp_path):
    base, _ = proxy()
    _call(base, _chat("frontier/gpt", f"PAN {PAN}"))
    _call(base, _chat("local/x", "nothing personal"))
    records = credgate.audit_read(tmp_path / "audit.jsonl")
    assert [r["destination"]["name"] for r in records] == ["frontier", "local"]
    assert records[0]["items"][0]["action"] == "tokenise"
    assert {r["policy"]["revision"] for r in records} == {3}
    assert PAN not in (tmp_path / "audit.jsonl").read_text()


def test_whole_conversation_and_tool_arguments_are_governed(proxy):
    base, _ = proxy()
    payload = {
        "model": "frontier/gpt",
        "messages": [
            {"role": "system", "content": [{"type": "text", "text": f"Customer {PAN}"}]},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c",
                        "type": "function",
                        "function": {"name": "f", "arguments": json.dumps({"pan": PAN})},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "c", "content": f"found {PAN}"},
            {"role": "user", "content": "and?"},
        ],
    }
    status, _, _ = _call(base, payload)
    assert status == 200
    assert PAN not in json.dumps(FakeModel.received[-1]["body"])


def test_bad_requests_and_errors_fail_closed(proxy):
    base, config = proxy()
    assert _call(base, _chat("gpt", "x"))[0] == 400
    assert _call(base, _chat("nowhere/gpt", "x"))[0] == 404
    image = {
        "model": "frontier/gpt",
        "messages": [
            {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}
        ],
    }
    assert _call(base, image)[0] == 400
    assert _call(base, raw=b"not json")[0] == 400
    status, _, body = _call(base, _chat("down/x", "hello"))
    assert status == 502
    assert json.loads(body)["error"]["code"] == "endpoint_unreachable"
    assert FakeModel.received == []

    def broken(*args, **kwargs):
        raise RuntimeError("policy engine failed")

    config.policy.apply = broken
    status, _, body = _call(base, _chat("frontier/gpt", f"PAN {PAN}"))
    assert status == 500
    assert json.loads(body)["error"]["code"] == "credgate_error"
    assert FakeModel.received == []


def test_models_are_listed_per_endpoint(proxy):
    base, _ = proxy()
    status, _, body = _call(base, path="/models")
    ids = [m["id"] for m in json.loads(body)["data"]]
    assert status == 200
    assert "local/llama-3.1-70b" in ids
    assert "frontier/qwen" in ids
    assert not any(i.startswith(("copilot/", "down/")) for i in ids)


def test_endpoint_keys_come_from_the_environment(proxy, monkeypatch):
    monkeypatch.setenv("CREDGATE_UPSTREAM_KEY_FRONTIER", "sk-test-123")
    base, _ = proxy()
    _call(base, _chat("frontier/gpt", "hello"))
    _call(base, _chat("local/x", "hello"))
    assert [r["auth"] for r in FakeModel.received] == ["Bearer sk-test-123", None]


def test_shared_mode_needs_keys_and_records_users(proxy, upstream, tmp_path, capsys):
    with pytest.raises(ValueError, match="needs a keys file"):
        ProxyConfig(policy=_policy(upstream), audit=tmp_path / "a.jsonl", host="0.0.0.0")
    keys = tmp_path / "keys.json"
    assert main(["proxy", "add-user", "priya", "--keys", str(keys)]) == 0
    key = capsys.readouterr().out.strip()
    assert key.startswith("cgk_")
    assert key not in keys.read_text()
    other = add_user(keys, "rahul")
    with pytest.raises(ValueError, match="already exists"):
        add_user(keys, "priya")

    base, _ = proxy(keys=keys)
    assert _call(base, _chat("local/x", "hi"))[0] == 401
    assert _call(base, _chat("local/x", "hi"), key="cgk_wrong")[0] == 401
    assert _call(base, _chat("local/x", "hi"), key=key)[0] == 200
    assert _call(base, _chat("local/x", "hi"), key=other)[0] == 200
    actors = [r["actor"] for r in credgate.audit_read(tmp_path / "audit.jsonl")]
    assert actors == ["priya", "rahul"]


@pytest.mark.skipif(not hasattr(__import__("os"), "fork"), reason="workers need fork")
def test_worker_processes_serve_together_and_stop_together(upstream, tmp_path, server_kind):
    import os
    import signal
    import socket
    import subprocess
    import sys
    import time
    from concurrent.futures import ThreadPoolExecutor

    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "policy": "credgate-policy",
                "version": 1,
                "id": "w",
                "revision": 1,
                "destinations": {"frontier": {"tier": "frontier", "url": upstream}},
                "rules": [],
                "default_action": "tokenise",
            }
        )
    )
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from credgate.cli import main; main()",
            "proxy",
            "serve",
            "--policy",
            str(policy),
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--port",
            str(port),
            "--workers",
            "3",
            "--server",
            server_kind,
        ],
        env=env,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        base = f"http://127.0.0.1:{port}/v1"
        with ThreadPoolExecutor(12) as pool:
            results = list(
                pool.map(lambda i: _call(base, _chat("frontier/m", f"PAN {PAN} #{i}")), range(30))
            )
        assert all(status == 200 for status, _, _ in results)
        assert all(PAN not in r["body"]["messages"][0]["content"] for r in FakeModel.received)
        check = credgate.audit_verify(tmp_path / "audit.jsonl")
        assert check.ok
        assert check.records == 30
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
    time.sleep(0.5)
    with pytest.raises(ConnectionRefusedError):  # no worker left listening
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_health_needs_no_key_and_reveals_nothing(proxy, tmp_path):
    keys = tmp_path / "keys.json"
    add_user(keys, "priya")
    base, _ = proxy(keys=keys)
    for path in ("/healthz", "/healthz/"):
        status, _, body = _call(base.removesuffix("/v1"), path=path)
        assert status == 200
        health = json.loads(body)
        assert health["status"] == "ok"
        assert health["policy"] == {"id": "test", "revision": 3}
        assert set(health) == {"status", "policy", "loaded_at", "last_reload"}
    assert _call(base, path="/models")[0] == 401  # everything else still needs a key


def test_request_ids_are_echoed_and_sanitised(proxy):
    base, _ = proxy()
    for sent, echoed in (
        ("lb-7f3a:42", "lb-7f3a:42"),
        ("bad id\r\nX-Evil: 1", None),
        ("x" * 200, None),
    ):
        req = urllib.request.Request(
            base + "/chat/completions",
            method="POST",
            data=json.dumps(_chat("local/m", "hi")).encode(),
        )
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Request-ID", sent.replace("\r\n", " "))
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.headers.get("X-Request-ID") == echoed


class SlowModel(FakeModel):
    def do_POST(self):
        import time

        time.sleep(2)
        super().do_POST()


@pytest.mark.skipif(not hasattr(__import__("os"), "fork"), reason="workers need fork")
def test_sigterm_drains_for_load_balancers(tmp_path, server_kind):
    import os
    import signal
    import socket
    import subprocess
    import sys
    import time

    slow = _start(ThreadingHTTPServer(("127.0.0.1", 0), SlowModel))
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "policy": "credgate-policy",
                "version": 1,
                "id": "d",
                "revision": 1,
                "destinations": {
                    "slow": {
                        "tier": "local",
                        "url": f"http://127.0.0.1:{slow.server_address[1]}/v1",
                    }
                },
                "rules": [],
                "default_action": "allow",
            }
        )
    )
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from credgate.cli import main; main()",
            "proxy",
            "serve",
            "--policy",
            str(policy),
            "--audit",
            str(tmp_path / "audit.jsonl"),
            "--port",
            str(port),
            "--workers",
            "2",
            "--drain-seconds",
            "4",
            "--server",
            server_kind,
        ],
        env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        result = {}
        slow_request = threading.Thread(
            target=lambda: result.update(answer=_call(base + "/v1", _chat("slow/m", "hello")))
        )
        slow_request.start()
        time.sleep(0.5)  # the request is now waiting for the slow endpoint
        proc.send_signal(signal.SIGTERM)
        # Within the 4-second drain window, /healthz turns to "draining" as
        # soon as the signal is handled (later on a busy machine).
        deadline = time.monotonic() + 3
        status, body = 0, b""
        while time.monotonic() < deadline:
            status, _, body = _call(base, path="/healthz")
            if status == 503:
                break
            time.sleep(0.05)
        assert status == 503
        assert json.loads(body)["status"] == "draining"
        slow_request.join(timeout=20)
        assert result["answer"][0] == 200  # finished, not cut off
        assert proc.wait(timeout=30) == 0
        time.sleep(0.5)
        with pytest.raises(ConnectionRefusedError):  # no worker left listening
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
    finally:
        if proc.poll() is None:
            proc.kill()
        slow.shutdown()


def test_proxy_rotates_and_prunes_its_audit_log(upstream, tmp_path):
    from datetime import UTC, datetime

    from credgate.proxy import _retention

    audit = tmp_path / "audit.jsonl"
    # an old month already on disk, written with rotation
    old = credgate.AuditLog(audit, rotate=True)
    decision = _policy(upstream).decide(["hello"], "local")
    old.record(decision, time=datetime(2019, 3, 1, tzinfo=UTC))
    config = ProxyConfig(policy=_policy(upstream), audit=audit, port=0, audit_retention_years=5)
    server = _start(make_server(config, log=lambda line: None))
    base = f"http://127.0.0.1:{server.server_address[1]}/v1"
    try:
        assert _call(base, _chat("local/x", "hello"))[0] == 200  # a new month: rotates
    finally:
        server.shutdown()
    assert (tmp_path / "audit.2019-03.jsonl").exists()
    messages = []
    thread = threading.Thread(target=_retention, args=(config, messages.append), daemon=True)
    thread.start()
    # The first pass runs at once; on a busy machine it can take seconds, so
    # wait for it rather than for a fixed time.
    deadline = time.monotonic() + 60
    while not messages and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not (tmp_path / "audit.2019-03.jsonl").exists()
    assert "audit.2019-03.jsonl" in messages[0]
    check = credgate.audit_verify(audit)
    assert check.ok
    assert check.records == 1
    with pytest.raises(ValueError, match="at least 1"):
        ProxyConfig(policy=_policy(upstream), audit=audit, audit_retention_years=-2)
