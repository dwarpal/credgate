"""Trying to break the proxy: every way personal data could get past the
policy, malformed and hostile HTTP, a hostile endpoint, concurrency, and
failures that must stop a request rather than let it through.

The leak oracle: the fake endpoint records the raw bytes it receives, and no
identifier may appear in them in any form."""

from __future__ import annotations

import json
import re
import socket
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import credgate
from credgate import proxy as proxy_module
from credgate.proxy import ProxyConfig, add_user, make_server

PAN = "ABCPE1234F"
MOBILE = "9876543210"
AADHAAR = "542229371182"
# Every way these appear in the attacks below; none may reach the endpoint.
FORBIDDEN = [
    PAN,
    PAN.lower(),
    MOBILE,
    "98765 43210",
    AADHAAR,
    "\uff21\uff22\uff23\uff30\uff25\uff11\uff12\uff13\uff14\uff26",
    "१२३४",
    "\\u0041BCPE",
]


class Recorder(BaseHTTPRequestHandler):
    raw: ClassVar[list] = []
    headers_seen: ClassVar[list] = []

    def do_GET(self):
        self._json({"object": "list", "data": [{"id": "m"}]})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).raw.append(raw)
        type(self).headers_seen.append(dict(self.headers))
        body = json.loads(raw)
        last = body["messages"][-1]["content"]
        text = last if isinstance(last, str) else json.dumps(last)
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
                        "message": {"role": "assistant", "content": f"echo: {text}"},
                    }
                ],
            }
        )

    def _json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class Redirector(Recorder):
    target = ""

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(307)
        self.send_header("Location", type(self).target)
        self.send_header("Content-Length", "0")
        self.end_headers()


class NotJson(Recorder):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        data = b"<html>gateway error</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/v1"


@pytest.fixture
def env(tmp_path, server_kind):
    Recorder.raw, Recorder.headers_seen = [], []
    servers = []
    ok, ok_url = _serve(Recorder)
    sink, sink_url = _serve(Recorder)  # where a redirect points
    Redirector.target = sink_url + "/chat/completions"
    redirect, redirect_url = _serve(Redirector)
    bad, bad_url = _serve(NotJson)
    servers += [ok, sink, redirect, bad]
    policy = credgate.Policy.from_dict(
        {
            "policy": "credgate-policy",
            "version": 1,
            "id": "attack",
            "revision": 1,
            "destinations": {
                "frontier": {"tier": "frontier", "url": ok_url},
                "redirecting": {"tier": "local", "url": redirect_url},
                "broken": {"tier": "local", "url": bad_url},
                "local": {"tier": "local", "url": ok_url},
            },
            "rules": [
                {
                    "id": "card-cvv-expiry",
                    "when": {"tiers": ["frontier"], "all_of": ["card", "card_cvv", "card_expiry"]},
                    "action": "block",
                },
                {
                    "id": "ids",
                    "when": {"tiers": ["frontier"], "classes": ["identity_strong"]},
                    "action": "tokenise",
                },
                {"id": "local-ok", "when": {"tiers": ["local"]}, "action": "allow"},
            ],
            "default_action": "redact",
        }
    )

    def start(**kwargs):
        kwargs.setdefault("audit", tmp_path / "audit.jsonl")
        kwargs.setdefault("server", server_kind)
        config = ProxyConfig(policy=policy, port=0, **kwargs)
        server = make_server(config, log=lambda line: None)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}/v1", server.server_address[1]

    yield start
    for s in servers:
        s.shutdown()


def post(base, payload=None, raw=None, key=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(base + "/chat/completions", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def chat(text="hello", model="frontier/m", **extra):
    return {"model": model, "messages": [{"role": "user", "content": text}], **extra}


def assert_no_leak():
    for raw in Recorder.raw:
        text = raw.decode("utf-8")
        decoded = json.dumps(json.loads(raw), ensure_ascii=False)
        # As detection sees it: invisible characters dropped, digits and
        # letters folded (full-width, Devanagari), and without any whitespace.
        folded = credgate.normalise(decoded).text
        squeezed = re.sub(r"\s", "", folded)
        for form in (text, decoded, folded, squeezed):
            for value in FORBIDDEN:
                assert value not in form, f"{value!r} reached the endpoint: {decoded[:300]}"


# --- A. Personal data hidden anywhere in the request ----------------------

LEAKS = {
    "metadata": chat(metadata={"note": f"PAN {PAN}"}),
    "user-field": chat(user=f"mobile {MOBILE}"),
    "message-name": {
        "model": "frontier/m",
        "messages": [{"role": "user", "name": PAN, "content": "hi"}],
    },
    "stop-sequences": chat(stop=[f"PAN {PAN}", "x"]),
    "predicted-output": chat(prediction={"type": "content", "content": f"PAN {PAN}"}),
    "tool-definition": chat(
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": f"Look up PAN {PAN}",
                    "parameters": {
                        "type": "object",
                        "properties": {"q": {"type": "string", "description": f"e.g. {PAN}"}},
                    },
                },
            }
        ]
    ),
    "json-schema": chat(
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "x",
                "schema": {"type": "object", "description": f"Customer PAN {PAN}"},
            },
        }
    ),
    "future-field": chat(
        x_vendor_extension={"deep": [{"note": f"PAN {PAN}"}, [f"mobile {MOBILE}"]]}
    ),
    "number-not-string": chat(metadata={"aadhaar": int(AADHAAR)}),
    "number-in-list": chat(x_ids=[int(AADHAAR)]),
    "text-parts": {
        "model": "frontier/m",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": f"PAN {PAN}"},
                    {"type": "text", "text": f"mobile {MOBILE}"},
                ],
            }
        ],
    },
    "tool-results-and-arguments": {
        "model": "frontier/m",
        "messages": [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c",
                        "type": "function",
                        "function": {
                            "name": "f",
                            "arguments": json.dumps({"pan": PAN, "aadhaar": AADHAAR}),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "c",
                "content": [{"type": "text", "text": f"found {PAN}"}],
            },
            {"role": "user", "content": "ok"},
        ],
    },
    "system-and-developer": {
        "model": "frontier/m",
        "messages": [
            {"role": "system", "content": f"Customer PAN {PAN}"},
            {"role": "developer", "content": f"mobile {MOBILE}"},
            {"role": "user", "content": "hi"},
        ],
    },
    "lower-case": chat(f"pan {PAN.lower()}"),
    "zero-width": chat("PAN ABC​PE‍1234F"),
    "full-width": chat("PAN \uff21\uff22\uff23\uff30\uff25\uff11\uff12\uff13\uff14\uff26"),
    "devanagari-digits": chat("PAN ABCPE१२३४F, mobile ९८७६५४३२१०"),
    "nbsp-in-mobile": chat("mobile 98765\u00a043210"),
}


@pytest.mark.parametrize("payload", LEAKS.values(), ids=list(LEAKS))
def test_no_personal_data_reaches_a_frontier_endpoint(env, payload):
    base, _ = env()
    status, _ = post(base, payload)
    assert status == 200
    assert len(Recorder.raw) == 1
    assert_no_leak()


def test_json_unicode_escapes_are_decoded_before_checking(env):
    base, _ = env()
    raw = (
        b'{"model": "frontier/m", "messages": '
        b'[{"role": "user", "content": "PAN \\u0041BCPE1234F"}]}'
    )
    assert post(base, raw=raw)[0] == 200
    assert_no_leak()


# --- B. What cannot be checked is refused, not sent -------------------------

REFUSED = {
    "content-object": {
        "model": "frontier/m",
        "messages": [{"role": "user", "content": {"text": PAN}}],
    },
    "text-part-not-a-string": {
        "model": "frontier/m",
        "messages": [{"role": "user", "content": [{"type": "text", "text": [PAN]}]}],
    },
    "image": {
        "model": "frontier/m",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
                ],
            }
        ],
    },
    "audio-part": {
        "model": "frontier/m",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}}
                ],
            }
        ],
    },
    "file-part": {
        "model": "frontier/m",
        "messages": [
            {"role": "user", "content": [{"type": "file", "file": {"file_data": "AAAA"}}]}
        ],
    },
    "audio-output": chat(modalities=["text", "audio"]),
    "part-without-type": {
        "model": "frontier/m",
        "messages": [{"role": "user", "content": [{"text": PAN}]}],
    },
    "pan-as-field-name": chat(metadata={f"customer {PAN}": "x"}),
    "deep-nesting": chat(metadata=json.loads("[" * 100 + "]" * 100)),
    "no-messages": {"model": "frontier/m", "messages": []},
    "message-not-object": {"model": "frontier/m", "messages": [f"PAN {PAN}"]},
    "body-not-object": [f"PAN {PAN}"],
    "model-without-endpoint": chat(model="m"),
    "empty-model-name": chat(model="frontier/"),
    "empty-endpoint": chat(model="/m"),
    "unknown-endpoint": chat(model="Frontier/m"),
}


@pytest.mark.parametrize("payload", REFUSED.values(), ids=list(REFUSED))
def test_what_cannot_be_checked_is_refused(env, payload):
    base, _ = env()
    status, body = post(base, payload)
    assert status in (400, 404)
    assert "error" in body
    assert Recorder.raw == []


def test_invalid_bodies(env):
    base, _ = env()
    for raw in (b"not json", b"\xff\xfe\x00", b"", b"{" * 5000):
        status, _ = post(base, raw=raw)
        assert status in (400, 411)
    assert Recorder.raw == []


# --- C. Hostile HTTP --------------------------------------------------------


def _raw_http(port, data, shutdown_write=False):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(data)
        if shutdown_write:
            s.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
        return b"".join(chunks)


def test_chunked_and_lying_lengths(env, server_kind):
    _, port = env()
    body = json.dumps(chat(f"PAN {PAN}")).encode()
    chunked = (
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
        + hex(len(body))[2:].encode()
        + b"\r\n"
        + body
        + b"\r\n0\r\n\r\n"
    )
    if server_kind == "standard":
        # The standard library cannot read chunked bodies: refused.
        assert _raw_http(port, chunked).startswith(b"HTTP/1.1 411")
    else:
        # uvicorn reads them properly: governed like any other request.
        assert _raw_http(port, chunked).startswith(b"HTTP/1.1 200")
        assert all(PAN.encode() not in raw for raw in Recorder.raw)
        Recorder.raw.clear()
    bad = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: ten\r\n\r\n"
    assert _raw_http(port, bad).startswith(b"HTTP/1.1 400")
    short = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 999\r\n\r\n" + body
    answer = _raw_http(port, short, shutdown_write=True)
    # Refused (standard) or the connection dropped (uvicorn): never forwarded.
    assert answer.startswith(b"HTTP/1.1 400") or (server_kind == "uvicorn" and answer == b"")
    assert Recorder.raw == []


def test_no_request_smuggling_after_a_rejected_request(env, tmp_path):
    keys = tmp_path / "keys.json"
    add_user(keys, "priya")
    _, port = env(keys=keys)
    second = json.dumps(chat(f"PAN {PAN}", model="local/m")).encode()
    smuggled = (
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: "
        + str(len(second)).encode()
        + b"\r\n\r\n"
        + second
    )
    # Unauthenticated, with a second request hidden in a body the proxy never reads.
    first = (
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: "
        + str(len(smuggled)).encode()
        + b"\r\n\r\n"
        + smuggled
    )
    answer = _raw_http(port, first)
    assert answer.startswith(b"HTTP/1.1 401")
    assert answer.count(b"HTTP/1.1") == 1  # the hidden request was never answered
    assert b"connection: close" in answer.lower()
    assert Recorder.raw == []


def test_unknown_paths_and_methods(env):
    _, port = env()
    for line in (
        b"GET /v1/chat/completions?x=1",
        b"POST /chat/completions",
        b"PUT /v1/chat/completions",
        b"GET /../../etc/passwd",
        b"POST /v1/completions",
    ):
        answer = _raw_http(
            port, line + b" HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        assert answer.split(b" ")[1] in (b"400", b"404", b"501")
    assert Recorder.raw == []


def test_slow_clients_are_dropped():
    assert 0 < proxy_module._Handler.timeout <= 300


# --- D. A hostile or broken endpoint ----------------------------------------


def test_redirects_are_not_followed(env):
    base, _ = env()
    status, body = post(base, chat("hello", model="redirecting/m"))
    assert status == 502
    assert body["error"]["code"] == "endpoint_redirect"
    assert Recorder.raw == []  # the redirect target received nothing


def test_endpoints_that_do_not_answer_json(env):
    base, _ = env()
    status, body = post(base, chat("hello", model="broken/m"))
    assert status == 502
    assert body["error"]["code"] == "endpoint_error"


def test_oversized_answers(env, monkeypatch):
    monkeypatch.setattr(proxy_module, "MAX_ANSWER", 10)
    base, _ = env()
    status, body = post(base, chat("hello", model="local/m"))
    assert status == 502
    assert "too much" in body["error"]["message"]


def test_only_this_requests_tokens_are_restored(env):
    base, _ = env()
    other = credgate.Vault("0123456789abcdef" * 4)
    foreign = credgate.tokenise(f"PAN {PAN}", other).split()[-1]  # a token from another vault
    status, body = post(base, chat(f"what is {foreign}?"))
    assert status == 200
    assert foreign in body["choices"][0]["message"]["content"]
    assert PAN not in body["choices"][0]["message"]["content"]


def test_client_keys_never_reach_the_endpoint(env, tmp_path, monkeypatch):
    keys = tmp_path / "keys.json"
    key = add_user(keys, "priya")
    base, _ = env(keys=keys)
    assert post(base, chat("hello"), key=key)[0] == 200
    sent = Recorder.headers_seen[-1]
    assert "Authorization" not in sent
    assert key not in json.dumps(sent)


# --- E. Configuration that must be refused ------------------------------------


def test_unsafe_configurations_are_refused(tmp_path):
    def policy(url):
        return credgate.Policy.from_dict(
            {
                "policy": "credgate-policy",
                "version": 1,
                "id": "p",
                "revision": 1,
                "destinations": {"x": {"tier": "local", "url": url}},
                "rules": [],
                "default_action": "redact",
            }
        )

    for url in ("file:///etc/passwd", "ftp://host/v1", "gopher://x", "javascript:alert(1)"):
        with pytest.raises(ValueError, match="http"):
            ProxyConfig(policy=policy(url), audit=tmp_path / "a.jsonl")
    for host in ("0.0.0.0", "::", "192.168.1.10"):
        with pytest.raises(ValueError, match="keys file"):
            ProxyConfig(policy=policy("http://x/v1"), audit=tmp_path / "a.jsonl", host=host)
    for host in ("127.0.0.1", "localhost", "::1"):
        ProxyConfig(policy=policy("http://x/v1"), audit=tmp_path / "a.jsonl", host=host)
    keys = tmp_path / "k.json"
    keys.write_text('{"credgate_proxy_keys": 1, "users": {}}')
    with pytest.raises(ValueError, match="No users"):
        ProxyConfig(policy=policy("http://x/v1"), audit=tmp_path / "a.jsonl", keys=keys)
    with pytest.raises(ValueError, match="names may contain"):
        add_user(tmp_path / "k2.json", "eve\nadmin")


def test_keys_file_is_private(tmp_path):
    keys = tmp_path / "keys.json"
    add_user(keys, "priya")
    assert keys.stat().st_mode & 0o077 == 0


# --- F. Concurrency ------------------------------------------------------------


def test_concurrent_requests_keep_the_audit_chain_and_their_own_values(env, tmp_path):
    base, _ = env()
    pans = credgate.synth_indian_pii(40, seed=7)

    def one(i):
        pan = pans[i]["pan"]
        if i % 5 == 0:  # some blocked
            return post(base, chat("Card 4111 1111 1111 1111, CVV 123, expiry 08/29")), None
        return post(base, chat(f"PAN {pan}")), pan

    with ThreadPoolExecutor(16) as pool:
        results = list(pool.map(one, range(40)))
    for (status, body), pan in results:
        if pan is None:
            assert status == 403
        else:
            assert status == 200
            assert body["choices"][0]["message"]["content"] == f"echo: PAN {pan}"
    check = credgate.audit_verify(tmp_path / "audit.jsonl")
    assert check.ok
    assert check.records == 40
    for raw in Recorder.raw:
        assert not any(p["pan"] in raw.decode() for p in pans)


# --- G. Failures stop the request ----------------------------------------------


def test_nothing_is_sent_when_the_audit_log_cannot_be_written(env, tmp_path):
    folder = tmp_path / "audit-is-a-folder"
    folder.mkdir()
    base, _ = env(audit=folder)
    status, body = post(base, chat("hello"))
    assert status == 500
    assert body["error"]["code"] == "credgate_error"
    assert Recorder.raw == []


def test_bursts_of_connections_wait_in_a_long_enough_queue(tmp_path):
    # Python's standard server keeps only 5 connections waiting to be
    # accepted; a burst beyond that waits for the kernel's retries.
    pol = credgate.Policy.from_dict(
        {
            "policy": "credgate-policy",
            "version": 1,
            "id": "q",
            "revision": 1,
            "destinations": {"x": {"tier": "local", "url": "http://127.0.0.1:9/v1"}},
            "rules": [],
            "default_action": "allow",
        }
    )
    server = make_server(
        ProxyConfig(policy=pol, audit=tmp_path / "a.jsonl", port=0), log=lambda line: None
    )
    try:
        assert server.request_queue_size >= 128
    finally:
        server.server_close()
