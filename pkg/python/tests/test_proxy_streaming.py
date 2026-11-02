"""Proxy phase 2: answers streamed as they arrive, and the Anthropic and
Ollama APIs, against a fake server that speaks all three and streams in
small pieces - so tokens are split across pieces."""

from __future__ import annotations

import http.client
import json
import random
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import credgate
from credgate.proxy import ProxyConfig, _Restorer, add_user, make_server

PAN = "ABCPE1234F"
PIECE = 3  # characters per streamed piece: every token is split


class FakeEverything(BaseHTTPRequestHandler):
    """Echoes the last user text, as OpenAI, Anthropic or Ollama would."""

    received: ClassVar[list] = []
    delay: ClassVar[float] = 0.0  # seconds between streamed pieces
    stall_after: ClassVar[int | None] = None  # stop sending after this many pieces
    stopped: ClassVar[threading.Event] = threading.Event()
    garbage_after: ClassVar[int | None] = None  # send something unreadable after this many
    reset_after: ClassVar[int | None] = None  # drop the connection after this many
    first_delay: ClassVar[float] = 0.0  # the model "thinking" before its first piece

    def do_GET(self):
        if self.path == "/api/tags":
            self._json({"models": [{"name": "llama3.1:8b", "model": "llama3.1:8b", "size": 1}]})
        elif self.path == "/api/version":
            self._json({"version": "0.12.6"})
        else:
            self._json({"object": "list", "data": [{"id": "m"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).received.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        if self.path == "/api/show":
            self._json({"capabilities": ["completion", "tools"], "model_info": {"ctx": 8192}})
            return
        if self.path.endswith("/count_tokens"):
            self._json({"input_tokens": 12})
            return
        text = "Noted: " + _last_text(body)
        if self.path == "/v1/chat/completions":
            self._openai(body, text)
        elif self.path == "/v1/messages":
            self._anthropic(body, text)
        elif self.path in ("/api/chat", "/api/generate"):
            self._ollama(body, text, "response" if self.path == "/api/generate" else None)
        else:
            self.send_error(404)

    def _openai(self, body, text):
        if not body.get("stream"):
            self._json(
                {
                    "id": "c1",
                    "object": "chat.completion",
                    "model": body["model"],
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}],
                }
            )
            return
        base = {"id": "c1", "object": "chat.completion.chunk", "created": 1, "model": body["model"]}
        events = [base | {"choices": [{"index": 0, "delta": {"role": "assistant"}}]}]
        events += [
            base | {"choices": [{"index": 0, "delta": {"content": p}}]} for p in _pieces(text)
        ]
        events.append(base | {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        self._stream([f"data: {json.dumps(e)}\n\n" for e in events] + ["data: [DONE]\n\n"])

    def _anthropic(self, body, text):
        message = {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        if not body.get("stream"):
            self._json(message)
            return

        def ev(name, data):
            return f"event: {name}\ndata: {json.dumps(data)}\n\n"

        start = message | {"content": []}
        events = [ev("message_start", {"type": "message_start", "message": start})]
        events.append(
            ev(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            )
        )
        events += [
            ev(
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": p},
                },
            )
            for p in _pieces(text)
        ]
        events.append(ev("content_block_stop", {"type": "content_block_stop", "index": 0}))
        events.append(ev("message_stop", {"type": "message_stop"}))
        self._stream(events)

    def _ollama(self, body, text, field):
        def piece(t, done=False):
            p = {"model": body["model"], "done": done}
            if field:
                p[field] = t
            else:
                p["message"] = {"role": "assistant", "content": t}
            return p

        if body.get("stream") is False:
            self._json(piece(text, done=True))
            return
        lines = [json.dumps(piece(p)) + "\n" for p in _pieces(text)]
        lines.append(json.dumps(piece("", done=True)) + "\n")
        self._stream(lines, "application/x-ndjson")

    def _stream(self, parts, content_type="text/event-stream"):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()
        time.sleep(type(self).first_delay)
        try:
            for i, part in enumerate(parts):
                if type(self).stall_after is not None and i >= type(self).stall_after:
                    time.sleep(5)  # stalls: the proxy's timeout ends it
                    return
                if type(self).garbage_after is not None and i >= type(self).garbage_after:
                    garbage = (
                        "{not json at all\n" if "ndjson" in content_type else "data: {not json\n\n"
                    )
                    self.wfile.write(garbage.encode())
                    self.wfile.flush()
                    time.sleep(0.5)
                    return
                if type(self).reset_after is not None and i >= type(self).reset_after:
                    import socket as _socket
                    import struct

                    self.connection.setsockopt(
                        _socket.SOL_SOCKET, _socket.SO_LINGER, struct.pack("ii", 1, 0)
                    )
                    self.connection.close()  # an abrupt reset, not a clean end
                    return
                self.wfile.write(part.encode())
                self.wfile.flush()
                if type(self).delay:
                    time.sleep(type(self).delay)
        except (BrokenPipeError, ConnectionResetError):
            type(self).stopped.set()

    def _json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def _pieces(text):
    return [text[i : i + PIECE] for i in range(0, len(text), PIECE)]


def _last_text(body):
    if "prompt" in body:
        return body["prompt"]
    content = body["messages"][-1]["content"]
    if isinstance(content, str):
        return content
    return " ".join(b.get("text", "") for b in content if isinstance(b, dict))


def _start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def upstream():
    FakeEverything.received = []
    FakeEverything.delay = 0.0
    FakeEverything.stall_after = None
    FakeEverything.stopped = threading.Event()
    FakeEverything.garbage_after = None
    FakeEverything.reset_after = None
    FakeEverything.first_delay = 0.0
    server = _start(ThreadingHTTPServer(("127.0.0.1", 0), FakeEverything))
    yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()


def _policy(url):
    return credgate.Policy.from_dict(
        {
            "policy": "credgate-policy",
            "version": 1,
            "id": "streams",
            "revision": 1,
            "destinations": {
                "frontier": {"tier": "frontier", "url": url},
                "local": {"tier": "local", "url": url},
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
    servers = []

    def start(**kwargs):
        kwargs.setdefault("server", server_kind)
        config = ProxyConfig(
            policy=_policy(upstream), audit=tmp_path / "audit.jsonl", port=0, **kwargs
        )
        lines = []
        server = _start(make_server(config, log=lines.append))
        server.log_lines = lines
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}", server

    yield start
    for s in servers:
        s.shutdown()


def _post(base, path, payload, headers=None):
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def _logged(server, word, seconds=5.0):
    """The proxy logs after the answer is sent: wait for its line."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if any(word in line for line in server.log_lines):
            return True
        time.sleep(0.02)
    return False


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=15) as r:
        return json.loads(r.read())


def _sse_data(body):
    return [line[6:] for line in body.decode().splitlines() if line.startswith("data: ")]


TEXT = f"PAN {PAN}, mobile 9876543210"
EXPECTED = f"Noted: PAN {PAN}, mobile [MOBILE_IN]"


# --- the restorer ----------------------------------------------------------------


def test_tokens_split_anywhere_are_restored_like_whole_text():
    vault = credgate.Vault(b"k" * 32)
    tokenised = credgate.tokenise(f"PAN {PAN} and Aadhaar 2345 6789 0124 and again {PAN}.", vault)
    tok = tokenised.split()[1]  # e.g. [PAN_xxxx]
    name = tok.strip("[]")
    variants = [
        tokenised,
        f"see {tok.lower()}!",  # any letter case
        f"bare {name} here",  # without brackets
        f"spaced [ {name} ] here",
        f"glued x{name} stays",  # not a token: no boundary before it
        f"{tok}{tok}",
        "no tokens [here] at all, just [ brackets and words_like_this",
        f"ends with {tok}",
        f"ends with bare {name}",
    ]
    rng = random.Random(7)
    for text in variants:
        whole = credgate.restore(text, vault)
        for _ in range(200):
            cuts = sorted(rng.sample(range(1, len(text)), k=min(len(text) - 1, rng.randint(1, 8))))
            pieces = [text[a:b] for a, b in zip([0, *cuts], [*cuts, len(text)], strict=True)]
            r = _Restorer(vault)
            out = "".join(r.feed(p) for p in pieces) + r.flush()
            assert out == whole, (text, pieces)
        # one character at a time
        r = _Restorer(vault)
        assert "".join(r.feed(c) for c in text) + r.flush() == whole
    assert PAN in credgate.restore(tokenised, vault)


def test_the_restorer_holds_back_only_what_could_be_a_token():
    r = _Restorer(credgate.Vault(b"k" * 32))
    assert r.feed("Hello there, ") == "Hello there, "
    assert r.feed("[PAN_") == ""  # could be a token
    assert r.feed("x] and") == "[PAN_x] and"[:-3]  # unknown token passes through; "and" waits
    assert r.flush() == "and"
    long_word = "a" * 200
    assert r.feed(long_word + " ") == long_word + " "  # too long to be a token


# --- OpenAI ------------------------------------------------------------------------


def test_openai_streams_with_tokens_restored(proxy):
    base, server = proxy()
    status, headers, body = _post(
        base,
        "/v1/chat/completions",
        {"model": "frontier/gpt", "stream": True, "messages": [{"role": "user", "content": TEXT}]},
    )
    assert status == 200
    assert headers["Content-Type"] == "text/event-stream"
    sent = FakeEverything.received[-1]["body"]
    assert sent["stream"] is True
    assert PAN not in json.dumps(sent)
    events = _sse_data(body)
    assert events[-1] == "[DONE]"
    chunks = [json.loads(e) for e in events[:-1]]
    assert all(c["model"] == "frontier/gpt" for c in chunks)
    text = "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks if c["choices"])
    assert text == EXPECTED
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    assert _logged(server, "200 stream")  # the log says it streamed, on both servers


def test_answers_arrive_while_the_model_is_still_writing(proxy):
    FakeEverything.delay = 0.1
    base, _ = proxy()
    host, port = base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=15)
    started = time.monotonic()
    conn.request(
        "POST",
        "/v1/chat/completions",
        json.dumps(
            {
                "model": "local/m",
                "stream": True,
                "messages": [{"role": "user", "content": "x" * 60}],
            }
        ),
        {"Content-Type": "application/json"},
    )
    response = conn.getresponse()
    first = response.readline()
    first_at = time.monotonic() - started
    response.read()
    total = time.monotonic() - started
    assert first.startswith(b"data: ")
    assert total > 2  # ~23 pieces at 0.1 s
    assert first_at < total / 3  # the first piece came long before the last


def test_a_client_that_leaves_stops_the_endpoint_stream(proxy):
    FakeEverything.delay = 0.05
    base, server = proxy()
    host, port = base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=15)
    conn.request(
        "POST",
        "/v1/chat/completions",
        json.dumps(
            {
                "model": "local/m",
                "stream": True,
                "messages": [{"role": "user", "content": "y" * 3000}],
            }
        ),
        {"Content-Type": "application/json"},
    )
    response = conn.getresponse()
    response.readline()
    response.close()  # the user closed the tab
    conn.close()
    assert FakeEverything.stopped.wait(10)
    assert _logged(server, "client_closed")


def test_an_endpoint_that_stalls_ends_the_stream_with_an_error_event(proxy):
    FakeEverything.stall_after = 3
    base, server = proxy(timeout=1)
    status, _, body = _post(
        base,
        "/v1/chat/completions",
        {
            "model": "local/m",
            "stream": True,
            "messages": [{"role": "user", "content": "hello there"}],
        },
    )
    assert status == 200  # already started
    events = _sse_data(body)
    assert events[-1] == "[DONE]"
    assert json.loads(events[-2])["error"]["code"] == "endpoint_unreachable"
    assert _logged(server, "endpoint_unreachable")


def test_blocked_streaming_requests_are_refused_before_anything_streams(proxy):
    base, _ = proxy()
    card = "Card 4111 1111 1111 1111, CVV 123, expiry 08/29"
    status, headers, body = _post(
        base,
        "/v1/chat/completions",
        {"model": "frontier/gpt", "stream": True, "messages": [{"role": "user", "content": card}]},
    )
    assert status == 403
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body)["error"]["code"] == "policy_blocked"
    assert FakeEverything.received == []


# --- Anthropic ------------------------------------------------------------------------


def _anthropic(model, content, **extra):
    return {
        "model": model,
        "max_tokens": 100,
        "messages": [{"role": "user", "content": content}],
        **extra,
    }


def test_anthropic_messages_are_governed_and_restored(proxy, monkeypatch):
    monkeypatch.setenv("CREDGATE_UPSTREAM_KEY_FRONTIER", "sk-ant-upstream")
    base, _ = proxy()
    status, _, body = _post(
        base,
        "/v1/messages",
        _anthropic(
            "frontier/claude-x", [{"type": "text", "text": TEXT}], system=f"Customer PAN is {PAN}."
        ),
        {"anthropic-version": "2023-06-01", "anthropic-beta": "tools-2024-04-04"},
    )
    assert status == 200
    got = FakeEverything.received[-1]
    assert got["path"] == "/v1/messages"
    assert PAN not in json.dumps(got["body"])
    assert got["body"]["model"] == "claude-x"
    headers = {k.lower(): v for k, v in got["headers"].items()}
    assert headers["x-api-key"] == "sk-ant-upstream"
    assert "authorization" not in headers
    assert headers["anthropic-version"] == "2023-06-01"
    assert headers["anthropic-beta"] == "tools-2024-04-04"
    answer = json.loads(body)
    assert answer["model"] == "frontier/claude-x"
    assert answer["content"][0]["text"] == EXPECTED


def test_anthropic_streams_with_tokens_restored(proxy):
    base, _ = proxy()
    status, headers, body = _post(
        base, "/v1/messages", _anthropic("frontier/claude-x", TEXT, stream=True)
    )
    assert status == 200
    assert headers["Content-Type"] == "text/event-stream"
    events = [json.loads(e) for e in _sse_data(body)]
    assert events[0]["message"]["model"] == "frontier/claude-x"
    text = "".join(e["delta"]["text"] for e in events if e["type"] == "content_block_delta")
    assert text == EXPECTED
    # every delta comes before its block ends
    kinds = [e["type"] for e in events]
    assert kinds.index("content_block_stop") > max(
        i for i, k in enumerate(kinds) if k == "content_block_delta"
    )
    assert "event: content_block_delta" in body.decode()


def test_anthropic_tools_thinking_and_results_are_handled_exactly(proxy):
    base, _ = proxy()
    payload = {
        "model": "frontier/claude-x",
        "max_tokens": 100,
        "tools": [
            {
                "name": "lookup_customer",
                "description": "Find a customer",
                "input_schema": {"type": "object", "properties": {"pan": {"type": "string"}}},
            }
        ],
        "messages": [
            {"role": "user", "content": "Find the customer"},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": "I should look it up.",
                        "signature": "c2lnbmF0dXJl" * 8,
                    },
                    {"type": "redacted_thinking", "data": "ZW5jcnlwdGVk" * 8},
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "lookup_customer",
                        "input": {"pan": PAN},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": [{"type": "text", "text": f"Customer {PAN}, mobile 9876543210"}],
                    },
                ],
            },
        ],
    }
    status, _, _ = _post(base, "/v1/messages", payload)
    assert status == 200
    sent = FakeEverything.received[-1]["body"]
    dump = json.dumps(sent)
    assert PAN not in dump
    assert "9876543210" not in dump
    assert sent["tools"][0]["name"] == "lookup_customer"
    blocks = sent["messages"][1]["content"]
    assert blocks[0]["signature"] == "c2lnbmF0dXJl" * 8
    assert blocks[1]["data"] == "ZW5jcnlwdGVk" * 8
    assert blocks[2]["name"] == "lookup_customer"
    assert blocks[2]["id"] == "toolu_1"
    assert sent["messages"][2]["content"][0]["tool_use_id"] == "toolu_1"


@pytest.mark.parametrize(
    "block",
    [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}},
        {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "x"}},
        {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "image", "source": {}}]},
        {"type": "something_new", "text": "?"},
    ],
)
def test_anthropic_content_that_cannot_be_checked_is_refused(proxy, block):
    base, server = proxy()
    status, _, body = _post(base, "/v1/messages", _anthropic("frontier/claude-x", [block]))
    assert status == 400
    error = json.loads(body)
    assert error["type"] == "error"  # Anthropic's error shape, which its SDKs read
    assert error["error"]["type"] == "unsupported_content"
    assert FakeEverything.received == []
    # the proxy's log names the type refused (a name, never the content)
    kind = block["content"][0]["type"] if block["type"] == "tool_result" else block["type"]
    assert _logged(server, f"unsupported_content({kind})")


def test_anthropic_token_counting_is_governed_too(proxy):
    base, _ = proxy()
    status, _, body = _post(
        base, "/v1/messages/count_tokens", _anthropic("frontier/claude-x", TEXT)
    )
    assert status == 200
    assert json.loads(body) == {"input_tokens": 12}
    got = FakeEverything.received[-1]
    assert got["path"] == "/v1/messages/count_tokens"
    assert PAN not in json.dumps(got["body"])


def test_anthropic_clients_authenticate_with_x_api_key(proxy, tmp_path):
    keys = tmp_path / "keys.json"
    key = add_user(keys, "analyst-7")
    base, _ = proxy(keys=keys)
    status, _, body = _post(base, "/v1/messages", _anthropic("local/m", "hi"))
    assert status == 401
    assert json.loads(body)["error"]["type"] == "unauthorized"
    status, _, _ = _post(base, "/v1/messages", _anthropic("local/m", "hi"), {"x-api-key": key})
    assert status == 200
    assert credgate.audit_read(tmp_path / "audit.jsonl")[-1]["actor"] == "analyst-7"


# --- Ollama --------------------------------------------------------------------------------


def test_ollama_chat_streams_by_default_with_tokens_restored(proxy):
    base, _ = proxy()
    status, headers, body = _post(
        base,
        "/api/chat",
        {"model": "frontier/llama3.1:8b", "messages": [{"role": "user", "content": TEXT}]},
    )
    assert status == 200
    assert headers["Content-Type"] == "application/x-ndjson"
    got = FakeEverything.received[-1]
    assert got["path"] == "/api/chat"  # the endpoint's own API, beside /v1
    assert got["body"]["model"] == "llama3.1:8b"
    assert PAN not in json.dumps(got["body"])
    lines = [json.loads(line) for line in body.splitlines()]
    assert lines[-1]["done"] is True
    assert all(line["model"] == "frontier/llama3.1:8b" for line in lines)
    assert "".join(line["message"]["content"] for line in lines) == EXPECTED


def test_ollama_generate_without_streaming(proxy):
    base, _ = proxy()
    status, _, body = _post(
        base,
        "/api/generate",
        {
            "model": "frontier/llama3.1:8b",
            "prompt": TEXT,
            "stream": False,
            "options": {"num_ctx": 131072, "seed": 123456789},
            "context": [128000, 300000],
        },
    )
    assert status == 200
    sent = FakeEverything.received[-1]["body"]
    assert PAN not in json.dumps(sent)
    assert sent["options"] == {"num_ctx": 131072, "seed": 123456789}
    assert sent["context"] == [128000, 300000]
    assert json.loads(body)["response"] == EXPECTED


def test_ollama_images_are_refused(proxy):
    base, _ = proxy()
    status, _, body = _post(
        base,
        "/api/chat",
        {
            "model": "frontier/llava",
            "messages": [{"role": "user", "content": "what is this", "images": ["iVBOR"]}],
        },
    )
    assert status == 400
    assert json.loads(body)["code"] == "unsupported_content"
    status, _, _ = _post(
        base, "/api/generate", {"model": "frontier/llava", "prompt": "x", "images": ["iVBOR"]}
    )
    assert status == 400
    assert FakeEverything.received == []


def test_ollama_model_list_details_and_version(proxy):
    base, _ = proxy()
    names = [m["name"] for m in _get(base, "/api/tags")["models"]]
    assert "frontier/llama3.1:8b" in names
    assert "local/llama3.1:8b" in names
    assert not any(n.startswith("copilot/") for n in names)
    status, _, body = _post(base, "/api/show", {"model": "local/llama3.1:8b"})
    assert status == 200
    assert json.loads(body)["capabilities"] == ["completion", "tools"]
    assert FakeEverything.received[-1]["body"] == {"model": "llama3.1:8b"}
    assert _get(base, "/api/version") == {"version": "0.12.6"}
    status, _, _ = _post(base, "/api/show", {"model": "copilot/x"})
    assert status == 403


def test_every_api_is_audited(proxy, tmp_path):
    base, _ = proxy()
    _post(
        base,
        "/v1/chat/completions",
        {"model": "frontier/m", "messages": [{"role": "user", "content": TEXT}]},
    )
    _post(base, "/v1/messages", _anthropic("frontier/m", TEXT))
    _post(
        base,
        "/api/chat",
        {"model": "frontier/m", "stream": False, "messages": [{"role": "user", "content": TEXT}]},
    )
    records = credgate.audit_read(tmp_path / "audit.jsonl")
    assert len(records) == 3
    assert credgate.audit_verify(tmp_path / "audit.jsonl").ok
    assert PAN not in (tmp_path / "audit.jsonl").read_text()


# --- Claude Code and other clients that bring their own key --------------------------


def test_models_without_an_endpoint_go_to_the_default_endpoint(proxy):
    base, _ = proxy()
    status, _, body = _post(base, "/v1/messages", _anthropic("claude-sonnet-x", "hi"))
    assert status == 400  # no default: the endpoint must be named
    assert json.loads(body)["error"]["type"] == "invalid_model"
    base, _ = proxy(default_endpoint="frontier")
    status, _, body = _post(base, "/v1/messages", _anthropic("claude-sonnet-x", TEXT))
    assert status == 200
    sent = FakeEverything.received[-1]["body"]
    assert sent["model"] == "claude-sonnet-x"
    assert PAN not in json.dumps(sent)  # the frontier rules applied
    assert json.loads(body)["model"] == "claude-sonnet-x"  # as the client asked


def test_unknown_default_endpoints_are_refused(upstream, tmp_path):
    with pytest.raises(ValueError, match="not in the policy"):
        ProxyConfig(policy=_policy(upstream), audit=tmp_path / "a.jsonl", default_endpoint="nope")


def _upstream_headers():
    return {k.lower(): v for k, v in FakeEverything.received[-1]["headers"].items()}


def test_localhost_passes_the_users_own_key_on(proxy, monkeypatch):
    monkeypatch.delenv("CREDGATE_UPSTREAM_KEY_FRONTIER", raising=False)
    base, _ = proxy()
    _post(
        base,
        "/v1/messages",
        _anthropic("frontier/m", "hi"),
        {"Authorization": "Bearer sk-ant-oat-user", "anthropic-beta": "oauth-2025-04-20"},
    )
    headers = _upstream_headers()
    assert headers["authorization"] == "Bearer sk-ant-oat-user"
    assert headers["anthropic-beta"] == "oauth-2025-04-20"
    _post(base, "/v1/messages", _anthropic("frontier/m", "hi"), {"x-api-key": "sk-ant-user"})
    assert _upstream_headers()["x-api-key"] == "sk-ant-user"
    # the proxy's own key for the endpoint wins, and the user's is not sent
    monkeypatch.setenv("CREDGATE_UPSTREAM_KEY_FRONTIER", "sk-ant-proxy")
    _post(base, "/v1/messages", _anthropic("frontier/m", "hi"), {"x-api-key": "sk-ant-user"})
    headers = _upstream_headers()
    assert headers["x-api-key"] == "sk-ant-proxy"
    assert "sk-ant-user" not in json.dumps(headers)


def test_shared_mode_never_passes_client_keys_on(proxy, tmp_path, monkeypatch):
    monkeypatch.delenv("CREDGATE_UPSTREAM_KEY_FRONTIER", raising=False)
    keys = tmp_path / "keys.json"
    key = add_user(keys, "analyst-7")
    base, _ = proxy(keys=keys)
    for path, payload in [
        ("/v1/messages", _anthropic("frontier/m", "hi")),
        (
            "/v1/chat/completions",
            {"model": "frontier/m", "messages": [{"role": "user", "content": "hi"}]},
        ),
        (
            "/api/chat",
            {
                "model": "frontier/m",
                "stream": False,
                "messages": [{"role": "user", "content": "hi"}],
            },
        ),
    ]:
        status, _, _ = _post(base, path, payload, {"Authorization": f"Bearer {key}"})
        assert status == 200
        assert key not in json.dumps(FakeEverything.received[-1]["headers"])


# --- endpoints that misbehave mid-answer ----------------------------------------------


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/v1/chat/completions",
            {
                "model": "local/m",
                "stream": True,
                "messages": [{"role": "user", "content": "hello there friend"}],
            },
        ),
        (
            "/v1/messages",
            {
                "model": "local/m",
                "max_tokens": 9,
                "stream": True,
                "messages": [{"role": "user", "content": "hello there friend"}],
            },
        ),
        (
            "/api/chat",
            {"model": "local/m", "messages": [{"role": "user", "content": "hello there friend"}]},
        ),
    ],
)
def test_an_unreadable_answer_ends_the_stream_cleanly(proxy, path, payload):
    FakeEverything.garbage_after = 3
    base, server = proxy()
    status, _, body = _post(base, path, payload)  # a corrupt stream would fail to parse here
    assert status == 200
    text = body.decode()
    assert "not json" not in text  # never passed on
    assert "endpoint_error" in text
    assert _logged(server, "endpoint_error")
    # the connection is still usable: the next request on a fresh one works
    FakeEverything.garbage_after = None
    assert _post(base, path, payload)[0] == 200


def test_an_endpoint_that_drops_mid_answer_is_not_mistaken_for_the_client(proxy):
    FakeEverything.reset_after = 3
    base, server = proxy()
    status, _, body = _post(
        base,
        "/v1/chat/completions",
        {
            "model": "local/m",
            "stream": True,
            "messages": [{"role": "user", "content": "hello there friend"}],
        },
    )
    assert status == 200
    events = _sse_data(body)
    assert events[-1] == "[DONE]"
    # an abrupt reset reads as an error or as the end of the answer; either
    # way the stream ends properly and the client is not blamed
    assert not any("client_closed" in line for line in server.log_lines)


# --- uvicorn: what only a production server does ---------------------------------------


def _stream_request(base, model="local/m", text="hello"):
    host, port = base.removeprefix("http://").split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=30)
    body = {"model": model, "stream": True, "messages": [{"role": "user", "content": text}]}
    conn.request(
        "POST", "/v1/chat/completions", json.dumps(body), {"Content-Type": "application/json"}
    )
    return conn, conn.getresponse()


def test_uvicorn_notices_a_client_that_leaves_while_the_model_thinks(proxy, server_kind):
    if server_kind != "uvicorn":
        pytest.skip("the standard server notices at the next piece")
    FakeEverything.first_delay = 4
    base, server = proxy()
    conn, response = _stream_request(base)
    assert response.status == 200
    time.sleep(0.3)
    left = time.monotonic()
    response.close()
    conn.close()
    assert _logged(server, "client_closed", seconds=3)
    assert time.monotonic() - left < 2  # not after the model's 4 seconds


def test_uvicorn_limits_requests_in_progress(proxy, server_kind):
    if server_kind != "uvicorn":
        pytest.skip("uvicorn only")
    FakeEverything.first_delay = 2
    base, _ = proxy(concurrency=2)
    results = []

    def one():
        try:
            conn, response = _stream_request(base)
            results.append(response.status)
            response.read()
            conn.close()
        except Exception as e:  # pragma: no cover - reported below
            results.append(repr(e))

    threads = [threading.Thread(target=one) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert sorted(results).count(200) >= 1
    assert 503 in results  # more than allowed at once: refused, so a balancer can retry
    assert set(results) <= {200, 503}, results
