"""A policy-enforcing proxy for OpenAI-compatible model endpoints.

Tools send their requests to the proxy instead of the model endpoint. For
each request it applies the policy for the requested endpoint - allow,
redact, tokenise or block - records the decision in the audit log, forwards
what may be sent, and puts tokenised values back into the answer. It fails
closed: if anything goes wrong before the request is forwarded, nothing is
sent.

Endpoints are the policy's destinations, and each needs a ``url`` (the
OpenAI-compatible base URL, e.g. ``http://vllm.internal:8000/v1``). Clients
ask for ``"<destination>/<model>"``, e.g. ``"vllm-gpu/llama-3.1-70b"``. The
proxy holds the endpoints' own API keys (``CREDGATE_UPSTREAM_KEY_<NAME>``
environment variables, e.g. ``CREDGATE_UPSTREAM_KEY_VLLM_GPU``); clients
never see them.

Two modes:

- **localhost** (default): listens on 127.0.0.1; requests are recorded as
  the operating-system user running the proxy.
- **shared**: listens on a network address and requires a keys file; each
  client sends ``Authorization: Bearer <key>`` and is recorded by name. Add
  users with :func:`add_user` (``credgate proxy add-user``). Use TLS
  (``certfile``/``keyfile``) or a TLS-terminating reverse proxy.

Phase 1: ``POST /v1/chat/completions`` and ``GET /v1/models``. Streaming
requests (``"stream": true``) get the complete answer as a single streamed
message; token-by-token streaming comes later.

Only the Python standard library is used.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .policy import Policy
from .tokenise import Vault, restore

MAX_BODY = 20 * 1024 * 1024
MAX_ANSWER = 50 * 1024 * 1024
# Detection is CPU work in Python, which runs one thread at a time per
# process: threads competing for it are slower in total than taking turns.
# Waiting for endpoints still overlaps; more cores need more workers.
_CPU = threading.Lock()
_KEY_PREFIX = "cgk_"


@dataclass
class ProxyConfig:
    """Settings of a proxy.

    Args:
        policy: The policy, or a path to its YAML file.
        audit: The audit log file (JSON Lines); every request is recorded.
        host: Address to listen on; ``127.0.0.1`` for localhost mode.
        port: Port to listen on.
        keys: Keys file (see :func:`add_user`); required unless ``host`` is
            a loopback address.
        certfile: TLS certificate (PEM) for HTTPS; with ``keyfile``.
        keyfile: TLS private key (PEM).
        token_key: Key for the tokens sent to models (hex or bytes); default
            ``CREDGATE_TOKEN_KEY``, otherwise a random key per proxy process.
        audit_key: Key for hashing identifiers in the audit log; default
            ``CREDGATE_AUDIT_KEY``.
        timeout: Seconds to wait for an endpoint.
        workers: Processes serving requests (Linux and macOS). Detection is
            CPU work, and one Python process uses one core for it; with
            several workers the proxy uses several cores.
        drain_seconds: On SIGTERM, how long to keep serving while reporting
            "draining" on ``/healthz``, so a load balancer stops routing here;
            then requests in progress are finished and the proxy exits.
    """

    policy: Policy | str | os.PathLike[str]
    audit: str | os.PathLike[str]
    host: str = "127.0.0.1"
    port: int = 8790
    keys: str | os.PathLike[str] | None = None
    certfile: str | None = None
    keyfile: str | None = None
    token_key: str | bytes | None = None
    audit_key: str | bytes | None = None
    timeout: float = 300
    workers: int = 1
    drain_seconds: float = 5
    _users: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.policy, Policy):
            self.policy = Policy.load(self.policy)
        if not _is_loopback(self.host) and self.keys is None:
            raise ValueError(
                f"Listening on {self.host} (not localhost) needs a keys file, so that every "
                "request is authenticated and recorded by user: add users with "
                "`credgate proxy add-user`."
            )
        if self.keys is not None:
            self._users = _read_keys(self.keys)
            if not self._users:
                raise ValueError(
                    f"No users in {self.keys}; add one with `credgate proxy add-user`."
                )
        if not 1 <= self.workers <= 64:
            raise ValueError("`workers` must be between 1 and 64.")
        if self.workers > 1 and not hasattr(os, "fork"):
            raise ValueError("Several workers need fork (Linux, macOS); run one per port instead.")
        if (self.certfile is None) != (self.keyfile is None):
            raise ValueError("`certfile` and `keyfile` go together.")
        if self.token_key is None:
            self.token_key = os.environ.get("CREDGATE_TOKEN_KEY") or secrets.token_bytes(32)
        Vault(self.token_key)  # validates the key now, not on the first request
        for name, dest in self.policy.destinations.items():
            if dest.url and urllib.parse.urlsplit(dest.url).scheme not in ("http", "https"):
                raise ValueError(f"Endpoint {name!r}: the URL must be http:// or https://.")


def serve(config: ProxyConfig, log: Callable[[str], Any] | None = None) -> None:
    """Run the proxy until interrupted."""
    server = make_server(config, log=log)
    scheme = "https" if config.certfile else "http"
    mode = "shared" if config.keys else "localhost"
    host, port = server.server_address[:2]
    (log or _stderr)(
        f"credgate proxy ({mode} mode, {config.workers} worker(s)) on {scheme}://{host}:{port}/v1"
        f" - policy {config.policy.id} revision {config.policy.revision}, audit log {config.audit}"
    )
    # Workers share the listening socket; each request is self-contained, and
    # the audit log takes concurrent writers.
    parent = os.getpid()
    children = []
    for _ in range(config.workers - 1):
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, lambda *_: _drain(server, config.drain_seconds))
            threading.Thread(target=_exit_with_parent, args=(parent,), daemon=True).start()
            try:
                server.serve_forever()
                _wait_for_requests(config.timeout)
            finally:
                os._exit(0)
        children.append(pid)

    def terminate(signum: int, frame: Any) -> None:
        for pid in children:
            _signal(pid, signal.SIGTERM)  # each worker drains on its own
        _drain(server, config.drain_seconds)

    signal.signal(signal.SIGTERM, terminate)
    try:
        server.serve_forever()  # returns when drained; Ctrl-C stops at once
        _wait_for_requests(config.timeout)
    except KeyboardInterrupt:
        for pid in children:
            _signal(pid, signal.SIGKILL)
    finally:
        for pid in children:
            with contextlib.suppress(OSError):
                os.waitpid(pid, 0)
        server.server_close()


# Load balancers: on SIGTERM the proxy reports "draining" on /healthz (so the
# balancer stops routing to it) while it keeps serving for `drain_seconds`,
# then stops accepting and finishes the requests in progress.
_DRAINING = threading.Event()
_IN_FLIGHT = [0]
_IN_FLIGHT_LOCK = threading.Lock()


def _drain(server: Any, seconds: float) -> None:
    if _DRAINING.is_set():
        return
    _DRAINING.set()

    def later() -> None:
        time.sleep(seconds)
        server.shutdown()

    threading.Thread(target=later, daemon=True).start()


def _wait_for_requests(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _IN_FLIGHT_LOCK:
            if _IN_FLIGHT[0] == 0:
                return
        time.sleep(0.05)


def _signal(pid: int, sig: int) -> None:
    with contextlib.suppress(OSError):
        os.kill(pid, sig)


def _exit_with_parent(parent: int) -> None:
    """A worker stops when the main process is gone, even if it was killed."""
    while os.getppid() == parent:
        time.sleep(1)
    os._exit(0)


def make_server(
    config: ProxyConfig, log: Callable[[str], Any] | None = None
) -> ThreadingHTTPServer:
    """The proxy's HTTP server, not yet serving (port 0 picks a free port)."""
    attrs = {"config": config, "log": staticmethod(log or _stderr)}
    handler = type("CredgateProxyHandler", (_Handler,), attrs)
    server = ThreadingHTTPServer((config.host, config.port), handler)
    if config.certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config.certfile, config.keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    # Workers share this socket and are all woken for each connection; the
    # ones that lose the race must not wait in accept() forever (they would
    # never see a shutdown), so accept() times out and the loop checks again.
    # Accepted connections are blocking again (Python resets them).
    server.socket.settimeout(0.5)
    return server


def add_user(keys: str | os.PathLike[str], name: str) -> str:
    """Add a user to a keys file (created if missing) and return their new
    API key. Only a hash of the key is stored; the key is shown once."""
    if not re.fullmatch(r"[A-Za-z0-9._@-]{1,100}", name):
        raise ValueError("User names may contain letters, digits, '.', '_', '@' and '-'.")
    path = Path(keys)
    users = _read_keys(path) if path.exists() else {}
    if name in users:
        raise ValueError(f"User {name!r} already exists in {path}.")
    key = _KEY_PREFIX + secrets.token_urlsafe(32)
    users[name] = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"credgate_proxy_keys": 1, "users": users}, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
    return key


def _read_keys(path: str | os.PathLike[str]) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("credgate_proxy_keys") != 1:
        raise ValueError(f"{path} is not a credgate proxy keys file.")
    users = data.get("users", {})
    if not all(isinstance(v, str) and v.startswith("sha256:") for v in users.values()):
        raise ValueError(f"{path}: every user needs a `sha256:` key hash.")
    return dict(users)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


class _ProxyError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class _Handler(BaseHTTPRequestHandler):
    config: ProxyConfig
    log: Callable[[str], Any]
    protocol_version = "HTTP/1.1"
    server_version = "credgate-proxy"
    timeout = 120  # seconds a client may take to send its request

    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/healthz", "/v1/healthz"):
            self._health()
            return
        self._handle(self._models if self.path.rstrip("/") == "/v1/models" else None)

    def _health(self) -> None:
        """For load balancers: no key needed, nothing sensitive."""
        policy: Policy = self.config.policy  # type: ignore[assignment]
        draining = _DRAINING.is_set()
        self._body_read = True
        self._send(
            503 if draining else 200,
            {
                "status": "draining" if draining else "ok",
                "policy": {"id": policy.id, "revision": policy.revision},
            },
        )

    def do_POST(self) -> None:
        handler = self._chat if self.path.rstrip("/") == "/v1/chat/completions" else None
        self._handle(handler)

    def _handle(self, handler: Callable[[str], tuple[int, Any, str]] | None) -> None:
        started = time.monotonic()
        user, status, note = "-", 500, ""
        self._body_read = self.command == "GET"  # per request: connections are reused
        request_id = self.headers.get("X-Request-ID", "")
        self._request_id = request_id if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", request_id) else ""
        with _IN_FLIGHT_LOCK:
            _IN_FLIGHT[0] += 1
        try:
            user = self._authenticate()
            if handler is None:
                raise _ProxyError(404, "not_found", f"Unknown path {self.path}.")
            status, payload, note = handler(user)
            self._send(status, payload)
        except _ProxyError as e:
            status, note = e.status, e.code
            self._send(e.status, _error(e.code, e.message))
        except Exception as e:  # fail closed: never forward after an error
            status, note = 500, "credgate_error"
            self._send(
                500, _error("credgate_error", f"credgate could not process the request: {e}")
            )
        finally:
            ms = round(1000 * (time.monotonic() - started))
            # Never the request or answer text: who, where, outcome.
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            rid = f" request-id={self._request_id}" if self._request_id else ""
            self.log(f"{stamp} {user} {self.command} {self.path} {status} {note} {ms}ms{rid}")
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT[0] -= 1

    def _authenticate(self) -> str:
        users = self.config._users
        if not users:
            return _os_user()
        header = self.headers.get("Authorization", "")
        key = header[7:].strip() if header.lower().startswith("bearer ") else ""
        digest = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
        for name, stored in users.items():
            if hmac.compare_digest(digest, stored):
                return name
        raise _ProxyError(401, "unauthorized", "A valid credgate proxy key is required.")

    def _models(self, user: str) -> tuple[int, Any, str]:
        policy: Policy = self.config.policy  # type: ignore[assignment]
        data = []
        for name, dest in policy.destinations.items():
            if dest.blocked or not dest.url:
                continue
            try:
                upstream = _upstream_json("GET", dest.url.rstrip("/") + "/models", None, name, 10)
                ids = [m["id"] for m in upstream.get("data", []) if "id" in m]
            except Exception:  # an endpoint that is down is just not listed
                ids = []
            data += [{"id": f"{name}/{i}", "object": "model", "owned_by": name} for i in ids]
        return 200, {"object": "list", "data": data}, ""

    def _chat(self, user: str) -> tuple[int, Any, str]:
        body = self._read_json()
        model = body.get("model")
        if not isinstance(model, str) or "/" not in model:
            raise _ProxyError(
                400,
                "invalid_model",
                'Ask for a model as "<endpoint>/<model>", e.g. "vllm-gpu/llama-3.1-70b".',
            )
        destination, _, upstream_model = model.partition("/")
        if not destination or not upstream_model:
            raise _ProxyError(400, "invalid_model", 'Ask for a model as "<endpoint>/<model>".')
        policy: Policy = self.config.policy  # type: ignore[assignment]
        dest = policy.destinations.get(destination)
        if dest is None:
            raise _ProxyError(
                404, "unknown_endpoint", f"Endpoint {destination!r} is not in the policy."
            )
        if not dest.url and not dest.blocked:
            raise _ProxyError(
                502, "no_endpoint_url", f"Endpoint {destination!r} has no `url` in the policy."
            )

        slots = _text_slots(body)
        vault = Vault(self.config.token_key)
        audit = AuditLog(self.config.audit, key=self.config.audit_key, actor=user)
        with _CPU:
            decision = policy.apply(
                [get() for get, _ in slots], destination, vault=vault, audit=audit
            )
        if not decision.allowed:
            raise _ProxyError(
                403,
                "policy_blocked",
                f"Blocked by policy {policy.id} (revision {policy.revision}): "
                + ", ".join(decision.blocked_by),
            )
        for (_, set_), text in zip(slots, decision.texts or [], strict=True):
            set_(text)

        stream = bool(body.pop("stream", False))
        body.pop("stream_options", None)
        body["model"] = upstream_model
        answer = _upstream_json(
            "POST",
            dest.url.rstrip("/") + "/chat/completions",
            body,
            destination,
            self.config.timeout,
        )
        for choice in answer.get("choices", []):
            message = choice.get("message") or {}
            # Values go back into the text for the user, never into tool calls.
            if isinstance(message.get("content"), str):
                message["content"] = restore(message["content"], vault)
        answer["model"] = model
        if stream:
            return 200, _as_stream(answer), "stream"
        return 200, answer, ""

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding"):
            raise _ProxyError(411, "length_required", "Send the body with a Content-Length.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise _ProxyError(400, "invalid_request", "Invalid Content-Length.") from None
        if length <= 0 or length > MAX_BODY:
            raise _ProxyError(
                413 if length > MAX_BODY else 400, "invalid_request", "Missing or too large body."
            )
        raw = self.rfile.read(length)
        self._body_read = True
        if len(raw) < length:
            raise _ProxyError(
                400, "invalid_request", "The body is shorter than its Content-Length."
            )
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
            raise _ProxyError(400, "invalid_json", f"The body is not valid JSON: {e}") from None
        if not isinstance(body, dict):
            raise _ProxyError(400, "invalid_json", "The body must be a JSON object.")
        return body

    def _send(self, status: int, payload: Any) -> None:
        if isinstance(payload, _Stream):
            data = payload.data
            content_type = "text/event-stream"
        else:
            data = json.dumps(payload).encode()
            content_type = "application/json"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if getattr(self, "_request_id", ""):
            self.send_header("X-Request-ID", self._request_id)
        if status >= 400 or not self._body_read:
            # Never read leftover bytes of a rejected request as a new one.
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # our own log line instead, without the request text


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


# Values that must reach the endpoint exactly as sent: they name things or
# set behaviour, and never carry free text.
_STRUCTURAL = {
    "model",
    "role",
    "type",
    "id",
    "tool_call_id",
    "object",
    "finish_reason",
    "format",
    "detail",
    "service_tier",
    "reasoning_effort",
    "voice",
    "modalities",
    "parallel_tool_calls",
    "strict",
}
# Numeric settings, which are never personal data.
_NUMERIC = {
    "temperature",
    "top_p",
    "n",
    "max_tokens",
    "max_completion_tokens",
    "presence_penalty",
    "frequency_penalty",
    "seed",
    "top_logprobs",
    "logprobs",
    "top_k",
    "min_p",
    "repetition_penalty",
}
# Content parts credgate cannot check are refused, not forwarded.
_TEXT_PARTS = {"text"}
_MAX_DEPTH = 64


def _text_slots(body: dict[str, Any]) -> list[tuple[Callable[[], str], Callable[[str], None]]]:
    """Every value in the request that could carry personal data, as (get, set)
    pairs: all strings - message contents, tool results and arguments, names,
    metadata, stop sequences, any field the proxy does not know - except
    structural ones, and whole numbers of 6 digits or more (an Aadhaar number
    can be sent as a number). Field names with personal data, and content
    credgate cannot check (images, audio, files), are refused."""
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise _ProxyError(400, "invalid_request", "`messages` must be a non-empty list.")
    for message in messages:
        if not isinstance(message, dict):
            raise _ProxyError(400, "invalid_request", "Each message must be an object.")
        content = message.get("content")
        if content is not None and not isinstance(content, (str, list)):
            raise _ProxyError(
                400, "unsupported_content", "Message content must be text or a list of parts."
            )
        for part in content if isinstance(content, list) else []:
            if not (
                isinstance(part, dict)
                and part.get("type") in _TEXT_PARTS
                and isinstance(part.get("text"), str)
            ):
                kind = part.get("type") if isinstance(part, dict) else type(part).__name__
                raise _ProxyError(
                    400,
                    "unsupported_content",
                    f"Content of type {kind!r} cannot be checked for personal data; not sent.",
                )
    modalities = body.get("modalities")
    if isinstance(modalities, list) and "audio" in modalities:
        raise _ProxyError(400, "unsupported_content", "Audio cannot be checked, so it is not sent.")

    slots: list[tuple[Callable[[], str], Callable[[str], None]]] = []
    keys: list[str] = []

    def walk(obj: Any, key: str | None, parent: str | None, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise _ProxyError(400, "invalid_request", "The request is nested too deeply.")
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append(k)
                if k == "logit_bias" or (k == "name" and key == "function"):
                    continue  # token ids; function names must stay exact
                if k in _STRUCTURAL and not isinstance(v, (dict, list)):
                    continue
                if isinstance(v, str):
                    slots.append(
                        (lambda o=obj, k=k: o[k], lambda t, o=obj, k=k: o.__setitem__(k, t))
                    )
                elif _number_like(v) and k not in _NUMERIC:
                    slots.append((lambda o=obj, k=k: str(o[k]), _number_setter(obj, k)))
                else:
                    walk(v, k, key, depth + 1)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                if isinstance(v, str) and key not in _STRUCTURAL:
                    slots.append(
                        (lambda o=obj, i=i: o[i], lambda t, o=obj, i=i: o.__setitem__(i, t))
                    )
                elif _number_like(v) and key not in _NUMERIC:
                    slots.append((lambda o=obj, i=i: str(o[i]), _number_setter(obj, i)))
                else:
                    walk(v, key, parent, depth + 1)

    walk(body, None, None, 0)
    from .detect import detect_pii

    if detect_pii(keys):
        raise _ProxyError(
            400,
            "personal_data_in_field_name",
            "A field name contains personal data; it is not sent.",
        )
    return slots


def _number_like(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and abs(v) >= 100_000


def _number_setter(obj: Any, k: Any) -> Callable[[str], None]:
    def set_(text: str) -> None:
        if text != str(obj[k]):  # redacted or tokenised: the number becomes text
            obj[k] = text

    return set_


def _upstream_json(method: str, url: str, body: Any, destination: str, timeout: float) -> Any:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    env = "CREDGATE_UPSTREAM_KEY_" + re.sub(r"[^A-Z0-9]", "_", destination.upper())
    if os.environ.get(env):
        headers["Authorization"] = f"Bearer {os.environ[env]}"
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read(MAX_ANSWER + 1)
            if len(raw) > MAX_ANSWER:
                raise _ProxyError(
                    502, "endpoint_error", f"Endpoint {destination!r} answered too much."
                )
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            raise _ProxyError(
                502,
                "endpoint_redirect",
                f"Endpoint {destination!r} redirected to {e.headers.get('Location')!r}; "
                "the proxy does not follow redirects (set the final URL in the policy).",
            ) from None
        detail = e.read()[:2000].decode("utf-8", "replace")
        raise _ProxyError(
            e.code if 400 <= e.code < 600 else 502,
            "endpoint_error",
            f"Endpoint {destination!r} answered {e.code}: {detail}",
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise _ProxyError(
            502, "endpoint_unreachable", f"Endpoint {destination!r} unreachable: {e}"
        ) from None
    except json.JSONDecodeError:
        raise _ProxyError(
            502, "endpoint_error", f"Endpoint {destination!r} did not answer JSON."
        ) from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Requests go only to the URL in the policy, never where a redirect points."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# Only HTTP(S) and no redirects; proxies from the environment (HTTPS_PROXY,
# NO_PROXY) are honoured, as an organisation's egress may need them.
_OPENER = urllib.request.build_opener(_NoRedirect())


@dataclass
class _Stream:
    data: bytes


def _as_stream(answer: dict[str, Any]) -> _Stream:
    """The complete answer as server-sent events, as streaming clients expect."""
    base = {k: answer.get(k) for k in ("id", "created", "model")} | {
        "object": "chat.completion.chunk"
    }
    events = []
    for choice in answer.get("choices", []):
        message = choice.get("message") or {}
        delta = {k: message[k] for k in ("role", "content", "tool_calls") if k in message}
        events.append(base | {"choices": [{"index": choice.get("index", 0), "delta": delta}]})
        events.append(
            base
            | {
                "choices": [
                    {
                        "index": choice.get("index", 0),
                        "delta": {},
                        "finish_reason": choice.get("finish_reason"),
                    }
                ]
            }
        )
    if "usage" in answer:
        events.append(base | {"choices": [], "usage": answer["usage"]})
    lines = [f"data: {json.dumps(e)}\n\n" for e in events] + ["data: [DONE]\n\n"]
    return _Stream("".join(lines).encode())


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": code, "code": code}}
