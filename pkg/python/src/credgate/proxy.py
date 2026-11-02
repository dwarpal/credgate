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

Three APIs, each forwarded to an endpoint that speaks the same API:

- **OpenAI** chat completions: ``POST /v1/chat/completions``,
  ``GET /v1/models``. Forwarded to ``<url>/chat/completions``.
- **Anthropic** messages: ``POST /v1/messages`` and
  ``/v1/messages/count_tokens`` (Claude Code, the Anthropic SDKs).
  Forwarded to ``<url>/messages``, with the endpoint's key as ``x-api-key``.
- **Ollama**: ``POST /api/chat``, ``/api/generate``, ``/api/show`` and
  ``GET /api/tags``, ``/api/version`` (Ollama clients, VS Code Copilot Chat
  with Ollama models). Forwarded to the endpoint's URL without its ``/v1``.

Answers stream as the model writes them (``"stream": true``; Ollama streams
unless told not to). Tokens are put back as they arrive: a piece of text that
could still be the start of a token is held back until it is complete.

Two servers:

- **standard** (default): the Python standard library only - nothing to
  install, for one person on their own machine.
- **uvicorn** (``server="uvicorn"``; ``pip install 'credgate[server]'``): a
  production HTTP server (BSD-3-licensed) for a shared proxy: keep-alive,
  a limit on requests in progress (``concurrency``; more get ``503``), and a
  client that leaves is noticed even while the model is still thinking.

Both run the same code for everything else - policy, audit, streaming - and
the same tests.
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
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
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
        audit_rotate: Start a new audit file each month (see
            :class:`~credgate.AuditLog`).
        audit_retention_years: Remove monthly audit files older than this
            (at least 1; 0 keeps them all), at start and once a day.
        default_endpoint: The endpoint for models asked for without one (no
            ``<endpoint>/``), e.g. ``claude`` so that Claude Code works with
            its own model names.
        server: ``"standard"`` (the Python standard library) or ``"uvicorn"``
            (production HTTP server; needs ``credgate[server]``).
        concurrency: With uvicorn, the requests one worker handles at once;
            more are answered ``503`` so a load balancer can try elsewhere.
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
    audit_rotate: bool = True
    audit_retention_years: int = 5
    default_endpoint: str | None = None
    server: str = "standard"
    concurrency: int = 256
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
        if self.audit_retention_years and self.audit_retention_years < 1:
            raise ValueError(
                "`audit_retention_years` must be at least 1 (or 0 to keep everything)."
            )
        if self.server not in ("standard", "uvicorn"):
            raise ValueError('`server` must be "standard" or "uvicorn".')
        if self.server == "uvicorn":
            try:
                import uvicorn  # noqa: F401
            except ImportError:
                raise ValueError(
                    "The uvicorn server needs uvicorn: pip install 'credgate[server]'."
                ) from None
        if not 1 <= self.concurrency <= 100_000:
            raise ValueError("`concurrency` must be between 1 and 100000.")
        if not 1 <= self.workers <= 64:
            raise ValueError("`workers` must be between 1 and 64.")
        if self.workers > 1 and not hasattr(os, "fork"):
            raise ValueError("Several workers need fork (Linux, macOS); run one per port instead.")
        if (self.certfile is None) != (self.keyfile is None):
            raise ValueError("`certfile` and `keyfile` go together.")
        if self.token_key is None:
            self.token_key = os.environ.get("CREDGATE_TOKEN_KEY") or secrets.token_bytes(32)
        Vault(self.token_key)  # validates the key now, not on the first request
        if self.default_endpoint and self.default_endpoint not in self.policy.destinations:
            raise ValueError(f"Default endpoint {self.default_endpoint!r} is not in the policy.")
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
        f"credgate proxy ({mode} mode, {config.server} server, {config.workers} worker(s)) "
        f"on {scheme}://{host}:{port}/v1"
        f" - policy {config.policy.id} revision {config.policy.revision}, audit log {config.audit}"
    )
    # Workers share the listening socket; each request is self-contained, and
    # the audit log takes concurrent writers.
    parent = os.getpid()
    children: list[int] = []
    uvicorn = config.server == "uvicorn"
    for _ in range(config.workers - 1):
        pid = os.fork()
        if pid == 0:
            if not uvicorn:  # uvicorn handles its signals (and the drain) itself
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, lambda *_: _drain(server, config.drain_seconds))
            threading.Thread(target=_exit_with_parent, args=(parent,), daemon=True).start()
            try:
                server.serve_forever()
                if not uvicorn:
                    _wait_for_requests(config.timeout)
            finally:
                os._exit(0)
        children.append(pid)

    if config.audit_rotate and config.audit_retention_years:
        threading.Thread(target=_retention, args=(config, log or _stderr), daemon=True).start()

    if uvicorn:
        # Signals reach the main process; each worker drains on its own.
        server.server.on_signal = lambda sig: [_signal(pid, sig) for pid in children]
        try:
            server.serve_forever()
        finally:
            for pid in children:
                with contextlib.suppress(OSError):
                    os.waitpid(pid, 0)
            server.server_close()
        return

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


def _retention(config: ProxyConfig, log: Callable[[str], Any]) -> None:
    """Remove audit files past the retention period, at start and daily (in
    the main process only, so two never prune at once)."""
    from .audit import audit_prune

    while True:
        try:
            removed = audit_prune(config.audit, keep_years=config.audit_retention_years)
            if removed:
                log(
                    f"credgate proxy: audit files past {config.audit_retention_years} years "
                    "removed: " + ", ".join(removed)
                )
        except Exception as e:  # never stop serving over retention; say so
            log(f"credgate proxy: audit retention not applied: {e}")
        time.sleep(24 * 3600)


def _exit_with_parent(parent: int) -> None:
    """A worker stops when the main process is gone, even if it was killed."""
    while os.getppid() == parent:
        time.sleep(1)
    os._exit(0)


def make_server(config: ProxyConfig, log: Callable[[str], Any] | None = None) -> Any:
    """The proxy's HTTP server, not yet serving (port 0 picks a free port):
    ``serve_forever()`` runs it, ``shutdown()`` stops it."""
    if config.server == "uvicorn":
        from ._proxy_asgi import UvicornServer

        return UvicornServer(config, log or _stderr)
    attrs = {"config": config, "log": staticmethod(log or _stderr)}
    handler = type("CredgateProxyHandler", (_Handler,), attrs)
    server = _Server((config.host, config.port), handler)
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


class _Server(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        if isinstance(sys.exc_info()[1], ConnectionError):
            return  # a client that went away is not an error worth a traceback
        super().handle_error(request, client_address)


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
    def __init__(self, status: int, code: str, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.detail = detail  # for the proxy's log: a name, never request text


class _ClientGone(Exception):
    """The client closed the connection while the answer was streaming."""


class _Exchange:
    """One request, whichever server received it: who sent it, where it goes,
    what the policy does with it, and the answer - JSON, or pieces to stream.
    ``read_body`` returns the request body (raising :class:`_ProxyError` if it
    is missing or too large); it is called only once the client is known."""

    def __init__(
        self,
        config: ProxyConfig,
        method: str,
        path: str,
        headers: Any,
        read_body: Callable[[], bytes],
    ) -> None:
        self.config = config
        self.command = method
        self.path = path
        self.headers = headers
        self._read_body = read_body
        self._note = ""
        route = path.split("?", 1)[0].rstrip("/")
        self._route_path = route
        self._api = (
            "anthropic"
            if route.startswith("/v1/messages")
            else "ollama"
            if route.startswith("/api/")
            else "openai"
        )
        request_id = headers.get("X-Request-ID", "") or ""
        self.request_id = request_id if re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", request_id) else ""

    def run(self) -> tuple[str, int, Any, str]:
        """(user, status, payload, note); never raises: errors are answers."""
        if self._route_path in ("/healthz", "/v1/healthz") and self.command == "GET":
            return "-", *self._health()
        routes: dict[str, Callable[[str], tuple[int, Any, str]]] = (
            {
                "/v1/models": self._models,
                "/api/tags": self._ollama_tags,
                "/api/version": self._ollama_version,
            }
            if self.command == "GET"
            else {
                "/v1/chat/completions": self._chat,
                "/v1/messages": lambda user: self._messages(user, "/messages"),
                "/v1/messages/count_tokens": lambda user: self._messages(
                    user, "/messages/count_tokens"
                ),
                "/api/chat": lambda user: self._ollama(user, "chat"),
                "/api/generate": lambda user: self._ollama(user, "generate"),
                "/api/show": self._ollama_show,
            }
            if self.command == "POST"
            else {}
        )
        user = "-"
        try:
            user = self._authenticate()
            handler = routes.get(self._route_path)
            if handler is None:
                raise _ProxyError(404, "not_found", f"Unknown path {self.path}.")
            status, payload, note = handler(user)
            return user, status, payload, note
        except _ProxyError as e:
            note = e.code + (f"({e.detail})" if e.detail else "")
            return user, e.status, _error(self._api, e.code, e.message), note
        except Exception as e:  # fail closed: never forward after an error
            message = f"credgate could not process the request: {e}"
            return user, 500, _error(self._api, "credgate_error", message), "credgate_error"

    def _health(self) -> tuple[int, Any, str]:
        """For load balancers: no key needed, nothing sensitive."""
        policy: Policy = self.config.policy  # type: ignore[assignment]
        draining = _DRAINING.is_set()
        payload = {
            "status": "draining" if draining else "ok",
            "policy": {"id": policy.id, "revision": policy.revision},
        }
        return 503 if draining else 200, payload, ""

    def pieces(self, live: _Live) -> Iterator[bytes]:
        """A streamed answer's pieces. Once the first byte is sent the status
        cannot change: an error that comes later ends the stream with an error
        event in the API's own format (and is noted for the log)."""
        sent = 0
        try:
            for piece in live.pieces:
                sent += len(piece)
                if sent > MAX_ANSWER:
                    raise _ProxyError(502, "endpoint_error", "The endpoint answered too much.")
                yield piece
        except GeneratorExit:
            raise
        except _ProxyError as e:
            self._note = e.code
            yield _stream_error(self._api, e.code, e.message)
        except (TimeoutError, OSError) as e:  # reading from the endpoint
            self._note = "endpoint_unreachable"
            yield _stream_error(
                self._api, "endpoint_unreachable", f"The endpoint stopped answering: {e}"
            )
        except Exception as e:  # an answer credgate cannot read: end it, never pass it on
            self._note = "endpoint_error"
            yield _stream_error(
                self._api, "endpoint_error", f"The endpoint's answer could not be read: {e}"
            )

    def _authenticate(self) -> str:
        users = self.config._users
        if not users:
            return _os_user()
        # Bearer (OpenAI, Ollama clients) or x-api-key (Anthropic clients).
        header = self.headers.get("Authorization", "")
        key = header[7:].strip() if header.lower().startswith("bearer ") else ""
        key = key or self.headers.get("x-api-key", "").strip()
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

    # --- requests: route, govern, forward --------------------------------------

    def _route(self, model: Any) -> tuple[str, Any, str]:
        """The policy endpoint and the endpoint's own model name."""
        default = self.config.default_endpoint
        if default and isinstance(model, str) and model and "/" not in model:
            model = f"{default}/{model}"
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
        return destination, dest, upstream_model

    def _credentials(self, destination: str) -> dict[str, str]:
        """In localhost mode, when the proxy holds no key for the endpoint, the
        client's own key goes on: it is the user's (e.g. Claude Code signed in
        to their account). Never in shared mode, where the client's key is
        its credgate key."""
        if self.config._users or os.environ.get(_key_env(destination)):
            return {}
        return {h: self.headers[h] for h in ("Authorization", "x-api-key") if self.headers.get(h)}

    def _govern(self, user: str, slots: list[Any], destination: str) -> Vault:
        """Apply the policy to every slot, in place; raises if blocked."""
        policy: Policy = self.config.policy  # type: ignore[assignment]
        vault = Vault(self.config.token_key)
        audit = AuditLog(
            self.config.audit,
            key=self.config.audit_key,
            actor=user,
            rotate=self.config.audit_rotate,
        )
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
        return vault

    def _chat(self, user: str) -> tuple[int, Any, str]:
        body = self._read_json()
        model = body.get("model")
        destination, dest, upstream_model = self._route(model)
        vault = self._govern(user, _openai_slots(body), destination)

        body["model"] = upstream_model
        creds = self._credentials(destination)
        url = dest.url.rstrip("/") + "/chat/completions"
        if body.get("stream"):
            response = _upstream_open(
                "POST", url, body, destination, self.config.timeout, "openai", creds
            )
            return (
                200,
                _Live("text/event-stream", _openai_stream(response, vault, model), response),
                "stream",
            )
        answer = _upstream_json(
            "POST", url, body, destination, self.config.timeout, "openai", creds
        )
        for choice in answer.get("choices", []):
            message = choice.get("message") or {}
            # Values go back into the text for the user, never into tool calls.
            if isinstance(message.get("content"), str):
                message["content"] = restore(message["content"], vault)
        answer["model"] = model
        return 200, answer, ""

    def _messages(self, user: str, path: str) -> tuple[int, Any, str]:
        body = self._read_json()
        model = body.get("model")
        destination, dest, upstream_model = self._route(model)
        vault = self._govern(user, _anthropic_slots(body), destination)

        body["model"] = upstream_model
        url = dest.url.rstrip("/") + path
        headers = {
            "anthropic-version": self.headers.get("anthropic-version") or "2023-06-01",
        } | self._credentials(destination)
        if self.headers.get("anthropic-beta"):
            headers["anthropic-beta"] = self.headers["anthropic-beta"]
        if body.get("stream"):
            response = _upstream_open(
                "POST", url, body, destination, self.config.timeout, "anthropic", headers
            )
            return (
                200,
                _Live("text/event-stream", _anthropic_stream(response, vault, model), response),
                "stream",
            )
        answer = _upstream_json(
            "POST", url, body, destination, self.config.timeout, "anthropic", headers
        )
        for block in answer.get("content", []) if isinstance(answer, dict) else []:
            if (
                isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
            ):
                block["text"] = restore(block["text"], vault)
        if isinstance(answer, dict) and "model" in answer:
            answer["model"] = model
        return 200, answer, ""

    def _ollama(self, user: str, kind: str) -> tuple[int, Any, str]:
        body = self._read_json()
        model = body.get("model")
        destination, dest, upstream_model = self._route(model)
        vault = self._govern(user, _ollama_slots(body, kind), destination)

        body["model"] = upstream_model
        creds = self._credentials(destination)
        url = _ollama_base(dest.url) + "/api/" + kind
        field = "response" if kind == "generate" else None
        if body.get("stream", True):  # Ollama streams unless told not to
            body["stream"] = True
            response = _upstream_open(
                "POST", url, body, destination, self.config.timeout, "openai", creds
            )
            return (
                200,
                _Live(
                    "application/x-ndjson", _ollama_stream(response, vault, model, field), response
                ),
                "stream",
            )
        answer = _upstream_json(
            "POST", url, body, destination, self.config.timeout, "openai", creds
        )
        if isinstance(answer, dict):
            text = _ollama_text(answer, field)
            if text is not None:
                _ollama_set(answer, field, restore(text, vault))
            answer["model"] = model
        return 200, answer, ""

    def _ollama_show(self, user: str) -> tuple[int, Any, str]:
        """Model details (context length, capabilities): no request text."""
        body = self._read_json()
        destination, dest, upstream_model = self._route(body.get("model") or body.get("name"))
        if dest.blocked:
            raise _ProxyError(403, "policy_blocked", f"Endpoint {destination!r} is blocked.")
        answer = _upstream_json(
            "POST",
            _ollama_base(dest.url) + "/api/show",
            {"model": upstream_model},
            destination,
            30,
            "openai",
            self._credentials(destination),
        )
        return 200, answer, ""

    def _ollama_tags(self, user: str) -> tuple[int, Any, str]:
        policy: Policy = self.config.policy  # type: ignore[assignment]
        models = []
        for name, dest in policy.destinations.items():
            if dest.blocked or not dest.url:
                continue
            try:
                upstream = _upstream_json(
                    "GET", _ollama_base(dest.url) + "/api/tags", None, name, 10
                )
                found = [m for m in upstream.get("models", []) if isinstance(m, dict)]
            except Exception:  # not an Ollama server, or down: not listed
                found = []
            for m in found:
                m = dict(m)
                for k in ("name", "model"):
                    if isinstance(m.get(k), str):
                        m[k] = f"{name}/{m[k]}"
                models.append(m)
        return 200, {"models": models}, ""

    def _ollama_version(self, user: str) -> tuple[int, Any, str]:
        policy: Policy = self.config.policy  # type: ignore[assignment]
        for name, dest in policy.destinations.items():
            if dest.blocked or not dest.url:
                continue
            try:
                return (
                    200,
                    _upstream_json("GET", _ollama_base(dest.url) + "/api/version", None, name, 5),
                    "",
                )
            except Exception:
                continue
        raise _ProxyError(502, "endpoint_unreachable", "No Ollama endpoint answered.")

    def _read_json(self) -> dict[str, Any]:
        raw = self._read_body()
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
            raise _ProxyError(400, "invalid_json", f"The body is not valid JSON: {e}") from None
        if not isinstance(body, dict):
            raise _ProxyError(400, "invalid_json", "The body must be a JSON object.")
        return body


def _log_line(
    user: str, method: str, path: str, status: int, note: str, started: float, request_id: str
) -> str:
    """The proxy's own log line: who, where, outcome - never the text."""
    ms = round(1000 * (time.monotonic() - started))
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    rid = f" request-id={request_id}" if request_id else ""
    return f"{stamp} {user} {method} {path} {status} {note} {ms}ms{rid}"


class _Handler(BaseHTTPRequestHandler):
    """The standard-library server's side of an exchange."""

    config: ProxyConfig
    log: Callable[[str], Any]
    protocol_version = "HTTP/1.1"
    server_version = "credgate-proxy"
    timeout = 120  # seconds a client may take to send its request

    def do_GET(self) -> None:
        self._serve()

    def do_POST(self) -> None:
        self._serve()

    def _serve(self) -> None:
        started = time.monotonic()
        self._body_read = self.command == "GET"  # per request: connections are reused
        exchange = _Exchange(self.config, self.command, self.path, self.headers, self._read_raw)
        self._request_id = exchange.request_id
        with _IN_FLIGHT_LOCK:
            _IN_FLIGHT[0] += 1
        user, status, note = "-", 500, ""
        try:
            user, status, payload, note = exchange.run()
            if isinstance(payload, _Live):
                note = self._send_live(exchange, payload) or note
            else:
                self._send(status, payload)
        finally:
            self.log(
                _log_line(user, self.command, self.path, status, note, started, exchange.request_id)
            )
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT[0] -= 1

    def _read_raw(self) -> bytes:
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
        return raw

    def _send(self, status: int, payload: Any) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._common_headers(status)
        self.end_headers()
        self.wfile.write(data)

    def _common_headers(self, status: int) -> None:
        self.send_header("Cache-Control", "no-store")
        if getattr(self, "_request_id", ""):
            self.send_header("X-Request-ID", self._request_id)
        if status >= 400 or not self._body_read:
            # Never read leftover bytes of a rejected request as a new one.
            self.send_header("Connection", "close")
            self.close_connection = True

    def _send_live(self, exchange: _Exchange, live: _Live) -> str:
        """Pieces of the answer as they arrive, in chunked encoding; returns
        the note for the log."""
        self.send_response(200)
        self.send_header("Content-Type", live.content_type)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Accel-Buffering", "no")  # nginx: pass pieces on at once
        self._common_headers(200)
        self.end_headers()
        try:
            for piece in exchange.pieces(live):
                self._chunk(piece)
            self._chunk(b"", last=True)
        except _ClientGone:
            self.close_connection = True
            return "client_closed"  # the client went away: stop reading the endpoint
        finally:
            live.close()
        return exchange._note

    def _chunk(self, data: bytes, last: bool = False) -> None:
        try:
            if data:
                self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
            if last:
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except OSError as e:
            raise _ClientGone from e

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
    "tool_use_id",
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
    "signature",  # Anthropic thinking blocks: checked by the provider, opaque
    "keep_alive",
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
    "budget_tokens",
    "num_ctx",
    "num_predict",
    "num_batch",
    "num_keep",
    "num_gpu",
    "num_thread",
}
# Content parts credgate cannot check are refused, not forwarded.
_TEXT_PARTS = {"text"}
# Anthropic content blocks that carry only text (or values walked below);
# images, documents and anything new are refused.
_ANTHROPIC_BLOCKS = {"text", "tool_use", "tool_result", "thinking", "redacted_thinking"}
_MAX_DEPTH = 64

_Slots = list[tuple[Callable[[], str], Callable[[str], None]]]


def _refuse(kind: Any) -> _ProxyError:
    name = re.sub(r"[^A-Za-z0-9_.-]", "?", str(kind))[:40]
    return _ProxyError(
        400,
        "unsupported_content",
        f"Content of type {kind!r} cannot be checked for personal data; not sent.",
        name,
    )


def _openai_slots(body: dict[str, Any]) -> _Slots:
    """The values of an OpenAI chat request that could carry personal data."""
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
                raise _refuse(part.get("type") if isinstance(part, dict) else type(part).__name__)
    modalities = body.get("modalities")
    if isinstance(modalities, list) and "audio" in modalities:
        raise _ProxyError(400, "unsupported_content", "Audio cannot be checked, so it is not sent.")
    return _slots(body)


def _anthropic_slots(body: dict[str, Any]) -> _Slots:
    """The values of an Anthropic messages request that could carry personal
    data: the system prompt, every text, tool input and tool result."""
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise _ProxyError(400, "invalid_request", "`messages` must be a non-empty list.")

    def check(blocks: Any) -> None:
        if blocks is None or isinstance(blocks, str):
            return
        if not isinstance(blocks, list):
            raise _ProxyError(
                400, "unsupported_content", "Content must be text or a list of blocks."
            )
        for block in blocks:
            if not isinstance(block, dict) or block.get("type") not in _ANTHROPIC_BLOCKS:
                raise _refuse(
                    block.get("type") if isinstance(block, dict) else type(block).__name__
                )
            if block["type"] == "tool_result":
                check(block.get("content"))

    for message in messages:
        if not isinstance(message, dict):
            raise _ProxyError(400, "invalid_request", "Each message must be an object.")
        check(message.get("content"))
    check(body.get("system"))
    return _slots(body)


def _ollama_slots(body: dict[str, Any], kind: str) -> _Slots:
    """The values of an Ollama chat or generate request that could carry
    personal data. Images cannot be checked and are refused."""
    if kind == "chat":
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise _ProxyError(400, "invalid_request", "`messages` must be a non-empty list.")
        for message in messages:
            if not isinstance(message, dict):
                raise _ProxyError(400, "invalid_request", "Each message must be an object.")
            if message.get("images"):
                raise _refuse("image")
            if message.get("content") is not None and not isinstance(message["content"], str):
                raise _ProxyError(400, "unsupported_content", "Message content must be text.")
    else:
        if not isinstance(body.get("prompt", ""), str):
            raise _ProxyError(400, "invalid_request", "`prompt` must be text.")
        if body.get("images"):
            raise _refuse("image")
    return _slots(body)


def _slots(body: dict[str, Any]) -> _Slots:
    """Every value in the request that could carry personal data, as (get, set)
    pairs: all strings - message contents, tool results and arguments, names,
    metadata, stop sequences, any field the proxy does not know - except
    structural ones, and whole numbers of 6 digits or more (an Aadhaar number
    can be sent as a number). Field names with personal data are refused."""
    slots: _Slots = []
    keys: list[str] = []

    def walk(obj: Any, key: str | None, parent: str | None, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise _ProxyError(400, "invalid_request", "The request is nested too deeply.")
        if isinstance(obj, dict):
            kind = obj.get("type")
            for k, v in obj.items():
                keys.append(k)
                if k in ("logit_bias", "context"):
                    continue  # token ids (OpenAI logit_bias, Ollama context)
                if k == "name" and (
                    key in ("function", "tools", "tool_choice")
                    or kind in ("tool_use", "tool", "server_tool_use")
                ):
                    continue  # tool and function names must stay exact
                if k == "data" and kind == "redacted_thinking":
                    continue  # encrypted by the provider, readable by no one
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


def _key_env(destination: str) -> str:
    """The environment variable with the proxy's key for an endpoint."""
    return "CREDGATE_UPSTREAM_KEY_" + re.sub(r"[^A-Z0-9]", "_", destination.upper())


def _ollama_base(url: str) -> str:
    """Ollama's own API lives beside its OpenAI-compatible one (``/v1``)."""
    url = url.rstrip("/")
    return url[:-3] if url.endswith("/v1") else url


def _upstream_request(
    method: str,
    url: str,
    body: Any,
    destination: str,
    api: str,
    headers: dict[str, str] | None,
) -> urllib.request.Request:
    all_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    env = _key_env(destination)
    if os.environ.get(env):
        if api == "anthropic":
            all_headers["x-api-key"] = os.environ[env]
        else:
            all_headers["Authorization"] = f"Bearer {os.environ[env]}"
    all_headers |= headers or {}
    data = None if body is None else json.dumps(body).encode()
    return urllib.request.Request(url, data=data, headers=all_headers, method=method)


def _upstream_open(
    method: str,
    url: str,
    body: Any,
    destination: str,
    timeout: float,
    api: str = "openai",
    headers: dict[str, str] | None = None,
) -> Any:
    """The endpoint's response, open for reading as it arrives. Errors before
    the answer starts (refused, unreachable) are raised here, before the client
    gets anything."""
    request = _upstream_request(method, url, body, destination, api, headers)
    try:
        return _OPENER.open(request, timeout=timeout)
    except urllib.error.HTTPError as e:
        raise _endpoint_error(e, destination) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise _ProxyError(
            502, "endpoint_unreachable", f"Endpoint {destination!r} unreachable: {e}"
        ) from None


def _upstream_json(
    method: str,
    url: str,
    body: Any,
    destination: str,
    timeout: float,
    api: str = "openai",
    headers: dict[str, str] | None = None,
) -> Any:
    response = _upstream_open(method, url, body, destination, timeout, api, headers)
    try:
        with response:
            raw = response.read(MAX_ANSWER + 1)
    except (TimeoutError, OSError) as e:
        raise _ProxyError(
            502, "endpoint_unreachable", f"Endpoint {destination!r} unreachable: {e}"
        ) from None
    if len(raw) > MAX_ANSWER:
        raise _ProxyError(502, "endpoint_error", f"Endpoint {destination!r} answered too much.")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise _ProxyError(
            502, "endpoint_error", f"Endpoint {destination!r} did not answer JSON."
        ) from None


def _endpoint_error(e: urllib.error.HTTPError, destination: str) -> _ProxyError:
    if 300 <= e.code < 400:
        return _ProxyError(
            502,
            "endpoint_redirect",
            f"Endpoint {destination!r} redirected to {e.headers.get('Location')!r}; "
            "the proxy does not follow redirects (set the final URL in the policy).",
        )
    detail = e.read()[:2000].decode("utf-8", "replace")
    return _ProxyError(
        e.code if 400 <= e.code < 600 else 502,
        "endpoint_error",
        f"Endpoint {destination!r} answered {e.code}: {detail}",
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Requests go only to the URL in the policy, never where a redirect points."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# Only HTTP(S) and no redirects; proxies from the environment (HTTPS_PROXY,
# NO_PROXY) are honoured, as an organisation's egress may need them.
_OPENER = urllib.request.build_opener(_NoRedirect())


# --- streaming ---------------------------------------------------------------


@dataclass
class _Live:
    """An answer sent on as it arrives: its pieces, and the endpoint response
    to close when the client is done (or gone)."""

    content_type: str
    pieces: Iterator[bytes]
    response: Any

    def close(self) -> None:
        # Shut the connection down first: a read blocked in another thread
        # wakes up at once (closing alone does not wake it on Linux).
        with contextlib.suppress(Exception):
            self.response.fp.raw._sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(Exception):
            self.response.close()


# The longest text that could still turn into a token: a type name and a
# 13-character key, with spaces inside the brackets. Longer runs are passed on.
_HOLD = 96
_WORD_TAIL = re.compile(r"\w*\Z")


class _Restorer:
    """Puts tokens back into text that arrives in pieces. The end of a piece
    that could be the start of a token (``[PAN_`` or ``PAN_rl``) is held back
    until the next piece shows whether it is one, so a token split across
    pieces is restored like any other."""

    def __init__(self, vault: Vault) -> None:
        self.vault = vault
        self.pending = ""
        self.before = ""  # the last character passed on: a token needs a boundary

    def feed(self, text: str) -> str:
        self.pending += text
        cut = len(self.pending)
        bracket = self.pending.rfind("[")
        if bracket >= 0 and "]" not in self.pending[bracket:] and cut - bracket <= _HOLD:
            cut = bracket
        tail = _WORD_TAIL.search(self.pending)
        if tail and cut - tail.start() <= _HOLD:
            cut = min(cut, tail.start())
        ready, self.pending = self.pending[:cut], self.pending[cut:]
        return self._restore(ready)

    def flush(self) -> str:
        ready, self.pending = self.pending, ""
        return self._restore(ready)

    def _restore(self, text: str) -> str:
        if not text:
            return ""
        if "_" not in text:  # every token has one: nothing to restore
            self.before = text[-1]
            return text
        out = restore(self.before + text, self.vault)[len(self.before) :]
        self.before = text[-1]
        return out


def _sse_events(response: Any) -> Iterator[tuple[str | None, str | None, bytes]]:
    """Server-sent events as (event name, data, raw bytes)."""
    lines: list[bytes] = []
    while True:
        line = response.readline(MAX_ANSWER)
        if not line:
            if lines:
                yield _sse_parse(lines)
            return
        if line in (b"\n", b"\r\n"):
            if lines:
                yield _sse_parse(lines)
                lines = []
            continue
        lines.append(line)


def _sse_parse(lines: list[bytes]) -> tuple[str | None, str | None, bytes]:
    event = data = None
    for line in lines:
        text = line.decode("utf-8", "replace").rstrip("\r\n")
        if text.startswith("event:"):
            event = text[6:].strip()
        elif text.startswith("data:"):
            piece = text[5:].lstrip(" ")
            data = piece if data is None else data + "\n" + piece
    return event, data, b"".join(lines) + b"\n"


def _sse(data: Any, event: str | None = None) -> bytes:
    head = f"event: {event}\n" if event else ""
    return f"{head}data: {json.dumps(data)}\n\n".encode()


def _openai_stream(response: Any, vault: Vault, model: str) -> Iterator[bytes]:
    restorers: dict[int, _Restorer] = {}
    last: dict[str, Any] = {}
    for _, data, raw in _sse_events(response):
        if data is None:
            yield raw  # comments, keep-alives
            continue
        if data.strip() == "[DONE]":
            break
        chunk = json.loads(data)
        if not isinstance(chunk, dict):
            continue
        if "model" in chunk:
            chunk["model"] = model
        last = {k: chunk[k] for k in ("id", "created", "model", "object") if k in chunk}
        for choice in chunk.get("choices") or []:
            r = restorers.setdefault(choice.get("index", 0), _Restorer(vault))
            delta = choice.get("delta") or {}
            text = r.feed(delta["content"]) if isinstance(delta.get("content"), str) else ""
            if choice.get("finish_reason"):
                text += r.flush()
            # Values go back into the text for the user, never into tool calls.
            if isinstance(delta.get("content"), str) or text:
                delta["content"] = text
                choice["delta"] = delta
        yield _sse(chunk)
    for index, r in restorers.items():
        rest = r.flush()
        if rest:
            yield _sse(last | {"choices": [{"index": index, "delta": {"content": rest}}]})
    yield b"data: [DONE]\n\n"


def _anthropic_stream(response: Any, vault: Vault, model: str) -> Iterator[bytes]:
    restorers: dict[int, _Restorer] = {}
    for event, data, raw in _sse_events(response):
        if data is None:
            yield raw
            continue
        message = json.loads(data)
        kind = message.get("type") if isinstance(message, dict) else None
        if kind == "message_start" and isinstance(message.get("message"), dict):
            message["message"]["model"] = model
        elif (
            kind == "content_block_delta"
            and (message.get("delta") or {}).get("type") == "text_delta"
        ):
            r = restorers.setdefault(message.get("index", 0), _Restorer(vault))
            message["delta"]["text"] = r.feed(message["delta"].get("text") or "")
        elif kind == "content_block_stop":
            r = restorers.pop(message.get("index", 0), None)
            rest = r.flush() if r else ""
            if rest:
                yield _sse(
                    {
                        "type": "content_block_delta",
                        "index": message.get("index", 0),
                        "delta": {"type": "text_delta", "text": rest},
                    },
                    "content_block_delta",
                )
        yield _sse(message, event or kind)


def _ollama_text(piece: dict[str, Any], field: str | None) -> str | None:
    """The answer text of an Ollama reply: ``response`` (generate) or
    ``message.content`` (chat)."""
    value = piece.get(field) if field else (piece.get("message") or {}).get("content")
    return value if isinstance(value, str) else None


def _ollama_set(piece: dict[str, Any], field: str | None, text: str) -> None:
    if field:
        piece[field] = text
    else:
        message = piece.get("message")
        if not isinstance(message, dict):
            message = piece["message"] = {"role": "assistant"}
        message["content"] = text


def _ollama_stream(response: Any, vault: Vault, model: str, field: str | None) -> Iterator[bytes]:
    """Ollama streams one JSON object per line; the last has ``done: true``."""
    r = _Restorer(vault)
    while True:
        line = response.readline(MAX_ANSWER)
        if not line:
            break
        if not line.strip():
            continue
        piece = json.loads(line)
        if not isinstance(piece, dict):
            continue
        text = _ollama_text(piece, field)
        out = r.feed(text or "") + (r.flush() if piece.get("done") else "")
        if text is not None or out:
            _ollama_set(piece, field, out)
        piece["model"] = model
        yield json.dumps(piece).encode() + b"\n"
    rest = r.flush()
    if rest:  # the endpoint stopped without a last ("done") line
        piece = {"model": model, "done": False}
        _ollama_set(piece, field, rest)
        yield json.dumps(piece).encode() + b"\n"


def _error(api: str, code: str, message: str) -> dict[str, Any]:
    """An error in the shape the client's SDK expects."""
    if api == "anthropic":
        return {"type": "error", "error": {"type": code, "message": message}}
    if api == "ollama":
        return {"error": message, "code": code}
    return {"error": {"message": message, "type": code, "code": code}}


def _stream_error(api: str, code: str, message: str) -> bytes:
    """An error after the answer started: the last event of the stream."""
    if api == "anthropic":
        return _sse(_error(api, code, message), "error")
    if api == "ollama":
        return json.dumps(_error(api, code, message)).encode() + b"\n"
    return _sse(_error(api, code, message)) + b"data: [DONE]\n\n"
