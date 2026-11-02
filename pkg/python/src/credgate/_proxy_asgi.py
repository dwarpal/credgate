"""The proxy on uvicorn: the same exchanges as the standard-library server,
served by a production HTTP server (``pip install 'credgate[server]'``).

uvicorn parses HTTP, keeps connections alive and shuts down gracefully; the
proxy limits the requests in progress per worker (``concurrency``; more get
``503`` at once, with ``Retry-After``). Each request still runs as
an :class:`~credgate.proxy._Exchange` - the same policy, audit and streaming
code - in a thread, so detection does not hold up other connections. A client
that goes away is noticed even while the model is still thinking, and the
endpoint's stream is closed at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import uvicorn

from . import proxy as P

_BODY_TIMEOUT = 120  # seconds a client may take to send its request body
_QUEUED = 256  # pieces read ahead of a slow client, at most


class _Headers(dict):
    """Request headers, looked up without regard to case."""

    def __init__(self, raw: list[tuple[bytes, bytes]]) -> None:
        super().__init__((k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in raw)

    def get(self, key: str, default: Any = None) -> Any:
        return super().get(key.lower(), default)

    def __getitem__(self, key: str) -> Any:
        return super().__getitem__(key.lower())

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and super().__contains__(key.lower())


def make_app(config: P.ProxyConfig, log: Callable[[str], Any]) -> Callable[..., Any]:
    """The proxy as an ASGI application."""
    pool: list[ThreadPoolExecutor] = []  # made in the worker process, after fork
    active = [0]  # requests in progress in this worker (one event loop: no lock needed)

    def executor() -> ThreadPoolExecutor:
        if not pool:
            # A thread per request in progress: waiting for a model holds one.
            pool.append(
                ThreadPoolExecutor(config.concurrency + 8, thread_name_prefix="credgate-proxy")
            )
        return pool[0]

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        health = scope.get("path", "").rstrip("/") in ("/healthz", "/v1/healthz")
        if not health and active[0] >= config.concurrency:
            await _busy(config, log, scope, send)
            return
        active[0] += 1
        try:
            await _exchange(config, log, executor(), scope, receive, send)
        finally:
            active[0] -= 1

    return app


async def _exchange(
    config: P.ProxyConfig,
    log: Callable[[str], Any],
    executor: ThreadPoolExecutor,
    scope: dict[str, Any],
    receive: Any,
    send: Any,
) -> None:
    started = time.monotonic()
    loop = asyncio.get_running_loop()
    headers = _Headers(scope.get("headers", []))
    query = scope.get("query_string", b"").decode("latin-1")
    path = scope.get("path", "/") + (f"?{query}" if query else "")
    method = scope["method"]
    disconnected = asyncio.Event()

    body: list[bytes | P._ProxyError] = []

    def read_body() -> bytes:
        if not body:  # not read yet (the client was not known): read it now
            future = asyncio.run_coroutine_threadsafe(_read_body(receive, disconnected), loop)
            return future.result()
        if isinstance(body[0], P._ProxyError):
            raise body[0]
        return body[0]

    exchange = P._Exchange(config, method, path, headers, read_body)
    with P._IN_FLIGHT_LOCK:
        P._IN_FLIGHT[0] += 1
    user, status, note = "-", 500, ""
    try:
        if method == "POST" and _known_client(exchange):
            # Read on the event loop, so the request makes one trip to a thread.
            try:
                body.append(await _read_body(receive, disconnected))
            except P._ProxyError as e:
                body.append(e)
        user, status, payload, note = await loop.run_in_executor(executor, exchange.run)
        extra = [(b"cache-control", b"no-store")]
        if status >= 400:
            # As the standard server does: never read leftover bytes of a
            # rejected request as a new one.
            extra.append((b"connection", b"close"))
        if exchange.request_id:
            extra.append((b"x-request-id", exchange.request_id.encode()))
        if isinstance(payload, P._Live):
            ended = await _stream(exchange, payload, extra, executor, receive, send, disconnected)
            note = ended or exchange._note or note  # "stream" unless it ended otherwise
        else:
            data = json.dumps(payload).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(data)).encode()),
                        *extra,
                    ],
                }
            )
            await send({"type": "http.response.body", "body": data})
    except OSError:
        note = "client_closed"
    finally:
        log(P._log_line(user, method, path, status, note, started, exchange.request_id))
        with P._IN_FLIGHT_LOCK:
            P._IN_FLIGHT[0] -= 1


def _known_client(exchange: P._Exchange) -> bool:
    """The client's key checks out (a hash comparison, fast enough for the
    event loop); bodies of unknown clients are never read."""
    try:
        exchange._authenticate()
        return True
    except P._ProxyError:
        return False


async def _busy(
    config: P.ProxyConfig, log: Callable[[str], Any], scope: dict[str, Any], send: Any
) -> None:
    """More requests than ``concurrency`` in progress: refused at once, so a
    load balancer can send it elsewhere. Nothing is read or forwarded."""
    path = scope.get("path", "/")
    api = (
        "anthropic"
        if path.startswith("/v1/messages")
        else "ollama"
        if path.startswith("/api/")
        else "openai"
    )
    message = f"The proxy is busy ({config.concurrency} requests in progress); try again."
    data = json.dumps(P._error(api, "busy", message)).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 503,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(data)).encode()),
                (b"retry-after", b"1"),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": data})
    log(P._log_line("-", scope["method"], path, 503, "busy", time.monotonic(), ""))


async def _read_body(receive: Any, disconnected: asyncio.Event) -> bytes:
    """The whole request body, at most ``MAX_BODY`` bytes."""
    parts, size = [], 0
    while True:
        try:
            message = await asyncio.wait_for(receive(), _BODY_TIMEOUT)
        except TimeoutError:
            raise P._ProxyError(408, "request_timeout", "The request body took too long.") from None
        if message["type"] == "http.disconnect":
            disconnected.set()
            raise P._ProxyError(400, "invalid_request", "The client went away.")
        body = message.get("body", b"")
        size += len(body)
        if size > P.MAX_BODY:
            raise P._ProxyError(413, "invalid_request", "Missing or too large body.")
        parts.append(body)
        if not message.get("more_body", False):
            break
    if size == 0:
        raise P._ProxyError(400, "invalid_request", "Missing or too large body.")
    return b"".join(parts)


async def _stream(
    exchange: P._Exchange,
    live: P._Live,
    extra: list[tuple[bytes, bytes]],
    executor: ThreadPoolExecutor,
    receive: Any,
    send: Any,
    disconnected: asyncio.Event,
) -> str:
    """Send the answer's pieces as they arrive; returns the note for the log."""
    loop = asyncio.get_running_loop()

    async def watch() -> None:
        # The client may leave while the model is still thinking: close the
        # endpoint's stream at once rather than at the next piece.
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected.set()
                live.close()
                return

    watcher = asyncio.create_task(watch())
    # One thread reads the endpoint and checks the pieces; it hands them over
    # through a queue (at most _QUEUED waiting), and whatever has arrived is
    # sent as one write - no round trip between threads per piece.
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
    room = threading.Semaphore(_QUEUED)

    def produce() -> None:
        pieces = exchange.pieces(live)
        try:
            for piece in pieces:
                while not room.acquire(timeout=0.5):
                    if disconnected.is_set():
                        return
                if disconnected.is_set():
                    return
                loop.call_soon_threadsafe(queue.put_nowait, piece)
        finally:
            pieces.close()
            loop.call_soon_threadsafe(queue.put_nowait, None)

    producer = loop.run_in_executor(executor, produce)
    try:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", live.content_type.encode()),
                    (b"x-accel-buffering", b"no"),  # nginx: pass pieces on at once
                    *extra,
                ],
            }
        )
        done = False
        while not done:
            batch = [await queue.get()]
            while not queue.empty():
                batch.append(queue.get_nowait())
            if batch[-1] is None:
                done = True
                batch.pop()
            for _ in batch:
                room.release()
            if disconnected.is_set():
                return "client_closed"
            if batch:
                await send(
                    {"type": "http.response.body", "body": b"".join(batch), "more_body": True}  # type: ignore[arg-type]
                )
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return ""
    except OSError:  # the server reports a client that went away this way
        return "client_closed"
    finally:
        disconnected.set()  # stops the producer if it is still reading
        watcher.cancel()
        live.close()
        with contextlib.suppress(Exception):
            await producer


class _Server(uvicorn.Server):
    """uvicorn's server, with the proxy's drain: on SIGTERM ``/healthz``
    reports draining for ``drain_seconds`` while requests are still served,
    then the server stops accepting and finishes the requests in progress."""

    on_signal: Callable[[int], None] | None = None
    drain_seconds: float = 5

    def handle_exit(self, sig: int, frame: Any) -> None:
        if self.on_signal is not None:
            self.on_signal(sig)
        if sig == P.signal.SIGTERM and not P._DRAINING.is_set():
            P._DRAINING.set()
            timer = threading.Timer(self.drain_seconds, lambda: setattr(self, "should_exit", True))
            timer.daemon = True
            timer.start()
            return
        super().handle_exit(sig, frame)


class UvicornServer:
    """A uvicorn server on a socket of its own, with the same handle as the
    standard-library server: ``serve_forever()``, ``shutdown()``,
    ``server_address``, ``server_close()``."""

    def __init__(self, config: P.ProxyConfig, log: Callable[[str], Any]) -> None:
        family = socket.AF_INET6 if ":" in config.host else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((config.host, config.port))
        self.socket.listen(2048)
        self.socket.set_inheritable(True)
        self.server_address = self.socket.getsockname()
        self.server = _Server(
            uvicorn.Config(
                make_app(config, log),
                ssl_certfile=config.certfile,
                ssl_keyfile=config.keyfile,
                # A backstop against floods of connections; requests in
                # progress are limited by the proxy itself (`concurrency`).
                limit_concurrency=max(1024, 4 * config.concurrency),
                timeout_keep_alive=5,
                timeout_graceful_shutdown=int(config.timeout),
                proxy_headers=False,  # never trust X-Forwarded-For from clients
                server_header=False,
                access_log=False,  # the proxy writes its own line, without text
                log_level="warning",
                lifespan="on",
            )
        )
        self.server.drain_seconds = config.drain_seconds

    def serve_forever(self) -> None:
        self.server.run(sockets=[self.socket])

    def shutdown(self) -> None:
        self.server.should_exit = True

    def server_close(self) -> None:
        with contextlib.suppress(OSError):
            self.socket.close()
