"""Loopback-only, bearer-authenticated Prometheus exposition.

The node exposes aggregate counters only (``hsync_rendezvous.stats``): no CID,
bucket, IP or port, so the exposition keeps the no-log invariant. The responder
is deliberately small and rigid instead of pulling in an HTTP framework \u2014 a
metrics port must never become the widest attack surface of a public daemon, and
the project's dependency lock cannot gain a runtime dependency here.

Contract (the same shape as the sync server's authenticated ``/metrics``):
``GET|HEAD /metrics`` with ``Authorization: Bearer TOKEN`` returns the Prometheus
text format; every other request is refused with a plain-text status. Loopback is
not an authorisation boundary (the port is visible to every local user and can be
reached through a proxy or an SSH tunnel), so the token is mandatory.

Consumers: ``hsync_rendezvous.cli`` (``run --metrics-port``), and the exposition is
scraped by Prometheus or any compatible agent.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
from dataclasses import dataclass
from typing import NamedTuple

from hsync_common.protocol.rest import PROMETHEUS_CONTENT_TYPE, REST_METRICS_PATH
from hsync_common.ratelimit import TokenBucketLimiter
from pydantic import SecretStr

from hsync_rendezvous.stats import NodeStats

__all__ = [
    "PROMETHEUS_CONTENT_TYPE",
    "MetricsEndpoint",
    "MetricsServer",
]

_ERROR_CONTENT_TYPE = "text/plain; charset=utf-8"

# One request per connection, one bounded header block, a short read timeout: the
# endpoint answers a local scraper, not a browser, and holds no keep-alive state.
_HEADER_TERMINATOR = b"\r\n\r\n"
_MAX_HEADER_BYTES = 8 * 1024
_READ_TIMEOUT_SECONDS = 5.0
_MAX_CONCURRENT = 4
# Hard accept cap, applied before a byte is read: an unauthenticated flood must
# not allocate a task and an 8 KiB reader per connection. Higher than the serving
# cap so a short burst still gets the explicit 503 instead of a bare close.
_MAX_CONNECTIONS = 4 * _MAX_CONCURRENT
_RATE_PER_SECOND = 1.0
_RATE_BURST = 4
_RATE_KEY = "metrics"

_REASONS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    503: "Service Unavailable",
}


@dataclass(frozen=True, slots=True)
class MetricsEndpoint:
    """A resolved metrics listener: loopback address, port and bearer token."""

    host: str
    port: int
    token: SecretStr


class _Request(NamedTuple):
    method: str
    target: str
    headers: dict[str, str]


class _Refusal(Exception):
    """A request the endpoint answers without serving metrics."""

    def __init__(
        self,
        status: int,
        outcome: str,
        message: bytes,
        *,
        extra: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.status = status
        self.outcome = outcome
        self.message = message
        self.extra = extra
        super().__init__(outcome)


def _unauthorized() -> _Refusal:
    """The single refusal shape for every authentication failure (no oracle)."""
    return _Refusal(
        401,
        "unauthorized",
        b"not authenticated\n",
        extra=(("WWW-Authenticate", "Bearer"),),
    )


class MetricsServer:
    """One loopback HTTP listener serving ``/metrics`` from a :class:`NodeStats`."""

    def __init__(self, *, endpoint: MetricsEndpoint, stats: NodeStats) -> None:
        self._endpoint = endpoint
        self._stats = stats
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._limiter = TokenBucketLimiter(
            capacity=_RATE_BURST, refill=_RATE_PER_SECOND, window=1.0, max_keys=64
        )
        self._inflight = 0

    @classmethod
    async def start(cls, *, endpoint: MetricsEndpoint, stats: NodeStats) -> MetricsServer:
        """Bind the listener; an ``OSError`` propagates to the caller (fail fast)."""
        server = cls(endpoint=endpoint, stats=stats)
        server._server = await asyncio.start_server(
            server._spawn, endpoint.host, endpoint.port, limit=_MAX_HEADER_BYTES
        )
        return server

    @property
    def sockets(self) -> tuple[object, ...]:
        """Bound sockets (the bound port is authoritative for ``--metrics-port 0``)."""
        server = self._server
        return tuple(server.sockets) if server is not None else ()

    async def aclose(self) -> None:
        """Stop accepting, then cancel whatever is still being answered."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _spawn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Keep the per-connection task alive and cancellable (asyncio forgets it).

        The accept cap is enforced **before** a byte is read: an unauthenticated
        flood must not allocate a task and an 8 KiB reader per connection.
        """
        if len(self._tasks) >= _MAX_CONNECTIONS:
            writer.close()
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Answer one request; the head is read before any refusal is written.

        Reading first is deliberate: closing a socket that still holds unread
        request bytes makes the kernel send RST, which can discard the refusal
        the caller was meant to read. The read is bounded (header cap + timeout),
        so parsing first cannot buy a flood anything: the concurrency cap and the
        token bucket still run before a single metric is served.
        """
        self._inflight += 1
        try:
            try:
                request = await self._read_request(reader)
                if self._inflight > _MAX_CONCURRENT:
                    raise _Refusal(503, "unavailable", b"service unavailable\n")
                # Pre-auth budget per source: one local user (or the proxy's
                # loopback source) must not drain the bucket the legitimate
                # scraper needs. ``max_keys`` bounds the bucket map.
                peer = writer.get_extra_info("peername")
                rate_key = f"metrics:{peer[0]}" if peer else _RATE_KEY
                if not self._limiter.allow(rate_key):
                    retry = max(1, self._limiter.retry_after(rate_key))
                    raise _Refusal(
                        429,
                        "rate_limited",
                        b"too many requests\n",
                        extra=(("Retry-After", str(retry)),),
                    )
                self._check_authorization(request)
                if request.method not in ("GET", "HEAD"):
                    raise _Refusal(
                        405,
                        "method_not_allowed",
                        b"method not allowed\n",
                        extra=(("Allow", "GET, HEAD"),),
                    )
                if request.target.split("?", 1)[0] != REST_METRICS_PATH:
                    raise _Refusal(404, "not_found", b"not found\n")
            except _Refusal as refusal:
                self._stats.metrics_request(refusal.outcome)
                await self._respond(writer, refusal.status, refusal.message, extra=refusal.extra)
                return
            self._stats.metrics_request("ok")
            body = self._stats.render_prometheus().encode("utf-8")
            await self._respond(
                writer,
                200,
                body,
                content_type=PROMETHEUS_CONTENT_TYPE,
                head_only=request.method == "HEAD",
            )
        except (asyncio.IncompleteReadError, ConnectionError):
            # The client went away mid-request: nothing to answer, nothing to log.
            pass
        finally:
            self._inflight -= 1
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _read_request(self, reader: asyncio.StreamReader) -> _Request:
        """Read one bounded request head; raise :class:`_Refusal` instead of guessing."""
        try:
            head = await asyncio.wait_for(
                reader.readuntil(_HEADER_TERMINATOR), timeout=_READ_TIMEOUT_SECONDS
            )
        except TimeoutError:
            raise _Refusal(408, "unavailable", b"request timeout\n") from None
        except (asyncio.LimitOverrunError, ValueError):
            raise _Refusal(431, "unavailable", b"request header too large\n") from None
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise _Refusal(400, "unavailable", b"malformed request\n")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return _Request(method=parts[0].upper(), target=parts[1], headers=headers)

    def _check_authorization(self, request: _Request) -> None:
        """Constant-time bearer check; every failure gets the identical refusal."""
        scheme, _, credentials = request.headers.get("authorization", "").partition(" ")
        expected = self._endpoint.token.get_secret_value()
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            credentials.encode("utf-8"), expected.encode("utf-8")
        ):
            raise _unauthorized()

    async def _respond(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: bytes,
        *,
        content_type: str = _ERROR_CONTENT_TYPE,
        extra: tuple[tuple[str, str], ...] = (),
        head_only: bool = False,
    ) -> None:
        """Write one complete response and close (``Connection: close``, no chunking)."""
        lines = [
            f"HTTP/1.1 {status} {_REASONS.get(status, 'OK')}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        lines.extend(f"{name}: {value}" for name, value in extra)
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        writer.write(head if head_only else head + body)
        with contextlib.suppress(ConnectionError, RuntimeError):
            await writer.drain()
