"""TLS/TCP transport for ``rdv/1``.

One TLS/TCP connection = one ``rdv/1`` session, reusing the shared
:mod:`hsync_rendezvous.session` loop. Admission runs before the TLS handshake
and before any byte is read, so a client's ClientHello can never be parsed as
plaintext and a refused IP is dropped without any handshake work.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from collections.abc import Callable
from typing import cast

from hsync_common.protocol.rendezvous import RDV_ALPN, RDV_IDLE_TIMEOUT

from hsync_rendezvous.diagnostics import debug_event
from hsync_rendezvous.guard import ConnectionGuard
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.limits import (
    MAX_STREAM_DATA_BYTES,
    TCP_HANDSHAKE_TIMEOUT,
    TCP_LISTEN_BACKLOG,
)
from hsync_rendezvous.session import serve_rdv_session

__all__ = [
    "RendezvousTcpProtocol",
    "bind_tcp_socket",
    "serve_tcp_port",
    "tcp_protocol_factory",
]


class RendezvousTcpProtocol(asyncio.Protocol):
    """One TLS/TCP connection = one ``rdv/1`` session.

    A plain :class:`asyncio.Protocol` because admission must run before the TLS
    handshake **and before any byte is read**: ``loop.create_server`` (no ``ssl``)
    hands the connection here first, so :meth:`connection_made` reads the observed
    ``peername``, charges the :class:`ConnectionGuard` (refusal →
    ``transport.abort()``, no handshake work) and only then upgrades to TLS with
    ``loop.start_tls``. Running the handshake in a ``start_server`` callback
    instead would race: the client's ClientHello may already sit in the
    ``StreamReader`` buffer and would be lost to TLS.

    One connection carries one session (several frames may be pipelined on it):
    the one-shot exchange (``register``/``refresh``/``leave``/``query``), the
    relay requester's data connection (``relay_connect``) and the relay
    listener's control connection (``relay_listen``). A relay ``relay_attach`` is
    a fresh connection too, so its admission can be returned once the registry
    matches it (:meth:`exempt`).
    """

    def __init__(
        self,
        handler: RendezvousHandler,
        context: ssl.SSLContext,
        guard: ConnectionGuard | None = None,
    ) -> None:
        self._handler = handler
        self._context = context
        self._guard = guard
        self._transport: asyncio.BaseTransport | None = None
        self._peer_ip = "0.0.0.0"
        self._peer_port = 0
        self._admitted = False
        self._released = False
        self._exempted = False
        self._task: asyncio.Task[None] | None = None

    # -- admission + handshake ------------------------------------------------

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport
        peer = transport.get_extra_info("peername")
        if peer is not None:
            # IPv4/IPv6 peername is (host, port[, flowinfo, scope_id]); only the
            # observed source is used, exactly as the QUIC listener derives it,
            # so the per-IP guards, rate limits and the relay peer_ip check agree.
            self._peer_ip = str(peer[0])
            self._peer_port = int(peer[1])
        # asyncio.Protocol declares ``BaseTransport``, but the concrete socket
        # transport is both a ReadTransport and a WriteTransport; narrow it back
        # to the halves that carry ``abort``/``pause_reading``/``start_tls``.
        write_transport = cast(asyncio.WriteTransport, transport)
        guard = self._guard
        if guard is not None:
            if not guard.admit(self._peer_ip, transport="tcp"):
                debug_event("tcp connection refused ip-guard", peer=self._peer_ip)
                write_transport.abort()
                return
            self._admitted = True
        # No byte is read before the handshake: pause so a client's ClientHello
        # cannot land in the StreamReader buffer as plaintext (start_tls resumes
        # reading once the TLS protocol is installed).
        cast(asyncio.ReadTransport, transport).pause_reading()
        self._task = asyncio.create_task(self._handshake(write_transport))

    def connection_lost(self, exc: Exception | None) -> None:
        # Fires only before start_tls takes over as the connection's protocol
        # (abort, a client that disconnects during or without the handshake); the
        # post-TLS path releases from _handshake's finally.
        self._release()

    def eof_received(self) -> bool:
        # Keep asyncio's half-open semantics for TCP streams.
        return False

    async def _handshake(self, transport: asyncio.WriteTransport) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=MAX_STREAM_DATA_BYTES)
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            new_transport = await loop.start_tls(
                transport,
                protocol,
                self._context,
                server_side=True,
                ssl_handshake_timeout=TCP_HANDSHAKE_TIMEOUT,
            )
        except (ssl.SSLError, ConnectionError, TimeoutError, OSError):
            self._release()
            transport.abort()
            return
        if new_transport is None:
            # ``start_tls`` returns None when the transport is already closing:
            # there is no TLS session to serve, so release and stop.
            self._release()
            return
        ssl_object = new_transport.get_extra_info("ssl_object")
        selected = ssl_object.selected_alpn_protocol() if ssl_object is not None else None
        if selected != RDV_ALPN:
            # Python's server-side ALPN does not abort on no overlap: enforce it
            # here, in parity with the aioquic listener. ``selected`` is None when
            # the client offered no ALPN at all. A graceful close (FIN) is used
            # instead of ``abort()`` so a client sees a clean EOF, not a reset.
            debug_event("tcp alpn refused", peer=self._peer_ip, alpn=selected)
            self._release()
            new_transport.close()
            return
        writer = asyncio.StreamWriter(
            cast(asyncio.WriteTransport, new_transport), protocol, reader, loop
        )
        try:
            await self._serve(reader, writer)
        finally:
            self._release()
            if not writer.is_closing():
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # -- session --------------------------------------------------------------

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # One shared, transport-agnostic session loop: only the idle timer (a
        # silent peer is reaped) and the admission handle (relay-attach fan-out)
        # differ from the QUIC stream path.
        await serve_rdv_session(
            handler=self._handler,
            reader=reader,
            writer=writer,
            peer_ip=self._peer_ip,
            peer_port=self._peer_port,
            proto="tcp",
            idle_timeout=RDV_IDLE_TIMEOUT,
            admission=self,
        )

    # -- admission accounting -------------------------------------------------

    def _release(self) -> None:
        """Release this connection's accounting exactly once.

        An exempted connection returns its admission at exemption time; the
        metrics keep counting it until it really closes, so the close still
        decrements the metric level (``release_metrics``) without touching the
        admission accounting again.
        """
        if not self._admitted or self._released:
            return
        self._released = True
        guard = self._guard
        if guard is None:
            return
        if self._exempted:
            guard.release_metrics(transport="tcp")
        else:
            guard.release(self._peer_ip, transport="tcp")

    def exempt(self) -> None:
        """Return this connection's generic admission (relay-attach fan-out).

        Called by :meth:`hsync_rendezvous.relay.RelayRegistry._attach` once a
        ``relay_attach`` matches a pending session: the attach is then bounded by
        the relay session quotas, so its handshake token and active slot are
        returned. Idempotent; a later close does not release again.
        """
        if not self._admitted or self._released or self._exempted:
            return
        self._exempted = True
        guard = self._guard
        if guard is not None:
            guard.exempt(self._peer_ip, transport="tcp")


def tcp_protocol_factory(
    handler: RendezvousHandler,
    context: ssl.SSLContext,
    guard: ConnectionGuard | None,
) -> Callable[[], RendezvousTcpProtocol]:
    """Build the ``loop.create_server`` protocol factory for one shared handler."""

    def _create() -> RendezvousTcpProtocol:
        return RendezvousTcpProtocol(handler, context, guard)

    return _create


def bind_tcp_socket(host: str, port: int) -> socket.socket:
    """Bind and listen on one TCP socket (first address that binds wins).

    Uses the resolver so a hostname (or the ``::`` wildcard, with
    ``IPV6_V6ONLY=0`` for dual-stack) binds like the QUIC listener would; a
    concrete IP binds its own family. The socket is non-blocking, ready for
    ``loop.create_server(..., sock=...)``.
    """
    last_exc: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(sockaddr)
            sock.listen(TCP_LISTEN_BACKLOG)
            sock.setblocking(False)
            return sock
        except OSError as exc:
            last_exc = exc
            sock.close()
    if last_exc is not None:
        raise last_exc
    raise OSError(f"could not resolve {host}:{port}")


async def serve_tcp_port(
    port: int,
    *,
    host: str,
    loop: asyncio.AbstractEventLoop,
    factory: Callable[[], RendezvousTcpProtocol],
) -> tuple[asyncio.Server, int]:
    """Bind one TLS/TCP listener; returns ``(server, real_bound_port)``."""
    sock = bind_tcp_socket(host, port)
    try:
        server = await loop.create_server(factory, sock=sock)
    except OSError:
        sock.close()
        raise
    return server, int(sock.getsockname()[1])
