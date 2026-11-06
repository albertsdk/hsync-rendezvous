"""TLS/TCP transport for ``rdv/1``.

One TLS/TCP connection = one ``rdv/1`` session, reusing the shared
:mod:`hsync_rendezvous.session` loop.

Admission runs on the **accepted socket, before the TLS handshake and before a
single byte is read**: the accept loop charges the :class:`ConnectionGuard`,
closes a refused connection immediately, and only then hands the socket to
asyncio's TLS stack with ``loop.connect_accepted_socket``. That ordering matters
twice: it keeps per-IP admission ahead of any TLS work, and it avoids the
in-place ``start_tls`` upgrade window where a client's ClientHello could be read
by the pre-TLS protocol and dropped (a stalled handshake until the timeout).

``RendezvousTcpProtocol`` keeps the per-connection accounting (admission slot,
relay-attach exemption, metrics release); the accept loop owns the socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from collections.abc import Callable

from hsync_common.protocol.rendezvous import RDV_ALPN, RDV_IDLE_TIMEOUT

from hsync_rendezvous.diagnostics import debug_event
from hsync_rendezvous.guard import ConnectionGuard
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.limits import MAX_STREAM_DATA_BYTES, TCP_HANDSHAKE_TIMEOUT, TCP_LISTEN_BACKLOG
from hsync_rendezvous.session import serve_rdv_session

__all__ = [
    "RendezvousTcpProtocol",
    "TcpListener",
    "bind_tcp_socket",
    "serve_tcp_port",
    "tcp_protocol_factory",
]


class RendezvousTcpProtocol:
    """Per-connection admission accounting and one ``rdv/1`` session.

    The accept loop creates one instance per accepted socket, calls
    :meth:`admit` (before any TLS work), then :meth:`serve_accepted`. The class
    keeps the guard accounting so a relay ``relay_attach`` can return the
    generic admission while the connection stays open (:meth:`exempt`).

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
        self._peer_ip = "0.0.0.0"
        self._peer_port = 0
        self._admitted = False
        self._released = False
        self._exempted = False

    # -- admission ------------------------------------------------------------

    def admit(self, peer_ip: str, peer_port: int) -> bool:
        """Charge the guard for *peer_ip* before any TLS work; False = refuse."""
        self._peer_ip = peer_ip
        self._peer_port = peer_port
        guard = self._guard
        if guard is None:
            return True
        if not guard.admit(peer_ip, transport="tcp"):
            return False
        self._admitted = True
        return True

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

    # -- session --------------------------------------------------------------

    async def serve_accepted(self, conn: socket.socket) -> None:
        """Run the TLS handshake on an admitted socket and serve one session."""
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=MAX_STREAM_DATA_BYTES)
        stream_protocol = asyncio.StreamReaderProtocol(reader)
        try:
            # The TLS handshake happens inside asyncio's SSL transport: no
            # in-place upgrade, so no pre-TLS bytes can be read or dropped.
            transport, _ = await loop.connect_accepted_socket(
                lambda: stream_protocol,
                conn,
                ssl=self._context,
                ssl_handshake_timeout=TCP_HANDSHAKE_TIMEOUT,
            )
        except (ssl.SSLError, ConnectionError, TimeoutError, OSError) as exc:
            # Peer-free (the exception class only): a failed handshake is
            # routine, but a spike is what tells an operator the listener is
            # dropping connections.
            debug_event("tcp handshake failed", peer=self._peer_ip, exc=type(exc).__name__)
            self._release()
            with contextlib.suppress(OSError):
                conn.close()
            return

        ssl_object = transport.get_extra_info("ssl_object")
        selected = ssl_object.selected_alpn_protocol() if ssl_object is not None else None
        if selected != RDV_ALPN:
            # Python's server-side ALPN does not abort on no overlap: enforce it
            # here, in parity with the aioquic listener. ``selected`` is None when
            # the client offered no ALPN at all. A graceful close (FIN) is used
            # instead of ``abort()`` so a client sees a clean EOF, not a reset.
            debug_event("tcp alpn refused", peer=self._peer_ip, alpn=selected)
            self._release()
            transport.close()
            return

        writer = asyncio.StreamWriter(transport, stream_protocol, reader, loop)
        try:
            # One shared, transport-agnostic session loop: only the idle timer
            # (a silent peer is reaped) and the admission handle (relay-attach
            # fan-out) differ from the QUIC stream path.
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
        finally:
            self._release()
            if not writer.is_closing():
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    @property
    def peer_ip(self) -> str:
        """Observed source address (only for diagnostics/tests)."""
        return self._peer_ip


class TcpListener:
    """Accept loop for one TLS/TCP listener.

    Returns the same ``close()`` surface as :class:`asyncio.Server` so the
    orchestrator and tests treat both transports alike. Each accepted socket is
    admitted **before** the handshake and then served in its own task, so one
    slow TLS handshake never blocks the next accept.
    """

    def __init__(
        self,
        sock: socket.socket,
        factory: Callable[[], RendezvousTcpProtocol],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._sock = sock
        self._factory = factory
        self._loop = loop
        self._closed = False
        self._accept_task: asyncio.Task[None] | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    def start(self) -> None:
        self._accept_task = self._loop.create_task(self._accept_loop())

    async def _accept_loop(self) -> None:
        while not self._closed:
            try:
                conn, addr = await self._loop.sock_accept(self._sock)
            except asyncio.CancelledError:
                return
            except OSError as exc:
                if self._closed:
                    return
                # Transient accept error (EMFILE/ENFILE/ECONNABORTED): the
                # listener must survive a burst of churn.
                debug_event("tcp accept failed", exc=type(exc).__name__)
                await asyncio.sleep(0.05)
                continue
            conn.setblocking(False)
            protocol = self._factory()
            peer_ip, peer_port = str(addr[0]), int(addr[1])
            if not protocol.admit(peer_ip, peer_port):
                debug_event("tcp connection refused ip-guard", peer=peer_ip)
                with contextlib.suppress(OSError):
                    conn.close()
                continue
            task = self._loop.create_task(self._serve(protocol, conn))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _serve(self, protocol: RendezvousTcpProtocol, conn: socket.socket) -> None:
        try:
            await protocol.serve_accepted(conn)
        except Exception as exc:  # noqa: BLE001 - one connection must not stop the listener
            debug_event("tcp session failed", exc=type(exc).__name__)
            with contextlib.suppress(OSError):
                conn.close()

    def close(self) -> None:
        """Stop accepting and close the listening socket (idempotent)."""
        self._closed = True
        if self._accept_task is not None:
            self._accept_task.cancel()
        with contextlib.suppress(OSError):
            self._sock.close()

    async def wait_closed(self) -> None:
        """Await the accept loop and every in-flight connection task."""
        if self._accept_task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._accept_task
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    async def __aenter__(self) -> TcpListener:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self.close()
        await self.wait_closed()


def tcp_protocol_factory(
    handler: RendezvousHandler,
    context: ssl.SSLContext,
    guard: ConnectionGuard | None,
) -> Callable[[], RendezvousTcpProtocol]:
    """Build the per-connection protocol factory for one shared handler."""

    def _create() -> RendezvousTcpProtocol:
        return RendezvousTcpProtocol(handler, context, guard)

    return _create


def bind_tcp_socket(host: str, port: int) -> socket.socket:
    """Bind and listen on one TCP socket (first address that binds wins).

    Uses the resolver so a hostname (or the ``::`` wildcard, with
    ``IPV6_V6ONLY=0`` for dual-stack) binds like the QUIC listener would; a
    concrete IP binds its own family. The socket is non-blocking, ready for the
    accept loop.
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
) -> tuple[TcpListener, int]:
    """Bind one TLS/TCP listener; returns ``(listener, real_bound_port)``."""
    sock = bind_tcp_socket(host, port)
    listener = TcpListener(sock, factory, loop)
    listener.start()
    return listener, int(sock.getsockname()[1])
