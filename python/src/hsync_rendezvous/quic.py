"""QUIC/UDP transport for ``rdv/1`` (aioquic).

A thin adapter around aioquic: the single QUIC/UDP listener, the mandatory
RETRY + address-validation tokens (``retry`` aioquic flag), per-connection peer
tracking (STUN-echo source) and the NDJSON-over-bidi-stream framing via the
shared :mod:`hsync_rendezvous.session` loop. All business rules live in
``hsync_rendezvous.handler.RendezvousHandler`` and are fully testable without
sockets.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent
from hsync_common.protocol.rendezvous import RDV_ALPN, RDV_IDLE_TIMEOUT

from hsync_rendezvous.diagnostics import debug_event
from hsync_rendezvous.guard import ConnectionGuard
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.identity import NodeIdentity
from hsync_rendezvous.limits import (
    MAX_DATA_BYTES,
    MAX_RELAY_STREAMS_PER_CONNECTION,
    MAX_SESSIONS_PER_CONNECTION,
    MAX_STREAM_DATA_BYTES,
)
from hsync_rendezvous.session import serve_rdv_session

__all__ = [
    "RendezvousQuicProtocol",
    "build_quic_configuration",
    "protocol_factory",
    "serve_quic_port",
]


def build_quic_configuration(
    identity: NodeIdentity,
    *,
    idle_timeout: float = RDV_IDLE_TIMEOUT,
    max_stream_data: int = MAX_STREAM_DATA_BYTES,
    max_data: int = MAX_DATA_BYTES,
) -> QuicConfiguration:
    """Server-side QUIC/TLS configuration bound to the given TLS identity."""
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[RDV_ALPN],
        idle_timeout=idle_timeout,
        max_stream_data=max_stream_data,
        max_data=max_data,
    )
    config.certificate = identity.certificate
    config.private_key = identity.private_key
    return config


class RendezvousQuicProtocol(QuicConnectionProtocol):
    """One QUIC/UDP connection; every bidirectional stream is a ``rdv/1`` session.

    ``boot_handler`` is bound by the orchestrator (``server.start_server``)
    before the first datagram is dispatched (class attribute shared by all
    connections of the server). When a ``ConnectionGuard`` is bound too, a
    connecting peer is admitted against the per-IP handshake budget and
    active-connection cap before its server-side handshake work runs at all
    (see :meth:`datagram_received`).
    """

    boot_handler: RendezvousHandler

    def __init__(
        self,
        quic: Any,
        stream_handler: Callable[[Any, Any], Any] | None = None,
        guard: ConnectionGuard | None = None,
    ) -> None:
        super().__init__(quic, stream_handler)
        self.guard = guard
        # True once this connection was counted on the guard (one release per
        # admitted connection; the flag makes the count idempotent if QUIC
        # surfaces ConnectionTerminated twice).
        self.admitted_on_guard = False
        self.peer_addr: tuple[str, int] | None = None
        # Relay streams currently bridged on this connection. Tracked separately
        # from the rendezvous sessions so the relay headroom never raises the
        # per-connection budget a plain ``rdv/1`` client may pin.
        self._relay_streams = 0
        # Strong references to the per-session tasks: aioquic does not await the
        # stream handler, so without this the loop could garbage-collect a
        # running session.
        self._stream_tasks: set[asyncio.Task[None]] = set()
        # Route every new stream to our per-session coroutine instead of the
        # bare callback (aioquic does not await the stream handler itself).
        self._stream_handler = self._spawn_stream

    def datagram_received(self, data: bytes | str, addr: Any) -> None:
        peer_ip = str(addr[0])
        first = self.peer_addr is None
        # Transport admission happens BEFORE any handshake work: a refused IP
        # gets one CONNECTION_CLOSE and nothing else (see _refuse_unadmitted).
        if first:
            guard = self.guard
            if guard is not None:
                if not guard.admit(peer_ip, transport="quic"):
                    debug_event("connection refused ip-guard", peer=peer_ip)
                    payload = data.encode("utf-8") if isinstance(data, str) else data
                    self._refuse_unadmitted(payload, addr)
                    return
                self.admitted_on_guard = True
            # Keep the observed source endpoint: it is both the anti-amplification
            # ground truth and the STUN-echo answer (observed NAT-mapped port).
            self.peer_addr = (peer_ip, int(addr[1]))
        super().datagram_received(data, addr)

    def _refuse_unadmitted(self, data: bytes, addr: Any) -> None:
        """Reject an unadmitted connection without running any handshake work.

        aioquic registers a connection's QUIC network path only while processing
        its first datagram, and a CONNECTION_CLOSE cannot be sent without it, so
        the datagram is fed to ``QuicConnection`` at the bookkeeping layer only
        (``receive_datagram`` — no event processing, so no TLS work) and the
        connection is then closed. This is the single place that reaches into
        aioquic's private connection/loop (pinned ``>=1.2.0,<2.0.0``); the
        loopback guard test fails loudly if a future aioquic changes that shape.
        """
        self._quic.receive_datagram(data, addr, now=self._loop.time())
        self.close()

    def quic_event_received(self, event: QuicEvent) -> None:
        # Connection teardown releases the per-IP open-connection slot: the
        # guard's active count must converge to the real connection population.
        if (
            isinstance(event, ConnectionTerminated)
            and self.admitted_on_guard
            and self.guard is not None
        ):
            self.admitted_on_guard = False
            ip = self.peer_addr[0] if self.peer_addr is not None else "0.0.0.0"
            self.guard.release(ip, transport="quic")
        super().quic_event_received(event)

    def _observed_peer(self) -> tuple[str, int]:
        """Observed source endpoint, or a placeholder before the first datagram."""
        return self.peer_addr if self.peer_addr is not None else ("0.0.0.0", 0)

    def _spawn_stream(self, reader: Any, writer: Any) -> None:
        peer = self._observed_peer()
        rendezvous_streams = max(0, len(self._stream_tasks) - self._relay_streams)
        if (
            rendezvous_streams >= MAX_SESSIONS_PER_CONNECTION
            or self._relay_streams >= MAX_RELAY_STREAMS_PER_CONNECTION
        ):
            # rdv/1 uses one stream per exchange; the relay adds one long-lived
            # stream per paired session on its own budget. A connection over
            # either bound gets no further stream instead of pinning another
            # session task (see MAX_SESSIONS_PER_CONNECTION /
            # MAX_RELAY_STREAMS_PER_CONNECTION).
            debug_event("stream refused session-cap", peer=f"{peer[0]}:{peer[1]}")
            writer.close()
            return
        debug_event("session open", peer=f"{peer[0]}:{peer[1]}")
        task = asyncio.create_task(self._serve_stream(reader, writer))
        self._stream_tasks.add(task)
        task.add_done_callback(self._stream_tasks.discard)

    async def _serve_stream(self, reader: Any, writer: Any) -> None:
        peer_ip, peer_port = self._observed_peer()
        relay_stream = False

        def _on_relay_handoff() -> None:
            nonlocal relay_stream
            relay_stream = True
            self._relay_streams += 1

        try:
            await serve_rdv_session(
                handler=self.boot_handler,
                reader=reader,
                writer=writer,
                peer_ip=peer_ip,
                peer_port=peer_port,
                proto="udp",
                on_relay_handoff=_on_relay_handoff,
            )
        finally:
            debug_event("session close", peer=f"{peer_ip}:{peer_port}")
            if relay_stream:
                self._relay_streams = max(0, self._relay_streams - 1)
            if not writer.is_closing():
                writer.close()


def protocol_factory(
    handler: RendezvousHandler, guard: ConnectionGuard | None = None
) -> Callable[[Any, Any], Any]:
    """Build the aioquic ``create_protocol`` callable for one shared handler.

    aioquic instantiates one protocol object per QUIC connection; the closure
    binds the process-wide :class:`RendezvousHandler` and the optional :class:`ConnectionGuard`
    to each instance.
    """

    def _create(quic: Any, stream_handler: Any = None) -> RendezvousQuicProtocol:
        protocol = RendezvousQuicProtocol(quic, stream_handler, guard)
        protocol.boot_handler = handler
        return protocol

    return _create


async def serve_quic_port(
    port: int,
    *,
    host: str,
    config: QuicConfiguration,
    retry: bool,
    factory: Callable[[Any, Any], Any],
) -> tuple[Any, int]:
    """Bind one QUIC/UDP listener; returns ``(server, real_bound_port)``."""
    server = await serve(
        host,
        port,
        configuration=config,
        retry=retry,
        create_protocol=factory,
    )
    transport = server._transport
    sockname = transport.get_extra_info("sockname") if transport is not None else None
    return server, int(sockname[1]) if sockname is not None else int(port)
