"""``rdv/1`` data relay: pair two peers and pump their opaque TLS bytes.

The rendezvous is the only element of a p2p group that is always publicly
reachable, so it is also the only place that can join two peers whose NATs
accept no inbound connection (mobile CGNAT, a hotspot behind a carrier, hotel
Wi-Fi). The relay carries the peers' own TLS session **verbatim**: the node
never terminates it, never sees file names or content, and the two peers still
authenticate each other by certificate pinning. What the node does see is the
pairing (CID ↔ CID) and the byte volume, which is why the relay is disabled
only when the operator opts out (``--no-relay``) and is bounded by quotas.

Streams
-------
* A listener (the peer that serves: the p2p master) opens one **control** stream
  with ``relay_listen``; the node answers ``relay_listening`` and pushes one
  ``relay_incoming`` per requester. The listener answers with ``relay_ping``
  lines, which keep the QUIC connection alive while no session is running.
* A requester opens a **fresh** stream with ``relay_connect``; the node answers
  ``relay_ok`` and from that byte on the stream is opaque.
* The listener answers each ``relay_incoming`` with a **fresh** stream whose
  first line is ``relay_attach``; from there it is opaque too.

The pump is symmetric: two forwarding tasks, a fixed 64 KiB read buffer,
``drain()`` on both sides (so backpressure reaches the real sender), a per-
session byte cap and a per-session idle watchdog that drops the bridge after
``idle_timeout`` without traffic. Every counter kept here is an aggregate — no
CID, bucket, IP or port leaves this module.

Consumers: ``hsync_rendezvous.server`` (stream handoff), ``hsync_rendezvous.handler``
(validation/authorization), ``hsync_rendezvous.cli`` (the switch + quotas) and
the white-box tests.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Any

from hsync_common.ratelimit import TokenBucket

from hsync_rendezvous.diagnostics import debug_event, debug_log
from hsync_rendezvous.framing import FrameTooLarge, read_ndjson
from hsync_rendezvous.protocol import RdvError, RdvRelayAttach, RdvRelayConnect, RdvRelayListen
from hsync_rendezvous.relay_state import (
    Listener as _Listener,
)
from hsync_rendezvous.relay_state import (
    Pending as _Pending,
)
from hsync_rendezvous.relay_state import (
    PrefixedReader as PrefixedReader,
)
from hsync_rendezvous.relay_state import (
    RelayHandoff as RelayHandoff,
)
from hsync_rendezvous.relay_state import (
    RelayQuotas as RelayQuotas,
)
from hsync_rendezvous.relay_wire import close_writer as _close
from hsync_rendezvous.relay_wire import incoming_frame as _incoming
from hsync_rendezvous.relay_wire import is_ping as _is_ping
from hsync_rendezvous.relay_wire import listening_frame as _listening
from hsync_rendezvous.relay_wire import ok_frame as _ok
from hsync_rendezvous.relay_wire import refuse as _refuse
from hsync_rendezvous.relay_wire import terminate as _line
from hsync_rendezvous.stats import NodeStats

__all__ = [
    "RELAY_ATTACH_TIMEOUT_S",
    "RELAY_BUFFER_BYTES",
    "RELAY_ID_BYTES",
    "PrefixedReader",
    "RelayHandoff",
    "RelayQuotas",
    "RelayRegistry",
]

# Read/write chunk of one bridge. Fixed, so the memory a session can pin is
# bounded by ``sessions * 2 * RELAY_BUFFER_BYTES`` regardless of traffic shape.
RELAY_BUFFER_BYTES = 64 * 1024

# How long a listener has to attach a session the node announced. Long enough
# for a reconnect over a slow uplink, short enough that a dead listener cannot
# pin a pending session (and the requester's stream) indefinitely.
RELAY_ATTACH_TIMEOUT_S = 10.0

# Random session id width (``RelayId`` on the wire is its lowercase hex form).
RELAY_ID_BYTES = 16

# Bytes one control line may occupy (the ``relay_ping`` keepalive). The data
# streams are opaque and never framed, so this bound only protects the control
# stream parser.
_CONTROL_FRAME_BYTES = 1024


class RelayRegistry:
    """Listener registry, session pairing and byte pump (RAM only)."""

    def __init__(
        self,
        *,
        enabled: bool,
        quotas: RelayQuotas,
        stats: NodeStats,
        idle_timeout: float,
        attach_timeout: float = RELAY_ATTACH_TIMEOUT_S,
        ttl: int = 60,
    ) -> None:
        self.enabled = enabled
        self.quotas = quotas
        self.stats = stats
        self._idle_timeout = idle_timeout
        self._attach_timeout = attach_timeout
        self._ttl = ttl
        self._listeners: dict[tuple[str, str], _Listener] = {}
        self._pending: dict[str, _Pending] = {}
        self._sessions = 0
        self._per_ip: dict[str, int] = {}
        self._per_bucket: dict[str, int] = {}
        # Process-wide byte-rate shaper (shared token bucket): one second of
        # bytes of burst, refilled at the configured rate.
        self._bandwidth = (
            TokenBucket(
                capacity=float(quotas.bytes_per_second),
                refill=float(quotas.bytes_per_second),
                window=1.0,
            )
            if quotas.bytes_per_second
            else None
        )

    # -- introspection ---------------------------------------------------------

    @property
    def sessions(self) -> int:
        """Number of reserved relay sessions (pending or actively relaying)."""
        return self._sessions

    def has_listener(self, cid: str, bucket: str) -> bool:
        """Whether ``cid`` is currently listening for a relay on ``bucket``."""
        return (cid, bucket) in self._listeners

    # -- entry point -----------------------------------------------------------

    async def run(
        self,
        handoff: RelayHandoff,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
        admission: Any | None = None,
    ) -> None:
        """Take over one stream for the validated relay ``handoff``.

        ``admission`` is the connection's transport admission handle when the
        transport charges one (TLS/TCP): a matched ``relay_attach`` returns its
        generic admission through it (:meth:`_attach`), so a TCP listener's
        fan-out is bounded by the relay session quotas instead of the generic
        per-IP connection/handshake budget. ``None`` on QUIC, where the attach
        streams share the listener's one connection and are never charged.
        """
        if not handoff.authorized:
            _close(writer)
            return
        model = handoff.model
        if isinstance(model, RdvRelayListen):
            await self._listen(model, reader=reader, writer=writer, peer_ip=peer_ip)
        elif isinstance(model, RdvRelayConnect):
            await self._connect(model, reader=reader, writer=writer, peer_ip=peer_ip)
        else:
            await self._attach(
                model, reader=reader, writer=writer, peer_ip=peer_ip, admission=admission
            )

    # -- listener --------------------------------------------------------------

    async def _listen(
        self,
        model: RdvRelayListen,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
    ) -> None:
        """Hold one listener's control stream open and consume its keepalives."""
        key = (model.cid, model.bucket)
        previous = self._listeners.get(key)
        if previous is not None and previous.writer is not writer:
            # A reconnecting peer replaces its own listener: the previous control
            # stream belongs to a connection that is going away.
            self._listeners.pop(key, None)
            _close(previous.writer)
        listener = _Listener(
            cid=model.cid,
            bucket=model.bucket,
            group=model.group,
            peer_ip=peer_ip,
            writer=writer,
        )
        self._listeners[key] = listener
        debug_event("relay listener open", cid=model.cid, bucket=model.bucket)
        try:
            writer.write(_line(_listening(ttl=self._ttl)))
            await writer.drain()
            pending = bytearray()
            while True:
                try:
                    raw = await read_ndjson(
                        reader,
                        pending,
                        max_bytes=_CONTROL_FRAME_BYTES,
                        idle_timeout=self._idle_timeout,
                    )
                except FrameTooLarge:
                    # The control stream carries only keepalives, so an oversized
                    # line is a protocol violation: drop the listener.
                    return
                if raw is None:
                    return
                if not _is_ping(raw, model.cid, model.bucket):
                    # The control stream carries only keepalives, so anything
                    # else is a protocol violation: drop the listener.
                    return
        except (asyncio.CancelledError, ConnectionError, TimeoutError, OSError):
            return
        finally:
            if self._listeners.get(key) is listener:
                self._listeners.pop(key, None)
            debug_event("relay listener close", cid=model.cid, bucket=model.bucket)
            _close(writer)

    # -- requester -------------------------------------------------------------

    async def _deny(self, writer: Any, error: RdvError) -> None:
        """Answer one relay refusal and count it (aggregate only, never a peer)."""
        self.stats.refusal(error)
        await _refuse(writer, error)

    async def _connect(
        self,
        model: RdvRelayConnect,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
    ) -> None:
        """Pair the requester with a listener, then pump until either side ends."""
        listener = self._listeners.get((model.target_cid, model.bucket))
        if listener is None:
            await self._deny(writer, "relay_unavailable")
            return
        if not self._admit(peer_ip, model.bucket):
            await self._deny(writer, "overloaded")
            return
        relay_id = secrets.token_hex(RELAY_ID_BYTES)
        session = _Pending(
            listener=listener,
            dialer_cid=model.cid,
            dialer_ip=peer_ip,
            dialer_reader=reader,
            dialer_writer=writer,
            bucket=model.bucket,
        )
        self._pending[relay_id] = session
        listener.sessions += 1
        try:
            try:
                listener.writer.write(
                    _line(
                        _incoming(
                            relay_id=relay_id,
                            cid=model.cid,
                            expires_in=max(1, int(self._attach_timeout)),
                        )
                    )
                )
                await listener.writer.drain()
            except (ConnectionError, TimeoutError, OSError):
                await self._deny(writer, "relay_unavailable")
                return
            writer.write(_line(_ok(relay_id)))
            await writer.drain()
            try:
                await asyncio.wait_for(session.attached.wait(), self._attach_timeout)
            except TimeoutError:
                debug_event("relay attach timeout", cid=model.cid, bucket=model.bucket)
                return
            await self._pump(session)
        except (asyncio.CancelledError, ConnectionError, TimeoutError, OSError):
            return
        finally:
            self._pending.pop(relay_id, None)
            session.done.set()
            listener.sessions = max(0, listener.sessions - 1)
            self._release(session)
            _close(writer)
            if session.acceptor is not None:
                _close(session.acceptor[1])

    # -- listener side of one session -----------------------------------------

    async def _attach(
        self,
        model: RdvRelayAttach,
        *,
        reader: Any,
        writer: Any,
        peer_ip: str,
        admission: Any | None = None,
    ) -> None:
        """Hand a listener's fresh stream to the pending session it belongs to."""
        session = self._pending.get(model.relay_id)
        if (
            session is None
            or session.listener.cid != model.cid
            or session.listener.bucket != model.bucket
            or session.listener.peer_ip != peer_ip
            or session.acceptor is not None
        ):
            # Unmatched, foreign or duplicate attach: the stream closes with no
            # frame, so it is a counted drop rather than a wire refusal.
            self.stats.drop("relay_attach_refused")
            _close(writer)
            return
        # The attach matched a pending session, so this connection is bounded by
        # the relay session quotas that admitted it (global, per bucket, per
        # dialer IP) — not by the generic per-IP connection/handshake budget. On
        # TLS/TCP each attach is its own connection, so its generic admission is
        # returned here; QUIC passes no handle (attaches share the listener's one
        # connection and were never charged).
        if admission is not None:
            exempt = getattr(admission, "exempt", None)
            if exempt is not None:
                exempt()
        session.acceptor = (reader, writer)
        session.attached.set()
        try:
            await session.done.wait()
        except asyncio.CancelledError:
            return

    # -- pump ------------------------------------------------------------------

    async def _pump(self, session: _Pending) -> None:
        """Forward bytes both ways until one direction ends or a bound trips."""
        acceptor_reader, acceptor_writer = session.acceptor  # type: ignore[misc]
        debug_event("relay session open", cid=session.dialer_cid, bucket=session.bucket)
        self.stats.relay_session_opened()
        tasks = [
            asyncio.create_task(
                self._forward(session, session.dialer_reader, acceptor_writer),
                name="relay-forward-dialer",
            ),
            asyncio.create_task(
                self._forward(session, acceptor_reader, session.dialer_writer),
                name="relay-forward-acceptor",
            ),
        ]
        watchdog = asyncio.create_task(self._idle_watch(session))
        # The watchdog is one of the awaited tasks: when it fires (idle past
        # the deadline) the pump unblocks and cancels the two forwards, so a
        # silent session is torn down by the watchdog itself and a session
        # with traffic keeps pumping (the watchdog only returns on expiry).
        pump_tasks = [*tasks, watchdog]
        try:
            await asyncio.wait(pump_tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in pump_tasks:
                task.cancel()
            await asyncio.gather(*pump_tasks, return_exceptions=True)
            self.stats.relay_session_closed()
            debug_event(
                "relay session close",
                cid=session.dialer_cid,
                bucket=session.bucket,
                bytes=session.bytes,
            )

    async def _idle_watch(self, session: _Pending) -> None:
        """Close the session once it stays silent past the idle timeout.

        One wake-up per (estimated) expiry instead of a ``wait_for`` timer per
        forwarded chunk (a timer costs a few microseconds even when data is
        already buffered): the forward loops only update ``last_activity``, and
        this task sleeps straight to the next deadline, re-computing it after
        any activity. Closing both writers forces the forward tasks to see EOF,
        so the pump completes on its own.
        """
        try:
            while True:
                await asyncio.sleep(
                    max(0.0, session.last_activity + self._idle_timeout - time.monotonic())
                )
                if time.monotonic() - session.last_activity >= self._idle_timeout:
                    _close(session.dialer_writer)
                    if session.acceptor is not None:
                        _close(session.acceptor[1])
                    return
        except asyncio.CancelledError:
            return

    async def _forward(self, session: _Pending, reader: Any, writer: Any) -> None:
        """Copy one direction, enforcing the byte bounds.

        No per-chunk timer: ``reader.read`` returns immediately when the
        connection has buffered bytes and suspends otherwise, so the idle
        deadline is enforced by :meth:`_idle_watch` instead (one wake-up per
        session, not per chunk).
        """
        session_bytes = self.quotas.session_bytes
        stats = self.stats
        bandwidth = self._bandwidth
        while True:
            try:
                chunk = await reader.read(RELAY_BUFFER_BYTES)
            except (ConnectionError, OSError):
                return
            if not chunk:
                return
            session.bytes += len(chunk)
            session.last_activity = time.monotonic()
            if session_bytes and session.bytes > session_bytes:
                debug_event("relay session byte cap", cid=session.dialer_cid, bytes=session.bytes)
                return
            stats.relay_bytes(len(chunk))
            if bandwidth is not None:
                wait = bandwidth.charge(len(chunk))
                if wait:
                    await asyncio.sleep(wait)
            try:
                writer.write(chunk)
                await writer.drain()
            except (ConnectionError, TimeoutError, OSError):
                return

    # -- quotas ----------------------------------------------------------------

    def _admit(self, peer_ip: str, bucket: str) -> bool:
        """Reserve one session slot, or report ``overloaded`` (node capacity).

        The global, per-source and per-bucket ceilings mirror the routing-table
        shape: the per-bucket one is what a single bucket cannot rotate around,
        the per-source one what one abusive IP cannot exhaust.
        """
        if self._sessions >= self.quotas.max_sessions:
            return False
        if self._per_ip.get(peer_ip, 0) >= self.quotas.max_sessions_per_ip:
            return False
        if self._per_bucket.get(bucket, 0) >= self.quotas.max_sessions_per_bucket:
            return False
        self._sessions += 1
        self._per_ip[peer_ip] = self._per_ip.get(peer_ip, 0) + 1
        self._per_bucket[bucket] = self._per_bucket.get(bucket, 0) + 1
        return True

    def _release(self, session: _Pending) -> None:
        """Return the reserved session slot exactly once per session."""
        if not session.reserved:
            return
        session.reserved = False
        self._sessions = max(0, self._sessions - 1)
        for counters, key in (
            (self._per_ip, session.dialer_ip),
            (self._per_bucket, session.bucket),
        ):
            current = counters.get(key, 0) - 1
            if current > 0:
                counters[key] = current
            else:
                counters.pop(key, None)

    def close(self) -> None:
        """Drop every listener and pending session (shutdown path)."""
        for session in list(self._pending.values()):
            session.done.set()
            _close(session.dialer_writer)
            if session.acceptor is not None:
                _close(session.acceptor[1])
        self._pending.clear()
        for listener in list(self._listeners.values()):
            _close(listener.writer)
        self._listeners.clear()
        debug_log("relay registry closed")
