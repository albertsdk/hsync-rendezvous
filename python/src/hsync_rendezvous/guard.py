"""Per-IP transport admission for one listener process (RAM only).

The :class:`ConnectionGuard` is charged by both transports before any handshake
work and released on connection teardown, and it feeds the connection metrics
(open level, peak, per transport). It never persists anything (no-log).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from hsync_rendezvous.limits import (
    CONNECTION_ACTIVE_MAX_PER_IP,
    HANDSHAKE_BURST_PER_IP,
    HANDSHAKE_RATE_PER_SECOND,
)
from hsync_rendezvous.ratelimit import TokenBucketLimiter
from hsync_rendezvous.stats import NodeStats

__all__ = ["ConnectionGuard"]


@dataclass(slots=True)
class _PeerState:
    """Per-IP open-connection count and last-seen stamp (eviction input)."""

    count: int
    last_seen: float


class ConnectionGuard:
    """Per-IP transport admission gate for one listener process (RAM only).

    Two controls, both bound to the peer's source IP and never persisted
    (no-log): a token-bucket on new connections (the TLS handshake is the only
    step any RETRY-protected QUIC server cannot refuse for free) and a ceiling
    on simultaneously-open connections — per source IP and, when a process-wide
    ceiling is supplied, across every source (each connection may hold up to 128
    QUIC streams, so unbounded connections also mean unbounded idle-task memory).

    Sizing (see the module constants): the handshake budget stays far above
    what a whole NAT umbrella of legitimate clients can produce — they open a
    connection per exchange and idle out after 30 s — while a single-IP flood
    is throttled to at most ``handshake_burst`` new handshakes per second.
    """

    def __init__(
        self,
        *,
        handshake_rate: float = HANDSHAKE_RATE_PER_SECOND,
        handshake_burst: int = HANDSHAKE_BURST_PER_IP,
        active_max: int = CONNECTION_ACTIVE_MAX_PER_IP,
        global_max: int | None = None,
        stats: NodeStats | None = None,
    ) -> None:
        # Peer-free operational counters (RAM only); the transport is where a
        # connection actually opens and closes, so the level is observed here.
        self.stats = stats if stats is not None else NodeStats()
        self._handshakes = TokenBucketLimiter(
            capacity=handshake_burst, refill=handshake_rate, window=1.0
        )
        self._active_max = active_max
        self._global_max = global_max
        self._total_active = 0
        # Open-connection level per transport (``quic``/``tcp``): the global
        # ceiling spans both, but the per-transport level is what tells an
        # operator how much of it each transport holds.
        self._per_transport: dict[str, int] = {}
        # Metric levels (open connections, per transport and total) kept apart
        # from the admission counts above: a TCP relay attach that was exempted
        # no longer competes for the per-IP/global budget, but the metrics keep
        # counting it until the connection really closes.
        self._metric_total = 0
        self._metric_per_transport: dict[str, int] = {}
        # Seconds an IP must stay quiet (with all of its connections closed)
        # before evict_stale() forgets it: capacity/rate refills the bucket to
        # exactly the first-use value, so forgetting is decision-neutral.
        self._quiet_horizon = handshake_burst / handshake_rate
        # ip -> open connection count + last-seen stamp (see evict_stale).
        self._active: dict[str, _PeerState] = {}

    def admit(self, peer_ip: str, *, transport: str = "quic", now: float | None = None) -> bool:
        """Admit one new (connecting) connection from ``peer_ip``.

        Returns False when the IP has no handshake budget left, already holds
        ``active_max`` open connections, or the process-wide ``global_max``
        ceiling would be exceeded; the caller must then refuse the connection
        instead of running its handshake. ``transport`` tags the connection
        (``quic``/``tcp``) for the per-transport level; ``global_max`` spans
        every transport.
        """
        now = time.monotonic() if now is None else now
        entry = self._active.get(peer_ip)
        if entry is not None and entry.count >= self._active_max:
            return False
        if self._global_max is not None and self._total_active >= self._global_max:
            self._note(peer_ip, now)
            return False
        if not self._handshakes.allow(peer_ip, now=now):
            self._note(peer_ip, now)
            return False
        if entry is None:
            self._active[peer_ip] = _PeerState(count=1, last_seen=now)
        else:
            entry.count += 1
            entry.last_seen = now
        self._total_active += 1
        self._per_transport[transport] = self._per_transport.get(transport, 0) + 1
        self._metric_total += 1
        self._metric_per_transport[transport] = self._metric_per_transport.get(transport, 0) + 1
        self.stats.connections_changed(self._metric_total, opened=True)
        self.stats.transport_connections_changed(
            transport, self._metric_per_transport[transport], opened=True
        )
        return True

    def release(self, peer_ip: str, *, transport: str = "quic", now: float | None = None) -> None:
        """Mark one admitted connection from ``peer_ip`` as closed (full accounting)."""
        self._admission_release(peer_ip, transport, now)
        self._metrics_release(transport)

    def exempt(self, peer_ip: str, *, transport: str = "tcp", now: float | None = None) -> None:
        """Return one admitted connection's generic admission (TCP relay fan-out).

        The inverse of :meth:`admit` for a connection that belongs to a relay
        listener's fan-out: a TLS/TCP listener opens one connection per
        ``relay_attach``, and those are bounded by the relay session quotas, not
        the generic per-IP connection/handshake budget. Once the relay registry
        matches an attach it calls this through the connection's admission
        handle: the per-IP and process-wide active counts drop and the handshake
        token is refunded (never above ``handshake_burst``). Only the admission
        accounting is adjusted here — the metrics keep counting the open
        connection until it really closes (:meth:`release_metrics`).
        """
        self._admission_release(peer_ip, transport, now)
        self._handshakes.refund(peer_ip)

    def release_metrics(self, *, transport: str = "tcp") -> None:
        """Decrement the metric level for one closing exempted connection."""
        self._metrics_release(transport)

    def _admission_release(self, peer_ip: str, transport: str, now: float | None) -> None:
        self._total_active = max(0, self._total_active - 1)
        self._per_transport[transport] = max(0, self._per_transport.get(transport, 0) - 1)
        entry = self._active.get(peer_ip)
        if entry is None:
            return
        entry.count = max(0, entry.count - 1)
        entry.last_seen = time.monotonic() if now is None else now

    def _metrics_release(self, transport: str) -> None:
        self._metric_total = max(0, self._metric_total - 1)
        self._metric_per_transport[transport] = max(
            0, self._metric_per_transport.get(transport, 0) - 1
        )
        self.stats.connections_changed(self._metric_total)
        self.stats.transport_connections_changed(transport, self._metric_per_transport[transport])

    def transport_count(self, transport: str) -> int:
        """Open connections currently admitted for one transport (``quic``/``tcp``)."""
        return self._per_transport.get(transport, 0)

    def open_count(self, peer_ip: str) -> int:
        """Active connections currently accounted for (``0`` when unknown)."""
        entry = self._active.get(peer_ip)
        return entry.count if entry is not None else 0

    def total_count(self) -> int:
        """Process-wide admitted-connection count (``global_max`` accounting)."""
        return self._total_active

    def evict_stale(self, now: float | None = None) -> int:
        """Forget an IP once all of its connections closed and it went quiet.

        A refilled handshake bucket (``capacity / rate`` since last seen)
        behaves identically to a fresh one, so forgetting that IP cannot
        change any decision; this bounds the map under IP churn.
        """
        now = time.monotonic() if now is None else now
        stale = [
            ip
            for ip, entry in self._active.items()
            if entry.count <= 0 and now - entry.last_seen >= self._quiet_horizon
        ]
        for ip in stale:
            del self._active[ip]
        return len(stale)

    def _note(self, peer_ip: str, now: float) -> None:
        """Stamp the last-seen time so evict_stale() can reap refused IPs too."""
        entry = self._active.get(peer_ip)
        if entry is not None:
            entry.last_seen = now
