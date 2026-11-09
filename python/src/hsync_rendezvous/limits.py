"""Transport tuning constants shared by the QUIC and TLS/TCP listeners.

The directional bounds (frame, stream window, per-connection sessions, per-IP
admission) are the node's own anti-amplification and memory policy; keeping them
in one module lets the two transports and the shared session loop agree on the
same numbers without importing each other. ``hsync_common.protocol.rendezvous``
owns the wire SSOT (ALPN, idle timeout); this module owns the node's local
bounds.
"""

from __future__ import annotations

# Ingress bound for one rdv/1 frame (a register carries at most 16 endpoints).
# What the node *emits* is bounded separately by protocol.MAX_RESPONSE_BYTES.
MAX_FRAME_BYTES = 8192

# QUIC flow-control bounds: a request frame is at most MAX_FRAME_BYTES and the
# client only pipelines a few per stream, so the per-stream receive window bounds
# the server-side buffering per stream without stalling a legitimate exchange
# (responses are governed by the peer's own advertised limits). The
# connection-level window must cover every concurrent stream's share of that
# window, or it — not the per-stream one — becomes the throughput ceiling.
MAX_STREAM_DATA_BYTES = 4 * MAX_FRAME_BYTES

# Per-IP handshake admission and open-connection cap (the CLI also supplies a
# process-wide cap from ResourceLimits); RETRY only stops *amplified* (spoofed)
# handshakes, so the node needs its own budget — full rationale and sizing in
# the ConnectionGuard docstring.
#
# ``HANDSHAKE_RATE_PER_SECOND`` is the per-source CPU ceiling, so it stays the
# anti-flood bound; the burst covers a whole NAT umbrella starting at once,
# because a client opens one connection per exchange and a cold start performs
# a register plus its query burst back to back.
HANDSHAKE_RATE_PER_SECOND = 30
HANDSHAKE_BURST_PER_IP = 400
CONNECTION_ACTIVE_MAX_PER_IP = 256

# One rdv/1 exchange is one bidirectional stream, so a handful of concurrent
# sessions per connection is generous. aioquic hardcodes 128 concurrent bidi
# streams per connection; without this cap a peer could pin 128 session tasks
# (and 128x the per-connection memory budget) with streams it never closes.
# See RendezvousQuicProtocol._spawn_stream.
MAX_SESSIONS_PER_CONNECTION = 4
# Streams one connection may additionally hold for data-relay sessions: the
# listener keeps one control stream plus one stream per relayed peer, so the
# bound has to cover them without letting a connection pin unbounded tasks.
MAX_RELAY_STREAMS_PER_CONNECTION = 32
# The connection window must span every relay stream's per-stream window: a
# relayed session multiplexes one stream per bridged TCP connection, so a
# connection cap below the sum throttled each transfer to the shared budget and
# capped relayed throughput well under the per-stream allowance.
MAX_DATA_BYTES = MAX_RELAY_STREAMS_PER_CONNECTION * MAX_STREAM_DATA_BYTES

# One TLS/TCP connection = one rdv/1 session. Bounded handshake so a stalled TLS
# handshake (slow-loris, a dead client) cannot pin the guard's active slot
# indefinitely. QUIC bounds the same hazard through aioquic's own handshake
# timeout, so this constant applies to the TLS/TCP accept path only.
TCP_HANDSHAKE_TIMEOUT = 10.0
# Listen backlog of the TLS/TCP listener (the asyncio default, made explicit).
TCP_LISTEN_BACKLOG = 100

__all__ = [
    "CONNECTION_ACTIVE_MAX_PER_IP",
    "HANDSHAKE_BURST_PER_IP",
    "HANDSHAKE_RATE_PER_SECOND",
    "MAX_DATA_BYTES",
    "MAX_FRAME_BYTES",
    "MAX_RELAY_STREAMS_PER_CONNECTION",
    "MAX_SESSIONS_PER_CONNECTION",
    "MAX_STREAM_DATA_BYTES",
    "TCP_HANDSHAKE_TIMEOUT",
    "TCP_LISTEN_BACKLOG",
]
