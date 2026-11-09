"""Peer-free operational counters for the rendezvous node (RAM only, O(1)).

The node is no-log: nothing peer-related may reach disk. These aggregates carry no
CID, bucket, IP or port, so they are the only operational numbers the node
exposes \u2014 the service manager's ``STATUS=``, the Prometheus text file and the
loopback ``/metrics`` endpoint (``hsync_rendezvous.metrics``).

A level is observed where the event happens (a connection admitted or released, a
record upserted or removed) instead of being sampled: ``rdv/1`` clients open one
connection per exchange and let it idle out after 30 s, so a concurrency spike is
shorter than any sane sampling interval and a sampled peak would systematically
under-report it. A peak never decreases and nothing is persisted, so it covers
the lifetime of the process; long-term history is the monitoring system's job.

The same rule covers the refusal side of the protocol: every refusal the node
answers is counted by ``RdvError`` reason (what a client sees), every rate-limit
refusal is additionally counted by the budget that ran dry (which limit clipped
a source), and every frame dropped without a reply is counted by reason. That
pair is what tells an operator whether a limit is clipping legitimate traffic and
which one to re-size; no label ever carries a peer identity.

Consumers: ``hsync_rendezvous.server`` (connection guard), ``hsync_rendezvous.handler``
(registered peers and refusals), ``hsync_rendezvous.relay`` (relay refusals),
``hsync_rendezvous.session`` (oversized-frame drops), ``hsync_rendezvous.metrics``
(exposition) and ``hsync_rendezvous.cli`` (the periodic sink and the banner).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal, get_args

from hsync_rendezvous import __version__
from hsync_rendezvous.protocol import PROTOCOL_VERSION_RDV, RdvError

__all__ = [
    "DROP_REASONS",
    "LIMITERS",
    "METRICS_OUTCOMES",
    "NodeStats",
    "REFUSAL_REASONS",
]

# Outcomes the metrics endpoint can answer, in exposition order. The set is
# closed: an unknown outcome is not recorded, so the series cannot grow with
# caller input.
METRICS_OUTCOMES = (
    "ok",
    "unauthorized",
    "not_found",
    "method_not_allowed",
    "rate_limited",
    "unavailable",
)

# Connection metric families carry a closed ``transport`` label. Both series are
# always rendered: a node with one transport disabled must still expose a 0 for
# it, so a dashboard or alert never silently loses a series.
CONNECTION_TRANSPORTS = ("quic", "tcp")

# Refusal reasons are the ``rdv/1`` error domain itself (``RdvError``): deriving
# the tuple from the type keeps the exposition from drifting away from the wire
# contract when a reason is added or removed.
REFUSAL_REASONS: tuple[str, ...] = tuple(get_args(RdvError))

# The node's rate-limit budgets, as ``limiter`` label values: one series per
# budget tells an operator which limit clipped a source, which is the input
# capacity planning needs (``refusals_total`` alone only says *that* it did).
LimitName = Literal[
    "ops_ip",
    "query_pair",
    "query_ip",
    "register_pair",
    "relay_connect_pair",
    "relay_listen_pair",
    "bad_token_ip",
    "parse_ip",
]
LIMITERS: tuple[str, ...] = tuple(get_args(LimitName))

# Frames the node drops without answering (no oracle): bounded by their own
# budget instead of a spec error, so they are invisible on the wire and only
# visible here.
DropReason = Literal[
    "invalid_frame",
    "oversized_frame",
    "pre_parse_gate",
    "foreign_source",
    "relay_attach_refused",
]
DROP_REASONS: tuple[str, ...] = tuple(get_args(DropReason))


def _prom_escape(value: str) -> str:
    """Escape a Prometheus label value (backslash, double quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _render_labelled_counter(
    name: str,
    help_text: str,
    label: str,
    counts: dict[str, int],
    values: tuple[str, ...],
) -> list[str]:
    """Prometheus lines for one counter family with a closed label set.

    Every value is always rendered, so a scrape never loses a series because it
    has not been hit yet on this process (a dashboard or alert depends on it).
    """
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
    lines.extend(f'{name}{{{label}="{value}"}} {counts.get(value, 0)}' for value in values)
    return lines


def _render_connection_lines(stats: NodeStats) -> list[str]:
    """Prometheus lines for the connection families, labelled by transport.

    Each family is emitted once (HELP + TYPE) with one series per transport, so a
    QUIC-only or TCP-only node still yields both series and a scrape never loses
    a series depending on which transport is enabled.
    """
    families = (
        (
            "gauge",
            "hsync_rendezvous_connections_current",
            "Open connections by transport.",
            lambda transport: stats.transport_connections_current.get(transport, 0),
        ),
        (
            "gauge",
            "hsync_rendezvous_connections_peak",
            "Highest open-connection level by transport.",
            lambda transport: stats.transport_connections_peak.get(transport, 0),
        ),
        (
            "gauge",
            "hsync_rendezvous_connections_peak_timestamp_seconds",
            "When the per-transport peak was reached.",
            lambda transport: f"{stats.transport_connections_peak_at.get(transport, 0.0):.3f}",
        ),
        (
            "counter",
            "hsync_rendezvous_connections_total",
            "Admitted connections by transport.",
            lambda transport: stats.transport_connections_total.get(transport, 0),
        ),
    )
    lines: list[str] = []
    for kind, name, help_text, value_of in families:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        lines.extend(
            f'{name}{{transport="{transport}"}} {value_of(transport)}'
            for transport in CONNECTION_TRANSPORTS
        )
    return lines


@dataclass(slots=True)
class NodeStats:
    """Levels, peaks and lifetime counters of one node process.

    Levels and peaks are integers maintained in O(1) on the event path; the
    ``*_peak_at`` stamps are wall-clock (epoch seconds) so they can be compared
    with a monitoring time series, never ``monotonic()``.
    """

    started_at: float = field(default_factory=time.time)
    connections_current: int = 0
    connections_peak: int = 0
    connections_peak_at: float = 0.0
    connections_total: int = 0
    # Per-transport open-connection levels and their totals (closed set:
    # ``quic``/``tcp``). The ``connections_*`` fields above span both
    # transports; these feed the per-transport gauges. ``exempt`` (TCP relay
    # fan-out) does not lower them — metrics keep counting every open
    # connection until it really closes.
    transport_connections_current: dict[str, int] = field(default_factory=dict)
    transport_connections_peak: dict[str, int] = field(default_factory=dict)
    transport_connections_peak_at: dict[str, float] = field(default_factory=dict)
    transport_connections_total: dict[str, int] = field(default_factory=dict)
    peers_current: int = 0
    peers_peak: int = 0
    peers_peak_at: float = 0.0
    peers_updates_total: int = 0
    peers_expired_total: int = 0
    relay_sessions_current: int = 0
    relay_sessions_peak: int = 0
    relay_sessions_peak_at: float = 0.0
    relay_sessions_total: int = 0
    relay_bytes_total: int = 0
    metrics_requests: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(METRICS_OUTCOMES, 0)
    )
    # Refusals the node answered on the wire, by ``RdvError`` reason: the client's
    # own view of the node (what it saw, not why).
    refusals: dict[str, int] = field(default_factory=lambda: dict.fromkeys(REFUSAL_REASONS, 0))
    # Which budget produced a ``rate_limited``: the operator's view of the same
    # event, and the input for re-sizing a limit.
    limit_hits: dict[str, int] = field(default_factory=lambda: dict.fromkeys(LIMITERS, 0))
    drops: dict[str, int] = field(default_factory=lambda: dict.fromkeys(DROP_REASONS, 0))
    stats_write_errors: int = 0

    def connections_changed(self, current: int, *, opened: bool = False) -> None:
        """Record the open-connection level, ``opened`` on one admitted connection."""
        self.connections_current = current
        if opened:
            self.connections_total += 1
        if current > self.connections_peak:
            self.connections_peak = current
            self.connections_peak_at = time.time()

    def transport_connections_changed(
        self, transport: str, level: int, *, opened: bool = False
    ) -> None:
        """Record one transport's open-connection level (``quic``/``tcp``)."""
        self.transport_connections_current[transport] = level
        if opened:
            self.transport_connections_total[transport] = (
                self.transport_connections_total.get(transport, 0) + 1
            )
        if level > self.transport_connections_peak.get(transport, 0):
            self.transport_connections_peak[transport] = level
            self.transport_connections_peak_at[transport] = time.time()

    def peers_changed(self, current: int, *, written: bool = False, expired: int = 0) -> None:
        """Record the registered-peer level; ``written`` counts a register/refresh write."""
        self.peers_current = current
        if written:
            self.peers_updates_total += 1
        if expired:
            self.peers_expired_total += expired
        if current > self.peers_peak:
            self.peers_peak = current
            self.peers_peak_at = time.time()

    def metrics_request(self, outcome: str) -> None:
        """Count one ``/metrics`` request outcome (unknown outcomes are ignored)."""
        if outcome in self.metrics_requests:
            self.metrics_requests[outcome] += 1

    def refusal(self, reason: RdvError) -> None:
        """Count one refusal frame answered on the wire (closed ``RdvError`` domain)."""
        if reason in self.refusals:
            self.refusals[reason] += 1

    def limit_hit(self, limiter: str) -> None:
        """Count one budget that ran dry (closed ``LIMITERS`` domain)."""
        if limiter in self.limit_hits:
            self.limit_hits[limiter] += 1

    def drop(self, reason: str) -> None:
        """Count one silently dropped frame (closed ``DROP_REASONS`` domain)."""
        if reason in self.drops:
            self.drops[reason] += 1

    @property
    def refusals_total(self) -> int:
        """Every refusal answered since start (the ``STATUS=`` summary number)."""
        return sum(self.refusals.values())

    def relay_session_opened(self) -> None:
        """Record one relay session starting to relay bytes."""
        self.relay_sessions_current += 1
        self.relay_sessions_total += 1
        if self.relay_sessions_current > self.relay_sessions_peak:
            self.relay_sessions_peak = self.relay_sessions_current
            self.relay_sessions_peak_at = time.time()

    def relay_session_closed(self) -> None:
        """Record one relay session ending (the level never goes below zero)."""
        self.relay_sessions_current = max(0, self.relay_sessions_current - 1)

    def relay_bytes(self, count: int) -> None:
        """Count relayed bytes (one aggregate, never per peer)."""
        self.relay_bytes_total += count

    def stats_write_failed(self) -> None:
        """Count one failed periodic write of the Prometheus text file."""
        self.stats_write_errors += 1

    def status_text(self) -> str:
        """One-line summary for the service manager's ``STATUS=`` assignment."""
        quic = self.transport_connections_current.get("quic", 0)
        tcp = self.transport_connections_current.get("tcp", 0)
        return (
            f"conn={self.connections_current}/{self.connections_peak} "
            f"quic={quic} tcp={tcp} "
            f"peers={self.peers_current}/{self.peers_peak} "
            f"relay={self.relay_sessions_current}/{self.relay_sessions_peak} "
            f"refused={self.refusals_total}"
        )

    def render_prometheus(self) -> str:
        """Prometheus text exposition: fixed cardinality, never peer-identifying."""
        version = _prom_escape(__version__)
        protocol = _prom_escape(PROTOCOL_VERSION_RDV)
        lines = [
            "# HELP hsync_rendezvous_build_info Identity of the running node.",
            "# TYPE hsync_rendezvous_build_info gauge",
            f'hsync_rendezvous_build_info{{version="{version}",protocol="{protocol}"}} 1',
        ]
        lines.extend(_render_connection_lines(self))
        metrics = (
            (
                "gauge",
                "hsync_rendezvous_start_time_seconds",
                "Unix time the process started.",
                f"{self.started_at:.3f}",
            ),
            (
                "gauge",
                "hsync_rendezvous_peers_current",
                "Peers registered right now (TTL-bounded).",
                self.peers_current,
            ),
            (
                "gauge",
                "hsync_rendezvous_peers_peak",
                "Highest registered-peer level.",
                self.peers_peak,
            ),
            (
                "gauge",
                "hsync_rendezvous_peers_peak_timestamp_seconds",
                "When the peak was reached.",
                f"{self.peers_peak_at:.3f}",
            ),
            (
                "counter",
                "hsync_rendezvous_peers_updates_total",
                "Accepted register/refresh writes.",
                self.peers_updates_total,
            ),
            (
                "counter",
                "hsync_rendezvous_peers_expired_total",
                "Records dropped by the TTL sweep.",
                self.peers_expired_total,
            ),
            (
                "gauge",
                "hsync_rendezvous_relay_sessions_current",
                "Relayed sessions right now.",
                self.relay_sessions_current,
            ),
            (
                "gauge",
                "hsync_rendezvous_relay_sessions_peak",
                "Highest relayed-session level.",
                self.relay_sessions_peak,
            ),
            (
                "gauge",
                "hsync_rendezvous_relay_sessions_peak_timestamp_seconds",
                "When the peak was reached.",
                f"{self.relay_sessions_peak_at:.3f}",
            ),
            (
                "counter",
                "hsync_rendezvous_relay_sessions_total",
                "Relay sessions opened.",
                self.relay_sessions_total,
            ),
            (
                "counter",
                "hsync_rendezvous_relay_bytes_total",
                "Bytes forwarded by the relay.",
                self.relay_bytes_total,
            ),
        )
        lines.extend(
            line
            for kind, name, help_text, value in metrics
            for line in (
                f"# HELP {name} {help_text}",
                f"# TYPE {name} {kind}",
                f"{name} {value}",
            )
        )
        lines.extend(
            [
                "# HELP hsync_rendezvous_metrics_requests_total Requests answered by /metrics.",
                "# TYPE hsync_rendezvous_metrics_requests_total counter",
            ]
        )
        lines.extend(
            f'hsync_rendezvous_metrics_requests_total{{outcome="{outcome}"}} '
            f"{self.metrics_requests[outcome]}"
            for outcome in METRICS_OUTCOMES
        )
        lines.extend(
            _render_labelled_counter(
                "hsync_rendezvous_refusals_total",
                "Refusal frames answered, by reason.",
                "reason",
                self.refusals,
                REFUSAL_REASONS,
            )
        )
        lines.extend(
            _render_labelled_counter(
                "hsync_rendezvous_limit_hits_total",
                "Rate-limit refusals, by the budget that ran dry.",
                "limiter",
                self.limit_hits,
                LIMITERS,
            )
        )
        lines.extend(
            _render_labelled_counter(
                "hsync_rendezvous_drops_total",
                "Frames dropped without a reply, by reason.",
                "reason",
                self.drops,
                DROP_REASONS,
            )
        )
        lines.extend(
            (
                "# HELP hsync_rendezvous_stats_write_errors_total Failed stats-file writes.",
                "# TYPE hsync_rendezvous_stats_write_errors_total counter",
                f"hsync_rendezvous_stats_write_errors_total {self.stats_write_errors}",
            )
        )
        return "\n".join(lines) + "\n"
