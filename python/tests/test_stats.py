"""Aggregate counters: levels, event-exact peaks and the Prometheus exposition.

The node is no-log, so these are the only numbers it exposes: they must keep the
no-log invariant (no CID, bucket, IP or port), stay bounded (fixed cardinality)
and stay cheap (a couple of integer operations on the hot path).
"""

from __future__ import annotations

import re
import time

from hsync_rendezvous import __version__
from hsync_rendezvous.stats import (
    DROP_REASONS,
    LIMITERS,
    METRICS_OUTCOMES,
    REFUSAL_REASONS,
    NodeStats,
)

# A sample line: the metric name, an optional label block, one numeric value.
_SAMPLE_RE = re.compile(r"hsync_rendezvous_[a-z0-9_]+(\{[^}]*\})? -?[0-9.]+")


def test_levels_and_peaks_follow_the_events() -> None:
    stats = NodeStats()
    stats.connections_changed(2, opened=True)
    stats.connections_changed(5, opened=True)
    stats.connections_changed(1)
    # The level follows the last observation; the peak never decreases.
    assert (stats.connections_current, stats.connections_peak) == (1, 5)
    assert stats.connections_total == 2

    stats.peers_changed(7, written=True)
    stats.peers_changed(3)
    assert (stats.peers_current, stats.peers_peak) == (3, 7)
    assert stats.peers_updates_total == 1
    assert stats.peers_expired_total == 0


def test_a_peak_records_when_it_was_reached() -> None:
    stats = NodeStats()
    before = time.time()
    stats.peers_changed(4, written=True)
    assert before <= stats.peers_peak_at <= time.time()
    # A later, lower level must not move the stamp.
    stamped = stats.peers_peak_at
    stats.peers_changed(1)
    assert stats.peers_peak_at == stamped


def test_expirations_lower_the_level_but_never_the_peak() -> None:
    stats = NodeStats()
    stats.peers_changed(10, written=True)
    stats.peers_changed(6, expired=4)
    assert stats.peers_current == 6
    assert stats.peers_peak == 10
    assert stats.peers_expired_total == 4


def test_unknown_outcomes_cannot_grow_the_series() -> None:
    stats = NodeStats()
    stats.metrics_request("ok")
    stats.metrics_request("not-an-outcome")
    assert sum(stats.metrics_requests.values()) == 1
    assert set(stats.metrics_requests) == set(METRICS_OUTCOMES)


def test_refusals_are_counted_by_reason_and_summed() -> None:
    stats = NodeStats()
    stats.refusal("rate_limited")
    stats.refusal("rate_limited")
    stats.refusal("token_required")
    assert stats.refusals["rate_limited"] == 2
    assert stats.refusals_total == 3
    assert set(stats.refusals) == set(REFUSAL_REASONS)


def test_limit_hits_and_drops_ignore_unknown_labels() -> None:
    """Both label sets are closed: an unknown value cannot grow the series."""
    stats = NodeStats()
    stats.limit_hit("query_pair")
    stats.limit_hit("not-a-limiter")
    stats.drop("invalid_frame")
    stats.drop("not-a-reason")
    assert stats.limit_hits["query_pair"] == 1
    assert sum(stats.limit_hits.values()) == 1
    assert stats.drops["invalid_frame"] == 1
    assert sum(stats.drops.values()) == 1
    assert set(stats.limit_hits) == set(LIMITERS)
    assert set(stats.drops) == set(DROP_REASONS)


def test_status_text_is_one_short_line() -> None:
    stats = NodeStats()
    stats.connections_changed(3, opened=True)
    stats.transport_connections_changed("quic", 3, opened=True)
    stats.peers_changed(12, written=True)
    stats.relay_session_opened()
    stats.refusal("rate_limited")
    assert stats.status_text() == "conn=3/3 quic=3 tcp=0 peers=12/12 relay=1/1 refused=1"
    assert "\n" not in stats.status_text()


def test_exposition_has_a_fixed_cardinality_and_valid_types() -> None:
    stats = NodeStats()
    stats.connections_changed(3, opened=True)
    stats.peers_changed(11, written=True)
    stats.metrics_request("ok")
    body = stats.render_prometheus()

    samples = [line for line in body.splitlines() if line and not line.startswith("#")]
    # 8 connection gauges/counters (4 families x the closed quic/tcp label set)
    # + peer gauges/counters (5) + the 5 aggregate relay series + stats-write
    # error + build/start (2) + one line per closed outcome + one line per
    # closed refusal reason, limiter and drop reason: pinned so a new label or
    # series cannot slip in.
    assert len(samples) == 21 + len(METRICS_OUTCOMES) + len(REFUSAL_REASONS) + len(LIMITERS) + len(
        DROP_REASONS
    )
    for line in samples:
        assert _SAMPLE_RE.fullmatch(line), line
    for line in body.splitlines():
        if line.startswith("# TYPE"):
            assert line.split()[3] in ("gauge", "counter")


def test_exposition_never_carries_peer_data() -> None:
    """Every label is a closed set: build identity, outcomes, reasons, transports."""
    body = NodeStats().render_prometheus()
    assert set(re.findall(r'([a-z_]+)="', body)) == {
        "version",
        "protocol",
        "outcome",
        "reason",
        "limiter",
        "transport",
    }
    assert f'version="{__version__}"' in body
    assert 'protocol="rdv/1"' in body
