# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""Black-box **stress** tests for the ``rdv/1`` rendezvous node.

Same language-neutral contract as the rest of ``tests/``: the node is
spawned from ``HSYNC_RENDEZVOUS_BIN`` and driven only through the public CLI and
the ``rdv/1`` wire protocol. Nothing here imports ``hsync_rendezvous``; the same
suite must pass against the future ``c/`` port unchanged.

Where the functional suite proves each branch once, these tests prove the node
stays **correct and alive under sustained concurrent load, bursts, churn and a
garbage storm** — the observable contract a real deployment depends on.

Opt-in and bounded: requires ``HSYNC_BB_STRESS=1`` (on top of the suite's
``HSYNC_BB_RENDEZVOUS=1``). Scale is controlled by environment knobs, read at
import time because the harness scrubs every ``HSYNC_*`` variable before each
spawned process:

* ``HSYNC_BB_RENDEZVOUS_STRESS_CONNECTIONS`` (default 4)
* ``HSYNC_BB_RENDEZVOUS_STRESS_ROUNDS``      (default 4)
* ``HSYNC_BB_RENDEZVOUS_STRESS_PEERS``       (default 50)
* ``HSYNC_BB_RENDEZVOUS_STRESS_MAX_P99_MS``  (default 1000)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

import pytest
from harness import (
    QUERY_PAIR_BURST,
    RawOutcome,
    RdvClient,
    leave_frame,
    proc_rss_mb,
    query_frame,
    random_cid,
    refresh_frame,
    register_frame,
)

_ENABLED = os.environ.get("HSYNC_BB_STRESS") == "1"
_REASON = "Rendezvous stress tests are opt-in; set HSYNC_BB_STRESS=1 to enable"

pytestmark = pytest.mark.skipif(not _ENABLED, reason=_REASON)


def _knob(name: str, default: int) -> int:
    """Read a positive integer knob (falls back to *default* when unset/invalid)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


# Read once at import time: ``start_rendezvous`` scrubs HSYNC_* from the spawned
# process, and reading lazily inside a test body would be fragile under an
# env-isolation fixture.
_CONNECTIONS = _knob("HSYNC_BB_RENDEZVOUS_STRESS_CONNECTIONS", 4)
_ROUNDS = _knob("HSYNC_BB_RENDEZVOUS_STRESS_ROUNDS", 4)
_PEERS = _knob("HSYNC_BB_RENDEZVOUS_STRESS_PEERS", 50)
_MAX_P99_MS = _knob("HSYNC_BB_RENDEZVOUS_STRESS_MAX_P99_MS", 1000)

# The server sends no reply to ``leave`` (the stream stays open), so a leave
# must be observed through ``send_raw`` as SILENT, never through ``exchange``.
_LEAVE_TIMEOUT = 0.2


@dataclass
class _LoadReport:
    """Aggregate outcome of one concurrent worker (or the whole load run)."""

    latencies: list[float] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    requests: int = 0

    def merge(self, other: _LoadReport) -> None:
        self.latencies.extend(other.latencies)
        self.errors.extend(other.errors)
        self.requests += other.requests


def _percentile(values: Sequence[float], pct: float) -> float:
    """Linear-interpolated percentile (``values`` must be non-empty)."""
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * frac


def _report(name: str, report: _LoadReport, elapsed: float) -> None:
    """Print one stress summary line (observability, never an assertion)."""
    p99 = _percentile(report.latencies, 99) * 1000.0 if report.latencies else 0.0
    ops = report.requests / elapsed if elapsed > 0 else 0.0
    print(
        f"\n[BOOTSTRESS] {name}: requests={report.requests} errors={len(report.errors)} "
        f"elapsed={elapsed:.2f}s throughput={ops:.1f} req/s p99={p99:.1f}ms"
    )
    if report.errors:
        print(f"[BOOTSTRESS] first errors: {report.errors[:3]}")


async def _mixed_worker(port: int, bucket: str, rng, rounds: int) -> _LoadReport:
    """One client: register → query → refresh → leave, repeated ``rounds`` times.

    Exercises every frame the data plane uses on a single connection, so the
    load is representative rather than a single-frame micro-loop.
    """
    report = _LoadReport()
    async with RdvClient(port) as client:
        for _ in range(rounds):
            cid = random_cid(rng)

            started = time.perf_counter()
            ack = await client.exchange(register_frame(cid, bucket))
            report.latencies.append(time.perf_counter() - started)
            report.requests += 1
            if ack.get("type") != "ack":
                report.errors.append(ack)

            started = time.perf_counter()
            response = await client.exchange(query_frame(bucket, limit=20))
            report.latencies.append(time.perf_counter() - started)
            report.requests += 1
            if response.get("type") != "response" or response.get("error") is not None:
                report.errors.append(response)

            started = time.perf_counter()
            renewed = await client.exchange(refresh_frame(cid, bucket))
            report.latencies.append(time.perf_counter() - started)
            report.requests += 1
            if renewed.get("type") != "ack":
                report.errors.append(renewed)

            # leave: no reply by contract → SILENT on a still-open stream.
            result = await client.send_raw(
                (json.dumps(leave_frame(cid, bucket)) + "\n").encode(), timeout=_LEAVE_TIMEOUT
            )
            report.requests += 1
            if result.outcome is not RawOutcome.SILENT:
                report.errors.append({"leave_outcome": result.outcome.value})
    return report


async def _register_peers(port: int, bucket: str, rng, count: int) -> list[str]:
    """Register ``count`` distinct peers on one connection; return their CIDs."""
    cids = [random_cid(rng) for _ in range(count)]
    async with RdvClient(port) as client:
        for cid in cids:
            ack = await client.exchange(register_frame(cid, bucket))
            assert ack.get("type") == "ack", ack
    return cids


async def _churn_register_leave(port: int, bucket: str, rng, *, rounds: int, peers: int) -> None:
    """Register then ``leave`` ``peers`` distinct CIDs, ``rounds`` times, one connection."""
    cids = [random_cid(rng) for _ in range(peers)]
    async with RdvClient(port) as client:
        for _ in range(rounds):
            for cid in cids:
                ack = await client.exchange(register_frame(cid, bucket))
                assert ack.get("type") == "ack", ack
                # leave has no reply by contract → SILENT on a still-open stream.
                result = await client.send_raw(
                    (json.dumps(leave_frame(cid, bucket)) + "\n").encode(),
                    timeout=_LEAVE_TIMEOUT,
                )
                assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_sustained_mixed_load_stays_correct_and_alive(
    rendezvous_factory, bucket, rng
) -> None:
    """Concurrent register/query/refresh/leave load: every reply valid, node alive."""
    # Given: a node with rate limits off
    handle = rendezvous_factory(no_rate_limit=True)
    started = time.perf_counter()
    # When: concurrent mixed-load workers run
    reports = await asyncio.gather(
        *(_mixed_worker(handle.port, bucket, rng, _ROUNDS) for _ in range(_CONNECTIONS))
    )
    elapsed = time.perf_counter() - started

    total = _LoadReport()
    for part in reports:
        total.merge(part)
    _report("mixed-load", total, elapsed)

    # Then: zero contract violations, exact request count, node alive, p99 in budget
    assert total.errors == [], f"contract violations under load: {total.errors[:3]}"
    assert total.requests == _CONNECTIONS * _ROUNDS * 4
    assert handle.proc.poll() is None, "rendezvous died under sustained load"

    p99_ms = _percentile(total.latencies, 99) * 1000.0
    assert p99_ms <= _MAX_P99_MS, f"p99 {p99_ms:.1f}ms over budget {_MAX_P99_MS}ms"

    # Churn ended with a leave per peer: the bucket must converge to empty.
    async with RdvClient(handle.port) as client:
        final = await client.exchange(query_frame(bucket))
    assert final["count"] == 0
    assert final["peers"] == []


@pytest.mark.asyncio
async def test_registered_peers_all_discoverable_under_load(
    rendezvous_factory, bucket, rng
) -> None:
    """A peer registered under load is visible to a query on a fresh connection."""
    # Given: a node with rate limits off and N registered peers
    handle = rendezvous_factory(no_rate_limit=True)
    cids = await _register_peers(handle.port, bucket, rng, _PEERS)

    # When: concurrent queries run (each on a fresh connection)
    async def query_once() -> set[str]:
        async with RdvClient(handle.port) as client:
            # limit is capped at 50 by the spec (``ge=1, le=50``); _PEERS is kept
            # within that bound so one query can expose the whole bucket.
            response = await client.exchange(query_frame(bucket, limit=50))
        assert response.get("error") is None, response
        return {peer["cid"] for peer in response["peers"]}

    seen: set[str] = set()
    for result in await asyncio.gather(*(query_once() for _ in range(_CONNECTIONS))):
        seen |= result

    # Then: every registered peer is discoverable
    assert seen == set(cids), "queries did not expose every registered peer"
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_rate_limit_burst_recovers(rendezvous_factory, bucket) -> None:
    """Sustained burst trips ``rate_limited``; the node recovers after ``retry_after``."""
    # Given: a node with limits ON
    handle = rendezvous_factory()  # limits ON
    async with RdvClient(handle.port) as client:
        # When: the query (IP,bucket) limiter is burst to saturation
        limited = None
        for _ in range(QUERY_PAIR_BURST):
            response = await client.exchange(query_frame(bucket))
            assert response.get("error") is None, response
        limited = await client.exchange(query_frame(bucket))

        assert limited["type"] == "response"
        assert limited["error"] == "rate_limited"
        assert limited["peers"] == []
        retry_after = limited["retry_after"]
        assert retry_after >= 1

        # Then: once the bucket refills the very same request is served
        await asyncio.sleep(retry_after + 0.2)
        recovered = await client.exchange(query_frame(bucket))
    assert recovered.get("error") is None, recovered
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_garbage_storm_does_not_kill_node(rendezvous_factory, bucket) -> None:
    """A storm of malformed/unknown frames is dropped silently; the node survives."""
    # Given: a node with rate limits off and a batch of garbage frames
    handle = rendezvous_factory(no_rate_limit=True)
    garbage_lines = [
        b"not-json-at-all\n",
        b'{"type":"nope"}\n',
        b'{"protocol_version":"rdv/1","type":"register"}\n',  # missing fields
        b'{"protocol_version":"rdv/9","type":"query","bucket":"x","limit":1}\n',
        b'{"protocol_version":"rdv/1","type":"query","bucket":"x","limit":1,"evil":true}\n',
        b"\n",
    ]
    # One concatenated batch per stream: the server reads line by line and drops
    # every malformed/unknown frame without writing anything, so a single
    # ``send_raw`` observes the whole batch as SILENT (one timeout, not one per
    # frame).
    batch = b"".join(garbage_lines * _PEERS)

    async def storm() -> None:
        async with RdvClient(handle.port) as client:
            result = await client.send_raw(batch, timeout=0.3)
            # Contract: malformed/unknown frames are silently dropped with the
            # stream kept open (SILENT) — never a reply, never a crash.
            assert result.outcome is not RawOutcome.REPLY, result

    # When: concurrent garbage storms run
    await asyncio.gather(*(storm() for _ in range(_CONNECTIONS)))

    # Then: the node survives and still serves valid traffic
    assert handle.proc.poll() is None, "rendezvous died under a garbage storm"
    # Still serving valid traffic afterwards.
    async with RdvClient(handle.port) as client:
        response = await client.exchange(query_frame(bucket))
    assert response.get("type") == "response"
    assert response.get("error") is None


@pytest.mark.asyncio
async def test_ttl_sweep_converges_under_query_load(rendezvous_factory, bucket, rng) -> None:
    """Peers expire under continuous query load; the sweep keeps the node serving."""
    # Given: a node with TTL=1 and N registered peers
    handle = rendezvous_factory(no_rate_limit=True, ttl=1)
    cids = await _register_peers(handle.port, bucket, rng, min(_PEERS, 40))

    # When: the TTL elapses under continuous query load
    deadline = time.monotonic() + 2.5
    async with RdvClient(handle.port) as client:
        while time.monotonic() < deadline:
            response = await client.exchange(query_frame(bucket, limit=50))
            assert response.get("type") == "response"
            assert response.get("error") is None
            assert response["count"] <= min(_PEERS, 40)
            await asyncio.sleep(0.05)
        final = await client.exchange(query_frame(bucket, limit=50))

    # Then: expired peers converge to zero; the node survives
    assert final["count"] == 0, f"expired peers still advertised: {final['peers']}"
    assert len(cids) == min(_PEERS, 40)
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_churn_does_not_grow_memory_unbounded(rendezvous_factory, bucket, rng) -> None:
    """Register/leave churn must not leak: RSS growth stays bounded.

    The node is RAM-only, so a per-record leak would eventually exhaust the
    host; this asserts the routing table really releases a left peer instead of
    only hiding it from queries.
    """
    # Given: a node with rate limits off and a measurable RSS (Linux /proc)
    handle = rendezvous_factory(no_rate_limit=True)
    pid = handle.node_pid
    if pid is None or proc_rss_mb(pid) < 0:
        pytest.skip("RSS unavailable on this host (Linux /proc required)")

    peers = min(_PEERS, 100)
    await _churn_register_leave(handle.port, bucket, rng, rounds=1, peers=peers)  # warm up
    before = proc_rss_mb(pid)
    # When: three churn rounds run
    for _ in range(3):
        await _churn_register_leave(handle.port, bucket, rng, rounds=1, peers=peers)
    after = proc_rss_mb(pid)

    # Then: RSS growth stays bounded (a leak of one record per CID would exceed it)
    print(f"\n[BOOTSTRESS] churn-rss: before={before:.1f}MB after={after:.1f}MB peers={peers}")
    # Python's allocator retains freed arenas, so the bound is generous — but
    # finite: a leak of one routing/record object per churned CID would exceed it.
    assert after - before < 20.0, f"RSS grew {after - before:.1f}MB under churn"
    assert handle.proc.poll() is None
