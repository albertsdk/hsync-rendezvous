"""Black-box metrics: the loopback ``/metrics`` endpoint and its aggregates.

Every scenario drives the real binary through its public surfaces only — the CLI
and the HTTP endpoint — and asserts that the numbers reported match what the wire
actually produced. The endpoint is loopback-only and bearer-authenticated, so an
unauthenticated ``200`` anywhere here is a defect, and the exposition must never
carry peer identity (the node is no-log).
"""

from __future__ import annotations

import asyncio
import http.client
import re
from pathlib import Path

import pytest
from harness import RdvClient, free_tcp_port, random_cid, register_frame

TOKEN = "bb" * 32


def _scrape(port: int, token: str | None) -> tuple[int, str]:
    """One GET /metrics; returns the status and the body (headers are not used)."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        connection.request("GET", "/metrics", headers=headers)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8")
    finally:
        connection.close()


def _value(body: str, metric: str) -> float:
    """The single sample value of ``metric`` (asserts it is present exactly once)."""
    matches = re.findall(rf"^{re.escape(metric)} ([0-9.]+)$", body, re.MULTILINE)
    assert len(matches) == 1, f"{metric} not reported once: {matches}"
    return float(matches[0])


def _start_with_metrics(rendezvous_factory, tmp_path: Path):
    """A node whose metrics endpoint reads its token from a file (the env form)."""
    token_file = tmp_path / "metrics-token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    metrics_port = free_tcp_port()
    handle = rendezvous_factory(
        env_extra={
            "HSYNC_RENDEZVOUS_METRICS_PORT": str(metrics_port),
            "HSYNC_RENDEZVOUS_METRICS_TOKEN_FILE": str(token_file),
        }
    )
    assert "127.0.0.1:" in handle.stdout_text(), handle.stdout_text()
    return handle, metrics_port


def test_the_endpoint_requires_the_bearer_token(rendezvous_factory, tmp_path: Path) -> None:
    # Given: a node with the metrics endpoint enabled
    _, metrics_port = _start_with_metrics(rendezvous_factory, tmp_path)
    # Then: without a token the endpoint refuses, with it serves Prometheus text
    status, body = _scrape(metrics_port, None)
    assert status == 401
    assert "hsync_rendezvous_" not in body

    status, body = _scrape(metrics_port, "wrong-token")
    assert status == 401

    status, body = _scrape(metrics_port, TOKEN)
    assert status == 200
    assert "# TYPE hsync_rendezvous_peers_current gauge" in body


@pytest.mark.asyncio
async def test_registered_peers_move_the_level_and_the_peak(
    rendezvous_factory, tmp_path, bucket, rng
) -> None:
    # Given: a node with metrics and three registered peers
    handle, metrics_port = _start_with_metrics(rendezvous_factory, tmp_path)
    cids = [random_cid(rng) for _ in range(3)]
    async with RdvClient(handle.port) as client:
        for cid in cids:
            ack = await client.exchange(register_frame(cid, bucket))
            assert ack["type"] == "ack"

    # Then: the level and the peak report the registered population
    status, body = await asyncio.to_thread(_scrape, metrics_port, TOKEN)
    assert status == 200
    assert _value(body, "hsync_rendezvous_peers_current") == 3
    assert _value(body, "hsync_rendezvous_peers_peak") >= 3
    assert _value(body, "hsync_rendezvous_peers_updates_total") == 3


@pytest.mark.asyncio
async def test_concurrent_connections_raise_the_connection_peak(
    rendezvous_factory, tmp_path: Path
) -> None:
    # Given: a node with metrics and three simultaneous QUIC connections
    handle, metrics_port = _start_with_metrics(rendezvous_factory, tmp_path)
    async with RdvClient(handle.port), RdvClient(handle.port), RdvClient(handle.port):
        # Then: the live level and the peak both see the three connections
        status, body = await asyncio.to_thread(_scrape, metrics_port, TOKEN)
        assert status == 200
        assert _value(body, 'hsync_rendezvous_connections_current{transport="quic"}') >= 3
        assert _value(body, 'hsync_rendezvous_connections_peak{transport="quic"}') >= 3


@pytest.mark.asyncio
async def test_the_stats_file_is_written_periodically(
    rendezvous_factory, tmp_path: Path, bucket, rng
) -> None:
    # Given: a node publishing its aggregates to a Prometheus text file
    stats_file = tmp_path / "stats.prom"
    handle = rendezvous_factory(
        env_extra={
            "HSYNC_RENDEZVOUS_STATS_FILE": str(stats_file),
            "HSYNC_RENDEZVOUS_STATS_INTERVAL": "1",
        }
    )
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(random_cid(rng), bucket))

    # Then: the file appears with the exposition the endpoint serves
    for _ in range(50):
        if stats_file.exists():
            break
        await asyncio.sleep(0.1)
    body = stats_file.read_text(encoding="utf-8")
    assert "# TYPE hsync_rendezvous_peers_current gauge" in body
    assert _value(body, "hsync_rendezvous_peers_current") >= 1


@pytest.mark.asyncio
async def test_the_exposition_never_carries_peer_identity(
    rendezvous_factory, tmp_path: Path, bucket, rng
) -> None:
    # Given: a registered peer whose identity the node knows
    handle, metrics_port = _start_with_metrics(rendezvous_factory, tmp_path)
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))

    # Then: neither the CID nor the source address reaches the exposition
    status, body = await asyncio.to_thread(_scrape, metrics_port, TOKEN)
    assert status == 200
    assert cid not in body
    assert "127.0.0.1" not in body
    assert bucket not in body
