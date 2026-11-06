"""Black-box behaviour-parity tests over the **TLS/TCP** transport.

The rendezvous node serves the same ``rdv/1`` contract on QUIC/UDP and TLS/TCP,
so every observable behaviour the functional QUIC suite proves must hold on the
TCP path too: rate limiting, TTL expiry/refresh, protected/private authorization,
multi-port routing, IPv6, metrics accounting and the "no plaintext frame is ever
parsed" guarantee. Only the CLI and the wire are used.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

import pytest
from harness import (
    RdvTcpClient,
    derive_bucket_token,
    free_tcp_port,
    query_frame,
    random_cid,
    refresh_frame,
    register_frame,
    scrape_metrics,
)

TOKEN = "bb" * 32


def _sample(body: str, prefix: str) -> float:
    """The value of the first exposition line starting with *prefix*."""
    line = next(line for line in body.splitlines() if line.startswith(prefix))
    return float(line.split()[1])


@pytest.mark.asyncio
async def test_tcp_query_is_rate_limited_after_burst(rendezvous_factory, bucket) -> None:
    # Given: a node with rate limits ON
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    # When: the (IP, bucket) query limiter is burst to saturation
    for _ in range(10):
        response = await client.exchange(query_frame(bucket))
        assert response.get("error") is None, response
    limited = await client.exchange(query_frame(bucket))
    # Then: the next query is refused with retry_after, never dropped
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_tcp_expired_peer_disappears_from_queries(rendezvous_factory, bucket, rng) -> None:
    # Given: a node with TTL=1 and a peer registered over TCP
    handle = rendezvous_factory(ttl=1)
    cid = random_cid(rng)
    client = RdvTcpClient(handle.port)
    await client.exchange(register_frame(cid, bucket))
    # When: the TTL elapses
    await asyncio.sleep(1.6)
    # Then: the peer is no longer advertised
    response = await client.exchange(query_frame(bucket))
    assert response["count"] == 0
    assert response["peers"] == []


@pytest.mark.asyncio
async def test_tcp_refresh_keeps_peer_alive(rendezvous_factory, bucket, rng) -> None:
    # Given: a node with TTL=1 and a peer registered over TCP
    handle = rendezvous_factory(ttl=1)
    cid = random_cid(rng)
    client = RdvTcpClient(handle.port)
    await client.exchange(register_frame(cid, bucket))
    # When: a refresh arrives just before the TTL elapses, then the window passes
    await asyncio.sleep(0.7)
    ack = await client.exchange(refresh_frame(cid, bucket))
    assert ack["type"] == "ack"
    await asyncio.sleep(0.7)
    # Then: the peer is still alive (the refresh renewed it)
    response = await client.exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_protected_bucket_requires_the_token(
    rendezvous_factory, bucket, group_key, rng
) -> None:
    # Given: a node with a protected bucket
    handle = rendezvous_factory(protected=[bucket], keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    client = RdvTcpClient(handle.port)
    # When/Then: an anonymous query and register are uniformly refused
    assert (await client.exchange(query_frame(bucket)))["error"] == "token_required"
    assert (await client.exchange(register_frame(random_cid(rng), bucket)))[
        "error"
    ] == "token_required"
    # And: the correct token registers and is discoverable
    cid = random_cid(rng)
    ack = await client.exchange(register_frame(cid, bucket, token=token))
    assert ack["type"] == "ack"
    response = await client.exchange(query_frame(bucket, token=token))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_private_node_gates_every_bucket(
    rendezvous_factory, bucket, group_key, rng
) -> None:
    # Given: a private node with one provisioned bucket
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    token = derive_bucket_token(group_key.encode("utf-8"), bucket)
    client = RdvTcpClient(handle.port)
    # When/Then: an anonymous query is refused exactly like a wrong token
    assert (await client.exchange(query_frame(bucket)))["error"] == "token_required"
    assert (await client.exchange(query_frame(bucket, token="0" * 64)))["error"] == "token_required"
    # And: the correct token is served
    response = await client.exchange(query_frame(bucket, token=token))
    assert response["error"] is None
    assert response["type"] == "response"


@pytest.mark.asyncio
async def test_tcp_multi_port_shares_one_routing_table(rendezvous_factory, bucket, rng) -> None:
    # Given: a node listening on two ports
    handle = rendezvous_factory(ports=(free_tcp_port(), free_tcp_port()))
    primary, secondary = handle.ports
    cid = random_cid(rng)
    # When: a peer registers over TCP on the first port
    await RdvTcpClient(primary).exchange(register_frame(cid, bucket))
    # Then: a TLS/TCP query on the second port sees it (one shared table)
    response = await RdvTcpClient(secondary).exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_ipv6_listener_serves(rendezvous_factory, bucket, rng) -> None:
    # Given: an IPv6 loopback listener
    handle = rendezvous_factory(host="[::1]")
    client = RdvTcpClient(handle.port, host="::1")
    cid = random_cid(rng)
    # When: a peer registers and queries over TLS/TCP over IPv6
    ack = await client.exchange(register_frame(cid, bucket))
    response = await client.exchange(query_frame(bucket))
    # Then: the register is acknowledged and the peer is discoverable
    assert ack["type"] == "ack"
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_connections_and_peers_are_reported_in_metrics(
    rendezvous_factory, tmp_path: Path, bucket, rng
) -> None:
    # Given: a node with the metrics endpoint and a TCP-registered peer
    token_file = tmp_path / "metrics-token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")
    metrics_port = free_tcp_port()
    handle = rendezvous_factory(
        env_extra={
            "HSYNC_RENDEZVOUS_METRICS_PORT": str(metrics_port),
            "HSYNC_RENDEZVOUS_METRICS_TOKEN_FILE": str(token_file),
        }
    )
    await RdvTcpClient(handle.port).exchange(register_frame(random_cid(rng), bucket))

    # When: two TLS/TCP connections are held open while the exposition is scraped
    held = [await RdvTcpClient(handle.port).open_connection() for _ in range(2)]
    try:
        status, _, body = await asyncio.to_thread(scrape_metrics, metrics_port, TOKEN)
    finally:
        for _reader, writer in held:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # Then: the peer and the two live TCP connections are both reported
    assert status == 200
    assert _sample(body, "hsync_rendezvous_peers_current") >= 1
    assert _sample(body, 'hsync_rendezvous_connections_current{transport="tcp"}') >= 2


@pytest.mark.asyncio
async def test_plaintext_is_never_parsed_as_a_frame(rendezvous_factory, bucket, rng) -> None:
    """A bare TCP client (no TLS) must never have its bytes read as ``rdv/1``.

    The node performs the TLS handshake before reading any frame; plaintext
    NDJSON written on a cleartext socket must not be parsed nor answered.
    """
    # Given: a fresh node
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    # When: a cleartext socket sends a well-formed register frame
    reader, writer = await client.open_plain_connection()
    try:
        frame = register_frame(random_cid(rng), bucket)
        writer.write((json.dumps(frame) + "\n").encode("utf-8"))
        with contextlib.suppress(ConnectionError, OSError):
            await writer.drain()
        try:
            reply = await asyncio.wait_for(reader.readline(), timeout=1.0)
        except (TimeoutError, ConnectionError, OSError):
            reply = b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    # Then: no rdv/1 reply is produced (the plaintext is not a frame)
    assert not reply.startswith(b"{")
    # And: the node stays healthy and serves the real TLS/TCP transport
    ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None
