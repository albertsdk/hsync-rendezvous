"""Black-box **security probes** over the **TLS/TCP** transport.

The adversarial contract is transport-independent: every attack the QUIC probe
suite attempts must be refused the same way on the TLS/TCP listener (the same
``rdv/1`` validation runs after the handshake). Covered here: parser abuse,
single-frame-bound enforcement, pipelined/bucket-enumeration DoS, source
spoofing, log forging via control characters, and the guarantee that a cleartext
client's bytes are never parsed as a frame.

Opt-in: requires ``HSYNC_BB_SECURITY=1`` **on top of** ``HSYNC_BB_RENDEZVOUS=1``.
The 127.0.0.2 spoofing probes are skipped where the loopback alias cannot be
bound.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket

import pytest
from harness import (
    QUERY_IP_BURST,
    QUERY_PAIR_BURST,
    RawOutcome,
    RdvTcpClient,
    query_frame,
    random_bucket,
    random_cid,
    register_frame,
)

_ENABLED = os.environ.get("HSYNC_BB_SECURITY") == "1"
pytestmark = pytest.mark.skipif(
    not _ENABLED, reason="rendezvous security probes are opt-in; set HSYNC_BB_SECURITY=1"
)


def _second_loopback_available() -> bool:
    """True when a distinct loopback source address (127.0.0.2) can be bound."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.2", 0))
    except OSError:
        return False
    probe.close()
    return True


@pytest.mark.asyncio
async def test_tcp_parser_abuse_is_bounded(rendezvous_factory, bucket, rng) -> None:
    """Deep nesting, numeric overflow, JSON infinity and unicode/NUL smuggling are inert."""
    # Given: a fresh node
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    payloads = [
        b'{"pad":' + b"[" * 3000 + b"]" * 3000 + b"}\n",  # deep JSON nesting (~6 KB)
        b'{"protocol_version":"rdv/1","type":"query","bucket":"bb-x","limit":'
        + b"9" * 30
        + b"}\n",  # integer overflow
        b'{"protocol_version":"rdv/1","type":"query","bucket":"bb-x","limit":1e999}\n',
        (
            json.dumps(
                {
                    "protocol_version": "rdv/1",
                    "type": "register",
                    "cid": "\uff21" * 21,
                    "bucket": bucket,
                }
            )
            + "\n"
        ).encode("utf-8"),  # fullwidth unicode CID
        (
            json.dumps({"protocol_version": "rdv/1", "type": "query", "bucket": "bb\u0000x"}) + "\n"
        ).encode("utf-8"),  # NUL inside the bucket name
    ]
    # When: each parser-abuse payload is sent over TLS/TCP
    for payload in payloads:
        result = await client.send_raw(payload)
        # Then: no crash and no error oracle — silent drop or connection close
        assert result.outcome in (RawOutcome.SILENT, RawOutcome.CLOSED)
    # And: the node still serves valid traffic
    ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_tcp_oversized_frame_closes_the_connection(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    # When: an over-limit frame is sent
    result = await client.send_raw(b"x" * 9000 + b"\n")
    # Then: the connection is closed, and the node stays healthy
    assert result.outcome is RawOutcome.CLOSED
    ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_tcp_pipelined_burst_is_throttled_not_fatal(rendezvous_factory, bucket) -> None:
    # Given: a node with rate limits ON
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    frames = [query_frame(bucket) for _ in range(QUERY_PAIR_BURST + 20)]
    # When: more queries than the (IP, bucket) burst are pipelined on one TLS/TCP connection
    replies = await client.pipeline(frames, timeout=20.0)
    # Then: every reply is well-formed, the burst is throttled, the node survives
    assert len(replies) == QUERY_PAIR_BURST + 20
    assert all(reply["type"] == "response" for reply in replies)
    assert any(reply["error"] == "rate_limited" for reply in replies)
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_tcp_bucket_enumeration_sweep_hits_aggregate_cap(rendezvous_factory, rng) -> None:
    """One query per bucket defeats the pair limiter — the per-IP aggregate must cap it."""
    # Given: an open node and a fresh bucket name per probe
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    # When: distinct buckets are queried one after another, which the
    # per-(IP, bucket) limiter cannot stop — only the aggregate can. The loop is
    # bounded well past the burst so refill cannot make it unbounded.
    replies = []
    for _ in range(QUERY_IP_BURST + 200):
        reply = await client.exchange(query_frame(random_bucket(rng)))
        replies.append(reply)
        if reply["error"] is not None:
            break
    # Then: the anti-enumeration aggregate cap trips and the node stays alive
    assert any(reply["error"] == "rate_limited" for reply in replies)
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_tcp_foreign_source_cannot_replace_registration(
    rendezvous_factory, bucket, rng
) -> None:
    """The source-address ownership rule holds over TLS/TCP too."""
    if not _second_loopback_available():
        pytest.skip("127.0.0.2 loopback alias unavailable on this host")
    # Given: a peer registered from 127.0.0.1
    handle = rendezvous_factory()
    cid = random_cid(rng)
    await RdvTcpClient(handle.port).exchange(
        register_frame(cid, bucket, host="198.51.100.7", port=8443)
    )
    # When: 127.0.0.2 re-registers the same cid with different endpoints
    result = await RdvTcpClient(handle.port, local_ip="127.0.0.2").send_raw(
        (json.dumps(register_frame(cid, bucket, host="203.0.113.9", port=9999)) + "\n").encode()
    )
    # Then: the hijack attempt is dropped and the original registration survives
    assert result.outcome in (RawOutcome.SILENT, RawOutcome.CLOSED)
    response = await RdvTcpClient(handle.port).exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["endpoints"] == [
        {"proto": "tcp", "host": "198.51.100.7", "port": 8443}
    ]


@pytest.mark.asyncio
async def test_tcp_foreign_source_cannot_depart_peer(rendezvous_factory, bucket, rng) -> None:
    """A leave is honoured only from the source that registered the peer, over TCP too."""
    if not _second_loopback_available():
        pytest.skip("127.0.0.2 loopback alias unavailable on this host")
    # Given: a peer registered from 127.0.0.1
    handle = rendezvous_factory()
    cid = random_cid(rng)
    await RdvTcpClient(handle.port).exchange(register_frame(cid, bucket))
    # When: a leave for that (cid, bucket) arrives from 127.0.0.2
    result = await RdvTcpClient(handle.port, local_ip="127.0.0.2").send_raw(
        (
            json.dumps({"protocol_version": "rdv/1", "type": "leave", "cid": cid, "bucket": bucket})
            + "\n"
        ).encode()
    )
    # Then: the spoofed departure is ignored — the peer survives
    assert result.outcome in (RawOutcome.SILENT, RawOutcome.CLOSED)
    response = await RdvTcpClient(handle.port).exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_control_char_group_cannot_forge_log_lines(
    rendezvous_factory, bucket, rng
) -> None:
    """A group carrying control characters must not forge a second log line over TCP."""
    # Given: a node started with --debug (the peer-aware channel)
    handle = rendezvous_factory(debug=True)
    cid = random_cid(rng)
    forged_group = "grp\n2026-01-01T00:00:00Z - hsync-rendezvous[1] warn: FORGED-BY-ATTACKER"
    # When: a register over TLS/TCP carries the forged group
    frame = register_frame(cid, bucket)
    frame["group"] = forged_group
    ack = await RdvTcpClient(handle.port).exchange(frame)
    # Then: the register is served, and the forged text never starts a log line
    stderr = handle.stderr_text()
    assert ack["type"] == "ack"
    assert not any(
        line.startswith("2026-01-01T00:00:00Z - hsync-rendezvous[1] warn: FORGED-BY-ATTACKER")
        for line in stderr.splitlines()
    )


@pytest.mark.asyncio
async def test_tcp_plaintext_bytes_are_never_registered(rendezvous_factory, bucket, rng) -> None:
    """A cleartext client's frame must never reach the handler over the TCP listener."""
    # Given: a fresh node and a cleartext (non-TLS) socket
    handle = rendezvous_factory()
    client = RdvTcpClient(handle.port)
    cid = random_cid(rng)
    reader, writer = await client.open_plain_connection()
    try:
        # When: a well-formed register frame is written on the cleartext socket
        with contextlib.suppress(ConnectionError, OSError):
            writer.write((json.dumps(register_frame(cid, bucket)) + "\n").encode("utf-8"))
            await writer.drain()
        try:
            reply = await asyncio.wait_for(reader.readline(), timeout=1.0)
        except (TimeoutError, ConnectionError, OSError):
            reply = b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    # Then: no rdv/1 reply is produced and nothing was registered
    assert not reply.startswith(b"{")
    response = await client.exchange(query_frame(bucket))
    assert response["count"] == 0
    assert handle.proc.poll() is None
