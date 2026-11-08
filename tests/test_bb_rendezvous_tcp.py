"""Black-box tests for the TLS/TCP transport of the ``rdv/1`` node.

Same isolation contract as the QUIC black-box suite: a fresh subprocess per
test, a scrubbed environment, and only the public CLI + wire protocol. Nothing
here imports ``hsync_rendezvous``, so the same suite validates the two
transports against the spec and would keep validating a rewritten node.

It covers the acceptance criteria the TLS/TCP transport added: discovery over
TCP (with the STUN echo tagged ``tcp``), one shared routing table across both
transports, pipelined frames on one TCP connection, per-transport enable/
disable via flag **and** env, a refused ALPN, an all-transports-bound-failure
exit code, and a full relay session carried over TCP.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import pytest
from harness import (
    RawOutcome,
    RdvClient,
    RdvTcpClient,
    query_frame,
    random_cid,
    refresh_frame,
    register_frame,
    run_cli,
)


def _listen(cid: str, bucket: str) -> dict:
    return {"protocol_version": "rdv/1", "type": "relay_listen", "cid": cid, "bucket": bucket}


def _connect(cid: str, target_cid: str, bucket: str) -> dict:
    return {
        "protocol_version": "rdv/1",
        "type": "relay_connect",
        "cid": cid,
        "bucket": bucket,
        "target_cid": target_cid,
    }


def _attach(cid: str, bucket: str, relay_id: str) -> dict:
    return {
        "protocol_version": "rdv/1",
        "type": "relay_attach",
        "cid": cid,
        "bucket": bucket,
        "relay_id": relay_id,
    }


async def _read_json(reader: Any) -> dict:
    return json.loads(await asyncio.wait_for(reader.readline(), timeout=5.0))


def _write(writer: Any, frame: dict) -> None:
    writer.write((json.dumps(frame) + "\n").encode("utf-8"))


@pytest.mark.asyncio
async def test_tcp_register_ack_carries_tcp_stun_echo(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node serving both transports
    handle = rendezvous_factory()
    # When: a register is sent over TLS/TCP
    ack = await RdvTcpClient(handle.port).exchange(register_frame(random_cid(rng), bucket))
    # Then: the ack echoes the observed loopback TCP source + TTL
    assert ack["type"] == "ack"
    assert ack["observed_endpoint"]["proto"] == "tcp"
    assert ack["observed_endpoint"]["ip"] == "127.0.0.1"
    assert ack["ttl"] == 60


@pytest.mark.asyncio
async def test_tcp_query_relays_an_endpointless_peer_without_candidates(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a peer that registered over TCP with no listen endpoint
    handle = rendezvous_factory()
    cid = random_cid(rng)
    client = RdvTcpClient(handle.port)
    await client.exchange(register_frame(cid, bucket, endpoints=False))
    # When: a query is sent
    response = await client.exchange(query_frame(bucket))
    # Then: the peer is relayed with no candidate and reachable=false, over TCP too
    assert response["count"] == 1
    peer = response["peers"][0]
    assert peer["endpoints"] == []
    assert peer["reachable"] is False


@pytest.mark.asyncio
async def test_one_routing_table_is_shared_by_both_transports(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a peer registered over TCP
    handle = rendezvous_factory()
    cid = random_cid(rng)
    await RdvTcpClient(handle.port).exchange(register_frame(cid, bucket))
    # When: another client queries over QUIC/UDP
    async with RdvClient(handle.port) as udp:
        response = await udp.exchange(query_frame(bucket))
    # Then: the TCP-registered peer is visible (one process, one table)
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_quic_register_is_visible_to_a_tcp_query(rendezvous_factory, bucket, rng) -> None:
    # Given: a peer registered over QUIC/UDP
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as udp:
        await udp.exchange(register_frame(cid, bucket))
    # When: another client queries over TLS/TCP
    response = await RdvTcpClient(handle.port).exchange(query_frame(bucket))
    # Then: the QUIC-registered peer is visible (the table is transport-agnostic,
    # in both directions — a peer is dialed on its own data plane either way)
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_pipelined_frames_are_answered_in_order(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: register + query + refresh are pipelined on one TCP connection
    replies = await RdvTcpClient(handle.port).pipeline(
        [register_frame(cid, bucket), query_frame(bucket), refresh_frame(cid, bucket)]
    )
    # Then: each is answered in order, and the node did not close after the reply
    assert [r["type"] for r in replies] == ["ack", "response", "ack"]
    assert replies[1]["count"] == 1
    assert replies[1]["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_tcp_only_node_serves_tcp(rendezvous_factory, bucket, rng) -> None:
    # Given: a node started QUIC-less
    handle = rendezvous_factory(args=("--no-udp",))
    # When/Then: it still answers over TLS/TCP
    ack = await RdvTcpClient(handle.port).exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert ack["observed_endpoint"]["proto"] == "tcp"


@pytest.mark.asyncio
async def test_tcp_only_env_is_equivalent_to_the_flag(rendezvous_factory, bucket, rng) -> None:
    # Given: the same QUIC-less node, expressed through the envvar the units use
    handle = rendezvous_factory(env_extra={"HSYNC_RENDEZVOUS_UDP": "0"})
    # When/Then: TLS/TCP still serves
    ack = await RdvTcpClient(handle.port).exchange(register_frame(random_cid(rng), bucket))
    assert ack["observed_endpoint"]["proto"] == "tcp"


@pytest.mark.asyncio
async def test_udp_only_node_refuses_tcp(rendezvous_factory, bucket, rng) -> None:
    # Given: a node started TLS/TCP-less
    handle = rendezvous_factory(args=("--no-tcp",))
    cid = random_cid(rng)
    # When: a TCP connection is attempted
    with pytest.raises(OSError):  # connection refused — nothing listens on TCP
        await RdvTcpClient(handle.port).exchange(register_frame(cid, bucket))
    # Then: the node still serves QUIC
    async with RdvClient(handle.port) as udp:
        ack = await udp.exchange(register_frame(cid, bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_a_wrong_alpn_offer_is_refused(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    # When: a client offers an ALPN the node does not speak
    result = await RdvTcpClient(handle.port, alpn="something-else/1").send_raw(
        (json.dumps(register_frame(random_cid(rng), bucket)) + "\n").encode("utf-8")
    )
    # Then: the node closes the connection without answering
    assert result.outcome is RawOutcome.CLOSED


def test_tcp_bind_failure_exits_three() -> None:
    # Given: a TCP port another process already holds
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    port = int(holder.getsockname()[1])
    try:
        # When: a TCP-only node is asked to bind it
        result = run_cli(
            [
                "run",
                "--no-udp",
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(port),
                "--ephemeral",
            ]
        )
    finally:
        holder.close()
    # Then: nothing bound on any enabled transport -> exit 3 naming the transport
    assert result.returncode == 3
    assert "TLS/TCP" in result.stderr


@pytest.mark.asyncio
async def test_tcp_relay_carries_bytes_both_ways(rendezvous_factory, bucket, rng) -> None:
    # Given: a node with the relay on and a listener registered over TCP
    handle = rendezvous_factory()
    listener_cid = random_cid(rng)
    requester_cid = random_cid(rng)
    listener = RdvTcpClient(handle.port)
    await listener.exchange(register_frame(listener_cid, bucket))
    control_reader, control_writer = await listener.open_connection()
    try:
        _write(control_writer, _listen(listener_cid, bucket))
        await control_writer.drain()
        assert (await _read_json(control_reader))["type"] == "relay_listening"

        # When: a requester pairs with it over a fresh TCP connection
        requester = RdvTcpClient(handle.port)
        data_reader, data_writer = await requester.open_connection()
        try:
            _write(data_writer, _connect(requester_cid, listener_cid, bucket))
            await data_writer.drain()
            incoming = await _read_json(control_reader)
            assert incoming["type"] == "relay_incoming"
            relay_id = incoming["relay_id"]
            assert (await _read_json(data_reader))["type"] == "relay_ok"

            # And: the listener attaches with yet another TCP connection
            acceptor_reader, acceptor_writer = await listener.open_connection()
            try:
                _write(acceptor_writer, _attach(listener_cid, bucket, relay_id))
                await acceptor_writer.drain()

                data_writer.write(b"requester-bytes")
                await data_writer.drain()
                acceptor_writer.write(b"listener-bytes")
                await acceptor_writer.drain()

                # Then: both directions arrive verbatim (the node never parses them)
                assert (
                    await asyncio.wait_for(acceptor_reader.readexactly(15), timeout=5.0)
                    == b"requester-bytes"
                )
                assert (
                    await asyncio.wait_for(data_reader.readexactly(14), timeout=5.0)
                    == b"listener-bytes"
                )
            finally:
                await RdvTcpClient._close(acceptor_writer)
        finally:
            await RdvTcpClient._close(data_writer)
    finally:
        await RdvTcpClient._close(control_writer)
