"""Black-box data-relay tests over the ``rdv/1`` wire protocol.

Drives the real node process through the public frames only: a listener registers
its control stream, a requester pairs with it, the listener attaches a fresh
stream, and opaque bytes flow both ways. Nothing here knows about the registry
internals, so the suite keeps testing the contract if the implementation is
rewritten.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from harness import RdvClient, RdvTcpClient, random_cid, register_frame


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


async def _read_json(reader) -> dict:
    return json.loads(await asyncio.wait_for(reader.readline(), timeout=5.0))


def _write(writer, frame: dict) -> None:
    writer.write((json.dumps(frame) + "\n").encode("utf-8"))


@pytest.mark.asyncio
async def test_a_relayed_session_carries_bytes_both_ways(rendezvous_factory, bucket, rng) -> None:
    # Given: a node with the relay on by default and a registered listener
    handle = rendezvous_factory()
    listener_cid = random_cid(rng)
    requester_cid = random_cid(rng)
    async with RdvClient(handle.port) as listener:
        await listener.exchange(register_frame(listener_cid, bucket))
        control_reader, control_writer = await listener.open_stream()
        _write(control_writer, _listen(listener_cid, bucket))
        await control_writer.drain()
        assert (await _read_json(control_reader))["type"] == "relay_listening"

        async with RdvClient(handle.port) as requester:
            data_reader, data_writer = await requester.open_stream()
            _write(data_writer, _connect(requester_cid, listener_cid, bucket))
            await data_writer.drain()

            # When: the node announces the session and the requester gets its ok
            incoming = await _read_json(control_reader)
            assert incoming["type"] == "relay_incoming"
            assert incoming["cid"] == requester_cid
            relay_id = incoming["relay_id"]
            assert (await _read_json(data_reader))["type"] == "relay_ok"

            acceptor_reader, acceptor_writer = await listener.open_stream()
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


@pytest.mark.asyncio
async def test_a_node_with_the_relay_disabled_refuses_the_session(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a node started with --no-relay
    handle = rendezvous_factory(args=("--no-relay",))
    cid = random_cid(rng)
    target = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a relay session is requested
        reply = await client.exchange(_connect(cid, target, bucket))
    # Then: the uniform refusal names the missing capability
    assert reply["type"] == "relay_error"
    assert reply["error"] == "relay_unavailable"


@pytest.mark.asyncio
async def test_a_listener_is_required_before_a_session_can_start(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a node with the relay on by default and a peer that never opened a
    # listener
    handle = rendezvous_factory()
    cid = random_cid(rng)
    target = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a session towards that peer is requested
        reply = await client.exchange(_connect(cid, target, bucket))
    # Then: no listener means relay_unavailable, never a hang
    assert reply["type"] == "relay_error"
    assert reply["error"] == "relay_unavailable"


@pytest.mark.asyncio
async def test_a_bogus_relay_id_attach_is_closed(rendezvous_factory, bucket, rng) -> None:
    # Given: a pending relay session (listener control stream + requester ok)
    handle = rendezvous_factory(no_rate_limit=True)
    listener_cid = random_cid(rng)
    requester_cid = random_cid(rng)
    async with RdvClient(handle.port) as listener:
        await listener.exchange(register_frame(listener_cid, bucket))
        control_reader, control_writer = await listener.open_stream()
        _write(control_writer, _listen(listener_cid, bucket))
        await control_writer.drain()
        assert (await _read_json(control_reader))["type"] == "relay_listening"

        async with RdvClient(handle.port) as requester:
            data_reader, data_writer = await requester.open_stream()
            _write(data_writer, _connect(requester_cid, listener_cid, bucket))
            await data_writer.drain()
            assert (await _read_json(control_reader))["type"] == "relay_incoming"
            assert (await _read_json(data_reader))["type"] == "relay_ok"

            # When: the listener attaches with a relay_id that matches no session
            acceptor_reader, acceptor_writer = await listener.open_stream()
            _write(acceptor_writer, _attach(listener_cid, bucket, "0" * 32))
            await acceptor_writer.drain()
            # Then: the bogus attach is dropped (the stream is closed, not paired)
            closed = await asyncio.wait_for(acceptor_reader.readline(), timeout=2.0)
            assert closed == b""


@pytest.mark.asyncio
async def test_attach_from_a_non_listener_is_closed(rendezvous_factory, bucket, rng) -> None:
    # Given: a pending relay session owned by `listener_cid`
    handle = rendezvous_factory(no_rate_limit=True)
    listener_cid = random_cid(rng)
    requester_cid = random_cid(rng)
    async with RdvClient(handle.port) as listener:
        await listener.exchange(register_frame(listener_cid, bucket))
        control_reader, control_writer = await listener.open_stream()
        _write(control_writer, _listen(listener_cid, bucket))
        await control_writer.drain()
        assert (await _read_json(control_reader))["type"] == "relay_listening"

        async with RdvClient(handle.port) as requester:
            data_reader, data_writer = await requester.open_stream()
            _write(data_writer, _connect(requester_cid, listener_cid, bucket))
            await data_writer.drain()
            incoming = await _read_json(control_reader)
            assert (await _read_json(data_reader))["type"] == "relay_ok"

            # When: a *different* cid tries to attach with the real relay_id
            intruder = random_cid(rng)
            acceptor_reader, acceptor_writer = await listener.open_stream()
            _write(acceptor_writer, _attach(intruder, bucket, incoming["relay_id"]))
            await acceptor_writer.drain()
            # Then: the ownership check drops it (closed, no pairing)
            closed = await asyncio.wait_for(acceptor_reader.readline(), timeout=2.0)
            assert closed == b""


@pytest.mark.asyncio
async def test_a_closed_listener_makes_new_sessions_unavailable(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a listener whose control stream then closes
    handle = rendezvous_factory(no_rate_limit=True)
    listener_cid = random_cid(rng)
    async with RdvClient(handle.port) as listener:
        await listener.exchange(register_frame(listener_cid, bucket))
        control_reader, control_writer = await listener.open_stream()
        _write(control_writer, _listen(listener_cid, bucket))
        await control_writer.drain()
        assert (await _read_json(control_reader))["type"] == "relay_listening"
        control_writer.close()

        # When: a new relay session is requested towards the gone listener
        async with RdvClient(handle.port) as requester:
            reply = await requester.exchange(_connect(random_cid(rng), listener_cid, bucket))
        # Then: the listener is gone from the registry — uniform relay_unavailable
        assert reply["type"] == "relay_error"
        assert reply["error"] == "relay_unavailable"


@pytest.mark.asyncio
async def test_a_private_node_refuses_an_unauthenticated_relay(
    rendezvous_factory, bucket, group_key, rng
) -> None:
    # Given: a private node (every bucket gated)
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(random_cid(rng), bucket))
        # When: a relay session is requested with no bucket token
        reply = await client.exchange(_connect(random_cid(rng), random_cid(rng), bucket))
    # Then: the uniform authorization refusal, never a relay pairing
    assert reply["type"] == "relay_error"
    assert reply["error"] == "token_required"


@pytest.mark.asyncio
async def test_a_relay_bridges_the_two_transports(rendezvous_factory, bucket, rng) -> None:
    """A TLS/TCP listener and a QUIC requester are paired: the relay is transport-agnostic."""
    # Given: a node whose listener (and acceptor) use TLS/TCP
    handle = rendezvous_factory(no_rate_limit=True)
    listener_cid = random_cid(rng)
    requester_cid = random_cid(rng)
    tcp = RdvTcpClient(handle.port)
    await tcp.exchange(register_frame(listener_cid, bucket))
    control_reader, control_writer = await tcp.open_connection()
    _write(control_writer, _listen(listener_cid, bucket))
    await control_writer.drain()
    assert (await _read_json(control_reader))["type"] == "relay_listening"

    try:
        # When: the requester pairs over QUIC and the acceptor attaches over TLS/TCP
        async with RdvClient(handle.port) as requester:
            data_reader, data_writer = await requester.open_stream()
            _write(data_writer, _connect(requester_cid, listener_cid, bucket))
            await data_writer.drain()
            incoming = await _read_json(control_reader)
            assert (await _read_json(data_reader))["type"] == "relay_ok"

            acceptor_reader, acceptor_writer = await tcp.open_connection()
            _write(acceptor_writer, _attach(listener_cid, bucket, incoming["relay_id"]))
            await acceptor_writer.drain()

            data_writer.write(b"from-quic")
            await data_writer.drain()
            acceptor_writer.write(b"from-tcp")
            await acceptor_writer.drain()

            # Then: bytes cross the transport boundary verbatim, both directions
            assert (
                await asyncio.wait_for(acceptor_reader.readexactly(9), timeout=5.0) == b"from-quic"
            )
            assert await asyncio.wait_for(data_reader.readexactly(8), timeout=5.0) == b"from-tcp"
            acceptor_writer.close()
    finally:
        control_writer.close()
