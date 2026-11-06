"""Black-box register/refresh tests over the ``rdv/1`` wire protocol."""

from __future__ import annotations

import json

import pytest
from harness import (
    RawOutcome,
    RdvClient,
    leave_frame,
    query_frame,
    random_cid,
    refresh_frame,
    register_frame,
)


@pytest.mark.asyncio
async def test_register_ack_carries_stun_echo(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    # When: a register is sent
    async with RdvClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    # Then: the ack echoes the observed loopback UDP source + TTL + server time
    assert ack["type"] == "ack"
    assert ack["observed_endpoint"]["proto"] == "udp"
    assert ack["observed_endpoint"]["ip"] == "127.0.0.1"
    assert ack["ttl"] == 60
    assert ack["server_time"].endswith("Z")


@pytest.mark.asyncio
async def test_query_returns_advertised_endpoint(rendezvous_factory, bucket, rng) -> None:
    # Given: a registered peer with an advertised endpoint
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: a register (host/port) then a query are sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, host="198.51.100.7", port=8443))
        response = await client.exchange(query_frame(bucket))
    # Then: the advertised endpoint is relayed verbatim
    assert response["type"] == "response"
    assert response["count"] == 1
    peer = response["peers"][0]
    assert peer["cid"] == cid
    assert peer["endpoints"] == [{"proto": "tcp", "host": "198.51.100.7", "port": 8443}]


@pytest.mark.asyncio
async def test_query_falls_back_to_observed_source(rendezvous_factory, bucket, rng) -> None:
    # Given: a peer that registered with no listen endpoint
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: a query is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, endpoints=False))
        response = await client.exchange(query_frame(bucket))
    # Then: the observed source endpoint is relayed as the fallback endpoint
    assert response["type"] == "response"
    assert response["count"] == 1
    peer = response["peers"][0]
    assert peer["endpoints"][0]["host"] == "127.0.0.1"  # observed loopback source
    assert peer["endpoints"][0]["proto"] == "udp"


@pytest.mark.asyncio
async def test_refresh_acks(rendezvous_factory, bucket, rng) -> None:
    """Refresh acknowledges; the ack is the only wire-observable effect."""
    # Given: a registered peer
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: a refresh is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        ack = await client.exchange(refresh_frame(cid, bucket, connected=7))
    # Then: the node acknowledges
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_refresh_updates_the_connected_count(rendezvous_factory, bucket, rng) -> None:
    """A refresh's ``connected`` is persisted and relayed (not the register value)."""
    # Given: a peer registered with connected=3
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a refresh reports connected=9, then a query is sent
        await client.exchange(refresh_frame(cid, bucket, connected=9))
        response = await client.exchange(query_frame(bucket))
    # Then: the relayed "connected" reflects the refresh, not the registration
    assert response["count"] == 1
    assert response["peers"][0]["connected"] == 9


@pytest.mark.asyncio
async def test_refresh_unknown_cid_is_dropped(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node (no records)
    handle = rendezvous_factory()
    # When: a refresh for an unknown cid is sent
    async with RdvClient(handle.port) as client:
        result = await client.send_raw(
            (json.dumps(refresh_frame(random_cid(rng), bucket)) + "\n").encode("utf-8")
        )
    # Then: refresh never creates -> silent drop
    assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_reregister_replaces_endpoints_without_duplicating(
    rendezvous_factory, bucket, rng
) -> None:
    """Re-registering a CID updates its record in place (upsert, never a duplicate)."""
    # Given: a registered peer
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: the same cid re-registers with different endpoints
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, host="198.51.100.7", port=8443))
        await client.exchange(register_frame(cid, bucket, host="198.51.100.8", port=9443))
        response = await client.exchange(query_frame(bucket))
    # Then: the record is replaced in place (one peer, new endpoints)
    assert response["type"] == "response"
    assert response["count"] == 1  # the second register replaced, did not append
    assert response["peers"][0]["cid"] == cid
    assert response["peers"][0]["endpoints"] == [
        {"proto": "tcp", "host": "198.51.100.8", "port": 9443}
    ]


@pytest.mark.asyncio
async def test_multi_endpoint_list_is_relayed_verbatim_in_order(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    cid = random_cid(rng)
    endpoints = [
        {"proto": "tcp", "host": "198.51.100.7", "port": 8443},
        {"proto": "tcp", "host": "10.0.0.5", "port": 9000},
        {"proto": "udp", "host": "198.51.100.7", "port": 443},
    ]
    async with RdvClient(handle.port) as client:
        # When: a register advertises three endpoints, then a query is sent
        frame = register_frame(cid, bucket)
        frame["endpoints"] = endpoints
        await client.exchange(frame)
        response = await client.exchange(query_frame(bucket))
    # Then: the whole list is relayed verbatim, in order
    assert response["count"] == 1
    assert response["peers"][0]["endpoints"] == endpoints


@pytest.mark.asyncio
async def test_refresh_does_not_mutate_capacity_or_advertisement(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: a peer registered with a capacity and election advertisement
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(
            register_frame(cid, bucket, capacity=7, server_ready=True, prefer_master=True)
        )
        # When: a refresh (no capacity/election fields) is sent, then a query
        await client.exchange(refresh_frame(cid, bucket))
        response = await client.exchange(query_frame(bucket))
    # Then: the advertisement is unchanged (refresh never mutates it)
    peer = response["peers"][0]
    assert peer["capacity"] == 7
    assert peer["server_ready"] is True
    assert peer["prefer_master"] is True


@pytest.mark.asyncio
async def test_reregister_after_leave_starts_fresh(rendezvous_factory, bucket, rng) -> None:
    # Given: a registered peer
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: the peer leaves, then re-registers
        await client.send_raw((json.dumps(leave_frame(cid, bucket)) + "\n").encode())
        await client.exchange(register_frame(cid, bucket))
        response = await client.exchange(query_frame(bucket))
    # Then: exactly one fresh record remains
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_leave_removes_record_across_groups(rendezvous_factory, bucket, rng) -> None:
    # Given: a peer registered inside a group
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, group="home"))
        # When: a group-less leave for that (cid, bucket) is sent
        await client.send_raw((json.dumps(leave_frame(cid, bucket)) + "\n").encode())
        response = await client.exchange(query_frame(bucket, group="home"))
    # Then: the grouped record is gone (leave removes every (cid, bucket) entry)
    assert response["count"] == 0


@pytest.mark.asyncio
async def test_pipelined_three_frames_answered_in_order(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        # When: register + query + refresh are pipelined on one stream
        replies = await client.pipeline(
            [register_frame(cid, bucket), query_frame(bucket), refresh_frame(cid, bucket)]
        )
    # Then: each is answered in order (ack / response / ack)
    assert [r["type"] for r in replies] == ["ack", "response", "ack"]
    assert replies[1]["count"] == 1
    assert replies[1]["peers"][0]["cid"] == cid
