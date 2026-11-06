"""Black-box query/sample/group tests over the ``rdv/1`` wire protocol."""

from __future__ import annotations

import pytest
from harness import RdvClient, query_frame, random_cid, register_frame


@pytest.mark.asyncio
async def test_query_returns_registered_peers(rendezvous_factory, bucket, rng) -> None:
    # Given: two registered peers
    handle = rendezvous_factory()
    cid_a = random_cid(rng)
    cid_b = random_cid(rng)
    # When: a query is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid_a, bucket))
        await client.exchange(register_frame(cid_b, bucket))
        response = await client.exchange(query_frame(bucket))
    # Then: both peers are listed
    assert response["type"] == "response"
    assert response["error"] is None
    assert response["count"] == 2
    cids = {p["cid"] for p in response["peers"]}
    assert cids == {cid_a, cid_b}


@pytest.mark.asyncio
async def test_query_relays_capacity_hint(rendezvous_factory, bucket, rng) -> None:
    """The advisory capacity hint is relayed verbatim in the query peer list."""
    # Given: a serving and a slave peer with different capacities
    handle = rendezvous_factory()
    cid_serving = random_cid(rng)
    cid_slave = random_cid(rng)
    # When: a query is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid_serving, bucket, capacity=7))
        await client.exchange(register_frame(cid_slave, bucket, capacity=0))
        response = await client.exchange(query_frame(bucket))
    # Then: each capacity is relayed verbatim
    assert response["type"] == "response"
    assert response["error"] is None
    assert response["count"] == 2
    capacities = {p["cid"]: p["capacity"] for p in response["peers"]}
    assert capacities == {cid_serving: 7, cid_slave: 0}


@pytest.mark.asyncio
async def test_query_relays_the_election_advertisement(rendezvous_factory, bucket, rng) -> None:
    """The master-election advertisement is relayed verbatim on the public wire.

    A requester ranks candidates on these values (a serving incumbent outranks a
    newcomer; a ``never_master`` peer is not electable, and the advertised
    early-startup value breaks ties), so the node must echo them unchanged for
    both peer endpoint branches.
    """
    # Given: a serving incumbent and a never-master seeder
    handle = rendezvous_factory()
    cid_master = random_cid(rng)
    cid_never = random_cid(rng)
    # When: both register with election advertisements, then a query is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(
            register_frame(
                cid_master,
                bucket,
                server_ready=True,
                prefer_master=True,
                startup_time=1760000000.5,
                sync_direction="download-only",
            )
        )
        await client.exchange(
            register_frame(cid_never, bucket, never_master=True, capacity=0, endpoints=False)
        )
        response = await client.exchange(query_frame(bucket))
    # Then: each advertisement is echoed verbatim (with documented defaults)
    assert response["type"] == "response"
    assert response["error"] is None
    assert response["count"] == 2
    relayed = {p["cid"]: p for p in response["peers"]}
    assert relayed[cid_master]["server_ready"] is True
    assert relayed[cid_master]["prefer_master"] is True
    assert relayed[cid_master]["never_master"] is False
    assert relayed[cid_master]["startup_time"] == 1760000000.5
    assert relayed[cid_master]["sync_direction"] == "download-only"
    assert relayed[cid_never]["server_ready"] is False
    assert relayed[cid_never]["prefer_master"] is False
    assert relayed[cid_never]["never_master"] is True
    assert relayed[cid_never]["startup_time"] == 0.0
    assert relayed[cid_never]["sync_direction"] == "bidirectional"


@pytest.mark.asyncio
async def test_query_marks_reachability_by_advertised_endpoint(
    rendezvous_factory, bucket, rng
) -> None:
    """reachable is true only for peers that advertised a listen endpoint."""
    # Given: a master (with endpoint) and a slave (endpoint-less) peer
    handle = rendezvous_factory()
    cid_master = random_cid(rng)
    cid_slave = random_cid(rng)
    # When: a query is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid_master, bucket))
        await client.exchange(register_frame(cid_slave, bucket, endpoints=False))
        response = await client.exchange(query_frame(bucket))
    # Then: reachability follows the advertised endpoint
    assert response["type"] == "response"
    assert response["count"] == 2
    reachable = {p["cid"]: p["reachable"] for p in response["peers"]}
    assert reachable == {cid_master: True, cid_slave: False}
    slave = next(p for p in response["peers"] if p["cid"] == cid_slave)
    assert slave["endpoints"] == []


@pytest.mark.asyncio
async def test_query_group_filter(rendezvous_factory, bucket, rng) -> None:
    # Given: one grouped and one ungrouped peer
    handle = rendezvous_factory()
    home_cid = random_cid(rng)
    ungrouped_cid = random_cid(rng)
    # When: a query filtered by the group is sent
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(home_cid, bucket, group="home"))
        await client.exchange(register_frame(ungrouped_cid, bucket, group=None))
        response = await client.exchange(query_frame(bucket, group="home"))
    # Then: only the grouped peer is returned
    assert response["type"] == "response"
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == home_cid


@pytest.mark.asyncio
async def test_query_limit_bounds_sample(rendezvous_factory, bucket, rng) -> None:
    # Given: three registered peers
    handle = rendezvous_factory()
    # When: a query requests limit=1
    async with RdvClient(handle.port) as client:
        for _ in range(3):
            await client.exchange(register_frame(random_cid(rng), bucket))
        response = await client.exchange(query_frame(bucket, limit=1))
    # Then: exactly one peer is returned
    assert response["type"] == "response"
    assert response["count"] == 1
    assert len(response["peers"]) == 1


@pytest.mark.asyncio
async def test_pipelined_frames_answered_in_order(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: register + query are pipelined on one stream
    async with RdvClient(handle.port) as client:
        first, second = await client.pipeline([register_frame(cid, bucket), query_frame(bucket)])
    # Then: replies arrive in order
    assert first["type"] == "ack"
    assert second["type"] == "response"
    assert second["count"] == 1
    assert second["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_query_default_sample_limit_is_20(rendezvous_factory, bucket, rng) -> None:
    # Given: 25 registered peers (rate limits off so the register burst fits)
    handle = rendezvous_factory(no_rate_limit=True)
    async with RdvClient(handle.port) as client:
        for _ in range(25):
            await client.exchange(register_frame(random_cid(rng), bucket))
        # When: a query is sent without an explicit limit
        response = await client.exchange(query_frame(bucket))
    # Then: the default sample bound (20) applies
    assert response["count"] == 20
    assert len(response["peers"]) == 20


@pytest.mark.asyncio
async def test_query_limit_upper_bound_is_accepted(rendezvous_factory, bucket, rng) -> None:
    # Given: three registered peers
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        for _ in range(3):
            await client.exchange(register_frame(random_cid(rng), bucket))
        # When: a query uses the upper limit bound (50)
        response = await client.exchange(query_frame(bucket, limit=50))
    # Then: the whole bucket is returned (50 accepted, n=3)
    assert response["count"] == 3


@pytest.mark.asyncio
async def test_query_is_bucket_scoped(rendezvous_factory, bucket, rng) -> None:
    # Given: a peer registered in one bucket
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(random_cid(rng), bucket))
        # When: a different bucket is queried
        response = await client.exchange(query_frame(bucket + "x"))
    # Then: no cross-bucket leak
    assert response["count"] == 0
    assert response["peers"] == []


@pytest.mark.asyncio
async def test_query_group_less_excludes_grouped_peers(rendezvous_factory, bucket, rng) -> None:
    # Given: one grouped and one ungrouped peer
    handle = rendezvous_factory()
    grouped_cid = random_cid(rng)
    ungrouped_cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(grouped_cid, bucket, group="home"))
        await client.exchange(register_frame(ungrouped_cid, bucket))
        # When: a group-less query is sent
        response = await client.exchange(query_frame(bucket))
    # Then: only the ungrouped peer is returned (sample keys on (bucket, group))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == ungrouped_cid


@pytest.mark.asyncio
async def test_same_cid_in_different_groups_are_distinct_records(
    rendezvous_factory, bucket, rng
) -> None:
    # Given: the same cid registered in two groups
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, group="a"))
        await client.exchange(register_frame(cid, bucket, group="b"))
        # When: each group is queried
        a = await client.exchange(query_frame(bucket, group="a"))
        b = await client.exchange(query_frame(bucket, group="b"))
    # Then: the route key is (cid, bucket, group) -> two distinct records
    assert a["count"] == 1
    assert b["count"] == 1
    assert a["peers"][0]["cid"] == cid
    assert b["peers"][0]["cid"] == cid
