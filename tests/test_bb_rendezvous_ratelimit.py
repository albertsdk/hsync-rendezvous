"""Black-box rate-limit tests: burst then ``rate_limited`` + ``retry_after``.

The budgets below are the ``rdv/1`` contract (§Auth), restated here because the
suite is language-neutral and must validate any implementation against the spec,
not against its own source.

Loopback means every client shares one source IP, so this suite is also where the
multi-client side of the contract is exercised: one household behind one public
address must never be refused.
"""

from __future__ import annotations

import pytest
from harness import (
    BAD_TOKEN_BURST,
    QUERY_PAIR_BURST,
    REGISTER_PAIR_BURST,
    RdvClient,
    query_frame,
    random_cid,
    refresh_frame,
    register_frame,
)


@pytest.mark.asyncio
async def test_query_rate_limited_after_burst(rendezvous_factory, bucket) -> None:
    # Given: a node with rate limits on
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: the query burst is exhausted
        for _ in range(QUERY_PAIR_BURST):
            response = await client.exchange(query_frame(bucket))
            assert response["error"] is None
        limited = await client.exchange(query_frame(bucket))
    # Then: the next query is rate_limited with a retry hint
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["peers"] == []
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_register_rate_limited_after_burst(rendezvous_factory, bucket, rng) -> None:
    # Given: a node with rate limits on
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: the register burst is exhausted
        for _ in range(REGISTER_PAIR_BURST):
            ack = await client.exchange(register_frame(random_cid(rng), bucket))
            assert ack["type"] == "ack"
        limited = await client.exchange(register_frame(random_cid(rng), bucket))
    # Then: the next register is rate_limited
    assert limited["type"] == "response"
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_bad_token_rate_limited_after_burst(rendezvous_factory, bucket, group_key) -> None:
    # Given: a protected bucket and its key
    handle = rendezvous_factory(protected=[bucket], keys={bucket: group_key})
    async with RdvClient(handle.port) as client:
        # When: the failed-token burst is exhausted
        for _ in range(BAD_TOKEN_BURST):
            refused = await client.exchange(query_frame(bucket, token="0" * 64))
            assert refused["error"] == "token_required"
        limited = await client.exchange(query_frame(bucket, token="0" * 64))
    # Then: the next attempt is rate_limited (anti-abuse budget)
    assert limited["error"] == "rate_limited"
    assert limited["retry_after"] >= 1


@pytest.mark.asyncio
async def test_a_household_behind_one_ip_is_never_refused(rendezvous_factory, bucket, rng) -> None:
    """Two clients, one bucket, one public address: a lease cycle with no refusal.

    This is the shape of a home or an office: the per-(IP, bucket) and per-IP
    budgets serve every client's own start burst (one register plus eight
    queries) and its lease refresh, so a legitimate household never sees
    ``rate_limited`` and never has to back off.
    """
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as first, RdvClient(handle.port) as second:
        for client in (first, second):
            cid = random_cid(rng)
            assert (await client.exchange(register_frame(cid, bucket)))["type"] == "ack"
            for _ in range(8):
                response = await client.exchange(query_frame(bucket))
                assert response["error"] is None
            assert (await client.exchange(refresh_frame(cid, bucket)))["type"] == "ack"


@pytest.mark.asyncio
async def test_no_rate_limit_seam_disables_throttling(rendezvous_factory, bucket) -> None:
    # Given: a node started with the --no-rate-limit seam
    handle = rendezvous_factory(no_rate_limit=True)
    async with RdvClient(handle.port) as client:
        # When: the queries exceed the query pair burst
        # Then: with the seam off the limiter never triggers
        for _ in range(QUERY_PAIR_BURST + 5):
            response = await client.exchange(query_frame(bucket))
            assert response["error"] is None
