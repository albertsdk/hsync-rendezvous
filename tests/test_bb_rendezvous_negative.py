"""Black-box negative/robustness tests: silent drops, no oracle, leave semantics."""

from __future__ import annotations

import json

import pytest
from harness import (
    MAX_FRAME_BYTES,
    RawOutcome,
    RdvClient,
    leave_frame,
    query_frame,
    random_cid,
    register_frame,
)


@pytest.mark.asyncio
async def test_malformed_json_is_dropped(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a non-JSON line is sent
        result = await client.send_raw(b"{this is not json}\n")
        # Then: it is dropped silently and the node stays healthy
        assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_unknown_type_is_dropped(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a frame with an unknown type is sent
        raw = json.dumps({"protocol_version": "rdv/1", "type": "pwn"}) + "\n"
        result = await client.send_raw(raw.encode("utf-8"))
        # Then: it is dropped silently and the node stays healthy
        assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_oversized_frame_closes_stream(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: an over-limit frame is sent
        result = await client.send_raw(b"x" * 9000 + b"\n")
        # Then: the stream is closed, and the node stays healthy
        assert result.outcome is RawOutcome.CLOSED
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_targeted_field_is_rejected(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a register carries an unknown field (file_search)
        frame = register_frame(random_cid(rng), bucket)
        frame["file_search"] = "photo.jpg"
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        # Then: it is dropped silently (extra keys are forbidden)
        assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_invalid_cid_is_rejected(rendezvous_factory, bucket) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a register carries a malformed cid
        frame = register_frame("too-short", bucket)
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        # Then: it is dropped silently
        assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_wrong_protocol_version_is_rejected(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a register carries rdv/9
        frame = register_frame(random_cid(rng), bucket)
        frame["protocol_version"] = "rdv/9"
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        # Then: it is dropped silently
        assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_capacity_out_of_range_is_dropped(rendezvous_factory, bucket, rng) -> None:
    """The advisory capacity hint domain is 0..32: 33 is an invalid frame (silent drop)."""
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a register carries capacity=33
        frame = register_frame(random_cid(rng), bucket, capacity=33)
        result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
        # Then: it is dropped silently, and the node stays healthy
        assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_leave_removes_record_anonymously(rendezvous_factory, bucket, rng) -> None:
    # Given: a registered peer
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a leave is sent (no response frame by contract)
        result = await client.send_raw((json.dumps(leave_frame(cid, bucket)) + "\n").encode())
        assert result.outcome is RawOutcome.SILENT
        # Then: the record is gone from queries
        response = await client.exchange(query_frame(bucket))
    assert response["type"] == "response"
    assert response["count"] == 0


@pytest.mark.asyncio
async def test_partial_frame_then_disconnect_does_not_kill_node(
    rendezvous_factory, bucket, rng
) -> None:
    """A truncated NDJSON frame followed by a closed stream is inert, not fatal."""
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: half a frame (no newline) is sent and the stream closes
        result = await client.send_raw(b'{"protocol_version":"rdv/1","type":"reg', timeout=0.5)
        # Then: nothing to reply to (silent), and the node is unharmed
        assert result.outcome is RawOutcome.SILENT

    # A fresh connection still works: the truncated frame neither crashed nor
    # wedged the reader.
    async with RdvClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


# ---------------------------------------------------------------------------
# Boundary & field-grammar negatives (public contract only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_limit_out_of_range_is_dropped(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node and a bucket
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a query carries limit=0 and limit=51 (outside the 1..50 bound)
        for limit in (0, 51):
            raw = json.dumps(query_frame(bucket, limit=limit)) + "\n"
            result = await client.send_raw(raw.encode("utf-8"))
            # Then: each is dropped silently, and the node still serves
            assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_malformed_bucket_token_is_dropped(
    rendezvous_factory, bucket, group_key, rng
) -> None:
    """A non-64-hex token is an invalid frame (silent), not a failed-token attempt."""
    # Given: a protected bucket with a group key
    handle = rendezvous_factory(protected=[bucket], keys={bucket: group_key})
    async with RdvClient(handle.port) as client:
        # When: a register carries a token that is not 64 lowercase hex
        result = await client.send_raw(
            (json.dumps(register_frame(random_cid(rng), bucket, token="xyz")) + "\n").encode()
        )
        # Then: silent drop (no token_required oracle, no failed-token charge)
        assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_frame_size_boundary(rendezvous_factory) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: frames of exactly and just above the single-frame bound are sent
        at_limit = await client.send_raw(b"x" * MAX_FRAME_BYTES + b"\n")
        over_limit = await client.send_raw(b"x" * (MAX_FRAME_BYTES + 1) + b"\n")
    # Then: at the bound the line is accepted (JSON parse fails -> silent),
    #       above the bound the session is dropped (closed)
    assert at_limit.outcome is RawOutcome.SILENT
    assert over_limit.outcome is RawOutcome.CLOSED
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_malformed_field_types_are_dropped(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node and a bucket
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: structurally-wrong field types are sent
        cases = [
            register_frame(random_cid(rng), bucket, capacity="high"),  # type: ignore[arg-type]
            {"protocol_version": "rdv/1", "type": "register", "cid": 123, "bucket": bucket},
            {"protocol_version": 1, "type": "query", "bucket": bucket},
            register_frame(random_cid(rng), bucket, connected=-1),
            register_frame(random_cid(rng), bucket, capacity=-1),
            register_frame(random_cid(rng), bucket, sync_direction="sideways"),  # type: ignore[arg-type]
        ]
        for frame in cases:
            result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
            # Then: each is dropped silently
            assert result.outcome is RawOutcome.SILENT
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_endpoints_bounds_are_enforced(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node and a bucket
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: 17 endpoints (over the 16 cap) and a port=0 endpoint are sent
        many = [{"proto": "tcp", "host": "198.51.100.1", "port": 9000 + i} for i in range(17)]
        too_many = register_frame(random_cid(rng), bucket)
        too_many["endpoints"] = many
        zero_port = register_frame(random_cid(rng), bucket)
        zero_port["endpoints"] = [{"proto": "tcp", "host": "198.51.100.1", "port": 0}]
        for frame in (too_many, zero_port):
            result = await client.send_raw((json.dumps(frame) + "\n").encode("utf-8"))
            # Then: each is dropped silently
            assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_invalid_bucket_name_is_dropped(rendezvous_factory, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: buckets outside the canonical name grammar are used
        for bad_bucket in ("", "-x", "x-", "a b", "a/b", "x" * 64):
            raw = json.dumps(register_frame(random_cid(rng), bad_bucket)) + "\n"
            result = await client.send_raw(raw.encode("utf-8"))
            # Then: each is dropped silently
            assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_group_over_max_length_is_dropped(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: a 129-char group is sent (max_length is 128)
        raw = (json.dumps(register_frame(random_cid(rng), bucket, group="g" * 129)) + "\n").encode(
            "utf-8"
        )
        result = await client.send_raw(raw)
        # Then: the frame is dropped silently
        assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_cid_length_boundary(rendezvous_factory, bucket, rng) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: CIDs of 20, 21 and 22 chars are used
        for bad in ("a" * 20, "a" * 22):
            raw = json.dumps(register_frame(bad, bucket)) + "\n"
            # Then: 20/22 chars are dropped silently
            assert (await client.send_raw(raw.encode("utf-8"))).outcome is RawOutcome.SILENT
        # Then: the 21-char CID is accepted
        ack = await client.exchange(register_frame("a" * 21, bucket))
    assert ack["type"] == "ack"


@pytest.mark.asyncio
async def test_non_object_json_is_dropped(rendezvous_factory) -> None:
    # Given: a fresh node
    handle = rendezvous_factory()
    async with RdvClient(handle.port) as client:
        # When: well-formed JSON that is not a frame object is sent
        for payload in (b"[]\n", b'"x"\n', b"1\n"):
            result = await client.send_raw(payload)
            # Then: each is dropped silently
            assert result.outcome is RawOutcome.SILENT


@pytest.mark.asyncio
async def test_leave_unknown_cid_is_inert(rendezvous_factory, bucket, rng) -> None:
    # Given: a bucket with one registered peer
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
        # When: a leave for an unregistered cid is sent
        result = await client.send_raw(
            (json.dumps(leave_frame(random_cid(rng), bucket)) + "\n").encode()
        )
        # Then: it is silent and the registered peer survives
        assert result.outcome is RawOutcome.SILENT
        response = await client.exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid
