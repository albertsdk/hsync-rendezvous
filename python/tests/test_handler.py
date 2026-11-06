"""RendezvousHandler behavioural tests: routing, protected buckets, rate limits,
STUN-echo and frame rejection. Pure logic — no sockets involved.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from hsync_rendezvous import handler as handler_mod
from hsync_rendezvous.handler import RendezvousConfigError, RendezvousHandler
from hsync_rendezvous.tokens import derive_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"
CID2 = "abcdefghijklmnopqrstu"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
KEY = b"group-secret"


def decoded(raw: bytes | None) -> dict | None:
    """Decode a handler reply for assertions (handle() returns JSON bytes)."""
    return json.loads(raw) if raw is not None else None


def send(h: RendezvousHandler, frame: object, *, peer_ip: str, peer_port: int) -> bytes | None:
    """Feed a frame dict through the raw-bytes handle() contract."""
    return h.handle(json.dumps(frame), peer_ip=peer_ip, peer_port=peer_port)


def make_handler(
    protected: tuple[str, ...] = (),
    *,
    private: bool = False,
    keys: dict[str, str] | None = None,
) -> RendezvousHandler:
    """Build a handler; ``keys`` defaults to a ``k<bucket>`` secret per bucket."""
    if keys is None:
        keys = {bucket: "k" + bucket for bucket in protected}
    return RendezvousHandler(
        protected_buckets=protected,
        private=private,
        group_keys={bucket: SecretStr(key) for bucket, key in keys.items()},
    )


def test_open_bucket_still_runs_the_constant_time_compare(monkeypatch):
    """The open path performs the same compare, so timing does not reveal gating."""
    h = make_handler()
    calls: list[int] = []
    real = handler_mod.constant_time_equals

    def spy(left: bytes, right: bytes) -> bool:
        calls.append(1)
        return real(left, right)

    monkeypatch.setattr(handler_mod, "constant_time_equals", spy)
    assert h._authorize("open-bucket", None, "203.0.113.7") == "ok"
    assert len(calls) == 1


@contextmanager
def frozen_clock(now: float) -> Iterator[None]:
    """Pin the routing **and** handler clocks for TTL assertions.

    ``PeerRecord.expires_at`` and the on-request prune both read
    ``time.monotonic()``, so a test that compares against an absolute ``now``
    must freeze both: against the real clock the outcome would depend on the
    host uptime (a freshly booted runner sees ``now`` in the future).
    """
    with (
        patch("hsync_rendezvous.routing.time.monotonic", return_value=now),
        patch("hsync_rendezvous.handler.time.monotonic", return_value=now),
    ):
        yield


def register_frame(
    cid: str = CID,
    bucket: str = "shared",
    group: str | None = "home",
    token: str | None = None,
    host: str = "198.51.100.7",
    port: int = 443,
    capacity: int = 20,
    **extra: object,
) -> dict:
    frame: dict = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": cid,
        "bucket": bucket,
        "cert_fp": FP,
        "version": "1.0.0",
        "capacity": capacity,
        "endpoints": [{"proto": "tcp", "host": host, "port": port}],
    }
    if group is not None:
        frame["group"] = group
    if token is not None:
        frame["bucket_token"] = token
    frame.update(extra)
    return frame


def query_frame(
    bucket: str = "shared",
    group: str | None = "home",
    token: str | None = None,
    limit: int = 20,
) -> dict:
    frame: dict = {
        "protocol_version": "rdv/1",
        "type": "query",
        "bucket": bucket,
        "limit": limit,
    }
    if group is not None:
        frame["group"] = group
    if token is not None:
        frame["bucket_token"] = token
    return frame


def leave_frame(
    cid: str = CID,
    bucket: str = "shared",
    token: str | None = None,
) -> dict:
    frame: dict = {"protocol_version": "rdv/1", "type": "leave", "cid": cid, "bucket": bucket}
    if token is not None:
        frame["bucket_token"] = token
    return frame


def refresh_frame(
    cid: str = CID,
    bucket: str = "shared",
    group: str | None = "home",
    token: str | None = None,
    connected: int | None = None,
) -> dict:
    frame: dict = {"protocol_version": "rdv/1", "type": "refresh", "cid": cid, "bucket": bucket}
    if group is not None:
        frame["group"] = group
    if token is not None:
        frame["bucket_token"] = token
    if connected is not None:
        frame["connected"] = connected
    return frame


def test_register_acks_with_stun_echo_and_creates_record() -> None:
    h = make_handler()
    response = decoded(send(h, register_frame(), peer_ip="198.51.100.7", peer_port=54321))
    assert response is not None
    assert response["type"] == "ack"
    assert response["observed_endpoint"] == {
        "proto": "udp",
        "ip": "198.51.100.7",
        "port": 54321,
    }
    assert response["ttl"] == 60
    assert response["server_time"].endswith("Z")
    assert h.routing.count(bucket="shared") == 1


def test_query_returns_advertised_endpoint_random_sample() -> None:
    h = make_handler()
    send(
        h,
        register_frame(cid=CID, host="198.51.100.7"),
        peer_ip="198.51.100.7",
        peer_port=54321,
    )
    send(
        h,
        register_frame(cid=CID2, host="198.51.100.8"),
        peer_ip="198.51.100.8",
        peer_port=54322,
    )
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    assert response["type"] == "response"
    assert response["count"] == 2
    assert response["error"] is None
    peers = {
        (p["cid"], p["endpoints"][0]["host"], p["endpoints"][0]["port"]) for p in response["peers"]
    }
    assert peers == {
        (CID, "198.51.100.7", 443),
        (CID2, "198.51.100.8", 443),
    }


def test_query_relays_every_advertised_endpoint_in_order() -> None:
    """The candidate list is relayed verbatim: no hairpin for same-NAT peers.

    Every advertised endpoint survives, in order, so a requester behind the same
    NAT can prefer a local candidate over a public one with no hairpin route. A
    peer that advertised none is relayed with an empty list and
    ``reachable=false`` (there is nothing a third party could dial).
    """
    h = make_handler()
    send(
        h,
        register_frame(
            cid=CID,
            endpoints=[
                {"proto": "tcp", "host": "203.0.113.7", "port": 443},
                {"proto": "tcp", "host": "192.168.1.42", "port": 443},
            ],
        ),
        peer_ip="198.51.100.7",
        peer_port=54321,
    )
    no_endpoint = register_frame(cid=CID2, host="198.51.100.8")
    no_endpoint.pop("endpoints")
    send(h, no_endpoint, peer_ip="198.51.100.8", peer_port=54322)
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    relayed = {p["cid"]: p for p in response["peers"]}
    assert relayed[CID]["endpoints"] == [
        {"proto": "tcp", "host": "203.0.113.7", "port": 443},
        {"proto": "tcp", "host": "192.168.1.42", "port": 443},
    ]
    assert relayed[CID]["reachable"] is True
    assert relayed[CID2]["endpoints"] == []
    assert relayed[CID2]["reachable"] is False


def test_capacity_hint_round_trips_through_query() -> None:
    """The advisory capacity hint is stored and echoed in the query peer list."""
    h = make_handler()
    # endpoint branch: the advertised candidate list is relayed
    send(h, register_frame(cid=CID, capacity=32), peer_ip="198.51.100.7", peer_port=54321)
    # fallback branch: no advertised endpoint → the observed source is used
    no_endpoint = register_frame(cid=CID2, capacity=5, host="198.51.100.8")
    no_endpoint.pop("endpoints")
    send(h, no_endpoint, peer_ip="198.51.100.8", peer_port=54322)
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    assert response["count"] == 2
    capacities = {p["cid"]: p["capacity"] for p in response["peers"]}
    assert capacities == {CID: 32, CID2: 5}


def test_capacity_defaults_to_zero_and_survives_refresh() -> None:
    """Absent capacity = 0 (not a seeder); refresh never mutates it."""
    h = make_handler()
    frame = register_frame(cid=CID, capacity=0)
    frame.pop("capacity")  # absent on the wire → default 0
    send(h, frame, peer_ip="198.51.100.7", peer_port=54321)
    record = h.routing.get(CID, "shared", "home")
    assert record is not None
    assert record.capacity == 0
    send(
        h,
        {
            "protocol_version": "rdv/1",
            "type": "refresh",
            "cid": CID,
            "bucket": "shared",
            "group": "home",
            "connected": 7,
        },
        peer_ip="198.51.100.7",
        peer_port=54321,
    )
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    assert response["peers"][0]["capacity"] == 0
    # The advisory connected count was refreshed and must be relayed too.
    assert response["peers"][0]["connected"] == 7


def test_query_relays_the_connected_count() -> None:
    """A peer's connected count is relayed so peers can display group presence."""
    h = make_handler()
    send(h, register_frame(connected=2), peer_ip="198.51.100.7", peer_port=54321)

    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))

    assert response is not None
    assert response["peers"][0]["connected"] == 2


def test_refresh_updates_a_cached_connected_count() -> None:
    """A refresh invalidates the cached wire projection, not a stale count."""
    h = make_handler()
    send(h, register_frame(connected=1), peer_ip="198.51.100.7", peer_port=54321)
    first = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert first["peers"][0]["connected"] == 1

    send(h, refresh_frame(connected=3), peer_ip="198.51.100.7", peer_port=54321)
    second = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))

    assert second["peers"][0]["connected"] == 3


def test_election_advertisement_round_trips_through_query() -> None:
    """The election advertisement is stored and echoed verbatim in the peer list.

    A requester's master election ranks candidates on exactly these values, so
    the relay must not drop or rewrite them: a serving incumbent
    (``server_ready``) and a never-master seeder must stay distinguishable.
    """
    h = make_handler()
    # endpoint branch: the advertised candidate list is relayed
    send(
        h,
        register_frame(
            cid=CID,
            server_ready=True,
            prefer_master=True,
            startup_time=1760000000.5,
            sync_direction="download-only",
        ),
        peer_ip="198.51.100.7",
        peer_port=54321,
    )
    # fallback branch: no advertised endpoint → the observed source is used
    no_endpoint = register_frame(cid=CID2, host="198.51.100.8", never_master=True)
    no_endpoint.pop("endpoints")
    send(h, no_endpoint, peer_ip="198.51.100.8", peer_port=54322)
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    assert response["count"] == 2
    relayed = {p["cid"]: p for p in response["peers"]}
    assert relayed[CID]["server_ready"] is True
    assert relayed[CID]["prefer_master"] is True
    assert relayed[CID]["never_master"] is False
    assert relayed[CID]["startup_time"] == 1760000000.5
    assert relayed[CID]["sync_direction"] == "download-only"
    assert relayed[CID2]["server_ready"] is False
    assert relayed[CID2]["prefer_master"] is False
    assert relayed[CID2]["never_master"] is True
    assert relayed[CID2]["startup_time"] == 0.0
    assert relayed[CID2]["sync_direction"] == "bidirectional"


def test_election_advertisement_defaults_and_survives_refresh() -> None:
    """Absent advertisement keys default; ``refresh`` never mutates them.

    A role change (a seeder becoming master, a master yielding) requires a new
    ``register``: the record's wire projection is materialized once, exactly
    like ``capacity`` and ``reachable``.
    """
    h = make_handler()
    send(h, register_frame(cid=CID), peer_ip="198.51.100.7", peer_port=54321)
    record = h.routing.get(CID, "shared", "home")
    assert record is not None
    assert record.server_ready is False
    assert record.prefer_master is False
    assert record.never_master is False
    assert record.startup_time == 0.0
    assert record.sync_direction == "bidirectional"
    send(
        h,
        {
            "protocol_version": "rdv/1",
            "type": "refresh",
            "cid": CID,
            "bucket": "shared",
            "group": "home",
            "connected": 7,
        },
        peer_ip="198.51.100.7",
        peer_port=54321,
    )
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    peer = response["peers"][0]
    assert peer["server_ready"] is False
    assert peer["startup_time"] == 0.0
    assert peer["sync_direction"] == "bidirectional"


def test_reachable_is_derived_from_endpoints() -> None:
    """reachable = bool(endpoints): a peer with no advertised endpoint is not a master."""
    h = make_handler()
    send(h, register_frame(cid=CID), peer_ip="198.51.100.7", peer_port=54321)
    no_endpoint = register_frame(cid=CID2, host="198.51.100.8")
    no_endpoint.pop("endpoints")
    send(h, no_endpoint, peer_ip="198.51.100.8", peer_port=54322)
    response = decoded(send(h, query_frame(limit=10), peer_ip="10.0.0.1", peer_port=1111))
    assert response is not None
    reachable = {p["cid"]: p["reachable"] for p in response["peers"]}
    assert reachable == {CID: True, CID2: False}
    # the endpoint-less peer is relayed with no candidate at all: the node only
    # knows its source port, which is not a listen port a third party could dial
    fallback = next(p for p in response["peers"] if p["cid"] == CID2)
    assert fallback["endpoints"] == []
    # refresh never flips reachable (the record still advertises no endpoint)
    send(
        h,
        {
            "protocol_version": "rdv/1",
            "type": "refresh",
            "cid": CID2,
            "bucket": "shared",
            "group": "home",
        },
        peer_ip="198.51.100.8",
        peer_port=54322,
    )
    after = h.routing.get(CID2, "shared", "home")
    assert after is not None
    assert after.reachable is False


def test_query_group_filter() -> None:
    h = make_handler()
    send(h, register_frame(cid=CID, group="home"), peer_ip="10.0.0.1", peer_port=1111)
    send(
        h,
        register_frame(cid=CID2, group=None, host="198.51.100.8"),
        peer_ip="10.0.0.2",
        peer_port=1112,
    )
    response = decoded(send(h, query_frame(group="home"), peer_ip="10.0.0.3", peer_port=1113))
    assert response is not None
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == CID


def test_protected_bucket_uniform_token_required() -> None:
    h = make_handler(protected=("shared",))
    # anonymous query on a protected bucket → uniform refusal, empty list
    response = decoded(send(h, query_frame(token=None), peer_ip="10.0.0.1", peer_port=1))
    assert response is not None
    assert response["error"] == "token_required"
    assert response["peers"] == []
    assert response["count"] == 0
    # wrong (but well-formed) token → same uniform refusal
    response = decoded(send(h, query_frame(token="0" * 64), peer_ip="10.0.0.1", peer_port=1))
    assert response is not None
    assert response["error"] == "token_required"


def test_protected_bucket_correct_token_returns_peers() -> None:
    h = make_handler(protected=("shared",))
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token), peer_ip="198.51.100.7", peer_port=1)
    response = decoded(send(h, query_frame(token=token), peer_ip="10.0.0.1", peer_port=1))
    assert response is not None
    assert response["error"] is None
    assert response["count"] == 1


def test_protected_bucket_register_without_token_does_not_create() -> None:
    h = make_handler(protected=("shared",))
    response = decoded(send(h, register_frame(token=None), peer_ip="10.0.0.1", peer_port=1))
    assert response is not None
    assert response["error"] == "token_required"
    assert h.routing.count(bucket="shared") == 0
    # a token that cannot exist in the derivation domain (not 64 lowercase hex)
    # is an INVALID FRAME — silently dropped, like every other malformed frame —
    # never a failed-token attempt (which would answer token_required)
    assert send(h, register_frame(token="not-a-token"), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 0


def test_open_bucket_needs_no_token() -> None:
    h = make_handler()  # no protected buckets → everything open
    ack = decoded(send(h, register_frame(), peer_ip="1.1.1.1", peer_port=1))
    assert ack is not None and ack["type"] == "ack"
    resp = decoded(send(h, query_frame(), peer_ip="2.2.2.2", peer_port=1))
    assert resp is not None and resp["error"] is None


def test_open_mode_ignores_keys_of_undeclared_buckets() -> None:
    """A provisioned key must not gate a bucket the operator did not declare.

    Guard for the open-mode contract: ``--private`` is the only way to widen the
    protected-bucket policy to every bucket, so providing a key without
    ``--protected-bucket`` keeps the bucket open (byte-identical behavior).
    """
    h = make_handler(keys={"shared": "kshared"})
    resp = decoded(send(h, query_frame(token=None), peer_ip="10.0.0.1", peer_port=1))
    assert resp is not None and resp["error"] is None
    ack = decoded(send(h, register_frame(token=None), peer_ip="198.51.100.7", peer_port=1))
    assert ack is not None and ack["type"] == "ack"


def test_private_node_gates_every_bucket() -> None:
    h = make_handler(private=True, keys={"shared": "kshared"})
    token = derive_bucket_token(b"kshared", "shared")
    # no token → uniform refusal and no record created
    resp = decoded(send(h, register_frame(token=None), peer_ip="10.0.0.1", peer_port=1))
    assert resp is not None and resp["error"] == "token_required"
    assert h.routing.count(bucket="shared") == 0
    # valid token → ack + record
    ack = decoded(send(h, register_frame(token=token), peer_ip="198.51.100.7", peer_port=1))
    assert ack is not None and ack["type"] == "ack"
    assert h.routing.count(bucket="shared") == 1
    # valid token → peers are returned
    resp = decoded(send(h, query_frame(token=token), peer_ip="10.0.0.2", peer_port=1))
    assert resp is not None and resp["error"] is None and resp["count"] == 1


def test_private_node_refuses_unkeyed_bucket_like_a_wrong_token() -> None:
    """A bucket without a key is refused exactly like a wrong token (no oracle)."""
    h = make_handler(private=True, keys={"shared": "kshared"})
    unkeyed = decoded(
        send(h, query_frame(bucket="other", token=None), peer_ip="10.0.0.1", peer_port=1)
    )
    unkeyed_token = decoded(
        send(h, query_frame(bucket="other", token="0" * 64), peer_ip="10.0.0.1", peer_port=1)
    )
    keyed_wrong = decoded(
        send(h, query_frame(bucket="shared", token="0" * 64), peer_ip="10.0.0.1", peer_port=1)
    )
    assert unkeyed is not None and unkeyed_token is not None and keyed_wrong is not None
    for response in (unkeyed, unkeyed_token, keyed_wrong):
        assert response["type"] == "response"
        assert response["error"] == "token_required"
        assert response["peers"] == []
        assert response["count"] == 0


def test_private_node_failed_token_budget_still_applies() -> None:
    h = make_handler(private=True, keys={"shared": "kshared"})
    for _ in range(5):  # 5 failed-token attempts/min per IP, same budget
        resp = decoded(send(h, query_frame(token="0" * 64), peer_ip="10.0.0.7", peer_port=1))
        assert resp is not None and resp["error"] == "token_required"
    resp = decoded(send(h, query_frame(token="0" * 64), peer_ip="10.0.0.7", peer_port=1))
    assert resp is not None
    assert resp["error"] == "rate_limited"
    assert resp["retry_after"] >= 1


def test_private_leave_requires_a_valid_token() -> None:
    """Private mode closes the spoofable-leave vector; refusals stay silent."""
    h = make_handler(private=True, keys={"shared": "kshared"})
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token), peer_ip="198.51.100.7", peer_port=1)
    assert h.routing.count(bucket="shared") == 1
    # anonymous leave → silently dropped (the spec has no leave response)
    assert send(h, leave_frame(token=None), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 1
    # wrong token → still dropped
    assert send(h, leave_frame(token="0" * 64), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 1
    # valid token → record removed, still no response frame
    assert send(h, leave_frame(token=token), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 0


def test_private_leave_on_unkeyed_bucket_is_dropped() -> None:
    h = make_handler(private=True, keys={"shared": "kshared"})
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token), peer_ip="198.51.100.7", peer_port=1)
    send(h, leave_frame(bucket="other"), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 1


def test_private_node_without_keys_fails_fast() -> None:
    with pytest.raises(RendezvousConfigError, match="private node without any group key"):
        make_handler(private=True)
    # one key is enough to serve the node
    assert make_handler(private=True, keys={"shared": "kshared"}) is not None


def test_query_rate_limited_per_ip_bucket_pair() -> None:
    h = make_handler()
    results = []
    for _ in range(10):  # burst 10 for (IP, bucket)
        results.append(decoded(send(h, query_frame(), peer_ip="10.0.0.9", peer_port=1)))
    assert all(r is not None and r["type"] == "response" and r["error"] is None for r in results)
    limited = decoded(send(h, query_frame(), peer_ip="10.0.0.9", peer_port=1))
    assert limited is not None
    assert limited["error"] == "rate_limited"
    assert limited["peers"] == []
    assert limited["count"] == 0
    assert limited["retry_after"] >= 1
    # a different IP is not throttled by the same bucket
    other = decoded(send(h, query_frame(), peer_ip="10.0.0.8", peer_port=1))
    assert other is not None and other["error"] is None


def test_register_rate_limited_per_ip_bucket_pair() -> None:
    h = make_handler()
    for _ in range(10):  # 10/min per (IP, bucket)
        ack = decoded(send(h, register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1))
        assert ack is not None and ack["type"] == "ack"
    response = decoded(send(h, register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1))
    assert response is not None
    assert response["type"] == "response"
    assert response["error"] == "rate_limited"
    assert response["retry_after"] >= 1


def test_bad_token_attempts_rate_limited_per_ip() -> None:
    h = make_handler(protected=("shared",))
    for _ in range(5):  # 5 failed-token attempts/min per IP
        response = decoded(send(h, query_frame(token="0" * 64), peer_ip="10.0.0.5", peer_port=1))
        assert response is not None and response["error"] == "token_required"
    response = decoded(send(h, query_frame(token="0" * 64), peer_ip="10.0.0.5", peer_port=1))
    assert response is not None
    assert response["error"] == "rate_limited"


def test_leave_removes_record_anonymously() -> None:
    h = make_handler()
    ack = decoded(send(h, register_frame(), peer_ip="10.0.0.1", peer_port=1))
    assert ack is not None and ack["type"] == "ack"
    assert h.routing.count(bucket="shared") == 1
    send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 0


def test_leave_removes_all_groups_registered_from_the_same_source() -> None:
    h = make_handler()
    # The same CID registered in two groups of the same bucket.
    send(h, register_frame(cid=CID, group="home"), peer_ip="10.0.0.1", peer_port=1)
    send(h, register_frame(cid=CID, group="work"), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 2
    # leave carries no group: it must remove every (cid, bucket) entry the
    # departing source owns (the outbound policy is per source IP, not per group).
    send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 0
    assert h.routing.get(CID, "shared", "home") is None
    assert h.routing.get(CID, "shared", "work") is None
    # Indexes must remain consistent for later registrations and queries.
    send(h, register_frame(cid=CID2, group="home"), peer_ip="10.0.0.3", peer_port=3)
    assert h.routing.count(bucket="shared") == 1
    response = decoded(
        send(h, query_frame(group="home", limit=10), peer_ip="10.0.0.4", peer_port=4)
    )
    assert response is not None
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == CID2


def test_leave_from_a_foreign_source_is_ignored() -> None:
    """Open mode: a leave from an IP the peer never registered from evicts nothing.

    This is the regression test for the spoofable-departure vector: the frame
    alone (``cid`` + ``bucket`` are plain wire data) must not be able to break
    someone else's rendezvous entry, and the node exposes nothing back (the spec
    carries no leave response, so the refusal is a silent drop).
    """
    h = make_handler()
    send(h, register_frame(), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 1
    # stranger IP: silently ignored, the record survives
    assert send(h, leave_frame(), peer_ip="10.0.0.2", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 1
    # the owner source itself still leaves normally
    assert send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 0


def test_source_rebind_leaves_only_own_records() -> None:
    """A source-IP change keeps the other-source record alive until TTL expiry.

    Two devices on different networks registering the *same* CID (or a NAT
    rebinding) own separate records: one of them departing must not evict the
    other, and the departed one simply re-registers with its next cycle.
    """
    h = make_handler()
    send(h, register_frame(group="home"), peer_ip="10.0.0.1", peer_port=1)
    send(h, register_frame(group="work"), peer_ip="10.0.0.2", peer_port=2)
    assert h.routing.count(bucket="shared") == 2
    send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 1
    assert h.routing.get(CID, "shared", "home") is None
    assert h.routing.get(CID, "shared", "work") is not None


def test_partial_leave_keeps_the_cid_index_faithful() -> None:
    """Regression (found by the fuzz harness, seed 0): after a partial
    (same-source) leave the ``(cid, bucket)`` index must not keep dropped keys —
    pre-fix, the next leave/query over the index hit a KeyError on the routing
    table instead of iterating the surviving records.
    """
    h = make_handler()
    send(h, register_frame(group="home"), peer_ip="10.0.0.1", peer_port=1)
    send(h, register_frame(group="work"), peer_ip="10.0.0.2", peer_port=2)
    # partial leave: only the foreign-source record must survive
    assert send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 1
    # the index stays usable after the partial removal (pre-fix: KeyError here)
    assert h.routing.source_ips(CID, "shared") == ["10.0.0.2"]
    assert send(h, leave_frame(), peer_ip="10.0.0.2", peer_port=2) is None
    assert h.routing.count(bucket="shared") == 0
    assert h.routing.source_ips(CID, "shared") == []


def test_protected_bucket_leave_with_a_valid_token_removes_from_any_source() -> None:
    """On a protected bucket a valid token authenticates the departure."""
    h = make_handler(protected=("shared",))
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 1
    # token-carrying leave from an unrelated source IP: authenticated → removed
    assert send(h, leave_frame(token=token), peer_ip="10.0.0.9", peer_port=9) is None
    assert h.routing.count(bucket="shared") == 0


def test_protected_bucket_leave_from_the_owner_source_needs_no_token() -> None:
    """The same-source exemption also covers protected buckets (plain departure)."""
    h = make_handler(protected=("shared",))
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token), peer_ip="10.0.0.1", peer_port=1)
    assert send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1) is None
    assert h.routing.count(bucket="shared") == 0


def test_protected_bucket_foreign_leave_without_a_token_is_ignored() -> None:
    """Neither the source nor (a valid) token state: silently ignored."""
    h = make_handler(protected=("shared",))
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.count(bucket="shared") == 1
    assert send(h, leave_frame(), peer_ip="10.0.0.9", peer_port=9) is None
    assert h.routing.count(bucket="shared") == 1
    assert send(h, leave_frame(token="0" * 64), peer_ip="10.0.0.9", peer_port=9) is None
    assert h.routing.count(bucket="shared") == 1


def test_refresh_renews_ttl_but_never_creates() -> None:
    h = make_handler()
    with frozen_clock(1_000.0):
        send(h, register_frame(), peer_ip="10.0.0.1", peer_port=1)
    before = h.routing.get(CID, "shared", "home", now=1_000.0)
    assert before is not None
    before_expires = before.expires_at  # live record: touch() mutates it too
    with frozen_clock(1_030.0):
        refreshed = decoded(
            send(
                h,
                {
                    "protocol_version": "rdv/1",
                    "type": "refresh",
                    "cid": CID,
                    "bucket": "shared",
                    "group": "home",
                    "connected": 7,
                },
                peer_ip="10.0.0.1",
                peer_port=1,
            )
        )
    assert refreshed is not None
    assert refreshed["type"] == "ack"
    after = h.routing.get(CID, "shared", "home", now=1_030.0)
    assert after is not None
    assert after.connected == 7
    assert after.expires_at > before_expires
    assert before_expires == 1_060.0  # register: t + TTL
    assert after.expires_at == 1_090.0  # refresh: t + TTL from the new time
    # unknown CID: refresh must NOT create a record. Stays under the frozen clock
    # so the periodic prune (now=1030) does not expire the live CID (t+TTL 1090).
    with frozen_clock(1_030.0):
        dropped = send(
            h,
            {
                "protocol_version": "rdv/1",
                "type": "refresh",
                "cid": CID2,
                "bucket": "shared",
            },
            peer_ip="10.0.0.1",
            peer_port=1,
        )
    assert dropped is None
    assert h.routing.count(bucket="shared") == 1


def test_unknown_and_malformed_frames_are_dropped() -> None:
    h = make_handler()
    # Not JSON at all, and JSON that is not an object: dropped (no-log, no oracle).
    assert h.handle(b"", peer_ip="10.0.0.1", peer_port=1) is None
    assert h.handle(b"{oops", peer_ip="10.0.0.1", peer_port=1) is None
    assert h.handle(b"null", peer_ip="10.0.0.1", peer_port=1) is None
    assert h.handle(b'"not a dict"', peer_ip="10.0.0.1", peer_port=1) is None
    assert h.handle(b"[1,2]", peer_ip="10.0.0.1", peer_port=1) is None
    # Missing / unknown discriminator: dropped by the rigid schema.
    assert h.handle(b'{"protocol_version":"rdv/1"}', peer_ip="10.0.0.1", peer_port=1) is None
    assert (
        h.handle(b'{"protocol_version":"rdv/1","type":"pwn"}', peer_ip="10.0.0.1", peer_port=1)
        is None
    )
    # named targeted fields are rejected by the rigid schema
    bad = register_frame()
    bad["file_search"] = "photo.jpg"
    assert h.handle(json.dumps(bad), peer_ip="10.0.0.1", peer_port=1) is None


def test_malformed_frames_have_their_own_budget() -> None:
    """An IP that floods invalid frames exhausts its own budget and is then
    dropped BEFORE the parser runs, so a parse storm costs no event-loop CPU.
    Invalid frames never drain the VALID-frame admission, and a different IP
    starts from its own fresh budget.
    """
    h = make_handler()
    from hsync_rendezvous.handler import PARSE_IP_BURST

    for _ in range(PARSE_IP_BURST):
        assert h.handle(b"{oops", peer_ip="10.0.0.9", peer_port=1) is None
    # Over budget the IP is gated wholesale: even a well-formed frame from it is
    # dropped pre-parse, which is exactly what bounds the parse storm.
    assert h.handle(b"{oops", peer_ip="10.0.0.9", peer_port=1) is None
    assert h.handle(json.dumps(register_frame(cid=CID2)), peer_ip="10.0.0.9", peer_port=1) is None
    # ...and a different IP starts from its own fresh budget
    ack = decoded(send(h, register_frame(cid=CID2), peer_ip="10.0.0.8", peer_port=1))
    assert ack is not None and ack["type"] == "ack"


def test_generic_per_ip_admission_cap() -> None:
    h = make_handler()
    from hsync_rendezvous.handler import OP_IP_BURST

    for _ in range(OP_IP_BURST):
        send(h, register_frame(cid=CID2), peer_ip="9.9.9.9", peer_port=1)
    response = decoded(send(h, register_frame(cid=CID2), peer_ip="9.9.9.9", peer_port=1))
    assert response is not None
    assert response["error"] == "rate_limited"


def test_protected_bucket_without_key_fails_fast() -> None:
    try:
        RendezvousHandler(protected_buckets=("shared",), group_keys={})
    except RendezvousConfigError:
        pass
    else:  # pragma: no cover - expected to raise
        raise AssertionError("protected bucket without a key must fail at startup")


def test_prune_removes_expired_records() -> None:
    from hsync_rendezvous.routing import PeerRecord

    h = make_handler()
    h.routing.upsert(
        PeerRecord(
            cid=CID,
            bucket="shared",
            group="home",
            ip="10.0.0.1",
            cert_fp=FP,
            version="1.0.0",
            endpoints=(),
            expires_at=1000.0,
        )
    )
    assert h.prune(now=1500.0) == 1
    assert h.routing.count() == 0


def test_handle_prunes_periodically() -> None:
    """handle() sweeps expired records at most once per prune_interval.

    Regression for the bug where ``handle()`` never invoked ``prune()`` — expired
    records would linger until the next real frame arrived, so a quiet bucket
    kept stale peers in memory (and the soak failed its convergence check).
    """
    from hsync_rendezvous.routing import PeerRecord

    h = make_handler()

    def add_expired(cid: str, expires_at: float, ip: str) -> None:
        h.routing.upsert(
            PeerRecord(
                cid=cid,
                bucket="shared",
                group="home",
                ip=ip,
                cert_fp=FP,
                version="1.0.0",
                endpoints=(),
                expires_at=expires_at,
            )
        )

    # An already-expired record must be swept by the FIRST handle() (the
    # last_prune is None, so the first call always sweeps).
    add_expired("expired-first", 1000.0, "10.0.0.1")
    with patch("hsync_rendezvous.handler.time.monotonic", return_value=2000.0):
        send(h, register_frame(cid=CID2), peer_ip="10.0.0.1", peer_port=1)
        assert h.routing.count() == 1  # "expired-first" swept, CID2 live
        # A second call within the same 15 s window must NOT re-sweep.
        send(h, register_frame(cid=CID), peer_ip="10.0.0.2", peer_port=1)
        assert h.routing.count() == 2

    # A record that only expires AFTER the first sweep, then advance past
    # prune_interval: the interval sweep must remove it (not the register,
    # which targets a different CID).
    add_expired("expired-between", 2010.0, "10.0.0.3")
    assert h.routing.count() == 3
    with patch("hsync_rendezvous.handler.time.monotonic", return_value=2020.0):
        send(h, register_frame(cid=CID), peer_ip="10.0.0.4", peer_port=1)
    # "expired-between" swept by the interval prune; CID2 + CID remain.
    assert h.routing.count() == 2
    assert h.routing.get("expired-between", "shared", "home") is None


def test_wire_serialization_is_compact_and_spec_ordered() -> None:
    """Pin the serialized frame: spec/fixture field order, compact, nulls kept.

    Guards that ``error``/``retry_after`` stay present (the language-neutral
    contract suite reads ``response["error"]``) and that keys use field order, not
    alphabetical. ``json.loads`` preserves document order, so the key lists below
    are the actual wire order.
    """
    # ack — must come from an OPEN bucket: on a protected bucket a tokenless
    # register is refused and yields a ``response`` frame, not an ``ack``.
    h = make_handler()
    raw = send(h, register_frame(), peer_ip="198.51.100.7", peer_port=54321)
    assert raw is not None
    ack = json.loads(raw)
    assert list(ack) == [
        "protocol_version",
        "type",
        "observed_endpoint",
        "ttl",
        "server_time",
        "retry_after",
    ]
    assert list(ack["observed_endpoint"]) == ["proto", "ip", "port"]
    assert ack["observed_endpoint"] == {"proto": "udp", "ip": "198.51.100.7", "port": 54321}
    assert ack["retry_after"] is None

    # refusal — protected bucket, no token: fully deterministic, so pin exact bytes
    hp = make_handler(protected=("shared",))
    refusal = send(hp, query_frame(token=None), peer_ip="10.0.0.2", peer_port=2)
    assert refusal == (
        b'{"protocol_version":"rdv/1","type":"response","peers":[],"count":0,'
        b'"ttl":60,"error":"token_required","retry_after":null}'
    )

    # success response with one peer — order, compactness, nulls present
    ok = send(h, query_frame(limit=1), peer_ip="10.0.0.3", peer_port=3)
    assert ok is not None
    decoded_ok = json.loads(ok)
    assert list(decoded_ok) == [
        "protocol_version",
        "type",
        "peers",
        "count",
        "ttl",
        "error",
        "retry_after",
    ]
    assert list(decoded_ok["peers"][0]) == [
        "cid",
        "endpoints",
        "cert_fp",
        "bucket",
        "group",
        "version",
        "capacity",
        "connected",
        "reachable",
        "server_ready",
        "prefer_master",
        "never_master",
        "inbound",
        "startup_time",
        "sync_direction",
    ]
    assert decoded_ok["peers"][0]["endpoints"][0]["host"] == "198.51.100.7"
    assert decoded_ok["peers"][0]["capacity"] == 20  # relayed advisory hint
    assert decoded_ok["peers"][0]["server_ready"] is False  # relayed election advert
    assert decoded_ok["peers"][0]["sync_direction"] == "bidirectional"
    assert decoded_ok["count"] == 1
    assert decoded_ok["error"] is None and decoded_ok["retry_after"] is None
    # compact separators, and valid JSON that round-trips
    assert ok == json.dumps(decoded_ok, separators=(",", ":")).encode()


def test_response_bytes_match_the_pydantic_serializer() -> None:
    """The hand-assembled response must stay byte-identical to the pydantic dump.

    ``_response`` concatenates cached peer fragments around a server-controlled
    envelope; this pins that envelope against the test-side pydantic mirror
    (``rdv_response``) so the wire format cannot drift.
    """
    from pydantic import TypeAdapter
    from rdv_response import RDV_RESPONSE_ADAPTER, RdvResponse

    from hsync_rendezvous.protocol import Endpoint, RdvPeer

    peers = [
        RdvPeer(
            cid=CID,
            endpoints=[Endpoint(proto="tcp", host="198.51.100.7", port=443)],
            cert_fp=FP,
            bucket="shared",
            group="home",
            version="1.0.0",
            capacity=20,
            connected=2,
        )
    ]
    fragments = [TypeAdapter(RdvPeer).dump_json(peer) for peer in peers]
    h = make_handler()
    expected = RDV_RESPONSE_ADAPTER.dump_json(
        RdvResponse(protocol_version="rdv/1", type="response", peers=peers, count=1, ttl=60)
    )
    assert h._response(peers=fragments, error=None, retry_after=None) == expected


def test_ack_bytes_match_the_pydantic_serializer(monkeypatch) -> None:
    """The hand-assembled ack must stay byte-identical to the pydantic dump.

    ``_ack`` concatenates server-controlled bytes around the socket-observed
    endpoint; this pins that envelope against ``RDV_ACK_ADAPTER`` so the wire
    format cannot drift.
    """
    from hsync_rendezvous.protocol import (
        PROTOCOL_VERSION_RDV,
        RDV_ACK_ADAPTER,
        ObservedEndpoint,
        RdvAck,
    )

    monkeypatch.setattr("hsync_rendezvous.handler._utc_now_z", lambda: "2026-10-09T10:00:00Z")
    h = make_handler()
    expected = RDV_ACK_ADAPTER.dump_json(
        RdvAck(
            protocol_version=PROTOCOL_VERSION_RDV,
            type="ack",
            observed_endpoint=ObservedEndpoint(proto="udp", ip="198.51.100.7", port=54321),
            ttl=int(h.ttl),
            server_time="2026-10-09T10:00:00Z",
        )
    )
    assert h._ack("198.51.100.7", 54321) == expected


def test_peer_record_keeps_endpoints_compact_and_caches_wire_bytes() -> None:
    """Records store primitive endpoints and cache the serialized wire fragment.

    Memory invariant: no pydantic ``Endpoint``/``RdvPeer`` instance is retained
    per record (they cost ~3x the tuple); ``_to_peer`` returns the cached
    ``bytes`` fragment unchanged on the second call (no per-query rebuild).
    """
    from hsync_rendezvous.handler import RendezvousHandler
    from hsync_rendezvous.protocol import RdvQuery

    h = make_handler()
    send(h, register_frame(), peer_ip="198.51.100.7", peer_port=54321)
    record = h.routing.get(CID, "shared", "home")
    assert record is not None
    assert record.endpoints == (("tcp", "198.51.100.7", 443),)

    query = RdvQuery(protocol_version="rdv/1", type="query", bucket="shared", group="home")
    first = RendezvousHandler._to_peer(record, query)
    assert isinstance(first, bytes)
    assert record.wire is first
    assert RendezvousHandler._to_peer(record, query) is first


# --- source-IP ownership (anti-hijack), per-IP isolation and bounded table ---


def test_foreign_source_cannot_hijack_a_registration() -> None:
    """A different source IP must not overwrite a live registration.

    Regression for the registration-hijack vector: an attacker who learns a
    ``(cid, bucket, group)`` (e.g. from an anonymous query) can no longer point
    the victim's rendezvous record at its own endpoints.
    """
    h = make_handler()
    ack = decoded(send(h, register_frame(host="10.0.0.1"), peer_ip="10.0.0.1", peer_port=1))
    assert ack is not None and ack["type"] == "ack"
    assert send(h, register_frame(host="203.0.113.9"), peer_ip="203.0.113.9", peer_port=2) is None
    record = h.routing.get(CID, "shared", "home")
    assert record is not None
    assert record.ip == "10.0.0.1"
    assert record.endpoints[0][1] == "10.0.0.1"
    # the victim still owns the record: its own refresh renews it and its leave
    # removes it (the attacker's writes changed nothing)
    refreshed = decoded(send(h, refresh_frame(), peer_ip="10.0.0.1", peer_port=1))
    assert refreshed is not None and refreshed["type"] == "ack"
    send(h, leave_frame(), peer_ip="10.0.0.1", peer_port=1)
    assert h.routing.get(CID, "shared", "home") is None


def test_foreign_source_cannot_renew_someone_elses_record() -> None:
    """A foreign refresh is ignored, so it cannot keep a stale record alive."""
    h = make_handler()
    send(h, register_frame(), peer_ip="10.0.0.1", peer_port=1)
    assert send(h, refresh_frame(), peer_ip="203.0.113.9", peer_port=2) is None
    record = h.routing.get(CID, "shared", "home")
    assert record is not None and record.ip == "10.0.0.1"


def test_token_authorized_source_may_replace_a_protected_record() -> None:
    """A token holder is authenticated bucket membership and may replace from any source."""
    h = make_handler(protected=("shared",))
    token = derive_bucket_token(b"kshared", "shared")
    send(h, register_frame(token=token, host="10.0.0.1"), peer_ip="10.0.0.1", peer_port=1)
    ack = decoded(
        send(
            h,
            register_frame(token=token, host="203.0.113.9"),
            peer_ip="203.0.113.9",
            peer_port=2,
        )
    )
    assert ack is not None and ack["type"] == "ack"
    record = h.routing.get(CID, "shared", "home")
    assert record is not None and record.ip == "203.0.113.9"


def test_register_limit_is_isolated_per_source_ip() -> None:
    """One source cannot exhaust the registration budget of another in the same bucket."""
    h = make_handler()
    for _ in range(10):  # burst 10 for (IP, bucket)
        ack = decoded(send(h, register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1))
        assert ack is not None and ack["type"] == "ack"
    limited = decoded(send(h, register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1))
    assert limited is not None and limited["error"] == "rate_limited"
    other = decoded(send(h, register_frame(cid="o" * 21), peer_ip="2.2.2.2", peer_port=1))
    assert other is not None and other["type"] == "ack"


def test_query_ip_cap_is_isolated_per_source() -> None:
    """The aggregate per-IP query cap throttles an enumerator, not its neighbours."""
    from hsync_rendezvous.handler import QUERY_IP_BURST

    h = make_handler()
    # Distinct buckets so the per-(IP, bucket) limiter never triggers first: the
    # aggregate per-IP cap is what stops a namespace sweep.
    for i in range(QUERY_IP_BURST):
        send(h, query_frame(bucket=f"b{i}"), peer_ip="9.9.9.9", peer_port=1)
    limited = decoded(send(h, query_frame(bucket="b-sweep"), peer_ip="9.9.9.9", peer_port=1))
    assert limited is not None and limited["error"] == "rate_limited"
    other = decoded(send(h, query_frame(), peer_ip="8.8.8.8", peer_port=1))
    assert other is not None and other["error"] is None


def test_routing_table_cap_applies_backpressure() -> None:
    """The host-derived record cap refuses new keys instead of growing RAM."""
    from hsync_rendezvous.resources import ResourceLimits

    limits = ResourceLimits(
        max_peer_records=2,
        max_limiter_keys=64,
        max_active_connections=8,
        max_active_connections_per_ip=8,
        max_records_per_group=2,
        max_records_per_bucket=10,
    )
    h = RendezvousHandler(limits=limits)
    assert decoded(send(h, register_frame(cid=CID), peer_ip="1.1.1.1", peer_port=1)) is not None
    assert decoded(send(h, register_frame(cid=CID2), peer_ip="1.1.1.1", peer_port=1)) is not None
    # a third key in the same group is refused by the per-group ceiling...
    same_group = decoded(send(h, register_frame(cid="y" * 21), peer_ip="1.1.1.1", peer_port=1))
    assert same_group is not None and same_group["error"] == "overloaded"
    # ...and a new group is refused by the global ceiling (both are backpressure)
    full = decoded(
        send(h, register_frame(cid="z" * 21, group="other"), peer_ip="1.1.1.1", peer_port=1)
    )
    assert full is not None and full["error"] == "overloaded"
    # refreshing an existing key never grows the table and stays accepted
    refreshed = decoded(send(h, refresh_frame(), peer_ip="1.1.1.1", peer_port=1))
    assert refreshed is not None and refreshed["type"] == "ack"


# --- expiry-aware ownership, layered ceilings and bounded relay ---------------


def test_an_expired_record_is_absent_from_the_table_view() -> None:
    """A record past its TTL reads as absent, not as a stale claim."""
    h = make_handler()
    with frozen_clock(1_000.0):
        send(h, register_frame(), peer_ip="10.0.0.1", peer_port=1)
    record = h.routing.get(CID, "shared", "home", now=1_000.0)
    assert record is not None
    assert record.expires_at == 1_060.0  # t + DEFAULT_TTL
    assert h.routing.get(CID, "shared", "home", now=record.expires_at + 1.0) is None


def test_a_ttl_lapse_frees_the_key_for_another_source() -> None:
    """Ownership follows liveness: an expired record blocks nobody."""
    h = make_handler()
    with frozen_clock(1_000.0):
        send(h, register_frame(host="10.0.0.1"), peer_ip="10.0.0.1", peer_port=1)
    with frozen_clock(1_070.0):
        ack = decoded(
            send(h, register_frame(host="203.0.113.9"), peer_ip="203.0.113.9", peer_port=2)
        )
    assert ack is not None and ack["type"] == "ack"
    record = h.routing.get(CID, "shared", "home", now=1_070.0)
    assert record is not None and record.ip == "203.0.113.9"


def test_refresh_never_revives_an_expired_record() -> None:
    """A refresh past the TTL is dropped: the client falls back to a register."""
    h = make_handler()
    with frozen_clock(1_000.0):
        send(h, register_frame(), peer_ip="10.0.0.1", peer_port=1)
    with frozen_clock(1_070.0):
        assert send(h, refresh_frame(), peer_ip="10.0.0.1", peer_port=1) is None


def test_the_bucket_ceiling_cannot_be_rotated_around_with_group_names() -> None:
    """``group`` is registrant-chosen, so the per-bucket ceiling is the binding one."""
    from hsync_rendezvous.resources import ResourceLimits

    limits = ResourceLimits(
        max_peer_records=10,
        max_limiter_keys=64,
        max_active_connections=8,
        max_active_connections_per_ip=8,
        max_records_per_group=10,
        max_records_per_bucket=2,
    )
    h = RendezvousHandler(limits=limits, enforce_rate_limits=False)
    replies = [
        decoded(
            send(
                h,
                register_frame(cid=f"Bkt{index:018d}", group=f"g{index}"),
                peer_ip="1.1.1.1",
                peer_port=1_000 + index,
            )
        )
        for index in range(4)
    ]
    assert [reply["type"] for reply in replies] == ["ack", "ack", "response", "response"]
    assert [reply.get("error") for reply in replies[2:]] == ["overloaded", "overloaded"]
    assert h.routing.count("shared") == 2


def test_pruning_releases_the_bucket_accounting_on_both_paths() -> None:
    """Both sweep paths (incremental and bulk rebuild) keep ``_per_bucket`` exact."""
    from hsync_rendezvous.routing import PeerRecord, RoutingTable

    def record(cid: str, expires_at: float) -> PeerRecord:
        return PeerRecord(
            cid=cid,
            bucket="shared",
            group=None,
            ip="10.0.0.1",
            cert_fp=FP,
            version="1.0.0",
            endpoints=(),
            expires_at=expires_at,
        )

    # Incremental path: one of four expires, so the ceiling must free one slot.
    table = RoutingTable(max_records=10, max_records_per_bucket=4)
    assert table.upsert(record("Inc000000000000000000", 900.0)) is True
    for index in range(1, 4):
        assert table.upsert(record(f"Inc{index:018d}", 1_000.0)) is True
    assert table.prune(now=950.0) == 1
    assert table.upsert(record("Inc900000000000000000", 1_000.0)) is True

    # Bulk path: every record expires, so the counters reset with the table.
    table = RoutingTable(max_records=10, max_records_per_bucket=2)
    assert table.upsert(record("All000000000000000000", 900.0)) is True
    assert table.upsert(record("All100000000000000000", 900.0)) is True
    assert table.prune(now=1_000.0) == 2
    assert table.upsert(record("All200000000000000000", 1_000.0)) is True


def test_relayed_peer_endpoints_are_capped() -> None:
    """A register may advertise 16 candidates; the relay carries the first four."""
    from hsync_rendezvous.protocol import MAX_RELAY_ENDPOINTS

    h = make_handler()
    endpoints = [
        {"proto": "tcp", "host": f"198.51.100.{index + 1}", "port": 4_000 + index}
        for index in range(16)
    ]
    send(h, register_frame(endpoints=endpoints), peer_ip="10.0.0.1", peer_port=1)
    reply = decoded(send(h, query_frame(), peer_ip="10.0.0.2", peer_port=2))
    assert reply is not None and reply["count"] == 1
    relayed = reply["peers"][0]["endpoints"]
    assert len(relayed) == MAX_RELAY_ENDPOINTS
    assert relayed[0]["host"] == "198.51.100.1"


def test_a_response_stays_within_the_byte_budget() -> None:
    """Endpoint-heavy registrants cannot make one query emit an unbounded reply."""
    from hsync_rendezvous.protocol import MAX_RESPONSE_BYTES

    h = make_handler()
    host = ".".join(["a" * 63] * 3)  # 191-char dialable DNS name
    endpoints = [{"proto": "tcp", "host": host, "port": 443}] * 4
    registered = 40
    for index in range(registered):
        send(
            h,
            register_frame(cid=f"Bud{index:018d}", endpoints=endpoints, version="1" * 64),
            peer_ip=f"10.1.{index // 256}.{index % 256}",
            peer_port=1_000 + index,
        )
    reply = send(h, query_frame(limit=50), peer_ip="9.9.9.9", peer_port=4444)
    assert reply is not None
    assert len(reply) <= MAX_RESPONSE_BYTES
    relayed = decoded(reply)["count"]
    assert 1 <= relayed < registered
