"""Rdv/1 protocol model + routing + token tests."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError
from rdv_response import RdvResponse

from hsync_rendezvous.protocol import (
    CAPACITY_MAX,
    CID_PATTERN,
    STARTUP_TIME_MAX,
    RdvAck,
    RdvPeer,
    RdvQuery,
    RdvRegister,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

# A canonical SHA-256 certificate fingerprint (the value a pin compares).
FP = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fixtures_match_boot1_models() -> None:
    """The shared SSOT fixtures must validate against the rdv/1 models."""
    assert RdvRegister.model_validate(_load_fixture("rendezvous-register.json"))
    assert RdvQuery.model_validate(_load_fixture("rendezvous-query.json"))
    assert RdvAck.model_validate(_load_fixture("rendezvous-ack.json"))
    assert RdvResponse.model_validate(_load_fixture("rendezvous-response.json"))


from hsync_rendezvous.ratelimit import TokenBucketLimiter
from hsync_rendezvous.routing import PeerRecord, RoutingTable
from hsync_rendezvous.tokens import derive_bucket_token, verify_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"


def test_cid_pattern_matches_boot1_spec() -> None:
    """CID shape is the hsync-common SSOT, pinned to the documented rdv/1 value.

    ``CID_PATTERN`` is imported from ``hsync_common.models.event`` : this
    test fails if an upstream change silently alters the documented wire shape.
    """
    assert CID_PATTERN == r"^[A-Za-z0-9]{21}$"
    assert re.fullmatch(CID_PATTERN, CID)
    assert re.fullmatch(CID_PATTERN, "A" * 20) is None
    assert re.fullmatch(CID_PATTERN, "A" * 22) is None


def test_bucket_uses_canonical_hsync_name_rule() -> None:
    """``bucket`` accepts the canonical HSYNC name and rejects everything else."""
    register = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "cert_fp": FP,
        "version": "1.0.0",
    }
    for good in ("shared", "a", "my-bucket_1", "b" * 63):
        assert RdvRegister(**register, bucket=good).bucket == good
    for bad in ("", "-lead", "trail-", "has space", "dot.name", "a" * 64):
        with pytest.raises(ValueError):
            RdvRegister(**register, bucket=bad)

    # query carries the same domain (no cid / cert_fp)
    assert RdvQuery(protocol_version="rdv/1", type="query", bucket="shared").bucket == "shared"
    with pytest.raises(ValueError):
        RdvQuery(protocol_version="rdv/1", type="query", bucket="has space")

    # RdvPeer is validated on the same rule
    with pytest.raises(ValueError):
        RdvPeer(
            cid=CID,
            endpoints=[{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
            cert_fp=FP,
            bucket="has space",
            version="1.0.0",
        )


def test_register_accepts_valid_and_rejects_unknown_fields() -> None:
    ok = RdvRegister(
        protocol_version="rdv/1",
        type="register",
        cid=CID,
        bucket="shared",
        group="home",
        cert_fp=FP,
        version="1.0.0",
        endpoints=[{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
    )
    assert ok.cid == CID
    assert ok.type == "register"

    # The schema must reject any targeted/unknown field (agnostic).
    try:
        RdvRegister(
            protocol_version="rdv/1",
            type="register",
            cid=CID,
            bucket="shared",
            cert_fp=FP,
            version="1.0.0",
            file_search="photo.jpg",  # type: ignore[call-arg]
        )
    except ValueError:
        pass
    else:  # pragma: no cover - expected to raise
        raise AssertionError("unknown field must be rejected")


def test_capacity_hint_domain_bounds() -> None:
    """The advisory capacity hint is 0..32 (0 = not a seeder); 33 is rejected."""
    register = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "cert_fp": FP,
        "version": "1.0.0",
    }
    assert RdvRegister(**register).capacity == 0  # absent → 0
    assert RdvRegister(**register, capacity=CAPACITY_MAX).capacity == CAPACITY_MAX
    with pytest.raises(ValueError):
        RdvRegister(**register, capacity=CAPACITY_MAX + 1)

    peer = {
        "cid": CID,
        "endpoints": [{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
        "cert_fp": FP,
        "bucket": "shared",
        "version": "1.0.0",
    }
    assert RdvPeer(**peer).capacity == 0  # absent → 0
    assert RdvPeer(**peer, capacity=CAPACITY_MAX).capacity == CAPACITY_MAX
    with pytest.raises(ValueError):
        RdvPeer(**peer, capacity=CAPACITY_MAX + 1)


def test_election_advertisement_domain_bounds() -> None:
    """The advertised election values are validated, never silently coerced.

    Defaults (absent keys): not serving, no pin, unknown startup and
    bidirectional. ``startup_time`` must be a finite non-negative JSON number
    inside the exact-integer range; ``sync_direction`` must be one of the three
    canonical tokens the client uses.
    """
    register = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "cert_fp": FP,
        "version": "1.0.0",
    }
    default = RdvRegister(**register)
    assert default.server_ready is False
    assert default.prefer_master is False
    assert default.never_master is False
    assert default.startup_time == 0.0
    assert default.sync_direction == "bidirectional"

    advertised = RdvRegister(
        **register,
        server_ready=True,
        prefer_master=True,
        startup_time=1760000000.5,
        sync_direction="upload-only",
    )
    assert advertised.server_ready is True
    assert advertised.prefer_master is True
    assert advertised.startup_time == 1760000000.5
    assert advertised.sync_direction == "upload-only"

    # pydantic's lax mode coerces 1/0 to bool and numeric strings to float; the
    # client mirror is the strict side of the contract (it rejects both before
    # sending), so a value that reaches the node is either valid or rejected.
    assert RdvRegister(**register, server_ready=1).server_ready is True
    assert RdvRegister(**register, startup_time="1760000000").startup_time == 1760000000.0

    for bad in (
        {"server_ready": None},
        {"startup_time": -1},
        {"startup_time": STARTUP_TIME_MAX * 2},
        {"sync_direction": "sideways"},
    ):
        with pytest.raises(ValueError):
            RdvRegister(**register, **bad)

    peer = {
        "cid": CID,
        "endpoints": [{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
        "cert_fp": FP,
        "bucket": "shared",
        "version": "1.0.0",
    }
    assert RdvPeer(**peer).never_master is False
    assert RdvPeer(**peer, never_master=True).never_master is True
    with pytest.raises(ValueError):
        RdvPeer(**peer, sync_direction="sideways")
    with pytest.raises(ValueError):
        RdvPeer(**peer, startup_time=-1)


def test_bucket_token_derivation_and_verify() -> None:
    key = b"supersecret"
    token = derive_bucket_token(key, "shared")
    assert len(token) == 64
    assert token == derive_bucket_token(key, "shared")  # deterministic
    assert token != derive_bucket_token(key, "other")  # bucket-scoped
    assert verify_bucket_token(token, token) is True
    assert verify_bucket_token(token, None) is False
    assert verify_bucket_token(token, "0" * 64) is False
    assert verify_bucket_token(token, "short") is False


def test_bucket_token_wire_grammar_is_64_lowercase_hex() -> None:
    """The token domain is fixed by the key-derivation contract, so the wire
    models reject anything else as an invalid frame (the failure mode of a
    non-derivable token is "malformed", never a per-IP failed-token attempt).
    """
    register = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "cert_fp": FP,
        "version": "1.0.0",
    }
    good = "0123456789abcdef" * 4
    assert RdvRegister(**register, bucket_token=good).bucket_token == good
    assert (
        RdvQuery(
            protocol_version="rdv/1", type="query", bucket="shared", bucket_token=good
        ).bucket_token
        == good
    )
    for bad in ("", "z" * 64, "A" * 64, "a" * 63, "a" * 65, "a" * 31 + "\n"):
        with pytest.raises(ValueError):
            RdvRegister(**register, bucket_token=bad)
        with pytest.raises(ValueError):
            RdvQuery(protocol_version="rdv/1", type="query", bucket="shared", bucket_token=bad)


def test_connected_advisory_bound_is_bounded() -> None:
    """The advisory connected count is a small non-negative JSON integer."""
    register = {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "cert_fp": FP,
        "version": "1.0.0",
    }
    assert RdvRegister(**register).connected is None
    assert RdvRegister(**register, connected=7).connected == 7
    assert RdvRegister(**register, connected=2**53).connected == 2**53
    for bad in (-1, 2**53 + 1):
        with pytest.raises(ValueError):
            RdvRegister(**register, connected=bad)


def test_routing_table_upsert_prune_sample() -> None:
    table = RoutingTable()
    # deterministic: record A expires at 2000, record B at 3000
    table.upsert(
        PeerRecord(
            cid=CID,
            bucket="shared",
            group=None,
            ip="198.51.100.7",
            cert_fp=FP,
            version="1.0.0",
            endpoints=(),
            expires_at=2000.0,
        )
    )
    table.upsert(
        PeerRecord(
            cid="Zz9y8Xx7Ww6Vv5Uu4Tt3Ss2R",
            bucket="shared",
            group=None,
            ip="198.51.100.8",
            cert_fp=FP,
            version="1.0.0",
            endpoints=(),
            expires_at=3000.0,
        )
    )
    assert len(table.sample("shared", limit=10, now=1000.0)) == 2
    assert table.count("shared") == 2
    assert table.prune(now=2500.0) == 1  # only A expired
    assert table.count("shared") == 1
    assert table.prune(now=3500.0) == 1  # B expired too
    assert table.count("shared") == 0


def test_token_bucket_burst_then_sustained() -> None:
    lim = TokenBucketLimiter(capacity=10, refill=5, window=60.0)
    now = 1000.0
    # burst: the full capacity is consumable at once
    assert all(lim.allow("a", now + i) for i in range(10))
    assert lim.allow("a", now + 10) is False  # exhausted
    # sustained: exactly 5 tokens have refilled after one window
    assert lim.allow("a", now + 60) is True
    assert lim.retry_after("a") >= 1


@pytest.mark.parametrize("host", ["198.51.100.7", "peer.example", "2001:db8::1", "[2001:db8::1]"])
def test_register_accepts_dialable_endpoint_hosts(host: str) -> None:
    frame = _load_fixture("rendezvous-register.json")
    frame["endpoints"] = [{"proto": "tcp", "host": host, "port": 443}]
    assert RdvRegister.model_validate(frame).endpoints[0].host == host


@pytest.mark.parametrize(
    "host", ["", "..\\..", "../elsewhere", "a b", "a\x00b", "999.1.1.1", "a..b", "x" * 64]
)
def test_register_rejects_non_dialable_endpoint_hosts(host: str) -> None:
    frame = _load_fixture("rendezvous-register.json")
    frame["endpoints"] = [{"proto": "tcp", "host": host, "port": 443}]
    with pytest.raises(ValidationError):
        RdvRegister.model_validate(frame)


@pytest.mark.parametrize("cert_fp", ["", "f", "AA:BB", "not-a-fingerprint", "sha256:zz"])
def test_register_rejects_a_malformed_certificate_fingerprint(cert_fp: str) -> None:
    frame = _load_fixture("rendezvous-register.json")
    frame["cert_fp"] = cert_fp
    with pytest.raises(ValidationError):
        RdvRegister.model_validate(frame)


def test_peer_certificate_fingerprint_uses_the_same_grammar() -> None:
    peer = _load_fixture("rendezvous-response.json")["peers"][0]
    peer["cert_fp"] = "sha256:" + FP.replace(":", "").lower()
    assert RdvPeer.model_validate(peer)
    peer["cert_fp"] = "AA:BB"
    with pytest.raises(ValidationError):
        RdvPeer.model_validate(peer)
