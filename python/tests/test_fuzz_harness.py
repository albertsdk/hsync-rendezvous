"""Bounded deterministic fuzz burst: the standalone harness targets at CI scale.

The long exploratory runs live in ``fuzz/fuzz_boot.py`` (stdlib-only,
seedable) and the coverage-guided driver in ``fuzz/fuzz_guided.py``; this
module runs the SAME targets and invariants for a small, fixed budget so the
whole pytest suite exercises the decoder/SSDP/token invariants too. A fuzz
finding fails the test with the reproducing input, never an uncaught trace.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

FUZZ_DIR = Path(__file__).resolve().parents[1] / "fuzz"
sys.path.insert(0, str(FUZZ_DIR))

import fuzz_boot


def test_fuzz_burst_decoder_ssdp_token() -> None:
    counts = fuzz_boot.run_fuzz(
        iterations_per_target=500,
        seed=20261005,
        targets=("handle", "ssdp", "token"),
    )
    assert counts == {"handle": 500, "ssdp": 500, "token": 500}


def test_fuzz_handle_invariants_are_exercised_by_a_happy_path() -> None:
    """The reply/leak assertions run on real accepted frames, not only on
    garbage: a happy-path register must reply ``ack``, be attributed to the
    leak set, and a following query must relay exactly that peer through the
    invariant-checked response — so a model bug that relays unregistered or
    foreign-bucket peers would fire here."""
    fuzz_boot.reset_leak_trackers()
    handler = fuzz_boot.fresh_handler()
    register_raw = (
        json.dumps(
            {
                "protocol_version": "rdv/1",
                "type": "register",
                "cid": fuzz_boot.PROBE_CID,
                "bucket": "shared",
                "group": "home",
                "cert_fp": fuzz_boot.PROBE_FP,
                "version": "1.0.0",
                "endpoints": [{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
                "bucket_token": fuzz_boot.token_for(b"kshared", "shared"),
            }
        ).encode("utf-8")
        + b"\n"
    )
    out = handler.handle(register_raw, peer_ip=fuzz_boot.PEER_IP, peer_port=fuzz_boot.PEER_PORT)
    assert out is not None, "happy-path register must be acknowledged"
    fuzz_boot.track_accepts(register_raw, out)
    assert fuzz_boot.seen_cids == {fuzz_boot.PROBE_CID}
    assert fuzz_boot.seen_buckets == {"shared"}

    query_raw = (
        json.dumps(
            {
                "protocol_version": "rdv/1",
                "type": "query",
                "bucket": "shared",
                "group": "home",
                "limit": 20,
                "bucket_token": fuzz_boot.token_for(b"kshared", "shared"),
            }
        ).encode("utf-8")
        + b"\n"
    )
    reply = handler.handle(query_raw, peer_ip=fuzz_boot.PEER_IP, peer_port=fuzz_boot.PEER_PORT)
    assert reply is not None, "the happy-path query must be answered"
    fuzz_boot.assert_reply(query_raw, reply)
    frame = json.loads(reply)
    assert frame["type"] == "response"
    assert frame["count"] == 1
    assert [p["cid"] for p in frame["peers"]] == [fuzz_boot.PROBE_CID]


def test_guided_burst_discovers_arcs() -> None:
    """The coverage-guided driver runs its CI burst cleanly and finds arcs.

    A finding fails here with the reproducing seed; longer sessions run via
    ``.venv/bin/python fuzz/fuzz_guided.py --seconds N`` (see fuzz/fuzz_boot.py
    for the shared invariants).
    """
    pytest.importorskip("coverage")
    import fuzz_guided

    report = fuzz_guided.run_guided(iterations=200, seed=20261005, seconds=0.0)
    assert report["iterations"] == 200
    assert report["arcs"] >= 1  # the arc feedback loop actually measured something
    assert report["findings"] == 0
