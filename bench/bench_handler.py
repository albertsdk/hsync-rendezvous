"""L1 — pure-handler micro-benchmark (no sockets, deterministic, Python-only).

This is the ONLY benchmark that is implementation-specific: it measures
``RendezvousHandler.handle`` throughput/latency directly (validation, routing
sample/scan, serialization) with the routing table pre-populated at several
sizes. The transport cost is isolated in ``bench_quic.py`` (language-neutral).

Methodology (corrected):

* One ``RendezvousHandler(enforce_rate_limits=False)`` per scenario, so every measured
  operation runs the named branch (an ``ack``/``response``/silent ``leave``),
  never a ``rate_limited`` refusal. Each measured reply is asserted to be on the
  intended branch, so a silent drop or refusal can never masquerade as success.
* One untimed ``prune()`` before warmup, so the periodic O(n) TTL sweep never
  leaks into a measured sample (production prunes every 15 s, not per request).
* Input frames are pre-encoded ``bytes`` (the production transport passes
  ``bytes``), prebuilt outside the timed region.
* Each record's wire projection is materialized when ``register`` creates it, so
  a ``query`` sample measures the steady state rather than a first-touch rebuild
  (the same reason a large table no longer looks O(n)).

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/bench_handler.py \
        [--count N] [--json-out FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "python" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "tests"))

from common import (  # noqa: E402
    BenchResult,
    add_json_out,
    make_cids,
    maybe_write_json,
    measure,
    print_table,
)
from harness import (  # noqa: E402
    leave_frame,
    query_frame,
    refresh_frame,
    register_frame,
)
from hsync_rendezvous.handler import RendezvousHandler  # noqa: E402

_PEER_IP = "198.51.100.7"
_PEER_PORT = 54321
_WARMUP = 200
_ACK_PREFIX = b'{"protocol_version":"rdv/1","type":"ack"'


def _populate(
    handler: RendezvousHandler, bucket: str, count: int, start: int = 0
) -> list[tuple[str, str]]:
    """Register ``count`` peers into ONE bucket and move the records into ``handler``.

    Setup only, never measured: a single no-rate-limit pool handler registers
    every CID directly (the register burst would otherwise cap at 10/bucket).
    Returns the ``(cid, observed source IP)`` of each peer, so a scenario that
    needs to act *as* a peer (``leave``) can use the same source the record was
    registered from — the node only honours a departure from that source.
    """
    cids = make_cids(count, start=start)
    peers: list[tuple[str, str]] = []
    pool = RendezvousHandler(enforce_rate_limits=False)
    for index, cid in enumerate(cids):
        octet = index % 250 + 1
        source_ip = f"10.9.{(index // 250) % 250}.{octet}"
        response = pool.handle(
            json.dumps(
                register_frame(
                    cid,
                    bucket=bucket,
                    host=f"10.1.{(index // 250) % 250}.{octet}",
                )
            ).encode(),
            peer_ip=source_ip,
            peer_port=_PEER_PORT,
        )
        assert response is not None and json.loads(response)["type"] == "ack", response
        peers.append((cid, source_ip))
    for record in pool.routing._records.values():
        handler.routing.upsert(record)
    assert handler.routing.count(bucket=bucket) == count
    return peers


def _bench_register(count: int) -> BenchResult:
    # One handler, no rate limits: every measured op is a real register/ack.
    handler = RendezvousHandler(enforce_rate_limits=False)
    cids = make_cids(count + _WARMUP, start=1_000_000)
    raws = [json.dumps(register_frame(cid, "shared")).encode() for cid in cids]
    state = {"i": 0}

    def op() -> None:
        i = state["i"]
        state["i"] += 1
        reply = handler.handle(raws[i], peer_ip=_PEER_IP, peer_port=_PEER_PORT)
        assert reply is not None and reply.startswith(_ACK_PREFIX), reply

    result = measure("register", op, count=count, warmup=_WARMUP)
    assert handler.routing.count(bucket="shared") == count + _WARMUP
    return result


def _bench_query(table_size: int, limit: int, count: int) -> BenchResult:
    # One handler, no rate limits; one untimed prune so the first measured query
    # never pays an O(n) sweep. Every record's wire projection is materialized at
    # register, so these are steady-state numbers (no first-touch rebuild).
    handler = RendezvousHandler(enforce_rate_limits=False)
    _populate(handler, "shared", table_size)
    handler.prune()
    query = json.dumps(query_frame("shared", limit=limit)).encode()

    def op() -> None:
        reply = handler.handle(query, peer_ip="10.0.0.9", peer_port=1111)
        assert reply is not None and b'"error":null' in reply, reply

    return measure(f"query(table={table_size},limit={limit})", op, count=count)


def _bench_refresh(table_size: int, count: int) -> BenchResult:
    # One handler, no rate limits; refresh always targets the first populated CID.
    # The refresh must come from the record's own registered source: the handler
    # only honours a renewal from the source the peer registered from.
    handler = RendezvousHandler(enforce_rate_limits=False)
    peers = _populate(handler, "shared", table_size)
    handler.prune()
    cid, source = peers[0]
    refresh_raw = json.dumps(refresh_frame(cid, "shared")).encode()

    def op() -> None:
        reply = handler.handle(refresh_raw, peer_ip=source, peer_port=_PEER_PORT)
        assert reply is not None and reply.startswith(_ACK_PREFIX), reply

    return measure(f"refresh(table={table_size})", op, count=count)


def _bench_leave(count: int) -> BenchResult:
    # One handler, no rate limits; each op removes one record (leave returns no
    # frame). No warmup: a warmup would drain the table before measurement.
    # The leave carries each peer's own observed source IP: the node honours a
    # departure only from the source the record was registered from.
    handler = RendezvousHandler(enforce_rate_limits=False)
    peers = _populate(handler, "shared", count, start=2_000_000)
    leave_raws = [
        (json.dumps(leave_frame(cid, "shared")).encode(), source) for cid, source in peers
    ]
    state = {"i": 0}

    def op() -> None:
        i = state["i"]
        state["i"] += 1
        raw, source = leave_raws[i]
        reply = handler.handle(raw, peer_ip=source, peer_port=1)
        assert reply is None, reply

    result = measure("leave", op, count=count, warmup=0)
    assert handler.routing.count() == 0
    return result


def _bench_prune(table_size: int) -> BenchResult:
    # prune cost: expire the whole table once per timing sample; 20 samples.
    samples: list[float] = []
    for _ in range(20):
        handler = RendezvousHandler(enforce_rate_limits=False)
        _populate(handler, "shared", table_size)
        # force expiry without sleeping: backdate every record.
        now_backdated = time.monotonic() - 61.0
        for record in handler.routing._records.values():
            record.expires_at = now_backdated
        start = time.perf_counter()
        removed = handler.prune()
        samples.append(time.perf_counter() - start)
        assert removed == table_size
    return BenchResult(f"prune(expired={table_size})", samples, 20)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=2000)
    add_json_out(parser)
    args = parser.parse_args()

    count = args.count
    results = [
        _bench_register(count),
        _bench_query(100, 20, count),
        _bench_query(1_000, 20, count),
        _bench_query(10_000, 20, min(count, 500)),
        _bench_refresh(1_000, count),
        _bench_leave(min(count, 500)),
        _bench_prune(1_000),
    ]
    print(f"handler micro-benchmark (ops={count}, no rate limits, steady state)")
    print_table(results)
    maybe_write_json(args.json_out, results)


if __name__ == "__main__":
    main()
