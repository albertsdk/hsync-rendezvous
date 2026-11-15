# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""L6 — RAM-footprint benchmark (Python-internal for A, language-neutral for B).

Two sections:

* **A — per-item footprint (in-process, deterministic)**: builds a
  ``RoutingTable`` (with the ``wire`` fragment cache populated, i.e. steady
  state) at several table sizes / advertised-endpoint counts, and a
  ``TokenBucketLimiter`` at several key counts. Every measured object is kept
  alive across the ``tracemalloc`` snapshot, so the reported number is the
  *retained* bytes per item — the low-variance, allocator-independent figure for
  the data structures themselves.
* **B — node RSS (opt-in)**: spawns the rendezvous binary
  (``HSYNC_RENDEZVOUS_BIN``, default the Python build), pipeline-registers
  ``--peers`` peers with ``--endpoints`` endpoints each, and reports the process
  RSS delta per record read from ``/proc/<pid>/status``. It measures the whole
  process (interpreter, allocator, per-record overhead), so it is the
  end-to-end counterpart of A and the metric an operator cares about.

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/memory.py \
        [--records 20000] [--limiter-keys 100000] \
        [--node --peers 20000 --endpoints 3] [--json-out FILE]
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import json
import sys
import tempfile
import tracemalloc
from collections.abc import Callable
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "python" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "tests"))

from common import add_json_out, make_cid, make_cids, proc_rss_mb  # noqa: E402
from harness import (  # noqa: E402
    RdvClient,
    register_frame,
    start_rendezvous,
    terminate,
)
from hsync_common.ratelimit import TokenBucketLimiter  # noqa: E402
from hsync_rendezvous.handler import RendezvousHandler  # noqa: E402
from hsync_rendezvous.routing import PeerRecord, RoutingTable  # noqa: E402


def _retained(build: Callable[[], object]) -> tuple[int, object]:
    """Bytes allocated by ``build()`` that are still live at the snapshot.

    ``build()`` must return the root it allocated; the caller keeps that
    reference alive (the snapshot is taken here, before returning).
    """
    gc.collect()
    tracemalloc.start()
    baseline = tracemalloc.take_snapshot()
    obj = build()
    snapshot = tracemalloc.take_snapshot()
    total = sum(stat.size_diff for stat in snapshot.compare_to(baseline, "filename"))
    tracemalloc.stop()
    return total, obj


def _make_record(index: int, bucket: str, endpoints: int) -> PeerRecord:
    """A record built directly from primitives (no pydantic setup noise)."""
    host = f"10.0.{index % 255}.{(index % 254) + 1}"
    return PeerRecord(
        cid=make_cid(index),
        bucket=bucket,
        group="g",
        ip="10.0.0.1",
        cert_fp="sha256:" + "ab" * 32,
        version="1.0.0",
        endpoints=tuple(("udp", host, 40000 + j) for j in range(endpoints)),
    )


def _measure_records(records: int, endpoints: int, *, wire: bool) -> float:
    """Retained bytes per live routing-table record (indexes + optional cache)."""

    def build() -> RoutingTable:
        table = RoutingTable()
        for index in range(records):
            record = _make_record(index, "shared", endpoints)
            table.upsert(record)
            if wire:
                # Steady state: every record has served a query at least once,
                # so its pre-serialized fragment is cached on the record.
                RendezvousHandler._to_peer(record)
        return table

    total, table = _retained(build)
    assert table.count(bucket="shared") == records
    return total / records


def _measure_limiter(keys: int) -> float:
    """Retained bytes per tracked rate-limiter key."""

    def build() -> TokenBucketLimiter:
        limiter = TokenBucketLimiter(capacity=50, refill=10.0, window=60.0, max_keys=keys + 1)
        for index in range(keys):
            limiter.allow(f"ip-{index // 256}.{index % 256}")
        return limiter

    total, limiter = _retained(build)
    assert len(limiter._buckets) == keys
    return total / keys


async def _measure_node_rss(peers: int, endpoints: int, batch: int, group_size: int) -> dict:
    """Register ``peers`` peers over the wire and report the node RSS delta.

    Peers are spread over ``group_size``-sized groups: the node's per-group record
    ceiling (``ResourceLimits.max_records_per_group``, a fraction of the global
    ceiling) would otherwise answer ``overloaded`` and under-count the store. Only
    acked records are counted, and the per-record figure divides by that count.
    """
    cids = make_cids(peers, start=5_000_000)
    with tempfile.TemporaryDirectory(prefix="rendezvous-memory-") as tmp:
        handle = start_rendezvous(Path(tmp), ttl=3600, no_rate_limit=True)
        try:
            if handle.node_pid is None:  # pragma: no cover - start awaits readiness
                raise RuntimeError("rendezvous readiness PID was not reported")
            rss_base = proc_rss_mb(handle.node_pid)
            acked = 0
            refused = 0
            async with RdvClient(handle.port) as client:
                for start in range(0, peers, batch):
                    frames = [
                        register_frame(
                            cid,
                            "shared",
                            group=f"g{index // group_size}",
                            endpoints=[
                                {"proto": "udp", "host": "10.1.0.1", "port": 40000 + j}
                                for j in range(endpoints)
                            ],
                        )
                        for index, cid in enumerate(cids[start : start + batch], start=start)
                    ]
                    for reply in await client.pipeline(frames, timeout=30.0):
                        if reply.get("type") == "ack":
                            acked += 1
                        else:
                            refused += 1
            rss_after = proc_rss_mb(handle.node_pid)
        finally:
            terminate(handle)
    return {
        "peers": peers,
        "endpoints": endpoints,
        "acked": acked,
        "refused": refused,
        "rss_base_mb": round(rss_base, 1),
        "rss_after_mb": round(rss_after, 1),
        "rss_delta_mb": round(rss_after - rss_base, 1),
        "bytes_per_record": round((rss_after - rss_base) * 1024 * 1024 / max(1, acked), 1),
    }


def _print_section_a(rows: list[tuple[str, float, int]]) -> None:
    header = f"{'metric':<44}{'bytes/item':>12}{'items':>10}"
    print(header)
    print("-" * len(header))
    for name, per_item, count in rows:
        print(f"{name:<44}{per_item:>12.1f}{count:>10}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=20_000)
    parser.add_argument("--limiter-keys", type=int, default=100_000)
    parser.add_argument("--node", action="store_true", help="Also measure node process RSS.")
    parser.add_argument("--peers", type=int, default=20_000)
    parser.add_argument("--endpoints", type=int, default=3)
    parser.add_argument("--batch", type=int, default=500, help="Frames per pipeline batch.")
    parser.add_argument(
        "--group-size",
        type=int,
        default=1000,
        help="Records per group, kept under the node's per-group ceiling.",
    )
    add_json_out(parser)
    args = parser.parse_args()

    rows: list[tuple[str, float, int]] = []
    results: dict = {"section_a": [], "section_b": None}

    print("L6 memory — section A: retained bytes per item (tracemalloc, steady state)")
    for endpoints in (1, 3, 16):
        per_item = _measure_records(args.records, endpoints, wire=True)
        name = f"routing record (wire cache, endpoints={endpoints})"
        rows.append((name, per_item, args.records))
        results["section_a"].append(
            {"name": name, "bytes_per_item": round(per_item, 1), "items": args.records}
        )
    per_item = _measure_records(args.records, 3, wire=False)
    rows.append(("routing record (no wire cache, endpoints=3)", per_item, args.records))
    results["section_a"].append(
        {
            "name": "routing record (no wire cache, endpoints=3)",
            "bytes_per_item": round(per_item, 1),
            "items": args.records,
        }
    )
    per_key = _measure_limiter(args.limiter_keys)
    rows.append(("rate-limiter key", per_key, args.limiter_keys))
    results["section_a"].append(
        {
            "name": "rate-limiter key",
            "bytes_per_item": round(per_key, 1),
            "items": args.limiter_keys,
        }
    )
    _print_section_a(rows)

    if args.node:
        print("\nL6 memory — section B: node process RSS (end-to-end, wire-only)")
        node = asyncio.run(
            _measure_node_rss(args.peers, args.endpoints, args.batch, args.group_size)
        )
        results["section_b"] = node
        print(
            f"peers={node['peers']} acked={node['acked']} refused={node['refused']} "
            f"endpoints={node['endpoints']} rss={node['rss_base_mb']}->{node['rss_after_mb']}MB "
            f"delta={node['rss_delta_mb']}MB ({node['bytes_per_record']} B/record)"
        )

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2)
            handle.write("\n")
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
