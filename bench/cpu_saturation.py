"""L5 — CPU-saturation sweep (language-neutral driver; Linux /proc sampling).

Answers "at what load does one core saturate?". The rendezvous is a single-process
asyncio loop, so its CPU is measured as a fraction of ONE core (from
``/proc/<pid>/stat`` utime+stime). This script spawns the binary and drives it
with a rising number of concurrent query connections; at each level it reports
the node CPU% next to the client-observed throughput and latency. The knee where
CPU approaches ~100% while ops/s stops scaling is the vertical limit of the
single process — the data that decides whether parallelism / a C port is
actually needed.

Loopback caveat: the client runs on the same host, so at high concurrency it
competes for CPU. The *node* CPU is isolated via ``/proc``, but the latency
figures are end-to-end through the client.

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/cpu_saturation.py \\
        [--peers 200] [--levels 1,2,4,8,16,32] [--step-seconds 3] [--json-out FILE]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from common import (  # noqa: E402
    add_json_out,
    cpu_percent,
    format_cpu,
    make_cids,
    maybe_write_json,
    percentile,
    proc_cpu_seconds,
    timed_query,
)
from harness import (  # noqa: E402
    RdvClient,
    query_frame,
    register_frame,
    start_rendezvous,
    terminate,
)

_BUCKET = "shared"


@dataclass
class LevelResult:
    """One sweep level: load, node CPU% (one core), throughput and latency."""

    concurrency: int
    cpu_pct: float | None
    ops_per_s: float
    p50_ms: float
    p99_ms: float
    queries: int

    def as_dict(self) -> dict:
        return {
            "concurrency": self.concurrency,
            "node_cpu_pct_one_core": None if self.cpu_pct is None else round(self.cpu_pct, 1),
            "ops_per_s": round(self.ops_per_s, 1),
            "p50_ms": round(self.p50_ms, 4),
            "p99_ms": round(self.p99_ms, 4),
            "queries": self.queries,
        }


async def _prime(port: int, peers: int) -> None:
    """Register ``peers`` peers into the shared bucket (the load's table)."""
    async with RdvClient(port) as client:
        for cid in make_cids(peers, start=7_000_000):
            await client.exchange(register_frame(cid, _BUCKET), timeout=5.0)


async def _level(port: int, node_pid: int, concurrency: int, seconds: float) -> LevelResult:
    """Drive ``concurrency`` query connections for ``seconds``; sample node CPU."""
    query = query_frame(_BUCKET, limit=20)
    deadline = time.monotonic() + seconds  # shared wall-clock budget for every worker
    latencies: list[float] = []

    async def worker() -> None:
        async with RdvClient(port) as client:
            while time.monotonic() < deadline:
                latencies.append(await timed_query(client, query, require_no_error=False))

    cpu_before = proc_cpu_seconds(node_pid)
    started = time.perf_counter()
    await asyncio.gather(*[worker() for _ in range(concurrency)])
    wall = time.perf_counter() - started
    cpu_after = proc_cpu_seconds(node_pid)

    lat_ms = [s * 1000.0 for s in latencies]
    return LevelResult(
        concurrency=concurrency,
        cpu_pct=cpu_percent(cpu_before, cpu_after, wall),
        ops_per_s=len(latencies) / wall if wall > 0 else 0.0,
        p50_ms=percentile(lat_ms, 50.0),
        p99_ms=percentile(lat_ms, 99.0),
        queries=len(latencies),
    )


def _print_table(levels: list[LevelResult]) -> None:
    header = (
        f"{'load(conns)':>12}{'node CPU%':>12}{'ops/s':>12}"
        f"{'p50_ms':>10}{'p99_ms':>10}{'queries':>10}"
    )
    print(header)
    print("-" * len(header))
    for level in levels:
        print(
            f"{level.concurrency:>12}{format_cpu(level.cpu_pct):>12}"
            f"{level.ops_per_s:>12.1f}{level.p50_ms:>10.3f}"
            f"{level.p99_ms:>10.3f}{level.queries:>10}"
        )


def _verdict(levels: list[LevelResult]) -> None:
    print("\nnode CPU is % of ONE core (the node is a single-process asyncio loop)")
    if not levels:
        return
    if all(level.cpu_pct is None for level in levels):
        print("CPU sampling unavailable (needs Linux /proc/<pid>/stat)")
        return
    saturated = next((lv for lv in levels if lv.cpu_pct is not None and lv.cpu_pct >= 90.0), None)
    if saturated is not None:
        print(
            f"one core saturates at ~{saturated.concurrency} concurrent connections "
            f"(node CPU {format_cpu(saturated.cpu_pct)})"
        )
    else:
        top = levels[-1]
        print(
            f"core NOT saturated up to {top.concurrency} concurrent connections "
            f"({format_cpu(top.cpu_pct)}, max tested level)"
        )


async def _amain(
    port: int, node_pid: int, levels: list[int], step_seconds: float
) -> list[LevelResult]:
    return [await _level(port, node_pid, n, step_seconds) for n in levels]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peers", type=int, default=200, help="Peers primed in the bucket.")
    parser.add_argument(
        "--levels",
        default="1,2,4,8,16,32",
        help="Concurrency levels to sweep (comma-separated).",
    )
    parser.add_argument(
        "--step-seconds", type=float, default=3.0, help="Measurement window per level."
    )
    add_json_out(parser)
    args = parser.parse_args()

    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    with tempfile.TemporaryDirectory(prefix="rendezvous-cpu-") as tmp:
        handle = start_rendezvous(Path(tmp), no_rate_limit=True)
        node_pid = handle.node_pid
        if node_pid is None:  # pragma: no cover - start_rendezvous always awaits readiness
            raise RuntimeError("rendezvous readiness PID was not reported")
        try:
            asyncio.run(_prime(handle.port, args.peers))
            results = asyncio.run(_amain(handle.port, node_pid, levels, args.step_seconds))
            print("CPU-saturation sweep (loopback; node CPU from /proc/<pid>/stat)")
            _print_table(results)
            _verdict(results)
            maybe_write_json(args.json_out, results)
        finally:
            terminate(handle)


if __name__ == "__main__":
    main()
