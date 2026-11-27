"""Shared benchmark helpers (L1/L2/L3): deterministic CIDs + measurement.

Stdlib only. Deterministic counter-based CIDs keep every benchmark run
reproducible without ``random`` seed juggling. Frame builders live in
``tests/harness.py`` (single source, language-neutral) and are imported by the
benchmark scripts. This module never imports ``hsync_rendezvous``.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

__all__ = [
    "ALPHABET",
    "BenchResult",
    "add_json_out",
    "cpu_percent",
    "format_cpu",
    "make_cid",
    "make_cids",
    "maybe_write_json",
    "measure",
    "percentile",
    "print_table",
    "proc_cpu_seconds",
    "proc_rss_mb",
    "timed_query",
]

# CID alphabet (spec: ^[A-Za-z0-9]{21}$).
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def make_cid(n: int) -> str:
    """Deterministic 21-char CID for counter value ``n``."""
    base = len(ALPHABET)
    chars = []
    value = n
    for _ in range(21):
        chars.append(ALPHABET[value % base])
        value //= base
    return "".join(reversed(chars))


def make_cids(count: int, start: int = 0) -> list[str]:
    return [make_cid(start + i) for i in range(count)]


class BenchResult:
    """One measured operation: name, sample count and latency stats (ms)."""

    def __init__(self, name: str, samples: Sequence[float], count: int) -> None:
        lat_ms = [s * 1000.0 for s in samples]
        self.name = name
        self.count = count
        self.total_s = sum(samples)
        self.ops = count / self.total_s if self.total_s > 0 else 0.0
        self.p50 = statistics.median(lat_ms) if lat_ms else 0.0
        self.p99 = percentile(lat_ms, 99.0)
        self.mean = statistics.fmean(lat_ms) if lat_ms else 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "count": self.count,
            "total_s": round(self.total_s, 4),
            "ops_per_s": round(self.ops, 1),
            "mean_ms": round(self.mean, 4),
            "p50_ms": round(self.p50, 4),
            "p99_ms": round(self.p99, 4),
        }


def percentile(data: Sequence[float], pct: float) -> float:
    if not data:
        return 0.0
    ordered = sorted(data)
    # Nearest-rank percentile: rank = ceil(pct/100 * n) - 1.
    rank = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * pct / 100.0) - 1))
    return ordered[rank]


def measure(
    name: str,
    func: Callable[[], None],
    *,
    count: int,
    warmup: int = 200,
) -> BenchResult:
    """Run ``func`` ``count`` times (after ``warmup``) and time each call."""
    for _ in range(warmup):
        func()
    samples: list[float] = []
    for _ in range(count):
        start = time.perf_counter()
        func()
        samples.append(time.perf_counter() - start)
    return BenchResult(name, samples, count)


async def timed_query(
    client: Any, frame: dict, *, timeout: float = 10.0, require_no_error: bool = True
) -> float:
    """Time one ``query`` round-trip on an established client, in seconds.

    ``client`` is a ``tests/harness.py`` ``RdvClient`` (duck-typed to keep this
    module free of the harness import). Raises ``RuntimeError`` when the reply
    is not a ``response`` frame, or — when ``require_no_error`` — when the node
    answered an error: timing a rate-limited reply would not measure the query
    path. Single source for the query round-trip the L2/L5 benchmarks share.
    """
    start = time.perf_counter()
    reply = await client.exchange(frame, timeout=timeout)
    elapsed = time.perf_counter() - start
    if reply.get("type") != "response":
        raise RuntimeError("unexpected reply frame")
    if require_no_error and reply.get("error") is not None:
        raise RuntimeError(f"query refused: {reply.get('error')}")
    return elapsed


def print_table(results: Sequence[BenchResult]) -> None:
    header = f"{'operation':<28}{'ops/s':>12}{'mean_ms':>10}{'p50_ms':>10}{'p99_ms':>10}{'n':>8}"
    print(header)
    print("-" * len(header))
    for result in results:
        print(
            f"{result.name:<28}{result.ops:>12.1f}{result.mean:>10.4f}"
            f"{result.p50:>10.4f}{result.p99:>10.4f}{result.count:>8}"
        )


def add_json_out(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json-out",
        default=None,
        help="Write the results as JSON to the given path (besides stdout).",
    )


def maybe_write_json(path: str | None, results: Sequence[BenchResult]) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump([r.as_dict() for r in results], handle, indent=2)
        handle.write("\n")
    print(f"wrote {path}")


# --------------------------------------------------------------------------- #
# Node process sampling (Linux /proc) — CPU and RSS of the spawned rendezvous
# --------------------------------------------------------------------------- #

try:
    _CLK_TCK: float = float(os.sysconf("SC_CLK_TCK"))  # type: ignore[attr-defined]
except (AttributeError, OSError, ValueError):  # pragma: no cover - non-Unix
    _CLK_TCK = 100.0


def proc_cpu_seconds(pid: int) -> float | None:
    """Total CPU seconds (user+system) consumed by ``pid``, or ``None``.

    Read from ``/proc/<pid>/stat``; ``None`` when the file is unavailable
    (non-Linux hosts). ``comm`` (field 2) may contain spaces/parens, so parsing
    resumes after the last ``)``: ``utime``/``stime`` are then fields 14/15, i.e.
    indexes 11/12 of the post-comm tokens.
    """
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
    except OSError:
        return None
    tokens = stat.rsplit(")", 1)[-1].split()
    if len(tokens) < 13:
        return None
    return (int(tokens[11]) + int(tokens[12])) / _CLK_TCK


def proc_rss_mb(pid: int) -> float:
    """Resident set size of ``pid`` in MiB (Linux /proc); ``-1.0`` if unavailable."""
    try:
        status = (Path("/proc") / str(pid) / "status").read_text(encoding="utf-8")
    except OSError:
        return -1.0
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024.0
    return -1.0


def cpu_percent(
    cpu_before: float | None, cpu_after: float | None, wall_seconds: float
) -> float | None:
    """CPU busy fraction as % of ONE core over ``wall_seconds`` (``None`` if unknown)."""
    if cpu_before is None or cpu_after is None or wall_seconds <= 0:
        return None
    return max(0.0, (cpu_after - cpu_before) / wall_seconds) * 100.0


def format_cpu(pct: float | None) -> str:
    """Render a CPU percentage (``'n/a'`` when ``None``)."""
    return "n/a" if pct is None else f"{pct:.0f}%"
