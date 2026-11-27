"""L4 — handshake profiling (diagnostic; Python-internal driver).

Explains *why* the L2 ``quic-handshake`` number is large and separates the cost
a faster implementation language CAN remove (CPU spent in packets/crypto/JSON)
from the cost it CANNOT (a fixed client-side drain timer).

L2 times ``aioquic.connect()`` as a context manager, i.e. the handshake *plus*
its teardown. The teardown (``close()`` + ``wait_closed()``) blocks until the
QUIC closing-period timer expires (``_close_at = now + 3 * PTO``, see
``aioquic/quic/connection.py``) — on a loopback host that is ~130-135 ms of pure
wait at ~0% CPU, roughly ten times the handshake itself. This script measures
the two halves separately (wall time and client CPU), so the recoverable margin
is explicit.

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/profile_handshake.py \\
        [--count N] [--cprofile TOP] [--json-out FILE]
"""

from __future__ import annotations

import argparse
import asyncio
import cProfile
import pstats
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from aioquic.asyncio import connect
from common import (
    BenchResult,
    add_json_out,
    maybe_write_json,
    print_table,
)
from harness import client_config, start_rendezvous, terminate

# Kept <= 28 chars so print_table's column alignment holds.
_HANDSHAKE = "handshake(enter)"
_TEARDOWN = "teardown(exit)"
_TOTAL = "full-connect(bench)"


async def _phase(
    port: int, count: int, warmup: int = 5
) -> tuple[list[BenchResult], dict[str, float]]:
    """Split one ``connect()`` into handshake vs teardown; wall time + client CPU."""
    config = client_config()
    for _ in range(warmup):
        async with connect("127.0.0.1", port, configuration=config):
            pass

    handshake: list[float] = []
    teardown: list[float] = []
    total: list[float] = []
    cpu_handshake = 0.0
    cpu_teardown = 0.0
    for _ in range(count):
        t0 = time.perf_counter()
        c0 = time.process_time()
        cm = connect("127.0.0.1", port, configuration=config)
        await cm.__aenter__()  # TLS 1.3 + QUIC handshake
        t1 = time.perf_counter()
        c1 = time.process_time()
        await cm.__aexit__(None, None, None)  # close() + wait_closed() = drain timer
        t2 = time.perf_counter()
        c2 = time.process_time()
        handshake.append(t1 - t0)
        teardown.append(t2 - t1)
        total.append(t2 - t0)
        cpu_handshake += c1 - c0
        cpu_teardown += c2 - c1

    results = [
        BenchResult(_HANDSHAKE, handshake, count),
        BenchResult(_TEARDOWN, teardown, count),
        BenchResult(_TOTAL, total, count),
    ]
    cpu = {
        "handshake_cpu_ms": round(cpu_handshake / count * 1000.0, 3),
        "teardown_cpu_ms": round(cpu_teardown / count * 1000.0, 3),
    }
    return results, cpu


async def _cprofile(port: int, count: int, top: int) -> None:
    """Print the top ``top`` client-side CPU consumers across ``count`` handshakes."""
    config = client_config()
    for _ in range(5):
        async with connect("127.0.0.1", port, configuration=config):
            pass
    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(count):
        cm = connect("127.0.0.1", port, configuration=config)
        await cm.__aenter__()
        await cm.__aexit__(None, None, None)
    profiler.disable()
    print(
        f"\nTop {top} client CPU consumers ({count} handshakes, cProfile)\n"
        "  (the event loop's idle wait shows up as the selector poll; the real\n"
        "   CPU work is the aioquic/tls functions underneath it):"
    )
    pstats.Stats(profiler, stream=sys.stdout).sort_stats("cumulative").print_stats(top)


def _report(results: list[BenchResult], cpu: dict[str, float]) -> None:
    handshake, teardown, total = results
    print("Handshake profiling (client-side; server = spawned rendezvous binary)")
    print("  enter = TLS 1.3 + QUIC handshake | exit = close() + wait_closed() drain")
    print_table(results)
    print("\nClient CPU per phase (time.process_time):")
    print(
        f"  handshake : {cpu['handshake_cpu_ms']:8.2f} ms  "
        f"({cpu['handshake_cpu_ms'] / handshake.mean * 100:5.1f}% of wall)"
    )
    print(
        f"  teardown  : {cpu['teardown_cpu_ms']:8.2f} ms  "
        f"({cpu['teardown_cpu_ms'] / teardown.mean * 100:5.1f}% of wall)"
    )
    print(
        f"\nVerdict: the L2 metric reports {total.mean:.1f} ms, but only "
        f"{handshake.mean:.1f} ms is handshake; {teardown.mean:.1f} ms "
        f"({teardown.mean / total.mean * 100:.0f}%) is the client-side closing drain "
        f"({cpu['teardown_cpu_ms'] / teardown.mean * 100:.0f}% CPU — a timer, not work)."
    )
    print(
        f"Handshake CPU is {cpu['handshake_cpu_ms'] / handshake.mean * 100:.0f}% of the "
        "handshake: that is the portion a faster language could compress."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument(
        "--cprofile",
        type=int,
        default=0,
        metavar="TOP",
        help="Also run a profiled pass and print the TOP CPU consumers (0 = off).",
    )
    add_json_out(parser)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rendezvous-prof-") as tmp:
        handle = start_rendezvous(Path(tmp), no_rate_limit=True)
        try:
            results, cpu = asyncio.run(_phase(handle.port, args.count))
            _report(results, cpu)
            if args.cprofile:
                asyncio.run(_cprofile(handle.port, args.count, args.cprofile))
            maybe_write_json(args.json_out, results)
        finally:
            terminate(handle)


if __name__ == "__main__":
    main()
