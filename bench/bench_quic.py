"""L2 — transport loopback load benchmark (real transport, language-neutral).

Spawns the rendezvous binary (``HSYNC_RENDEZVOUS_BIN``, default Python build) and
drives it with a real client over the ``rdv/1`` wire protocol, on **QUIC/UDP**
(default), **TLS/TCP**, or both. This benchmark is independent of the
implementation language: it measures the handshake cost separately from per-frame
cost, plus end-to-end query throughput, against whatever binary is selected.

Transport asymmetry is part of the contract: a QUIC client reuses one connection
and opens a stream per exchange, while ``rdv/1`` over TCP is one session per
connection, so the TLS/TCP rows time the whole session (handshake + frame) and
carry a ``tcp-`` prefix to keep the operation names distinct in ``compare.py``.

Loopback numbers are comparative (v1 vs future ports), not production SLAs:
localhost removes real network latency but keeps the full TLS 1.3 stack.

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/bench_quic.py \
        [--transport quic|tcp|both] [--connections N] [--frames N] \
        [--concurrency C] [--peers P] [--json-out FILE]
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from aioquic.asyncio import connect  # noqa: E402
from common import (  # noqa: E402
    BenchResult,
    add_json_out,
    make_cids,
    maybe_write_json,
    print_table,
    timed_query,
)
from harness import (  # noqa: E402
    RdvTcpClient,
    client_config,
    open_session,
    query_frame,
    register_frame,
    start_rendezvous,
    terminate,
)

_TRANSPORTS = ("quic", "tcp")


async def _bench_handshakes(port: int, count: int, transport: str) -> BenchResult:
    """Time the handshake only (connection setup), teardown outside the region.

    On QUIC the teardown is deliberately left OUTSIDE the timed region: the
    context-manager exit calls ``wait_closed()``, which blocks on the QUIC
    closing-period drain timer (``_close_at = now + 3 * PTO``) instead of
    measuring handshake work. Timing the whole ``async with`` therefore reported
    a ~10x inflated "handshake" (mostly idle timer on loopback) — see
    ``bench/profile_handshake.py``. On TLS/TCP ``open_connection`` returns once
    the TLS 1.3 handshake completed, so the same region is handshake work.
    """
    samples: list[float] = []
    if transport == "tcp":
        client = RdvTcpClient(port)
        for _ in range(5):
            _reader, writer = await client.open_connection()
            await client._close(writer)
        for _ in range(count):
            start = time.perf_counter()
            _reader, writer = await client.open_connection()
            samples.append(time.perf_counter() - start)
            await client._close(writer)
        return BenchResult("tcp-handshake(sequential)", samples, count)

    config = client_config()
    for _ in range(5):
        async with connect("127.0.0.1", port, configuration=config):
            pass
    for _ in range(count):
        cm = connect("127.0.0.1", port, configuration=config)
        start = time.perf_counter()
        await cm.__aenter__()
        samples.append(time.perf_counter() - start)
        await cm.__aexit__(None, None, None)  # closing drain, not handshake work
    return BenchResult("quic-handshake(sequential)", samples, count)


async def _bench_frames_on_one_connection(
    port: int, frames: int, peers: int, transport: str
) -> BenchResult:
    """Register+query round-trips on one client (QUIC reuses, TCP re-dials)."""
    cids = make_cids(peers, start=5_000_000)
    query = query_frame("shared", limit=20)
    samples: list[float] = []
    async with open_session(transport, port) as client:
        await client.pipeline([register_frame(cid, "shared") for cid in cids], timeout=30.0)
        for _ in range(10):
            await client.exchange(query, timeout=5.0)
        for _ in range(frames):
            samples.append(await timed_query(client, query))
    name = (
        f"tcp-query-session-rtt(peers={peers})"
        if transport == "tcp"
        else f"query-rtt-1conn(peers={peers})"
    )
    return BenchResult(name, samples, frames)


async def _bench_concurrent_queries(
    port: int, connections: int, per_conn: int, transport: str
) -> BenchResult:
    """N concurrent clients each doing per_conn query round-trips."""

    async def worker() -> list[float]:
        query = query_frame("shared", limit=20)
        samples: list[float] = []
        async with open_session(transport, port) as client:
            for _ in range(per_conn):
                samples.append(await timed_query(client, query))
        return samples

    await worker()
    started = time.perf_counter()
    results = await asyncio.gather(*[worker() for _ in range(connections)])
    wall = time.perf_counter() - started
    total = connections * per_conn
    print(f"  {transport} wall: {wall:.2f}s for {total} queries over {connections} clients")
    merged = [sample for samples in results for sample in samples]
    prefix = "tcp-" if transport == "tcp" else ""
    return BenchResult(f"{prefix}query-rtt({connections}x{per_conn}-concurrent)", merged, total)


async def _amain(args: argparse.Namespace, port: int) -> list[BenchResult]:
    transports = _TRANSPORTS if args.transport == "both" else (args.transport,)
    results: list[BenchResult] = []
    for transport in transports:
        results.append(await _bench_handshakes(port, args.connections, transport))
        results.append(
            await _bench_frames_on_one_connection(port, args.frames, args.peers, transport)
        )
        results.append(
            await _bench_concurrent_queries(port, args.concurrency, args.per_conn, transport)
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--transport",
        choices=("quic", "tcp", "both"),
        default="quic",
        help="Transport to drive (default quic; both runs the matrix twice).",
    )
    parser.add_argument("--connections", type=int, default=50)
    parser.add_argument("--frames", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--per-conn", type=int, default=25)
    parser.add_argument("--peers", type=int, default=200)
    add_json_out(parser)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rendezvous-bench-") as tmp:
        handle = start_rendezvous(Path(tmp), no_rate_limit=True)
        try:
            results = asyncio.run(_amain(args, handle.port))
        finally:
            terminate(handle)

    print(f"Loopback load, transport={args.transport} (localhost; comparative, not an SLA)")
    print_table(results)
    maybe_write_json(args.json_out, results)


if __name__ == "__main__":
    main()
