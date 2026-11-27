"""L3 — soak script (MANUAL, not a test): sustained mixed traffic.

Spawns the rendezvous binary (language-neutral) and drives it with
register/refresh/query/leave traffic for --duration seconds over **QUIC/UDP**
(default), **TLS/TCP**, or both, sampling the *node* process RSS and CPU (/proc)
and its convergence (a final query must return zero peers after the load stops
and the TTL drains).

Pass criteria: no exception, convergence (TTL/prune drain the table), RSS delta
under --max-rss-mb. Nothing is written by the node itself. Rate limiting is
disabled for the soak (it measures sustained throughput/convergence; the BB
suite covers rate-limit behaviour separately).

Transport asymmetry is part of the contract: a QUIC client reuses one connection
and opens a stream per frame; ``rdv/1`` over TLS/TCP is one session per
connection, so every TCP operation dials (and pays the TLS handshake for) a fresh
session.

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/soak.py \
        [--transport quic|tcp|both] [--duration 600] [--peers 500] [--qps 20] \
        [--ttl 60]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from common import (
    add_json_out,
    cpu_percent,
    format_cpu,
    make_cids,
    proc_cpu_seconds,
    proc_rss_mb,
)
from harness import (
    leave_frame,
    open_session,
    query_frame,
    refresh_frame,
    register_frame,
    start_rendezvous,
    terminate,
)


async def _soak(
    args: argparse.Namespace, port: int, node_pid: int, transport: str
) -> dict[str, object]:
    t0 = time.monotonic()
    cids = make_cids(args.peers, start=9_000_000)
    rss_start = proc_rss_mb(node_pid)
    cpu_start = proc_cpu_seconds(node_pid)
    errors = 0
    ops = 0

    async def _send(client, frame: dict, expect_reply: bool) -> dict | None:
        if not expect_reply:
            await client.send_only(frame)
            return None
        return await client.exchange(frame, timeout=5.0)

    # Only CIDs that actually got an ack are "live": refresh/leave must never
    # target an unknown record (the server would silently drop it, causing a
    # read timeout that is not a real error).
    live: list[str] = []

    async with open_session(transport, port) as client:
        deadline = time.monotonic() + args.duration
        tick = 0
        next_sample = time.monotonic() + 30.0
        last_cpu = cpu_start
        last_sample_t = t0
        while time.monotonic() < deadline:
            tick += 1
            kind = tick % 10
            try:
                if kind < 4 or not live:
                    cid = cids[tick % args.peers]
                    reply = await _send(client, register_frame(cid, "shared"), True)
                    if reply is not None and reply.get("type") == "ack":
                        live.append(cid)
                elif kind < 7:
                    await _send(client, refresh_frame(live[0], "shared"), True)
                elif kind < 9:
                    await _send(client, query_frame("shared", limit=20), True)
                else:
                    await _send(client, leave_frame(live.pop(0), "shared"), False)
                ops += 1
            except Exception as exc:
                errors += 1
                print(f"op error ({type(exc).__name__}): {exc}")
            now = time.monotonic()
            if now >= next_sample:
                cpu_now = proc_cpu_seconds(node_pid)
                cpu_pct = cpu_percent(last_cpu, cpu_now, now - last_sample_t)
                last_cpu, last_sample_t = cpu_now, now
                next_sample = now + 30.0
                rss = proc_rss_mb(node_pid)
                print(
                    f"  t+{now - t0:5.0f}s ops={ops} errors={errors} "
                    f"rss={rss:.0f}MB cpu={format_cpu(cpu_pct)}"
                )
            await asyncio.sleep(max(0.0, 1.0 / args.qps))

    # drain: stop load, wait past TTL, the table must converge to zero peers
    await asyncio.sleep(args.drain)
    async with open_session(transport, port) as client:
        reply = await client.exchange(query_frame("shared", limit=20), timeout=5.0)
    left = reply["count"]
    rss_end = proc_rss_mb(node_pid)
    cpu_avg = cpu_percent(cpu_start, proc_cpu_seconds(node_pid), time.monotonic() - t0)
    print(
        f"drained: transport={transport} peers={left} "
        f"rss={rss_start:.0f}->{rss_end:.0f}MB "
        f"cpu_avg={format_cpu(cpu_avg)} ops={ops}"
    )
    ok = errors == 0 and left == 0 and (rss_end - rss_start) <= args.max_rss_mb
    print("SOAK-" + ("PASS" if ok else "FAIL"))
    return {
        "ok": ok,
        "transport": transport,
        "duration_s": round(time.monotonic() - t0, 1),
        "peers": args.peers,
        "qps": args.qps,
        "ops": ops,
        "errors": errors,
        "peers_left": left,
        "rss_start_mb": round(rss_start, 1),
        "rss_end_mb": round(rss_end, 1),
        "rss_delta_mb": round(rss_end - rss_start, 1),
        "cpu_avg_pct": None if cpu_avg is None else round(cpu_avg, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--transport",
        choices=("quic", "tcp", "both"),
        default="quic",
        help="Transport to soak (default quic; both runs the soak twice).",
    )
    parser.add_argument("--duration", type=float, default=600.0)
    parser.add_argument("--peers", type=int, default=500)
    parser.add_argument("--qps", type=float, default=20.0)
    parser.add_argument("--max-rss-mb", type=float, default=120.0)
    parser.add_argument("--ttl", type=int, default=60)
    parser.add_argument(
        "--drain",
        type=float,
        default=90.0,
        help="Seconds to wait after load for TTL/prune convergence.",
    )
    add_json_out(parser)
    args = parser.parse_args()

    transports = ("quic", "tcp") if args.transport == "both" else (args.transport,)
    with tempfile.TemporaryDirectory(prefix="rendezvous-soak-") as tmp:
        handle = start_rendezvous(Path(tmp), ttl=args.ttl, no_rate_limit=True)
        node_pid = handle.node_pid
        if node_pid is None:  # pragma: no cover - start_rendezvous always awaits readiness
            raise RuntimeError("rendezvous readiness PID was not reported")
        try:
            summaries = [
                asyncio.run(_soak(args, handle.port, node_pid, transport))
                for transport in transports
            ]
        finally:
            terminate(handle)
    if args.json_out:
        payload: object = summaries[0] if len(summaries) == 1 else {"runs": summaries}
        with open(args.json_out, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        print(f"wrote {args.json_out}")
    raise SystemExit(0 if all(summary["ok"] for summary in summaries) else 1)


if __name__ == "__main__":
    main()
