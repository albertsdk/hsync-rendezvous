"""L3 — soak script (MANUAL, not a test): sustained mixed traffic.

Spawns the rendezvous binary (language-neutral) and drives it with
register/refresh/query/leave traffic for --duration seconds, sampling the
*node* process RSS and CPU (/proc) and its convergence (a final query must
return zero peers after the load stops and the TTL drains).

Pass criteria: no exception, convergence (TTL/prune drain the table), RSS delta
under --max-rss-mb. Nothing is written by the node itself. Rate limiting is
disabled for the soak (it measures sustained throughput/convergence; the BB
suite covers rate-limit behaviour separately).

Usage:
    cd hsync-rendezvous && python/.venv/bin/python bench/soak.py \
        [--duration 600] [--peers 500] [--qps 20] [--ttl 60]
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

from aioquic.asyncio import connect  # noqa: E402
from common import (  # noqa: E402
    add_json_out,
    cpu_percent,
    format_cpu,
    make_cids,
    proc_cpu_seconds,
    proc_rss_mb,
)
from harness import (  # noqa: E402
    client_config,
    leave_frame,
    query_frame,
    refresh_frame,
    register_frame,
    start_rendezvous,
    terminate,
)


async def _soak(args: argparse.Namespace, port: int, node_pid: int) -> dict[str, object]:
    t0 = time.monotonic()
    cids = make_cids(args.peers, start=9_000_000)
    config = client_config()
    rss_start = proc_rss_mb(node_pid)
    cpu_start = proc_cpu_seconds(node_pid)
    errors = 0
    ops = 0

    async def _send(frame: dict, expect_reply: bool, protocol) -> dict | None:
        reader, writer = await protocol.create_stream()
        writer.write((json.dumps(frame) + "\n").encode())
        await writer.drain()
        if not expect_reply:
            writer.close()
            return None
        raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
        writer.close()
        return json.loads(raw)

    # Only CIDs that actually got an ack are "live": refresh/leave must never
    # target an unknown record (the server would silently drop it, causing a
    # read timeout that is not a real error).
    live: list[str] = []

    async with connect("127.0.0.1", port, configuration=config) as p:
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
                    reply = await _send(register_frame(cid, "shared"), True, p)
                    if reply is not None and reply.get("type") == "ack":
                        live.append(cid)
                elif kind < 7:
                    await _send(refresh_frame(live[0], "shared"), True, p)
                elif kind < 9:
                    await _send(query_frame("shared", limit=20), True, p)
                else:
                    await _send(leave_frame(live.pop(0), "shared"), False, p)
                ops += 1
            except Exception as exc:  # noqa: BLE001 - soak must record, not crash
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
    async with connect("127.0.0.1", port, configuration=config) as p:
        r, w = await p.create_stream()
        w.write((json.dumps(query_frame("shared", limit=20)) + "\n").encode())
        await w.drain()
        raw = await asyncio.wait_for(r.readline(), timeout=5.0)
        w.close()
    left = json.loads(raw)["count"]
    rss_end = proc_rss_mb(node_pid)
    cpu_avg = cpu_percent(cpu_start, proc_cpu_seconds(node_pid), time.monotonic() - t0)
    print(
        f"drained: peers={left} rss={rss_start:.0f}->{rss_end:.0f}MB "
        f"cpu_avg={format_cpu(cpu_avg)} ops={ops}"
    )
    ok = errors == 0 and left == 0 and (rss_end - rss_start) <= args.max_rss_mb
    print("SOAK-" + ("PASS" if ok else "FAIL"))
    return {
        "ok": ok,
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

    with tempfile.TemporaryDirectory(prefix="rendezvous-soak-") as tmp:
        handle = start_rendezvous(Path(tmp), ttl=args.ttl, no_rate_limit=True)
        node_pid = handle.node_pid
        if node_pid is None:  # pragma: no cover - start_rendezvous always awaits readiness
            raise RuntimeError("rendezvous readiness PID was not reported")
        try:
            summary = asyncio.run(_soak(args, handle.port, node_pid))
        finally:
            terminate(handle)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2)
            stream.write("\n")
        print(f"wrote {args.json_out}")
    raise SystemExit(0 if summary["ok"] else 1)


if __name__ == "__main__":
    main()
