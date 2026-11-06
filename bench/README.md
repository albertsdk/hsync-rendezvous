# Benchmarks — hsync-rendezvous

Six tiers, split by language-dependence:

| Tier | Script | Transport | Language-neutral? |
|---|---|---|---|
| L1 | `bench_handler.py` | none (calls `RendezvousHandler.handle`) | **No** — Python-internal micro-benchmark |
| L2 | `bench_quic.py` | real QUIC/UDP loopback | **Yes** — spawns the binary, wire-only |
| L3 | `soak.py` | real QUIC/UDP loopback (sustained) | **Yes** — spawns the binary, wire-only |
| L4 | `profile_handshake.py` | real QUIC/UDP loopback (diagnostic) | **No** — splits the `aioquic` client cost |
| L5 | `cpu_saturation.py` | real QUIC/UDP loopback (diagnostic) | **No** — sweeps load, reads node CPU from `/proc` |
| L6 | `memory.py` | in-process (A) + real QUIC/UDP loopback (B) | **Mixed** — A is Python-internal (`tracemalloc`); B spawns the binary, wire-only |

L2/L3/L6-B launch the rendezvous executable (`HSYNC_RENDEZVOUS_BIN`, default Python
build) and drive it only through the `rdv/1` wire protocol, so the same
benchmark runs unchanged against the future `c/` port. L1 (handler),
L6-A and the L4/L5 diagnostics are Python-internal; L5's CPU sampling needs Linux
`/proc` and reports `n/a` elsewhere.

These load/diagnostic tiers drive **QUIC/UDP** through the wire harness in
`tests/harness.py`. The **TLS/TCP** transport is covered by the functional and
black-box test suites (see [`tests/README.md`](../tests/README.md)), not by the
load tiers.

> **The `quic-handshake` metric measures the handshake, not the teardown.**
> `aioquic`'s connect context manager calls `wait_closed()` on exit, which blocks
> on the QUIC closing-period drain timer (`3 * PTO` — ~130 ms of idle wait on
> loopback at ~0% CPU). L2 therefore times only the handshake (`__aenter__`) and
> lets the drain run outside the measured region; L4 quantifies both halves.

## Running

```bash
cd hsync-rendezvous

# L1 — handler micro-benchmark (Python-only)
python/.venv/bin/python bench/bench_handler.py --count 2000

# L2 — QUIC loopback load (language-neutral)
python/.venv/bin/python bench/bench_quic.py --connections 50 --frames 200

# L3 — soak (language-neutral)
python/.venv/bin/python bench/soak.py --duration 600 --peers 500 --qps 20

# L4 — handshake profiling (Python-internal, diagnostic)
python/.venv/bin/python bench/profile_handshake.py --count 50 --cprofile 15

# L5 — CPU-saturation sweep (Linux; node CPU% vs load vs p99)
python/.venv/bin/python bench/cpu_saturation.py --peers 200 --levels 1,2,4,8,16,32

# L6 — RAM footprint (in-process per-item, and opt-in node process RSS)
python/.venv/bin/python bench/memory.py --records 20000 --limiter-keys 100000
python/.venv/bin/python bench/memory.py --node --peers 20000 --endpoints 3

# Against a different implementation
HSYNC_RENDEZVOUS_BIN=/path/to/hsync-rendezvous python/.venv/bin/python bench/bench_quic.py
```

`--json-out FILE` writes machine-readable results on every tier.

## Comparing two runs

`bench/compare.py` pairs two `--json-out` runs (a file, or a directory of
`*.json`) by operation name and flags a regression when an operation's median
(`p50_ms`) grows past `--threshold` while its before-run mean sat at/above the
`--min-mean-ms` noise floor; it exits 1 on any flagged regression. Same metrics
on every tier, so it is the language-neutral way to quantify a change or the
Python→C port:

```bash
python/.venv/bin/python bench/bench_handler.py --count 4000 --json-out /tmp/before.json
# ... apply a change ...
python/.venv/bin/python bench/bench_handler.py --count 4000 --json-out /tmp/after.json
python/.venv/bin/python bench/compare.py /tmp/before.json /tmp/after.json
```

## Shared helpers

- `bench/common.py` — deterministic CIDs, timing/stats and node-process sampling
  (`proc_cpu_seconds` / `proc_rss_mb` / `cpu_percent`, stdlib only).
- `tests/harness.py` — wire frame builders, process lifecycle, QUIC client and
  the shared `client_config()` (single source used by the black-box suite and
  every L2/L4 benchmark).
