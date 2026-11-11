# HSYNC Rendezvous — Python implementation (v1)

In-memory, zero-knowledge P2P rendezvous node for HSYNC, sharing the single wire
protocol `rdv/1` (see [`../protocol-spec/rdv-1.md`](../protocol-spec/rdv-1.md)).

## Status

**v1 complete**: QUIC listener(s) (aioquic) with mandatory RETRY +
address-validation, persisted or in-memory TLS identity, rigid `rdv/1` schemas,
in-memory routing table (TTL/prune/sample), sliding-window rate limits,
protected buckets with constant-time token compare, STUN-echo, zero-touch UPnP,
an in-memory opaque-TLS data relay (on by default) and the no-log invariant
enforced under a read-only filesystem test.

## Layout

```
python/
├── pyproject.toml
├── src/hsync_rendezvous/
│   ├── __init__.py / __main__.py  # package + `python -m hsync_rendezvous`
│   ├── cli.py            # Typer CLI (run, identity show/rotate, --version, envvars)
│   ├── diagnostics.py    # always-on peer-free stderr channel + opt-in --debug sink
│   ├── framing.py        # bounded NDJSON framing (request loop + relay control)
│   ├── protocol.py       # rdv/1 frame models + validators (pydantic extra="forbid")
│   ├── handler.py        # transport-agnostic core (routing + token auth + rate limits)
│   ├── server.py         # QUIC transport (aioquic), connection guard, TLS identity
│   ├── routing.py        # in-memory routing table (TTL/prune/sample)
│   ├── ratelimit.py      # sliding-window rate limiters (hsync_common re-export)
│   ├── relay.py          # in-memory opaque-TLS data relay (on by default)
│   ├── resources.py      # host RAM/CPU-derived ceilings
│   ├── stats.py          # peer-free aggregate counters
│   ├── metrics.py        # loopback bearer-authenticated /metrics endpoint
│   ├── systemd.py        # sd_notify readiness / watchdog
│   ├── tokens.py         # bucket_token derive + constant-time compare
│   └── upnp.py           # zero-touch UDP mapping (SSDP + SOAP, best-effort)
├── fuzz/
│   ├── fuzz_boot.py      # deterministic stdlib fuzz targets (decoder/SSDP/tokens)
│   └── fuzz_guided.py    # coverage-guided corpus driver
└── tests/
    ├── conftest.py / rdv_response.py        # fixtures / response parity oracle
    ├── test_scaffold.py                     # fixtures / spec + schema positives/negatives
    ├── test_handler.py                      # routing, TTL, token auth, rate limits, STUN-echo
    ├── test_server.py                       # QUIC loopback + connection guard
    ├── test_relay.py                        # relay pairing, quotas, shutdown
    ├── test_cli.py                          # CLI contract
    ├── test_identity.py                     # persistent identity create/load/rotate
    ├── test_ratelimit.py                    # limiter semantics
    ├── test_resources.py                    # host-derived ceilings
    ├── test_stats.py                        # aggregate counters
    ├── test_metrics_http.py                 # loopback /metrics endpoint
    ├── test_upnp.py                         # SSDP/SOAP shapes, stateless no-IGD
    ├── test_nolog.py                        # zero-write invariant (read-only fs)
    ├── test_systemd.py                      # sd_notify payloads
    ├── test_diagnostics.py                  # peer-free channel + debug sink
    ├── test_fuzz_harness.py                 # bounded deterministic + coverage-guided burst
    ├── test_install_script.py               # install.sh contract
    ├── test_compile_script.py               # compile.sh container commands
    ├── test_deb_maintainer_scripts.py       # deb lifecycle
    └── test_build_scripts_windows.py        # windows installer scaffolding
```

## Run

```bash
python -m hsync_rendezvous run --listen-host 0.0.0.0 --listen-port 443
```

## Build (standalone binary)

```bash
cd python
./compile.sh            # → python/dist/linux-amd64/hsync-rendezvous
```

This per-language script builds binaries only (`native`, `onedir`). The
repository-root [`../compile.sh`](../compile.sh) is the entry point for the
user-facing artifacts and wraps it: `native` (host standalone),
`rpi` (Raspberry Pi armhf/arm64) and `deb`/`deb-all`. Protected buckets and keys
provisioning, service deployment and the full option list:
[`../docs/usage.md`](../docs/usage.md).