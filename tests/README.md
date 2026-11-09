# Black-box tests — hsync-rendezvous

Language-neutral functional tests for the `rdv/1` rendezvous node. They are
**independent of the implementation language**: the same suite will
validate the future `c/` port unchanged.

## Contract

The tests spawn the rendezvous executable and observe **only** its public
surface:

- the CLI (`run`, `--version`, `--private`, fail-fast exit codes — 2 config
  error, 3 listener bind failure);
- the `rdv/1` wire protocol over QUIC/UDP and TLS/TCP (`hsync-rdv/1` ALPN, NDJSON frames).

They never import `hsync_rendezvous` or touch internal state. If the whole
implementation were rewritten while keeping the same CLI + wire contract, the
suite would still pass.

## Running

The suite is gated by `HSYNC_BB_RENDEZVOUS=1` and uses the Python virtualenv only
as a *test runner* (pytest + aioquic for the wire client):

```bash
# from the workspace root (equivalent: make test-bb-rendezvous)
cd hsync-rendezvous
HSYNC_BB_RENDEZVOUS=1 python/.venv/bin/python -m pytest -q tests/
```

### Stress suite (opt-in)

`tests/test_bb_rendezvous_stress.py` is gated **in addition** by `HSYNC_BB_STRESS=1`
and proves the node stays correct and alive under sustained concurrent load,
bursts, churn, a garbage storm and a TTL sweep under load. Scale is bounded by
environment knobs (read at import time):

```bash
cd hsync-rendezvous
HSYNC_BB_RENDEZVOUS=1 HSYNC_BB_STRESS=1 python/.venv/bin/python -m pytest -q tests/test_bb_rendezvous_stress.py
```

| Knob | Default | Meaning |
|---|---|---|
| `HSYNC_BB_RENDEZVOUS_STRESS_CONNECTIONS` | 4 | concurrent QUIC clients |
| `HSYNC_BB_RENDEZVOUS_STRESS_ROUNDS` | 4 | register/query/refresh/leave rounds per client |
| `HSYNC_BB_RENDEZVOUS_STRESS_PEERS` | 50 | peers registered for the rendezvous/TTL/garbage scenarios |
| `HSYNC_BB_RENDEZVOUS_STRESS_MAX_P99_MS` | 1000 | p99 latency budget for the mixed-load scenario |

Without `HSYNC_BB_STRESS=1` the module is skipped, so the default suite stays
fast.

### Security probes (opt-in)

`tests/test_bb_rendezvous_security.py` is gated **in addition** by
`HSYNC_BB_SECURITY=1` and runs adversarial black-box probes (penetration-style)
against the running node: authorization bypass (cross-bucket token replay,
foreign-bucket eviction, malformed-token budget abuse, private-mode enumeration
oracle), source spoofing from a second loopback address (127.0.0.2 register
hijack / leave eviction), parser abuse (deep nesting, integer overflow, JSON
infinity, unicode/NUL smuggling), DoS (pipelined burst, bucket-enumeration
sweep, raw non-QUIC UDP garbage, concurrent handshake flood), wrong-ALPN
handshake, authorization timing uniformity, secret handling (`--keys-fd` never
leaks onto argv/env, identity file `0600`/`0700`, ephemeral writes nothing),
log-forging via control characters and reply amplification.

The probes are black-box by the same contract as the functional suite (CLI +
`rdv/1` wire only) and stay skipped in the default run because they send
deliberately hostile traffic. `tests/test_bb_rendezvous_security_tcp.py` runs the
same adversarial probes against the TLS/TCP listener, under the same gate:

```bash
cd hsync-rendezvous
HSYNC_BB_RENDEZVOUS=1 HSYNC_BB_SECURITY=1 python/.venv/bin/python -m pytest -q "tests/test_bb_rendezvous_security*.py"
```

| Knob | Default | Meaning |
|---|---|---|
| `HSYNC_BB_RENDEZVOUS_SECURITY_FLOOD` | 120 | handshakes in the connection-flood probe |
| `HSYNC_BB_RENDEZVOUS_SECURITY_TIMING` | 30 | rounds in the authorization timing probe |

The 127.0.0.2 spoofing probes are skipped automatically where a second
loopback alias cannot be bound.

## Language selection

The executable under test is resolved from `HSYNC_RENDEZVOUS_BIN` (a path to the
`hsync-rendezvous` binary); it defaults to the Python build
(`python/.venv/bin/hsync-rendezvous`). To run the suite against a different
implementation, point the variable at its binary — the CLI contract is the
same:

```bash
HSYNC_BB_RENDEZVOUS=1 HSYNC_RENDEZVOUS_BIN=/path/to/hsync-rendezvous \
  python/.venv/bin/python -m pytest -q tests/
```

## Readiness and isolation

- Readiness is signalled through the `HSYNC_RENDEZVOUS_READY_FILE` seam: the
  process writes its PID there once a listener is bound, and removes it
  on graceful shutdown (`SIGTERM`). The suite keys readiness on the file
  **appearing with a PID**, not on that PID equalling the launcher's: a
  onefile-packaged binary (PyInstaller, the `.deb` payload) runs the app in a
  child process, so the two PIDs differ.
- Each test starts a fresh subprocess with an environment scrubbed of every
  `HSYNC_*` variable **and** of the service-manager variables (`NOTIFY_SOCKET`,
  `WATCHDOG_USEC`, `WATCHDOG_PID`), so a suite running inside a systemd session
  cannot make the spawned node announce readiness to the runner's own manager.
  Teardown happens in a `finally`/fixture, so there are no orphan processes or
  cross-test contamination. The process runs in its own
  session (`start_new_session`) and is terminated as a whole group (SIGTERM,
  then SIGKILL), so a onefile launcher's application child is reaped too; a
  readiness failure also terminates the spawned process before re-raising.
- Protected-bucket keys are provisioned via `--keys-fd` (a pipe, never a file).
- Test data (CIDs, buckets, group keys) is randomized per run; the RNG seed is
  logged (`[seed] <n>`) for reproducible failures.

## Coverage

| Module | Scenarios |
|---|---|
| `test_bb_rendezvous_lifecycle.py` | `--version`, fail-fast config (`--no-udp --no-tcp`, `--listen-port`/`--listen-ports` conflict, duplicate/out-of-range ports, metrics without a token), readiness, graceful shutdown (`SIGTERM` idle **and under load**, `SIGINT`), IPv6 `[::1]` listener, debug mode (peer-aware stderr log), port-in-use bind failure (exit 3), `--upnp` banner + serving, invalid `--ttl` fail-fast |
| `test_bb_rendezvous_register.py` | STUN-echo ack, advertised/observed endpoints, refresh ack + `connected` update, unknown-CID refresh drop, re-register replaces endpoints (upsert), multi-endpoint list relayed in order, refresh never mutates capacity/election, re-register after leave, leave removes across groups, 3-frame pipeline, refresh-after-expiry drop |
| `test_bb_rendezvous_query.py` | peer listing, group filter, limit bounds, pipelined frames, capacity + election-advertisement relay, reachable, default sample limit (20), upper bound accepted, bucket scoping, group-less exclusion, same-cid distinct groups |
| `test_bb_rendezvous_protected_buckets.py` | uniform `token_required`, correct/wrong token, no oracle |
| `test_bb_rendezvous_private.py` | `--private`/envvar: every bucket gated, unkeyed bucket, gated `leave`, fail-fast without keys, banner |
| `test_bb_rendezvous_ratelimit.py` | burst → `rate_limited` + `retry_after` (query/register/bad-token), and the mirror case: two clients on one public address (a household) complete a lease cycle without a refusal |
| `test_bb_rendezvous_negative.py` | malformed/unknown/oversized/forbidden frames, partial-frame-then-disconnect, leave, limit out-of-range, malformed token, exact frame-size boundary, wrong field types, endpoints bounds, invalid bucket name, group length, cid length, non-object JSON, leave unknown cid |
| `test_bb_rendezvous_ttl.py` | TTL expiry convergence, refresh keeps peer alive |
| `test_bb_rendezvous_identity.py` | persistent identity (stable across restart), `identity rotate` (fingerprint changes), `identity show` (PEM, no key leak), fail-fast on missing file, `--identity`/`--ephemeral` exclusivity |
| `test_bb_rendezvous_multiport.py` | multi-port best-effort bind, one routing table shared by every port |
| `test_bb_rendezvous_tcp.py` | **TLS/TCP transport**: register/query/ack (TCP STUN echo; an endpoint-less peer is relayed with no candidates), pipelined frames, relay over TCP, wrong-ALPN refusal, `--tcp`/`--no-udp`/envvar, bind failure (exit 3), UDP-only refuses TCP |
| `test_bb_rendezvous_tcp_negative.py` | **TLS/TCP**: the negative/robustness frame suite (malformed/unknown/oversized/non-object/forbidden/boundary/grammar), over TCP |
| `test_bb_rendezvous_tcp_behaviour.py` | **TLS/TCP**: rate limit, TTL expiry + refresh, protected/private auth, multi-port shared table, IPv6, metrics `transport="tcp"` accounting, and "no plaintext frame is ever parsed" |
| `test_bb_rendezvous_security.py` | **opt-in** (`HSYNC_BB_SECURITY=1`): adversarial QUIC probes — authz bypass, source spoofing, parser abuse, DoS, wrong ALPN, timing side channel, secret handling, log forging, amplification |
| `test_bb_rendezvous_security_tcp.py` | **opt-in** (`HSYNC_BB_SECURITY=1`): the same adversarial probes over **TLS/TCP** — parser abuse, single-frame bound, pipelined/enumeration DoS, foreign-source register/leave, log forging, and cleartext bytes never reaching the handler |
| `test_bb_rendezvous_metrics.py` | loopback `/metrics`: uniform `401` without/with a wrong token, `200` with it, `404` unknown path, `405` non-read method, `HEAD` headers without a body, missing token file fail-fast, registered peers move the level and the peak, concurrent connections raise the connection peak, the periodic Prometheus text file, refusal/limit-hit/drop counters by reason (with closed label sets), and an exposition that never carries peer identity |
| `test_bb_rendezvous_stress.py` | **opt-in** (`HSYNC_BB_STRESS=1`): sustained mixed load, full-bucket rendezvous, rate-limit burst + recovery, garbage storm, TTL sweep under query load, register/leave churn RSS-bound (no leak) |
| `test_harness_readiness.py` | harness self-test: readiness is keyed on the application PID (not the launcher's), early-exit and timeout are surfaced |

Per-IP rate-limit isolation between *distinct* source IPs is not exercised here
(loopback forces a single source address); it is covered by the white-box unit
suite in `python/tests/test_handler.py`. The opposite case — several clients
sharing one address, which loopback reproduces exactly — is covered in
`test_bb_rendezvous_ratelimit.py`.
