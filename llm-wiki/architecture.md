# Architecture — hsync-rendezvous

Two interchangeable listeners on the same ports — QUIC/UDP and TLS/TCP (TLS 1.3
on both) — in-memory routing state, no logs; the only persisted
artifact is the node's own TLS identity. The v1
implementation is Python (aioquic); the C implementation planned in
the repo root `README.md` will share the same wire protocol SSOT
(`protocol-spec/rdv-1.md`) and the same fixtures.

## Layers

```
UDP :443 + TCP :443
  └─ server.py    transport assembly: start_servers/start_tcp_servers + shared
                  best-effort binder; public transport surface
       ├─ quic.py     QUIC (aioquic): RETRY, bounded windows, RendezvousQuicProtocol
       ├─ tcp.py      TLS/TCP (asyncio + ssl): admission before the handshake
       ├─ tls.py      TLS 1.3 context from the node identity (memfd/unlinked temp)
       ├─ session.py  transport-agnostic rdv/1 request loop + relay hand-off
       ├─ guard.py    ConnectionGuard: per-IP/global admission + connection metrics
       ├─ identity.py self-signed ECDSA P-256 identity (persistent/in-memory)
       └─ limits.py   frame/stream/session/admission tuning constants
  └─ handler.py   RendezvousHandler: transport-agnostic core — routing table,
                  token authorization (declared protected buckets or
                  every bucket in node-wide private mode), rate limiters
       ├─ wire.py      hand-assembled response/ack/peer serialization
       ├─ routing.py   in-memory table keyed (cid, bucket, group), bounded
       ├─ ratelimit.py bounded sliding-window limiters (peek + eviction)
       ├─ resources.py host RAM/CPU-derived ceilings for table + limiters
       └─ tokens.py    shared bucket_token primitives
  └─ relay.py     RelayRegistry: listener/session pairing and byte pump
       ├─ relay_state.py quotas/handoff/listener/pending/prefix reader
       └─ relay_wire.py  relay control-frame serialization
  └─ protocol.py  pydantic models for every rdv/1 frame (extra="forbid")
  └─ upnp.py      zero-touch UDP port mapping via SSDP + SOAP (best-effort)
  └─ cli.py       Typer CLI: `hsync-rendezvous run [OPTIONS]`, `--version`
       ├─ binding.py    listener bind errors/messages + shared bind step
       └─ lifecycle.py  prune/watchdog loops, readiness and stats files
```

## Module map

| Module | Responsibility | Key symbols |
|---|---|---|
| `python/src/hsync_rendezvous/protocol.py` | `rdv/1` frames; CID `^[A-Za-z0-9]{21}$`; 64-hex bucket token; client→server discriminated union; server→client `bytes` serializers (the `response` envelope itself is hand-assembled in `wire.py` and pinned by the test-side mirror `tests/rdv_response.py`) | `RdvRegister`, `RdvRefresh`, `RdvLeave`, `RdvQuery`, `RdvAck`, `RdvPeer`, `Endpoint`, `ObservedEndpoint`, `RdvFrame`, `RDV_FRAME_ADAPTER`, `RDV_ACK_ADAPTER`, `RDV_PEER_ADAPTER`; field grammars (`EndpointHost` → `is_valid_endpoint_host`, `CertificateFingerprint` → `parse_fingerprint`) and the relay bounds `MAX_RELAY_ENDPOINTS` / `MAX_RESPONSE_BYTES` |
| `python/src/hsync_rendezvous/framing.py` | Bounded NDJSON framing shared by every stream protocol: one newline-terminated, size-bounded reader with a per-stream `pending` buffer (pipelined frames are each returned in turn) and an optional idle timeout; oversized frames raise `FrameTooLarge` | `read_ndjson`, `FrameTooLarge` |
| `python/src/hsync_rendezvous/routing.py` | RAM-only table, TTL/prune/sample, source-IP ownership on mutation, bounded by `max_records` / `max_records_per_bucket` / `max_records_per_group` ceilings; `get` is active-only (expiry is the ownership authority); secondary indexes (`_by_group`/`_by_cid`/`_pos`) + a cached serialized `PeerRecord.wire` fragment (`bytes`); endpoints held as `(proto, host, port)` tuples, never pydantic models | `PeerRecord`, `EndpointTuple`, `RoutingTable` (`upsert` → `bool`, `remove`, `get`, `prune`, `sample`, `count`, `source_ips`) |
| `python/src/hsync_rendezvous/handler.py` | Request pipeline: malformed-frame pre-parse gate → validate (single pass) → per-IP admission → per-IP/per-(IP,bucket) limits → authorize (constant-time; declared protected buckets, or every bucket when `private=True`) → ownership check → mutate → reply (byte layout in `wire.py`); relays at most `MAX_RELAY_ENDPOINTS` endpoints per peer within `MAX_RESPONSE_BYTES` | `RendezvousHandler.handle`, `RendezvousConfigError`, `OP_IP_BURST`, `WINDOW_SECONDS`, `_may_replace`, `_authorize` |
| `python/src/hsync_rendezvous/wire.py` | Pure serialization of the server-controlled reply envelopes (`response` aggregate, STUN-echo `ack`) and the cached peer fragment; byte-for-byte pinned by the test-side pydantic mirror | `response_bytes`, `ack_bytes`, `peer_fragment` |
| `python/src/hsync_rendezvous/ratelimit.py` | Re-exports the `hsync_common.ratelimit.TokenBucketLimiter` SSOT (shared with `hsync-client`); the daemon imports the limiter from this package | `TokenBucketLimiter` (`allow`, `has_tokens`, `retry_after`, `refund`, `evict_stale`) |
| `python/src/hsync_rendezvous/resources.py` | Host-resource **budgeting**: available/total RAM and CPU count come from the shared `hsync-common/hsync_common/runtime.py` (cgroup v1/v2 incl. the process's nested cgroup, `MemAvailable`), and this module derives the `ResourceLimits` ceilings for the routing table, limiter maps and connection guard; conservative fallback when `/proc` is hidden | `ResourceLimits` (`detect`, `max_peer_records`, `max_records_per_bucket`, `max_records_per_group`), `available_memory_bytes`, `total_memory_bytes`, `cpu_count` |
| `python/src/hsync_rendezvous/tokens.py` | Re-exports the shared token primitives from `hsync-common/hsync_common/protocol/rdv_tokens.py` (`HMAC-SHA256(key, "rdv/1" || bucket)[:32]`, constant-time compare); the shared module is the single implementation used by the canonical daemon and the client mirror | `derive_bucket_token`, `verify_bucket_token`, `BUCKET_TOKEN_LEN` |
| `python/src/hsync_rendezvous/server.py` | Transport **assembly and public surface**: binds the process-wide handler, TLS identity and guard to one or more listeners on both transports (`start_servers`, `start_tcp_servers`, `--ports`; multi-port, decision 57), shared best-effort per-port binder, and re-exports the transport API (identity/guard/TLS/quic/tcp) used by `cli.py` and the white-box tests | `start_server`, `start_servers`, `start_tcp_servers`, `start_tcp_server`, `_bind_each_port`, plus re-exported `NodeIdentity`, `make_identity`, `load_or_create_identity`, `load_identity`, `rotate_identity`, `rotation_hint`, `IdentityError`, `build_tls_context`, `RendezvousQuicProtocol`, `RendezvousTcpProtocol`, `ConnectionGuard`, `build_quic_configuration` |
| `python/src/hsync_rendezvous/identity.py` | Self-signed ECDSA P-256 TLS identity (ADR-0034/ADR-0037): persistent by default (combined cert+key PEM, `0600`/`0700`, on-load key/cert consistency check, decision 54), in-memory via `make_identity` (`--ephemeral`); rotation preserves the existing DNS/IP SANs (decision 62) | `NodeIdentity`, `make_identity`, `load_or_create_identity`, `load_identity`, `rotate_identity`, `rotation_hint`, `IdentityError`, `_san_names`, `_atomic_write_identity`, `_key_matches_certificate` |
| `python/src/hsync_rendezvous/guard.py` | `ConnectionGuard`: per-IP handshake budget + per-IP and process-wide open-connection caps (sized by `ResourceLimits`), charged before any handshake work and released on teardown; feeds the connection metrics (total + per transport) and reaps quiet IPs | `ConnectionGuard.admit`/`release`/`exempt`/`release_metrics`/`transport_count`/`evict_stale` |
| `python/src/hsync_rendezvous/tls.py` | Server-side TLS 1.3 context from the node identity, ALPN `hsync-rdv/1`; the combined PEM is loaded through an anonymous memfd on Linux (unlinked `0600` temp file elsewhere) so the key never touches a filesystem | `build_tls_context` |
| `python/src/hsync_rendezvous/session.py` | Transport-agnostic `rdv/1` request loop shared by both transports: bounded NDJSON frame IO, one `handler.handle` per frame, reply write, and the relay hand-off (buffered prefix included) | `serve_rdv_session` |
| `python/src/hsync_rendezvous/quic.py` | QUIC adapter: RETRY, bounded receive windows (≤32 KiB/stream, ≤1 MiB/connection), per-connection peer tracking, session/relay stream caps, one `rdv/1` session per bidi stream | `build_quic_configuration`, `RendezvousQuicProtocol`, `protocol_factory`, `serve_quic_port` |
| `python/src/hsync_rendezvous/tcp.py` | TLS/TCP adapter: admission **before** the handshake and before any byte is read (`loop.start_tls`), ALPN enforcement, idle reaping, one connection = one session | `RendezvousTcpProtocol`, `tcp_protocol_factory`, `bind_tcp_socket`, `serve_tcp_port` |
| `python/src/hsync_rendezvous/limits.py` | Local transport bounds (frame, stream/connection windows, per-connection sessions/relay streams, per-IP admission, TLS handshake, listen backlog) shared by both transports | `MAX_FRAME_BYTES`, `MAX_STREAM_DATA_BYTES`, `MAX_DATA_BYTES`, `MAX_SESSIONS_PER_CONNECTION`, `MAX_RELAY_STREAMS_PER_CONNECTION`, `HANDSHAKE_*`, `CONNECTION_ACTIVE_MAX_PER_IP`, `TCP_HANDSHAKE_TIMEOUT`, `TCP_LISTEN_BACKLOG` |
| `python/src/hsync_rendezvous/upnp.py` | Facade over the SSRF-hardened `hsync_common.upnp` SSOT (shared with `hsync-client`): adds the async `UpnpManager`; stateless when no IGD. Opt-in (`--upnp`), one manager per bound port so every `--ports` door is also mapped; the mapping carries a finite lease (2x the refresh window) and is removed on graceful shutdown | `UpnpManager.run`, `UpnpManager.close`, `add_port_mapping`, `discover_igd` |
| `python/src/hsync_rendezvous/diagnostics.py` | Two stderr channels: **always-on `warn`/`error`** node health (peer-free by construction, field allow-list, error dedup with `suppressed=<n>`) and the opt-in **full operation log** (decisions #25, #35, #36); never on disk (no-log invariant); line format `<ISO-8601 UTC Z> - hsync-rendezvous[<pid>] <level>: …` | `configure_debug`, `debug_enabled` (cheap predicate hot paths use to skip building `debug_event` fields when the opt-in sink is off), `debug_log`, `debug_event`, `warn_event`, `error_event`, `_emit`, `_sanitize`, `_PUBLIC_FIELDS` |
| `python/src/hsync_rendezvous/cli.py` | Typer multi-command app; group keys from `--keys-fd` / `HSYNC_RENDEZVOUS_KEYS_FD` or `--keys-file` / `HSYNC_RENDEZVOUS_KEYS_FILE` (read once, size- and time-bounded; duplicate buckets refused — decisions 54/59/61); near-expiry and mismatch hints name the configured identity; fail-fast config; `--ttl`/`--debug`/`--ready-file` seams; `--identity`/`--public-host` + `identity show`/`rotate`; process lifecycle: SIGINT/SIGTERM take the graceful path, SIGHUP is ignored, sd_notify READY/STATUS/WATCHDOG/STOPPING (decisions 67/68); opt-in aggregate sinks: `--metrics-port`/`--metrics-token-*` (loopback + Bearer), `--stats-file`/`--stats-interval` (Prometheus text file), shared with the handler and the guard (decisions 71/72); binding and lifecycle helpers live in `binding.py`/`lifecycle.py` | `run`, `identity_show`, `identity_rotate`, `main` (`--version`), `_resolve_secret`, `_load_keys`, `_read_token`, `_parse_keys`, `_read_fd`, `_fd_readable_before`, `_near_expiry_reason`, `_async_main`, `_install_shutdown_handlers` |
| `python/src/hsync_rendezvous/binding.py` | Listener bind errors, the actionability messages for exit codes 3/4, and the shared best-effort bind step for the UDP and TCP transports | `BindError`, `ReadyFileError`, `bind_transport`, `bind_error`, `bind_error_message`, `ready_file_error_message`, `warn_bind_failures` |
| `python/src/hsync_rendezvous/lifecycle.py` | Periodic duties of a running node: TTL prune, service-manager watchdog, readiness PID file, and STATUS/text-file metric publication | `prune_loop`, `watchdog_loop`, `write_ready_file`, `remove_ready_file`, `write_stats_file`, `stats_loop` |
| `python/src/hsync_rendezvous/systemd.py` | `sd_notify` sender for the service manager: READY=1 (every requested listener bound), WATCHDOG=1 (fed at half `$WATCHDOG_USEC`), STOPPING=1 (teardown start); honours `$NOTIFY_SOCKET` including the `@` abstract namespace and refuses a ping addressed to another `$WATCHDOG_PID`; inert and exception-free outside systemd (container without systemd, launchd, Windows, foreground) | `notify_ready`, `notify_stopping`, `notify_watchdog`, `watchdog_interval`, `_send` |
| `python/src/hsync_rendezvous/stats.py` | Peer-free aggregate counters (RAM only, O(1)): connection and registered-peer levels, event-exact peaks with their wall-clock stamp, lifetime counters, relay session/byte aggregates, the closed metrics-outcome list and the refusal side of the protocol — refusals by `RdvError` reason, rate-limit refusals by the budget that ran dry, and silent drops by reason (each label set closed); renders the Prometheus text exposition with a fixed cardinality and no label that could identify a peer (decisions 71, 79); the reference for the numbers is `docs/metrics.md` | `NodeStats`, `METRICS_OUTCOMES`, `REFUSAL_REASONS`, `LIMITERS`, `DROP_REASONS`, `NodeStats.refusal`/`limit_hit`/`drop`/`refusals_total`, `NodeStats.render_prometheus`, `NodeStats.status_text` |
| `python/src/hsync_rendezvous/relay.py` | Data-relay pairing and byte pump (ADR-0047): `RelayRegistry` holds the listener control streams, pairs a requester with the listener of its `target_cid`, and bridges the two streams symmetrically (fixed `RELAY_BUFFER_BYTES` + `drain()` both ways, idle timeout per direction, per-session byte ceiling, `await`-based aggregate bandwidth shaper, attach timeout, host-derived session ceilings); RAM only, aggregate counters only (`--no-relay` makes the node discovery-only) | `RelayRegistry`, `RELAY_BUFFER_BYTES`, `RELAY_ATTACH_TIMEOUT_S`, `RelayRegistry.run`, `RelayRegistry.close` |
| `python/src/hsync_rendezvous/relay_state.py` | Registry state types: session quotas, the handler's handoff value, listener/pending records, and the prefix-replaying reader used when the handshake line and the first opaque bytes arrive together | `RelayQuotas`, `RelayHandoff`, `Listener`, `Pending`, `PrefixedReader` |
| `python/src/hsync_rendezvous/relay_wire.py` | Serialization of the relay control frames (`relay_listening`/`relay_incoming`/`relay_ok`/`relay_error`), the ping check, and stream close/refuse | `listening_frame`, `incoming_frame`, `ok_frame`, `error_frame`, `is_ping`, `refuse`, `close_writer` |
| `python/src/hsync_rendezvous/metrics.py` | Loopback-only, bearer-authenticated `/metrics`: a rigid HTTP/1.1 responder (one request per connection, 8 KiB header cap, 5 s read timeout, `GET`/`HEAD` only, no body, no keep-alive), constant-time token check with a uniform 401, a token bucket and a concurrency cap; stdlib only, because the project lock cannot gain a runtime dependency (decision 72) | `MetricsEndpoint`, `MetricsServer` (`start`, `aclose`), `PROMETHEUS_CONTENT_TYPE` |
| `python/fuzz/fuzz_boot.py` | Deterministic stdlib fuzz harness (decoder + SSDP/token validators; security invariants, not just crash-freedom; CI burst in `python/tests/test_fuzz_harness.py`) | `run_fuzz`, `Finding`, targets `handle`/`ssdp`/`token` |
| `python/fuzz/fuzz_guided.py` | Coverage-guided driver on the same generators/invariants: per-iteration branch-arc signatures via `coverage.Coverage` (branch=True), evolving FIFO-capped corpus (cap 512), deterministic seeds, corpus persistence (`--corpus-out/--corpus-in`); ~140 it/s (tracing) vs ~20 000 it/s static | `run_guided`, `_ArcMeter.arcs`, `_guided_frame` |

## Request flow (per datagram/stream frame)

1. `session.py` (`serve_rdv_session`) reads one newline-terminated frame (≤ 8 KiB, checked on the frame
   length itself so an oversized frame always closes the stream); a frame longer
   than 8 KiB closes the session silently (no-log).
2. `RendezvousHandler.handle` (`python/src/hsync_rendezvous/handler.py::RendezvousHandler.handle`) first consults
   the malformed-frame budget: an IP that has exhausted it is dropped before the
   parser runs, so a parse flood costs no event-loop CPU. Otherwise the raw frame
   is validated in a single pass via the `RdvFrame` discriminated union
   (`RDV_FRAME_ADAPTER.validate_json`). `ValidationError` → silent drop
   (no-log, no oracle); it charges only the malformed-frame budget, never the
   valid-frame admission, so a garbage sender cannot throttle valid neighbours
   behind a shared NAT IP. Only a *valid* frame then charges the generic per-IP
   admission (`OP_IP_*`).
3. Type-specific limits (every limiter keyed by source IP): register/refresh
   per (IP, bucket); query per (IP, bucket) plus an aggregate per IP across
   buckets (anti-enumeration); relay connect/listen per (IP, bucket). The budgets
   and the rules they are derived from live in `protocol-spec/rdv-1.md` §Auth and
   `handler.py` (`QUERY_*`, `REGISTER_PAIR_*`, `RELAY_*`); the routing table and
   the limiter maps are bounded by `ResourceLimits` (host RAM/CPU), so
   per-IP/bucket churn cannot grow them without limit.
4. Protected-bucket check: if the bucket is gated — declared `--protected-bucket` on an open node,
   or *any* bucket on a private node — a constant-time compare decides, running
   on the same 64-byte shapes whether or not the bucket has a key (no timing
   side-channel on the provisioned set); failures are rate-limited after the
   per-IP failed-token budget and answered uniformly with `token_required` /
   `rate_limited` (+ `retry_after`).
5. Mutation: `register` upserts (STUN-echo source `ip:port`) and copies the
   advisory fields onto the record (`capacity`, `reachable`, and the election
   advertisement `server_ready`/`prefer_master`/`never_master`/`inbound`/`startup_time`/
   `sync_direction` — decision 31); `refresh` touches TTL only and never creates
   or mutates them. `register`, `refresh` and `leave` all enforce **record
   ownership**: a source other than the record's observed IP is silently refused
   unless the frame was token-authorized on a private/protected bucket, so a
   learned `(cid, bucket, group)` cannot hijack, keep alive, or evict another
   peer's record. Creating a record above the host-derived table ceiling, or
   above the per-`(bucket, group)` ceiling that keeps one sample from being
   saturated, is refused with `overloaded` (capacity backpressure), never by growing RAM.
6. Reply: `ack` (register/refresh, carries `observed_endpoint`) or `response`
   (query, random sample up to `limit`, at most `MAX_RELAY_ENDPOINTS` advertised
   endpoints per peer within a `MAX_RESPONSE_BYTES` frame budget, every advisory
   field relayed verbatim); returned
   as already-serialized JSON **bytes** (Pydantic `TypeAdapter.dump_json`),
   written verbatim by the transport.

## Security model

- **No-log**: nothing peer-related is written to disk; the node's TLS identity
  (the operator's own key+cert, ADR-0034/ADR-0037 — not peer data) is kept by
  default as a stable, pin-able, rotatable identity, and `--ephemeral` keeps it
  in memory instead. A persisted identity is written atomically through a unique
  temp file (a crash cannot wedge the next start) and is loaded only when its
  private key matches its certificate (decision 54). Verified by
  `python/tests/test_nolog.py` under a read-only filesystem.
- **Anti-amplification**: QUIC RETRY + address-validation before connection
  state (`start_server(..., retry=True)`, `python/src/hsync_rendezvous/server.py`),
  and a node-side **transport guard** (`ConnectionGuard`,
  `python/src/hsync_rendezvous/guard.py`): a per-IP handshake budget
  (`limits.HANDSHAKE_RATE_PER_SECOND` / `HANDSHAKE_BURST_PER_IP` — the sustained
  rate is the per-source CPU bound, the burst absorbs a whole NAT umbrella's cold
  start), a per-IP cap and a process-wide cap on simultaneously-open
  connections, all sized by `ResourceLimits` from host RAM/CPU, checked in
  `RendezvousQuicProtocol.datagram_received` before any handshake work; released on
  `ConnectionTerminated`, lazily forgetting quiet/empty IPs. QUIC receive windows
  are bounded (≤32 KiB per stream, ≤1 MiB per connection: the connection window
  spans every concurrent relay stream, so it must cover their sum). The guard shares
  the rate-limit seam (`--no-rate-limit`) so benchmarks stay unthrottled.
- **Malformed-frame budget**: invalid/unknown frames charge a separate per-IP
  budget (`handler.py` `PARSE_IP_*`, `_bad_parse_ip`), and once an IP exhausts
  it that IP's frames are dropped **before** validation — so a parse storm costs
  no validation CPU — without adding any oracle (the drop stays silent) and
  without draining a NAT neighbour's valid-frame admission.
- **Frame-domain tightness**: `bucket_token` must be 64 lowercase hex chars
  (`BucketToken` annotation, `protocol.py`) and `connected` is bounded to
  `0..2^53` (`CONNECTED_MAX`), so a token that cannot be a derivable HMAC output
  or an absurd counter is an invalid frame, not a per-IP accounting event.
- **Protected buckets**: the group key never enters any record; only the derived token.
  Protected buckets are declared by the operator (`--protected-bucket`,
  repeatable) and fail fast at startup if declared without a key
  (`RendezvousConfigError`, exit code 2). The client derives the same token from its p2p
  shared key (raw `HSYNC_P2P_KEY`, or `HSYNC_P2P_PASSPHRASE` derived to it →
  `derive_bucket_token`), so one client key
  authenticates to any bucket whose group key equals it; the user-facing model is
  `docs/usage.md` ("Privacy and anonymity model").
- **Private node** (`--private` / `HSYNC_RENDEZVOUS_PRIVATE=1`): the protected-bucket check
  applies to every bucket, `leave` included, and a node started without any
  group key fails fast (`RendezvousConfigError`, exit code 2). It is a policy on the
  same wire contract — no new frame field, no protocol bump. Operator-facing
  procedure (provisioning, rotation, trade-offs) is in `docs/usage.md`.
- **Sandboxed deployment**: hardened systemd unit
  (`packaging/systemd/hsync-rendezvous.service`: DynamicUser, protect*,
  SystemCallFilter, `Type=notify` + `WatchdogSec=` so readiness means "every
  listener bound" and a wedged event loop is restarted, plus explicit restart
  bounds and cgroup caps — decisions 68/69), launchd plist
  (`packaging/launchd/it.hsync.rendezvous.plist`), WinSW service definition
  (`packaging/windows/hsync-rendezvous-service.xml`). The `.deb` maintainer scripts
  stop the node on an upgrade without touching the administrator's enablement and
  start it again only when it was enabled (decision 70).
- **Observability**: peer-free aggregates (`stats.py`) reach the operator only
  through the service manager's `STATUS=`, an optional atomically replaced
  Prometheus text file and an optional loopback `/metrics` endpoint that requires
  a bearer token from a systemd credential (decisions 71/72); the always-on
  stderr channel stays peer-free by construction. Besides levels/peaks and the
  relay aggregates, the exposition carries the refusal side of the protocol:
  `hsync_rendezvous_refusals_total{reason}` (what a client sees),
  `hsync_rendezvous_limit_hits_total{limiter}` (which budget clipped it) and
  `hsync_rendezvous_drops_total{reason}` (silent drops), so a limit clipping
  legitimate traffic is distinguishable from abuse. The user-facing reference is
  `docs/metrics.md`.

## Target matrix

| Target | Deployment unit | Status |
|---|---|---|
| Linux | `packaging/systemd/hsync-rendezvous.service` | v1 |
| macOS | `packaging/launchd/it.hsync.rendezvous.plist` | v1 |
| Windows | `packaging/windows/hsync-rendezvous-service.xml` (WinSW) | v1 |
| Windows installer (x64) | `packaging/windows/hsync-rendezvous.iss` (Inno Setup, built in CI) + `hsync-rendezvous-service-frozen.xml`; per-machine, registers the WinSW service | v1 |
| Linux `.deb` (amd64/arm64/armhf) | `../compile.sh -t deb`/`deb-all` (`-l/--language`, default `python`; `c` rejected until that port exists) + `packaging/deb/` (control, maintainer scripts, deb unit, man page) | v1 |
| Linux `.rpm` (x86_64/aarch64) | `../compile.sh -t rpm`/`rpm-all` + `packaging/rpm/` (`.spec`, Rocky Linux 9 builder); `python/compile.sh -t onedir` payload staged for `/usr/lib/hsync-rendezvous` | v1 |
| Raspberry Pi OS (armhf/arm64) | `../compile.sh -t rpi` (Docker + qemu, reuses `packaging/deb/Dockerfile.builder`) → `dist/rpi/<arch>/hsync-rendezvous` | v1 |

## Packaging

- `python/compile.sh` builds binaries only (`native` host standalone into
  `-o/--output-dir`, `onedir` bundle consumed by the root entry point).
  `python/dist/` and `python/build/` are git-ignored build outputs.
- `../compile.sh -t native` wraps `python/compile.sh -t native` and places the
  host executable at `dist/<os>-<arch>/hsync-rendezvous`.
- `../compile.sh -t rpi` cross-builds the onefile executable for Raspberry Pi
  OS 32-bit (armhf/armv7) and 64-bit (arm64/aarch64) inside an emulated
  debian:bookworm container, reusing `packaging/deb/Dockerfile.builder`; output
  `dist/rpi/<arch>/hsync-rendezvous`. PyInstaller's `build/` and `*.spec`
  intermediates are redirected to `/tmp/work` (via `HSYNC_PYINSTALLER_WORKPATH`)
  so nothing is written into the mounted host tree.
- `../compile.sh -t deb` embeds the selected language's payload
  (today `python/compile.sh -t onedir`) as `/usr/lib/hsync-rendezvous/` with a
  `/usr/bin/hsync-rendezvous` symlink, the hardened deb systemd unit, and the
  gzipped man page; `DEBIAN/postinst` creates `/etc/hsync-rendezvous/` (0750)
  for the out-of-package group-keys file and never enables the service.
- `../compile.sh -t rpm` builds a `.rpm` from a staged buildroot
  (`_stage_rpm_buildroot`) reusing the deb man page + unit, and runs `rpmbuild`
  with an absolute `_topdir` and a writable `_dbpath` (a relative `_topdir`
  breaks `%{buildroot}`, and non-root rpmbuild cannot open `/var/lib/rpm`).
  `packaging/rpm/Dockerfile.builder` (Rocky Linux 9) provides the cross-build;
  the spec uses `DynamicUser` (no system user) and creates `/etc/hsync-rendezvous`
  (0750) in `%post`.
- The Windows installer (`packaging/windows/hsync-rendezvous.iss`, built in CI on
  `windows-latest`) is per-machine: it installs the frozen `.exe` + WinSW (as
  `hsync-rendezvous-service.exe`) + `hsync-rendezvous-service-frozen.xml`, grants
  LocalService modify on `%ProgramData%\hsync-rendezvous`, then installs and starts
  the service. Uninstall stops and removes it.
- The release workflow (`../.github/workflows/release.yml`) also publishes
  fixed-name `latest` aliases (e.g. `hsync-rendezvous-x86_64.rpm`,
  `hsync-rendezvous-amd64.deb`, `hsync-rendezvous-windows-amd64-setup.exe`) so the
  docs can link `releases/latest/download/<name>` without a version
  (`RELEASES.md` §5.8); guarded by `python/tests/test_compile_script.py`.
- **Binary portability floor**: `native` and `deb` build on the host, so their
  executable embeds the build machine's CPython + glibc (incompatible with any
  machine carrying an older glibc); `deb-all`/`rpi` build inside
  `python:3.14.9-bookworm` (glibc 2.36) and `rpm-all` inside `rockylinux:9`
  (glibc 2.34), so those are the portable artifacts — the produced amd64
  bundle embeds CPython 3.14.9 (`libpython3.14.so.1.0`, `libgcc_s.so.1`); the
  3.12 bundles measured a `libc6 (>= 2.35)` floor, so re-measure it with
  `dpkg-shlibdeps` when rebuilding the 3.14.9 packages. `BASE_IMAGE` is a
  Dockerfile `ARG` only — no CLI flag selects an older base. The `.deb`'s
  `Depends: libc6` covers the launcher only, never the bundled Python.
  Operator-facing procedure: `docs/faq.md`.
- `c/` port plugs in by extending `validate_language()`, `_build_native()`,
  `_build_onedir()`, `_container_native_cmd()` and `_container_build_cmd()` in
  `../compile.sh` (dispatch points, fail-fast contract) — never by adding
  packaging logic inside the per-language script.

### Distribution & install entry points

Four consumer-facing ways to run a node, kept identical in shape to
`hsync-server` (decisions #41):

| Method | Files | Notes |
|---|---|---|
| Installer script | `install.sh` | Resolves the latest release (or a pinned `--version`/`--image-digest`), checks every prerequisite (Docker, Compose v2, and `cosign` unless `--no-verify`) before writing anything, verifies the image's Sigstore signature, writes `.env` + a self-contained `compose.yaml` under `~/.local/share/hsync-rendezvous`, runs `docker compose up -d` and waits for the readiness PID. Docker Compose only; never `sudo`. |
| Docker / Compose | `Dockerfile`, `Dockerfile.dockerignore`, `python/entrypoint.sh`, `compose.yaml`, `docker.sh` | Build context = repo parent (needs the sibling `hsync-common`); the entrypoint opens the mounted group-keys file as fd 3; the container binds the unprivileged port 8443, the host maps `RENDEZVOUS_HOST_PORT` (default 443) for both `8443/udp` and `8443/tcp`; no new env vars. `docker.sh` builds/runs from source. |
| Debian package | `packaging/deb/` (see above) | Hardened systemd unit, `DynamicUser`, `CAP_NET_BIND_SERVICE`, group keys as a systemd credential. |
| From source | `run.sh` | Uniform clone-and-run: checks `../hsync-common`, creates `python/.venv` via Poetry, `exec hsync-rendezvous`. Mirrors `hsync-server/run.sh`. |

## Tests

| Suite | Scope |
|---|---|
| `python/tests/test_handler.py` | Routing, TTL (frozen clock), protected buckets, private policy (every bucket gated, unkeyed bucket, gated `leave`), rate limits, STUN-echo, frame rejection |
| `python/tests/test_scaffold.py` | Fixtures / spec contract + frame schema positives/negatives (rigid schema) |
| `python/tests/test_fuzz_harness.py` | Bounded deterministic fuzz burst (decoder/SSDP/token invariant targets; long runs via `python/fuzz/fuzz_boot.py --seconds N`, decision #47) + coverage-guided burst (decision #48) |
| `python/tests/test_server.py` | QUIC loopback: register/query/protected refusal, private-node refusal, garbage frames, pipelined frames on one stream, per-IP connection guard (cap + release), session-failure diagnostics (peer-free always-on line + opt-in debug detail) |
| `python/tests/test_server_tcp.py` | TLS/TCP loopback: admission before the handshake (no plaintext read), ALPN refusal, pipelined frames on one connection, relay over TCP, oversized-frame close, idle reaping, per-IP guard release |
| `python/tests/test_identity.py` | Persistent identity (default): create/load/rotate, `0600`/`0700` permissions, ECDSA P-256 only, key/cert consistency, stale-temp recovery, SAN from bind + `--public-host`, rotation preserves existing DNS/IP SANs without duplicates, 20-year validity, on-load permission hardening, rotation hint path |
| `python/tests/test_nolog.py` | Zero-write invariant under read-only fs |
| `python/tests/test_upnp.py` | SSDP/SOAP shapes, error downgrade, stateless no-IGD, LOCATION/source/redirect hardening |
| `python/tests/test_cli.py` | CLI version/fail-fast/keys contract (fd size + time bounds, fd 1/2 refused; file source, symlink/permission/cap checks) |
| `tests/` (repo root) | **Black-box** suite (language-neutral): spawns the real binary (`HSYNC_RENDEZVOUS_BIN`), speaks only `rdv/1` over QUIC and TLS/TCP, gated by `HSYNC_BB_RENDEZVOUS=1` |

### Black-box (language-neutral) tests

The root `tests/` directory holds the functional black-box suite. It is
deliberately **independent of any implementation language**: it launches the
rendezvous executable (path via `HSYNC_RENDEZVOUS_BIN`, defaulting to the Python
build) as a subprocess, waits for the `HSYNC_RENDEZVOUS_READY_FILE` readiness
seam (keyed on the ready file appearing with a PID, not on PID equality with the
launcher — a onefile-packaged binary runs the app in a child process), and
drives it **only** through the public CLI + `rdv/1` wire protocol
(QUIC/UDP and TLS/TCP, NDJSON, ALPN `hsync-rdv/1`). It never imports
`hsync_rendezvous`. The same suite will validate the future `c/`
port unchanged. Benchmarks (`bench/`) follow the same rule for L2/L3
(`bench_quic.py`, `soak.py` spawn the binary); L1 (`bench/bench_handler.py`) and
the diagnostics (L4 `bench/profile_handshake.py` — handshake vs `aioquic`
closing drain; L5 `bench/cpu_saturation.py` — load vs node CPU%) are
Python-internal.

## Known gaps / next phases

The monorepo `p2p`/rendezvous migration is **complete**:

- **Done**: `hsync-common` mirror (`protocol/rendezvous.py`, fixtures, drift test,
  capabilities v3); the advisory `capacity` hint (`0..32`) and the derived
  `reachable` flag relayed `register` → record → `query` (decisions 23–24); the
  **election advertisement** (`server_ready`/`prefer_master`/`never_master`/`inbound`/
  `startup_time`/`sync_direction`) relayed the same way so a rendezvous-discovered
  peer ranks in the client's master election exactly like an mDNS-discovered one
  (decision 31); the
  rendezvous's opt-in **debug operation log** (decision 25); client `hsync p2p`
  with both rendezvous plans and its black-box suite; desktop mode, wd-os5
  packaging; the peer data-plane protocol is `p2p/1`.
- **Open**: **Android client for `rdv/1`** (deferred; the QUIC stack decision is
  still open — the Android project removed its Rust/`quiche` JNI groundwork).
  Current state: the Android project's
  [`protocol-mirror`](https://github.com/albertsdk/hsync-android/blob/main/llm-wiki/modules/protocol-mirror.md)
  page.
- **Done / open (quality)**: a deterministic stdlib **fuzz harness** covers the
  decoder and the SSDP/token validators in CI (decision #47, `python/fuzz/
  fuzz_boot.py`), and a **coverage-guided in-process driver** (decision #48,
  `python/fuzz/fuzz_guided.py` — arc feedback via `coverage.py`) evolves the
  corpus the same way AFL does, at Python-branch granularity. Still open:
  Atheris (no Python 3.14 wheel) and libFuzzer for the C port (hard
  requirement there, clang toolchain, `c/` not started).
- **Not started (v2)**: C implementation — target toolchain C11 (`clang` or
  `gcc`) with `make`; the QUIC stack is chosen with the port.
