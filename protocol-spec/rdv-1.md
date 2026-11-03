# HSYNC Rendezvous — wire protocol `rdv/1`

> Single source of truth for the rendezvous wire protocol, shared by **all** language
> implementations (`python/`, future `c/`). Do not fork this spec into
> any implementation directory.

## Transport

- QUIC/UDP, default port **443** (the shared `RDV_DEFAULT_PORT`; any UDP port is
  selectable with `--listen-port`, and a recommended reachability set
  (`RDV_PORT_SET`, 443 + 53) with `--listen-ports`). **One process, one
  in-memory routing table, one or more UDP listeners** (multi-port; no TCP
  fallback — zero legacy). Multiple listeners share the same routing table so a
  peer registered via one port is visible to a query on another; state sharding
  across processes is forbidden (it would break rendezvous).
- **Redundancy is client-side, never server-side**: the tables of two different
  nodes are independent and the protocol has no frame that copies one into the
  other. A client MAY therefore lease and query **several** independent nodes
  (one `register`/`refresh`/`query` cycle per node) and merge the samples it
  gets back; a peer seen through one node is then visible through any other the
  client can reach, while each node keeps its single RAM-only table. The union
  is client state, not protocol state: a peer registered on node A is *not*
  visible to a client that only reaches node B, and an implementation MUST NOT
  pretend otherwise (no re-publication of another peer's record, which would
  also break the source-IP ownership rule in §Auth).
- TLS 1.3 inside QUIC: the exchanged peer list is not readable by ISPs.
- ALPN `hsync-rdv/1`.
- NDJSON payloads (one JSON object per line) over bidirectional QUIC streams;
  a client may pipeline several frames back-to-back on one stream and the
  server answers each frame in order.
- **Every frame** carries the common header `{protocol_version, type, ...}`;
  the server routes on `type` and rejects anything else (rigid validator).

## Address validation

- Server requires QUIC `RETRY` + `address_validation_token` before allocating connection state (anti-amplification).
- Per-IP token bucket: ~10 req/s (burst 50). Additional per-IP and per-`(IP, bucket)` limits in §Auth.
- Connection guard: ~30 handshakes/s (burst 100) per IP, a per-IP cap and a process-wide cap on simultaneously-open connections, checked before any handshake work runs.
- QUIC receive windows are bounded (≤32 KiB per stream, ≤128 KiB per connection) so a connection cannot buffer unbounded input.
- Idle connections are dropped after 30 s.

## Trust & identity (ADR-0034)

- The node presents a **self-signed** TLS certificate (ECDSA P-256 key by
  default; RSA/Ed25519 identities remain loadable).
- **Fingerprint** = SHA-256 of the leaf certificate DER, lowercase hex; canonical
  form `sha256:<hex>`. It is the same domain as the `cert_fp` field carried in
  frames, so a client-side pin and a relayed peer `cert_fp` are directly
  comparable. `cert_fp` accepts `sha256:<hex>`, bare hex or separator-grouped
  hex, and any value that does not normalize to a full SHA-256 digest makes the
  frame invalid — a peer can never publish a fingerprint that a pin could not
  compare.
- **Publication is out-of-band**: `identity show`, the startup banner and the
  service units print the fingerprint; the operator distributes it to clients
  (it is never sent by the node on the wire, so it cannot be learned from the
  protocol itself).
- **Verify before frame (client obligation)**: a client MUST establish the
  certificate fingerprint — via an explicit `--rendezvous-fingerprint` pin, the
  opt-in `--rendezvous-tofu` store, or an SSH-style confirmation prompt (the
  client-side default) — **before** writing any frame. The
  `bucket_token` travels inside `register`/`query`, so trust is decided pre-write;
  a mismatch closes the connection with zero application bytes sent.
- **Identity persists by default**: the node keeps a self-signed ECDSA P-256
  key+cert (created on first run, reused afterwards) so the fingerprint is stable
  across restarts and rotatable with `identity rotate`; `run --ephemeral` keeps
  the identity in memory instead (no identity file is written). The key+cert is
  the node's only on-disk artifact — never peer data (the no-log invariant is
  unchanged).
- **Rotation**: a client accepts up to two pins (old + new) during the rotation
  window; the trust store records whichever matched. `identity rotate` keeps the
  existing DNS/IP SANs, adds any `--public-host` names, and prints the new
  fingerprint.
- No wire change: `protocol_version` stays `rdv/1` — trust is a transport-layer
  concern layered on the unchanged frame contract.

## Frames (client → server on one stream)

| Frame | Payload |
|---|---|
| `register` | `{protocol_version:"rdv/1", type:"register", cid, bucket, group?, bucket_token?, cert_fp, version, capacity?, endpoints?:[{proto:"tcp"\|"udp", host, port}], connected?, server_ready?, prefer_master?, never_master?, inbound?, startup_time?, sync_direction?}` |
| `refresh` | `{protocol_version:"rdv/1", type:"refresh", cid, bucket, group?, bucket_token?, connected?}` |
| `leave` | `{protocol_version:"rdv/1", type:"leave", cid, bucket, bucket_token?}` |
| `query` | `{protocol_version:"rdv/1", type:"query", bucket, group?, bucket_token?, limit?}` |
| `relay_listen` | `{protocol_version:"rdv/1", type:"relay_listen", cid, bucket, group?, bucket_token?}` (§Data relay) |
| `relay_ping` | `{protocol_version:"rdv/1", type:"relay_ping", cid, bucket}` (§Data relay) |
| `relay_connect` | `{protocol_version:"rdv/1", type:"relay_connect", cid, bucket, target_cid, group?, bucket_token?}` (§Data relay) |
| `relay_attach` | `{protocol_version:"rdv/1", type:"relay_attach", cid, bucket, relay_id, bucket_token?}` (§Data relay) |

## Frames (server → client)

| Frame | Payload |
|---|---|
| `ack` | `{protocol_version:"rdv/1", type:"ack", observed_endpoint:{proto:"udp", ip, port}, ttl, server_time, retry_after?}` (STUN-echo) |
| `response` | `{protocol_version:"rdv/1", type:"response", peers:[{cid, endpoints:[{proto:"tcp"\|"udp", host, port}], cert_fp, bucket, group?, version, capacity, connected, reachable, server_ready, prefer_master, never_master, inbound, startup_time, sync_direction}], count, ttl}` or `{peers: [], count: 0, error:"token_required"\|"rate_limited"\|"overloaded", retry_after?}` |
| `relay_listening` | `{protocol_version:"rdv/1", type:"relay_listening", ttl}` (§Data relay) |
| `relay_incoming` | `{protocol_version:"rdv/1", type:"relay_incoming", relay_id, cid, expires_in}` (§Data relay) |
| `relay_ok` | `{protocol_version:"rdv/1", type:"relay_ok", relay_id}` (§Data relay) |
| `relay_error` | `{protocol_version:"rdv/1", type:"relay_error", error:"token_required"\|"rate_limited"\|"overloaded"\|"relay_unavailable", retry_after?}` (§Data relay) |

## Data relay

Two peers that no inbound NAT mapping reaches (carrier-grade NAT, a hotspot
behind a carrier, a guest network) can still run the `p2p/1` data plane: the node
pairs them and forwards their bytes, which stay **opaque TLS** end to end. The
node never terminates or inspects that TLS, so content, file names and
credentials remain invisible to it, and the peers keep authenticating each other
by certificate pinning. What the node necessarily observes is the pairing
(`cid` ↔ `cid`) and the volume.

- **On by default**: every node accepts relay frames. Start one with `--no-relay`
  to make it discovery-only: every relay frame is then answered
  `relay_error{error:"relay_unavailable"}` (uniform, like every other refusal) and
  no relay state is ever created.
- **Listener** (the peer that serves — the p2p master): opens one stream, sends
  `relay_listen`, receives `relay_listening`. That stream is the **control**
  stream of the registration: the node pushes one `relay_incoming` per requester,
  and the peer answers with `relay_ping` lines (no reply) to keep the QUIC
  connection alive while no session runs. A second `relay_listen` for the same
  `(cid, bucket)` from the same content replaces the previous control stream.
- **Requester**: opens a **fresh** stream and sends `relay_connect` with the
  `target_cid` it wants to reach. The node answers `relay_ok{relay_id}` on that
  same stream; from that byte on the stream is opaque in both directions. A
  refusal is `relay_error` followed by a close.
- **Attach**: for each `relay_incoming`, the listener opens a **fresh** stream
  whose first line is `relay_attach{relay_id}`; every following byte is opaque.
  The node bridges the two streams with a fixed 64 KiB buffer and `drain()` on
  both sides (backpressure reaches the real sender).
- **Authorization**: `relay_listen` is accepted only from the current owner of the
  `(cid, bucket, group)` record (the same source-IP-or-token rule `register`
  uses), so a peer cannot open a relay in another peer's name; `relay_connect`,
  `relay_attach` and `relay_listen` all carry the optional `bucket_token` and are
  refused uniformly (`token_required`) on protected/private buckets;
  `relay_attach` must also match the `relay_id`, the listener `cid`/`bucket` and
  the listener's source IP, and an unknown `relay_id` attaches to nothing.
- **Bounds**: `relay_id` is 16 random bytes (32 lowercase hex). A session the
  listener does not attach within `expires_in` is dropped. Sessions are capped
  globally, per source IP and per bucket (host-derived, answered with
  `overloaded`), throttled to an operator-set aggregate byte rate and closed at
  an optional per-session byte ceiling; an idle session (no bytes either way for
  the configured idle timeout) is closed. `relay_connect` is rate-limited per
  `(IP, bucket)` like `query`, `relay_listen` like `register`.
- **Stream budget**: a listener connection holds its control stream plus one
  stream per relayed session; the per-connection stream cap therefore covers
  `MAX_SESSIONS_PER_CONNECTION + MAX_RELAY_STREAMS_PER_CONNECTION`.
- **No-log unchanged**: relay counters are aggregates only (sessions, bytes); no
  CID, bucket, IP or port is written anywhere, and an idle control stream is the
  only thing a listener keeps open.

## Rules

- **No targeted requests**: schema rejects unknown fields (`extra="forbid"`); there is no field for a file path/hash. Agnostic by construction.
- `type` is mandatory: the frame kind is declared, never guessed from the payload.
- **CID**: `^[A-Za-z0-9]{21}$` full-match.
- **Bucket name**: the canonical HSYNC bucket name shared by client, server and
  desktop (`hsync-common` SSOT, `hsync_common.path_validation.is_valid_bucket_name`):
  1–63 characters, alphanumeric with `-` and `_` allowed only in the middle
  (never leading or trailing). It is the same sync bucket the data plane uses,
  so a value outside that rule makes the frame invalid and it is silently
  dropped — the daemon and the client mirror enforce one identical domain.
- **Anonymous `query`**: on an open node anyone with bucket (+group) can list peers; privacy via optional `bucket_token`. On a private node every query must carry a valid token (see §Auth).
- **No-log**: no timestamps/IPs written to disk anywhere in this path.
- Malformed, unknown-`type` or oversized frames are silently dropped (no oracle, no log). An IP that exhausts its malformed-frame budget is dropped before the parser runs, so a parse flood costs no event-loop CPU.
- `refresh` never creates a record: an unknown CID is dropped so the client falls back to `register`.
- **`capacity` (advisory service-capacity hint)**: integer `0..32`, default `0`, carried on `register` and echoed in every `query` peer. It is the number of concurrent peer-download reads the peer declares it can serve right now (`0` = not a seeder). The rendezvous copies it onto the record and relays it, but it is **not authenticated** and **not authoritative**: the authoritative value is `serve_slots` on the authenticated data-plane handshake (ADR 0030). The requester may use it only to pre-size concurrency and to skip `capacity=0` peers — never to exclude a live seeder. The rendezvous must **not** order the sample by `capacity` (the sample stays random, so a self-declared value cannot buy priority). `refresh` does not carry `capacity` and never mutates it; a changed value requires a new `register`.
- **`reachable`**: derived from `bool(endpoints)` at `register` time — `true` iff the peer advertised at least one listen endpoint (it can act as a data-plane master). A register that carries no endpoint (e.g. the first STUN register, before the public TCP endpoint is known) is advertised with `reachable=false` and a single-element `endpoints` list carrying the observed UDP source; a requester must not treat it as a master. `refresh` never changes `reachable`.
- **`endpoints` (candidate list)**: the `query` response relays the peer's first **four** declared `endpoints[]`, in order (advisory, unauthenticated). When the peer advertised none, the node relays the single observed source endpoint instead. Each `host` must be a **dialable host** — an IPv4/IPv6 literal or a DNS name, with no control characters, path separators, empty or over-long labels — and a value outside that grammar makes the frame invalid (the same predicate in the daemon and the client mirror). The requester must try the candidates (preferring a host/LAN candidate reachable from its own network) and fall back to the next on failure, so peers behind the same NAT — where the public endpoint is unreachable (no NAT hairpinning) — still connect over the local path. The advertised order is the peer's preference for external reachability; the requester's own-network priority is a client-side policy.
- **`connected` (advisory connected count)**: a non-negative integer `0..2^53` (like `startup_time`, inside the exactly-representable integer range of a JSON number) carried on `register` and `refresh` and echoed verbatim on every `query` peer (so peers can display group presence without a data-plane round-trip); `refresh` may update it (the only advisory value `refresh` is allowed to change). The node never interprets it.
- **Election advertisement (`server_ready`, `prefer_master`, `never_master`, `inbound`, `startup_time`, `sync_direction`)**: the same values the client's mDNS TXT record carries (SSOT: `hsync-common` `protocol.p2p` / `protocol.pairing`), relayed verbatim from `register` onto the record and echoed on **every** `query` peer. Defaults when a peer advertises none: `false`, `false`, `false`, `false`, `0.0` (unknown) and `bidirectional`. They let a rendezvous-discovered peer take part in the client's master election exactly like an mDNS-discovered one: `server_ready` marks the serving incumbent (which outranks a newcomer, even a `prefer_master` one), `prefer_master`/`never_master` are the operator election inputs (`never_master` nodes are not electable), `inbound` marks a node with a confirmed externally dialable endpoint (it serves without the relay and outranks a relay-only node), `startup_time` is the earliest-startup tiebreaker and `sync_direction` expresses the bidirectional preference. The node never interprets them, never orders the sample by them, and they are **not authenticated**: a peer may claim any value, and the data plane authenticates its identity by certificate pinning. Like `capacity`, a changed value requires a new `register` — `refresh` never mutates them.

## Auth — bucket tokens: protected buckets and private nodes

- `bucket_token = HMAC-SHA256(group_key, "rdv/1" || bucket)[:32]` hex (64 characters), optional on register/refresh/query/leave. The client's group key is the raw `HSYNC_P2P_KEY`, or the 64-hex key derived from `HSYNC_P2P_PASSPHRASE`; the node always consumes the raw key. The wire grammar is enforced by the frame models in **every** implementation: a value that is not exactly 64 lowercase hex characters makes the frame invalid (silently dropped, budgeted by the malformed-frame limit below) — never a failed-token attempt.
- **Group-key strength**: the key is the token's only entropy, so the node's key source enforces at least 32 characters (`MIN_GROUP_KEY_CHARS`). A client may instead supply `HSYNC_P2P_PASSPHRASE` (at least 12 characters), which it derives to the same 64-hex key; the node always consumes the derived key. A shorter key is a configuration error (exit code 2), never a weaker deployment.
- Server-side: operator declares protected buckets (`--protected-bucket`); token compared in constant time (`hmac.compare_digest` Python).
- Matrix: protected bucket + missing/wrong token → `peers: []`, `error:"token_required"` (uniform — no bucket-existence oracle); correct token → full random `K` sample (default 20, `limit` 1..50). Open bucket: no token needed.
- **Private node** (`--private` / `HSYNC_RENDEZVOUS_PRIVATE=1`): the protected-bucket check applies to *every* bucket, not only the declared protected set. A bucket with no key loaded is refused exactly like a wrong token (same `token_required` answer, same failed-token budget), so the set of provisioned buckets is not observable either. `leave` is gated in this mode too — an anonymous `leave` would let anyone who knows a `(cid, bucket)` pair spoof a departure; `leave` has no response frame, so a refusal is a silent drop. Startup fails fast (exit code 2) when `--private` is set with zero group keys. The wire format is unchanged: this is a server-side policy.
- **Record ownership (open nodes)**: creating, replacing or renewing a `(cid, bucket, group)` record is honoured only from the source network the record was registered from — the observed source IP (the peer itself or its NAT umbrella) — or, on a protected/private bucket, with a valid token from any source. A `register`, `refresh` or `leave` from any other source is silently dropped: a peer that learns another peer's `(cid, bucket, group)` (e.g. from an anonymous `query`) cannot point that rendezvous record at different endpoints, keep a hijacked record alive through the victim's own refresh, or evict it. **Ownership follows liveness**: a record past its TTL is absent for every decision, so a source-IP change (or a node that went away) frees the key for re-registration at the TTL boundary, and a `refresh` never revives an expired record — the peer registers again. On protected/private buckets the token authenticates bucket membership (not a specific CID), so a token holder may replace a record from any source; the private/protected token path also removes every `(cid, bucket)` record on `leave`.
- **Refusal error domain**: a refusal is a `response` with `peers: []`, `count: 0` carrying exactly one of `token_required` (authorization — never reveals whether a bucket exists), `rate_limited` (per-IP or per-`(IP, bucket)` limit; `retry_after` is the seconds until that limiter refills) or `overloaded` (the node is at its host-derived capacity ceiling; `retry_after` is advisory backpressure, not a client abuse signal). An `error` value outside that set is invalid. Implementations must accept all three so a node's capacity answer is never misread as a contract violation.
- Rate limits (in-memory sliding windows), every limiter keyed by source IP so one source cannot exhaust another's budget: `query` 5/min per `(IP, bucket)` (burst 10) plus an aggregate 20/min per IP across every bucket (burst 40, anti-enumeration); `register`/`refresh` 10/min per `(IP, bucket)` (burst 10); failed-token attempts ~5/min per IP. On limit: respond `{error:"rate_limited", retry_after:<s>}` — never silently drop. A silent malformed/unknown-frame budget (~30/min per IP, burst 60) gates the parser: once an IP exhausts it, its frames are dropped before validation, so a parse flood costs no event-loop CPU. Every limiter's tracked-key population is capped from the host resources, so per-IP/bucket churn cannot grow it without bound.
- **Bounded state**: the routing table and the rate-limiter maps have host-derived ceilings (from available RAM and CPU count, with conservative floors). The routing table is bounded globally, per **bucket** and per `(bucket, group)`: `group` is registrant-chosen, so the per-bucket ceiling is the one that cannot be rotated around, and one bucket can never be filled to the global ceiling or dominate its random sample. A `register` that would exceed any ceiling is refused with `{error:"overloaded", retry_after:<s>}` after a reclamation sweep, never by growing RAM without limit. `overloaded` is **node capacity**, not a client rate limit: a requester should treat it as transient backpressure (retry, or prefer another rendezvous), and it must not be counted against the source as abuse. `retry_after` is advisory.
- **Bounded response**: a `response` relays at most four `endpoints` per peer and the relayed peers stay within a 32 KiB frame budget (the peer count is reduced when the budget is exhausted; `count` always reports what was actually relayed). A registrant controls its own endpoint data, so the sample size alone is not a bound on what one query makes the node emit.

## In-memory routing table

- Key `(cid, bucket, group)` → `{ip_src, udp_port, cert_fp, version, protocol, endpoints[], connected, reachable, capacity, expires_at}`.
- TTL 60 s; client refresh every 30 s; prune every 15 s; response = random `K` sample.
- Responses relay the peer's first four declared `endpoints[]` (fallback: a single-element list with the observed source endpoint), within a 32 KiB frame budget.
- RAM-only, bounded globally, per bucket and per `(bucket, group)` by host-derived ceilings (no disk persistence, no unbounded growth).