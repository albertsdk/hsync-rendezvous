# Data models — `rdv/1` frames

The `rdv/1` wire contract is defined once in `protocol-spec/rdv-1.md` and mirrored
by typed models in every implementation. The Python v1 models live in
`python/src/hsync_rendezvous/protocol.py` (pydantic v2, all with `extra="forbid"` so
any unknown/targeted field makes the frame invalid — rigid schema). The future C
tree mirrors the same frames with `struct`s/`enum`s and an explicit
unknown-field rejection; do not fork the shapes here.

## Common header

Every frame carries `{protocol_version, type, ...}`. `_RdvFrame`
(`python/src/hsync_rendezvous/protocol.py::_RdvFrame`) is the shared base: mandatory `type`
discriminator plus `protocol_version` pinned to `rdv/1`
(`PROTOCOL_VERSION_RDV`, `hsync-common/hsync_common/protocol/rendezvous.py::PROTOCOL_VERSION_RDV`). The server routes on `type` and never
guesses the frame kind from the payload shape.

## Frame inventory

| Frame | Direction | Model | Fields (beyond the header) |
|---|---|---|---|
| `register` | client → server | `RdvRegister` (`python/src/hsync_rendezvous/protocol.py::RdvRegister`) | `cid`, `bucket`, `group?`, `bucket_token?`, `cert_fp`, `version`, `capacity`, `endpoints[]`, `connected?`, `server_ready?`, `prefer_master?`, `never_master?`, `inbound?`, `startup_time?`, `sync_direction?` |
| `refresh` | client → server | `RdvRefresh` (`python/src/hsync_rendezvous/protocol.py::RdvRefresh`) | `cid`, `bucket`, `group?`, `bucket_token?`, `connected?` |
| `leave` | client → server | `RdvLeave` (`python/src/hsync_rendezvous/protocol.py::RdvLeave`) | `cid`, `bucket`, `bucket_token?` |
| `query` | client → server | `RdvQuery` (`python/src/hsync_rendezvous/protocol.py::RdvQuery`) | `bucket`, `group?`, `bucket_token?`, `limit` (1–50, default 20) |
| `ack` | server → client | `RdvAck` (`python/src/hsync_rendezvous/protocol.py::RdvAck`) | `observed_endpoint`, `ttl`, `server_time`, `retry_after?` |
| `response` | server → client | hand-assembled by `handler._response`; parity oracle `RdvResponse` in `python/tests/rdv_response.py` | `peers[]`, `count`, `ttl`, `error?` (`token_required`/`rate_limited`/`overloaded`/`relay_unavailable`), `retry_after?` |
| `relay_listen` | client → server | `RdvRelayListen` (`python/src/hsync_rendezvous/protocol.py::RdvRelayListen`) | `cid`, `bucket`, `group?`, `bucket_token?` |
| `relay_ping` | client → server | `RdvRelayPing` (`python/src/hsync_rendezvous/protocol.py::RdvRelayPing`) | `cid`, `bucket` |
| `relay_connect` | client → server | `RdvRelayConnect` (`python/src/hsync_rendezvous/protocol.py::RdvRelayConnect`) | `cid`, `bucket`, `target_cid`, `group?`, `bucket_token?` |
| `relay_attach` | client → server | `RdvRelayAttach` (`python/src/hsync_rendezvous/protocol.py::RdvRelayAttach`) | `cid`, `bucket`, `relay_id`, `bucket_token?` |
| `relay_listening` | server → client | `RdvRelayListening` (`python/src/hsync_rendezvous/protocol.py::RdvRelayListening`) | `ttl` |
| `relay_incoming` | server → client | `RdvRelayIncoming` (`python/src/hsync_rendezvous/protocol.py::RdvRelayIncoming`) | `relay_id`, `cid`, `expires_in` |
| `relay_ok` | server → client | `RdvRelayOk` (`python/src/hsync_rendezvous/protocol.py::RdvRelayOk`) | `relay_id` |
| `relay_error` | server → client | `RdvRelayError` (`python/src/hsync_rendezvous/protocol.py::RdvRelayError`) | `error`, `retry_after?` |

`capacity` (domain `0..32`, default `0`; `CAPACITY_MAX` at `python/src/hsync_rendezvous/protocol.py::CAPACITY_MAX`) is the
**advisory service-capacity hint**: the number of concurrent peer-download reads the
peer declares it can serve (`0` = not a seeder). The handler copies it from
`register` onto the record and relays it in every `query` peer, but it is **not
authenticated and not authoritative** — the authoritative value is `serve_slots`
on the authenticated data-plane handshake (ADR 0030). `refresh` neither carries nor
mutates it, and the sample is never ordered by it.

`server_ready`/`prefer_master`/`never_master`/`inbound`/`startup_time`/`sync_direction` are the
**election advertisement** (decision #31): the same values the client's mDNS TXT
record carries (SSOT: `hsync-common` `protocol.p2p`/`protocol.pairing`), copied from
`register` onto the record and echoed on every `query` peer so a rendezvous-discovered
peer ranks in the client's master election exactly like an mDNS-discovered one.
Defaults when a peer advertises none: `false`, `false`, `false`, `0.0` (unknown;
bounded by `STARTUP_TIME_MAX`, `python/src/hsync_rendezvous/protocol.py::STARTUP_TIME_MAX`) and `bidirectional`
(`SyncDirection`, `python/src/hsync_rendezvous/protocol.py::SyncDirection`). The node never interprets them, never orders the
sample by them, and they are **not authenticated** (the data plane authenticates
identity by certificate pinning). Like `capacity`, a changed value requires a new
`register` — `refresh` never mutates them.

`reachable` is derived from `bool(endpoints)` at `register` time: it is `true` only
for a peer that advertised at least one listen endpoint (it can act as a data-plane
server — a master **or** a read-only seeder). An endpoint-less register (the first
STUN register) is advertised with `reachable=false` and a single-element
`endpoints` list carrying its observed source endpoint on the transport that
delivered the register (`udp` or `tcp`). `refresh` never changes it; a
change requires a new `register`.

`RdvPeer.endpoints` relays the first `MAX_RELAY_ENDPOINTS` (four) advertised
candidates, in order (decision #40); only a register that carried no endpoint at
all falls back to the observed source. Each relayed `host` is guaranteed dialable
by `hsync_common.endpoint.is_valid_endpoint_host` (including routable IP
literals: no loopback/link-local/multicast/reserved), and the whole response stays
within `MAX_RESPONSE_BYTES`. The requester tries the candidates, preferring a
host/LAN one reachable from its own network, so two peers behind the same NAT —
where the public endpoint has no hairpin route — still connect over the local path.
The relayed list is advisory and unauthenticated, like the other peer fields.

## Nested models

| Model | Owner | Fields |
|---|---|---|
| `Endpoint` (`python/src/hsync_rendezvous/protocol.py::Endpoint`) | `RdvRegister.endpoints[]` | `proto` (`tcp`/`udp`), `host`, `port` |
| `ObservedEndpoint` (`python/src/hsync_rendezvous/protocol.py::ObservedEndpoint`) | `RdvAck.observed_endpoint` | `proto`, `ip`, `port` (STUN-echo of the source) |
| `RelayId` (`python/src/hsync_rendezvous/protocol.py::RelayId`) | `RdvRelayAttach.relay_id`, `RdvRelayIncoming.relay_id`, `RdvRelayOk.relay_id` | 32 lowercase hex characters (16 random bytes, minted per pairing) |
| `RdvPeer` (`python/src/hsync_rendezvous/protocol.py::RdvPeer`) | `response.peers[]` | `cid`, `endpoints[]`, `cert_fp`, `bucket`, `group?`, `version`, `capacity`, `reachable`, `server_ready`, `prefer_master`, `never_master`, `inbound`, `startup_time`, `sync_direction` |

The client→server frames are dispatched in one pass by the discriminated union
`RdvFrame = Annotated[RdvRegister | RdvRefresh | RdvLeave | RdvQuery,
Field(discriminator="type")]` (`python/src/hsync_rendezvous/protocol.py::RdvFrame`) and validated from raw bytes via
`RDV_FRAME_ADAPTER` (`python/src/hsync_rendezvous/protocol.py::RDV_FRAME_ADAPTER`, a `TypeAdapter[RdvFrame]`). The
server→client frames (`RdvAck`/`RdvPeer` and the hand-assembled `response`) are deliberately
excluded from the union: they are never validated on the input path.

## Shared validators

| Constant | Location | Rule |
|---|---|---|
| `CID_PATTERN` | imported from `hsync_common.ids` (`hsync-common/hsync_common/ids.py::CID_PATTERN`) | `^[A-Za-z0-9]{21}$` — **SSOT import** (hsync-common), pinned to the rdv/1 spec value by `test_cid_pattern_matches_boot1_spec` |
| `BucketName` | `protocol.py` | canonical HSYNC bucket name via `hsync_common.path_validation.is_valid_bucket_name` (`[A-Za-z0-9]` with `-`/`_` in the middle, 1..63) — applied to every wire `bucket` |
| `BucketToken` | `protocol.py` | 64 lowercase hex characters (grammar `_BUCKET_TOKEN_RE`, `BUCKET_TOKEN_LEN`) — enforced as a wire-model validator (decision #46), so a token outside the key-derivation domain is an invalid frame, not a failed-token attempt |
| `BUCKET_TOKEN_LEN` | `protocol.py` | 64 (lowercase hex = `hex(32 bytes)`), derived as `HMAC-SHA256(key, "rdv/1" || bucket)[:32]` |
| `BucketProto` | `protocol.py` | `Literal["tcp", "udp"]` |
| `CAPACITY_MAX` | `protocol.py` | 32 — upper bound of the advisory `capacity` hint (`0` = not a seeder); mirrors `serve_slots` |
| `CONNECTED_MAX` | `protocol.py` | `2^53` — upper bound of the advisory `connected` count (like `STARTUP_TIME_MAX`: inside the exactly-representable integer range of a JSON number) |
| `RDV_DEFAULT_PORT` | imported from `hsync_common.constants` (rendezvous `cli.py` default; client bare-host default) | `443` — default UDP listener port (spec §Transport); single SSOT shared with `hsync-client` |
| `RDV_PORT_SET` | imported from `hsync_common.constants` (rendezvous `--ports` recommended value; client `HSYNC_RENDEZVOUS_PORTS` fallback) | `(443, 53)` — ordered recommended reachability set (canonical QUIC then DNS); see decision 57 |

## Runtime (non-wire) structures

| Structure | Location | Role |
|---|---|---|
| `PeerRecord` | `python/src/hsync_rendezvous/routing.py::PeerRecord` | RAM-only routing entry keyed `(cid, bucket, group)`; carries `capacity` (advisory hint), `expires_at` (TTL), the advertised endpoints as wire-agnostic `(proto, host, port)` tuples (`EndpointTuple`, `python/src/hsync_rendezvous/routing.py::EndpointTuple`) and a lazily-built cached `wire` fragment (`bytes | None`, the serialized `RdvPeer`) |
| `RoutingTable` | `python/src/hsync_rendezvous/routing.py::RoutingTable` | In-memory registry (`upsert`→`bool`/`remove`/`get`/`prune`/`sample`/`count`/`source_ips`); never persisted, single-thread (no lock: one event loop). `upsert` returns `False` above a host-derived `max_records` ceiling, a `max_records_per_bucket` ceiling (the one a registrant cannot rotate around, since `group` is free-form) or a `max_records_per_group` ceiling (so one sample cannot be saturated), so the handler can apply backpressure. `get` returns only an **active** record, so a TTL lapse frees the key and never revives through `refresh`. Backed by three secondary indexes — `_by_group` (bucket+group → keys, O(1) `sample`), `_by_cid` (cid+bucket → keys, O(1) `remove`), `_pos` (key → list position for O(1) swap-remove) — plus the `_per_bucket` counter. `prune` rebuilds the indexes in bulk when ≥ 50% of records expire, else removes incrementally. |
| `TokenBucketLimiter` | `hsync-common/hsync_common/ratelimit.py` (re-exported at `python/src/hsync_rendezvous/ratelimit.py`) | Shared in-memory token bucket SSOT (also used by `hsync-client`) for the per-IP/per-(IP, bucket) rate limits; `has_tokens` is a non-consuming peek used by the pre-parse malformed-frame gate; `max_keys` evicts the least-recently-used key on insert and `evict_stale` drops fully-refilled buckets, bounding key-state growth |
| `ResourceLimits` | `python/src/hsync_rendezvous/resources.py` | Host-derived ceilings (`max_peer_records`, `max_records_per_bucket`, `max_records_per_group`, `max_limiter_keys`, `max_active_connections`, `max_active_connections_per_ip`) from available RAM (the process's own cgroup limit, then `MemAvailable`, then sysconf) and CPU count; `detect()` is read-only/best-effort with a conservative fallback |
| `ConnectionGuard` | `python/src/hsync_rendezvous/guard.py` | Per-IP handshake budget + per-IP and process-wide open-connection caps, sized by `ResourceLimits`; checked before any handshake work, released on `ConnectionTerminated` |
| `NodeIdentity` | `python/src/hsync_rendezvous/identity.py` | Self-signed TLS identity (cert + ECDSA P-256 key). Persisted (`0600`/`0700`) by default via `load_or_create_identity`/`rotate_identity`, or built in memory by `make_identity` (`--ephemeral`). `expires_at` is the certificate `NotAfter`; `fingerprint` is the leaf-DER SHA-256 (`sha256:<hex>`), the trust anchor for client pinning (ADR-0034/ADR-0037) |

## Relationships

```
register/refresh ──► RdvRegister / RdvRefresh ──► RdvAck (STUN-echo + ttl)
query           ──► RdvQuery                    ──► response ──► RdvPeer[]
leave           ──► RdvLeave                    ──► (no reply frame)
```

`RdvPeer` is projected from a `PeerRecord` (wire `peer_fragment`,
`python/src/hsync_rendezvous/wire.py::peer_fragment`): the peer's first
`MAX_RELAY_ENDPOINTS` (four) endpoints are relayed, falling back to the observed
source endpoint when the register carried none; `_query` then stops adding peers
once the `MAX_RESPONSE_BYTES` budget is spent. The projection is serialized once
with `RDV_PEER_ADAPTER` and the resulting JSON fragment cached on
`PeerRecord.wire` (`bytes`), not the `RdvPeer` model — the fragment is embedded
verbatim in the response envelope and reused on later samples. It is valid for the record's
lifetime because `register` always builds a fresh `PeerRecord` and `refresh` only
mutates `connected`/`expires_at` (`connected` **is** part of the projection, so a
refresh that changes it resets `wire`; every other projected field is copied from
`register` and requires a fresh `register`/new `PeerRecord` to change). The
response envelope itself is assembled by the handler around the fragments.
The committed fixtures in `fixtures/rendezvous-*.json` validate every one of these
models via the drift test in `python/tests/test_scaffold.py`.
