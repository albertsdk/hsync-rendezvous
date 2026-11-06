# HSYNC Rendezvous — LLM Wiki

Internal, agent-optimized knowledge base for the `hsync-rendezvous` project
(no-log, zero-knowledge P2P rendezvous node speaking `rdv/1` over **QUIC/UDP**
and **TLS/TCP**).

**Source references.** Local paths are relative to this repository root and use
`path/to/file.ext::Symbol`. Cross-repo references are relative to the `hsync/`
workspace root and start with the sibling repo directory (`hsync-common/…`,
`hsync-client/…`, `hsync-server/…`, `hsync-rendezvous/…`, `hsync-desktop/…`);
they are code spans, not hyperlinks.

## Table of contents

| Document | Content |
|---|---|
| [architecture.md](architecture.md) | High-level system overview: layers, data flow, security model, target matrix |
| [data-models.md](data-models.md) | The `rdv/1` frame models, nested types, shared validators and their relationships |
| [decisions.md](decisions.md) | Implementation decisions |

## Project snapshot (v1 — Python, complete)

| Artifact | Path |
|---|---|
| Wire-protocol specification (SSOT) | `protocol-spec/rdv-1.md` |
| Shared protocol fixtures | `fixtures/rendezvous-*.json` |
| Python implementation | `python/src/hsync_rendezvous/` |
| [`compile.sh`](../compile.sh) | Root build entry point (`native`/`rpi`/`deb`/`deb-all`/`rpm`/`rpm-all`, `-l/--language`); per-language binary builds stay in their own directory | v1 |
| [`run.sh`](../run.sh) | Uniform "run after clone" entry point (checks the sibling `hsync-common`, creates the in-project venv, runs the node) — mirrors `hsync-server/run.sh` |
| Install/distribution | `install.sh` (Docker Compose installer), `compose.yaml`, `Dockerfile` + `Dockerfile.dockerignore` + `python/entrypoint.sh` (image, group keys as fd 3), `docker.sh` (source image build/lifecycle) |
| OS service units | `packaging/{systemd,launchd,windows}/` |
| End-user documentation | `docs/` (`getting-started.md` chooser + one `getting-started-<method>.md` per install method; `usage.md`/`faq.md` are the reference; `operations.md` is the operating how-to: supervision, watchdog, log bounds, identity backup/rotation, upgrades, reachability probe) |

## Hard invariants (read before touching any module)

1. **No-log**: the process NEVER writes peer data (IPs, CIDs, timestamps) to
   disk. Only peer-free aggregates may be published (connection/peer levels and
   peaks on `STATUS=`, an optional Prometheus text file and the loopback
   `/metrics` endpoint — decisions 71/72). The TLS identity is a persistent ECDSA P-256 key+cert kept **by default**
   (`run --identity PATH` overrides the XDG state path; `run --ephemeral` keeps
   it in memory instead) — the operator's own key+cert (ADR-0034/ADR-0037), never
   peer data, and the node's only on-disk artifact. Enforced by
   `python/tests/test_nolog.py` (read-only filesystem sandbox). Diagnostics
   come in two stderr channels: an **always-on**, peer-free operational one
   (`warn`/`error`, decisions #36) and the opt-in peer-aware `--debug` sink
   (decision #25); without `--debug` nothing peer-related leaves memory.
2. **RAM only**: the routing table lives in
   `python/src/hsync_rendezvous/routing.py` and is never persisted. TTL 60 s,
   prune every 15 s, client refresh every 30 s. The data relay keeps the same
   promise: its listener/session state lives in
   `python/src/hsync_rendezvous/relay.py`, RAM only, and only aggregate counters
   exist (`--no-relay` makes the node discovery-only; ADR-0047).
3. **Rigid schema**: every `rdv/1` frame model uses pydantic
   `extra="forbid"` — unknown/targeted fields make the frame invalid and it is
   silently dropped. The field domains are enforced too: `bucket_token` must be
   64 lowercase hex characters (`BucketToken`, `protocol.py`), `connected`
   is bounded to `0..2^53` (`CONNECTED_MAX`), `endpoints[].host` must be a
   dialable host (`EndpointHost` → `hsync_common.endpoint.is_valid_endpoint_host`)
   and `cert_fp` must normalize to a full SHA-256 digest (`CertificateFingerprint`
   → `hsync_common.protocol.pairing.parse_fingerprint`), so a value that cannot
   exist in the key-derivation domain, a wire-bignumber, an undialable target or
   an uncomparable pin is an invalid frame, not an unbounded
   storage/accounting/relay event (decision #46).
4. **Protected buckets**: tokens are derived
   `HMAC-SHA256(key, "rdv/1" || bucket)[:32]` hex, compared in constant time
   (`hmac.compare_digest`) whether or not the bucket has a key; refusals are
   uniform (`token_required`) and never reveal bucket existence or the
   provisioned set. `--private` widens the same policy to every bucket
   (including `leave`): see `decisions.md` #22/#51. The group key is the token's
   only entropy, so the node's key source enforces `MIN_GROUP_KEY_CHARS` (32
   characters); a client may use `HSYNC_P2P_PASSPHRASE` (12+) derived to it.
5. **Record ownership**: on an open bucket, `register`/`refresh`/`leave` are
   honoured only from the source IP the record belongs to (or with a valid token
   on a protected bucket); a foreign source cannot overwrite, keep alive or
   evict another peer's record (decision #45). Ownership follows liveness:
   `RoutingTable.get` returns only active records, so a TTL lapse frees the key
   and a `refresh` never revives an expired record.
6. **Bounded state**: the routing table, the rate-limiter key maps and the
   connection guard are capped from the host's RAM/CPU (`ResourceLimits`,
   `resources.py`), so adversarial churn is answered with backpressure, never
   unbounded growth (decisions #43/#49/#50). The table is capped globally, per
   bucket and per `(bucket, group)`, a `response` relays at most
   `MAX_RELAY_ENDPOINTS` endpoints per peer within `MAX_RESPONSE_BYTES`, and a
   connection runs at most `MAX_SESSIONS_PER_CONNECTION` sessions, so what a
   registrant controls can never size what the node allocates or emits.
7. **Zero backward compatibility**: breaking the wire contract means bumping
   the mandatory `protocol_version` (`rdv/1`) and updating spec, fixtures,
   implementation and tests atomically.
8. **SSOT note**: the CID shape and the bucket-name rule are **imported** from
   `hsync-common` (`hsync_common.ids.CID_PATTERN`,
   `hsync_common.path_validation.is_valid_bucket_name`), not re-declared locally;
   the rdv/1 spec + fixtures stay the cross-language contract. The daemon also
   reuses `hsync_common.ssl_utils` for its TLS identity (see
   `decisions.md` #26 and hsync-common ADR-0033); ADR-0034/ADR-0037 define the
   persistent identity (`--identity`, `--ephemeral`, `identity show`/`rotate`)
   and the `sha256:<hex>` trust fingerprint.
