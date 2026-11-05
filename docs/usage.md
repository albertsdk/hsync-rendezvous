# Usage reference — hsync-rendezvous

Reference for the CLI, the environment variables, the group-keys contract and
the OS service units. Installation and the open-mode quick start are on the
[welcome page](README.md).

## Command

The commands are `run`, `identity show`, and `identity rotate` (plus the
top-level `--version` flag):

```text
hsync-rendezvous run [OPTIONS]
hsync-rendezvous identity show [--identity PATH] [--pem]
hsync-rendezvous identity rotate [--identity PATH] [--public-host NAME]...
hsync-rendezvous --version
```

### `run` options

| Option | Default | Description |
|---|---|---|
| `--listen-host` | `0.0.0.0` | Address to bind the listeners to. Accepts an optional port (`HOST[:PORT]`, e.g. `0.0.0.0:443` or `[::1]:443`). Applies to both transports (QUIC/UDP and TLS/TCP). |
| `--listen-port` | `443` | Port (1–65535) for both the QUIC/UDP and TLS/TCP listeners. 443 is the QUIC/HTTP3 and HTTPS default; ports below 1024 need root or `CAP_NET_BIND_SERVICE` (the systemd unit grants it). Mutually exclusive with a port in `--listen-host HOST:PORT`. |
| `--listen-ports` | *(none)* | Comma-separated ports to listen on in **one process** (multi-port), on both transports. The listeners share one in-memory routing table, so a peer registered via one port is visible to a query on another. The point is to offer several inbound doors because a **client's egress firewall** may block UDP 443 while allowing another port. Recommended reachability set: `443,53` (`RDV_PORT_SET`); 53 is the most permissive UDP port but is usually held by the local resolver — free it or omit it. Binding is **best-effort and per (port, transport)**: a port that cannot bind on a transport is skipped with a warning and the node keeps serving the rest (it fails only if **no** transport binds any port). Mutually exclusive with `--listen-port` and a port in `--listen-host HOST:PORT`. |
| `--udp` / `--no-udp` | *(enabled)* | Serve the **QUIC/UDP** listener (on by default; `--no-udp` disables it). Environment variable form: `HSYNC_RENDEZVOUS_UDP=0` disables, `=1` forces. |
| `--tcp` / `--no-tcp` | *(enabled)* | Serve the **TLS/TCP** listener on the same ports (on by default; `--no-tcp` disables it). The two transports are interchangeable for discovery and relay; a client picks one with `--rendezvous-transport`. TCP 443 may already be held by a co-hosted HTTPS server — run the node QUIC-only with `--no-tcp` in that case. Environment variable form: `HSYNC_RENDEZVOUS_TCP=0` disables, `=1` forces. Disabling both `--no-udp` and `--no-tcp` is a configuration error (exit code 2). |
| `--identity` | XDG state path | Path of the persistent TLS identity (key+cert). Created on first run and reused afterwards, so the certificate fingerprint is stable across restarts and can be pinned by clients. Default: `$HSYNC_RENDEZVOUS_IDENTITY`, else `$HSYNC_STATE_DIR/rendezvous/identity.pem`, else `$XDG_STATE_HOME/hsync/rendezvous/identity.pem` (`~/.local/state/…`). |
| `--ephemeral` | *(disabled flag)* | Keep the TLS identity in memory and write no identity file (read-only filesystems, throwaway nodes); the fingerprint changes on every restart, so clients cannot pin it. Mutually exclusive with `--identity`. Environment variable form: `HSYNC_RENDEZVOUS_EPHEMERAL=1`. |
| `--public-host` | *(none)* | Public hostname or IP to add to the certificate SAN (repeatable). |
| `--protected-bucket` | *(none)* | Bucket that requires a valid `bucket_token`. Repeat the flag once per bucket (`--protected-bucket shared --protected-bucket home`). The group-keys file may carry more buckets than declared; each **declared** bucket must have its key provisioned or startup fails fast (exit code 2). Buckets not declared stay open unless `--private` gates them all. |
| `--keys-fd` | *(none)* | File descriptor carrying the group keys (see below). Environment variable form: `HSYNC_RENDEZVOUS_KEYS_FD`. |
| `--keys-file` | *(none)* | File carrying the group keys (same `bucket=<hex-key>` format); read once at startup and never written. Portable alternative to `--keys-fd` for service managers that cannot pass a descriptor (Windows/WinSW); the two are mutually exclusive. A missing/non-regular file or a symlink is a configuration error (exit code 2); on POSIX a group-writable or world-accessible file is reported on the always-on warning channel (0640 group-read is accepted). Environment variable form: `HSYNC_RENDEZVOUS_KEYS_FILE`. |
| `--private` | *(disabled flag)* | Private node: every frame must carry a valid `bucket_token`, for **every** bucket (not only `--protected-bucket`). Starting it with no group key fails fast (exit code 2). Environment variable form: `HSYNC_RENDEZVOUS_PRIVATE=1`. |
| `--upnp` | *(disabled flag)* | Map the listener port(s) with UPnP for **both** transports (UDP for QUIC and TCP for TLS/TCP; opt-in, off by default). With `--listen-ports`, every bound port is mapped on both protocols, so each offered door is also reachable from the WAN side. |
| `--relay` / `--no-relay` | *(enabled)* | Relay the peers' opaque bytes (`rdv/1` relay frames), so two peers that no inbound NAT mapping reaches can still run their data plane through this node. **On by default**; `--no-relay` disables it. Without the relay the node answers every relay frame with `relay_unavailable` and only directly reachable peers connect. Relaying spends the node's uplink, which is why the aggregate rate and the other bounds below stay in force. The node never terminates or inspects the relayed payload. Environment variable form: `HSYNC_RENDEZVOUS_RELAY=0` disables, `=1` forces. |
| `--relay-idle-timeout` | `120` | Seconds without traffic in either direction before a relayed session (or a listener control stream) is closed. Range `30..3600`. |
| `--relay-session-bytes` | `0` | Close a relayed session after this many forwarded bytes (`0` = no per-session cap; the byte rate stays the primary bound). |
| `--relay-bandwidth` | `8192` | Aggregate relay throughput cap in KiB/s (`0` = unlimited). Excess traffic is throttled by backpressure, never dropped. |
| `--ttl` | `60` | Record TTL in seconds (1–3600). Peers refresh every 30 s by default, so 60 s leaves one refresh of headroom. It must stay **above** the clients' refresh interval (`HSYNC_RENDEZVOUS_REFRESH_INTERVAL`, 30 s by default): a shorter TTL expires live records between two refreshes. Lower it only when the clients refresh more often (tests). |
| `--debug` | *(disabled flag)* | Emit the full operation log to stderr (opt-in): connections, frames, decisions, record changes and TTL sweeps, **including the peer identity** (CID, bucket, IP, port). Every line is timestamped and self-identifying (`2026-09-30T10:30:45.123Z - hsync-rendezvous[1234] debug: …`). Stderr only — never written to disk; without it no peer data leaves memory. Environment variable form: `HSYNC_RENDEZVOUS_DEBUG=1`. |
| `--ready-file` | *(none)* | Write the process PID to this path once the listener is bound (readiness seam, contains no peer data). Environment variable form: `HSYNC_RENDEZVOUS_READY_FILE`. An unwritable path fails fast with exit code 4. |
| `--metrics-host` | `127.0.0.1` | Loopback address for the `/metrics` endpoint. Only `127.0.0.1`, `::1` (any loopback literal) or `localhost` is accepted: the endpoint serves plain HTTP and is never bound to a public interface. Environment variable form: `HSYNC_RENDEZVOUS_METRICS_HOST`. |
| `--metrics-port` | *(disabled)* | Serve aggregate metrics on `--metrics-host:PORT` (loopback TCP). Requires a bearer token; see [Metrics](#metrics). Environment variable form: `HSYNC_RENDEZVOUS_METRICS_PORT`. |
| `--metrics-token-fd` | *(none)* | File descriptor carrying the metrics bearer token (one line, at least 32 characters). The preferred form on POSIX service managers. Environment variable form: `HSYNC_RENDEZVOUS_METRICS_TOKEN_FD`. |
| `--metrics-token-file` | *(none)* | File carrying the metrics bearer token; portable alternative to `--metrics-token-fd` (the two are mutually exclusive). Environment variable form: `HSYNC_RENDEZVOUS_METRICS_TOKEN_FILE`. |
| `--stats-file` | *(none)* | Write the aggregate counters to this path in Prometheus text format, replacing it atomically every `--stats-interval` seconds (node_exporter textfile collector). Environment variable form: `HSYNC_RENDEZVOUS_STATS_FILE`. |
| `--stats-interval` | `15` | Seconds between two publications (`STATUS=` on the service manager and the `--stats-file`). 1–3600. Environment variable form: `HSYNC_RENDEZVOUS_STATS_INTERVAL`. |
| `--no-rate-limit` | *(disabled flag)* | Disable rate limiting entirely (benchmark/test seam). **CLI-only**: there is deliberately no environment-variable form, so a stale `.env` or unit setting cannot silently unthrottle a node. Never enable in production — it removes the anti-abuse limits the spec requires. The transport guard is not created in this mode, so the `hsync_rendezvous_connections_*` gauges stay at 0 (the peer gauges are unaffected). |

### `identity show`

Prints the persisted identity fingerprint (or, with `--pem`, the public
certificate). `--identity PATH` is optional and defaults to the standard state
path; the private key is never printed.

```bash
hsync-rendezvous identity show
# → sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### `identity rotate`

Regenerates the persisted key+cert and prints the new fingerprint, which the
operator distributes to clients. `--identity PATH` is optional and defaults to
the standard state path; a POSIX service that uses an explicit `--identity` must
repeat that flag here. Give clients both the old and the new fingerprint
(`--rendezvous-fingerprint` is repeatable) during the rotation window; the node
itself keeps only the new certificate. Rotation keeps every existing DNS/IP
SAN, so hostname-validating clients keep working; pass `--public-host` only for
new names. The command re-reads and verifies the pair it wrote, then **you must
restart the node** to serve it (the identity is loaded at startup) and verify
the certificate clients actually see with
`hsync trust rendezvous-server fingerprint <host:port>` — `identity show` prints the persisted
file, not the served certificate. Rotation is also the
recovery for a corrupted identity whose key no longer matches its certificate;
a file that is not a valid PEM identity at all is refused (delete it and restart
to regenerate).

```bash
hsync-rendezvous identity rotate --identity /var/lib/hsync-rendezvous/identity.pem \
    --public-host rdv.example.com
```

### `--version`

Prints the version and the protocol, e.g.
`hsync-rendezvous 1.0.0 (rdv/1, Python v1)`, then exits.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Normal termination (Ctrl+C / SIGTERM). |
| 2 | Configuration error: missing group key (a duplicate `bucket=` line is refused), `--private` without a key, `--keys-fd` together with `--keys-file`, out-of-range `--ttl`, etc. The node refuses to start. |
| 3 | Listener bind failure: the port is privileged, already in use, or `--listen-host` is not a local address. The stderr message explains how to fix it. |
| 4 | Readiness-file failure: `--ready-file` points at a path the node cannot create (missing parent directory, no permission, or a stale file the `O_EXCL` seam refuses to overwrite). |

## Environment variables

| Variable | Meaning |
|---|---|
| `HSYNC_RENDEZVOUS_KEYS_FD` | Same as `--keys-fd`; the env-var form is what service wrappers set. |
| `HSYNC_RENDEZVOUS_KEYS_FILE` | Same as `--keys-file`; the portable source for service managers that cannot pass a descriptor (Windows/WinSW). |
| `HSYNC_RENDEZVOUS_IDENTITY` | Same as `--identity`; overrides the default state path of the persistent TLS identity. |
| `HSYNC_STATE_DIR` | Installation state directory; the default identity lives under its `rendezvous/` subdirectory. |
| `HSYNC_RENDEZVOUS_EPHEMERAL` | Same as `--ephemeral`; set to `1` to keep the identity in memory (no identity file). |
| `HSYNC_RENDEZVOUS_PRIVATE` | Same as `--private`; set to `1` to require a valid `bucket_token` on every frame. |
| `HSYNC_RENDEZVOUS_RELAY` | Same as `--relay`; `0` disables the data relay (discovery-only), `1` forces it on. |
| `HSYNC_RENDEZVOUS_RELAY_IDLE_TIMEOUT` | Same as `--relay-idle-timeout`. |
| `HSYNC_RENDEZVOUS_RELAY_SESSION_BYTES` | Same as `--relay-session-bytes`. |
| `HSYNC_RENDEZVOUS_RELAY_BANDWIDTH` | Same as `--relay-bandwidth`. |
| `HSYNC_RENDEZVOUS_DEBUG` | Same as `--debug`; set to `1` for the full opt-in operation log (peer identity included; stderr only). |
| `HSYNC_RENDEZVOUS_READY_FILE` | Same as `--ready-file`; the readiness PID path used by tests/orchestrators. |
| `HSYNC_RENDEZVOUS_METRICS_HOST` | Same as `--metrics-host`. |
| `HSYNC_RENDEZVOUS_METRICS_PORT` | Same as `--metrics-port`. |
| `HSYNC_RENDEZVOUS_METRICS_TOKEN_FD` | Same as `--metrics-token-fd`. |
| `HSYNC_RENDEZVOUS_METRICS_TOKEN_FILE` | Same as `--metrics-token-file`. |
| `HSYNC_RENDEZVOUS_STATS_FILE` | Same as `--stats-file`. |
| `HSYNC_RENDEZVOUS_STATS_INTERVAL` | Same as `--stats-interval`. |

## Group keys (`--keys-fd` / `--keys-file`)

Group keys provision **protected buckets**. They are read ONCE at startup from
either a **file descriptor** (`--keys-fd`; the preferred form on POSIX service
managers, where the key payload never has a path inside the sandbox that the
process could reopen) or an **operator-managed file** (`--keys-file`; the
portable form for Windows/WinSW and simple setups). The node never writes the
key material to disk in either form. `stdout`/`stderr` (descriptors 1 and 2) are
refused, the payload is capped (1 MiB) and, on POSIX, a descriptor read is
bounded in time (about five seconds): a misrouted or stuck-open descriptor fails
fast with a configuration error instead of stalling startup. `--keys-fd` and
`--keys-file` are mutually exclusive.

For `--keys-file`, the path must be a regular file (a symlink is refused),
a group-writable or world-accessible file is reported on the always-on warning
channel (0640 group-read is accepted), and the operator may delete the file
after startup (the node keeps the keys in memory; restarting requires the file
again).

Line format (comments and blank lines are ignored):

```text
# bucket=<hex-group-key>
shared=9f1c...
home=44ab...
```

Provisioning keys never turns a bucket on by itself: a bucket is token-gated
only when it is declared with the (repeatable) `--protected-bucket` flag, or —
for every bucket, provisioned or not — when the node runs with `--private`.

A bucket may appear only once: a duplicate line is a configuration error, never
a silent last-wins override.

Example with a systemd credential (fd 5):

```bash
hsync-rendezvous run --protected-bucket shared --keys-fd 5 \
    5< /etc/hsync-rendezvous/group-keys
```

The portable file form (same payload, used by the Windows service):

```bash
hsync-rendezvous run --protected-bucket shared \
    --keys-file /etc/hsync-rendezvous/group-keys
```

Notes:

- Clients derive the same `bucket_token` from the group key with
  `HMAC-SHA256(key, "rdv/1" || bucket)[:32]` and send only the derived token
  (64 lowercase hex chars) on `register`/`refresh`/`query`.
- Wrong or missing tokens are answered uniformly with `token_required` and
  rate-limited (5/min per IP → `rate_limited` with `retry_after`); the node
  never reveals whether a bucket exists.

## Private node (authenticated rendezvous)

An **open** node serves every bucket, gating only the ones declared with
`--protected-bucket`. A **private** node gates *all* of them: that is the mode
for a rendezvous node that acts as the rendezvous point of one community instead
of a public service.

```bash
# every bucket needs a key; without any key the node refuses to start (exit 2)
hsync-rendezvous run --private \
    --keys-fd 5 5< /etc/hsync-rendezvous/group-keys
```

What `--private` changes:

| Aspect | Open node (default) | Private node |
|---|---|---|
| `register` / `refresh` / `query` | token required only for `--protected-bucket`; records are owned by their source network | token required for **every** bucket |
| `leave` | honoured only from the source network the peer registered from (a `leave` from any other IP is silently ignored); on a protected bucket a valid token removes from any source | token required (an anonymous `leave` is silently dropped) |
| Bucket with no key loaded | served (public) | refused exactly like a wrong token |
| Startup with no group key | allowed | fails fast, exit code 2 |
| Rate limits | unchanged | unchanged (private mode never removes them) |

Notes:

- For an operator who provisions a key for **every** bucket the node serves,
  `--private` is the convenience one-switch equivalent of declaring every bucket
  with `--protected-bucket`: the provisioned buckets behave the same, plus
  `leave` is gated too, and an **empty** key file is refused at startup (exit 2)
  instead of staying open — see the table above.
- The wire format does not change: `bucket_token` is the same optional field the
  protected buckets already use, so a client only needs the group key — no
  new protocol version and no client-side mode switch.
- Refusals stay uniform (`token_required`, then `rate_limited` with
  `retry_after`): a client cannot tell which buckets exist or are provisioned.
- Deployment: uncomment the `HSYNC_RENDEZVOUS_PRIVATE=1` example in the unit or
  service XML shipped with your OS (see "Deploying as a service"); the env-var
  form is exactly equivalent to the flag. On Windows the keys file is passed
  with `--keys-file` (the installer creates it empty and grants LocalService
  read access).

### Provisioning and key rotation

1. Mint one group key per bucket (for example `openssl rand -hex 32`). It must
   be at least 32 characters: the key is the bucket token's only entropy, so a
   shorter value is a configuration error (exit code 2) on the node. A client may
   instead use `HSYNC_P2P_PASSPHRASE` (at least 12 characters), which it derives
   to the same 64-hex key. When the clients are GUI apps (HSYNC Desktop), the
   natural workflow is the other way around: pick the shared password the devices
   use, derive the key with the client's `hsync derive-group-key`, and store that
   64-hex output as the `bucket=<key>` line — the Desktop field always treats
   what a user types as a shared password, so a node key minted randomly can
   only ever be matched by a raw-key CLI client (or a legacy stored value).
2. Write one `bucket=<key>` line per bucket to
   `/etc/hsync-rendezvous/group-keys` (0640, root-owned) and pass it to the node
   with `--keys-fd 5` (the packaged systemd/launchd units) or
   `--keys-file /etc/hsync-rendezvous/group-keys` (Windows and simple setups).
   An **empty** file means no protected buckets (open mode); a standard service
   install ships it empty, so the node starts open until you provision keys.
   `--private` with an empty file is a configuration error (exit 2): provision
   at least one key before enabling private mode.
3. Distribute the same key to the clients allowed in that bucket: they derive
   `HMAC-SHA256(key, "rdv/1" || bucket)[:32]` and send only the derived token.

**Revocation is key rotation** — there is no per-peer account to disable.
Replace the key in the group-keys file, restart the node and redistribute the new
key; the previous tokens stop matching immediately. Treat a leaked group key as
a leaked node capability.

Trade-offs (by design, not defects):

- The token proves a *capability*, not an identity: on a protected/private
  bucket whoever holds the key can register under any `cid` (or remove a known
  pair), so peers verify the TLS fingerprint of the peers they contact and a
  spoofed entry does not survive contact. On an **open** bucket, `register`,
  `refresh` and `leave` are honoured only from the record's own source network.
- Rate limits still apply to legitimate key holders; private mode is not a
  substitute for the anti-abuse limits.
- No account system and no persistence: routing table, keys and limits live in
  RAM only (see "Privacy and anonymity model").

## Endpoint candidates (`endpoints`)

`register` carries the peer's data-plane endpoint candidates. The node stores
them and relays the **first four, in order**, on every peer of a `query` response
(a peer that advertised none is relayed as a single-element list with its
observed source endpoint), and the whole response stays within a 32 KiB budget.

Each advertised `host` must be dialable — an IPv4/IPv6 literal or a DNS name; a
value outside that grammar (control characters, path separators, empty or
over-long labels) makes the frame invalid, so a registrant cannot hand other
peers an undialable or internal-looking target.

The list is **advisory only** and the node never interprets or orders by it. A
requester tries the candidates, preferring one reachable from its own network
(a host/LAN address) over the NATed public one, so two peers behind the same NAT
— where the public endpoint has no hairpin route on most home routers — still
connect over the local path. The candidates are unauthenticated hints: the data
plane authenticates the peer by certificate pinning before any file is
exchanged.

## Peer capacity hint (`capacity`)

`register` may carry an advisory `capacity` hint (integer `0..32`, default `0`;
`0` means "not a peer-download seeder"). The node stores it and echoes it in every
peer of a `query` response, so a client can pre-size its download concurrency.

The hint is **advisory only**: it is not authenticated and not authoritative. The
authoritative limit is the `serve_slots` value a peer advertises on the
authenticated data-plane handshake (ADR 0030), so a client must never treat
`capacity` as a guarantee nor use it to exclude a peer. The node never orders its
random sample by `capacity`, so a self-declared value buys no priority; `refresh`
neither carries nor changes it.

## Election advertisement (`server_ready`, `prefer_master`, `never_master`)

A `register` may also carry the master-election advertisement: the three flags
`server_ready`, `prefer_master`, `never_master` plus `startup_time` and
`sync_direction` (defaults: `false`, `false`, `false`, `0.0` and
`bidirectional`). The node stores them and echoes them on every peer of a
`query` response, so devices that find each other through the node run the same
master election they would run on a local network:

- `server_ready` marks the device that is currently serving the bucket: it wins
  the election over a newcomer, even one set with `prefer_master`, so a peer
  that joins later does not trigger a takeover.
- `never_master` excludes a device from candidacy (`hsync p2p --never-master`).
- `startup_time` and `sync_direction` break remaining ties deterministically.

Like `capacity`, the advertisement is **advisory only**: it is not
authenticated, the node never interprets it, and the data plane still
authenticates every peer by TLS certificate pinning. A changed value (a device
becoming master, or giving the role up) is published with a new `register`;
`refresh` never alters it.

## Privacy and anonymity model

A rendezvous is what turns a group of devices into a **private P2P network over the
Internet**: they find each other through the node, while the file data keeps
flowing only between peers. These are the properties an operator or a community
can rely on.

- **No accounts, no registration** — there is no user database and no per-peer
  credential to issue or revoke. The only credential is the group key of a
  protected bucket (or of a private node): a *capability*, not an identity.
- **Pseudonymous, not anonymous** — the node invents no identity of its own. The
  `cid` a client presents in p2p mode is its **persistent device identifier** (the
  same `device_id` that anchors TOFU pins), so treat it as a stable pseudonym, not
  as an ephemeral anonymous token.
- **Nothing survives the process** — peer data (IPs, CIDs, timestamps) lives only in
  RAM with the configured `--ttl` (default 60 s, max 3600 s); the routing table,
  the group keys and the rate-limit windows are all in memory. Stop the process and
  every trace of the network is gone.
- **No peer data on disk, ever** — the routing table and the rate-limit windows
  live only in memory; the group keys are read once into memory and never
  written. The only persistent artifact is the node's own self-signed key+cert
  (ECDSA P-256, `0600` inside a `0700` directory), kept by default so the
  fingerprint is stable and clients can pin it; `--ephemeral` drops even that.
  With `--ready-file` (used by the container installer) an ephemeral PID file is
  also written and removed on graceful shutdown.
- **Uniform refusals (no enumeration oracle)** — a wrong/missing token and a bucket
  with no key loaded are answered with the same `token_required` (then
  `rate_limited` with `retry_after`), compared in constant time in both cases, so
  a client cannot tell which buckets exist, which are provisioned, or that a
  private node gates everything.
- **Records are owned by their source** — creating, replacing or renewing a
  rendezvous record is honoured only from the source address it was registered
  from (or with a valid token on a protected bucket). A peer that learns another
  peer's `(cid, bucket, group)` cannot redirect its record, keep a hijacked one
  alive, or evict it.
- **Silent about peers by default** — output goes to the console only and the
  shipped service units route stderr to the system log (`journalctl -u
  hsync-rendezvous`, a launchd file, the WinSW log). That always-on channel carries
  the node's **own** operational state (a UPnP mapping that could not be created,
  an unwritable readiness file, an unexpected session failure) and is **peer-free
  by construction**: it accepts only non-identifying fields, so no CID, bucket or
  IP can reach it. `--debug` is the only channel that can emit peer identity, and
  it is opt-in, stderr-only and never written to disk (see "Diagnostics").

### Transport security

- Two interchangeable transports, both carrying **TLS 1.3**: **QUIC/UDP** and
  **TLS/TCP** on the same ports (default 443), with the same ALPN
  (`hsync-rdv/1`), the same node identity and the same `rdv/1` frames. Discovery
  (`register`/`refresh`/`leave`/`query`) and the relay behave identically on
  both. The exchanged peer list is not readable by an ISP or a passive observer
  on the path, whichever transport a client picks.
- The node presents a **self-signed** certificate and clients authenticate it by
  SHA-256 fingerprint: on a terminal the first contact is confirmed at a prompt
  (the default `ask` policy, like `ssh`), while an unattended client pins the
  fingerprint or trusts the first sighting — the exact steps are in "TLS identity
  & pinning". The fingerprint is the same on both transports (one identity), so
  a pin is shared.
- QUIC `RETRY` + address validation before any connection state is allocated
  (anti-amplification) and a node-side **transport guard**: about 30 new
  connections/handshakes per second (burst 100) per source address, plus a per-IP
  and a process-wide cap on simultaneously-open connections, all enforced before
  any handshake work runs and sized from the host's RAM and CPU. On TLS/TCP the
  admission runs before the TLS handshake **and before any byte is read**, so a
  handshake flood from one IP is refused with no handshake work at all. QUIC
  receive windows and the TLS/TCP stream reader are bounded too, so a connection
  cannot buffer unbounded input. A connection or handshake flood is throttled
  without external help (works with a bare listener, no firewall/nginx needed for
  per-source floods; a distributed volumetric attack still needs upstream
  mitigation).
- **Layered in-memory rate limits**, every window keyed by source address so one
  peer cannot exhaust another's budget: the valid-frame admission (~10 req/s,
  burst 50), per-`(IP, bucket)` windows for `register`/`refresh` (10/min) and
  `query` (5/min), an aggregate per-IP `query` cap (20/min, anti-enumeration), the
  failed-token budget (~5/min per IP) **and a pre-parse budget for
  malformed/unknown frames** (~30/min per IP, burst 60) so a flood of garbage
  frames cannot turn frame validation into a CPU-exhaustion channel. Rate-limit
  refusals are always answered (`rate_limited` + `retry_after`); the silent
  malformed-frame budget answers nothing (there is no oracle to hand out). The
  routing table and the limiter tables have host-derived ceilings, globally, per
  bucket and per bucket/group, so a registration flood is answered with
  `overloaded` backpressure (`retry_after` advisory) instead of exhausting RAM or
  saturating a single bucket's sample; the per-bucket ceiling is the one a
  registrant cannot rotate around, because `group` is chosen by the peer. A
  `query` response is bounded too (at most four endpoints per peer, 32 KiB per
  frame), so a registrant cannot turn a small query into a large reply. Every
  `rdv/1` frame rejects unknown fields, and the deployed units are
  sandboxed (systemd `DynamicUser`, syscall filter).
- **UPnP is opt-in and hardened**: off by default (`--upnp` enables it). SSDP
  replies must originate from a private
  LAN address and their `LOCATION` must be `http(s)://<private-IP-literal>/…`
  (no hostnames, no external hosts, no redirects) — the device rendezvous cannot
  be steered into fetching arbitrary internal/external URLs. On a node with no
  LAN (a public VPS) SSDP simply finds nothing and the node runs stateless, as
  always; nothing about the mapping workflow changes on a LAN. The mapping
  carries a finite lease, renewed before it expires, and is removed on graceful
  shutdown — a stopped or crashed node leaves no permanent rule on the router.

### What it is not

- **Not an anonymity network** — it is a rendezvous point, so it observes the
  `ip:port` a peer registers with (and echoes it back in the `ack`), and a `query`
  response hands each peer the `ip:port`/`cert_fp` of the peers it returns. Hiding
  your IP from the node or from your peers is out of scope; nothing here is
  Tor-like.
- **Not a storage node and not a control plane** — it stores no file and orders
  nothing. It forwards the peers' **opaque TLS** for peers that no inbound NAT
  mapping reaches: it never terminates or inspects that TLS, so it sees no
  content, file name or credential. What it does see is the pairing
  (`cid` ↔ `cid`) and the byte volume. With `--no-relay`, file data flows only
  between directly reachable peers.
- **A private node is authentication, not a VPN** — it gates who may use the node as
  a rendezvous point (and as a relay); the sync traffic is encrypted by the peers'
  own HTTPS/WSS session.

## TLS identity & pinning

The node keeps a persistent, self-signed TLS identity (ECDSA P-256), created on
first run and reused afterwards, so its fingerprint is stable across restarts and
clients can pin it. Its key+cert is the node's only **persistent** artifact
(never peer data; with `--ready-file` an ephemeral PID file is also written and
removed on graceful shutdown). By default it lives at
`$XDG_STATE_HOME/hsync/rendezvous/identity.pem` (`~/.local/state/…`); set an
explicit path (e.g. a service directory) with `--identity`:

```bash
# create (first run) and reuse (subsequent runs) the identity:
hsync-rendezvous run --identity /var/lib/hsync-rendezvous/identity.pem \
    --public-host rdv.example.com
```

Each name/IP clients dial should be added with `--public-host` (repeatable) so a
TLS client that validates the hostname — not only the fingerprint — accepts the
handshake. The file is written with `0600` permissions in a `0700` directory,
and on load the node verifies that the private key matches the certificate,
refusing a mismatched or corrupted file instead of failing later in the TLS
handshake. Read the fingerprint and distribute it to clients out of band:

```bash
hsync-rendezvous identity show --identity /var/lib/hsync-rendezvous/identity.pem
```

`--ephemeral` writes no identity file: the fingerprint then changes on every
restart and clients cannot pin it — use it on a read-only filesystem or for a
throwaway node. Clients authenticate the node by fingerprint: a terminal confirms
the first contact at the prompt, an unattended client pins it with
`--rendezvous-fingerprint` (or trusts the first sighting with `--rendezvous-tofu`);
see the client `p2p-rendezvous` documentation. To rotate the key
(e.g. after a suspected compromise), regenerate it, give clients both the old
and the new fingerprint (`--rendezvous-fingerprint` is repeatable) during the
rotation window, then move them to the new one. Rotation **preserves every
existing DNS/IP SAN** and adds any new `--public-host`; pass `--public-host`
only for names the node did not already carry. **Restart the node** to serve the
new identity (it is loaded at startup), then verify the served certificate from
a client with `hsync trust rendezvous-server fingerprint <host:port>`.

```bash
hsync-rendezvous identity rotate --identity /var/lib/hsync-rendezvous/identity.pem \
    --public-host rdv.example.com
```

## Diagnostics

The node emits two kinds of line on stderr, in the same format — a UTC ISO 8601
timestamp, the emitting process, the level and the message:

```text
2026-09-30T10:30:45.123Z - hsync-rendezvous[1234] warn: upnp no igd on lan port=443
2026-09-30T10:30:45.130Z - hsync-rendezvous[1234] debug: register ack cid=A1b2C3d4E5f6G7h8I9j0K bucket=shared
```

**Always on — node health (`warn` / `error`).** Operational events the operator
must see without any flag: a UPnP mapping that could not be created, an
unwritable `--ready-file`, an unexpected failure inside one QUIC session (which
the listener isolates and keeps serving; with `--debug` that same failure also
carries the exception message on the peer-aware debug channel). This channel is
**peer-free by construction**: it accepts only non-identifying fields, and
passing a peer field is a programming error that raises rather than logging.
Repeated identical errors are throttled and reported as `suppressed=<n>`, so a
failing path cannot flood the log.

**Opt-in — the full operation log (`debug`).** `--debug` (or
`HSYNC_RENDEZVOUS_DEBUG=1`) adds the whole request life cycle on stderr —
connections opened/closed, frames received, the decision taken, records
created/refreshed/removed, TTL sweeps and refusals — **including the peer
identity** (CID, bucket, IP, port) that makes the log usable for analysis. When
it is enabled the node says so once on the always-on channel
(`warn: peer data logging enabled`).

Neither channel ever writes to disk from the process: without `--debug` no peer
data leaves memory. `--debug` is a **troubleshooting switch, never a deployment
setting**: the lines it emits carry peer identity (CID, bucket, IP, port), and
the shipped units hand stderr to a log the operating system persists (the
journal, a file — `/var/log/hsync-rendezvous.err` on macOS, the WinSW log on
Windows), which would turn that into an on-disk record of peer activity. Enable
it for the session you are diagnosing, then remove it; bound the log retention
there too (`/etc/systemd/journald.conf`: `SystemMaxUse=`, `MaxRetentionSec=`,
then `journalctl -u hsync-rendezvous`; rotate the launchd file with `newsyslog`).

The `--ready-file`/`HSYNC_RENDEZVOUS_READY_FILE` seam writes the process PID to
the given path once at least one listener is bound (and removes it on graceful
shutdown). It carries no peer data and exists so tests and orchestrators can
await readiness deterministically. A path the node cannot write (missing
directory, no permission, or an existing file — even a stale one) fails fast
with exit code 4 and an actionable message instead of a traceback. The Docker
entrypoint removes a stale readiness file before `exec`, so a container killed
ungracefully (`docker kill` timeout → SIGKILL) never leaves the next start
wedged.

## Signals and service manager

The process contract is small: the node is meant to be owned by a supervisor.

| Signal | Effect |
|---|---|
| `SIGINT`, `SIGTERM` | Graceful stop: the listeners close, the readiness file is removed, the process exits 0. |
| `SIGHUP` | Ignored: a hangup (a terminal closed, an SSH session dropped, a PTY torn down) is not a stop request, so an unattended node keeps serving. |

There is no reload path: the TLS identity and the group keys are read at
startup, so a replacement takes a restart (see
[TLS identity & pinning](#tls-identity--pinning)).

Under systemd the unit is `Type=notify` with a watchdog, so the node announces
its state to the service manager:

| Notification | When |
|---|---|
| `READY=1` | Every requested listener is bound — the same condition as `--ready-file`, not the mere existence of the process. |
| `WATCHDOG=1` | Continuously, at half the unit's `WatchdogSec=`: a wedged event loop stops answering and the unit is restarted. |
| `STOPPING=1` | At the start of the teardown, so an intentional stop is not mistaken for a failure. |

Outside systemd (a container without systemd, launchd, Windows, a foreground
run) the notifications are inert no-ops and `--ready-file` stays the readiness
seam for whatever orchestrates the node.

## Metrics

The node can publish **aggregate** counters — never peer data — on three sinks
that all report the same numbers: the service manager's `STATUS=` line, an
optional Prometheus text file, and an optional loopback HTTP endpoint.

| Sink | Enable with | Contract |
|---|---|---|
| `systemctl status` | always, under systemd | shows `STATUS=conn=3/57 peers=1203/1240` |
| Prometheus text file | `--stats-file PATH` | replaced atomically every `--stats-interval` seconds; scrape it with node_exporter's textfile collector |
| HTTP `/metrics` | `--metrics-port PORT` + a bearer token | loopback only, `GET`/`HEAD` on `/metrics`, `Authorization: Bearer TOKEN` |

The endpoint mirrors the sync server's authenticated `/metrics`: the same path
(`REST_METRICS_PATH`, `/metrics`), the same Prometheus content type and
`Authorization: Bearer`, with uniform `401` refusals. The token must be at least
32 characters and is never echoed or logged; a request without it is refused even
on loopback, because loopback is not an authorization boundary (every local user,
a proxy or an SSH tunnel can reach it).

### What the numbers mean

Two populations are reported, and they are **not** the same number.

| Metric | Type | Meaning |
|---|---|---|
| `hsync_rendezvous_peers_current` | gauge | **Clients registered right now** (TTL-bounded) |
| `hsync_rendezvous_peers_peak` | gauge | Highest registered population since the process started |
| `hsync_rendezvous_peers_peak_timestamp_seconds` | gauge | When that peak was reached |
| `hsync_rendezvous_peers_updates_total` | counter | Accepted `register`/`refresh` writes |
| `hsync_rendezvous_peers_expired_total` | counter | Records dropped by the TTL sweep |
| `hsync_rendezvous_connections_current{transport}` | gauge | Open connections by transport (`quic`, `tcp`) |
| `hsync_rendezvous_connections_peak{transport}` | gauge | Highest open-connection level per transport since start |
| `hsync_rendezvous_connections_peak_timestamp_seconds{transport}` | gauge | When that per-transport peak was reached |
| `hsync_rendezvous_connections_total{transport}` | counter | Connections admitted per transport since start |
| `hsync_rendezvous_metrics_requests_total{outcome}` | counter | Requests answered by `/metrics` (`ok`, `unauthorized`, `not_found`, `method_not_allowed`, `rate_limited`, `unavailable`) |
| `hsync_rendezvous_stats_write_errors_total` | counter | Failed stats-file writes |
| `hsync_rendezvous_build_info{version,protocol}` | gauge | Always `1`; identifies the running build |
| `hsync_rendezvous_start_time_seconds` | gauge | Unix time the process started |

`peers` is the count of clients online. `connections{transport}` measures handshake
concurrency instead, because a client opens **one connection per exchange**
(`register`/`refresh`/`query`) and lets it idle out after 30 s: reporting the
connections as "clients connected" would be wrong by an order of magnitude.

Both peaks are **event-exact** (observed when a connection is admitted or a record
changes, never sampled) and never decrease. They cover the lifetime of the
process, so a restart resets them; use the monitoring system for history. A peak
can be inflated by churn (short-lived registrations): that is intended, it is what
capacity planning needs.

The counters are integers in RAM, nothing is persisted, and no label ever carries
a CID, IP, port or bucket: these are the only numbers the node exposes and they
keep the no-log invariant. `peers_current` counts records that are not yet swept,
so it can include entries up to one prune interval (15 s) past their TTL.

## Deploying as a service

[operations.md](operations.md) is the operating guide: supervision, readiness
and watchdog, log bounds, identity backup and rotation, upgrades and the external
reachability probe. This section is the unit reference it builds on.

The [Debian package](getting-started-deb.md) installs and manages the systemd
unit automatically; the [Docker](getting-started-docker.md) and
[installer-script](getting-started-script.md) methods run the node in a
container. The ready-made units below are for a manual [source install](getting-started-source.md):

Ready-made units are in `packaging/`:

| OS | Unit | Install |
|---|---|---|
| <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> Linux | `packaging/systemd/hsync-rendezvous.service` | `sudo cp … /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now hsync-rendezvous` — hardened (DynamicUser, syscall filter); group keys are read from a systemd credential. |
| <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> macOS | `packaging/launchd/it.hsync.rendezvous.plist` | `sudo cp … /Library/LaunchDaemons/ && sudo launchctl rendezvous system …` — group keys are exposed as fd 3 by the embedded shell wrapper. |
| <img src="assets/os/windows.svg" alt="Windows" width="16" height="16"> Windows | `packaging/windows/hsync-rendezvous-service.xml` | WinSW v2: rename `WinSW-x64.exe` to `hsync-rendezvous-service.exe` next to the XML, adjust the venv path, then `.\hsync-rendezvous-service.exe install` + `start`. |

Edit the executable paths inside each unit to the location of your venv.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `configuration error: protected bucket(s) without a group key …` | You declared `--protected-bucket` without provisioning its key: pass `--keys-fd`/`HSYNC_RENDEZVOUS_KEYS_FD` or `--keys-file`/`HSYNC_RENDEZVOUS_KEYS_FILE` with a matching `bucket=<key>` line. |
| `configuration error: private node without any group key …` | You started a private node (`--private` / `HSYNC_RENDEZVOUS_PRIVATE=1`) without provisioning a key: pass a keys source with at least one `bucket=<key>` line. |
| `configuration error: cannot open group keys file …` | `--keys-file` points at a missing or unreadable path: create the file and grant read access to the service account (`LocalService` on Windows). |
| `configuration error: --keys-fd and --keys-file are mutually exclusive` | Pass one key source only. |
| `configuration error: duplicate group key for bucket …` | The keys source lists the same bucket twice: keep exactly one line per bucket. |
| `warn: group keys file permissions are too open` | The `--keys-file` file is group-writable or world-accessible: restrict it to `0600`/`0640` (the node keeps serving). |
| `error: cannot bind the QUIC/UDP listener … — permission denied` (or `the TLS/TCP listener …`) | You bound a privileged port (< 1024, e.g. the 443 default) without root: use `--listen-port 8443` (any port ≥ 1024), run as root, or grant the capability (`sudo setcap cap_net_bind_service=+ep <hsync-rendezvous>`). The systemd unit already grants it. This exit (code 3) happens only when **no** transport binds any port. |
| `error: cannot bind the QUIC/UDP listener … — address already in use` (or `the TLS/TCP listener …`) | Another process (or another node instance) is using that port on **every** enabled transport: stop it, pick a free port with `--listen-port`, or disable the conflicting transport (`--no-tcp` if a co-hosted HTTPS server holds TCP 443). A conflict on **one** transport only is skipped best-effort (the node keeps serving the other). |
| `error: cannot bind the QUIC/UDP listener … — the address is not available` (or `the TLS/TCP listener …`) | `--listen-host` is not a local interface address: use a local IP, or `0.0.0.0` to listen on all of them. |
| Client gets `token_required` | The bucket is gated (declared `--protected-bucket`, or every bucket on a private node) and the client's derived token is missing/wrong — check the group key on the client side. |
| Client gets `rate_limited` | A per-source limit was exceeded (per-IP ~10 req/s admission, 5/min failed tokens, 5/min queries per (IP, bucket), 20/min aggregate queries per IP, 10/min registers per (IP, bucket)); wait for `retry_after` seconds — this counts against the source. |
| Client gets `overloaded` | The node is at its host-derived routing-table ceiling (capacity backpressure, not a client abuse signal); retry after `retry_after` seconds, or prefer another rendezvous. It is not counted against the source. |
| No UPnP mapping | UPnP is off by default; with `--upnp` a router without IGD or a refused mapping keeps the node running stateless and reports it once on the always-on channel (`warn: upnp no igd on lan port=…` or `warn: upnp mapping unavailable reason=…`); publish a public UDP endpoint in another way or leave UPnP disabled. |
| `error: cannot write the readiness file …` (exit code 4) | `--ready-file` points at a path the node cannot create (missing parent directory, no permission, or a stale file that `O_EXCL` refuses to overwrite): create/remove the path or point the flag elsewhere. |
| `warn: upnp mapping unavailable` / `error: session failed` in the logs | Always-on diagnostics, not peer data: the node degraded (no UPnP mapping) or one session failed unexpectedly and was isolated. Both are emitted without `--debug` and never contain a peer identity. |
| Need to see what the node is doing | Operational warnings and errors are already on stderr (and in the service log). Start with `--debug` (or `HSYNC_RENDEZVOUS_DEBUG=1`) to add the full operation log, peer identity included. |
