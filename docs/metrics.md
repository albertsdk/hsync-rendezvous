# Metrics — reference

The node publishes **aggregate counters only**. No metric ever carries a CID, a
bucket, an IP address or a port: the rendezvous is no-log, so these numbers are
the only operational data it exposes. They are integers in RAM, updated where the
event happens, and nothing is persisted — a restart resets them (long-term
history belongs to your monitoring system).

Three sinks report the same numbers. Enabling them, minting the bearer token and
wiring a scrape is the operating procedure in
[operations.md → Measure the node](operations.md#measure-the-node); this page is
the reference for what the numbers mean.

| Sink | Contract |
|---|---|
| `systemctl status` | always on under systemd; the `STATUS=` line carries a one-line live summary |
| Prometheus text file | the whole exposition, replaced atomically on the interval you set |
| HTTP `/metrics` | loopback only, `GET`/`HEAD` on `/metrics`, `Authorization: Bearer TOKEN`; Prometheus text format |

The endpoint is loopback-only **and** bearer-authenticated: loopback is not an
authorisation boundary (every local user, a proxy or an SSH tunnel can reach it),
so the token is mandatory and is never logged or echoed. Every request is
answered with a closed status (`ok`, `unauthorized`, `not_found`,
`method_not_allowed`, `rate_limited`, `unavailable`).

## Metric families

Every label set is **closed**: an unknown value cannot create a series, and every
value of a closed set is always exposed — a dashboard never loses a series
because it has not been hit yet on this process.

### Identity and uptime

| Metric | Type | Meaning |
|---|---|---|
| `hsync_rendezvous_build_info{version,protocol}` | gauge | Always `1`; identifies the running build and the wire protocol |
| `hsync_rendezvous_start_time_seconds` | gauge | Unix time the process started |

### Peers (the routing table)

| Metric | Type | Meaning |
|---|---|---|
| `hsync_rendezvous_peers_current` | gauge | Peers registered right now (TTL-bounded) |
| `hsync_rendezvous_peers_peak` | gauge | Highest registered population since the process started |
| `hsync_rendezvous_peers_peak_timestamp_seconds` | gauge | When that peak was reached |
| `hsync_rendezvous_peers_updates_total` | counter | Accepted `register`/`refresh` writes |
| `hsync_rendezvous_peers_expired_total` | counter | Records dropped by the TTL sweep |

`peers_current` counts records that are not swept yet, so it can include entries
up to one prune interval past their TTL.

### Connections (the transport)

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hsync_rendezvous_connections_current` | gauge | `transport` | Open connections right now |
| `hsync_rendezvous_connections_peak` | gauge | `transport` | Highest open-connection level since start |
| `hsync_rendezvous_connections_peak_timestamp_seconds` | gauge | `transport` | When that peak was reached |
| `hsync_rendezvous_connections_total` | counter | `transport` | Connections admitted since start |

`transport` is `quic` or `tcp`; both series are always exposed, so a node serving
only one transport still reports `0` for the other.

**Peers and connections are different populations.** A client opens one
connection per exchange (`register`, `refresh`, `query`) and lets it idle out
after 30 s, so `connections` measures handshake concurrency and churn, not the
number of clients: reading it as "clients connected" would be wrong by an order
of magnitude. Use `peers_current` for the population.

### Relay (opaque byte forwarding)

| Metric | Type | Meaning |
|---|---|---|
| `hsync_rendezvous_relay_sessions_current` | gauge | Relayed sessions pairing two peers right now |
| `hsync_rendezvous_relay_sessions_peak` | gauge | Highest relayed-session level since start |
| `hsync_rendezvous_relay_sessions_peak_timestamp_seconds` | gauge | When that peak was reached |
| `hsync_rendezvous_relay_sessions_total` | counter | Relayed sessions opened |
| `hsync_rendezvous_relay_bytes_total` | counter | Bytes forwarded by the relay |

A node started with `--no-relay` keeps all of these at `0`.

### Refusals, rate limits and drops

These three families answer three different questions, and no one of them can be
replaced by another:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hsync_rendezvous_refusals_total` | counter | `reason` | Refusal frames the node **answered**, by `rdv/1` error reason |
| `hsync_rendezvous_limit_hits_total` | counter | `limiter` | Rate-limit refusals, by **the budget that ran dry** |
| `hsync_rendezvous_drops_total` | counter | `reason` | Frames the node **discarded without answering**, by reason |

* `reason` (refusals) is the `rdv/1` error domain: `token_required`
  (authorization — the bucket is gated and the token is missing or wrong),
  `rate_limited` (a per-source budget is exhausted; `retry_after` tells the
  client how long to wait), `overloaded` (the node is at its host-derived
  capacity ceiling — backpressure, **not** client abuse) or `relay_unavailable`
  (the data relay is disabled on this node).
* `limiter` (limit hits) names the budget: `ops_ip` (per-IP frame admission),
  `query_pair` / `query_ip` (query per `(IP, bucket)` / per IP),
  `register_pair`, `relay_connect_pair`, `relay_listen_pair`, `bad_token_ip`
  (failed-token attempts) or `parse_ip` (malformed frames).
* `reason` (drops) is one of `invalid_frame`, `oversized_frame`,
  `pre_parse_gate` (the malformed-frame budget is exhausted, so the source's
  frames are dropped before validation), `foreign_source` (a source tried to
  touch a record it does not own) or `relay_attach_refused`.

A refusal is visible to the client; a drop is silent by design (there is no
oracle to hand out). `limit_hits` is the only series that tells you **which**
budget produced a `rate_limited`, which is what you need to tell a limit that is
clipping legitimate clients from a source that is misbehaving.

### The exposition endpoint itself

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `hsync_rendezvous_metrics_requests_total` | counter | `outcome` | Requests answered by `/metrics` |
| `hsync_rendezvous_stats_write_errors_total` | counter | — | Failed writes of the Prometheus text file |

## Capacity planning

The node sizes its own memory ceilings (routing table, limiter key maps,
connections and relay sessions) from the RAM and CPU it can see, and answers
`overloaded` when a ceiling is reached. The useful signals are therefore:

| Question | Metric |
|---|---|
| How many clients do I serve, now and at peak? | `peers_current`, `peers_peak` |
| How much handshake concurrency do they create? | `connections_peak{transport}` |
| Am I refusing legitimate clients, and for which budget? | `refusals_total{reason="rate_limited"}`, `limit_hits_total` |
| Am I at the node's capacity? | `refusals_total{reason="overloaded"}` |
| Is churn (TTL expiry) driving the population? | `rate(peers_expired_total[5m])` |
| Is the relay paying for itself? | `relay_sessions_total`, `relay_bytes_total` |

`rate_limited` refusals do not grow with the client population when the node is
sized correctly: the per-source budgets admit the fastest cadence a client may
configure, several clients per bucket and a whole address sharing one public IP.
A rising `limit_hits_total{limiter="query_ip"}` or `{limiter="register_pair"}`
means a single source is asking for more than its share — usually a
misconfigured client cadence, not the node. A rising
`refusals_total{reason="overloaded"}` means the **node**, not the source, needs
more memory or more nodes.

## Queries and alerts

```text
# clients online now, and the peak since the last restart
hsync_rendezvous_peers_current
hsync_rendezvous_peers_peak

# a week-long peak, independent of restarts
max_over_time(hsync_rendezvous_peers_current[7d])

# handshakes per second and TTL churn
rate(hsync_rendezvous_connections_total[5m])
rate(hsync_rendezvous_peers_expired_total[5m])

# refusals by reason, and which budget is doing the refusing
sum by (reason) (rate(hsync_rendezvous_refusals_total[5m]))
sum by (limiter) (rate(hsync_rendezvous_limit_hits_total[5m]))

# silent drops (malformed frames, oversized frames, ownership)
sum by (reason) (rate(hsync_rendezvous_drops_total[5m]))
```

Two alerts cover the operational floor: capacity backpressure, and a node that
stopped answering `/metrics`.

```yaml
groups:
  - name: hsync-rendezvous
    rules:
      - alert: HsyncRendezvousAtCapacity
        expr: rate(hsync_rendezvous_refusals_total{reason="overloaded"}[5m]) > 0
        for: 10m
        annotations:
          summary: The node refuses registrations at its capacity ceiling
          description: Raise the memory budget or add another rendezvous node.
      - alert: HsyncRendezvousDown
        expr: up{job="hsync-rendezvous"} == 0
        for: 5m
```

## Guarantees

* **Fixed cardinality.** Every label is a closed set, so the exposition cannot
  grow with caller input and a scrape stays cheap.
* **No peer data.** No CID, bucket, source address or port is ever a metric or a
  label. These aggregates are the only numbers the node exposes.
* **RAM only.** Nothing here is written unless you point `--stats-file` at a
  path, and that file holds exactly this exposition.
* **Event-exact peaks.** A peak is observed when a connection is admitted or a
  record changes, never sampled: a concurrency spike is shorter than any sane
  sampling interval. A peak never decreases and covers the lifetime of the
  process, so a restart resets it.
