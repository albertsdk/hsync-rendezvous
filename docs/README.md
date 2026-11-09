# HSYNC Rendezvous — Welcome

`hsync-rendezvous` is the Internet rendezvous node of the HSYNC sync network: it
tells P2P clients which peers are currently online, without storing anything.
It runs a no-log, zero-knowledge rendezvous service speaking the `rdv/1` protocol
over two interchangeable transports — QUIC/UDP and TLS/TCP (port 443 by default):
the routing table lives only in RAM, and the node's
own TLS key is its only persistent artifact (an optional readiness PID file is
written only when `--ready-file` is set).

> **Status**: v1 complete and stable (Python). The `rdv/1` protocol is versioned
> and specified in `protocol-spec/rdv-1.md`.

Run it as-is and it is a **public** rendezvous point. Run it with `--private` and
it becomes the closed rendezvous point of a single community: every frame is
authenticated against a group key, there is no account to create and nothing is
stored — a **private, pseudonymous P2P network over the Internet** whose file data
still flows only between peers.

## How it works in one paragraph

A client registers itself with the node every 30 seconds and gets back an `ack`
with its observed public (NAT-mapped) endpoint; its full endpoint candidate list
is relayed to querying peers. To find peers, clients query the node and receive a
random sample of the currently registered peers in their bucket. Everything lives
in RAM with a 60-second TTL: stop the process and every trace of your network is
gone. The node also relays the peers' opaque TLS by default, so two peers that
no NAT mapping reaches can still run their data plane through it (disable with
`--no-relay`).

## Requirements

- <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> <img src="assets/os/windows.svg" alt="Windows" width="16" height="16"> Linux, macOS or Windows, following the method's own prerequisites
- Port 443 (or any other port) reachable from the Internet over UDP and/or TCP —
  the node serves QUIC/UDP and TLS/TCP on the same ports by default; the 443
  default is privileged: run as root, grant `CAP_NET_BIND_SERVICE` (the `.deb`
  and systemd unit do), or use a port ≥ 1024 (e.g. `--listen-port 8443`)
- Optional: a UPnP-capable router for zero-touch port mapping on both transports
  (opt in with `--upnp`)
- Optional: a **second** inbound port (e.g. 53) so clients whose network blocks
  443 on one transport can still reach the node — see `--listen-ports` in
  [usage.md](usage.md#run-options)

Python 3.12–3.14 and Poetry are needed **only** for the
[from-source](getting-started-source.md) method: the packages, the Windows
installer and the container image bundle the runtime.

## Start here

This guide is organised as a linear journey; pick the step that matches where
you are.

### 1. Choose your install method

Pick the method that matches your host in the
[Getting Started chooser](getting-started.md): installer script, Docker/Compose,
Debian/Ubuntu package, RPM package, Windows installer, or from source. That page
is the single source of truth for the comparison table.

### 2. Configure the node

- **Public node** — the default; no configuration.
- **Private node / protected buckets** — provision group keys; see
  [usage.md → Private node](usage.md#private-node-authenticated-rendezvous) and
  [usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file).

### 3. Point clients at it

Pass the node to the client's `p2p` command (`hsync p2p <host>`; with the group
key for a private node). The client side is covered by the
[client p2p rendezvous guide](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-rendezvous.md).

### 4. Operate it

Supervision, readiness and watchdog, log bounds, aggregate metrics, identity
backup and rotation, upgrades and the external reachability probe:
[operations.md](operations.md). What every metric means — and how to tell a
limit clipping legitimate clients from abuse — is [metrics.md](metrics.md).

### 5. Reference & internals

| Document | Content |
|---|---|
| [usage.md](usage.md) | CLI reference, protected buckets and private nodes, keys provisioning, privacy/security model, signals and the OS service units |
| [metrics.md](metrics.md) | Metric reference: the three sinks, every family with its labels and meaning, capacity planning, PromQL queries and alert rules |
| [operations.md](operations.md) | Operating how-to: systemd lifecycle, watchdog, log bounds, aggregate metrics, identity backup/rotation, upgrades, reachability probe |
| [faq.md](faq.md) | Operational FAQ: certificate pin/TOFU mismatches, stable identity, client-side recovery, signals |
| `protocol-spec/rdv-1.md` | Wire protocol specification |
