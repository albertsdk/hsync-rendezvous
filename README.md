<p align="center">
  <img src="docs/assets/hsync-logo-horizontal.svg" alt="HSYNC logo" width="300">
</p>

# HSYNC Rendezvous

**HSYNC Rendezvous** is the optional rendezvous node that lets HSYNC peers find
each other over the Internet when they are **not** on the same local network. It
is a stateless, no-log meeting point: it tells P2P clients which peers are
online without ever storing anything, speaking the `rdv/1` protocol over two
interchangeable transports — QUIC/UDP and TLS/TCP (port 443 by default on both).
Think of it as an **address book, not a post office**: it helps
your devices find each other. File data normally flows directly between peers;
two that no NAT mapping can reach fall back to relaying their encrypted traffic
through the node (see [Usage](docs/usage.md)).

> New to HSYNC? Start with the [HSYNC Ecosystem](https://github.com/albertsdk/hsync/blob/main/README.md) for an overview of the platform before deploying a rendezvous.

**Why it exists:** the [HSYNC Client](https://github.com/albertsdk/hsync-client)'s
[p2p Mode](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-mode.md)
discovers peers over mDNS on the local network. A rendezvous extends that same
mode across networks: same election, same transport, same peer-to-peer data
plane — only rendezvous differs.

**Status:** v1 **complete and stable** (Python + aioquic): packaged, tested,
and the implementation clients currently talk to. A C port is
planned as an **additive v2** for higher handshake throughput, not a
prerequisite — this is a **multi-language** repository: one protocol, several
implementations sharing the same spec and fixtures (see the
[repository layout](CONTRIBUTING.md#repository-layout)).

> 👉 **Operational Advisory:** the node's TLS identity is its only persistent
> artifact, so distribute its fingerprint to clients (or let them confirm it once
> at the prompt) and pin it — that is what makes a public node verifiably yours.

---

[![License: BSD 3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-brightgreen.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/albertsdk/hsync-rendezvous)](https://github.com/albertsdk/hsync-rendezvous/releases/latest)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![C11 (planned)](https://img.shields.io/badge/C-11_(planned)-A8B9CC.svg)](c/)
[![Status: v1](https://img.shields.io/badge/Status-v1-yellow.svg)](docs/README.md)

---

## What you can do with HSYNC Rendezvous

- **Extend p2p Mode across networks** — let devices that are not on the same
  LAN discover each other, with no central server holding the files.
- **Run a private, closed network** — start the node with `--private` and every
  frame is authenticated against a group key: no accounts, nothing stored.
- **Keep rendezvous stateless and no-log** — clients register and query
  candidates; the routing table is RAM-only with a 60-second TTL, and file data
  flows only between peers (through the relay, still opaque TLS, only when no
  peer can be reached directly).
  
## What it is

HSYNC syncs files peer-to-peer without a central server. On a single local
network peers find each other with mDNS; when devices are spread across the
Internet they need a rendezvous point. The rendezvous is exactly that, and nothing
more:

- Clients **register** their endpoint candidate list (the NAT-mapped public
  address and the local/LAN address) with the node every ~30 s and receive the
  observed endpoint back in an `ack`.
- Clients **query** the node and get a random sample of the peers currently
  registered in their bucket, each with the candidate endpoints the node relays
  (the first four of the registered list); the requester tries the candidates,
  preferring one reachable from its own network.
- The routing table is **RAM-only** with a 60-second TTL: stop the process and
  every trace of the network is gone.

It is a rendezvous point and a **relay of opaque TLS** by default: two peers
that no inbound NAT mapping reaches (mobile carrier-grade NAT, a hotspot behind
a carrier) can still run their data plane through the node, which forwards their
bytes without ever terminating or inspecting that TLS — content, file names and
credentials stay invisible to it. The relay is on by default (disable it with
`--no-relay`); with the relay off, file data flows only between directly
reachable peers.

A node run as-is is a **public** rendezvous point for anyone who knows its
hostname. Started with `--private` it becomes the closed rendezvous point of a
single community instead: every frame is authenticated against a group key, there
is no account to create and nothing is stored — a **private, pseudonymous P2P
network over the Internet** whose file data still flows only between peers. See
[Private node](docs/usage.md#private-node-authenticated-rendezvous) and the
[privacy and anonymity model](docs/usage.md#privacy-and-anonymity-model).

## When you need it

**You need a rendezvous when:**

* your P2P group spans different networks — home ↔ office, two branches, a laptop on mobile data — and you don't want a central server holding the files;
* you want a private, closed group: start the node with `--private`, so every
  frame is authenticated against a group key — see [Private node](docs/usage.md#private-node-authenticated-rendezvous).

**You don't need it when:**

* all your devices are on the same local network — plain `hsync p2p` discovers them via mDNS;
* your devices sync through an [HSYNC Server](https://github.com/albertsdk/hsync-server) (Server Mode), which already acts as their meeting point.

## Getting started

Pick an install method and follow it to a running node:

- [Installer script](docs/getting-started-script.md) — one `curl` command and the
  released container image;
- [Docker / Compose](docs/getting-started-docker.md) — manual container setup;
- [Debian package](docs/getting-started-deb.md) — `.deb` with a hardened systemd unit;
- [RPM package](docs/getting-started-rpm.md) — `.rpm` for RHEL/Rocky/Alma/Fedora;
- [Windows installer](docs/getting-started-windows.md) — per-machine service installer;
- [From source](docs/getting-started-source.md) — clone and run.

The [Getting Started](docs/getting-started.md) chooser compares the methods; point
clients at the node with the `hsync p2p` rendezvous argument (`hsync p2p <host>`)
— see the client
[p2p rendezvous guide](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-rendezvous.md).

## Design invariants

- **No-log** — the process never writes peer data (IPs, CIDs, timestamps) to
  disk; the only on-disk artifact is the node's own TLS key+cert, kept by default
  (ECDSA P-256, `0600`) so its fingerprint is stable and pin-able across restarts.
  `--ephemeral` replaces it with an in-memory identity for read-only filesystems
  or throwaway nodes. Diagnostics on stderr come in two channels: an always-on,
  **peer-free** operational one (warnings/errors about the node itself) and the
  opt-in `--debug` operation log, the only one that can contain peer identity.
- **No telemetry** — the node never phones home: no usage data, analytics or
  statistics leave the process.
- **Zero-knowledge / protected buckets** — group tokens are HMAC-SHA256
  capabilities compared in constant time; refusals are uniform and never reveal
  whether a bucket exists.
- **Rigid schema** — every `rdv/1` frame rejects unknown fields; malformed
  frames are silently dropped, never reinterpreted.
- **One wire protocol** — `protocol-spec/rdv-1.md` is the single source of
  truth; every implementation must be byte-identical on the wire.

## Documentation

| Document | What it covers |
| -------- | -------------- |
| [Getting Started](docs/getting-started.md) | Choose an install method (installer script, Docker, `.deb`, source) and run the node |
| [Usage reference](docs/usage.md) | `run` options, environment variables, group keys, private nodes, privacy/security model, services, diagnostics |
| [Metrics reference](docs/metrics.md) | Every aggregate the node exposes, its labels and meaning, capacity planning, PromQL queries and alert rules |
| [Operations](docs/operations.md) | Supervision, watchdog, log bounds, metric sinks, identity backup/rotation, upgrades, reachability probe |
| [`rdv/1` specification](protocol-spec/rdv-1.md) | Wire protocol — the single source of truth |
| [Internal wiki](llm-wiki/README.md) | Architecture, data models, decisions, hard invariants |
| [Benchmarks](bench/README.md) | L1–L5 measurement scope and methodology |
| [Black-box suite](tests/README.md) | Language-neutral wire/CLI contract tests |
| [Contributing](CONTRIBUTING.md) | Development setup, toolchain, tests and contribution guidelines |
| [Report an issue](https://github.com/albertsdk/hsync-rendezvous/issues) | Open development and bug tracking |

## Associated Ecosystem Components

The other components of the HSYNC ecosystem:

- [HSYNC Main](https://github.com/albertsdk/hsync/blob/main/README.md) — Umbrella repository and project overview.
- [HSYNC Desktop](https://github.com/albertsdk/hsync-desktop/blob/main/README.md) — Desktop GUI front-end.
- [HSYNC Server](https://github.com/albertsdk/hsync-server/blob/main/README.md) — Central sync hub: REST API, WebSocket relay, file storage.
- [HSYNC Client](https://github.com/albertsdk/hsync-client/blob/main/README.md) — Reference client agent: the `hsync` CLI and its sync engine.
- [HSYNC Common](https://github.com/albertsdk/hsync-common/blob/main/README.md) — Shared library: data models, protocol, delta transfer, hashing.
- [HSYNC Android](https://github.com/albertsdk/hsync-android/blob/main/README.md) — Android client app. *(in development)*

## Security & Vulnerability Reporting

The rendezvous sits at the Internet edge, so security reports are taken seriously.
Please use GitHub's **Private Vulnerability Reporting** rather than a public issue:

👉 **[Report a vulnerability](https://github.com/albertsdk/hsync-rendezvous/security/advisories/new)**

See our [Security Policy](SECURITY.md) for supported versions and hardening guidance.

## 🙋‍♂️ A note from the maintainer

This project was born out of the need for a system capable of replicating the contents of a folder from a PC or Android device to a NAS, primarily for backup purposes. Several solutions were already available, but I couldn't find one that met all my requirements. This led to the somewhat questionable decision to develop one from scratch, while also providing an opportunity to gain a deeper understanding of programming languages, algorithms, frameworks, and related technologies.

Originally conceived as a hobby project, HSYNC has been under continuous development ever since. I believe it has now evolved to the point where its capabilities are comparable to those of commercial solutions, while also offering some distinctive features. As a result, it may also be suitable for deployment in certain production environments.

HSYNC is a passion project that I primarily develop and maintain in my spare time. Please keep this in mind when interacting with the project: we're all doing our best to build something great together, but this is not a paid, full-time job for any of us.

## Disclaimer

> [!WARNING]
> **The rendezvous exposes a network service.** Misconfiguration, software defects
> or unexpected conditions may expose your rendezvous metadata or make the node
> unavailable. **Use at your own risk**, run it in a controlled environment, and
> review the privacy model in the [Usage reference](docs/usage.md#privacy-and-anonymity-model).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY — including, without limitation, any direct, indirect, incidental, special, exemplary, or consequential damages, loss of data, or business interruption — WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This disclaimer supplements, and does not replace, the warranty disclaimer and limitation of liability provisions of the [BSD 3-Clause License](LICENSE), which govern this software.

## License

Distributed under the [BSD 3-Clause License](LICENSE).
