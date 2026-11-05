# HSYNC Rendezvous — Getting Started

`hsync-rendezvous` is the Internet rendezvous node of the HSYNC sync network: it
tells P2P clients which peers are currently online without storing anything. It
speaks the `rdv/1` protocol over two interchangeable transports — QUIC/UDP and
TLS/TCP (port 443 by default).

Pick **one** installation method below and follow it to a running node. The
methods are ordered from the simplest and most immediate to the most involved.

| # | Method | Platform | Best for | Guide |
| - | ------ | -------- | -------- | ----- |
| 1 | **Installer script** (`install.sh` via `curl`) | <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> | Least setup on a host with Docker: one command, TLS identity persisted | [Install with the script](getting-started-script.md) |
| 2 | **Docker / Compose** (manual) | <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> | You already manage containers, or want to build the image yourself | [Docker](getting-started-docker.md) |
| 3 | **Debian/Ubuntu package** (`.deb`) | <img src="assets/os/debian.svg" alt="Debian" width="16" height="16"> <img src="assets/os/ubuntu.svg" alt="Ubuntu" width="16" height="16"> | A Debian/Ubuntu host without Docker, managed by systemd | [Debian package](getting-started-deb.md) |
| 4 | **RPM package** (`.rpm`) | <img src="assets/os/redhat.svg" alt="Red Hat" width="16" height="16"> <img src="assets/os/fedora.svg" alt="Fedora" width="16" height="16"> | A RHEL/Rocky/Alma/Fedora host without Docker, managed by systemd | [RPM package](getting-started-rpm.md) |
| 5 | **Windows installer** (`.exe`) | <img src="assets/os/windows.svg" alt="Windows" width="16" height="16"> | A Windows Server x64 host: per-machine install, registers a Windows service | [Windows installer](getting-started-windows.md) |
| 6 | **From source** (clone and run) |  | Development, or a host where you control the toolchain | [Run from source](getting-started-source.md) |

All methods result in the same node. The node serves `rdv/1` over **QUIC/UDP
and TLS/TCP** on the same ports; the port (443 by default) must be reachable
from the Internet on UDP and/or TCP (ports below 1024 need elevated
privileges — the `.deb` systemd unit grants `CAP_NET_BIND_SERVICE`, the
container binds an unprivileged port internally). The node can also listen on
**several** ports at once (both transports on each), so a client whose network
blocks port 443 on one transport can still reach it on another port
(e.g. 443 + 53) — see `--listen-ports` in
[usage.md](usage.md#run-options).

## Requirements (all methods)

- Port 443 (or another port) reachable from the Internet over UDP and/or TCP —
  the node serves QUIC/UDP and TLS/TCP on the same ports by default
- Optional: a UPnP-capable router for zero-touch port mapping on both transports
  (opt in with `--upnp`)
- Optional: a **second** inbound port (e.g. 53) if some clients' networks block
  443 on one transport — see `--listen-ports` in [usage.md](usage.md#run-options)

## How it works in one paragraph

A client registers itself with the node every 30 seconds and gets back an `ack`
with its observed public endpoint; its full endpoint candidate list is relayed
to querying peers. To find peers, clients query the node and receive a random
sample of the currently registered peers in their bucket. Everything lives in
RAM with a 60-second TTL: stop the process and every trace of your network is
gone.

## Next

- Run it as-is for a **public** rendezvous point, or with `--private` for the
  closed rendezvous point of a community — see
  [usage.md](usage.md#private-node-authenticated-rendezvous).
- Point clients at it with the `hsync p2p` rendezvous argument (`hsync p2p <host>`)
  ([client p2p rendezvous guide](https://github.com/albertsdk/hsync-client/blob/main/docs/p2p-rendezvous.md)).
