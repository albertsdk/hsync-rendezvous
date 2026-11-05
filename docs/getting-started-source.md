# Getting Started — Method 6: From source

Run the node directly from a clone as a Python service — for development, or a
host where you control the toolchain. This is the most involved method; for a
managed host prefer the [installer script](getting-started-script.md) or the
[Debian package](getting-started-deb.md).

## Prerequisites

- Python 3.12–3.14
- Poetry
- The `hsync-common` repository checked out as a sibling of `hsync-rendezvous`
  (a path dependency of the Python v1)

## Install and run

### Quick path (`run.sh`)

With both repositories cloned side by side:

```bash
git clone https://github.com/albertsdk/hsync-rendezvous.git hsync-rendezvous
git clone https://github.com/albertsdk/hsync-common.git hsync-common
cd hsync-rendezvous
./run.sh run
```

`run.sh` creates the in-project virtualenv on first use, installs the main
dependencies, and starts the node, forwarding any argument to `hsync-rendezvous`
(`./run.sh --help`). It stops with a clear message if `../hsync-common` is
missing.

> Port **443 is a privileged port** (below 1024) on both UDP and TCP. To bind it,
> run as root or grant `CAP_NET_BIND_SERVICE`; in development prefer an
> unprivileged port, e.g. `./run.sh run --listen-port 8443`.

From source the node has the same features as any other method: protected
buckets (`--protected-bucket`, repeatable, with a group-keys file) and private
mode (`--private`) are described in the shared reference
[usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file) and
[usage.md → Private node](usage.md#private-node-authenticated-rendezvous).

### Native commands

The same steps, spelled out (the virtualenv is created by `run.sh`):

```bash
cd python
.venv/bin/hsync-rendezvous run
```

On first run the node creates a persistent identity at
`$HSYNC_STATE_DIR/rendezvous/identity.pem` (`$XDG_STATE_HOME/hsync/rendezvous/identity.pem`
when `HSYNC_STATE_DIR` is unset; override with `--identity PATH`),
so its fingerprint is stable across restarts and clients can pin it. Read it
with `hsync-rendezvous identity show` (add the same `--identity PATH` when you
overrode it), and use `--ephemeral` for a throwaway node that keeps the identity
in memory.

Verify it started (another terminal):

```bash
cd python
.venv/bin/hsync-rendezvous identity show
```

### Serve a second port (optional)

Clients whose network blocks port 443 on one transport can still reach the node
if it listens on more than one port. Listen on 443 **and** 53 (the node serves
QUIC/UDP and TLS/TCP on each port; open both in the host firewall):

```bash
cd python
.venv/bin/hsync-rendezvous run --listen-ports 443,53
```

The ports share one routing table, so a peer registered on one port is
visible to a query on another. See `--listen-ports` in
[usage.md](usage.md#run-options).

## Standalone binary (no Python on the target)

`compile.sh` freezes the node into a self-contained executable:

```bash
./compile.sh
# → dist/<os>-<arch>/hsync-rendezvous
./dist/linux-amd64/hsync-rendezvous --version
```

Raspberry Pi OS executables (`armhf`/`arm64`) are cross-built inside Docker on
Debian 12 (bookworm); the produced binaries require `libc6 >= 2.35`: use
Raspberry Pi OS **Bookworm** or newer (Bullseye is glibc 2.31 and cannot run
them):

```bash
./compile.sh -t rpi
# → dist/rpi/armhf/hsync-rendezvous and dist/rpi/arm64/hsync-rendezvous
```

`native` embeds the host Python and its C library, so a binary copied to a
machine with an older glibc refuses to start; on another machine use the
[Debian package](getting-started-deb.md) instead.

## Use a service manager for an always-on node

For a managed host, run the node with systemd (or launchd/Windows) instead of an
interactive terminal:

```bash
sudo install -d -m 0750 /etc/hsync-rendezvous
# The unit's LoadCredential= sources must exist or the service fails to start:
# group-keys empty = open mode; metrics-token empty = metrics endpoint off.
sudo install -m 0640 -o root -g root /dev/null /etc/hsync-rendezvous/group-keys
sudo install -m 0640 -o root -g root /dev/null /etc/hsync-rendezvous/metrics-token
sudo install -m 0640 -o root -g root /path/to/group-keys \
    /etc/hsync-rendezvous/group-keys   # protected buckets (overwrites the empty file)
sudo cp packaging/systemd/hsync-rendezvous.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hsync-rendezvous.service
```

Edit the executable path inside the unit to your venv or binary. macOS
(`packaging/launchd/`) and Windows (`packaging/windows/`) units are provided
too; the unit reference is
[usage.md → Deploying as a service](usage.md#deploying-as-a-service) and the
operating procedures (watchdog, log bounds, identity backup and rotation,
upgrades, reachability probe) are in [operations.md](operations.md).

## Update

```bash
cd /path/to/hsync-rendezvous
git pull
./run.sh run
```

The persistent identity under the state directory is preserved, so the
fingerprint clients pinned does not change.

## Next

- Prefer a packaged install? [Debian package](getting-started-deb.md).
- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
