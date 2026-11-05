# Getting Started — Method 3: Debian/Ubuntu package

The `.deb` installs the node as a hardened systemd service under a dynamic user
with `CAP_NET_BIND_SERVICE` (so it can bind port 443 on UDP and TCP), and provisions group keys
as a systemd credential. No Docker and no Python are required.

> The packages are built on Debian 12 (base glibc 2.36); the produced package
> requires `libc6 >= 2.35`, so Ubuntu 22.04/24.04 LTS and Debian 12+ run it.

## Prerequisites

- <img src="assets/os/debian.svg" alt="Debian" width="16" height="16"> <img src="assets/os/ubuntu.svg" alt="Ubuntu" width="16" height="16"> Debian or Ubuntu, `amd64`, `arm64` or `armhf`
- A root shell or `sudo`
- A port reachable from the Internet (443 by default) over UDP and/or TCP — QUIC uses UDP, TLS/TCP uses TCP

## Install

### From the release (recommended)

Download the latest package for your architecture and install it:

```bash
curl -fLO "https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/hsync-rendezvous-amd64.deb"
sudo dpkg -i hsync-rendezvous-amd64.deb
sudo apt install -f
```

The URL always points to the **latest stable** release; use `arm64` or `armhf`
instead of `amd64` on those architectures. To pin a version, use
`https://github.com/albertsdk/hsync-rendezvous/releases/download/vX.Y.Z/hsync-rendezvous_<version>_<arch>.deb`.

### Build from the checkout

From the `hsync-rendezvous` checkout — `-t deb` builds for the host architecture
and needs **no Docker** (the host must provide `dpkg-shlibdeps` so the `libc6`
dependency is computed):

```bash
./compile.sh -t deb
# → dist/deb/hsync-rendezvous_<ver>_<arch>.deb
```

`./compile.sh -t deb-all` cross-builds the `amd64`, `arm64` and `armhf` packages
inside Docker (needs Docker plus the qemu-user-static binfmt handlers).

## Provision group keys (protected buckets / private node)

Group keys are a secret provisioned by the administrator, never shipped in the
package. The install creates `/etc/hsync-rendezvous/group-keys` **empty**, which
means open mode (no protected buckets); the service unit reads it as a systemd
credential. Provision the keys over it:

```bash
sudo install -m 0640 /path/to/group-keys /etc/hsync-rendezvous/group-keys
```

The keys are read **once at startup**: if the node is already running, restart the
service (`sudo systemctl restart hsync-rendezvous`) to load them.

The file has one `bucket=<hex-group-key>` line per protected bucket (comments
and blank lines are ignored; a duplicate bucket is a configuration error).
Mint each key with `openssl rand -hex 32` — a key shorter than 32 characters is
refused — and keep the file root-only. An example with two protected buckets:

```text
# one bucket=<hex-group-key> line per protected bucket
shared=378767051d3c551e615922cbffb543563a93bbf39d615a2c46389c2f6b246068
home=63379453eeb327abf615e2e89aa3921fb4c20edf11a12a260058ed299dc153cb
```

The full format, the client-side token derivation and the rotation procedure
live in [usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file) and
[usage.md → Provisioning and key rotation](usage.md#provisioning-and-key-rotation).

A drop-in
cannot append an argument to `ExecStart`, so replace the whole command while
keeping the identity path, the keys source and the credential redirection.
`--protected-bucket` is repeatable: pass it once per bucket to protect
(`--protected-bucket shared --protected-bucket home`):

```bash
sudo systemctl edit hsync-rendezvous.service
```

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'exec /usr/bin/hsync-rendezvous run --listen-host 0.0.0.0 --listen-port 443 --identity /var/lib/hsync-rendezvous/identity.pem --protected-bucket BUCKET --keys-fd 5 5<"$CREDENTIALS_DIRECTORY/group-keys"'
```

For a fully private node (every bucket gated), an environment drop-in is enough
and keeps the unit's command untouched:

```ini
[Service]
Environment=HSYNC_RENDEZVOUS_PRIVATE=1
```

What `--private` changes — the one-switch equivalent of a `--protected-bucket`
for every provisioned bucket, plus `leave` gating and the empty-keys-file
refusal — is in the shared reference
[usage.md → Private node](usage.md#private-node-authenticated-rendezvous).

## Start the service

The package never enables the service automatically (opt-in start):

```bash
sudo systemctl enable --now hsync-rendezvous.service
sudo systemctl status hsync-rendezvous.service
```

## Optional: serve a second port

If some clients' networks block port 443 on one transport, the node can also listen on 53: the
two ports share one routing table, so a peer registered on one is visible to a
query on the other. Both QUIC/UDP and TLS/TCP are served on each port. The
packaged unit pins a single port, so override its
command with a drop-in:

```bash
sudo systemctl edit hsync-rendezvous.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/hsync-rendezvous run --listen-host 0.0.0.0 --listen-ports 443,53 --identity /var/lib/hsync-rendezvous/identity.pem
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart hsync-rendezvous.service
```

Open port 53 (UDP and TCP) in the host firewall too, and free that port if the local resolver
already holds it. If you provisioned group keys, this override **loses** the
unit's automatic `--keys-fd`: keep `LoadCredential=` and append
`--keys-fd 5 5<"$CREDENTIALS_DIRECTORY/group-keys"` to the command (as in the
protected-bucket example above). See `--listen-ports` in
[usage.md](usage.md#run-options).

## Verify the node is running

```bash
sudo journalctl -u hsync-rendezvous.service
sudo hsync-rendezvous identity show --identity /var/lib/hsync-rendezvous/identity.pem
# → sha256:<fingerprint>   (the exact value clients pin)
```

The identity command prints the certificate fingerprint clients pin. The
persistent identity lives at `/var/lib/hsync-rendezvous/identity.pem` (the unit's
`StateDirectory`) and stays stable across restarts.

## Manage and update

```bash
sudo systemctl status hsync-rendezvous.service
sudo journalctl -u hsync-rendezvous.service -f
sudo systemctl restart hsync-rendezvous.service
```

To update, install the newer `.deb` over the existing one (`sudo dpkg -i …`):
the group keys and the TLS identity are preserved, and an enabled service is
restarted for you. [operations.md](operations.md) covers the full procedure,
plus the watchdog, the log bounds, identity backup and rotation, and the
external reachability probe.

## Next

- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
- Running directly from a clone? [From source](getting-started-source.md).
