# Getting Started — RPM package (RHEL/Rocky/Alma/Fedora)

The `.rpm` installs the node as a hardened systemd service under a dynamic user
with `CAP_NET_BIND_SERVICE` (so it can bind port 443 on UDP and TCP), and provisions group keys
as a systemd credential. No Docker and no Python are required.

> The RPM binaries are built on a Rocky Linux 9 baseline (glibc 2.34), so they
> run on RHEL/Rocky/Alma 9+, recent Fedora, and any distro with glibc ≥ 2.34.
> Debian/Ubuntu is covered by the [Debian package](getting-started-deb.md).

## Prerequisites

- <img src="assets/os/redhat.svg" alt="Red Hat" width="16" height="16"> <img src="assets/os/fedora.svg" alt="Fedora" width="16" height="16"> RHEL, Rocky Linux, AlmaLinux (9+) or Fedora, on `x86_64` or `aarch64`
- A root shell or `sudo`
- A port reachable from the Internet (443 by default) over UDP and/or TCP — QUIC uses UDP, TLS/TCP uses TCP

## Install

```bash
curl -fLO "https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/hsync-rendezvous-x86_64.rpm"
sudo dnf install hsync-rendezvous-x86_64.rpm
```

The URL always points to the **latest stable** release; use `aarch64` instead of
`x86_64` on ARM. To pin a version, use
`https://github.com/albertsdk/hsync-rendezvous/releases/download/vX.Y.Z/hsync-rendezvous-<version>-1.el9.<arch>.rpm`.

To build from the checkout instead:

```bash
./compile.sh -t rpm        # host arch
./compile.sh -t rpm-all    # x86_64 + aarch64 (Docker)
```

## Configure and run

The package installs a hardened systemd unit (DynamicUser +
`CAP_NET_BIND_SERVICE` so it can bind port 443 on UDP and TCP; group keys exposed only as a
systemd credential) and **never enables the service automatically** — opt in
with:

```bash
sudo systemctl enable --now hsync-rendezvous.service
sudo systemctl status hsync-rendezvous.service
```

Group keys and private mode are node-wide concerns, not packaging ones: the
`bucket=<hex-key>` file format, key rotation, and the
`--protected-bucket` / `--private` model are in the shared reference
[usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file) and
[usage.md → Private node](usage.md#private-node-authenticated-rendezvous).
On RPM the keys file lives at `/etc/hsync-rendezvous/group-keys` (created empty
by `%post`; open mode until you provision it) and the unit reads it as a
credential — restart the service after writing it:

```bash
sudo install -m 0640 /path/to/group-keys /etc/hsync-rendezvous/group-keys
sudo systemctl restart hsync-rendezvous
```

For a fully private node, an environment drop-in leaves the unit's command
untouched (what `--private` changes is in the shared reference above):

```bash
sudo systemctl edit hsync-rendezvous.service
```

```ini
[Service]
Environment=HSYNC_RENDEZVOUS_PRIVATE=1
```

To also serve a second port (for clients whose network blocks 443 on one transport), replace
the unit's single `--listen-port` with `--listen-ports` in a drop-in, keeping
the unit's `--keys-fd 5 5<"$CREDENTIALS_DIRECTORY/group-keys"` when you
provisioned keys — see `--listen-ports` in
[usage.md → run options](usage.md#run-options).

> Unlike `dpkg -i`, an RPM upgrade does **not** stop and restart an enabled
> service for you: after `sudo dnf upgrade hsync-rendezvous-*.rpm`, restart it
> once to pick up the new binary:
>
> ```bash
> sudo systemctl restart hsync-rendezvous
> ```
>
> First install: if `sudo systemctl enable --now hsync-rendezvous` fails with a
> `Failed to load credential ... metrics-token` error, the packaged `%post`
> (before 1.0.15) created only the empty `group-keys` source. Create both empty
> credential sources and start again:
>
> ```bash
> sudo install -m 0640 -o root -g root /dev/null /etc/hsync-rendezvous/group-keys
> sudo install -m 0640 -o root -g root /dev/null /etc/hsync-rendezvous/metrics-token
> sudo systemctl enable --now hsync-rendezvous
> ```

## Next

- Prefer containers? [Installer script](getting-started-script.md) or
  [Docker](getting-started-docker.md).
- Running directly from a clone? [From source](getting-started-source.md).
