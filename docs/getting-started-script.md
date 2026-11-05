# Getting Started — Method 1: Installer script

The `install.sh` installer is the recommended way to get a rendezvous running: it
downloads the released container image, persists the TLS identity in a plain
host directory, and starts the node with Docker Compose.

## Prerequisites

- <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> Linux or macOS with Docker Engine or Docker Desktop running
- Docker Compose v2 (`docker compose version`)
- `cosign` on `PATH` — the installer verifies the container image's Sigstore
  signature before starting it. When it is missing, the installer prints the
  install command for your platform and stops before writing any file; see
  [Install cosign](#install-cosign). `--no-verify` skips the check.
- A port reachable from the Internet (443 by default) over UDP and/or TCP — QUIC uses UDP, TLS/TCP uses TCP

Docker must already be installed. If it is missing — or the Compose v2 plugin is
missing, or the daemon is not running — the installer stops before writing anything
and prints the install commands for your platform together with the official Docker
docs. It never installs Docker and never invokes `sudo`; it only prints the commands
for you to run. See the [FAQ](faq.md#why-does-the-installer-stop-with-required-command-not-found-docker).

### Docker installed as a snap

The snap-packaged `docker` is confined: its `home` interface denies hidden paths
under `$HOME`, so it cannot read `.env` in the default install directory
`~/.local/share/hsync-rendezvous`. When it detects a snap `docker` and an install
directory under a hidden path, the installer falls back to a non-hidden default
(`$HOME/hsync-rendezvous`) automatically. If you passed `--install-dir` explicitly,
it stops before writing anything and tells you to re-run with a non-hidden
directory:

```bash
curl -fsSL https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/install.sh \
  | bash -s -- --install-dir "$HOME/hsync-rendezvous"
```

Installing Docker Engine (<https://docs.docker.com/engine/install/>) instead of
the snap avoids the constraint entirely.

## Install

### Quick install (one command, latest stable release)

```bash
curl -fsSL https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/install.sh | bash
```

This downloads and runs the installer in one step. The host port `443` is
mapped to the container on both UDP and TCP; the node's persistent TLS identity lives in
`~/.local/share/hsync-rendezvous/hsync-data`.

### Verified install (checksum)

To verify the download before running it:

```bash
curl -fLO "https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/install.sh"
curl -fLO "https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
chmod 700 install.sh
./install.sh
```

On macOS, use `shasum -a 256 install.sh` and compare the result with the
matching line in `SHA256SUMS`.

### Verify the container image

Before starting the node, the installer verifies the released image's
**Sigstore (cosign) signature** — keyless, signed by the release workflow — and
refuses to start an image whose signature does not match. The check runs before
any file is written, so a missing `cosign` leaves no partial installation
behind. To pin an exact image instead of a mutable tag, pass the digest the
release was signed at, quoted — the validator expects exactly 64 lowercase hex
characters:

```bash
./install.sh --image-digest "sha256:DIGEST_HEX64"
```

#### Install cosign

Releases are signed with the **cosign v3** bundle format: use the latest
`cosign`, because a v2 binary reports that the image carries no signature.

The official prebuilt binary works on any Linux distribution. The asset name
ends with the CPU: `amd64` on x86-64, `arm64` on ARM64, `arm` on 32-bit ARM.

```bash
curl -fsSLo /tmp/cosign \
  "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign
cosign version
```

Arch Linux and Alpine ship `cosign` as a package:

```bash
sudo pacman -S cosign
```

```bash
sudo apk add cosign
```

On macOS, install it with Homebrew:

```bash
brew install cosign
```

#### Skip the verification

If you cannot install `cosign`, `--no-verify` skips the check (the image is then
trusted on the registry reference alone). With the one-line install the option
goes after `bash -s --`:

```bash
curl -fsSL https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/install.sh \
  | bash -s -- --no-verify
```

With a downloaded copy of the script, pass the flag directly:

```bash
./install.sh --no-verify
```

### Choose the host port

Clients connect to the host port (`443`) over QUIC/UDP or TLS/TCP; the container maps it to an
unprivileged internal port. To use another public port, for example `8443`:

```bash
./install.sh --public-port 8443
```

The installer maps a **single** host port on both transports. To also serve a second port
(e.g. 53) for clients whose network blocks 443 on one transport, use the manual Compose
override in the [Docker guide](getting-started-docker.md#serve-a-second-port-optional).

### Private node (authenticated rendezvous)

A **private** node requires a valid `bucket_token` on every frame. Provision the
group keys file with one `bucket=<hex-group-key>` line per protected bucket
(mint a key per bucket with `openssl rand -hex 32`; an **empty** file means open
mode, while `--private` with an empty file is a configuration error):

```text
# /secure/path/group-keys — one line per protected bucket
shared=378767051d3c551e615922cbffb543563a93bbf39d615a2c46389c2f6b246068
home=63379453eeb327abf615e2e89aa3921fb4c20edf11a12a260058ed299dc153cb
```

```bash
./install.sh --private --keys-file /secure/path/group-keys
```

`--private` is the one-switch equivalent of declaring every bucket provisioned
in the keys file with `--protected-bucket` (it additionally gates `leave` and
refuses to start with an empty keys file) — see
[usage.md → Private node](usage.md#private-node-authenticated-rendezvous).

The full format, the client-side token derivation and the key-rotation procedure
are in [usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file).

## Verify the node is running

The installer waits for the node to write its readiness PID. Check the logs and
the certificate fingerprint clients pin:

```bash
# use your --install-dir instead if you passed one (the snap fallback may have
# moved the default to $HOME/hsync-rendezvous)
cd "$HOME/.local/share/hsync-rendezvous"
docker compose ps
docker compose logs | grep -i fingerprint
```

## Manage and update

```bash
# use your --install-dir instead if you passed one
cd "$HOME/.local/share/hsync-rendezvous"
docker compose logs -f
docker compose restart
docker compose down
docker compose up -d
```

`docker compose down` does not delete the identity directory. To update, run the
installer again with the same directory: it updates the pinned image version
while preserving the TLS identity (so the fingerprint clients pinned stays the
same).

```bash
./install.sh
```

Run `./install.sh --help` for version, install-directory, port, `--private`,
`--keys-file`, `--image-digest`, `--no-verify`, `--no-start` and `--dry-run`
options.

## Next

- Prefer to manage containers yourself? [Docker / Compose](getting-started-docker.md).
- No Docker host? [Debian package](getting-started-deb.md) or
  [run from source](getting-started-source.md).
