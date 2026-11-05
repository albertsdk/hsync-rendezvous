# Getting Started — Method 2: Docker / Compose (manual)

Use this method when you already manage containers, want to run the released
image with your own Compose setup, or want to build the image from source. For
the one-command installer instead, see
[Method 1: installer script](getting-started-script.md).

## Prerequisites

- <img src="assets/os/linux.svg" alt="Linux" width="16" height="16"> <img src="assets/os/apple.svg" alt="macOS" width="16" height="16"> Linux or macOS with Docker Engine or Docker Desktop running
- Docker Compose v2 (`docker compose version`)
- A host port reachable from the Internet (443 by default), mapped for both
  QUIC/UDP and TLS/TCP

## Install

### With the released image (manual Compose)

Download `compose.yaml` from the release, create a private `.env` beside it, and
start it:

```dotenv
HSYNC_RENDEZVOUS_IMAGE=ghcr.io/albertsdk/hsync-rendezvous:v1.0.0
HSYNC_RENDEZVOUS_IDENTITY=/var/lib/hsync-rendezvous/identity.pem
# Private node / protected buckets (optional):
#HSYNC_RENDEZVOUS_KEYS_PATH=/secure/path/group-keys
#HSYNC_RENDEZVOUS_KEYS_FILE=/keys
#HSYNC_RENDEZVOUS_PRIVATE=1
# The data relay is on by default; uncomment for a discovery-only node:
#HSYNC_RENDEZVOUS_RELAY=0
```

The keys file carries one `bucket=<hex-key>` line per bucket — the format,
rotation and the `--protected-bucket`/`--private` model are in the shared
reference [usage.md → Group keys](usage.md#group-keys---keys-fd----keys-file).

`HSYNC_RENDEZVOUS_PRIVATE=1` is the one-switch equivalent of declaring
`--protected-bucket` for every bucket in the keys file (it additionally gates
`leave` and refuses to start with an empty keys file) — see
[usage.md → Private node](usage.md#private-node-authenticated-rendezvous).

The container binds the unprivileged port `8443`; the host maps
`RENDEZVOUS_HOST_PORT` (default `443`) to it for both transports (QUIC/UDP and
TLS/TCP). Verify the image signature before
starting (the released image is signed keyless by the release workflow), then
start it:

```bash
chmod 600 .env compose.yaml
cosign verify \
  --certificate-identity-regexp '^https://github\.com/albertsdk/hsync-rendezvous/\.github/workflows/release\.yml@refs/(heads|tags)/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "${HSYNC_RENDEZVOUS_IMAGE:-ghcr.io/albertsdk/hsync-rendezvous:v1.0.0}"
docker compose config --quiet
docker compose pull
docker compose up -d
```

The [`install.sh`](getting-started-script.md) path runs this verification for
you (and can pin an exact digest with `--image-digest`).

### Quick container (diagnostic only)

A temporary `docker run` is useful only for a short smoke test:

```bash
mkdir -p hsync-data
docker run --rm -d --name hsync-rendezvous-test \
  -p 443:8443/udp -p 443:8443/tcp \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd)/hsync-data:/var/lib/hsync-rendezvous" \
  ghcr.io/albertsdk/hsync-rendezvous:v1.0.0 run --listen-port 8443
docker logs hsync-rendezvous-test
docker stop hsync-rendezvous-test
```

### Serve a second port (optional)

The shipped Compose maps a single host port to the container's internal port for
both transports. To also answer clients whose network blocks UDP 443 (and those
that need TLS/TCP), listen on a second internal port and map it to another host
port:

```yaml
command: ["run", "--listen-host", "0.0.0.0", "--listen-ports", "8443,5353"]
ports:
  - "443:8443/udp"
  - "443:8443/tcp"
  - "53:5353/udp"
  - "53:5353/tcp"
```

Both ports share one routing table; the container keeps using unprivileged
ports. See `--listen-ports` in [usage.md](usage.md#run-options).

### Build the image from source

To build from source, follow the build steps in
[Contributing](../CONTRIBUTING.md).

`./docker.sh` also supports `stop`, `restart`, `status`, `logs -f`, `shell` and
`clean`; it persists the identity under `./hsync-data`. Environment variables
select the public port (`RENDEZVOUS_HOST_PORT`), private mode
(`HSYNC_RENDEZVOUS_PRIVATE=1`) and the group keys
(`HSYNC_RENDEZVOUS_KEYS_PATH=/path/to/group-keys`). Run `./docker.sh --help`.

## Verify the node is running

```bash
docker compose ps
docker compose logs | grep -i fingerprint
```

`docker compose ps` also reports the container's health, which is the node's own
readiness file: `healthy` means at least one listener is bound (QUIC/UDP or
TLS/TCP), not merely that the container is up.

## Manage and update

```bash
docker compose logs -f
docker compose restart
docker compose down
docker compose up -d
```

`docker compose down` does not delete the identity directory. To update, pull the
new image tag (or rebuild with `./docker.sh build`) and bring the stack up again.

## Next

- Prefer the automated installer? [Installer script](getting-started-script.md).
- No Docker host? [Debian package](getting-started-deb.md) or
  [run from source](getting-started-source.md).
