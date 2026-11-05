# HSYNC Rendezvous — FAQ

Operational questions about running the node and about the clients that connect
to it. For the CLI itself see [usage.md](usage.md).

## Why does my client abort with "Rendezvous '…' trust failed: the certificate fingerprint does not match the accepted pin"?

**Symptom.** A client that connected to the node before now stops with:

```text
ERROR: Rendezvous '<host>:<port>' trust failed: the certificate fingerprint
does not match the accepted pin (possible man-in-the-middle).
The rendezvous presented this SHA256 fingerprint:
  sha256:<new-fingerprint>
```

The client also prints the known-hosts file that holds the accepted pin and the
exact `hsync trust rendezvous-server add`/`hsync trust rendezvous-server remove` commands that
unblock the situation.

**Why.** The client authenticates the node's **self-signed** certificate by
fingerprint: at the prompt (the default `ask` policy) or, with
`--rendezvous-tofu`, it remembers the first fingerprint it sees for `<host>:<port>`
and refuses any later change as a possible man-in-the-middle. The node keeps its
identity stable by default (a persisted ECDSA P-256 key+cert), so a plain restart
does **not** change the fingerprint; a mismatch means the operator rotated the
identity (`hsync-rendezvous identity rotate --identity /var/lib/hsync-rendezvous/identity.pem`),
pointed the node at a different
identity file, or ran it with `--ephemeral` (a fresh in-memory key each start).
It can also indicate a real man-in-the-middle.

**Fix — operator (recommended).** Keep the node's persistent identity (the
default) so the fingerprint survives restarts, then distribute that fingerprint
to clients:

```bash
# start the node (in its own terminal, or as a service)
hsync-rendezvous run --identity /var/lib/hsync-rendezvous/identity.pem

# then, in another terminal, read the fingerprint:
hsync-rendezvous identity show --identity /var/lib/hsync-rendezvous/identity.pem
```

Clients then pin it with `--rendezvous-fingerprint <fingerprint>` (or confirm it
once at the prompt on a terminal).

**Fix — clients after an expected change.** If the new fingerprint is legitimate
(e.g. the operator rotated the identity), accept it explicitly:

```bash
hsync p2p HOST -b BUCKET --rendezvous-fingerprint NEW_FINGERPRINT
```

Or, if a client already pinned it, forget the stale pin with
`hsync trust rendezvous-server remove` (the client prints this exact command, with the host
and port, when it refuses) so the next connection is trusted again; the entry
lives in the client's trust store (`rendezvous_server_known_hosts.json` under
`$XDG_STATE_HOME/hsync/`, or the path in
`HSYNC_RENDEZVOUS_TRUST_FILE`).

**Never** accept a fingerprint you cannot explain: a mismatch is precisely what
the pin protects against.

## Why does closing the terminal or dropping the SSH session not stop the node?

**By design.** `SIGHUP` is ignored: a hangup (the terminal was closed, the SSH
session dropped, the PTY was torn down) is not a stop request, so an unattended
node keeps serving `rdv/1` instead of dying silently with the session. Stopping
stays on `SIGINT`/`SIGTERM` — what `systemctl stop` and Ctrl+C send — which
closes the transports, removes the readiness file and exits 0 (see
[Signals](usage.md#signals-and-service-manager)).

If the node did disappear, the cause is not the session:

```bash
systemctl status hsync-rendezvous.service
sudo journalctl -u hsync-rendezvous.service
uptime -s
sudo journalctl -k | grep -i "killed process"
```

A climbing restart counter means a crash (the journal holds the always-on
`warn`/`error` line behind it); a recent boot means the host restarted; a
`killed process` line means the OOM killer. A reboot or an OOM kill leaves no
traceback in the node's own log — and an enabled unit is brought back by
systemd, which is exactly why the node belongs under it.

A foreground run has no restart policy, no resource limits, no filesystem
sandbox and no journal, so it is not a deployment: see
[operations.md](operations.md#start-it-and-keep-it-running).

## What is `--public-host` for?

`hsync p2p` authenticates the node by **certificate fingerprint** (prompt, TOFU
or pin), not by hostname: the QUIC/TLS handshake does not validate the
certificate chain or its SAN, so a client reaches the node with or without this
flag.

It matters when the node is dialled by a TLS client that *does* verify the
hostname — a generic QUIC/TLS tool, or any implementation that does not pin the
fingerprint. Without it, and when the node binds `0.0.0.0`/`::`, the certificate
SAN falls back to the placeholder DNS name `hsync-rendezvous`, which never matches
the address dialled, so such a client rejects the handshake (`Error: 298`). Add
every name/IP that clients dial:

```bash
hsync-rendezvous run --identity /var/lib/hsync-rendezvous/identity.pem \
    --public-host rdv.example.net
```

`--public-host` is repeatable. Changing the SAN requires regenerating the
certificate, so the fingerprint changes too — see the rotation window above, and
repeat every public host when you rotate.

## How do I rotate the node identity without breaking clients?

The identity is persisted by default (created on first run, reused afterwards), so
a restart reuses the same fingerprint. To change it deliberately — e.g. after a
suspected compromise — rotate it:

```bash
hsync-rendezvous identity rotate --identity /var/lib/hsync-rendezvous/identity.pem \
    --public-host rdv.example.com
```

Rotation prints the new fingerprint; during the change window clients can be
given both fingerprints (the client accepts up to two pins), then moved to the
new one. Rotation keeps the existing DNS/IP SANs and adds any `--public-host`
you pass. The command re-reads and verifies the pair it wrote; **restart the
node** to serve the new identity (it is loaded at startup), then verify the
certificate a client actually sees with
`hsync trust rendezvous-server fingerprint <host:port>` (`identity show` reads the persisted
file, not the served certificate). A node started with `--ephemeral` is the
exception: it keeps the identity in memory, so *any* restart changes the
fingerprint — do not pin such a node.

## I ran a *public* node — do clients need a fingerprint?

Not necessarily: on a terminal the client confirms the fingerprint once at the
prompt (the default `ask` policy) and remembers it, while an unattended client
uses `--rendezvous-tofu` instead. Pin it explicitly with
`--rendezvous-fingerprint` when the identity must be *stable* and verified out of
band.

## A client keeps logging "Waiting for peers to join"

The node is reachable but no peer is registered in the bucket yet — nothing is
wrong: see the client's
[FAQ — p2p Mode](https://github.com/albertsdk/hsync-client/blob/main/docs/faq-p2p.md).

A trust failure never produces that wait: the client disables the rendezvous source,
keeps syncing on the local network and never contacts the node again until the
fingerprint is pinned, so only the cross-network peers are missing while the local
ones keep working.

## Some clients cannot reach my node even though it is up

The node serves **two interchangeable transports on the same port**: QUIC/UDP
(primary) and TLS/TCP, for a client network whose egress blocks UDP. `hsync-client`
races both (default `auto`) and remembers the winner, so a client that blocks
outbound UDP 443 still reaches the node over TLS/TCP 443 with no node change.

If *only some* clients fail while others work, their network may also block the
inbound port from the client side; give them another door by listening on a
second port — 443 **and** 53, sharing one routing table, with both open in the
host firewall:

```bash
hsync-rendezvous run --listen-ports 443,53
```

With a packaged install, set the same option through a unit/Compose override
(see the Debian, Windows or Docker guide); for the full semantics see
`--listen-ports` in [usage.md](usage.md#run-options).

## Does the node speak TCP, or only QUIC?

Both. Every node serves `rdv/1` over **QUIC/UDP and TLS/TCP on the same port(s)**
with the same self-signed TLS 1.3 identity and ALPN `hsync-rdv/1`; the client's
default `auto` transport races the two per endpoint (QUIC preferred) and pins the
winner. A node started with `--no-udp` is TLS/TCP-only, `--no-tcp` is QUIC-only,
and disabling both is a configuration error (exit 2). The same switches exist as
`HSYNC_RENDEZVOUS_UDP`/`HSYNC_RENDEZVOUS_TCP` (`1`/`0`) for the service units.
Clients select the transport themselves with `--rendezvous-transport auto|quic|tcp`
(env `HSYNC_RENDEZVOUS_TRANSPORT`). `--upnp` maps only the enabled transports.
See the wire contract in [`protocol-spec/rdv-1.md`](../protocol-spec/rdv-1.md)
(§Transport).

## Peers discover each other but never sync (mobile data, hotspot, CGNAT)

Two peers behind carrier-grade NAT have no inbound address at all: rendezvous and
the master election work, then the slave keeps logging `No reachable endpoint for
master …`. The relay is **on by default**, so the node already carries the data
plane — this symptom appears only when it was started with `--no-relay`. Remove
that flag and the node forwards the peers' TLS verbatim (it never sees content,
names or credentials; it does see which devices are paired and how many bytes
they exchanged):

```bash
hsync-rendezvous run
```

The client then logs `[RELAY]` on both sides and the sync proceeds through the
node. The relay is bounded by default: set the aggregate rate with
`--relay-bandwidth` (KiB/s, default 8192), the per-session ceiling with
`--relay-session-bytes` and the idle window with `--relay-idle-timeout` (default
120 s). To keep a node discovery-only, start it with `--no-relay` (or
`HSYNC_RENDEZVOUS_RELAY=0`): it answers every relay frame with
`relay_unavailable` and only directly reachable peers connect. See
[usage.md](usage.md#run-options) and the wire contract in
[`protocol-spec/rdv-1.md`](../protocol-spec/rdv-1.md) (§Data relay).

## Where can I read the pin the client stored?

On the client host, in `rendezvous_server_known_hosts.json` under `$XDG_STATE_HOME/hsync/`
(or `~/.local/state/hsync/`), overridable with `HSYNC_RENDEZVOUS_TRUST_FILE`; the
client prints this path whenever it pins a fingerprint. It maps `<host>:<port>`
to the current fingerprint and its `updated_at` timestamp.

## Why does the binary abort with "GLIBC … not found" on another machine?

**Symptom.** The standalone executable built with `./compile.sh` (the default
`native` target) and copied to another machine dies before printing anything:

```text
[PYI-1111637:ERROR] Failed to load Python shared library
'/tmp/_MEI0010f654EX8vvI/libpython3.14.so.1.0':
/lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found
(required by /tmp/_MEI0010f654EX8vvI/libpython3.14.so.1.0)
```

**Why.** PyInstaller does not cross-compile: `native` freezes the **build
machine's own** CPython (3.14 in that example) together with its C library, and
glibc is compatible backwards only. A binary produced on glibc 2.43 therefore
demands `GLIBC_2.38` and cannot start on a machine running 2.35 (Ubuntu 22.04)
or 2.36 (Debian 12). `-t deb` is **not** a fix: it builds that same host payload
and merely moves the failure from exec time to `dpkg -i`.

**Fix.** Use the cross-build target, which compiles inside a Debian 12
(bookworm) container with its own CPython 3.14; the produced package's measured
glibc floor is **2.35**, then install it on the machine:

```bash
uname -m   # x86_64 → amd64; aarch64 → arm64; armv7l → armhf
./compile.sh -t deb-all
# → dist/deb/hsync-rendezvous_<ver>_<arch>.deb (needs Docker + qemu)
scp dist/deb/hsync-rendezvous_*_amd64.deb TARGET_HOST:/tmp/
ssh TARGET_HOST 'sudo dpkg -i /tmp/hsync-rendezvous_*_amd64.deb'
```

`TARGET_HOST` is the SSH host of the destination machine. Pick the architecture
from the failing path in the error (`/lib/x86_64-linux-gnu/` → `amd64`).

To run it without installing anything, unpack the same package instead:

```bash
dpkg-deb -x dist/deb/hsync-rendezvous_*_amd64.deb /tmp/hsync-rendezvous-bin
/tmp/hsync-rendezvous-bin/usr/lib/hsync-rendezvous/hsync-rendezvous --version
```

**Fix without Docker.** Build **on the destination machine**: `./compile.sh`
run there freezes that machine's own interpreter and matches it by construction.
It needs Python 3.12+ and the build dependencies (`CONTRIBUTING.md`).

**Which targets work.** The produced package requires `libc6 >= 2.35`, so
Debian 12 and Ubuntu 22.04 or newer run it; Debian 11 and Ubuntu 20.04 (glibc
2.31) do not — build on the machine itself there. Check the glibc of the
destination with `ldd --version | head -1`.

**Do not trust `Depends:`.** The `libc6` dependency of the package is computed
from the launcher only: the bundled Python and `libgcc_s` that actually need
2.35 are invisible to `dpkg-shlibdeps`, so a successful `dpkg -i` does not prove
the node will start.

## Why does the installer fail with "open .../.env: permission denied"?

```text
open /home/USER/.local/share/hsync-rendezvous/.env: permission denied
```

The snap-packaged `docker` is confined and cannot read hidden paths under
`$HOME`; the default install directory `~/.local/share/hsync-rendezvous` is
hidden, so `docker compose` cannot load `.env`. The installer detects this and
falls back to `$HOME/hsync-rendezvous` automatically; an explicit `--install-dir`
under a hidden path is refused. Install Docker Engine instead of the snap if you
want to keep a hidden directory — see
[Getting Started — Docker installed as a snap](getting-started-script.md#docker-installed-as-a-snap).

## Why does the installer stop with "required command not found: docker"?

```text
Error: required command not found: docker
```

The node runs as a container, so the installer needs Docker Engine (or Docker
Desktop) and the Compose v2 plugin before doing anything. It never installs Docker
itself: it prints the install commands for your platform (Debian/Ubuntu,
Fedora/RHEL, Arch, openSUSE, Alpine, macOS) and the official docs, then stops
without writing anything.

Install Docker, make sure the daemon is running
(`sudo systemctl enable --now docker`) and your user is in the `docker` group
(`sudo usermod -aG docker "$USER"`, then log out and back in), and re-run the same
command. If the failure is `Error: Docker Compose v2 is required`, the Compose v2
plugin is missing — Docker Compose v1 (`docker-compose`) is not supported.

Prefer not to run Docker? Use the Debian package
([getting-started-deb.md](getting-started-deb.md)) or run from source
([getting-started-source.md](getting-started-source.md)). See also
[Getting Started — Prerequisites](getting-started-script.md#prerequisites).

## Why does the installer stop with "required command not found: cosign"?

```text
Error: required command not found: cosign
```

The installer verifies the released image's Sigstore signature before starting
the node, and that check needs `cosign`. It prints the install command for your
platform (Homebrew, pacman, apk, or the official prebuilt binary) and stops
**before writing any file**, so nothing is left half-created.

Install the latest `cosign` and re-run the same command. Releases are signed
with cosign v3 bundles, so a v2 binary reports that the image carries no
signature even when the release is intact. See
[Getting Started — Install cosign](getting-started-script.md#install-cosign).

To install without the check (the image is then trusted on the registry
reference alone), forward `--no-verify` through the pipe:

```bash
curl -fsSL https://github.com/albertsdk/hsync-rendezvous/releases/latest/download/install.sh \
  | bash -s -- --no-verify
```
