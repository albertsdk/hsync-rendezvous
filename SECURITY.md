# Security Policy

## Supported Versions

Security fixes are applied to the latest version on the `main` branch.

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Open the **Security** tab of this repository.
2. Click **Report a vulnerability** to start a private advisory.

Please include the affected version, how the node is deployed, steps to
reproduce, the impact, and any suggested mitigation. Allow a reasonable time for
a fix before any public disclosure. We aim to acknowledge reports within a few
days and to keep you informed of remediation progress.

## Security Model

- **No peer-data persistence** — the routing table is RAM-only and the process
  never writes peer data (IPs, CIDs, timestamps) to disk (no-log invariant).
- **Rendezvous, not data** — the rendezvous only helps peers find each other; file
  data never passes through it.
- **Uniform refusals** — protected buckets return a uniform `token_required`
  refusal that never reveals whether a bucket exists; group keys are read once
  from a file descriptor (`--keys-fd`) or an operator-managed file
  (`--keys-file`, for service managers that cannot pass a descriptor, e.g.
  Windows), never from a path inside the sandbox on POSIX, and the node never
  writes them to disk.
- **Rate limiting** — in-memory per-source token buckets, sized so a legitimate
  client (and a whole home or office behind one address) is never refused
  (§Auth of `protocol-spec/rdv-1.md`); over-limit requests receive
  `rate_limited` with `retry_after`, and every refusal is counted so a limit
  clipping legitimate traffic is distinguishable from abuse (`docs/metrics.md`). A node at its host-derived
  routing-table ceiling answers `overloaded` (capacity backpressure; advisory
  `retry_after`, not counted against the source) instead of mislabelling itself
  as a rate limit.
- **Supply chain** — the released container image is signed keyless with
  Sigstore/cosign by the release workflow, and `install.sh` verifies that
  signature against the workflow's OIDC identity before starting the node
  (an explicit `--no-verify` opts out). `--image-digest sha256:…` pins an exact
  image instead of a mutable tag.
- **Identity** — the TLS identity is a persistent ECDSA P-256 key+cert, created
  on first run and reused afterwards so the fingerprint is stable and can be
  pinned (ADR-0034/ADR-0037); it is the node's only on-disk artifact.
  `--identity PATH` overrides the path and `--ephemeral` keeps the identity in
  memory instead.

## Trust model (what the node can and cannot vouch for)

The rendezvous is an **unauthenticated matchmaker**, by design: it relays what a
peer declares and never becomes an identity authority.

- On an **open** bucket any source may claim a `(cid, bucket, group)` that is
  free or past its TTL, and may advertise any dialable endpoint, `cert_fp` and
  election advertisement. Ownership is bound to the observed source IP only
  while the record is alive (`register`/`refresh`/`leave` from another source are
  dropped), so a live registration cannot be hijacked, kept alive or evicted by
  a third party.
- Peer **identity is therefore established on the data plane**, which pins the
  peer certificate (TOFU, `sha256:<hex>` fingerprint) before any file is
  exchanged. A relayed `cert_fp` is a claim, not a proof.
- Where the identity of the peers in a bucket matters, run the bucket
  **protected** (`--protected-bucket`) or the node **private** (`--private`):
  a valid `bucket_token` then authenticates bucket membership and pins who may
  write.
- The group key behind that token is the only entropy, so it must be at least 32
  characters on the node (a client may instead supply a 12+
  `HSYNC_P2P_PASSPHRASE`, which it derives to that key) and be rotated like any
  shared secret: rotate the key, restart the node, redistribute it.

## Hardening Recommendations

- Run the node on port 443 over UDP and TCP (QUIC and TLS/TCP) via the packaged
  service unit and keep dependencies up to date. Install the container image through `install.sh` (or verify it
  with `cosign verify` yourself) so an unverified image is never started.
- If clients pin the fingerprint, keep the persistent identity (the default) or
  an explicit `--identity PATH`, and distribute the `sha256:<hex>` fingerprint
  out of band. Do not `--ephemeral` a node whose clients pin it.
- Keep `--debug` disabled in production: it is stderr-only but peer-aware.
