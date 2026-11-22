# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `epoch` in `register` and every `peers[]` entry: the leadership term the client uses
  to settle a partition heal.

### Changed

- `--version` is answered before the CLI stack is imported (~260 ms to ~15 ms),
  so packaging scripts and health checks no longer load Typer/pydantic/aioquic.
- A peer's wire projection is materialized at register/refresh instead of on the
  first query, so query cost stays flat as a table grows (10k peers: ~138 us to
  ~28 us p50, at the cost of ~13 us more on the one-off register).

### Removed

- `startup_time` from the election advertisement (register, relayed peers and the
  protocol spec): the election never reads a clock.

### Fixed

- A query to a partly-expired group (21-79 peers, fewer live than the requested
  limit) could spin the node at 100% CPU forever; the sampler now bounds its
  attempts.
- The L6 memory benchmark runs again (stale `PeerRecord` fields and fingerprint
  validator), and `bench/soak.py` accepts the `--json-out` the README documents.

## [1.1.0] - 2026-11-11

### Added

- `rdv/1` is served over **TLS/TCP** alongside QUIC/UDP on the same ports, with
  the same ALPN (`hsync-rdv/1`), self-signed identity and NDJSON framing. One
  connection carries one session (pipelined frames allowed), admission runs
  before the TLS handshake, and `--tcp/--no-tcp` / `--udp/--no-udp`
  (`HSYNC_RENDEZVOUS_TCP` / `HSYNC_RENDEZVOUS_UDP`) select the served transports;
  disabling both is a configuration error.
- The data relay pairs a TLS/TCP listener with a QUIC/UDP requester (and the
  reverse), so a relayed tunnel is transport-agnostic.

### Changed

- Dependency refresh: `typer` 0.29.
- Connection metrics are labelled by transport
  (`hsync_rendezvous_connections_*{transport="quic"|"tcp"}`), and both series
  are always exposed so a dashboard keeps reporting a disabled transport as 0.
- The compose/environment host port is `RENDEZVOUS_HOST_PORT` and maps both UDP
  and TCP, since the node serves the two transports on one port.

### Fixed

- A register that advertises no listen endpoint is relayed with an empty
  candidate list and `reachable=false`, instead of a fabricated endpoint built
  from that connection's source port, which no other peer could dial.
