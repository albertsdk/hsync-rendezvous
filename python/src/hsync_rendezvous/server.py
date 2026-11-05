"""QUIC/UDP transport for ``rdv/1`` (aioquic).

The transport is a thin adapter around aioquic: it handles the single
QUIC/UDP listener, the mandatory RETRY + address-validation tokens (``retry``
aioquic flag), per-connection peer tracking (STUN-echo source) and the
NDJSON-over-bidi-stream framing. All business rules live in
``hsync_rendezvous.handler.RendezvousHandler`` and are fully testable without sockets.

TLS identity: a self-signed certificate built from ``hsync_common.ssl_utils``
(ECDSA P-256 — ADR-0037). It persists by default at a state path (``0600`` in a
``0700`` directory) so its fingerprint is stable and pin-able across restarts;
``run --ephemeral`` keeps it in memory instead. Either way, no peer data is ever
written to disk (no-log).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import ssl
import stat
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hsync_common import ssl_utils
from hsync_common.protocol.rendezvous import RDV_ALPN, RDV_IDLE_TIMEOUT

from hsync_rendezvous.diagnostics import debug_enabled, debug_event, error_event, warn_event
from hsync_rendezvous.framing import FrameTooLarge, read_ndjson
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.protocol import BucketProto
from hsync_rendezvous.ratelimit import TokenBucketLimiter
from hsync_rendezvous.relay import PrefixedReader, RelayHandoff
from hsync_rendezvous.stats import NodeStats

__all__ = [
    "RDV_ALPN",
    "RDV_IDLE_TIMEOUT",
    "CONNECTION_ACTIVE_MAX_PER_IP",
    "HANDSHAKE_BURST_PER_IP",
    "HANDSHAKE_RATE_PER_SECOND",
    "MAX_FRAME_BYTES",
    "MAX_RELAY_STREAMS_PER_CONNECTION",
    "MAX_SESSIONS_PER_CONNECTION",
    "RendezvousQuicProtocol",
    "RendezvousTcpProtocol",
    "ConnectionGuard",
    "IdentityError",
    "NodeIdentity",
    "build_quic_configuration",
    "build_tls_context",
    "load_identity",
    "load_or_create_identity",
    "make_identity",
    "rotate_identity",
    "rotation_hint",
    "start_server",
    "start_servers",
    "start_tcp_server",
    "start_tcp_servers",
]

# ``RDV_ALPN`` and ``RDV_IDLE_TIMEOUT`` are the hsync-common wire SSOT
# (``hsync_common.protocol.rendezvous``), imported above so the node and the
# client can never handshake on different ALPN or idle windows.
# Ingress bound for one rdv/1 frame (a register carries at most 16 endpoints).
# What the node *emits* is bounded separately by protocol.MAX_RESPONSE_BYTES.
MAX_FRAME_BYTES = 8192
# QUIC flow-control bounds: a request frame is at most MAX_FRAME_BYTES and the
# client only pipelines a few per stream, so the per-stream receive window bounds
# the server-side buffering per stream without stalling a legitimate exchange
# (responses are governed by the peer's own advertised limits). The
# connection-level window must cover every concurrent stream's share of that
# window, or it — not the per-stream one — becomes the throughput ceiling.
MAX_STREAM_DATA_BYTES = 4 * MAX_FRAME_BYTES

# Per-IP handshake admission and open-connection cap (the CLI also supplies a
# process-wide cap from ResourceLimits); RETRY only stops *amplified* (spoofed)
# handshakes, so the node needs its own budget — full rationale and sizing in
# the ConnectionGuard docstring.
HANDSHAKE_RATE_PER_SECOND = 30
HANDSHAKE_BURST_PER_IP = 100
CONNECTION_ACTIVE_MAX_PER_IP = 256

# One rdv/1 exchange is one bidirectional stream, so a handful of concurrent
# sessions per connection is generous. aioquic hardcodes 128 concurrent bidi
# streams per connection; without this cap a peer could pin 128 session tasks
# (and 128x the per-connection memory budget) with streams it never closes.
# See RendezvousQuicProtocol._spawn_stream.
MAX_SESSIONS_PER_CONNECTION = 4
# Streams one connection may additionally hold for data-relay sessions: the
# listener keeps one control stream plus one stream per relayed peer, so the
# bound has to cover them without letting a connection pin unbounded tasks.
MAX_RELAY_STREAMS_PER_CONNECTION = 32
# The connection window must span every relay stream's per-stream window: a
# relayed session multiplexes one stream per bridged TCP connection, so a
# connection cap below the sum throttled each transfer to the shared budget and
# capped relayed throughput well under the per-stream allowance.
MAX_DATA_BYTES = MAX_RELAY_STREAMS_PER_CONNECTION * MAX_STREAM_DATA_BYTES

# HSYNC service identities are always ECDSA P-256 (ADR-0037).
PrivateKey = ec.EllipticCurvePrivateKey

# Identity file/dir permissions: a long-lived private key must not be
# world-readable (shared service-identity model, ADR-0037).
_IDENTITY_FILE_MODE = ssl_utils.KEY_FILE_MODE
_IDENTITY_DIR_MODE = ssl_utils.IDENTITY_DIR_MODE


class NodeIdentity:
    """TLS identity (self-signed cert + private key), ephemeral or persistent."""

    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: PrivateKey,
    ) -> None:
        self.certificate = certificate
        self.private_key = private_key

    @property
    def fingerprint(self) -> str:
        return ssl_utils.compute_cert_fingerprint(self.certificate)

    @property
    def expires_at(self) -> datetime:
        """The certificate's ``NotAfter`` (UTC) — when the pinned identity lapses."""
        return self.certificate.not_valid_after_utc


def _generate_identity(host: str, public_hosts: Sequence[str]) -> NodeIdentity:
    """Build a fresh in-memory ECDSA P-256 identity (no disk writes).

    One constructor for every path (`make_identity`, first-use creation,
    rotation) so the subject, SANs and validity can never drift between them.
    """
    key = ssl_utils.generate_ecdsa_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(NameOID.COMMON_NAME, "hsync-rendezvous")],
        san_list=_sans_for(host, public_hosts),
        validity_days=ssl_utils.SERVICE_CERT_VALIDITY_DAYS,
        basic_constraints_ca=False,
    )
    return NodeIdentity(certificate=cert, private_key=key)


def _key_matches_certificate(certificate: x509.Certificate, private_key: PrivateKey) -> bool:
    """True when ``private_key`` is the key behind ``certificate``'s public key.

    Delegates to the shared service-identity model
    (:func:`hsync_common.ssl_utils.public_keys_match`) so the rendezvous, the sync
    server and their rotation commands cannot drift on how a mismatched pair is
    detected.
    """
    return ssl_utils.public_keys_match(certificate, private_key)


def make_identity(host: str = "0.0.0.0", *, public_hosts: Sequence[str] = ()) -> NodeIdentity:
    """Build a fresh in-memory self-signed identity (no disk writes).

    Used by ``run --ephemeral`` (read-only filesystems, throwaway nodes) and by
    tests; the default run persists the identity via :func:`load_or_create_identity`.
    """
    return _generate_identity(host, public_hosts)


def _warn_if_identity_dir_writable(identity_path: Path) -> None:
    """Warn when an existing identity directory is group/world writable.

    ``--identity`` may point into a directory this process does not own (a shared
    state tree, a bind-mounted volume, ``/tmp``): the directory is never
    re-permissioned (a directory we create is ``0700``, see
    :func:`hsync_common.ssl_utils.ensure_identity_dir`), but an operator is told
    when the one they supplied is too permissive for a private key.
    """
    parent = identity_path.parent
    if not parent.exists():
        return
    try:
        mode = stat.S_IMODE(parent.stat().st_mode)
    except OSError as exc:
        raise IdentityError(f"could not stat identity directory {parent}: {exc}") from exc
    if mode & 0o022:
        warn_event(
            "identity directory is group/world writable",
            path=str(parent),
            reason=f"mode {oct(mode)}; use 0700 for the private key directory",
        )


def load_or_create_identity(
    path: str | Path,
    *,
    host: str = "0.0.0.0",
    public_hosts: Sequence[str] = (),
) -> NodeIdentity:
    """Load the persistent identity at ``path``, generating it on first use.

    The file is a combined PEM (certificate followed by the unencrypted PKCS#8
    private key), written with ``0600`` permissions in a ``0700`` directory — the
    same model as SSH host keys. When the file exists it is loaded as-is; when
    absent a fresh ECDSA P-256 identity is generated and written. This is the
    default code path: :func:`make_identity` is used only for ``run --ephemeral``.
    """
    identity_path = Path(path)
    if identity_path.exists():
        return load_identity(identity_path)

    identity = _generate_identity(host, public_hosts)
    _warn_if_identity_dir_writable(identity_path)
    _atomic_write_identity(identity_path, identity)
    return identity


def _san_names(certificate: x509.Certificate) -> list[str]:
    """Return the DNS and IP SANs of *certificate* (shared helper)."""
    return ssl_utils.identity_san_names(certificate)


def rotation_hint(path: str | Path) -> str:
    """Return the command that rotates the identity at ``path``.

    Used by the near-expiry warning (``cli.py``) and the key/cert mismatch error
    so both name the file the process actually reads, not the default path.
    """
    return f'hsync-rendezvous identity rotate --identity "{path}"'


def rotate_identity(
    path: str | Path,
    *,
    host: str = "0.0.0.0",
    public_hosts: Sequence[str] = (),
) -> NodeIdentity:
    """Regenerate the persistent identity at ``path`` with a fresh key.

    Keeps every DNS/IP SAN of the current certificate and adds the explicit
    ``host``/``public_hosts``; the old certificate is replaced atomically. The
    caller must distribute the new fingerprint to clients (two-pin rotation
    window).

    Rotation is the recovery for a corrupted identity, so the current file is
    only checked *structurally* (it must be a PEM identity): a key/certificate
    mismatch does not block it. A file that is not an identity at all is
    refused, so a mistyped path cannot overwrite unrelated data.
    """
    identity_path = Path(path)
    if not identity_path.exists():
        raise IdentityError(f"identity file {identity_path} does not exist; nothing to rotate")
    old_certificate, _ = _parse_identity_file(identity_path)
    # Keep every hostname the node was reachable under: a rotation that silently
    # dropped a SAN would break hostname-validating clients even with a valid pin.
    identity = _generate_identity(host, [*_san_names(old_certificate), *public_hosts])
    _atomic_write_identity(identity_path, identity)
    return identity


def load_identity(path: str | Path) -> NodeIdentity:
    """Load a persistent identity from a combined cert+key PEM file (read-only)."""
    identity_path = Path(path)
    if not identity_path.exists():
        raise IdentityError(f"identity file {identity_path} does not exist")
    return _load_identity_file(identity_path)


def _parse_identity_file(identity_path: Path) -> tuple[x509.Certificate, PrivateKey]:
    """Parse a combined cert+key PEM file, checking structure only.

    Verifies the file holds a PEM certificate and an unencrypted PKCS#8 ECDSA
    private key and returns them. It does NOT check that the key matches the
    certificate (that is :func:`_load_identity_file`'s job) and does not touch
    permissions, so it is safe to call on a file that is about to be replaced
    (``identity rotate``). A malformed PEM raises :class:`IdentityError`, never
    a raw ``ValueError``.
    """
    try:
        data = identity_path.read_bytes()
    except OSError as exc:
        raise IdentityError(f"could not read identity file {identity_path}: {exc}") from exc
    try:
        return ssl_utils.parse_identity_pem(data)
    except ssl_utils.IdentityPemMissingError as exc:
        raise IdentityError(
            f"identity file {identity_path} must contain a certificate and a "
            "PKCS#8 private key; delete it and restart to regenerate"
        ) from exc
    except ssl_utils.IdentityKeyTypeError as exc:
        raise IdentityError(
            f"identity file {identity_path} must hold an ECDSA P-256 private key"
        ) from exc
    except ssl_utils.IdentityPemInvalidError as exc:
        raise IdentityError(
            f"identity file {identity_path} is not a valid PEM identity: {exc}"
        ) from exc


def _load_identity_file(identity_path: Path) -> NodeIdentity:
    """Parse a combined cert+key PEM file into a :class:`NodeIdentity`.

    Fails with a clear error when the file does not contain both a certificate
    and an unencrypted PKCS#8 private key, or when the private key does not
    match the certificate (never falls back to a fresh identity, which would
    silently rotate the pinned fingerprint).

    Unattended daemons need the key readable without a passphrase, so the
    *at-rest* protection is file permission: on load, a group/world-readable
    key file is re-chmodded to 0600 and the operator is warned once (the
    identity is the node's impersonation anchor — a leaked key lets an attacker
    take its fingerprint over).
    """
    try:
        mode = identity_path.stat().st_mode & 0o777
    except OSError as exc:
        raise IdentityError(f"could not stat identity file {identity_path}: {exc}") from exc
    if mode != _IDENTITY_FILE_MODE:
        try:
            os.chmod(identity_path, _IDENTITY_FILE_MODE)
            warn_event(
                "identity file permissions hardened",
                path=str(identity_path),
                reason=f"mode {oct(mode)} -> 0600",
            )
        except OSError as exc:
            error_event(
                "identity file permissions could not be hardened",
                path=str(identity_path),
                reason=type(exc).__name__,
            )
    cert, key = _parse_identity_file(identity_path)
    if not _key_matches_certificate(cert, key):
        raise IdentityError(
            f"identity file {identity_path} private key does not match its certificate "
            f"(run '{rotation_hint(identity_path)}' to regenerate a consistent pair)"
        )
    return NodeIdentity(certificate=cert, private_key=key)


def _atomic_write_identity(identity_path: Path, identity: NodeIdentity) -> None:
    """Write the combined identity atomically, owner-only, creating the directory.

    Delegates to the shared service-identity writer
    (:func:`hsync_common.ssl_utils.write_identity_file`), so the durability and
    permission policy is defined once.
    """
    ssl_utils.write_identity_file(
        identity_path,
        ssl_utils.serialize_cert_pem(identity.certificate),
        ssl_utils.serialize_private_key_unencrypted(identity.private_key),
        mode=_IDENTITY_FILE_MODE,
    )


def _sans_for(host: str, public_hosts: Sequence[str]) -> list[x509.GeneralName]:
    """Build the SAN list: every ``--public-host`` plus the bind address.

    A bind address of ``0.0.0.0``/``::`` has no usable IP SAN, so it falls back to
    the fixed DNS name ``hsync-rendezvous`` (the out-of-band pin is what actually
    authenticates the node, not the SAN). Duplicates — including a preserved SAN
    that matches the bind fallback — are collapsed to keep the certificate clean.
    """
    names = [*public_hosts]
    names.append(host if host not in ("0.0.0.0", "::") else "hsync-rendezvous")
    sans: list[x509.GeneralName] = []
    seen: set[tuple[bool, str]] = set()
    for name in names:
        try:
            general: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(name))
        except ValueError:
            # A DNS-name bind host (e.g. ``--listen-host localhost``) has no IP SAN;
            # record it as a DNS SAN instead of failing identity generation.
            general = x509.DNSName(name)
        key = (isinstance(general, x509.IPAddress), str(general.value))
        if key not in seen:
            seen.add(key)
            sans.append(general)
    return sans


class IdentityError(RuntimeError):
    """The persistent identity file could not be loaded or written safely."""


@dataclass(slots=True)
class _PeerState:
    """Per-IP open-connection count and last-seen stamp (eviction input)."""

    count: int
    last_seen: float


class ConnectionGuard:
    """Per-IP transport admission gate for one listener process (RAM only).

    Two controls, both bound to the peer's source IP and never persisted
    (no-log): a token-bucket on new connections (the TLS handshake is the only
    step any RETRY-protected QUIC server cannot refuse for free) and a ceiling
    on simultaneously-open connections — per source IP and, when a process-wide
    ceiling is supplied, across every source (each connection may hold up to 128
    QUIC streams, so unbounded connections also mean unbounded idle-task memory).

    Sizing (see the module constants): the handshake budget stays far above
    what a whole NAT umbrella of legitimate clients can produce — they open a
    connection per exchange and idle out after 30 s — while a single-IP flood
    is throttled to at most ``handshake_burst`` new handshakes per second.
    """

    def __init__(
        self,
        *,
        handshake_rate: float = HANDSHAKE_RATE_PER_SECOND,
        handshake_burst: int = HANDSHAKE_BURST_PER_IP,
        active_max: int = CONNECTION_ACTIVE_MAX_PER_IP,
        global_max: int | None = None,
        stats: NodeStats | None = None,
    ) -> None:
        # Peer-free operational counters (RAM only); the transport is where a
        # connection actually opens and closes, so the level is observed here.
        self.stats = stats if stats is not None else NodeStats()
        self._handshakes = TokenBucketLimiter(
            capacity=handshake_burst, refill=handshake_rate, window=1.0
        )
        self._active_max = active_max
        self._global_max = global_max
        self._total_active = 0
        # Open-connection level per transport (``quic``/``tcp``): the global
        # ceiling spans both, but the per-transport level is what tells an
        # operator how much of it each transport holds.
        self._per_transport: dict[str, int] = {}
        # Metric levels (open connections, per transport and total) kept apart
        # from the admission counts above: a TCP relay attach that was exempted
        # no longer competes for the per-IP/global budget, but the metrics keep
        # counting it until the connection really closes.
        self._metric_total = 0
        self._metric_per_transport: dict[str, int] = {}
        # Seconds an IP must stay quiet (with all of its connections closed)
        # before evict_stale() forgets it: capacity/rate refills the bucket to
        # exactly the first-use value, so forgetting is decision-neutral.
        self._quiet_horizon = handshake_burst / handshake_rate
        # ip -> open connection count + last-seen stamp (see evict_stale).
        self._active: dict[str, _PeerState] = {}

    def admit(self, peer_ip: str, *, transport: str = "quic", now: float | None = None) -> bool:
        """Admit one new (connecting) connection from ``peer_ip``.

        Returns False when the IP has no handshake budget left, already holds
        ``active_max`` open connections, or the process-wide ``global_max``
        ceiling would be exceeded; the caller must then refuse the connection
        instead of running its handshake. ``transport`` tags the connection
        (``quic``/``tcp``) for the per-transport level; ``global_max`` spans
        every transport.
        """
        now = time.monotonic() if now is None else now
        entry = self._active.get(peer_ip)
        if entry is not None and entry.count >= self._active_max:
            return False
        if self._global_max is not None and self._total_active >= self._global_max:
            self._note(peer_ip, now)
            return False
        if not self._handshakes.allow(peer_ip, now=now):
            self._note(peer_ip, now)
            return False
        if entry is None:
            self._active[peer_ip] = _PeerState(count=1, last_seen=now)
        else:
            entry.count += 1
            entry.last_seen = now
        self._total_active += 1
        self._per_transport[transport] = self._per_transport.get(transport, 0) + 1
        self._metric_total += 1
        self._metric_per_transport[transport] = self._metric_per_transport.get(transport, 0) + 1
        self.stats.connections_changed(self._metric_total, opened=True)
        self.stats.transport_connections_changed(
            transport, self._metric_per_transport[transport], opened=True
        )
        return True

    def release(self, peer_ip: str, *, transport: str = "quic", now: float | None = None) -> None:
        """Mark one admitted connection from ``peer_ip`` as closed (full accounting)."""
        self._admission_release(peer_ip, transport, now)
        self._metrics_release(transport)

    def exempt(self, peer_ip: str, *, transport: str = "tcp", now: float | None = None) -> None:
        """Return one admitted connection's generic admission (TCP relay fan-out).

        The inverse of :meth:`admit` for a connection that belongs to a relay
        listener's fan-out: a TLS/TCP listener opens one connection per
        ``relay_attach``, and those are bounded by the relay session quotas, not
        the generic per-IP connection/handshake budget. Once the relay registry
        matches an attach it calls this through the connection's admission
        handle: the per-IP and process-wide active counts drop and the handshake
        token is refunded (never above ``handshake_burst``). Only the admission
        accounting is adjusted here — the metrics keep counting the open
        connection until it really closes (:meth:`release_metrics`).
        """
        self._admission_release(peer_ip, transport, now)
        self._handshakes.refund(peer_ip)

    def release_metrics(self, *, transport: str = "tcp") -> None:
        """Decrement the metric level for one closing exempted connection."""
        self._metrics_release(transport)

    def _admission_release(self, peer_ip: str, transport: str, now: float | None) -> None:
        self._total_active = max(0, self._total_active - 1)
        self._per_transport[transport] = max(0, self._per_transport.get(transport, 0) - 1)
        entry = self._active.get(peer_ip)
        if entry is None:
            return
        entry.count = max(0, entry.count - 1)
        entry.last_seen = time.monotonic() if now is None else now

    def _metrics_release(self, transport: str) -> None:
        self._metric_total = max(0, self._metric_total - 1)
        self._metric_per_transport[transport] = max(
            0, self._metric_per_transport.get(transport, 0) - 1
        )
        self.stats.connections_changed(self._metric_total)
        self.stats.transport_connections_changed(transport, self._metric_per_transport[transport])

    def transport_count(self, transport: str) -> int:
        """Open connections currently admitted for one transport (``quic``/``tcp``)."""
        return self._per_transport.get(transport, 0)

    def open_count(self, peer_ip: str) -> int:
        """Active connections currently accounted for (``0`` when unknown)."""
        entry = self._active.get(peer_ip)
        return entry.count if entry is not None else 0

    def total_count(self) -> int:
        """Process-wide admitted-connection count (``global_max`` accounting)."""
        return self._total_active

    def evict_stale(self, now: float | None = None) -> int:
        """Forget an IP once all of its connections closed and it went quiet.

        A refilled handshake bucket (``capacity / rate`` since last seen)
        behaves identically to a fresh one, so forgetting that IP cannot
        change any decision; this bounds the map under IP churn.
        """
        now = time.monotonic() if now is None else now
        stale = [
            ip
            for ip, entry in self._active.items()
            if entry.count <= 0 and now - entry.last_seen >= self._quiet_horizon
        ]
        for ip in stale:
            del self._active[ip]
        return len(stale)

    def _note(self, peer_ip: str, now: float) -> None:
        """Stamp the last-seen time so evict_stale() can reap refused IPs too."""
        entry = self._active.get(peer_ip)
        if entry is not None:
            entry.last_seen = now


def build_quic_configuration(
    identity: NodeIdentity,
    *,
    idle_timeout: float = RDV_IDLE_TIMEOUT,
    max_stream_data: int = MAX_STREAM_DATA_BYTES,
    max_data: int = MAX_DATA_BYTES,
) -> QuicConfiguration:
    """Server-side QUIC/TLS configuration bound to the given TLS identity."""
    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=[RDV_ALPN],
        idle_timeout=idle_timeout,
        max_stream_data=max_stream_data,
        max_data=max_data,
    )
    config.certificate = identity.certificate
    config.private_key = identity.private_key
    return config


async def _serve_rdv_session(
    *,
    handler: RendezvousHandler,
    reader: Any,
    writer: Any,
    peer_ip: str,
    peer_port: int,
    proto: BucketProto,
    idle_timeout: float | None = None,
    admission: Any | None = None,
    on_relay_handoff: Callable[[], None] | None = None,
) -> None:
    """Run one ``rdv/1`` request loop over a byte stream.

    Transport-agnostic: the QUIC listener calls this once per bidirectional
    stream (no idle timer, no admission handle), the TLS/TCP connection once per
    connection (``idle_timeout`` reaps a silent peer and ``admission`` is the
    connection's handle, returned to the relay once an ``relay_attach`` matches).
    On a ``RelayHandoff`` the same reader/writer are handed to the relay —
    ``pending`` bytes already read past the handshake newline included — and this
    loop returns; the caller owns the transport teardown. Keeping one loop here
    is what stops the two transports from drifting.
    """
    peer = f"{peer_ip}:{peer_port}"
    pending = bytearray()
    try:
        while True:
            raw = await read_ndjson(
                reader, pending, max_bytes=MAX_FRAME_BYTES, idle_timeout=idle_timeout
            )
            if raw is None:
                return  # EOF (client closes first) or the idle timeout
            response = handler.handle(raw, peer_ip=peer_ip, peer_port=peer_port, proto=proto)
            if isinstance(response, RelayHandoff):
                # The relay takes the connection/stream over: from here on the
                # bytes are opaque TLS, so the NDJSON loop must never consume
                # them. ``pending`` may already hold the first opaque bytes.
                if on_relay_handoff is not None:
                    on_relay_handoff()
                stream_reader: Any = reader
                if pending:
                    stream_reader = PrefixedReader(bytes(pending), reader)
                    pending.clear()
                await handler.relay.run(
                    response,
                    reader=stream_reader,
                    writer=writer,
                    peer_ip=peer_ip,
                    admission=admission,
                )
                return
            if response is not None:
                writer.write(response + b"\n")
                await writer.drain()
    except FrameTooLarge:
        debug_event("drop oversized-frame", peer=peer)
        return  # oversized frame: refuse and close the session silently
    except asyncio.CancelledError:
        # Cancellation is control flow, not a session failure: re-raise so the
        # owning task is really cancelled. The caller still tears the transport
        # down (QUIC stream task, or RendezvousTcpProtocol._handshake's finally).
        raise
    except (ConnectionError, TimeoutError, OSError):
        return
    except Exception as exc:  # noqa: BLE001 - one session must not take the node down
        # Unexpected failure in one session: the listener and every other session
        # stay up (isolation), but the operator must still see it — the always-on
        # error channel carries the exception CLASS only, no peer identity.
        error_event("session failed", exc=type(exc).__name__)
        if debug_enabled():
            # The opt-in peer-aware channel gets the exception detail too: it may
            # name the failing input, which is exactly what --debug is for.
            debug_event("session failure detail", exc=type(exc).__name__, error=repr(exc))


class RendezvousQuicProtocol(QuicConnectionProtocol):
    """One QUIC/UDP connection; every bidirectional stream is a ``rdv/1`` session.

    ``rdv_handler`` is bound by :func:`start_server` before the first datagram
    is dispatched (class attribute shared by all connections of the server).
    When a ``ConnectionGuard`` is bound too, a connecting peer is admitted
    against the per-IP handshake budget and active-connection cap before its
    server-side handshake work runs at all (see :meth:`datagram_received`).
    """

    boot_handler: RendezvousHandler

    def __init__(
        self,
        quic: Any,
        stream_handler: Callable[[Any, Any], Any] | None = None,
        guard: ConnectionGuard | None = None,
    ) -> None:
        super().__init__(quic, stream_handler)
        self.guard = guard
        # True once this connection was counted on the guard (one release per
        # admitted connection; the flag makes the count idempotent if QUIC
        # surfaces ConnectionTerminated twice).
        self.admitted_on_guard = False
        self.peer_addr: tuple[str, int] | None = None
        # Relay streams currently bridged on this connection. Tracked separately
        # from the rendezvous sessions so the relay headroom never raises the
        # per-connection budget a plain ``rdv/1`` client may pin.
        self._relay_streams = 0
        # Strong references to the per-session tasks: aioquic does not await the
        # stream handler, so without this the loop could garbage-collect a
        # running session.
        self._stream_tasks: set[asyncio.Task[None]] = set()
        # Route every new stream to our per-session coroutine instead of the
        # bare callback (aioquic does not await the stream handler itself).
        self._stream_handler = self._spawn_stream

    def datagram_received(self, data: bytes | str, addr: Any) -> None:
        peer_ip = str(addr[0])
        first = self.peer_addr is None
        # Transport admission happens BEFORE any handshake work: a refused IP
        # gets one CONNECTION_CLOSE and nothing else (see _refuse_unadmitted).
        if first:
            guard = self.guard
            if guard is not None:
                if not guard.admit(peer_ip, transport="quic"):
                    debug_event("connection refused ip-guard", peer=peer_ip)
                    payload = data.encode("utf-8") if isinstance(data, str) else data
                    self._refuse_unadmitted(payload, addr)
                    return
                self.admitted_on_guard = True
            # Keep the observed source endpoint: it is both the anti-amplification
            # ground truth and the STUN-echo answer (observed NAT-mapped port).
            self.peer_addr = (peer_ip, int(addr[1]))
        super().datagram_received(data, addr)

    def _refuse_unadmitted(self, data: bytes, addr: Any) -> None:
        """Reject an unadmitted connection without running any handshake work.

        aioquic registers a connection's QUIC network path only while processing
        its first datagram, and a CONNECTION_CLOSE cannot be sent without it, so
        the datagram is fed to ``QuicConnection`` at the bookkeeping layer only
        (``receive_datagram`` — no event processing, so no TLS work) and the
        connection is then closed. This is the single place that reaches into
        aioquic's private connection/loop (pinned ``>=1.2.0,<2.0.0``); the
        loopback guard test fails loudly if a future aioquic changes that shape.
        """
        self._quic.receive_datagram(data, addr, now=self._loop.time())
        self.close()

    def quic_event_received(self, event: QuicEvent) -> None:
        # Connection teardown releases the per-IP open-connection slot: the
        # guard's active count must converge to the real connection population.
        if (
            isinstance(event, ConnectionTerminated)
            and self.admitted_on_guard
            and self.guard is not None
        ):
            self.admitted_on_guard = False
            ip = self.peer_addr[0] if self.peer_addr is not None else "0.0.0.0"
            self.guard.release(ip, transport="quic")
        super().quic_event_received(event)

    def _observed_peer(self) -> tuple[str, int]:
        """Observed source endpoint, or a placeholder before the first datagram."""
        return self.peer_addr if self.peer_addr is not None else ("0.0.0.0", 0)

    def _spawn_stream(self, reader: Any, writer: Any) -> None:
        peer = self._observed_peer()
        rendezvous_streams = max(0, len(self._stream_tasks) - self._relay_streams)
        if (
            rendezvous_streams >= MAX_SESSIONS_PER_CONNECTION
            or self._relay_streams >= MAX_RELAY_STREAMS_PER_CONNECTION
        ):
            # rdv/1 uses one stream per exchange; the relay adds one long-lived
            # stream per paired session on its own budget. A connection over
            # either bound gets no further stream instead of pinning another
            # session task (see MAX_SESSIONS_PER_CONNECTION /
            # MAX_RELAY_STREAMS_PER_CONNECTION).
            debug_event("stream refused session-cap", peer=f"{peer[0]}:{peer[1]}")
            writer.close()
            return
        debug_event("session open", peer=f"{peer[0]}:{peer[1]}")
        task = asyncio.create_task(self._serve_stream(reader, writer))
        self._stream_tasks.add(task)
        task.add_done_callback(self._stream_tasks.discard)

    async def _serve_stream(self, reader: Any, writer: Any) -> None:
        peer_ip, peer_port = self._observed_peer()
        relay_stream = False

        def _on_relay_handoff() -> None:
            nonlocal relay_stream
            relay_stream = True
            self._relay_streams += 1

        try:
            await _serve_rdv_session(
                handler=self.boot_handler,
                reader=reader,
                writer=writer,
                peer_ip=peer_ip,
                peer_port=peer_port,
                proto="udp",
                on_relay_handoff=_on_relay_handoff,
            )
        finally:
            debug_event("session close", peer=f"{peer_ip}:{peer_port}")
            if relay_stream:
                self._relay_streams = max(0, self._relay_streams - 1)
            if not writer.is_closing():
                writer.close()


def _protocol_factory(
    handler: RendezvousHandler, guard: ConnectionGuard | None = None
) -> Callable[[Any, Any], Any]:
    """Build the aioquic ``create_protocol`` callable for one shared handler.

    aioquic instantiates one protocol object per QUIC connection; the closure
    binds the process-wide :class:`RendezvousHandler` and the optional :class:`ConnectionGuard`
    to each instance.
    """

    def _create(quic: Any, stream_handler: Any = None) -> RendezvousQuicProtocol:
        protocol = RendezvousQuicProtocol(quic, stream_handler, guard)
        protocol.boot_handler = handler
        return protocol

    return _create


async def start_servers(
    host: str,
    ports: Sequence[int],
    handler: RendezvousHandler,
    *,
    retry: bool = True,
    identity: NodeIdentity | None = None,
    idle_timeout: float = RDV_IDLE_TIMEOUT,
    connection_guard: ConnectionGuard | None = None,
) -> tuple[list[Any], list[int], NodeIdentity, list[tuple[int, BaseException]]]:
    """Bind one QUIC/UDP listener per port, all sharing ONE process-wide
    ``handler``, TLS identity and ``connection_guard``.

    A single routing table backs every port (decision #21: state sharding would
    break rendezvous — a peer registered via one port must be visible to a query
    via another). Binding is **best-effort**: a port that cannot bind (address
    in use, permission) is skipped and reported in ``failures`` so the node
    still starts on the ports that are free (e.g. 443 when 53 is taken by a
    local resolver). Raises the first ``OSError`` if **no** port could be bound.
    """
    if not ports:
        raise ValueError("start_servers requires at least one port")
    identity = identity or make_identity(host)
    config = build_quic_configuration(identity, idle_timeout=idle_timeout)
    factory = _protocol_factory(handler, connection_guard)

    servers: list[Any] = []
    bound_ports: list[int] = []
    failures: list[tuple[int, BaseException]] = []
    first_error: BaseException | None = None
    for port in ports:
        try:
            server = await serve(
                host,
                port,
                configuration=config,
                retry=retry,
                create_protocol=factory,
            )
        except OSError as exc:
            failures.append((port, exc))
            if first_error is None:
                first_error = exc
            continue
        transport = server._transport
        sockname = transport.get_extra_info("sockname") if transport is not None else None
        bound_ports.append(int(sockname[1]) if sockname is not None else int(port))
        servers.append(server)
    if not servers and first_error is not None:
        raise first_error
    return servers, bound_ports, identity, failures


async def start_server(
    host: str,
    port: int,
    handler: RendezvousHandler,
    *,
    retry: bool = True,
    identity: NodeIdentity | None = None,
    idle_timeout: float = RDV_IDLE_TIMEOUT,
    connection_guard: ConnectionGuard | None = None,
) -> tuple[Any, int, NodeIdentity]:
    """Start a single QUIC/UDP listener and return ``(server, bound_port, identity)``.

    Single-port form of :func:`start_servers` — the common one-listener case.
    ``retry`` enables QUIC RETRY packets + address-validation
    tokens before any connection state is allocated (spec: mandatory,
    anti-amplification). ``connection_guard`` adds the node-side per-IP handshake
    budget and active-connection cap.
    """
    servers, bound_ports, identity, _ = await start_servers(
        host,
        [port],
        handler,
        retry=retry,
        identity=identity,
        idle_timeout=idle_timeout,
        connection_guard=connection_guard,
    )
    return servers[0], bound_ports[0], identity


# ---------------------------------------------------------------------------
# TLS/TCP transport
# ---------------------------------------------------------------------------
# One connection = one ``rdv/1`` session. Bounded handshake so a stalled TLS
# handshake (slow-loris, a dead client) cannot pin the guard's active slot
# indefinitely. QUIC bounds the same hazard through aioquic's own handshake
# timeout, so this constant applies to the TLS/TCP accept path only.
TCP_HANDSHAKE_TIMEOUT = 10.0
# Listen backlog of the TLS/TCP listener (the asyncio default, made explicit).
TCP_LISTEN_BACKLOG = 100


def _write_all(fd: int, payload: bytes) -> None:
    """Write every byte of *payload* to *fd* (a short ``os.write`` is retried)."""
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _memfd(payload: bytes) -> int | None:
    """Anonymous in-memory file holding *payload*, or ``None`` where unsupported.

    ``os.memfd_create`` exists on Linux only (Python 3.8+); a hardened kernel
    may still refuse it. Returning ``None`` is not an error — the caller falls
    back to an owner-only temp file — but on Linux it is what keeps
    ``run --ephemeral`` (and, harmlessly, a persistent identity too) from ever
    putting the private key on a filesystem.
    """
    creator = getattr(os, "memfd_create", None)
    if creator is None:
        return None
    try:
        fd = creator("hsync-rdv-tls", 0)
    except OSError:
        return None
    try:
        _write_all(fd, payload)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        os.close(fd)
        return None
    return fd


def _load_cert_chain_from_memory(context: ssl.SSLContext, payload: bytes) -> None:
    """Load a combined PEM certificate+key into *context* without a plaintext key file.

    ``ssl.SSLContext.load_cert_chain`` accepts only a path, so the combined PEM
    (the node's own identity, never peer data) is handed to it through an
    anonymous memfd on Linux — read via ``/proc/self/fd/N`` — so the private key
    never touches a filesystem even with ``--ephemeral``. Where ``memfd_create``
    is unavailable (macOS/Windows) it falls back to an owner-only ``0600`` temp
    file, loaded and unlinked immediately.
    """
    fd = _memfd(payload)
    if fd is not None:
        try:
            context.load_cert_chain(f"/proc/self/fd/{fd}")
            return
        except OSError:
            # No /proc, or the load refused the fd: fall through to the temp-file
            # path rather than failing with an opaque error.
            pass
        finally:
            os.close(fd)
    file_fd, path = tempfile.mkstemp(prefix="hsync-rdv-tls-", suffix=".pem")
    try:
        with os.fdopen(file_fd, "wb") as handle:
            handle.write(payload)
        context.load_cert_chain(path)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def build_tls_context(identity: NodeIdentity) -> ssl.SSLContext:
    """Server-side TLS 1.3 context bound to the node's identity (ALPN ``hsync-rdv/1``).

    The combined PEM is loaded from memory (memfd on Linux, an unlinked temp file
    elsewhere) because ``load_cert_chain`` takes a path, not bytes. TLS 1.2 and
    below are refused. The ALPN token is enforced on both sides of the handshake:
    Python's server-side ALPN does not abort a connection whose offer does not
    overlap, so :class:`RendezvousTcpProtocol` closes one whose
    ``selected_alpn_protocol()`` is not :data:`RDV_ALPN` (parity with the aioquic
    listener, which the handshake rejects).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols([RDV_ALPN])
    payload = ssl_utils.serialize_identity_pem(
        ssl_utils.serialize_cert_pem(identity.certificate),
        ssl_utils.serialize_private_key_unencrypted(identity.private_key),
    )
    _load_cert_chain_from_memory(context, payload)
    return context


class RendezvousTcpProtocol(asyncio.Protocol):
    """One TLS/TCP connection = one ``rdv/1`` session.

    A plain :class:`asyncio.Protocol` because admission must run before the TLS
    handshake **and before any byte is read**: ``loop.create_server`` (no ``ssl``)
    hands the connection here first, so :meth:`connection_made` reads the observed
    ``peername``, charges the :class:`ConnectionGuard` (refusal →
    ``transport.abort()``, no handshake work) and only then upgrades to TLS with
    ``loop.start_tls``. Running the handshake in a ``start_server`` callback
    instead would race: the client's ClientHello may already sit in the
    ``StreamReader`` buffer and would be lost to TLS.

    One connection carries one session (several frames may be pipelined on it):
    the one-shot exchange (``register``/``refresh``/``leave``/``query``), the
    relay requester's data connection (``relay_connect``) and the relay
    listener's control connection (``relay_listen``). A relay ``relay_attach`` is
    a fresh connection too, so its admission can be returned once the registry
    matches it (:meth:`exempt`).
    """

    def __init__(
        self,
        handler: RendezvousHandler,
        context: ssl.SSLContext,
        guard: ConnectionGuard | None = None,
    ) -> None:
        self._handler = handler
        self._context = context
        self._guard = guard
        self._transport: asyncio.BaseTransport | None = None
        self._peer_ip = "0.0.0.0"
        self._peer_port = 0
        self._admitted = False
        self._released = False
        self._exempted = False
        self._task: asyncio.Task[None] | None = None

    # -- admission + handshake ------------------------------------------------

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport
        peer = transport.get_extra_info("peername")
        if peer is not None:
            # IPv4/IPv6 peername is (host, port[, flowinfo, scope_id]); only the
            # observed source is used, exactly as the QUIC listener derives it,
            # so the per-IP guards, rate limits and the relay peer_ip check agree.
            self._peer_ip = str(peer[0])
            self._peer_port = int(peer[1])
        # asyncio.Protocol declares ``BaseTransport``, but the concrete socket
        # transport is both a ReadTransport and a WriteTransport; narrow it back
        # to the halves that carry ``abort``/``pause_reading``/``start_tls``.
        write_transport = cast(asyncio.WriteTransport, transport)
        guard = self._guard
        if guard is not None:
            if not guard.admit(self._peer_ip, transport="tcp"):
                debug_event("tcp connection refused ip-guard", peer=self._peer_ip)
                write_transport.abort()
                return
            self._admitted = True
        # No byte is read before the handshake: pause so a client's ClientHello
        # cannot land in the StreamReader buffer as plaintext (start_tls resumes
        # reading once the TLS protocol is installed).
        cast(asyncio.ReadTransport, transport).pause_reading()
        self._task = asyncio.create_task(self._handshake(write_transport))

    def connection_lost(self, exc: Exception | None) -> None:
        # Fires only before start_tls takes over as the connection's protocol
        # (abort, a client that disconnects during or without the handshake); the
        # post-TLS path releases from _handshake's finally.
        self._release()

    def eof_received(self) -> bool:
        # Keep asyncio's half-open semantics for TCP streams.
        return False

    async def _handshake(self, transport: asyncio.WriteTransport) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=MAX_STREAM_DATA_BYTES)
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            new_transport = await loop.start_tls(
                transport,
                protocol,
                self._context,
                server_side=True,
                ssl_handshake_timeout=TCP_HANDSHAKE_TIMEOUT,
            )
        except (ssl.SSLError, ConnectionError, TimeoutError, OSError):
            self._release()
            transport.abort()
            return
        if new_transport is None:
            # ``start_tls`` returns None when the transport is already closing:
            # there is no TLS session to serve, so release and stop.
            self._release()
            return
        ssl_object = new_transport.get_extra_info("ssl_object")
        selected = ssl_object.selected_alpn_protocol() if ssl_object is not None else None
        if selected != RDV_ALPN:
            # Python's server-side ALPN does not abort on no overlap: enforce it
            # here, in parity with the aioquic listener. ``selected`` is None when
            # the client offered no ALPN at all. A graceful close (FIN) is used
            # instead of ``abort()`` so a client sees a clean EOF, not a reset.
            debug_event("tcp alpn refused", peer=self._peer_ip, alpn=selected)
            self._release()
            new_transport.close()
            return
        writer = asyncio.StreamWriter(
            cast(asyncio.WriteTransport, new_transport), protocol, reader, loop
        )
        try:
            await self._serve(reader, writer)
        finally:
            self._release()
            if not writer.is_closing():
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # -- session --------------------------------------------------------------

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # One shared, transport-agnostic session loop: only the idle timer (a
        # silent peer is reaped) and the admission handle (relay-attach fan-out)
        # differ from the QUIC stream path.
        await _serve_rdv_session(
            handler=self._handler,
            reader=reader,
            writer=writer,
            peer_ip=self._peer_ip,
            peer_port=self._peer_port,
            proto="tcp",
            idle_timeout=RDV_IDLE_TIMEOUT,
            admission=self,
        )

    # -- admission accounting -------------------------------------------------

    def _release(self) -> None:
        """Release this connection's accounting exactly once.

        An exempted connection returns its admission at exemption time; the
        metrics keep counting it until it really closes, so the close still
        decrements the metric level (``release_metrics``) without touching the
        admission accounting again.
        """
        if not self._admitted or self._released:
            return
        self._released = True
        guard = self._guard
        if guard is None:
            return
        if self._exempted:
            guard.release_metrics(transport="tcp")
        else:
            guard.release(self._peer_ip, transport="tcp")

    def exempt(self) -> None:
        """Return this connection's generic admission (relay-attach fan-out).

        Called by :meth:`hsync_rendezvous.relay.RelayRegistry._attach` once a
        ``relay_attach`` matches a pending session: the attach is then bounded by
        the relay session quotas, so its handshake token and active slot are
        returned. Idempotent; a later close does not release again.
        """
        if not self._admitted or self._released or self._exempted:
            return
        self._exempted = True
        guard = self._guard
        if guard is not None:
            guard.exempt(self._peer_ip, transport="tcp")


def _tcp_protocol_factory(
    handler: RendezvousHandler,
    context: ssl.SSLContext,
    guard: ConnectionGuard | None,
) -> Callable[[], RendezvousTcpProtocol]:
    """Build the ``loop.create_server`` protocol factory for one shared handler."""

    def _create() -> RendezvousTcpProtocol:
        return RendezvousTcpProtocol(handler, context, guard)

    return _create


def _bind_tcp_socket(host: str, port: int) -> socket.socket:
    """Bind and listen on one TCP socket (first address that binds wins).

    Uses the resolver so a hostname (or the ``::`` wildcard, with
    ``IPV6_V6ONLY=0`` for dual-stack) binds like the QUIC listener would; a
    concrete IP binds its own family. The socket is non-blocking, ready for
    ``loop.create_server(..., sock=...)``.
    """
    last_exc: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(sockaddr)
            sock.listen(TCP_LISTEN_BACKLOG)
            sock.setblocking(False)
            return sock
        except OSError as exc:
            last_exc = exc
            sock.close()
    if last_exc is not None:
        raise last_exc
    raise OSError(f"could not resolve {host}:{port}")


async def start_tcp_servers(
    host: str,
    ports: Sequence[int],
    handler: RendezvousHandler,
    *,
    identity: NodeIdentity | None = None,
    connection_guard: ConnectionGuard | None = None,
) -> tuple[list[asyncio.Server], list[int], NodeIdentity, list[tuple[int, BaseException]]]:
    """Bind one TLS/TCP listener per port, all sharing ONE handler/identity/guard.

    Same best-effort binding contract as :func:`start_servers`: a port that
    cannot bind (address in use, permission, e.g. 443 already held by a co-hosted
    HTTPS server) is skipped and reported in ``failures`` so the node still
    starts on the ports that are free. Raises the first ``OSError`` only when
    **no** port could be bound.
    """
    if not ports:
        raise ValueError("start_tcp_servers requires at least one port")
    identity = identity or make_identity(host)
    context = build_tls_context(identity)
    factory = _tcp_protocol_factory(handler, context, connection_guard)
    loop = asyncio.get_running_loop()

    servers: list[asyncio.Server] = []
    bound_ports: list[int] = []
    failures: list[tuple[int, BaseException]] = []
    first_error: BaseException | None = None
    for port in ports:
        try:
            sock = _bind_tcp_socket(host, port)
        except OSError as exc:
            failures.append((port, exc))
            if first_error is None:
                first_error = exc
            continue
        try:
            server = await loop.create_server(factory, sock=sock)
        except OSError as exc:
            sock.close()
            failures.append((port, exc))
            if first_error is None:
                first_error = exc
            continue
        bound_ports.append(int(sock.getsockname()[1]))
        servers.append(server)
    if not servers and first_error is not None:
        raise first_error
    return servers, bound_ports, identity, failures


async def start_tcp_server(
    host: str,
    port: int,
    handler: RendezvousHandler,
    *,
    identity: NodeIdentity | None = None,
    connection_guard: ConnectionGuard | None = None,
) -> tuple[asyncio.Server, int, NodeIdentity]:
    """Start a single TLS/TCP listener and return ``(server, bound_port, identity)``.

    Single-port form of :func:`start_tcp_servers` — the common one-listener case.
    ``connection_guard`` adds the node-side per-IP handshake budget and
    active-connection cap, charged before the TLS handshake.
    """
    servers, bound_ports, identity, _ = await start_tcp_servers(
        host,
        [port],
        handler,
        identity=identity,
        connection_guard=connection_guard,
    )
    return servers[0], bound_ports[0], identity
