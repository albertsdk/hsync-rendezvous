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
import ipaddress
import os
import re
import stat
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hsync_common import ssl_utils

from hsync_rendezvous.diagnostics import debug_enabled, debug_event, error_event, warn_event
from hsync_rendezvous.framing import FrameTooLarge, read_ndjson
from hsync_rendezvous.handler import RendezvousHandler
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
    "ConnectionGuard",
    "IdentityError",
    "NodeIdentity",
    "build_quic_configuration",
    "load_identity",
    "load_or_create_identity",
    "make_identity",
    "rotate_identity",
    "rotation_hint",
    "start_server",
    "start_servers",
]

# ALPN protocol advertised on the QUIC handshake (client and server must agree).
RDV_ALPN = "hsync-rdv/1"
# Spec: idle connections are dropped after 30 s.
RDV_IDLE_TIMEOUT = 30.0
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

# PEM block extractors for the combined ``identity.pem`` (cert + private key).
_CERT_PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)
_KEY_PEM_RE = re.compile(rb"-----BEGIN PRIVATE KEY-----.+?-----END PRIVATE KEY-----", re.DOTALL)

# Identity file/dir permissions: a long-lived private key must not be world-readable.
_IDENTITY_FILE_MODE = 0o600
_IDENTITY_DIR_MODE = 0o700


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


def _identity_pem(identity: NodeIdentity) -> bytes:
    """Serialize a combined cert + unencrypted PKCS#8 key PEM payload."""
    return (
        ssl_utils.serialize_cert_pem(identity.certificate)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(identity.private_key)
    )


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


def _ensure_identity_dir(identity_path: Path) -> None:
    """Create the identity directory with ``0700``, never re-permission one we did not create.

    ``--identity`` may point into a directory this process does not own (a shared
    state tree, a bind-mounted volume, ``/tmp``): tightening its permissions
    unconditionally would break every other user of that path. A directory we
    create is ``0700``; a pre-existing one is reported when it is
    group/world-writable and left untouched.
    """
    parent = identity_path.parent
    if parent.exists():
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
        return
    parent.mkdir(parents=True, exist_ok=True, mode=_IDENTITY_DIR_MODE)
    os.chmod(parent, _IDENTITY_DIR_MODE)


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
    _ensure_identity_dir(identity_path)
    _atomic_write_identity(identity_path, _identity_pem(identity))
    return identity


def _san_names(certificate: x509.Certificate) -> list[str]:
    """Return the DNS and IP SANs of ``certificate`` as strings.

    Rotation preserves these names; other GeneralName types (URI, email, …) are
    never produced by the rendezvous, so they are intentionally ignored.
    """
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [
        *san.get_values_for_type(x509.DNSName),
        *(str(address) for address in san.get_values_for_type(x509.IPAddress)),
    ]


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
    _atomic_write_identity(identity_path, _identity_pem(identity))
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
    cert_match = _CERT_PEM_RE.search(data)
    key_match = _KEY_PEM_RE.search(data)
    if cert_match is None or key_match is None:
        raise IdentityError(
            f"identity file {identity_path} must contain a certificate and a "
            "PKCS#8 private key; delete it and restart to regenerate"
        )
    try:
        cert = x509.load_pem_x509_certificate(cert_match.group(0))
        key = serialization.load_pem_private_key(key_match.group(0), password=None)
    except ValueError as exc:
        raise IdentityError(
            f"identity file {identity_path} is not a valid PEM identity: {exc}"
        ) from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise IdentityError(f"identity file {identity_path} must hold an ECDSA P-256 private key")
    return cert, key


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


def _atomic_write_identity(identity_path: Path, payload: bytes) -> None:
    """Write the identity file atomically with owner-only permissions.

    The temporary file gets a **unique** name in the target directory: a crash
    (SIGKILL between create and replace) can leave a temp behind, and with a
    fixed name that leftover would block every later write on the exclusive
    creation flag, because the ``finally`` cleanup never runs after SIGKILL.
    A unique name means a stale temp can never block a later write; ``mkstemp``
    creates the file ``0600``, it is chmodded explicitly and handed to
    ``os.replace``, so a reader never observes a partial identity.
    """
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{identity_path.name}.", suffix=".tmp", dir=identity_path.parent
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, _IDENTITY_FILE_MODE)
        os.replace(tmp, identity_path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


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
        # Seconds an IP must stay quiet (with all of its connections closed)
        # before evict_stale() forgets it: capacity/rate refills the bucket to
        # exactly the first-use value, so forgetting is decision-neutral.
        self._quiet_horizon = handshake_burst / handshake_rate
        # ip -> open connection count + last-seen stamp (see evict_stale).
        self._active: dict[str, _PeerState] = {}

    def admit(self, peer_ip: str, *, now: float | None = None) -> bool:
        """Admit one new (connecting) connection from ``peer_ip``.

        Returns False when the IP has no handshake budget left, already holds
        ``active_max`` open connections, or the process-wide ``global_max``
        ceiling would be exceeded; the caller must then refuse the connection
        instead of running its handshake.
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
        self.stats.connections_changed(self._total_active, opened=True)
        return True

    def release(self, peer_ip: str, *, now: float | None = None) -> None:
        """Mark one connection from ``peer_ip`` as closed."""
        self._total_active = max(0, self._total_active - 1)
        self.stats.connections_changed(self._total_active)
        entry = self._active.get(peer_ip)
        if entry is None:
            return
        entry.count = max(0, entry.count - 1)
        entry.last_seen = time.monotonic() if now is None else now

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
                if not guard.admit(peer_ip):
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
            self.guard.release(ip)
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
        try:
            pending = bytearray()
            while True:
                raw = await read_ndjson(reader, pending, max_bytes=MAX_FRAME_BYTES)
                if raw is None:
                    return  # EOF: normal stream close, not a protocol drop
                response = self.boot_handler.handle(
                    raw,
                    peer_ip=peer_ip,
                    peer_port=peer_port,
                )
                if isinstance(response, RelayHandoff):
                    # The relay takes the stream over: from here on the bytes are
                    # opaque TLS, so the NDJSON loop must never consume them.
                    # ``pending`` may already hold the first opaque bytes (the
                    # frame read can pass the handshake newline), so it is handed
                    # back to the relay instead of being dropped.
                    self._relay_streams += 1
                    relay_stream = True
                    stream_reader = reader
                    if pending:
                        stream_reader = PrefixedReader(bytes(pending), reader)
                        pending.clear()
                    await self.boot_handler.relay.run(
                        response, reader=stream_reader, writer=writer, peer_ip=peer_ip
                    )
                    return
                if response is not None:
                    writer.write(response + b"\n")
                    await writer.drain()
        except FrameTooLarge:
            debug_event("drop oversized-frame", peer=f"{peer_ip}:{peer_port}")
            return  # oversized frame: refuse and close the session silently
        except (asyncio.CancelledError, ConnectionError, TimeoutError):
            return
        except Exception as exc:
            # Unexpected failure in one session: the listener and every other
            # session stay up (isolation), but the operator must still see it —
            # the always-on error channel carries the exception CLASS only, no
            # peer identity. Without this the traceback would reach asyncio's
            # fallback handler in an unformatted, undocumented shape.
            error_event("session failed", exc=type(exc).__name__)
            if debug_enabled():
                # The opt-in peer-aware channel gets the exception detail too: it
                # may name the failing input, which is exactly what --debug is
                # for. The always-on line above stays class-only and peer-free.
                debug_event("session failure detail", exc=type(exc).__name__, error=repr(exc))
            return
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
