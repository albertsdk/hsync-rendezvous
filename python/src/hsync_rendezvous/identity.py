"""Persistent and in-memory TLS identity for the rendezvous node.

A self-signed ECDSA P-256 certificate built from ``hsync_common.ssl_utils``
(ADR-0037). It persists by default at a state path (``0600`` in a ``0700``
directory) so its fingerprint is stable and pin-able across restarts;
``run --ephemeral`` keeps it in memory instead. Either way, no peer data is ever
written to disk (no-log).
"""

from __future__ import annotations

import ipaddress
import os
import stat
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hsync_common import ssl_utils

from hsync_rendezvous.diagnostics import error_event, warn_event

__all__ = [
    "IdentityError",
    "NodeIdentity",
    "PrivateKey",
    "load_identity",
    "load_or_create_identity",
    "make_identity",
    "rotate_identity",
    "rotation_hint",
]

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


class IdentityError(RuntimeError):
    """The persistent identity file could not be loaded or written safely."""


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
