"""TLS material helpers for the TLS/TCP transport.

The combined cert+key PEM is handed to ``ssl.SSLContext.load_cert_chain``
without ever putting the private key on a filesystem: an anonymous memfd on
Linux, an unlinked owner-only temp file elsewhere.
"""

from __future__ import annotations

import contextlib
import os
import ssl
import tempfile

from hsync_common import ssl_utils
from hsync_common.protocol.rendezvous import RDV_ALPN

from hsync_rendezvous.identity import NodeIdentity

__all__ = ["build_tls_context"]


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
    overlap, so :class:`hsync_rendezvous.tcp.RendezvousTcpProtocol` closes one
    whose ``selected_alpn_protocol()`` is not :data:`RDV_ALPN` (parity with the
    aioquic listener, which the handshake rejects).
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
