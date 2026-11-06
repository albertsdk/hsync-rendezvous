"""Listener binding, best-effort multi-port startup and their operator messages.

Shared by the QUIC and TLS/TCP startup paths in ``cli``: one transport's bind
failure (or a requested port that could not bind) is turned into the same
actionable, peer-free stderr message and exit-code contract.
"""

from __future__ import annotations

import errno
import os
from collections.abc import Sequence
from typing import Any

from hsync_rendezvous.diagnostics import warn_event
from hsync_rendezvous.guard import ConnectionGuard
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.identity import NodeIdentity
from hsync_rendezvous.server import start_servers, start_tcp_servers

__all__ = [
    "BindError",
    "ReadyFileError",
    "bind_error",
    "bind_error_message",
    "bind_transport",
    "ready_file_error_message",
    "warn_bind_failures",
]


class BindError(Exception):
    """A bound endpoint could not be created (privileged port, port in use, bad host).

    Raised for every endpoint the node exposes — the QUIC/UDP listeners and the
    loopback metrics listener. ``what`` names the endpoint in the messages,
    ``port_flag``/``port_example`` the flags a free port is picked with and
    ``bind_advice`` the fallback guidance line.
    """

    def __init__(
        self,
        host: str,
        port: int,
        errno_value: int | None,
        *,
        what: str,
        port_flag: str,
        port_example: str,
        bind_advice: str,
    ) -> None:
        self.host = host
        self.port = port
        self.errno_value = errno_value
        self.what = what
        self.port_flag = port_flag
        self.port_example = port_example
        self.bind_advice = bind_advice
        super().__init__(f"cannot bind {host}:{port}")


class ReadyFileError(Exception):
    """The readiness PID file could not be written (missing directory, permission)."""

    def __init__(self, path: str, errno_value: int | None) -> None:
        self.path = path
        self.errno_value = errno_value
        self.reason = os.strerror(errno_value) if errno_value is not None else "write failed"
        super().__init__(f"cannot write the readiness file {path}: {self.reason}")


def errno_from(exc: BaseException) -> int | None:
    """Return the OS errno behind a bind failure, from ``exc`` or its cause.

    ``aioquic`` wraps the underlying ``create_datagram_endpoint`` error in a bare
    ``OSError("could not bind to local_addr …")`` without an ``errno``; the real
    ``PermissionError``/``OSError`` (carrying the errno) is chained as
    ``__cause__``.
    """
    if isinstance(exc, OSError) and exc.errno is not None:
        return exc.errno
    cause = exc.__cause__
    if isinstance(cause, OSError):
        return cause.errno
    return None


def warn_bind_failures(failures: list[tuple[int, BaseException]], *, proto: str) -> None:
    """Warn (always-on, peer-free) about requested ports a transport could not bind.

    Best-effort binding: a port held by another process (e.g. TCP 443 by a
    co-hosted HTTPS server, or UDP 53 by a local resolver) is skipped so the node
    still serves on the ports that are free.
    """
    for failed_port, failure in failures:
        errno_value = errno_from(failure)
        warn_event(
            "listener port unavailable",
            port=failed_port,
            proto=proto,
            reason=os.strerror(errno_value) if errno_value is not None else "bind failed",
        )


async def bind_transport(
    *,
    proto: str,
    host: str,
    ports: Sequence[int],
    handler: RendezvousHandler,
    identity: NodeIdentity | None,
    connection_guard: ConnectionGuard | None,
    what: str,
    bind_advice: str,
) -> tuple[list[Any], list[int], NodeIdentity | None, BindError | None]:
    """Bind one transport's listeners, best-effort (shared UDP/TCP startup shape).

    Returns the newly-bound servers, their real bound ports, the TLS identity the
    transport resolved and a :class:`BindError` only when the transport as a
    whole failed to bind; per-port failures are warned about (never fatal). The
    caller extends its own server/port lists and keeps the first failure for the
    exit path.
    """
    try:
        if proto == "udp":
            new_servers, new_ports, resolved_identity, failures = await start_servers(
                host,
                ports,
                handler,
                retry=True,
                identity=identity,
                connection_guard=connection_guard,
            )
        else:
            new_servers, new_ports, resolved_identity, failures = await start_tcp_servers(
                host,
                ports,
                handler,
                identity=identity,
                connection_guard=connection_guard,
            )
    except OSError as exc:
        return (
            [],
            [],
            identity,
            bind_error(host, ports[0], exc, what=what, bind_advice=bind_advice),
        )
    # Best-effort: a requested port that could not bind (address in use, e.g. 53
    # held by the local resolver) is skipped with an always-on, peer-free warning
    # instead of failing the whole node.
    warn_bind_failures(failures, proto=proto)
    return new_servers, new_ports, resolved_identity, None


def bind_error(
    host: str,
    port: int,
    exc: BaseException,
    *,
    what: str,
    bind_advice: str,
) -> BindError:
    """Build the exit-path :class:`BindError` for one failed transport bind."""
    return BindError(
        host,
        port,
        errno_from(exc),
        what=what,
        port_flag="--listen-port <PORT>",
        port_example="--listen-port 8443",
        bind_advice=bind_advice,
    )


def bind_error_message(exc: BindError) -> str:
    """Actionable stderr message for a failed endpoint bind (exit code 3)."""
    target = f"{exc.host}:{exc.port}"
    if exc.errno_value in (errno.EACCES, errno.EPERM):
        return (
            f"error: cannot bind {exc.what} on {target} — permission denied.\n"
            "       Ports below 1024 (the 443 default) need root or CAP_NET_BIND_SERVICE.\n"
            f"       Fix: use an unprivileged port (hsync-rendezvous run {exc.port_example}), run as\n"
            "       root, or grant the capability to the binary:\n"
            "         sudo setcap cap_net_bind_service=+ep <hsync-rendezvous>\n"
            "       The packaged systemd unit already grants CAP_NET_BIND_SERVICE."
        )
    if exc.errno_value == errno.EADDRINUSE:
        return (
            f"error: cannot bind {exc.what} on {target} — address already in use.\n"
            f"       Stop the process holding the port, or pick a free one: "
            f"hsync-rendezvous run {exc.port_flag}"
        )
    if exc.errno_value in (errno.EADDRNOTAVAIL, errno.EINVAL):
        return (
            f"error: cannot bind {exc.what} on {target} — the address is not available.\n"
            "       --listen-host must be a local interface address, or 0.0.0.0 to listen on all of them."
        )
    reason = os.strerror(exc.errno_value) if exc.errno_value is not None else "bind failed"
    return f"error: cannot bind {exc.what} on {target}: {reason}.\n       {exc.bind_advice}"


def ready_file_error_message(exc: ReadyFileError) -> str:
    """Actionable stderr message for an unwritable readiness file (exit code 4)."""
    target = exc.path
    if exc.errno_value == errno.ENOENT:
        return (
            f"error: cannot write the readiness file {target} — no such directory.\n"
            "       The parent directory must exist before the node starts: create it,\n"
            "       or drop --ready-file when nothing awaits the readiness signal."
        )
    if exc.errno_value in (errno.EACCES, errno.EPERM, errno.EROFS):
        return (
            f"error: cannot write the readiness file {target} — permission denied.\n"
            "       Point --ready-file at a path writable by the node's user."
        )
    if exc.errno_value == errno.EEXIST:
        return (
            f"error: cannot write the readiness file {target} — the path already exists.\n"
            "       A stale file from a previous run is not overwritten by design: remove it."
        )
    return (
        f"error: cannot write the readiness file {target}: {exc.reason}.\n"
        "       Check --ready-file (HSYNC_RENDEZVOUS_READY_FILE)."
    )
