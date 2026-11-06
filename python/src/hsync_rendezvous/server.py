"""Transport assembly and public surface of the rendezvous node.

Binds the process-wide :class:`~hsync_rendezvous.handler.RendezvousHandler`,
TLS identity and :class:`~hsync_rendezvous.guard.ConnectionGuard` to one or more
listeners, on **both** transports. The per-transport code lives in
:mod:`hsync_rendezvous.quic` and :mod:`hsync_rendezvous.tcp`; the reusable
pieces (identity, guard, TLS material, session loop, limits) live in their own
modules and are re-exported here as the transport layer's public surface.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from hsync_common.protocol.rendezvous import RDV_ALPN, RDV_IDLE_TIMEOUT

from hsync_rendezvous.guard import ConnectionGuard
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.identity import (
    IdentityError,
    NodeIdentity,
    load_identity,
    load_or_create_identity,
    make_identity,
    rotate_identity,
    rotation_hint,
)
from hsync_rendezvous.limits import (
    CONNECTION_ACTIVE_MAX_PER_IP,
    HANDSHAKE_BURST_PER_IP,
    HANDSHAKE_RATE_PER_SECOND,
    MAX_DATA_BYTES,
    MAX_FRAME_BYTES,
    MAX_RELAY_STREAMS_PER_CONNECTION,
    MAX_SESSIONS_PER_CONNECTION,
    MAX_STREAM_DATA_BYTES,
)
from hsync_rendezvous.quic import (
    RendezvousQuicProtocol,
    build_quic_configuration,
    protocol_factory,
    serve_quic_port,
)
from hsync_rendezvous.tcp import (
    RendezvousTcpProtocol,
    serve_tcp_port,
    tcp_protocol_factory,
)
from hsync_rendezvous.tls import build_tls_context

__all__ = [
    "RDV_ALPN",
    "RDV_IDLE_TIMEOUT",
    "CONNECTION_ACTIVE_MAX_PER_IP",
    "HANDSHAKE_BURST_PER_IP",
    "HANDSHAKE_RATE_PER_SECOND",
    "MAX_DATA_BYTES",
    "MAX_FRAME_BYTES",
    "MAX_RELAY_STREAMS_PER_CONNECTION",
    "MAX_SESSIONS_PER_CONNECTION",
    "MAX_STREAM_DATA_BYTES",
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


async def _bind_each_port(
    ports: Sequence[int],
    bind_one: Callable[[int], Awaitable[tuple[Any, int]]],
) -> tuple[list[Any], list[int], list[tuple[int, BaseException]], BaseException | None]:
    """Bind *ports* one at a time, best-effort (shared by both transports).

    A port that refuses to bind is skipped and reported in ``failures`` so the
    node still starts on the free ports; ``first_error`` is remembered so the
    caller can fail when **no** port bound. Each ``bind_one`` returns the bound
    server plus its real port (an ``0`` port resolves to the kernel-assigned
    one), keeping the per-transport bind detail next to its transport.
    """
    servers: list[Any] = []
    bound_ports: list[int] = []
    failures: list[tuple[int, BaseException]] = []
    first_error: BaseException | None = None
    for port in ports:
        try:
            server, bound_port = await bind_one(port)
        except OSError as exc:
            failures.append((port, exc))
            if first_error is None:
                first_error = exc
            continue
        servers.append(server)
        bound_ports.append(bound_port)
    return servers, bound_ports, failures, first_error


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
    factory = protocol_factory(handler, connection_guard)

    servers, bound_ports, failures, first_error = await _bind_each_port(
        ports,
        lambda port: serve_quic_port(port, host=host, config=config, retry=retry, factory=factory),
    )
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
    factory = tcp_protocol_factory(handler, context, connection_guard)
    loop = asyncio.get_running_loop()

    servers, bound_ports, failures, first_error = await _bind_each_port(
        ports,
        lambda port: serve_tcp_port(port, host=host, loop=loop, factory=factory),
    )
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
