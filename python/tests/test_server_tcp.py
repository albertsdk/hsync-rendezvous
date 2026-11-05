"""TLS/TCP transport tests: context/guard units + real loopback rdv/1 exchanges.

The loopback tests spin up a real TLS/TCP listener on 127.0.0.1:0 and talk to it
with a real ``asyncio`` TLS client (TLS 1.3, ALPN ``hsync-rdv/1``): they exercise
the full public contract (register→ack with STUN-echo tagged ``tcp``, query→
response, ALPN enforcement, admission before the handshake, pipelining) exactly
as a remote peer would.
"""

from __future__ import annotations

import asyncio
import json
import ssl

import pytest

from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.server import (
    MAX_FRAME_BYTES,
    RDV_ALPN,
    ConnectionGuard,
    RendezvousTcpProtocol,
    build_tls_context,
    make_identity,
    start_tcp_server,
)

CID = "A1b2C3d4E5f6G7h8I9j0K"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


def _client_context(*, alpn: str | None = RDV_ALPN) -> ssl.SSLContext:
    """A client TLS context that trusts nothing (the node is self-signed).

    ``check_hostname`` is cleared *before* ``verify_mode`` (the reverse order
    raises); ALPN is advertised only when a token is given, so an ALPN-less or
    wrong-token connection can be exercised too.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if alpn is not None:
        context.set_alpn_protocols([alpn])
    return context


async def _exchange(
    port: int,
    frame: dict,
    *,
    reader: asyncio.StreamReader | None = None,
    writer: asyncio.StreamWriter | None = None,
    context: ssl.SSLContext | None = None,
) -> dict:
    """Send one frame over TLS/TCP and return the single reply line.

    With ``reader``/``writer`` the frame rides an existing connection (the node
    keeps reading until EOF, so several frames may be pipelined on one
    connection); otherwise a fresh connection is opened and left to close.
    """
    owns = writer is None
    if writer is None:
        context = context or _client_context()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
    assert writer is not None and reader is not None
    writer.write((json.dumps(frame) + "\n").encode("utf-8"))
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), 5.0)
    if owns:
        writer.close()
    return json.loads(line)


def _register_frame(*, endpoints: list[dict] | None = None) -> dict:
    return {
        "protocol_version": "rdv/1",
        "type": "register",
        "cid": CID,
        "bucket": "shared",
        "group": "home",
        "cert_fp": FP,
        "version": "1.0.0",
        "endpoints": endpoints if endpoints is not None else [],
    }


def _query_frame() -> dict:
    return {"protocol_version": "rdv/1", "type": "query", "bucket": "shared", "group": "home"}


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------


def test_build_tls_context_is_tls13() -> None:
    context = build_tls_context(make_identity(host="127.0.0.1"))
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3


def test_guard_exempt_returns_admission_and_handshake_token() -> None:
    """``exempt`` undoes one admission (active slot + one handshake token)."""
    guard = ConnectionGuard(handshake_rate=0.001, handshake_burst=1, active_max=10)
    assert guard.admit("10.0.0.1", transport="tcp") is True
    assert guard.transport_count("tcp") == 1
    # The single burst token is spent: a second admission is refused.
    assert guard.admit("10.0.0.1", transport="tcp") is False
    # Exempting returns the slot AND the token, so the next admission succeeds.
    guard.exempt("10.0.0.1", transport="tcp")
    assert guard.open_count("10.0.0.1") == 0
    assert guard.transport_count("tcp") == 0
    assert guard.admit("10.0.0.1", transport="tcp") is True
    assert guard.transport_count("tcp") == 1


def test_tcp_protocol_exempt_is_idempotent_and_blocks_release() -> None:
    """The connection handle exempts once; a later close only lowers the metrics."""
    guard = ConnectionGuard(handshake_rate=0.001, handshake_burst=1, active_max=10)
    handler = RendezvousHandler(enforce_rate_limits=False)
    protocol = RendezvousTcpProtocol(handler, build_tls_context(make_identity()), guard)
    protocol._peer_ip = "10.0.0.1"
    protocol._admitted = True
    guard.admit("10.0.0.1", transport="tcp")
    assert guard.open_count("10.0.0.1") == 1
    assert guard.stats.connections_current == 1

    # Exemption returns the admission slot + handshake token but the metrics
    # keep counting the open connection (relay fan-out is bounded by session
    # quotas, not by the generic connection cap).
    protocol.exempt()
    protocol.exempt()  # idempotent
    assert guard.open_count("10.0.0.1") == 0
    assert guard.transport_count("tcp") == 0
    assert guard.stats.connections_current == 1

    # The real close lowers the metric level without touching admission again
    # (already returned at exemption time).
    protocol._release()
    assert guard.open_count("10.0.0.1") == 0
    assert guard.transport_count("tcp") == 0
    assert guard.stats.connections_current == 0


# ---------------------------------------------------------------------------
# loopback exchanges
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_loopback_register_query_tags_tcp_proto() -> None:
    """A TCP register→ack echoes the observed source with ``proto: tcp``."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    server, port, _identity = await start_tcp_server("127.0.0.1", 0, handler)
    try:
        ack = await _exchange(port, _register_frame())
        assert ack["type"] == "ack"
        assert ack["observed_endpoint"]["ip"] == "127.0.0.1"
        assert ack["observed_endpoint"]["proto"] == "tcp"

        response = await _exchange(port, _query_frame())
        assert response["error"] is None
        assert response["count"] == 1
        assert response["peers"][0]["cid"] == CID
    finally:
        server.close()


@pytest.mark.asyncio
async def test_endpointless_register_falls_back_to_tcp_observed_source() -> None:
    """An endpoint-less register relays the observed source tagged ``tcp``."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    server, port, _identity = await start_tcp_server("127.0.0.1", 0, handler)
    try:
        await _exchange(port, _register_frame(endpoints=[]))
        response = await _exchange(port, _query_frame())
        fallback = response["peers"][0]["endpoints"][0]
        assert fallback["proto"] == "tcp"
        assert fallback["host"] == "127.0.0.1"
    finally:
        server.close()


@pytest.mark.asyncio
async def test_pipelined_frames_on_one_connection() -> None:
    """The node keeps reading after a reply, so one connection carries several frames."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    server, port, _identity = await start_tcp_server("127.0.0.1", 0, handler)
    try:
        context = _client_context()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
        try:
            ack = await _exchange(port, _register_frame(), reader=reader, writer=writer)
            assert ack["type"] == "ack"
            # Same connection, second exchange: no EOF after the first reply.
            response = await _exchange(port, _query_frame(), reader=reader, writer=writer)
            assert response["type"] == "response"
            assert response["count"] == 1
        finally:
            writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_alpn_mismatch_is_refused() -> None:
    """A client offering a different ALPN is closed before any frame is served."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    server, port, _identity = await start_tcp_server("127.0.0.1", 0, handler)
    try:
        context = _client_context(alpn="hsync-other/1")
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
        try:
            # The server aborts: the client sees EOF without ever being served.
            line = await asyncio.wait_for(reader.readline(), 5.0)
            assert line == b""
        finally:
            writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_admission_refused_before_handshake() -> None:
    """An IP out of handshake budget is refused before any TLS handshake work."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    guard = ConnectionGuard(handshake_rate=0.001, handshake_burst=1, active_max=10)
    server, port, _identity = await start_tcp_server(
        "127.0.0.1", 0, handler, connection_guard=guard
    )
    context = _client_context()
    try:
        # First connection: admitted, and held open to keep its token spent.
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
        try:
            await asyncio.sleep(0.05)
            assert guard.transport_count("tcp") == 1
            with pytest.raises(OSError):
                await asyncio.open_connection(
                    "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
                )
        finally:
            writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_handshake_timeout_releases_admission(monkeypatch) -> None:
    """A connection that never completes the handshake is closed and its slot freed."""
    import hsync_rendezvous.server as server_mod

    monkeypatch.setattr(server_mod, "TCP_HANDSHAKE_TIMEOUT", 0.2)
    handler = RendezvousHandler(enforce_rate_limits=False)
    guard = ConnectionGuard(handshake_rate=1000.0, handshake_burst=1000, active_max=10)
    server, port, _identity = await start_tcp_server(
        "127.0.0.1", 0, handler, connection_guard=guard
    )
    try:
        # A raw TCP connection that never sends a ClientHello.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            assert await asyncio.wait_for(reader.read(), 5.0) == b""
            assert guard.transport_count("tcp") == 0  # admission returned
        finally:
            writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_oversized_frame_closes_the_session() -> None:
    """A frame past the 8 KiB bound is refused and the connection closed."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    server, port, _identity = await start_tcp_server("127.0.0.1", 0, handler)
    try:
        context = _client_context()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
        try:
            # No newline: the bound is what trips, not a valid-but-large frame.
            writer.write(b"x" * (MAX_FRAME_BYTES + 1))
            await writer.drain()
            assert await asyncio.wait_for(reader.readline(), 5.0) == b""
        finally:
            writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_idle_connection_is_reaped(monkeypatch) -> None:
    """A silent connection is dropped by the idle read timer."""
    import hsync_rendezvous.server as server_mod

    monkeypatch.setattr(server_mod, "RDV_IDLE_TIMEOUT", 0.2)
    handler = RendezvousHandler(enforce_rate_limits=False)
    server, port, _identity = await start_tcp_server("127.0.0.1", 0, handler)
    try:
        context = _client_context()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
        try:
            assert await asyncio.wait_for(reader.readline(), 5.0) == b""
        finally:
            writer.close()
    finally:
        server.close()


async def _wait_tcp_count(guard: ConnectionGuard, expected: int, timeout: float = 5.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if guard.transport_count("tcp") == expected:
            return True
        await asyncio.sleep(0.02)
    return False


def _relay_frame(**fields: object) -> dict:
    return {"protocol_version": "rdv/1", **fields}


@pytest.mark.asyncio
async def test_only_a_matched_tcp_attach_is_exempt_from_admission() -> None:
    """The attach's generic admission is returned; relay_listen/connect stay charged."""
    handler = RendezvousHandler(enforce_rate_limits=False)
    guard = ConnectionGuard(handshake_rate=1000.0, handshake_burst=1000, active_max=100)
    server, port, _identity = await start_tcp_server(
        "127.0.0.1", 0, handler, connection_guard=guard
    )
    context = _client_context()
    listener_reader, listener_writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
    )
    requester_reader, requester_writer = await asyncio.open_connection(
        "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
    )
    attach_writer = None
    try:
        # Listener: register + control connection with relay_listen.
        await _exchange(port, _register_frame(), reader=listener_reader, writer=listener_writer)
        listener_writer.write(
            (
                json.dumps(_relay_frame(type="relay_listen", cid=CID, bucket="shared")) + "\n"
            ).encode()
        )
        await listener_writer.drain()
        assert json.loads(await asyncio.wait_for(listener_reader.readline(), 5.0))["type"] == (
            "relay_listening"
        )

        # Requester: pair a session; the control and data connections are both charged.
        requester_writer.write(
            (
                json.dumps(
                    _relay_frame(
                        type="relay_connect",
                        cid="Z9y8X7w6V5u4T3s2R1q0P",
                        bucket="shared",
                        target_cid=CID,
                    )
                )
                + "\n"
            ).encode()
        )
        await requester_writer.drain()
        incoming = json.loads(await asyncio.wait_for(listener_reader.readline(), 5.0))
        assert incoming["type"] == "relay_incoming"
        relay_id = incoming["relay_id"]
        assert json.loads(await asyncio.wait_for(requester_reader.readline(), 5.0))["type"] == (
            "relay_ok"
        )
        assert await _wait_tcp_count(guard, 2)  # control + data, both charged

        # Attach: a fresh connection that matches the pending session is exempted,
        # so the charged count drops back to the two non-exempt connections.
        attach_reader, attach_writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="127.0.0.1"
        )
        attach_writer.write(
            (
                json.dumps(
                    _relay_frame(type="relay_attach", cid=CID, bucket="shared", relay_id=relay_id)
                )
                + "\n"
            ).encode()
        )
        await attach_writer.drain()
        assert await _wait_tcp_count(guard, 2)  # attach exempted, others still charged
        assert attach_reader is not None
    finally:
        for writer in (attach_writer, requester_writer, listener_writer):
            if writer is not None:
                writer.close()
        server.close()
