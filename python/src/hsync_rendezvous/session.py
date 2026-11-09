"""Transport-agnostic ``rdv/1`` session loop.

One request loop shared by the QUIC stream path and the TLS/TCP connection path;
keeping it single is what stops the two transports from drifting. The relay
hand-off (the point where the bytes stop being NDJSON and become an opaque pipe)
is handled here so both transports behave identically.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from hsync_rendezvous.diagnostics import debug_enabled, debug_event, error_event
from hsync_rendezvous.framing import FrameTooLarge, read_ndjson
from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.limits import MAX_FRAME_BYTES
from hsync_rendezvous.protocol import BucketProto
from hsync_rendezvous.relay import PrefixedReader, RelayHandoff

__all__ = ["serve_rdv_session"]


async def serve_rdv_session(
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
    loop returns; the caller owns the transport teardown.
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
        handler.note_drop("oversized_frame")
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
