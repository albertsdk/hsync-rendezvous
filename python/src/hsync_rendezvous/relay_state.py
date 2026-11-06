"""State types for the ``rdv/1`` data relay.

The registry's bookkeeping (listener, pending session, quotas), the handoff
value returned by the handler, and the byte-prefix reader used when the handshake
line and the first opaque bytes arrive together. No networking logic here.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from hsync_rendezvous.protocol import RdvRelayAttach, RdvRelayConnect, RdvRelayListen

__all__ = [
    "Listener",
    "Pending",
    "PrefixedReader",
    "RelayHandoff",
    "RelayQuotas",
]


@dataclass(slots=True, frozen=True)
class RelayQuotas:
    """Hard bounds applied to the relay, derived from the host or the flags.

    ``session_bytes`` and ``bytes_per_second`` are unlimited when ``0``; the
    session cap is enforced by closing the session (a requester reconnects and
    resumes), the byte rate by throttling the pump (real backpressure).
    """

    max_sessions: int
    max_sessions_per_ip: int
    max_sessions_per_bucket: int
    session_bytes: int = 0
    bytes_per_second: int = 0


@dataclass(slots=True, frozen=True)
class RelayHandoff:
    """A validated relay frame whose work needs the connection's own streams.

    ``RendezvousHandler`` validates and authorizes relay frames (it owns the token
    policy and the record-ownership rules) and returns one of these instead of
    reply bytes; the stream coroutine then hands the reader/writer to
    :meth:`RelayRegistry.run`. ``authorized=False`` is how a frame whose stream
    is already opaque (``relay_attach``) is refused: the node just closes it.
    """

    model: RdvRelayListen | RdvRelayConnect | RdvRelayAttach
    authorized: bool = True


@dataclass(slots=True)
class Listener:
    cid: str
    bucket: str
    group: str | None
    peer_ip: str
    writer: Any
    sessions: int = 0


@dataclass(slots=True)
class Pending:
    listener: Listener
    dialer_cid: str
    dialer_ip: str
    dialer_reader: Any
    dialer_writer: Any
    bucket: str
    attached: asyncio.Event = field(default_factory=asyncio.Event)
    done: asyncio.Event = field(default_factory=asyncio.Event)
    acceptor: tuple[Any, Any] | None = None
    bytes: int = 0
    reserved: bool = True
    # Last instant either direction forwarded an opaque chunk (idle watch).
    last_activity: float = field(default_factory=time.monotonic)


class PrefixedReader:
    """Reader that replays bytes the frame reader already buffered.

    The NDJSON frame reader may read past the newline of a relay handshake line
    (``relay_attach``/``relay_connect``), and those bytes are the *beginning* of
    the opaque stream: dropping them would corrupt the relayed TLS of any client
    that pipelines its first bytes with the handshake. ``read`` returns the
    buffered prefix first, then delegates to the connection's own reader.
    """

    __slots__ = ("_buffer", "_reader")

    def __init__(self, prefix: bytes, reader: Any) -> None:
        self._buffer = bytearray(prefix)
        self._reader = reader

    async def read(self, size: int = -1) -> bytes:
        """Return buffered bytes first, then read from the wrapped stream."""
        if self._buffer:
            if size is None or size < 0:
                data = bytes(self._buffer)
                self._buffer.clear()
                return data
            data = bytes(self._buffer[:size])
            del self._buffer[:size]
            return data
        return await self._reader.read(size)
