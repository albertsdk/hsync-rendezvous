"""Serialization of the ``rdv/1`` relay control frames.

Hand-assembled through the same pydantic adapters the wire contract pins; kept
separate from the registry so the byte layout and the pairing/pump logic can
change independently.
"""

from __future__ import annotations

from typing import Any

from hsync_rendezvous.protocol import (
    PROTOCOL_VERSION_RDV,
    RDV_FRAME_ADAPTER,
    RDV_RELAY_ERROR_ADAPTER,
    RDV_RELAY_INCOMING_ADAPTER,
    RDV_RELAY_LISTENING_ADAPTER,
    RDV_RELAY_OK_ADAPTER,
    RdvError,
    RdvRelayError,
    RdvRelayIncoming,
    RdvRelayListening,
    RdvRelayOk,
    RdvRelayPing,
)

__all__ = [
    "close_writer",
    "error_frame",
    "incoming_frame",
    "is_ping",
    "listening_frame",
    "ok_frame",
    "refuse",
    "terminate",
]


def terminate(payload: bytes) -> bytes:
    """Terminate one serialized frame the way ``rdv/1`` NDJSON expects."""
    return payload + b"\n"


def close_writer(writer: Any) -> None:
    """Close a stream writer, tolerating an already-closed stream."""
    try:
        if not writer.is_closing():
            writer.close()
    except Exception:  # noqa: BLE001 - teardown must never raise
        return


async def refuse(writer: Any, error: RdvError) -> None:
    """Write a ``relay_error`` line and close the stream."""
    try:
        writer.write(terminate(error_frame(error)))
        await writer.drain()
    except (ConnectionError, TimeoutError, OSError):
        pass
    close_writer(writer)


def is_ping(raw: bytes, cid: str, bucket: str) -> bool:
    """Whether ``raw`` is a ``relay_ping`` for this listener (never logged)."""
    try:
        frame = RDV_FRAME_ADAPTER.validate_json(raw)
    except Exception:  # noqa: BLE001 - any validation failure is a violation
        return False
    return isinstance(frame, RdvRelayPing) and frame.cid == cid and frame.bucket == bucket


def listening_frame(*, ttl: int) -> bytes:
    return RDV_RELAY_LISTENING_ADAPTER.dump_json(
        RdvRelayListening(protocol_version=PROTOCOL_VERSION_RDV, type="relay_listening", ttl=ttl)
    )


def incoming_frame(*, relay_id: str, cid: str, expires_in: int) -> bytes:
    return RDV_RELAY_INCOMING_ADAPTER.dump_json(
        RdvRelayIncoming(
            protocol_version=PROTOCOL_VERSION_RDV,
            type="relay_incoming",
            relay_id=relay_id,
            cid=cid,
            expires_in=expires_in,
        )
    )


def ok_frame(relay_id: str) -> bytes:
    return RDV_RELAY_OK_ADAPTER.dump_json(
        RdvRelayOk(protocol_version=PROTOCOL_VERSION_RDV, type="relay_ok", relay_id=relay_id)
    )


def error_frame(error: RdvError) -> bytes:
    """Serialize one uniform refusal (never a bucket-existence oracle)."""
    return RDV_RELAY_ERROR_ADAPTER.dump_json(
        RdvRelayError(protocol_version=PROTOCOL_VERSION_RDV, type="relay_error", error=error)
    )
