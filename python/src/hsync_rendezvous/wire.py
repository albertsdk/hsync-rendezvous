"""Hand-assembled ``rdv/1`` reply serialization.

The response/ack envelopes carry only server-controlled values (a fixed protocol
version/type, integers, the ASCII ``RdvError`` literal and the observed socket
endpoint), so they are assembled without a pydantic round-trip; peer fragments
are still produced by the pydantic adapter. Keeping the byte layout here (pure
functions) leaves ``RendezvousHandler`` focused on the matching logic, while the
byte-for-byte contract stays pinned by the handler tests.
"""

from __future__ import annotations

from hsync_rendezvous.protocol import (
    MAX_RELAY_ENDPOINTS,
    PROTOCOL_VERSION_RDV,
    RDV_PEER_ADAPTER,
    BucketProto,
    Endpoint,
    RdvError,
    RdvPeer,
    RdvQuery,
)
from hsync_rendezvous.routing import PeerRecord

__all__ = [
    "ack_bytes",
    "peer_fragment",
    "response_bytes",
]

# Pre-encoded once: the response envelope embeds it on every reply.
_PROTOCOL_VERSION_BYTES = PROTOCOL_VERSION_RDV.encode("ascii")


def response_bytes(
    *,
    ttl: float,
    peers: list[bytes],
    error: RdvError | None,
    retry_after: int | None,
) -> bytes:
    """Assemble the response envelope around pre-serialized peer fragments.

    The envelope carries only server-controlled values (a fixed protocol
    version/type, integers, and the ASCII ``RdvError`` literal), so it needs no
    JSON escaping; every peer fragment is still produced by the pydantic adapter
    (:func:`peer_fragment`). Byte-for-byte identical to what the test-side
    pydantic mirror (``tests/rdv_response``) emits — pinned by
    ``test_response_bytes_match_the_pydantic_serializer``.
    """
    error_field = b"null" if error is None else b'"' + error.encode("ascii") + b'"'
    retry_field = b"null" if retry_after is None else str(retry_after).encode("ascii")
    return (
        b'{"protocol_version":"'
        + _PROTOCOL_VERSION_BYTES
        + b'","type":"response","peers":['
        + b",".join(peers)
        + b'],"count":'
        + str(len(peers)).encode("ascii")
        + b',"ttl":'
        + str(int(ttl)).encode("ascii")
        + b',"error":'
        + error_field
        + b',"retry_after":'
        + retry_field
        + b"}"
    )


def ack_bytes(
    *,
    ttl: float,
    peer_ip: str,
    peer_port: int,
    proto: BucketProto,
    server_time: str,
) -> bytes:
    """Assemble the STUN-echo ``ack`` for the observed source endpoint.

    ``proto`` is the transport the frame arrived on: the client uses the observed
    host (with its own p2p listen port) as a fallback candidate. Hand-assembled
    like :func:`response_bytes`: the envelope is server-controlled and the
    observed ip/port come from the socket, so a pydantic round-trip would only
    re-validate already-trusted values. Byte-identical to the model dump — pinned
    by ``test_ack_bytes_match_the_pydantic_serializer``.
    """
    return (
        b'{"protocol_version":"rdv/1","type":"ack","observed_endpoint":'
        b'{"proto":"'
        + proto.encode("ascii")
        + b'","ip":"'
        + peer_ip.encode("ascii")
        + b'","port":'
        + str(peer_port).encode("ascii")
        + b'},"ttl":'
        + str(int(ttl)).encode("ascii")
        + b',"server_time":"'
        + server_time.encode("ascii")
        + b'","retry_after":null}'
    )


def peer_fragment(record: PeerRecord, model: RdvQuery) -> bytes:
    """Relay the peer's candidate endpoints over the observed source.

    The first :data:`MAX_RELAY_ENDPOINTS` advertised candidates are relayed
    verbatim and in order; only a register that carried no endpoint at all (the
    first STUN register) falls back to a single-element list with the observed
    source endpoint. Both branches share one projection so the relayed advisory
    fields (``capacity``, ``reachable`` and the election advertisement) cannot
    drift; the whole record is relayed verbatim and never interpreted.

    Returns the pre-serialized JSON fragment (not the ``RdvPeer`` model), so the
    record caches bytes — see ``PeerRecord.wire``.
    """
    cached = record.wire
    if cached is not None:
        return cached
    if record.endpoints:
        endpoints = [
            Endpoint(proto=proto, host=host, port=port)
            for (proto, host, port) in record.endpoints[:MAX_RELAY_ENDPOINTS]
        ]
    else:
        endpoints = [Endpoint(proto=record.proto, host=record.ip, port=record.port)]
    peer = RdvPeer(
        cid=record.cid,
        endpoints=endpoints,
        cert_fp=record.cert_fp,
        bucket=model.bucket,
        group=record.group,
        version=record.version,
        capacity=record.capacity,
        connected=record.connected,
        reachable=record.reachable,
        server_ready=record.server_ready,
        prefer_master=record.prefer_master,
        never_master=record.never_master,
        inbound=record.inbound,
        startup_time=record.startup_time,
        sync_direction=record.sync_direction,
    )
    fragment = RDV_PEER_ADAPTER.dump_json(peer)
    record.wire = fragment
    return fragment
