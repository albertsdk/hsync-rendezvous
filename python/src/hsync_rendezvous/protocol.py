"""``rdv/1`` wire-protocol frame models and strict validators.

This is the Python mirror of ``protocol-spec/rdv-1.md`` (single source of
truth at the repository root). Values are validated with ``extra="forbid"`` so
any unknown field — including any targeted "file X" request — is rejected.

Every frame carries a mandatory ``type`` discriminator (common header
``{protocol_version, type, ...}``); the server routes on it and never guesses
the frame kind from the payload shape.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Literal

# CID shape is the hsync-common SSOT (``hsync_common.models.event.CID_PATTERN``,
# ``^[A-Za-z0-9]{21}$``), re-exported here because the daemon imports it from
# ``hsync_rendezvous.protocol``. The ``rdv/1`` spec documents the same value;
# ``test_cid_pattern_matches_boot1_spec`` pins the two together.
from hsync_common.endpoint import is_valid_endpoint_host
from hsync_common.models.event import CID_PATTERN
from hsync_common.path_validation import is_valid_bucket_name
from hsync_common.protocol.pairing import parse_fingerprint
from hsync_common.protocol.rdv_tokens import BUCKET_TOKEN_LEN, is_valid_bucket_token
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, TypeAdapter

__all__ = [
    "RDV_ACK_ADAPTER",
    "RDV_FRAME_ADAPTER",
    "RDV_PEER_ADAPTER",
    "RDV_RELAY_ERROR_ADAPTER",
    "RDV_RELAY_INCOMING_ADAPTER",
    "RDV_RELAY_LISTENING_ADAPTER",
    "RDV_RELAY_OK_ADAPTER",
    "BUCKET_TOKEN_LEN",
    "CAPACITY_MAX",
    "CID_PATTERN",
    "MAX_RELAY_ENDPOINTS",
    "MAX_RESPONSE_BYTES",
    "PROTOCOL_VERSION_RDV",
    "STARTUP_TIME_MAX",
    "RdvAck",
    "RdvError",
    "RdvFrame",
    "RdvLeave",
    "RdvPeer",
    "RdvQuery",
    "RdvRefresh",
    "RdvRegister",
    "RdvRelayAttach",
    "RdvRelayConnect",
    "RdvRelayError",
    "RdvRelayIncoming",
    "RdvRelayListen",
    "RdvRelayListening",
    "RdvRelayOk",
    "RdvRelayPing",
    "BucketName",
    "BucketProto",
    "Endpoint",
    "ObservedEndpoint",
    "RelayId",
    "SyncDirection",
]

# Per-channel protocol version. Bump the suffix on any breaking change to the
# rendezvous channel's wire shape; peers then hard-fail instead of drifting.
PROTOCOL_VERSION_RDV: Literal["rdv/1"] = "rdv/1"

# hex(32 bytes) = 64 chars. Absent = open bucket. The token grammar and the
# derivation live in the shared, protocol-neutral
# ``hsync_common.protocol.rdv_tokens`` (re-exported by ``tokens.py``).
BucketProto = Literal["tcp", "udp"]

# Advisory service-capacity hint domain (``0..32``; ``0`` = not a peer-download
# seeder). Mirrors the authenticated ``serve_slots`` range (1..32); the rendezvous
# relays the value in ``query`` responses but never treats it as authoritative
# (ADR 0030) — the authoritative value stays on the authenticated WSS handshake.
CAPACITY_MAX = 32

# Canonical sync-direction vocabulary, mirrored from the client SSOT
# (``hsync_common.protocol.pairing`` + ``p2p``). The election advertisement
# below reuses the same tokens the mDNS TXT record carries so a rendezvous-relayed
# peer ranks exactly like a LAN-discovered one.
SyncDirection = Literal["bidirectional", "upload-only", "download-only"]

# Uniform refusal codes on a ``response``/``relay_error``: ``token_required``
# (authorization), ``rate_limited`` (per-IP/per-(IP,bucket) rate limit —
# ``retry_after`` is the bucket refill), ``overloaded`` (the node is at its
# host-derived ceiling; backpressure, not a client abuse signal) and
# ``relay_unavailable`` (no data relay: disabled on this node, no listener for
# the target CID, or the listener did not attach in time).
RdvError = Literal["token_required", "rate_limited", "overloaded", "relay_unavailable"]

# Upper bound for the advisory ``connected`` count, like ``startup_time`` kept
# inside the exactly-representable integer range of a JSON number: a wire value
# beyond this is garbage (silent drop) instead of an unbounded integer.
CONNECTED_MAX = 2**53

# Bound on the advertised unix ``startup_time`` (kept inside the
# exactly-representable integer range of a JSON number). ``0.0`` = unknown.
STARTUP_TIME_MAX = float(2**53)

# A ``response`` relays at most this many endpoints per peer, and the relayed
# peer fragments of one response stay within this byte budget. Both bound what an
# unauthenticated registrant can make the node emit: a 16-endpoint, 50-peer
# maximum would turn an 81-byte query into a ~260 KiB reply, i.e. a
# self-amplifying reflection surface (and a frame far above the 8 KiB ingress
# bound).
MAX_RELAY_ENDPOINTS = 4
MAX_RESPONSE_BYTES = 32 * 1024


def _validated_string(*, check: Callable[[str], bool], error: str) -> Callable[[str], str]:
    """One validator factory for the string-typed wire fields.

    Every canonical field type (bucket name, bucket token, endpoint host,
    certificate fingerprint) validates against the shared ``hsync_common``
    grammar for its domain, never an ad-hoc length bound; a value that fails it
    makes the frame invalid (silently dropped, like every other malformed
    frame).
    """

    def validate(value: str) -> str:
        if not check(value):
            raise ValueError(error)
        return value

    return validate


# Canonical bucket-name field type, applied to every ``bucket`` on the wire:
# ``[A-Za-z0-9]`` with ``-``/``_`` only in the middle, 1..63 characters.
BucketName = Annotated[
    str,
    AfterValidator(
        _validated_string(
            check=is_valid_bucket_name,
            error="invalid bucket name (canonical HSYNC bucket name required)",
        )
    ),
]


# Canonical bucket-token field type, applied to every ``bucket_token`` on the
# wire: hex(HMAC-SHA256(key, 'rdv/1' || bucket)[:32]), always 64 lowercase hex.
# Enforcing the grammar here (like ``BucketName`` does) turns a non-conforming
# token into an invalid frame — silently dropped and rate-limited by the
# malformed-frame budget — instead of a failed-token attempt.
BucketToken = Annotated[
    str,
    AfterValidator(
        _validated_string(
            check=is_valid_bucket_token,
            error="bucket_token must be 64 lowercase hex characters",
        )
    ),
]


# Canonical endpoint-host field type, applied to every advertised ``host``: an
# ``endpoints[]`` host is relayed to third parties and dialed by them, so only
# a value a resolver can turn into an address (IP literal or LDH hostname) is
# accepted — anything else would poison the relay.
EndpointHost = Annotated[
    str,
    AfterValidator(
        _validated_string(
            check=is_valid_endpoint_host,
            error="endpoint host must be an IP literal or a valid DNS name",
        )
    ),
]


# Canonical certificate-fingerprint field type for ``cert_fp``: it must
# normalize to a full SHA-256 digest (``sha256:<hex>``, bare hex, or
# separator-grouped hex — the shared ``parse_fingerprint`` grammar), because a
# short or malformed value would be unusable for pinning downstream.
CertificateFingerprint = Annotated[
    str,
    AfterValidator(
        _validated_string(
            check=lambda value: parse_fingerprint(value) is not None,
            error="cert_fp must be a SHA-256 certificate fingerprint (sha256:<hex> or bare hex)",
        )
    ),
]


# Data-relay session identifier handed out by the node per pairing: 16 random
# bytes as lowercase hex. Only the two paired peers ever see it, and a value that
# does not match a live pending session attaches to nothing.
RelayId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class _StrictModel(BaseModel):
    """A wire model that rejects every field it does not declare."""

    model_config = ConfigDict(extra="forbid")


class Endpoint(_StrictModel):
    """An advertised listen endpoint (register's ``endpoints[]``)."""

    proto: BucketProto
    host: EndpointHost
    port: int = Field(ge=1, le=65535)


class ObservedEndpoint(_StrictModel):
    """The source endpoint observed by the server (STUN-echo in ``ack``)."""

    proto: BucketProto
    ip: str
    port: int = Field(ge=1, le=65535)


class _RdvFrame(_StrictModel):
    """Common shape: mandatory ``type`` discriminator + ``protocol_version``."""

    protocol_version: Literal["rdv/1"]
    type: str


class _BucketFrame(_RdvFrame):
    """A frame scoped to one bucket, carrying the optional authorizing token.

    ``bucket_token`` is the optional authorizer (the handler checks it, never
    the model): on an open node it only gates the buckets the operator declared
    protected, and a private node requires it for every frame.
    """

    cid: str = Field(pattern=CID_PATTERN)
    bucket: BucketName
    bucket_token: BucketToken | None = None


class _GroupBucketFrame(_BucketFrame):
    """A bucket frame scoped to an optional group (registrant-selected slot)."""

    group: str | None = Field(default=None, max_length=128)


class RdvRegister(_GroupBucketFrame):
    """Client announces presence in a bucket (first contact).

    ``capacity`` is the advisory service-capacity hint: the number of
    concurrent peer-download reads the peer declares it can serve right now
    (``0`` = not a seeder). The rendezvous relays it in ``query`` responses; the
    authoritative value is the authenticated ``serve_slots`` (ADR 0030).

    ``server_ready``/``prefer_master``/``never_master``/``inbound``/
    ``startup_time``/``sync_direction`` are the **election advertisement**: the
    same values the mDNS TXT record carries, relayed verbatim in ``query`` peers
    so a rendezvous-discovered peer ranks exactly like a LAN-discovered one. The
    node never interprets them; they are not authenticated and not authoritative
    (the data plane authenticates identity by certificate pinning). A changed
    advertisement requires a new ``register`` — ``refresh`` never mutates them.
    """

    type: Literal["register"]
    cert_fp: CertificateFingerprint = Field(max_length=256)
    version: str = Field(min_length=1, max_length=64)
    capacity: int = Field(default=0, ge=0, le=CAPACITY_MAX)
    endpoints: list[Endpoint] = Field(default_factory=list, max_length=16)
    connected: int | None = Field(default=None, ge=0, le=CONNECTED_MAX)
    server_ready: bool = False
    prefer_master: bool = False
    never_master: bool = False
    inbound: bool = False
    startup_time: float = Field(default=0.0, ge=0, le=STARTUP_TIME_MAX)
    sync_direction: SyncDirection = "bidirectional"


class RdvRefresh(_GroupBucketFrame):
    """Client renews its TTL (and/or connected count) — authenticated like register."""

    type: Literal["refresh"]
    connected: int | None = Field(default=None, ge=0, le=CONNECTED_MAX)


class RdvLeave(_BucketFrame):
    """Client announces departure.

    ``bucket_token`` is optional on the wire: a private node (``--private``)
    enforces it, a protected bucket accepts it in place of a matching source
    IP. On an open bucket the departure is honoured only from the source
    network the peer registered from (handler leave policy): an
    unauthenticated leave from any other IP is silently ignored, so a frame
    that merely knows a ``(cid, bucket)`` pair cannot spoof a departure.
    """

    type: Literal["leave"]


class RdvQuery(_RdvFrame):
    """Client asks for a random sample of peers. Only generic — no file targeting."""

    type: Literal["query"]
    bucket: BucketName
    group: str | None = Field(default=None, max_length=128)
    bucket_token: BucketToken | None = None
    limit: int = Field(default=20, ge=1, le=50)


class RdvAck(_RdvFrame):
    """Server reply to register/refresh: STUN-echo observed endpoint + TTL."""

    type: Literal["ack"]
    observed_endpoint: ObservedEndpoint
    ttl: int = Field(ge=1, le=3600)
    server_time: str
    retry_after: int | None = Field(default=None, ge=1)


class RdvPeer(_StrictModel):
    """A single advertised peer in a query response.

    ``endpoints`` is capped at :data:`MAX_RELAY_ENDPOINTS` entries (in the
    peer's advertised order) so one response stays bounded, and each ``host``
    is guaranteed dialable by the shared grammar.

    ``capacity`` is the peer's advisory service-capacity hint as relayed from
    its ``register`` (``0`` = not a seeder). It is not authenticated and not
    authoritative: the requester must treat the authenticated ``serve_slots``
    as the source of truth (ADR 0030).

    The election-advertisement fields are the peer's own ``register`` values
    (documented defaults when it advertised none), relayed verbatim so the
    requester's master election sees the same inputs a mDNS-discovered peer
    would provide. They are unauthenticated claims — the data plane
    authenticates identity by certificate pinning.
    """

    cid: str = Field(pattern=CID_PATTERN)
    endpoints: list[Endpoint] = Field(min_length=1, max_length=16)
    cert_fp: CertificateFingerprint = Field(max_length=256)
    bucket: BucketName
    group: str | None = None
    version: str = Field(min_length=1, max_length=64)
    capacity: int = Field(default=0, ge=0, le=CAPACITY_MAX)
    connected: int = Field(default=0, ge=0, le=CONNECTED_MAX)
    reachable: bool = True
    server_ready: bool = False
    prefer_master: bool = False
    never_master: bool = False
    inbound: bool = False
    startup_time: float = Field(default=0.0, ge=0, le=STARTUP_TIME_MAX)
    sync_direction: SyncDirection = "bidirectional"


class RdvRelayListen(_GroupBucketFrame):
    """A serving peer registers a data-relay listener (``relay_listen``).

    The stream that carried this frame becomes the listener's **control**
    stream: the node answers ``relay_listening`` and pushes one
    ``relay_incoming`` per requester (the peer may answer with ``relay_ping``
    lines). The node accepts it only from the current owner of the
    ``(cid, bucket, group)`` record, so a peer cannot open a relay under
    another peer's identity.
    """

    type: Literal["relay_listen"]


class RdvRelayPing(_RdvFrame):
    """Keepalive on a listener control stream (``relay_ping``, no reply)."""

    type: Literal["relay_ping"]
    cid: str = Field(pattern=CID_PATTERN)
    bucket: BucketName


class RdvRelayConnect(_GroupBucketFrame):
    """A requester asks to be paired with a listening peer (``relay_connect``).

    Sent on a fresh stream: the node answers ``relay_ok`` (the rest of the
    stream is then opaque TLS) or ``relay_error`` followed by a close.
    """

    type: Literal["relay_connect"]
    target_cid: str = Field(pattern=CID_PATTERN)


class RdvRelayAttach(_BucketFrame):
    """A listener attaches the stream of one relayed session (``relay_attach``).

    First (and only framed) line of a fresh stream; every following byte is
    opaque TLS in both directions.
    """

    type: Literal["relay_attach"]
    relay_id: RelayId


class RdvRelayListening(_RdvFrame):
    """Server→listener: the relay listener is registered."""

    type: Literal["relay_listening"]
    ttl: int = Field(ge=1, le=3600)


class RdvRelayIncoming(_RdvFrame):
    """Server→listener: a requester wants one session.

    ``cid`` is the requester's CID (the listener bounds per-peer concurrency),
    ``expires_in`` the seconds left to attach before the node drops it.
    """

    type: Literal["relay_incoming"]
    relay_id: RelayId
    cid: str = Field(pattern=CID_PATTERN)
    expires_in: int = Field(ge=1, le=3600)


class RdvRelayOk(_RdvFrame):
    """Server→requester: the pairing exists and the stream is now opaque."""

    type: Literal["relay_ok"]
    relay_id: RelayId


class RdvRelayError(_RdvFrame):
    """Server→client: a relay request was refused."""

    type: Literal["relay_error"]
    error: RdvError
    retry_after: int | None = Field(default=None, ge=1)


# Client→server frames, dispatched on ``type``. ``RdvAck``/``RdvPeer`` and the
# ``relay_*`` server replies are server→client and deliberately excluded: they
# are never validated in the input path.
RdvFrame = Annotated[
    RdvRegister
    | RdvRefresh
    | RdvLeave
    | RdvQuery
    | RdvRelayListen
    | RdvRelayPing
    | RdvRelayConnect
    | RdvRelayAttach,
    Field(discriminator="type"),
]
RDV_FRAME_ADAPTER: TypeAdapter[RdvFrame] = TypeAdapter(RdvFrame)

# Server→client serializers: ``dump_json`` emits ``bytes`` directly, so the
# transport writes them verbatim instead of decoding to ``str`` and re-encoding.
# ``RDV_PEER_ADAPTER`` serializes one peer, so a record can cache its response
# fragment (``PeerRecord.wire``) instead of the ``RdvPeer`` model.
RDV_ACK_ADAPTER: TypeAdapter[RdvAck] = TypeAdapter(RdvAck)
RDV_PEER_ADAPTER: TypeAdapter[RdvPeer] = TypeAdapter(RdvPeer)
RDV_RELAY_LISTENING_ADAPTER: TypeAdapter[RdvRelayListening] = TypeAdapter(RdvRelayListening)
RDV_RELAY_INCOMING_ADAPTER: TypeAdapter[RdvRelayIncoming] = TypeAdapter(RdvRelayIncoming)
RDV_RELAY_OK_ADAPTER: TypeAdapter[RdvRelayOk] = TypeAdapter(RdvRelayOk)
RDV_RELAY_ERROR_ADAPTER: TypeAdapter[RdvRelayError] = TypeAdapter(RdvRelayError)


assert is_valid_bucket_token("a" * BUCKET_TOKEN_LEN)
