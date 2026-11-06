"""In-memory routing table for ``rdv/1`` — RAM only, no persistence.

Keyed by ``(cid, bucket, group)``; entries carry a TTL and are pruned by a
background sweep. Queries return a random sample (``K``). Nothing is ever
written to disk from this module.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import TypeVar

from hsync_rendezvous.protocol import BucketProto, RdvRegister, SyncDirection

_T = TypeVar("_T")

__all__ = [
    "DEFAULT_SAMPLE_LIMIT",
    "DEFAULT_TTL",
    "PeerRecord",
    "RoutingTable",
]

# A peer's advertised candidate endpoint, kept wire-agnostic as a
# ``(proto, host, port)`` tuple. The record is the long-lived object (up to the
# host-derived ceiling); holding pydantic ``Endpoint`` models in it costs ~3x the
# tuple for data only needed at serialization time.
EndpointTuple = tuple[BucketProto, str, int]

# Peer sampling is part of the matchmaker's exposure surface: with the
# predictable MT19937 generator a heavy query loop could reconstruct state and
# steer future samples. Draws come straight from ``os.urandom`` through a
# batch buffer (one syscall per chunk instead of one per draw) with rejection
# sampling, so the matchmaking stays OS-random and a K-index sample costs a
# fraction of the per-draw syscall version.
_RANDOM_CHUNK_BYTES = 256

# Seconds (spec: client refresh every 30 s, prune every 15 s, TTL 60 s).
DEFAULT_TTL = 60.0
DEFAULT_SAMPLE_LIMIT = 20


@dataclass(slots=True)
class PeerRecord:
    """A single active peer in a bucket/group."""

    cid: str
    bucket: str
    group: str | None
    ip: str
    cert_fp: str
    version: str
    endpoints: tuple[EndpointTuple, ...] = ()
    connected: int = 0
    reachable: bool = True
    capacity: int = 0
    # Election advertisement relayed verbatim from ``register`` (defaults when
    # the peer advertised none). The node never interprets these values.
    server_ready: bool = False
    prefer_master: bool = False
    never_master: bool = False
    inbound: bool = False
    startup_time: float = 0.0
    sync_direction: SyncDirection = "bidirectional"
    expires_at: float = field(default_factory=lambda: time.monotonic() + DEFAULT_TTL)
    # Materialized wire projection, lazily built by RendezvousHandler._to_peer and kept
    # as pre-serialized JSON bytes rather than the pydantic ``RdvPeer`` model:
    # the bytes are exactly what the response embeds, so caching them both halves
    # the per-record footprint and removes the per-query model rebuild. Valid
    # until a field changes: register always creates a NEW PeerRecord, and a
    # refresh that changes ``connected`` invalidates this cache. Every other
    # field IS part of the projection (the endpoints, capacity, reachable, the
    # connected count and the election advertisement), so none of them may be
    # mutated in place without a fresh register (new PeerRecord) or a reset.
    wire: bytes | None = field(default=None, repr=False, compare=False)

    def touch(self, ttl: float = DEFAULT_TTL) -> None:
        self.expires_at = time.monotonic() + ttl

    @classmethod
    def from_register(
        cls,
        model: RdvRegister,
        *,
        peer_ip: str,
    ) -> PeerRecord:
        """Build a record from a validated ``register`` frame.

        ``peer_ip`` is the observed source address, kept for record ownership:
        creating, replacing or renewing a record is honoured only from the source
        network that registered it. Every other field is relayed verbatim from
        the frame (or its documented default). One projector keeps ``register``
        handling in sync with the model.
        """
        return cls(
            cid=model.cid,
            bucket=model.bucket,
            group=model.group,
            ip=peer_ip,
            cert_fp=model.cert_fp,
            version=model.version,
            endpoints=tuple((e.proto, e.host, e.port) for e in model.endpoints),
            connected=model.connected or 0,
            reachable=bool(model.endpoints),
            capacity=model.capacity,
            server_ready=model.server_ready,
            prefer_master=model.prefer_master,
            never_master=model.never_master,
            inbound=model.inbound,
            startup_time=model.startup_time,
            sync_direction=model.sync_direction,
        )


class RoutingTable:
    """In-memory registry of active peers (per ``rdv/1``), RAM only.

    Owned by the node's single asyncio event-loop thread: there is no lock, so a
    caller must never share one table across threads (the daemon does not).
    """

    def __init__(
        self,
        *,
        max_records: int | None = None,
        max_records_per_group: int | None = None,
        max_records_per_bucket: int | None = None,
    ) -> None:
        self._records: dict[tuple[str, str, str | None], PeerRecord] = {}
        self._by_group: dict[tuple[str, str | None], list[tuple[str, str, str | None]]] = {}
        self._by_cid: dict[tuple[str, str], set[tuple[str, str, str | None]]] = {}
        self._pos: dict[tuple[str, str, str | None], int] = {}
        self._per_bucket: dict[str, int] = {}
        self._max_records = max_records
        self._max_per_group = max_records_per_group
        self._max_per_bucket = max_records_per_bucket
        # Batch-randomness buffer for ``_randbelow`` (see sample()).
        self._rand_buf = b""
        self._rand_pos = 0

    # -- mutation ----------------------------------------------------------

    def upsert(self, record: PeerRecord) -> bool:
        """Insert or refresh a peer record; ``False`` when a ceiling is hit.

        An existing key is always updated (it does not grow the table). A new
        key is refused once ``max_records`` is reached, once its bucket reaches
        ``max_records_per_bucket``, or once its ``(bucket, group)`` population
        reaches ``max_records_per_group``. The bucket ceiling is the one a
        hostile registrant cannot rotate around: ``group`` is attacker-chosen,
        so the per-group cap alone would let one bucket fill the whole table by
        rotating it. Either refusal lets the caller answer with backpressure
        instead of growing RAM without limit.
        """
        key = (record.cid, record.bucket, record.group)
        if key not in self._records:
            if self._max_records is not None and len(self._records) >= self._max_records:
                return False
            if (
                self._max_per_bucket is not None
                and self._per_bucket.get(record.bucket, 0) >= self._max_per_bucket
            ):
                return False
            group_keys = self._by_group.get((record.bucket, record.group))
            if (
                self._max_per_group is not None
                and group_keys is not None
                and len(group_keys) >= self._max_per_group
            ):
                return False
            lst = self._by_group.setdefault((record.bucket, record.group), [])
            self._pos[key] = len(lst)
            lst.append(key)
            self._by_cid.setdefault((record.cid, record.bucket), set()).add(key)
            self._per_bucket[record.bucket] = self._per_bucket.get(record.bucket, 0) + 1
        self._records[key] = record
        return True

    def _unindex(self, key: tuple[str, str, str | None]) -> None:
        """Remove ``key`` from ``_by_group``/``_pos`` (O(1) swap-remove).

        Does NOT touch ``_by_cid``: ``remove`` pops the whole ``(cid, bucket)`` set
        itself, and ``prune`` discards the key from it inline.
        """
        bucket, group = key[1], key[2]
        lst = self._by_group[(bucket, group)]
        pos = self._pos.pop(key)
        last = lst[-1]
        if pos != len(lst) - 1:
            lst[pos] = last
            self._pos[last] = pos
        lst.pop()
        if not lst:
            del self._by_group[(bucket, group)]

    def _decrement_bucket(self, bucket: str) -> None:
        """Account one record leaving ``bucket`` (keeps ``_per_bucket`` exact)."""
        remaining = self._per_bucket.get(bucket, 0) - 1
        if remaining > 0:
            self._per_bucket[bucket] = remaining
        else:
            self._per_bucket.pop(bucket, None)

    def _drop(self, key: tuple[str, str, str | None]) -> None:
        """Remove ``key`` from ``_records``, the group index and the bucket count."""
        bucket = key[1]
        del self._records[key]
        self._unindex(key)
        self._decrement_bucket(bucket)

    def _rebuild_indexes(self) -> None:
        """Rebuild every secondary index from ``_records`` in one linear pass."""
        by_group: dict[tuple[str, str | None], list[tuple[str, str, str | None]]] = {}
        by_cid: dict[tuple[str, str], set[tuple[str, str, str | None]]] = {}
        pos: dict[tuple[str, str, str | None], int] = {}
        per_bucket: dict[str, int] = {}
        for key in self._records:
            lst = by_group.setdefault((key[1], key[2]), [])
            pos[key] = len(lst)
            lst.append(key)
            by_cid.setdefault((key[0], key[1]), set()).add(key)
            per_bucket[key[1]] = per_bucket.get(key[1], 0) + 1
        self._by_group = by_group
        self._by_cid = by_cid
        self._pos = pos
        self._per_bucket = per_bucket

    def remove(
        self,
        cid: str,
        bucket: str,
        *,
        source_ip: str | None = None,
    ) -> int:
        """Remove records for ``(cid, bucket)`` regardless of group (leave).

        The ``leave`` frame carries no group field and a CID identifies a peer
        uniquely, so all of the caller's entries in the bucket must go.

        ``source_ip`` narrows the removal to records observed from that source
        IP: the handler's leave policy lets a peer only depart from the network
        it registered from, so a record owned by a *different* source IP must
        survive (it is someone else's registration, not an abuse the caller
        gets to rewrite). ``source_ip=None`` removes everything (token-
        authenticated departures and the token-gated private path).

        Returns the number of records removed.
        """
        keys = self._by_cid.get((cid, bucket))
        if not keys:
            return 0
        records = self._records
        doomed = [key for key in keys if source_ip is None or records[key].ip == source_ip]
        for key in doomed:
            self._drop(key)
            # _drop (via _unindex) does not touch _by_cid — see its contract:
            # the caller updates the cid index, so it always mirrors _records.
            keys.discard(key)
        if not keys:
            self._by_cid.pop((cid, bucket), None)
        return len(doomed)

    def source_ips(self, cid: str, bucket: str) -> list[str]:
        """Observed source IPs of every active record for ``(cid, bucket)``.

        Used by the leave policy to decide whether the sender may be the
        legitimate owner of the registration.
        """
        keys = self._by_cid.get((cid, bucket))
        if not keys:
            return []
        return [self._records[key].ip for key in keys]

    def get(
        self,
        cid: str,
        bucket: str,
        group: str | None = None,
        *,
        now: float | None = None,
    ) -> PeerRecord | None:
        """Return the **active** record for the exact key, or ``None``.

        A record past its TTL is absent: it must not block another source from
        claiming the key, and a refresh must not revive it (the peer
        re-registers instead). Ownership decisions (``_may_replace``) and
        ``refresh`` both read through here, so expiry is the single authority.
        """
        record = self._records.get((cid, bucket, group))
        if record is None:
            return None
        now = time.monotonic() if now is None else now
        return record if now < record.expires_at else None

    def prune(self, now: float | None = None, *, max_remove: int | None = None) -> int:
        """Drop expired records; returns the number of removed entries.

        ``max_remove`` caps how many records one sweep drops (an on-request
        path calls this with a budget so a huge stale backlog cannot stall the
        event loop; the background sweep keeps ``None`` and fully converges).
        Left-over expired records are picked up by the next sweep.
        """
        now = now if now is not None else time.monotonic()
        # Expiry is the bare ``now >= r.expires_at`` comparison: the sweep is
        # called with a resolved ``now``, so there is no per-record method call
        # to wrap it (one Python call less per record from the TTL sweep).
        expired = [k for k, r in self._records.items() if now >= r.expires_at]
        if max_remove is not None and len(expired) > max_remove:
            expired = expired[:max_remove]
        if not expired:
            return 0
        total = len(self._records)
        if len(expired) == total:
            # Full expiry: drop every structure in one C-level pass instead of
            # N dict deletes plus an index rebuild (the DB-equivalent of TRUNCATE).
            self._records.clear()
            self._by_group.clear()
            self._by_cid.clear()
            self._pos.clear()
            self._per_bucket.clear()
            return total
        for key in expired:
            del self._records[key]
        if len(expired) * 2 >= total:
            # Mass expiry: one bulk rebuild beats N swap-removes + set discards.
            self._rebuild_indexes()
        else:
            for key in expired:
                self._unindex(key)
                self._decrement_bucket(key[1])
                cset = self._by_cid[(key[0], key[1])]
                cset.discard(key)
                if not cset:
                    del self._by_cid[(key[0], key[1])]
        return len(expired)

    # -- queries -----------------------------------------------------------

    def _randbelow(self, n: int) -> int:
        """Uniform ``int`` in ``[0, n)`` from a batched ``os.urandom`` stream.

        Same rejection technique as CPython's ``_randbelow_with_getrandbits``
        (no modulo bias); indices are read from a refilled batch buffer, so the
        OS randomness syscall happens once per chunk instead of once per draw.
        """
        level = n.bit_length()
        # Draw exactly ``level`` random bits (the same sample space CPython's
        # ``getrandbits`` uses): two bytes would widen the sample space to 2**16
        # and push the acceptance rate of the rejection loop below 2% for n~1000.
        nbytes = (level + 7) // 8
        mask = (1 << level) - 1
        limit = (1 << level) // n * n
        while True:
            if self._rand_pos + nbytes > len(self._rand_buf):
                self._rand_buf = os.urandom(_RANDOM_CHUNK_BYTES)
                self._rand_pos = 0
            value = (
                int.from_bytes(self._rand_buf[self._rand_pos : self._rand_pos + nbytes], "big")
                & mask
            )
            self._rand_pos += nbytes
            if value < limit:
                return value % n

    def _shuffle(self, items: list[_T]) -> None:
        """Fisher–Yates over ``items`` using the batched OS randomness."""
        for i in range(len(items) - 1, 0, -1):
            j = self._randbelow(i + 1)
            items[i], items[j] = items[j], items[i]

    def _active_records(
        self, keys: list[tuple[str, str, str | None]], now: float
    ) -> list[PeerRecord]:
        """Active (unexpired) records for *keys*, one ``records[key]`` lookup per key."""
        records = self._records
        return [record for key in keys if now < (record := records[key]).expires_at]

    def sample(
        self,
        bucket: str,
        group: str | None = None,
        limit: int = DEFAULT_SAMPLE_LIMIT,
        now: float | None = None,
    ) -> list[PeerRecord]:
        """Return a random sample (up to ``limit``) of active peers in the bucket."""
        now = now if now is not None else time.monotonic()
        keys = self._by_group.get((bucket, group))
        if not keys:
            return []
        records = self._records
        n = len(keys)
        k = min(limit, n)
        if k == n:
            # Single ``records[key]`` lookup per key (walrus) instead of a
            # second lookup in the comprehension.
            all_records = self._active_records(keys, now)
            self._shuffle(all_records)
            return all_records
        # n > k: rejection-sample up to a bounded number of distinct draws; if
        # that does not yield k active records (mostly-expired group), fall back
        # to one linear pass. This caps the worst case at O(n) instead of the
        # coupon-collector O(n log n) the unbounded rejection loop would hit.
        result: list[PeerRecord] = []
        chosen: set[int] = set()
        budget = max(4 * k, 64)
        # Bound attribute lookups and the ``len(result)`` builtin out of the
        # draw loop; ``taken`` mirrors the appended count exactly.
        randbelow = self._randbelow
        taken = 0
        while taken < k and len(chosen) < budget:
            idx = randbelow(n)
            if idx in chosen:
                continue
            chosen.add(idx)
            record = records[keys[idx]]
            if now < record.expires_at:
                result.append(record)
                taken += 1
        if len(result) < k:
            remaining = self._active_records(keys, now)
            self._shuffle(remaining)
            return remaining[:k]
        return result

    def count(self, bucket: str | None = None, group: str | None = None) -> int:
        """Number of active records (optionally filtered)."""
        if bucket is None:
            return len(self._records)
        if group is None:
            # Exact by construction: ``_per_bucket`` is adjusted on every
            # insert/remove and rebuilt on mass expiry, so this is O(1) instead
            # of a full-table scan.
            return self._per_bucket.get(bucket, 0)
        return len(self._by_group.get((bucket, group), ()))
