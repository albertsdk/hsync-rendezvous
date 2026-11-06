"""Black-box **security probes** for the ``rdv/1`` rendezvous node.

Adversarial suite: each test is an attack attempt against the public surface
(CLI + ``rdv/1`` wire frames over QUIC/UDP), never against the
implementation — the same probes must keep passing against the future ``c/``
port. Attack classes covered:

* **Authorization bypass** — cross-bucket token replay, token grammar abuse,
  private-mode bucket enumeration oracle, eviction with a foreign token.
* **Source spoofing / hijack** — a second loopback source address
  (127.0.0.2) tries to replace or evict a registration it does not own.
* **Parser abuse** — deep JSON nesting, integer overflow, JSON infinity,
  unicode/NUL smuggling.
* **DoS** — pipelined frame burst, bucket-enumeration sweep, raw non-QUIC UDP
  garbage, a concurrent-handshake flood against the per-IP connection guard.
* **Transport** — wrong-ALPN handshake.
* **Side channel** — authorization timing uniformity (constant-time token
  comparison, no provisioned-set oracle).

Opt-in: requires ``HSYNC_BB_SECURITY=1`` **on top of** the suite's
``HSYNC_BB_RENDEZVOUS=1`` (security probes are adversarial by nature — they
send deliberately hostile traffic and bound-heavy bursts, so they stay out of
the default black-box run). Scale knobs, read once at import:

* ``HSYNC_BB_RENDEZVOUS_SECURITY_FLOOD`` (default 120) — handshakes in the
  connection-flood probe.
* ``HSYNC_BB_RENDEZVOUS_SECURITY_TIMING`` (default 30) — rounds in the timing
  probe.

The 127.0.0.2 probes need a loopback alias (Linux treats the whole 127/8 as
local); they are skipped where the bind fails.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import ssl
import statistics
import time
from pathlib import Path
from typing import Any

import pytest
from aioquic.asyncio import connect as quic_connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from harness import (
    RawOutcome,
    RdvClient,
    client_config,
    derive_bucket_token,
    leave_frame,
    query_frame,
    random_bucket,
    random_cid,
    register_frame,
)

_ENABLE_ENV = "HSYNC_BB_SECURITY"
_ENABLED = os.environ.get(_ENABLE_ENV) == "1"
_REASON = "rendezvous security probes are opt-in; set HSYNC_BB_SECURITY=1 to enable"
pytestmark = pytest.mark.skipif(not _ENABLED, reason=_REASON)


def _knob(name: str, default: int) -> int:
    """Positive-int environment knob (import time; tests scrub HSYNC_*)."""
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


_FLOOD = _knob("HSYNC_BB_RENDEZVOUS_SECURITY_FLOOD", 120)
_TIMING = _knob("HSYNC_BB_RENDEZVOUS_SECURITY_TIMING", 30)


# ---------------------------------------------------------------------------
# Probe helpers (transport-level; still black-box: they speak only rdv/1)
# ---------------------------------------------------------------------------


def _second_loopback_available() -> bool:
    """True when a distinct loopback source address (127.0.0.2) can be bound."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.2", 0))
    except OSError:
        return False
    probe.close()
    return True


async def _connect_from(
    local_ip: str,
    port: int,
    *,
    config: QuicConfiguration | None = None,
    timeout: float = 5.0,
) -> tuple[Any, QuicConnectionProtocol]:
    """QUIC connect bound to an explicit local source address (spoof/ALPN probe).

    aioquic's ``connect()`` only exposes ``local_port``; binding a second
    loopback address requires driving ``QuicConnection`` directly. The result
    still speaks only ``rdv/1`` — no implementation detail is touched.
    """
    if config is None:
        config = client_config()
    if config.server_name is None:
        config.server_name = "127.0.0.1"
    loop = asyncio.get_running_loop()
    connection = QuicConnection(configuration=config)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((local_ip, 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QuicConnectionProtocol(connection), sock=sock
    )
    try:
        protocol.connect(("127.0.0.1", port))
        await asyncio.wait_for(protocol.wait_connected(), timeout=timeout)
    except BaseException:
        protocol.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(protocol.wait_closed(), timeout=5.0)
        transport.close()
        raise
    return transport, protocol


async def _close_raw(transport: Any, protocol: QuicConnectionProtocol) -> None:
    """Tear a raw-probe connection down (mirrors the harness teardown rules)."""
    protocol.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(protocol.wait_closed(), timeout=5.0)
    transport.close()


async def _send_expect_silent(
    protocol: QuicConnectionProtocol, frame: dict, timeout: float = 1.0
) -> bool:
    """Send one frame; True when the server gives no reply (silent or closed)."""
    reader, writer = await protocol.create_stream()
    try:
        writer.write((json.dumps(frame) + "\n").encode("utf-8"))
        await writer.drain()
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except TimeoutError:
            return True
        return not raw
    finally:
        writer.close()


# ---------------------------------------------------------------------------
# Authorization-bypass probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_bucket_token_is_refused(rendezvous_factory, group_key, rng) -> None:
    """A bucket token is bound to its bucket: same key, different token per bucket."""
    # Given: two protected buckets provisioned with the SAME group key
    bucket_a = random_bucket(rng)
    bucket_b = random_bucket(rng)
    handle = rendezvous_factory(
        protected=[bucket_a, bucket_b], keys={bucket_a: group_key, bucket_b: group_key}
    )
    token_a = derive_bucket_token(group_key.encode("utf-8"), bucket_a)
    async with RdvClient(handle.port) as client:
        # When: bucket A's token is replayed against bucket B, then used on A
        hijack = await client.exchange(query_frame(bucket_b, token=token_a))
        ok = await client.exchange(query_frame(bucket_a, token=token_a))
    # Then: the cross-bucket replay is refused while the same token works on A
    assert hijack["error"] == "token_required"
    assert hijack["count"] == 0
    assert ok["error"] is None


@pytest.mark.asyncio
async def test_leave_with_foreign_bucket_token_cannot_evict(
    rendezvous_factory, bucket, group_key, rng
) -> None:
    # Given: a private node with two provisioned buckets and a peer in bucket A
    other = bucket + "z"
    handle = rendezvous_factory(private=True, keys={bucket: group_key, other: group_key})
    token_a = derive_bucket_token(group_key.encode("utf-8"), bucket)
    token_b = derive_bucket_token(group_key.encode("utf-8"), other)
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, token=token_a))
        # When: a leave for (cid, bucket) presents bucket B's token
        result = await client.send_raw(
            (json.dumps(leave_frame(cid, bucket, token=token_b)) + "\n").encode()
        )
        # Then: the eviction is silently refused and the peer survives
        assert result.outcome is RawOutcome.SILENT
        response = await client.exchange(query_frame(bucket, token=token_a))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


@pytest.mark.asyncio
async def test_malformed_token_is_not_charged_as_failed_token(
    rendezvous_factory, bucket, group_key
) -> None:
    """Grammar-invalid tokens hit the parse budget, not the auth budget (no oracle drain)."""
    # Given: a protected bucket with rate limits ON
    handle = rendezvous_factory(protected=[bucket], keys={bucket: group_key})
    async with RdvClient(handle.port) as client:
        # When: one grammar-invalid (uppercase-hex) token is sent
        result = await client.send_raw(
            (json.dumps(query_frame(bucket, token="A" * 64)) + "\n").encode()
        )
        assert result.outcome is RawOutcome.SILENT
        # Then: the full failed-token budget is still available afterwards
        for _ in range(5):
            reply = await client.exchange(query_frame(bucket, token="0" * 64))
            assert reply["error"] == "token_required"
        # And: the 6th wrong attempt (not the malformed one) trips the budget
        reply = await client.exchange(query_frame(bucket, token="0" * 64))
    assert reply["error"] == "rate_limited"


@pytest.mark.asyncio
async def test_private_enumeration_responses_are_identical(
    rendezvous_factory, bucket, group_key
) -> None:
    """No bucket-existence oracle: provisioned, unprovisioned and unknown buckets answer alike."""
    # Given: a private node with one provisioned bucket
    handle = rendezvous_factory(private=True, keys={bucket: group_key})
    # When: a provisioned, an unprovisioned and a nonexistent bucket are queried
    async with RdvClient(handle.port) as client:
        replies = [
            await client.exchange(query_frame(bucket, token=None)),
            await client.exchange(query_frame(bucket + "x", token=None)),
            await client.exchange(query_frame("bb-nonexistent", token=None)),
        ]
    # Then: the three refusals are byte-identical
    assert replies[0] == replies[1] == replies[2]
    assert replies[0]["error"] == "token_required"
    assert replies[0]["count"] == 0


# ---------------------------------------------------------------------------
# Source-spoofing probes (127.0.0.2 vs the registering 127.0.0.1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_foreign_source_cannot_replace_registration(rendezvous_factory, bucket, rng) -> None:
    """The source-IP ownership rule: another address cannot overwrite a live record."""
    if not _second_loopback_available():
        pytest.skip("127.0.0.2 loopback alias unavailable on this host")
    # Given: a peer registered from 127.0.0.1 with endpoints E1
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket, host="198.51.100.7", port=8443))
    # When: 127.0.0.2 re-registers the same cid with different endpoints
    transport, protocol = await _connect_from("127.0.0.2", handle.port)
    try:
        silent = await _send_expect_silent(
            protocol, register_frame(cid, bucket, host="203.0.113.9", port=9999)
        )
    finally:
        await _close_raw(transport, protocol)
    # Then: the hijack attempt is dropped and the original registration survives
    assert silent
    async with RdvClient(handle.port) as client:
        response = await client.exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["endpoints"] == [
        {"proto": "tcp", "host": "198.51.100.7", "port": 8443}
    ]


@pytest.mark.asyncio
async def test_foreign_source_cannot_depart_peer(rendezvous_factory, bucket, rng) -> None:
    """A leave is honoured only from the source network that registered the peer."""
    if not _second_loopback_available():
        pytest.skip("127.0.0.2 loopback alias unavailable on this host")
    # Given: a peer registered from 127.0.0.1
    handle = rendezvous_factory()
    cid = random_cid(rng)
    async with RdvClient(handle.port) as client:
        await client.exchange(register_frame(cid, bucket))
    # When: a leave for that (cid, bucket) arrives from 127.0.0.2
    transport, protocol = await _connect_from("127.0.0.2", handle.port)
    try:
        silent = await _send_expect_silent(protocol, leave_frame(cid, bucket))
    finally:
        await _close_raw(transport, protocol)
    # Then: the spoofed departure is ignored — the peer survives
    assert silent
    async with RdvClient(handle.port) as client:
        response = await client.exchange(query_frame(bucket))
    assert response["count"] == 1
    assert response["peers"][0]["cid"] == cid


# ---------------------------------------------------------------------------
# Parser-abuse probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parser_abuse_is_bounded(rendezvous_factory, bucket, rng) -> None:
    """Deep nesting, numeric overflow, JSON infinity and unicode/NUL smuggling are inert."""
    # Given: a fresh node
    handle = rendezvous_factory()
    payloads = [
        b'{"pad":' + b"[" * 3000 + b"]" * 3000 + b"}\n",  # deep JSON nesting (~6 KB)
        b'{"protocol_version":"rdv/1","type":"query","bucket":"bb-x","limit":'
        + b"9" * 30
        + b"}\n",  # integer overflow
        b'{"protocol_version":"rdv/1","type":"query","bucket":"bb-x","limit":1e999}\n',
        (
            json.dumps(
                {
                    "protocol_version": "rdv/1",
                    "type": "register",
                    "cid": "\uff21" * 21,
                    "bucket": bucket,
                }
            )
            + "\n"
        ).encode("utf-8"),  # fullwidth unicode CID
        (
            json.dumps({"protocol_version": "rdv/1", "type": "query", "bucket": "bb\u0000x"}) + "\n"
        ).encode("utf-8"),  # NUL inside the bucket name
    ]
    async with RdvClient(handle.port) as client:
        for payload in payloads:
            # When: each parser-abuse payload is sent
            result = await client.send_raw(payload)
            # Then: no crash and no error oracle — silent drop or stream close
            assert result.outcome in (RawOutcome.SILENT, RawOutcome.CLOSED)
        # And: the node still serves valid traffic
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


# ---------------------------------------------------------------------------
# DoS probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_raw_udp_garbage_is_ignored(rendezvous_factory, bucket, rng) -> None:
    # Given: a running node
    handle = rendezvous_factory()
    # When: non-QUIC UDP garbage is blasted at the listener port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for payload in (b"", b"\x00", os.urandom(1500), b"\xc0\xfd\x00\x01" + b"\x00" * 100):
            sock.sendto(payload, ("127.0.0.1", handle.port))
    finally:
        sock.close()
    # Then: the node ignores it and still serves
    async with RdvClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_pipelined_burst_is_throttled_not_fatal(rendezvous_factory, bucket) -> None:
    # Given: a node with rate limits ON
    handle = rendezvous_factory()
    frames = [query_frame(bucket) for _ in range(100)]
    async with RdvClient(handle.port) as client:
        # When: 100 queries are pipelined on a single stream
        replies = await client.pipeline(frames, timeout=15.0)
    # Then: every reply is well-formed, the burst is throttled, the node survives
    assert len(replies) == 100
    assert all(reply["type"] == "response" for reply in replies)
    assert any(reply["error"] == "rate_limited" for reply in replies)
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_bucket_enumeration_sweep_hits_aggregate_cap(rendezvous_factory, rng) -> None:
    """One query per bucket defeats the pair limiter — the per-IP aggregate must still cap it."""
    # Given: an open node and 45 distinct bucket names
    handle = rendezvous_factory()
    names = [random_bucket(rng) for _ in range(45)]
    async with RdvClient(handle.port) as client:
        # When: every bucket is queried once in a burst
        replies = [await client.exchange(query_frame(name)) for name in names]
    # Then: the anti-enumeration aggregate cap trips mid-sweep and the node stays alive
    assert any(reply["error"] == "rate_limited" for reply in replies)
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_connection_flood_keeps_node_serving(rendezvous_factory, bucket, rng) -> None:
    """A concurrent-handshake flood is throttled by the per-IP guard, never fatal."""
    # Given: a node with the production per-IP connection guard (limits ON)
    handle = rendezvous_factory()

    async def try_handshake() -> bool:
        async def _shake() -> None:
            async with quic_connect("127.0.0.1", handle.port, configuration=client_config()):
                pass

        try:
            await asyncio.wait_for(_shake(), timeout=15.0)
            return True
        except Exception:  # noqa: BLE001 - refused handshakes are the expected outcome
            return False

    # When: a concurrent handshake flood arrives from one source IP
    results = await asyncio.gather(*(try_handshake() for _ in range(_FLOOD)))
    admitted = sum(1 for ok in results if ok)
    print(f"[FLOOD] {admitted}/{_FLOOD} handshakes admitted by the per-IP guard")

    # Then: the node is still alive and serving (throttled, never crashed)
    await asyncio.sleep(1.0)  # let the handshake budget refill a little
    async with RdvClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None
    assert admitted >= _FLOOD // 2


# ---------------------------------------------------------------------------
# Transport and side-channel probes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wrong_alpn_cannot_reach_boot_frames(rendezvous_factory, bucket, rng) -> None:
    # Given: a running node advertising only the hsync-rdv/1 ALPN
    handle = rendezvous_factory()
    config = QuicConfiguration(
        is_client=True, alpn_protocols=["hsync-rdv/9"], verify_mode=ssl.CERT_NONE
    )
    # When: a client handshakes with a wrong ALPN
    transport = protocol = None
    try:
        transport, protocol = await _connect_from("127.0.0.1", handle.port, config=config)
    except Exception:  # noqa: BLE001 - handshake failure is the expected outcome
        protocol = None
    if protocol is not None:
        # Defensive: had the handshake completed, no rdv/1 frame may be answered
        try:
            assert await _send_expect_silent(protocol, query_frame(random_bucket(rng)))
        finally:
            await _close_raw(transport, protocol)
    # Then: the node is unaffected and still serves the correct ALPN
    async with RdvClient(handle.port) as client:
        ack = await client.exchange(register_frame(random_cid(rng), bucket))
    assert ack["type"] == "ack"
    assert handle.proc.poll() is None


@pytest.mark.asyncio
async def test_authorization_timing_is_uniform(rendezvous_factory, bucket, group_key) -> None:
    """Constant-time token check: provisioned and unprovisioned buckets cost the same."""
    # Given: a private node (rate limits off: this measures the pure authorization path)
    handle = rendezvous_factory(private=True, keys={bucket: group_key}, no_rate_limit=True)
    other = bucket + "z"
    keyed: list[float] = []
    unkeyed: list[float] = []
    async with RdvClient(handle.port) as client:
        for _ in range(_TIMING):
            # When: an anonymous query hits a provisioned, then an unprovisioned bucket
            t0 = time.perf_counter()
            reply = await client.exchange(query_frame(bucket, token=None))
            keyed.append(time.perf_counter() - t0)
            assert reply["error"] == "token_required"
            t0 = time.perf_counter()
            reply = await client.exchange(query_frame(other, token=None))
            unkeyed.append(time.perf_counter() - t0)
            assert reply["error"] == "token_required"
    # Then: the two paths cost the same (no provisioned-set oracle)
    m_keyed = statistics.median(keyed)
    m_unkeyed = statistics.median(unkeyed)
    print(f"[TIMING] provisioned={m_keyed * 1000:.3f}ms unprovisioned={m_unkeyed * 1000:.3f}ms")
    assert max(m_keyed, m_unkeyed) < 3.0 * max(min(m_keyed, m_unkeyed), 1e-6)


# ---------------------------------------------------------------------------
# Secret-handling, filesystem and log-injection probes
# ---------------------------------------------------------------------------


def test_group_keys_never_on_argv_or_in_env(rendezvous_factory, bucket, group_key) -> None:
    # Given: a node provisioned with a group key via --keys-fd
    handle = rendezvous_factory(protected=[bucket], keys={bucket: group_key})
    # When: the running process argv and environment are inspected
    assert handle.node_pid is not None, "readiness did not report the application pid"
    argv = Path(f"/proc/{handle.node_pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode()
    environ = (
        Path(f"/proc/{handle.node_pid}/environ").read_bytes().decode("utf-8", errors="replace")
    )
    # Then: the secret appears in neither
    assert group_key not in argv
    assert group_key not in environ


def test_identity_file_permissions(rendezvous_factory, tmp_path) -> None:
    # Given: a node with a persistent identity
    identity = tmp_path / "pentest-identity.pem"
    handle = rendezvous_factory(ephemeral=False, args=["--identity", str(identity)])
    # When: the file and its directory are inspected while the node runs
    assert handle.proc.poll() is None  # the node is up: the identity is in active use
    file_mode = identity.stat().st_mode & 0o777
    dir_mode = identity.parent.stat().st_mode & 0o777
    # Then: owner-only permissions, like an SSH host key
    assert file_mode == 0o600
    assert dir_mode == 0o700


def test_ephemeral_writes_no_identity_file(rendezvous_factory, tmp_path) -> None:
    # Given: a node started in ephemeral mode with an isolated XDG state dir
    xdg = tmp_path / "xdg-state"
    handle = rendezvous_factory(ephemeral=True, env_extra={"XDG_STATE_HOME": str(xdg)})
    # When: the state dir is inspected after startup
    # Then: nothing was written
    assert handle.proc.poll() is None
    assert not (xdg / "hsync").exists()


@pytest.mark.asyncio
async def test_control_char_group_cannot_forge_log_lines(rendezvous_factory, bucket, rng) -> None:
    """A group carrying control characters must not forge a second log line."""
    # Given: a node started with --debug (the peer-aware channel)
    handle = rendezvous_factory(debug=True)
    cid = random_cid(rng)
    forged_group = "grp\n2026-01-01T00:00:00Z - hsync-rendezvous[1] warn: FORGED-BY-ATTACKER"
    # When: a register carries the forged group
    async with RdvClient(handle.port) as client:
        frame = register_frame(cid, bucket)
        frame["group"] = forged_group
        ack = await client.exchange(frame)
    # Then: the register is served, and the forged text never starts a log line
    #       (it may appear inline as a sanitized value — that is by design)
    stderr = handle.stderr_text()
    assert ack["type"] == "ack"
    assert not any(
        line.startswith("2026-01-01T00:00:00Z - hsync-rendezvous[1] warn: FORGED-BY-ATTACKER")
        for line in stderr.splitlines()
    )


@pytest.mark.asyncio
async def test_refusal_amplification_is_bounded(rendezvous_factory, bucket) -> None:
    """Refusal replies must stay below the QUIC ~3x anti-amplification guidance."""
    # Given: a running node
    handle = rendezvous_factory()
    query = (json.dumps(query_frame(bucket)) + "\n").encode("utf-8")
    # When: one anonymous query is sent and the refusal measured
    async with RdvClient(handle.port) as client:
        reader, writer = await client._protocol.create_stream()
        writer.write(query)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readline(), timeout=5.0)
        writer.close()
    # Then: the reply stays within the anti-amplification guidance
    assert len(reply) / len(query) < 3.0


# ---------------------------------------------------------------------------
# Relay bounds (what a registrant can make the node emit)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_relay_is_bounded(rendezvous_factory, bucket, rng) -> None:
    """A 16-endpoint register is relayed as at most 4 endpoints, in order."""
    # Given: a peer that advertises the maximum number of long endpoints
    handle = rendezvous_factory()
    cid = random_cid(rng)
    long_host = ".".join(["a" * 63] * 3)
    frame = register_frame(cid, bucket)
    frame["endpoints"] = [
        {"proto": "tcp", "host": long_host, "port": 4000 + index} for index in range(16)
    ]
    async with RdvClient(handle.port) as client:
        ack = await client.exchange(frame)
        assert ack["type"] == "ack"
        # When: anyone queries the bucket
        response = await client.exchange(query_frame(bucket, limit=50))
    # Then: the relay carries the first four candidates and stays bounded
    assert response["count"] == 1
    relayed = response["peers"][0]["endpoints"]
    assert len(relayed) == 4
    assert relayed[0]["port"] == 4000
    assert len(json.dumps(response)) <= 32 * 1024


@pytest.mark.asyncio
async def test_a_non_dialable_endpoint_host_is_refused(rendezvous_factory, bucket, rng) -> None:
    """An advertised host no client could dial is an invalid frame, not relayed data."""
    # Given: a running node
    handle = rendezvous_factory()
    cid = random_cid(rng)
    # When: a register advertises a host outside the dialable grammar
    transport, protocol = await _connect_from("127.0.0.1", handle.port)
    try:
        frame = register_frame(cid, bucket)
        frame["endpoints"] = [{"proto": "tcp", "host": "../elsewhere", "port": 443}]
        silent = await _send_expect_silent(protocol, frame)
    finally:
        await _close_raw(transport, protocol)
    # Then: the frame is dropped and nothing is relayed for that bucket
    assert silent
    async with RdvClient(handle.port) as client:
        response = await client.exchange(query_frame(bucket))
    assert response["count"] == 0
