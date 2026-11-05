"""No-log property tests: the rdv/1 hot path never opens a file for writing.

The rendezvous is no-log by design: the register→query handler path (peer data),
the QUIC configuration and the in-memory (``--ephemeral``) identity must be able
to run under a filesystem guard that makes any write-mode open explode. Reading
is allowed (libraries, locale data), writing is not. The *only* permitted write
in the default run is the node's own persisted TLS identity file.
"""

from __future__ import annotations

import builtins
import json
import os
import time
from typing import Any

import pytest
from pydantic import SecretStr

from hsync_rendezvous.handler import RendezvousHandler
from hsync_rendezvous.server import build_quic_configuration, load_or_create_identity, make_identity
from hsync_rendezvous.stats import NodeStats
from hsync_rendezvous.tokens import derive_bucket_token

CID = "A1b2C3d4E5f6G7h8I9j0K"
FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

_REAL_OPEN = builtins.open
_REAL_OS_OPEN = os.open

_WRITE_MODES = "wax+"


class _WriteAttempted(RuntimeError):
    pass


def _no_write_open(file: Any, *args: Any, **kwargs: Any) -> Any:
    mode: str = ""
    if args:
        mode = str(args[0])
    elif "mode" in kwargs:
        mode = str(kwargs["mode"])
    if any(ch in mode for ch in _WRITE_MODES):
        raise _WriteAttempted(str(file))
    return _REAL_OPEN(file, *args, **kwargs)


def _no_write_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> Any:
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
        raise _WriteAttempted(str(path))
    return _REAL_OS_OPEN(path, flags, *args, **kwargs)


@pytest.fixture
def read_only_fs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builtins, "open", _no_write_open)
    monkeypatch.setattr(os, "open", _no_write_os_open)


def _frame(**fields: object) -> str:
    """Serialize a ``rdv/1`` frame dict for the raw-bytes ``handle()`` contract.

    Only ``protocol_version`` is implicit: each frame type carries its own
    mandatory fields (``cid`` belongs to register/leave, not to query), and the
    rigid schema rejects anything else.
    """
    return json.dumps({"protocol_version": "rdv/1", **fields})


def _exchange(handler: RendezvousHandler, frame: str) -> bytes | None:
    """Drive one frame through the handler, charging a fixed peer for the IP."""
    return handler.handle(frame, peer_ip="198.51.100.7", peer_port=54321)


def test_register_query_prune_never_writes(read_only_fs: pytest.MonkeyPatch) -> None:
    handler = RendezvousHandler(
        protected_buckets=("shared",),
        group_keys={"shared": SecretStr("kshared")},
    )
    token = derive_bucket_token(b"kshared", "shared")
    ack = _exchange(
        handler,
        _frame(
            type="register",
            cid=CID,
            bucket="shared",
            group="home",
            bucket_token=token,
            cert_fp=FP,
            version="1.0.0",
            endpoints=[{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
        ),
    )
    assert ack is not None and json.loads(ack)["type"] == "ack"

    response = _exchange(
        handler, _frame(type="query", bucket="shared", group="home", bucket_token=token)
    )
    assert response is not None and json.loads(response)["count"] == 1
    handler.prune()


def test_private_register_query_leave_never_writes(read_only_fs: pytest.MonkeyPatch) -> None:
    """Private mode adds no disk write either (holds in both policies)."""
    handler = RendezvousHandler(private=True, group_keys={"shared": SecretStr("kshared")})
    token = derive_bucket_token(b"kshared", "shared")
    ack = _exchange(
        handler,
        _frame(
            type="register",
            cid=CID,
            bucket="shared",
            group="home",
            bucket_token=token,
            cert_fp=FP,
            version="1.0.0",
            endpoints=[{"proto": "tcp", "host": "198.51.100.7", "port": 443}],
        ),
    )
    assert ack is not None and json.loads(ack)["type"] == "ack"

    response = _exchange(
        handler, _frame(type="query", bucket="shared", group="home", bucket_token=token)
    )
    assert response is not None and json.loads(response)["count"] == 1

    # the refusal path (unknown bucket / missing token) must not write either
    refused = _exchange(handler, _frame(type="query", bucket="unkeyed"))
    assert refused is not None and json.loads(refused)["error"] == "token_required"

    assert (
        _exchange(handler, _frame(type="leave", cid=CID, bucket="shared", bucket_token=token))
        is None
    )
    handler.prune()


def test_ephemeral_identity_and_config_never_write(read_only_fs: pytest.MonkeyPatch) -> None:
    """``--ephemeral``: the in-memory identity configures QUIC with zero writes."""
    identity = make_identity(host="127.0.0.1")
    config = build_quic_configuration(identity)
    assert config.certificate is not None
    assert config.private_key is not None
    assert identity.fingerprint


def test_persistence_requires_a_write(read_only_fs: pytest.MonkeyPatch, tmp_path) -> None:
    """The persisted default is the one write the node performs (its own key+cert).

    Under a filesystem that refuses every write, resolving the persisted identity
    fails, while the in-memory (``--ephemeral``) path above succeeds — pinning the
    fact that persistence is the write the default run is allowed to make.
    """
    with pytest.raises(_WriteAttempted):
        load_or_create_identity(tmp_path / "state" / "identity.pem", host="127.0.0.1")


def test_the_aggregate_counters_never_write(read_only_fs: pytest.MonkeyPatch) -> None:
    """Observing, expiring and rendering the aggregates is pure: no open()."""
    stats = NodeStats()
    handler = RendezvousHandler(ttl=60.0, stats=stats)
    _exchange(
        handler,
        _frame(type="register", cid=CID, bucket="shared", cert_fp=FP, version="1.0.0"),
    )
    handler.prune(time.monotonic())
    body = stats.render_prometheus()
    assert "hsync_rendezvous_peers_current 1" in body
    assert stats.status_text() == "conn=0/0 quic=0 tcp=0 peers=1/1 relay=0/0"
