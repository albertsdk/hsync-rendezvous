"""CLI smoke tests: version output, fail-fast configuration, keys-fd loading."""

from __future__ import annotations

import asyncio
import errno
import os
import re
import signal
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

# Help rendering is pinned to a fixed width at import time: rich reads COLUMNS
# when the help console is created, so a mid-process setenv would be too late,
# and the substring assertions on HSYNC_* env names must not depend on the
# terminal the suite happens to run in.
os.environ["COLUMNS"] = "120"

from hsync_rendezvous.cli import (
    _check_stats_target,
    _install_shutdown_handlers,
    _load_keys,
    _near_expiry_reason,
    _remove_ready_file,
    _resolve_identity,
    _resolve_metrics,
    _watchdog_loop,
    _write_ready_file,
    app,
    default_identity_path,
)
from hsync_rendezvous.handler import RendezvousConfigError

runner = CliRunner()

# Keep the CLI tests hermetic: without this the default identity would be created
# in the real XDG state dir. Tests that exercise persistence set their own path.
_EPHEMERAL_ENV = {"HSYNC_RENDEZVOUS_EPHEMERAL": "1"}

# Rich highlights option names by splitting them into styled segments (e.g.
# ``--private`` becomes ``-`` + ``-private`` with an ANSI reset between) whenever
# it emits color — as a CI runner that forces it does. Strip the escapes before
# substring assertions so the help checks do not depend on color detection.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Group keys must meet the shared strength floor (MIN_GROUP_KEY_CHARS).
_KEY_SHARED = "9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b"
_KEY_HOME = "1a3c5e7f9b0d2f4a6c8e0b2d4f6a8c0e"


def _plain(text: str) -> str:
    """Return *text* without ANSI styling (for help/substring assertions)."""
    return _ANSI_RE.sub("", text)


def _run_help() -> str:
    """Render ``run --help`` at a fixed width, plain (no ANSI).

    Rich folds a long word (an ``HSYNC_*`` name) when the description column gets
    narrow, so a substring assertion must not depend on the terminal the suite
    happens to run in. ``CliRunner``'s ``env`` does not reach the in-process
    rich console, so the width is set on ``os.environ`` for the call.
    """
    previous = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "120"
    try:
        result = runner.invoke(app, ["run", "--help"])
    finally:
        if previous is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = previous
    assert result.exit_code == 0
    return _plain(result.output)


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "rdv/1" in result.output
    assert "hsync-rendezvous" in result.output


def test_protected_bucket_without_key_fails_fast() -> None:
    result = runner.invoke(app, ["run", "--protected-bucket", "shared"])
    assert result.exit_code == 2
    combined = result.output + getattr(result, "stderr", "") or result.output
    assert "configuration error" in combined
    assert "protected bucket(s) without a group key" in combined


def test_load_keys_from_fd() -> None:
    read_fd, write_fd = os.pipe()
    os.write(
        write_fd,
        b"shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n# operator comment\nhome=1a3c5e7f9b0d2f4a6c8e0b2d4f6a8c0e\n",
    )
    os.close(write_fd)
    try:
        keys = _load_keys(read_fd)
    finally:
        os.close(read_fd)
    assert set(keys) == {"shared", "home"}
    assert keys["shared"].get_secret_value() == _KEY_SHARED
    assert keys["home"].get_secret_value() == _KEY_HOME


def test_load_keys_ignores_blank_and_comments() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"\n# only a comment\n")
    os.close(write_fd)
    try:
        keys = _load_keys(read_fd)
    finally:
        os.close(read_fd)
    assert keys == {}

    # None / negative fd → empty mapping (no crash)
    assert _load_keys(None) == {}
    assert _load_keys(-1) == {}


def test_load_keys_refuses_stdout_and_stderr() -> None:
    """fd 1/2 are never a key source: passing stdout/stderr is a config error."""
    for bad in (1, 2):
        try:
            _load_keys(bad)
        except RendezvousConfigError:
            pass
        else:  # pragma: no cover - expected to raise
            raise AssertionError(f"fd {bad} must be refused as a keys source")


def test_load_keys_caps_the_fd_payload(tmp_path) -> None:
    """A descriptor that keeps producing bytes is refused, never read to the end.

    A misrouted fd (a pipe held open, some random device) would otherwise stall
    startup or grow without bound: the cap fails fast instead.
    """
    from hsync_rendezvous.cli import KEYS_FD_MAX_BYTES

    with tempfile.NamedTemporaryFile(dir=tmp_path, suffix=".keys", delete=False) as handle:
        handle.write(b"shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n" * 100_000)  # well past the cap
        path = handle.name
    fd = os.open(path, os.O_RDONLY)
    try:
        try:
            _load_keys(fd)
        except RendezvousConfigError:
            pass
        else:  # pragma: no cover - expected to raise
            raise AssertionError(f"payload larger than {KEYS_FD_MAX_BYTES} bytes must fail fast")
    finally:
        os.close(fd)
        os.unlink(path)


@pytest.mark.skipif(os.name == "nt", reason="the read timeout is enforced with select() (POSIX)")
def test_load_keys_times_out_on_a_stuck_open_fd(monkeypatch) -> None:
    """A descriptor held open without EOF must fail fast, not hang startup.

    The write end stays open and silent, so the read would block forever without
    the bounded wait; the configuration error is raised instead.
    """
    monkeypatch.setattr("hsync_rendezvous.cli.KEYS_FD_READ_TIMEOUT_SECONDS", 0.05)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(RendezvousConfigError, match="not received within"):
            _load_keys(read_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_load_keys_from_file(tmp_path) -> None:
    """An operator file is a first-class key source (Windows has no fd seam)."""
    path = tmp_path / "group-keys"
    path.write_text(
        "shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n# operator comment\nhome=1a3c5e7f9b0d2f4a6c8e0b2d4f6a8c0e\n",
        encoding="utf-8",
    )
    keys = _load_keys(None, str(path))
    assert set(keys) == {"shared", "home"}
    assert keys["shared"].get_secret_value() == _KEY_SHARED
    assert keys["home"].get_secret_value() == _KEY_HOME


def test_load_keys_empty_file_means_open_mode(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("", encoding="utf-8")
    assert _load_keys(None, str(path)) == {}


def test_load_keys_missing_file_fails_fast(tmp_path) -> None:
    with pytest.raises(RendezvousConfigError, match="cannot open group keys file"):
        _load_keys(None, str(tmp_path / "missing"))


def test_load_keys_fd_and_file_are_mutually_exclusive(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n", encoding="utf-8")
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        with pytest.raises(RendezvousConfigError, match="mutually exclusive"):
            _load_keys(read_fd, str(path))
    finally:
        os.close(read_fd)


@pytest.mark.skipif(os.name == "nt", reason="creating a symlink needs a privilege on Windows")
def test_load_keys_refuses_a_symlink(tmp_path) -> None:
    real = tmp_path / "real"
    real.write_text("shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(RendezvousConfigError, match="symlink"):
        _load_keys(None, str(link))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_load_keys_warns_on_loose_permissions(tmp_path, monkeypatch) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n", encoding="utf-8")
    path.chmod(0o644)
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "hsync_rendezvous.cli.warn_event",
        lambda event, **fields: events.append((event, fields)),
    )
    assert set(_load_keys(None, str(path))) == {"shared"}
    assert events and events[0][0] == "group keys file permissions are too open"
    assert events[0][1]["path"] == str(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_load_keys_accepts_a_group_readable_file(tmp_path, monkeypatch) -> None:
    """0640 is the documented service-account mode: group read is allowed."""
    path = tmp_path / "group-keys"
    path.write_text("shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n", encoding="utf-8")
    path.chmod(0o640)
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "hsync_rendezvous.cli.warn_event",
        lambda event, **fields: events.append((event, fields)),
    )
    assert set(_load_keys(None, str(path))) == {"shared"}
    assert events == []


def test_load_keys_file_caps_the_payload(tmp_path) -> None:
    from hsync_rendezvous.cli import KEYS_FD_MAX_BYTES

    path = tmp_path / "group-keys"
    path.write_bytes(b"shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n" * 100_000)
    with pytest.raises(RendezvousConfigError, match="exceeded"):
        _load_keys(None, str(path))
    assert KEYS_FD_MAX_BYTES > 0


def test_load_keys_rejects_duplicate_buckets() -> None:
    read_fd, write_fd = os.pipe()
    os.write(
        write_fd,
        b"shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\nshared=1a3c5e7f9b0d2f4a6c8e0b2d4f6a8c0e\n",
    )
    os.close(write_fd)
    try:
        with pytest.raises(RendezvousConfigError, match="duplicate group key for bucket 'shared'"):
            _load_keys(read_fd)
    finally:
        os.close(read_fd)


def test_near_expiry_reason_names_the_configured_identity() -> None:
    reason = _near_expiry_reason(7, "/var/lib/hsync-rendezvous/identity.pem")
    assert "--identity" in reason
    assert "/var/lib/hsync-rendezvous/identity.pem" in reason


def test_keys_file_and_fd_are_rejected_by_the_cli(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["run", "--keys-fd", "5", "--keys-file", str(path)],
        env=_EPHEMERAL_ENV,
    )
    combined = result.output + getattr(result, "stderr", "")
    assert result.exit_code == 2
    assert "mutually exclusive" in combined


def test_missing_keys_file_fails_fast_via_the_cli(tmp_path) -> None:
    result = runner.invoke(
        app,
        ["run", "--keys-file", str(tmp_path / "missing")],
        env=_EPHEMERAL_ENV,
    )
    combined = result.output + getattr(result, "stderr", "")
    assert result.exit_code == 2
    assert "cannot open group keys file" in combined


def test_duplicate_keys_file_fails_fast_via_the_cli(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text(
        "shared=9f2c4b6a8d0e1f3a5c7b9d1e3f5a7c9b\nshared=1a3c5e7f9b0d2f4a6c8e0b2d4f6a8c0e\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["run", "--keys-file", str(path)], env=_EPHEMERAL_ENV)
    combined = result.output + getattr(result, "stderr", "")
    assert result.exit_code == 2
    assert "duplicate group key for bucket 'shared'" in combined


def test_keys_options_are_documented_in_help() -> None:
    output = _run_help()
    assert "--keys-fd" in output
    assert "--keys-file" in output
    assert "HSYNC_RENDEZVOUS_KEYS_FILE" in output


def test_ttl_out_of_range_is_rejected() -> None:
    for bad in ("0", "-1", "3601"):
        result = runner.invoke(app, ["run", "--ttl", bad])
        assert result.exit_code == 2


def test_private_without_key_fails_fast() -> None:
    result = runner.invoke(app, ["run", "--private"])
    assert result.exit_code == 2
    assert "private node without any group key" in result.output


def test_private_envvar_is_equivalent_to_the_flag() -> None:
    """The service units use the envvar form; it must reach the same fail-fast."""
    result = runner.invoke(app, ["run"], env={"HSYNC_RENDEZVOUS_PRIVATE": "1"})
    assert result.exit_code == 2
    assert "private node without any group key" in result.output


def test_private_option_is_documented_in_help() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    output = _plain(result.output)
    assert "--private" in output
    assert "HSYNC_RENDEZVOUS_PRIVATE" in output


def test_ready_file_helpers_write_pid_and_remove(tmp_path) -> None:
    ready = tmp_path / "ready"
    _write_ready_file(str(ready))
    assert ready.read_text(encoding="utf-8").strip() == str(os.getpid())
    _remove_ready_file(str(ready))
    assert not ready.exists()
    # removing a missing file is a no-op, not an error
    _remove_ready_file(str(ready))


def _combined(result) -> str:
    return result.output + getattr(result, "stderr", "") or result.output


def _patch_run_no_side_effects(monkeypatch, start_servers) -> None:
    """Stub both listener starts and the loop/shutdown seams.

    ``run`` resolves the loop runner (``_uvloop_runner``; the stdlib loop keeps
    the test process free of a global event-loop policy swap) and installs the
    shutdown-signal handlers before the bind; stubbing them keeps the tests
    deterministic. The node starts the QUIC/UDP and TLS/TCP transports through
    two seams (``start_servers`` and ``start_tcp_servers``); both are stubbed
    with the same fake, which returns the identical ``(servers, ports,
    identity, failures)`` shape.
    """
    monkeypatch.setattr("hsync_rendezvous.cli.start_servers", start_servers)
    monkeypatch.setattr("hsync_rendezvous.cli.start_tcp_servers", start_servers)
    monkeypatch.setattr("hsync_rendezvous.cli._uvloop_runner", lambda: None)
    monkeypatch.setattr("hsync_rendezvous.cli._install_shutdown_handlers", lambda: None)


def test_bind_permission_denied_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        # aioquic wraps the real error: no errno on the outer OSError.
        raise OSError("could not bind to local_addr ('0.0.0.0', 443)") from PermissionError(
            errno.EACCES, "Permission denied"
        )

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--listen-port", "443"], env=_EPHEMERAL_ENV)
    assert result.exit_code == 3
    out = _combined(result)
    assert "permission denied" in out
    assert "CAP_NET_BIND_SERVICE" in out
    assert "--listen-port 8443" in out
    assert "Traceback" not in out


def test_bind_address_in_use_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError(errno.EADDRINUSE, "Address already in use")

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(app, ["run", "--listen-port", "443"], env=_EPHEMERAL_ENV)
    assert result.exit_code == 3
    out = _combined(result)
    assert "already in use" in out
    assert "--listen-port <PORT>" in out
    assert "Traceback" not in out


def test_bind_bad_host_is_actionable(monkeypatch) -> None:
    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

    _patch_run_no_side_effects(monkeypatch, _boom)
    result = runner.invoke(
        app, ["run", "--listen-host", "127.0.0.1", "--listen-port", "443"], env=_EPHEMERAL_ENV
    )
    assert result.exit_code == 3
    out = _combined(result)
    assert "not available" in out
    assert "--listen-host" in out
    assert "0.0.0.0" in out


def test_run_port_default_uses_the_shared_ssot() -> None:
    """The effective default port is the shared ``RDV_DEFAULT_PORT`` (spec §Transport)."""
    from hsync_common.constants import RDV_DEFAULT_PORT

    from hsync_rendezvous.cli import _resolve_listeners

    assert _resolve_listeners(None, None, None) == ("0.0.0.0", [RDV_DEFAULT_PORT])
    assert _resolve_listeners("0.0.0.0", None, None) == ("0.0.0.0", [RDV_DEFAULT_PORT])


def test_host_port_shorthand_is_accepted() -> None:
    """``--listen-host HOST:PORT`` resolves host and port without a separate ``--listen-port``."""
    from hsync_rendezvous.cli import _resolve_listeners

    assert _resolve_listeners("0.0.0.0:8443", None, None) == ("0.0.0.0", [8443])
    assert _resolve_listeners("[::1]:8443", None, None) == ("::1", [8443])


def test_host_port_and_port_flag_are_mutually_exclusive() -> None:
    """A port in ``--listen-host`` and in ``--listen-port`` is a usage error, not a precedence."""
    import pytest
    import typer

    from hsync_rendezvous.cli import _resolve_listeners

    with pytest.raises(typer.BadParameter):
        _resolve_listeners("0.0.0.0:8443", 8443, None)


def test_port_flag_alone_keeps_the_default_host() -> None:
    """``--listen-port`` without ``--listen-host`` binds all interfaces."""
    from hsync_rendezvous.cli import _resolve_listeners

    assert _resolve_listeners(None, 8443, None) == ("0.0.0.0", [8443])


def test_ports_flag_resolves_the_ordered_set() -> None:
    """``--listen-ports`` resolves a comma-separated ordered set and conflicts with --listen-port."""
    import pytest
    import typer

    from hsync_rendezvous.cli import _resolve_listeners

    assert _resolve_listeners(None, None, "443,53") == ("0.0.0.0", [443, 53])
    # Whitespace around entries is tolerated; order is preserved.
    assert _resolve_listeners("0.0.0.0", None, "53, 443") == ("0.0.0.0", [53, 443])

    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, 443, "443,53")  # --listen-port + --listen-ports
    with pytest.raises(typer.BadParameter):
        _resolve_listeners("0.0.0.0:8443", None, "443,53")  # host port + --listen-ports
    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, None, "443,443")  # duplicate
    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, None, "0")  # out of range
    with pytest.raises(typer.BadParameter):
        _resolve_listeners(None, None, "443,notaport")  # non-integer


class _FakeIdentity:
    """Minimal stand-in for the listener identity (only ``fingerprint`` is read)."""

    fingerprint = "00" * 32


class _FakeServer:
    """Minimal stand-in for the started listener (only ``close`` is called)."""

    def close(self) -> None:
        pass


def test_ready_file_failure_is_actionable_exit_4(monkeypatch, tmp_path) -> None:
    """An unwritable --ready-file exits 4 with an actionable message, no traceback."""

    async def _start(*args, **kwargs):  # noqa: ANN002, ANN003
        return [_FakeServer()], [8443], _FakeIdentity(), []

    _patch_run_no_side_effects(monkeypatch, _start)
    ready = tmp_path / "missing-dir" / "ready.pid"
    result = runner.invoke(
        app, ["run", "--listen-port", "8443", "--ready-file", str(ready)], env=_EPHEMERAL_ENV
    )

    assert result.exit_code == 4
    out = _combined(result)
    assert "no such directory" in out
    assert "Traceback" not in out
    # The always-on diagnostics channel reports it too, and it stays peer-free.
    assert "error: readiness file not writable" in out
    assert f"path={ready}" in out


def test_ready_file_conflict_leaves_the_existing_file_alone(monkeypatch, tmp_path) -> None:
    """A pre-existing path is refused (O_EXCL) and never deleted by the node."""

    async def _start(*args, **kwargs):  # noqa: ANN002, ANN003
        return [_FakeServer()], [8443], _FakeIdentity(), []

    _patch_run_no_side_effects(monkeypatch, _start)
    ready = tmp_path / "ready.pid"
    ready.write_text("stale", encoding="utf-8")

    result = runner.invoke(
        app, ["run", "--listen-port", "8443", "--ready-file", str(ready)], env=_EPHEMERAL_ENV
    )

    assert result.exit_code == 4
    assert "already exists" in _combined(result)
    assert ready.read_text(encoding="utf-8") == "stale"


def test_debug_run_announces_the_peer_aware_stream(monkeypatch, tmp_path) -> None:
    """Opting into --debug is announced on the always-on channel (transparency).

    The unwritable readiness file ends the run deterministically right after the
    announcement, so the assertion does not depend on a serving process.
    """

    async def _start(*args, **kwargs):  # noqa: ANN002, ANN003
        return [_FakeServer()], [8443], _FakeIdentity(), []

    _patch_run_no_side_effects(monkeypatch, _start)
    ready = tmp_path / "missing-dir" / "ready.pid"
    result = runner.invoke(
        app,
        ["run", "--listen-port", "8443", "--debug", "--no-rate-limit", "--ready-file", str(ready)],
        env=_EPHEMERAL_ENV,
    )

    out = _combined(result)
    assert "warn: peer data logging enabled reason=--debug" in out
    assert "warn: rate limiting disabled reason=--no-rate-limit" in out


def test_default_identity_path_uses_xdg_state(monkeypatch, tmp_path) -> None:
    """With no override the path is an XDG *state* path (stable across restarts)."""
    monkeypatch.delenv("HSYNC_RENDEZVOUS_IDENTITY", raising=False)
    monkeypatch.delenv("HSYNC_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert default_identity_path() == tmp_path / "hsync" / "rendezvous" / "identity.pem"


def test_default_identity_path_follows_the_state_dir(monkeypatch, tmp_path) -> None:
    """HSYNC_STATE_DIR relocates the identity together with the rest of the state."""
    monkeypatch.delenv("HSYNC_RENDEZVOUS_IDENTITY", raising=False)
    monkeypatch.setenv("HSYNC_STATE_DIR", str(tmp_path / "state"))
    assert default_identity_path() == tmp_path / "state" / "rendezvous" / "identity.pem"


def test_default_identity_path_honours_the_env_override(monkeypatch, tmp_path) -> None:
    target = tmp_path / "custom" / "id.pem"
    monkeypatch.setenv("HSYNC_RENDEZVOUS_IDENTITY", str(target))
    assert default_identity_path() == target


def test_resolve_identity_returns_none_for_ephemeral() -> None:
    assert _resolve_identity(None, True, host="127.0.0.1", public_hosts=[]) is None


def test_resolve_identity_rejects_identity_and_ephemeral() -> None:
    import pytest

    from hsync_rendezvous.handler import RendezvousConfigError

    with pytest.raises(RendezvousConfigError, match="mutually exclusive"):
        _resolve_identity("id.pem", True, host="127.0.0.1", public_hosts=[])


def test_resolve_identity_defaults_to_the_state_path(monkeypatch, tmp_path) -> None:
    state = tmp_path / "state" / "identity.pem"
    monkeypatch.setenv("HSYNC_RENDEZVOUS_IDENTITY", str(state))
    node = _resolve_identity(None, False, host="127.0.0.1", public_hosts=[])
    assert node is not None
    assert state.is_file()


def test_identity_options_are_documented_in_help() -> None:
    output = _run_help()
    assert "--identity" in output
    assert "--ephemeral" in output
    assert "HSYNC_RENDEZVOUS_EPHEMERAL" in output


_PACKAGED_UNIT = Path(__file__).resolve().parents[2] / (
    "packaging/deb/usr/lib/systemd/system/hsync-rendezvous.service"
)
_SOURCE_UNIT = Path(__file__).resolve().parents[2] / ("packaging/systemd/hsync-rendezvous.service")
# A DynamicUser has no resolvable home directory, so the packaged unit must
# never rely on the default XDG state path (Path.home() raises RuntimeError).
_IDENTITY_FLAG = "--identity /var/lib/hsync-rendezvous/identity.pem"


def test_packaged_unit_pins_the_identity_path() -> None:
    """The deb unit passes an explicit identity path in every ExecStart branch."""
    text = _PACKAGED_UNIT.read_text(encoding="utf-8")
    assert "StateDirectory=hsync-rendezvous" in text
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            assert _IDENTITY_FLAG in line, f"missing identity path: {line}"


def test_packaged_unit_matches_the_source_unit() -> None:
    """The deb and source units must not diverge on identity handling again."""
    packaged = _PACKAGED_UNIT.read_text(encoding="utf-8")
    source = _SOURCE_UNIT.read_text(encoding="utf-8")
    assert ("StateDirectory=hsync-rendezvous" in source) == (
        "StateDirectory=hsync-rendezvous" in packaged
    )
    assert (_IDENTITY_FLAG in source) == (_IDENTITY_FLAG in packaged)


# Directives every packaged unit carries: readiness/watchdog, restart bounds,
# stop semantics and resource caps. The deb and the source unit must agree, so
# both files are checked against the same list.
_REQUIRED_UNIT_DIRECTIVES = (
    "Type=notify",
    "NotifyAccess=main",
    "WatchdogSec=30",
    "Restart=on-failure",
    "RestartSec=5s",
    "StartLimitIntervalSec=60",
    "StartLimitBurst=5",
    "TimeoutStopSec=15",
    "KillSignal=SIGTERM",
    "MemoryMax=512M",
    "TasksMax=256",
    "LimitNOFILE=8192",
    "LoadCredential=metrics-token:/etc/hsync-rendezvous/metrics-token",
)


@pytest.mark.parametrize("unit", [_PACKAGED_UNIT, _SOURCE_UNIT], ids=["deb", "source"])
def test_unit_is_a_supervised_notify_service(unit: Path) -> None:
    """Readiness, watchdog, restart bounds and resource caps are explicit."""
    text = unit.read_text(encoding="utf-8")
    for directive in _REQUIRED_UNIT_DIRECTIVES:
        assert directive in text, f"{unit.name}: missing {directive}"


@pytest.mark.parametrize("unit", [_PACKAGED_UNIT, _SOURCE_UNIT], ids=["deb", "source"])
def test_unit_never_enables_the_peer_aware_debug_log(unit: Path) -> None:
    """The journal is written to disk, so a unit must never run with --debug."""
    for line in unit.read_text(encoding="utf-8").splitlines():
        if line.startswith("ExecStart=") or line.startswith("Environment="):
            assert "--debug" not in line, line
            assert "HSYNC_RENDEZVOUS_DEBUG" not in line, line


def test_sighup_is_ignored_and_stop_signals_are_handled() -> None:
    """A hangup is not a stop request; SIGINT/SIGTERM take the graceful path."""
    if not hasattr(signal, "SIGHUP"):
        pytest.skip("SIGHUP unavailable on this platform")
    watched = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    saved = {sig: signal.getsignal(sig) for sig in watched}
    try:
        _install_shutdown_handlers()
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
        assert signal.getsignal(signal.SIGINT) is not signal.SIG_DFL
        assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL
    finally:
        for sig, handler in saved.items():
            signal.signal(sig, handler)


def test_watchdog_loop_feeds_the_service_manager(monkeypatch) -> None:
    """The watchdog task pings at the armed interval (half of WatchdogSec=)."""
    pings: list[str] = []
    monkeypatch.setattr(
        "hsync_rendezvous.cli.notify_watchdog", lambda: pings.append("ping") or True
    )

    async def _run() -> None:
        task = asyncio.create_task(_watchdog_loop(0.01))
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_run())
    assert len(pings) >= 2


def _combined(result) -> str:
    """stdout + stderr of a CliRunner result (fail-fast errors go to stderr)."""
    return (result.output or "") + (getattr(result, "stderr", "") or "")


def test_group_key_below_the_strength_floor_fails_fast() -> None:
    """The group key is the token's only entropy: a short key is a config error."""
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"shared=tooshort\n")
    os.close(write_fd)
    try:
        with pytest.raises(RendezvousConfigError, match="at least 32 characters"):
            _load_keys(read_fd)
    finally:
        os.close(read_fd)


def test_group_key_line_with_a_non_canonical_bucket_fails_fast(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text(f"not a bucket={_KEY_SHARED}\n", encoding="utf-8")
    with pytest.raises(RendezvousConfigError, match="invalid bucket name"):
        _load_keys(None, str(path))


def test_group_key_line_must_be_a_key_value_pair(tmp_path) -> None:
    path = tmp_path / "group-keys"
    path.write_text("shared\n", encoding="utf-8")
    with pytest.raises(RendezvousConfigError, match="malformed group key line"):
        _load_keys(None, str(path))


def test_keys_payload_must_be_utf8() -> None:
    """A mangled key byte must fail the load, never become a different token."""
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"shared=\xff\xfe\n")
    os.close(write_fd)
    try:
        with pytest.raises(RendezvousConfigError, match="not valid UTF-8"):
            _load_keys(read_fd)
    finally:
        os.close(read_fd)


def test_the_environment_cannot_enable_the_no_rate_limit_seam(monkeypatch) -> None:
    """--no-rate-limit is CLI-only: a stale env var cannot disable the limits."""
    monkeypatch.setenv("HSYNC_RENDEZVOUS_NO_RATE_LIMIT", "1")
    # TEST-NET-1 is never a local address, so the bind fails after the banner.
    result = runner.invoke(app, ["run", "--listen-host", "192.0.2.1", "--listen-port", "9"])
    assert "rate limit: enabled" in _plain(_combined(result))


def _metrics_token_file(tmp_path: Path, token: str = "t" * 64) -> Path:
    path = tmp_path / "metrics-token"
    path.write_text(token + "\n", encoding="utf-8")
    return path


def test_the_metrics_endpoint_is_disabled_without_a_port() -> None:
    assert _resolve_metrics(host="127.0.0.1", port=None, token_fd=None, token_file=None) is None


def test_a_metrics_token_without_a_port_is_a_configuration_error() -> None:
    with pytest.raises(RendezvousConfigError, match="require --metrics-port"):
        _resolve_metrics(host="127.0.0.1", port=None, token_fd=5, token_file=None)


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "::", "example.com", "192.0.2.1"])
def test_the_metrics_endpoint_only_listens_on_loopback(host: str, tmp_path: Path) -> None:
    token_file = _metrics_token_file(tmp_path)
    with pytest.raises(RendezvousConfigError, match="not a loopback address"):
        _resolve_metrics(host=host, port=9101, token_fd=None, token_file=str(token_file))


@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost"])
def test_every_loopback_form_is_accepted(host: str, tmp_path: Path) -> None:
    token_file = _metrics_token_file(tmp_path)
    endpoint = _resolve_metrics(host=host, port=9101, token_fd=None, token_file=str(token_file))
    assert endpoint is not None
    assert (endpoint.host, endpoint.port) == (host, 9101)
    assert endpoint.token.get_secret_value() == "t" * 64


def test_a_metrics_token_below_the_strength_floor_is_refused(tmp_path: Path) -> None:
    token_file = _metrics_token_file(tmp_path, token="tooshort")
    with pytest.raises(RendezvousConfigError, match="at least 32 characters"):
        _resolve_metrics(host="127.0.0.1", port=9101, token_fd=None, token_file=str(token_file))


def test_a_metrics_token_must_be_exactly_one_line(tmp_path: Path) -> None:
    token_file = tmp_path / "two-lines"
    token_file.write_text("a" * 64 + "\n" + "b" * 64 + "\n", encoding="utf-8")
    with pytest.raises(RendezvousConfigError, match="exactly one line"):
        _resolve_metrics(host="127.0.0.1", port=9101, token_fd=None, token_file=str(token_file))


def test_the_metrics_token_can_arrive_on_a_descriptor() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, ("c" * 64 + "\n").encode())
    os.close(write_fd)
    try:
        endpoint = _resolve_metrics(host="127.0.0.1", port=9101, token_fd=read_fd, token_file=None)
    finally:
        os.close(read_fd)
    assert endpoint is not None
    assert endpoint.token.get_secret_value() == "c" * 64


def test_the_two_metrics_token_sources_are_mutually_exclusive(tmp_path: Path) -> None:
    token_file = _metrics_token_file(tmp_path)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        with pytest.raises(RendezvousConfigError, match="mutually exclusive"):
            _resolve_metrics(
                host="127.0.0.1", port=9101, token_fd=read_fd, token_file=str(token_file)
            )
    finally:
        os.close(read_fd)


def test_a_metrics_endpoint_without_a_token_is_refused() -> None:
    with pytest.raises(RendezvousConfigError, match="requires a bearer token"):
        _resolve_metrics(host="127.0.0.1", port=9101, token_fd=None, token_file=None)


def test_the_stats_file_directory_must_exist(tmp_path: Path) -> None:
    with pytest.raises(RendezvousConfigError, match="does not exist"):
        _check_stats_target(str(tmp_path / "missing" / "stats.prom"))
    _check_stats_target(str(tmp_path / "stats.prom"))


def test_the_metrics_flags_are_documented_in_help() -> None:
    output = _run_help()
    for flag in (
        "--metrics-host",
        "--metrics-port",
        "--metrics-token-fd",
        "--metrics-token-file",
        "--stats-file",
        "--stats-interval",
    ):
        assert flag in output


def test_the_relay_flags_are_documented_in_help() -> None:
    """The relay is on by default: help exposes both the switch and the opt-out."""
    output = _run_help()
    for flag in (
        "--relay",
        "--no-relay",
        "--relay-bandwidth",
        "--relay-idle-timeout",
        "--relay-session-bytes",
    ):
        assert flag in output
    assert "HSYNC_RENDEZVOUS_RELAY" in output


def test_a_metrics_port_without_a_token_fails_fast() -> None:
    """Configuration is checked before any listener is bound."""
    result = runner.invoke(
        app,
        [
            "run",
            "--listen-host",
            "192.0.2.1",
            "--listen-port",
            "9",
            "--ephemeral",
            "--metrics-port",
            "9101",
        ],
    )
    assert result.exit_code == 2
    assert "requires a bearer token" in _combined(result)


@pytest.mark.parametrize("args", [["--metrics-port", "0"], ["--stats-interval", "0"]])
def test_out_of_range_operational_values_fail_fast(args: list[str]) -> None:
    result = runner.invoke(
        app, ["run", "--listen-host", "192.0.2.1", "--listen-port", "9", "--ephemeral", *args]
    )
    assert result.exit_code == 2
    assert "must be between" in _combined(result)
