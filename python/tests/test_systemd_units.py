"""Packaged systemd units: the Type=notify readiness contract must survive hardening.

The node announces ``READY=1`` (and later ``WATCHDOG=1``/``STOPPING=1``) with a
hand-rolled AF_UNIX sd_notify datagram (``hsync_rendezvous.systemd``). The
units' ``RestrictAddressFamilies=`` therefore has to keep AF_UNIX alongside the
QUIC listener families (AF_INET/AF_INET6): without it a ``Type=notify`` start
never becomes active and systemd kills the node after ``TimeoutStartSec`` (the
service sits in ``activating`` with ``Result: timeout`` and exits 0 on SIGTERM).
The black-box sd_notify tests run without the unit hardening, so this contract
is asserted structurally against the shipped unit files.

Consumers: the Debian package, the RPM package (stages the Debian unit) and the
manual source-install unit.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
UNITS = [
    REPO / "packaging" / "deb" / "usr" / "lib" / "systemd" / "system" / "hsync-rendezvous.service",
    REPO / "packaging" / "systemd" / "hsync-rendezvous.service",
]


def _service_section(path: Path) -> str:
    unit = path.read_text(encoding="utf-8")
    match = re.search(r"\[Service\]\n(.*?)\n\[", unit, re.DOTALL)
    assert match is not None, f"{path.name} is missing a [Service] section"
    return match.group(1)


def _restrict_address_families(service: str) -> list[str]:
    match = re.search(r"^\s*RestrictAddressFamilies=(.*)$", service, re.MULTILINE)
    assert match is not None, "RestrictAddressFamilies= is missing"
    return match.group(1).split()


def test_units_allow_af_unix_for_the_notify_socket() -> None:
    """The shipped units keep AF_UNIX so the sd_notify READY=1 datagram is not blocked."""
    for path in UNITS:
        service = _service_section(path)
        assert "Type=notify" in service, path.name
        assert "NotifyAccess=main" in service, path.name
        allowed = _restrict_address_families(service)
        assert set(allowed) == {"AF_INET", "AF_INET6", "AF_UNIX"}, path.name


def test_units_keep_the_quic_listener_families() -> None:
    """A future 'hardening' must not drop the families the UDP listeners need."""
    for path in UNITS:
        allowed = _restrict_address_families(_service_section(path))
        assert {"AF_INET", "AF_INET6"} <= set(allowed), path.name
