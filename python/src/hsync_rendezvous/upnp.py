"""UPnP-IGD for the rendezvous: the shared IGD client plus the async manager.

The SSDP/SOAP implementation (including the SSRF hardening) is the
``hsync_common.upnp`` SSOT shared with ``hsync-client``; this module only adds
``UpnpManager`` — the asyncio loop that maps the QUIC listener's UDP port and
refreshes it, reporting through the rendezvous diagnostics channel.

The node parses network data only with ElementTree on the bounded description
body (64 KiB) and never logs reply content (the no-log invariant).
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Sequence

import hsync_common.upnp as _shared_upnp
from hsync_common.upnp import (
    IgdService,
    UpnpError,
    _control_url_on_base,
    _igd_service_from_location,
    _location_host_matches_source,
    _parse_ssdp_response,
    add_port_mapping,
    build_add_mapping_soap,
    delete_port_mapping,
    discover_igd,
    is_lan_unicast_address,
    is_private_http_location,
    parse_soap_error,
)

from hsync_rendezvous.diagnostics import debug_event, warn_event

__all__ = [
    "IgdService",
    "UpnpError",
    "UpnpManager",
    "add_port_mapping",
    "build_add_mapping_soap",
    "delete_port_mapping",
    "discover_igd",
    "is_lan_unicast_address",
    "is_private_http_location",
    "parse_soap_error",
    # Private re-exports: the white-box tests and the SSDP fuzz target reach the
    # shared gate/parser helpers through this facade.
    "_control_url_on_base",
    "_location_host_matches_source",
    "_parse_ssdp_response",
]


def _first_igd_location(sock: socket.socket, timeout: float, local_ip: str) -> IgdService | None:
    """Delegate to the shared reply gate, keeping the local fetch seam.

    ``_igd_service_from_location`` is resolved from this module so callers (and
    tests/fuzz) can monkeypatch the fetch without reaching into the shared SSOT.
    """
    return _shared_upnp._first_igd_location(
        sock,
        timeout,
        local_ip,
        fetch=_igd_service_from_location,
    )


class UpnpManager:
    """Asyncio zero-touch UPnP: map the node's listener ports, refresh, and unmap.

    Stateless by design: rendezvous failure or an absent IGD is reported once on
    the always-on diagnostics channel and retried at the next cycle — the node
    keeps serving normally (the operator may instead open the port manually).

    The node serves both transports on one port, so by default every mapping is
    applied to ``UDP`` (QUIC) and ``TCP`` (TLS/TCP) together: peers reachable over
    either egress path are covered by the same router rule. A node started with
    ``--no-udp``/``--no-tcp`` passes only its enabled transports, so a disabled
    transport is never mapped.

    The mapping lifetime mirrors the process: the finite lease (twice the
    refresh interval) reclaims a mapping orphaned by a crash, and :meth:`close`
    removes it on graceful shutdown.
    """

    # Transport protocols one node port is offered as: the two ``rdv/1``
    # transports (QUIC/UDP and TLS/TCP). The CLI narrows this set to the
    # transports actually enabled.
    DEFAULT_PROTOCOLS = ("UDP", "TCP")

    def __init__(
        self,
        internal_port: int,
        *,
        external_port: int | None = None,
        refresh_interval: float = 300.0,
        protocols: Sequence[str] = DEFAULT_PROTOCOLS,
    ) -> None:
        self.internal_port = internal_port
        self.external_port = external_port if external_port is not None else internal_port
        self.refresh_interval = refresh_interval
        self.protocols = tuple(protocols)
        self._active: IgdService | None = None
        self._reported_missing = False

    @property
    def _proto_label(self) -> str:
        """Diagnostics label for the mapped transports (``udp``/``tcp``/``udp/tcp``)."""
        return "/".join(protocol.lower() for protocol in self.protocols)

    @property
    def _lease_duration(self) -> int:
        """Requested lease: two refresh windows, so a missed cycle cannot drop it."""
        return max(int(self.refresh_interval * 2), 60)

    async def run(self) -> None:
        while True:
            try:
                await asyncio.get_running_loop().run_in_executor(None, self._ensure_mapped)
            except UpnpError as exc:
                # Transient: retry at the next cycle, the node keeps serving —
                # but a mapping that never succeeds is exactly what an operator
                # must see to understand why peers cannot reach the node.
                warn_event("upnp mapping unavailable", reason=exc)
            await asyncio.sleep(self.refresh_interval)

    async def close(self) -> None:
        """Remove the mappings (best-effort) so the router keeps no stale rule.

        Cancel the refresh task first (``_async_main`` does): a live loop could
        re-add what this deletes. A failure is a warning, never an exception, and
        no peer data is logged.
        """
        service = self._active
        if service is None:
            return
        self._active = None
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._delete_mapping, service)
        except UpnpError as exc:
            warn_event("upnp unmap failed", reason=exc)
        else:
            debug_event("upnp mappings removed", port=self.external_port, proto=self._proto_label)

    def _ensure_mapped(self) -> None:
        service = self._active
        if service is None:
            service = discover_igd()
            if service is None:
                if not self._reported_missing:
                    warn_event("upnp no igd on lan", port=self.external_port)
                    self._reported_missing = True
                return
            self._add_mapping(service)
            self._active = service
            debug_event("upnp mapping active", port=self.external_port, proto=self._proto_label)
            return
        # Refresh the existing mappings (idempotent AddPortMapping).
        self._add_mapping(service)

    def _add_mapping(self, service: IgdService) -> None:
        for protocol in self.protocols:
            add_port_mapping(
                service,
                internal_port=self.internal_port,
                external_port=self.external_port,
                lease_duration=self._lease_duration,
                protocol=protocol,
            )

    def _delete_mapping(self, service: IgdService) -> None:
        for protocol in self.protocols:
            delete_port_mapping(service, external_port=self.external_port, protocol=protocol)
