"""UPnP-IGD tests: SOAP builders, description parsing, injected transport.

No real network is touched: ``http_post``/``http_get`` are injected, SSDP parsing
is tested with canned responses, and the SOAP XML is verified field by field.
"""

from __future__ import annotations

import asyncio

import pytest

from hsync_rendezvous.upnp import (
    IgdService,
    UpnpError,
    UpnpManager,
    _control_url_on_base,
    _first_igd_location,
    _parse_ssdp_response,
    add_port_mapping,
    build_add_mapping_soap,
    is_lan_unicast_address,
    is_private_http_location,
    parse_soap_error,
)

NS = "urn:schemas-upnp-org:service:WANIPConnection:1"
SERVICE = IgdService(control_url="http://192.168.1.1:5000/ctl/IPConn", local_ip="192.168.1.10")


def test_add_mapping_soap_contains_expected_fields() -> None:
    soap = build_add_mapping_soap(
        service_type=NS,
        internal_client="192.168.1.10",
        internal_port=443,
        external_port=443,
    ).decode("utf-8")
    assert "AddPortMapping" in soap
    assert '"urn:schemas-upnp-org:service:WANIPConnection:1"' in soap
    assert "<NewExternalPort>443</NewExternalPort>" in soap
    assert "<NewInternalPort>443</NewInternalPort>" in soap
    assert "<NewProtocol>UDP</NewProtocol>" in soap
    assert "<NewInternalClient>192.168.1.10</NewInternalClient>" in soap
    assert "<NewEnabled>1</NewEnabled>" in soap
    assert "hsync-rendezvous" in soap


def test_parse_soap_error_finds_error_code() -> None:
    fault = b"""<?xml version="1.0"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
      <s:Body><s:Fault><detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>713</errorCode><errorDescription>Conflict</errorDescription>
        </UPnPError>
      </detail></s:Fault></s:Body>
    </s:Envelope>"""
    assert parse_soap_error(fault) == 713
    assert parse_soap_error(b"<not-soap/>") is None
    assert parse_soap_error(b"") is None


def test_ssdp_response_location_extraction() -> None:
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://192.168.1.1:1900/rootDesc.xml\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    )
    assert _parse_ssdp_response(response) == "http://192.168.1.1:1900/rootDesc.xml"
    assert _parse_ssdp_response(b"HTTP/1.1 404 Not Found\r\n\r\n") is None


def test_lan_unicast_source_filter() -> None:
    """Only private-LAN addresses may speak SSDP to the node.

    The IGD answering our M-SEARCH is a LAN device; every other source — a
    plain-Internet host (no LAN is discoverable there), the APIPA range that
    also hosts cloud metadata, loopback, or a garbage string — is discarded
    unopened.
    """
    for good in ("192.168.1.7", "10.1.2.3", "172.16.5.5", "fd00::7", "fdca:777a::1"):
        assert is_lan_unicast_address(good) is True
    # global/doc addresses (extranet), the link-local metadata/host range,
    # loopback, garbage — all refused
    for bad in (
        "8.8.8.8",
        "203.0.113.9",
        "2001:db8::1",
        "169.254.169.254",
        "fe80::1",
        "127.0.0.1",
        "::1",
        "not-an-address",
    ):
        assert is_lan_unicast_address(bad) is False


def test_location_http_url_must_point_at_a_private_ip_literal() -> None:
    """LOCATION validation: the URL is attacker-influenced data.

    ``http://<private-IP-literal>/…`` is the only shape an IGD publishes; the
    hostname (DNS-rebindable) and non-HTTP schemes (file/ftp handlers) are
    refused so the SSDP reply can never become an SSRF primitive.
    """
    for good in (
        "http://192.168.1.1:5000/rootDesc.xml",
        "http://10.0.0.2/desc",
        "http://[fd00::7]:5000/d",
        "http://[fd00::7:5000]/d",
        "https://192.168.1.1/desc.xml",
        "https://192.168.1.1:5000/rootDesc.xml",
    ):
        assert is_private_http_location(good) is True
    for bad in (
        "",
        "file:///etc/passwd",
        "ftp://192.168.1.1/desc.xml",
        "http://router.lan/rootDesc.xml",
        "http://203.0.113.9/rootDesc.xml",
        "http://169.254.169.254/latest/meta-data/",
        "http://[2001:db8::1]/desc.xml",
        "http://user:password@192.168.1.1/desc.xml",
        "http://192.168.1.1:70000/desc.xml",
    ):
        assert is_private_http_location(bad) is False


def test_control_url_must_stay_on_the_igd_host() -> None:
    """A controlURL is resolved against the LOCATION's validated host only."""
    base = "http://192.168.1.1:5000/rootDesc.xml"
    # ordinary root-relative and device-relative controlURLs
    assert _control_url_on_base(base, "/ctl/IPConn") == "http://192.168.1.1:5000/ctl/IPConn"
    assert _control_url_on_base(base, "ctl/IPConn") == "http://192.168.1.1:5000/ctl/IPConn"
    # a path traversal stays confined to the validated host (normpath)
    assert _control_url_on_base(base, "/ctl/../desc") == "http://192.168.1.1:5000/desc"
    # anything that escapes the device is refused, never followed
    assert _control_url_on_base(base, "http://203.0.113.9/steal") is None
    assert _control_url_on_base(base, "//203.0.113.9/steal") is None
    assert _control_url_on_base(base, "https://192.168.1.1:5000/steal") is None


def test_add_port_mapping_injects_transport() -> None:
    calls: list[tuple[str, str, bytes]] = []

    def fake_post(url: str, soap_action: str, body: bytes) -> None:
        calls.append((url, soap_action, body))

    add_port_mapping(
        SERVICE,
        internal_port=443,
        http_post=fake_post,
    )
    assert len(calls) == 1
    url, soap_action, body = calls[0]
    assert url == SERVICE.control_url
    assert soap_action == f"{NS}#AddPortMapping"
    assert b"AddPortMapping" in body


def test_upnp_error_code_downgrade_message() -> None:
    """A mapping failure surfaces as UpnpError (the manager logs + retries)."""

    def failing_post(url: str, soap_action: str, body: bytes) -> None:
        raise OSError("no route to host")

    try:
        add_port_mapping(SERVICE, internal_port=443, http_post=failing_post)
    except UpnpError as exc:
        assert "AddPortMapping" in str(exc)
    else:  # pragma: no cover - expected to raise
        raise AssertionError("transport failure must raise UpnpError")


def test_upnp_manager_stateless_when_no_igd(monkeypatch: object) -> None:
    import hsync_rendezvous.upnp as upnp_mod

    monkeypatch.setattr(upnp_mod, "discover_igd", lambda *a, **k: None)
    manager = upnp_mod.UpnpManager(443, refresh_interval=3600.0)
    # No IGD on the LAN: the first run must not raise and must not mark the
    # mapping active, keeping the node serving.
    manager._ensure_mapped()
    assert manager._active is None
    assert manager._reported_missing is True


def test_upnp_manager_warns_once_when_no_igd(monkeypatch: object, capsys) -> None:
    """Without ``--debug`` the operator still learns the port was not mapped."""
    import hsync_rendezvous.upnp as upnp_mod

    monkeypatch.setattr(upnp_mod, "discover_igd", lambda *a, **k: None)
    manager = upnp_mod.UpnpManager(443, refresh_interval=3600.0)
    manager._ensure_mapped()
    manager._ensure_mapped()  # latched: the state stays unchanged, no repeat line

    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1
    assert " warn: upnp no igd on lan port=443" in lines[0]


@pytest.mark.asyncio
async def test_upnp_manager_reports_a_failed_cycle(monkeypatch: object, capsys) -> None:
    """An exception is retried, but never silently: the operator sees the reason."""

    def _boom(self) -> None:
        raise UpnpError("SSDP rendezvous failed: Network is unreachable")

    monkeypatch.setattr(UpnpManager, "_ensure_mapped", _boom)
    manager = UpnpManager(443, refresh_interval=3600.0)
    task = asyncio.create_task(manager.run())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1
    assert " warn: upnp mapping unavailable" in lines[0]
    assert "reason=SSDP rendezvous failed: Network is unreachable" in lines[0]


class _FakeSocket:
    """Minimal stand-in for the SSDP datagram socket (no network, no time waits)."""

    def __init__(self, replies: list[tuple[bytes, tuple[str, int]]]) -> None:
        self._replies = list(replies)

    def settimeout(self, _value: float) -> None:
        pass

    def sendto(self, _data: bytes, _addr: object) -> None:
        pass

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if not self._replies:
            raise TimeoutError("queue drained")
        return self._replies.pop(0)

    def getsockname(self) -> tuple[str, int]:
        return ("192.168.1.10", 0)


def test_ssdp_replies_off_lan_are_discarded_unopened(monkeypatch: object) -> None:
    """An off-LAN source never reaches the LOCATION fetch (no parse, no HTTP).

    The whole SSRF surface of SSDP is the *reply* anyone can send: restricting
    the accepted source to the private LAN collapses it to LAN-hostile only,
    and the LOCATION validation on top covers even an on-LAN rogue device.
    """
    import hsync_rendezvous.upnp as upnp_mod

    ssdp_reply = (
        b"HTTP/1.1 200 OK\r\n"
        b"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    )
    file_reply = ssdp_reply.replace(
        b"http://192.168.1.1:5000/rootDesc.xml",
        b"file:///etc/passwd",
    )
    fetched: list[str] = []

    def fake_fetch(location: str, local_ip: str) -> None:
        fetched.append(location)
        return None

    monkeypatch.setattr(upnp_mod, "_igd_service_from_location", fake_fetch)
    sock = _FakeSocket(
        [
            (ssdp_reply, ("203.0.113.9", 50000)),  # public-IP source: off-LAN
            (file_reply, ("192.168.1.50", 5000)),  # on-LAN source, file LOCATION
            (ssdp_reply, ("192.168.1.1", 1900)),  # on-LAN, valid LOCATION shape
        ]
    )
    result = _first_igd_location(sock, 2.0, "192.168.1.10")  # type: ignore[arg-type]
    assert result is None  # the fake fetch returns None, so the walk keeps going
    # the off-LAN reply was discarded UNOPENED; only the on-LAN http reply triggered a fetch
    assert fetched == ["http://192.168.1.1:5000/rootDesc.xml"]


def test_ssdp_location_host_must_match_reply_source(monkeypatch: object) -> None:
    """A LAN reply naming a *different* private host is discarded unopened.

    The reply source and its LOCATION host must be the same device: a spoofed
    reply from one LAN host naming another would otherwise steer the fetch at a
    host that never answered.
    """
    import hsync_rendezvous.upnp as upnp_mod

    reply = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n\r\n"
    fetched: list[str] = []

    def fake_fetch(location: str, local_ip: str) -> None:
        fetched.append(location)
        return None

    monkeypatch.setattr(upnp_mod, "_igd_service_from_location", fake_fetch)
    sock = _FakeSocket(
        [
            # LAN source (192.168.1.50) naming a different private host: refused.
            (reply, ("192.168.1.50", 1900)),
            # Same reply but the LOCATION host now equals the source: fetched.
            (reply.replace(b"192.168.1.1", b"192.168.1.50"), ("192.168.1.50", 1900)),
        ]
    )
    result = _first_igd_location(sock, 2.0, "192.168.1.10")  # type: ignore[arg-type]
    assert result is None
    assert fetched == ["http://192.168.1.50:5000/rootDesc.xml"]


def test_upnp_manager_requests_a_finite_lease(monkeypatch: object) -> None:
    """The mapping carries a finite lease (crash-safety), not a permanent rule."""
    import hsync_rendezvous.upnp as upnp_mod

    captured: dict[str, object] = {}

    def fake_add(service, *, internal_port, external_port, lease_duration=0, protocol="UDP", **_kw):
        captured.setdefault("protocols", []).append(protocol)
        captured["lease"] = lease_duration
        captured["external_port"] = external_port

    monkeypatch.setattr(upnp_mod, "discover_igd", lambda *a, **k: SERVICE)
    monkeypatch.setattr(upnp_mod, "add_port_mapping", fake_add)
    manager = upnp_mod.UpnpManager(443, refresh_interval=300.0)
    manager._ensure_mapped()
    assert captured["lease"] == 600  # two refresh windows
    assert captured["external_port"] == 443
    assert captured["protocols"] == ["UDP", "TCP"]


@pytest.mark.asyncio
async def test_upnp_manager_close_removes_the_mapping(monkeypatch: object) -> None:
    import hsync_rendezvous.upnp as upnp_mod

    calls: list[tuple[int, str]] = []

    def fake_delete(service, *, external_port, protocol="UDP", **_kw):
        calls.append((external_port, protocol))

    monkeypatch.setattr(upnp_mod, "delete_port_mapping", fake_delete)
    manager = upnp_mod.UpnpManager(443)
    manager._active = SERVICE
    await manager.close()
    # Both transports are offered on the one node port, so both are unmapped.
    assert calls == [(443, "UDP"), (443, "TCP")]
    assert manager._active is None


@pytest.mark.asyncio
async def test_upnp_manager_close_is_a_noop_when_unmapped() -> None:
    manager = UpnpManager(443)
    await manager.close()  # never mapped: nothing to delete, no error
    assert manager._active is None


@pytest.mark.asyncio
async def test_upnp_manager_close_degrades_to_a_warning(monkeypatch: object, capsys) -> None:
    """A failed unmap must never raise on the shutdown path."""
    import hsync_rendezvous.upnp as upnp_mod

    def boom(service, *, external_port, protocol="UDP", **_kw):
        raise UpnpError("DeletePortMapping failed: Connection refused")

    monkeypatch.setattr(upnp_mod, "delete_port_mapping", boom)
    manager = upnp_mod.UpnpManager(443)
    manager._active = SERVICE
    await manager.close()

    err = capsys.readouterr().err
    assert " warn: upnp unmap failed" in err
    assert "reason=DeletePortMapping failed: Connection refused" in err
    assert manager._active is None
