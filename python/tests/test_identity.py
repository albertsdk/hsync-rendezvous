# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Alberto Basso

"""White-box tests for the persistent rendezvous TLS identity (ADR-0034/ADR-0037).

Service identities are ECDSA P-256, stored unencrypted under ``0600``/``0700``
permissions, with a 20-year validity; the loader accepts nothing else.
"""

import ipaddress
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from hsync_common import ssl_utils

from hsync_rendezvous.server import (
    IdentityError,
    load_identity,
    load_or_create_identity,
    make_identity,
    rotate_identity,
    rotation_hint,
)


def test_make_identity_is_ecdsa_p256():
    node = make_identity(host="127.0.0.1")
    assert isinstance(node.private_key, ec.EllipticCurvePrivateKey)
    assert isinstance(node.private_key.curve, ec.SECP256R1)


def test_make_identity_san_includes_bind_and_public_hosts():
    node = make_identity(host="127.0.0.1", public_hosts=["rdv.example.com", "198.51.100.9"])
    san = node.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {n.value for n in san}
    assert "rdv.example.com" in names
    assert ipaddress.IPv4Address("198.51.100.9") in names
    assert ipaddress.IPv4Address("127.0.0.1") in names


def test_make_identity_wildcard_bind_uses_dns_name():
    node = make_identity(host="0.0.0.0")
    san = node.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {n.value for n in san}
    assert "hsync-rendezvous" in names


def test_make_identity_validity_is_twenty_years():
    from datetime import UTC, datetime, timedelta

    node = make_identity(host="127.0.0.1")
    assert node.expires_at == node.certificate.not_valid_after_utc
    assert node.expires_at > datetime.now(UTC) + timedelta(days=365 * 19)


def test_load_or_create_creates_with_restricted_permissions(tmp_path):
    path = tmp_path / "state" / "identity.pem"
    node = load_or_create_identity(path, host="127.0.0.1", public_hosts=["rdv.example.com"])
    assert path.is_file()
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert isinstance(node.private_key, ec.EllipticCurvePrivateKey)
    assert len(str(node.fingerprint)) == 64


def test_load_or_create_is_stable_across_loads(tmp_path):
    path = tmp_path / "identity.pem"
    first = load_or_create_identity(path)
    data = path.read_bytes()
    second = load_or_create_identity(path)
    assert str(second.fingerprint) == str(first.fingerprint)
    assert path.read_bytes() == data  # no rewrite on an existing identity


def test_rotate_changes_fingerprint(tmp_path):
    path = tmp_path / "identity.pem"
    first = load_or_create_identity(path)
    rotated = rotate_identity(path, host="127.0.0.1")
    assert str(rotated.fingerprint) != str(first.fingerprint)
    assert str(load_identity(path).fingerprint) == str(rotated.fingerprint)


def test_rotate_preserves_existing_dns_and_ip_sans(tmp_path):
    path = tmp_path / "identity.pem"
    load_or_create_identity(path, host="127.0.0.1", public_hosts=["old.example", "198.51.100.9"])

    rotated = rotate_identity(path, host="127.0.0.1", public_hosts=["new.example"])

    san = rotated.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = set(san.get_values_for_type(x509.DNSName))
    ips = {str(address) for address in san.get_values_for_type(x509.IPAddress)}
    assert {"old.example", "new.example"} <= dns
    assert "198.51.100.9" in ips
    assert "127.0.0.1" in ips


def test_rotate_does_not_duplicate_preserved_sans(tmp_path):
    path = tmp_path / "identity.pem"
    load_or_create_identity(path, host="0.0.0.0")

    rotated = rotate_identity(path, host="0.0.0.0")

    san = rotated.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    values = [name.value for name in san]
    assert values.count("hsync-rendezvous") == 1


def test_rotate_writes_a_consistent_pair_that_reloads(tmp_path):
    """A rotated identity re-reads cleanly and reports its persisted fingerprint.

    ``load_identity`` refuses a key that does not match its certificate, so this
    pins the property the CLI relies on: it only announces a fingerprint the
    node can actually serve.
    """
    path = tmp_path / "identity.pem"
    load_or_create_identity(path, host="127.0.0.1")

    rotated = rotate_identity(path, host="127.0.0.1")
    reloaded = load_identity(path)

    assert reloaded.fingerprint == rotated.fingerprint


def test_rotation_hint_names_the_identity_path():
    assert rotation_hint("/tmp/my identity.pem") == (
        'hsync-rendezvous identity rotate --identity "/tmp/my identity.pem"'
    )


def test_rotate_requires_existing_file(tmp_path):
    with pytest.raises(IdentityError):
        rotate_identity(tmp_path / "missing.pem")


def test_load_identity_rejects_missing_and_garbage(tmp_path):
    with pytest.raises(IdentityError):
        load_identity(tmp_path / "missing.pem")
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("this is not a PEM file")
    with pytest.raises(IdentityError):
        load_identity(garbage)


def test_load_identity_rejects_cert_without_key(tmp_path):
    node = make_identity(host="127.0.0.1")
    from hsync_common import ssl_utils

    cert_only = tmp_path / "cert-only.pem"
    cert_only.write_bytes(ssl_utils.serialize_cert_pem(node.certificate))
    with pytest.raises(IdentityError):
        load_identity(cert_only)


def _write_identity(path, key) -> None:
    cert = ssl_utils.build_self_signed_certificate(
        key,
        subject_attrs=[x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "hsync-rendezvous")],
        san_list=[x509.DNSName("hsync-rendezvous")],
        validity_days=30,
    )
    path.write_bytes(
        ssl_utils.serialize_cert_pem(cert)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(key)
    )


@pytest.mark.parametrize(
    "key_factory",
    [
        lambda: ssl_utils.generate_rsa_private_key(),
        lambda: ssl_utils.generate_ed25519_private_key(),
        lambda: dsa.generate_private_key(key_size=2048),
    ],
)
def test_load_identity_rejects_non_ecdsa(tmp_path, key_factory):
    """Service identities are ECDSA P-256 only; any other key type is refused."""
    path = tmp_path / "non-ecdsa.pem"
    _write_identity(path, key_factory())
    with pytest.raises(IdentityError):
        load_identity(path)


def test_make_identity_dns_bind_host_uses_dns_san():
    """A DNS-name bind host is recorded as a DNS SAN, not an IP SAN crash."""
    node = make_identity(host="localhost")
    san = node.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = {n.value for n in san}
    assert "localhost" in names


def test_load_identity_rejects_mismatched_key(tmp_path):
    """A certificate paired with a different private key is refused at load.

    Both are valid ECDSA P-256 files, so only the key/cert consistency check can
    catch the mismatch — otherwise the TLS handshake would fail later, opaquely.
    """
    cert_key = ssl_utils.generate_ecdsa_private_key()
    other_key = ssl_utils.generate_ecdsa_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        cert_key,
        subject_attrs=[x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "hsync-rendezvous")],
        san_list=[x509.DNSName("hsync-rendezvous")],
        validity_days=30,
    )
    path = tmp_path / "mismatched.pem"
    path.write_bytes(
        ssl_utils.serialize_cert_pem(cert)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(other_key)
    )
    with pytest.raises(IdentityError, match="does not match its certificate") as excinfo:
        load_identity(path)
    assert f'--identity "{path}"' in str(excinfo.value)


def test_load_or_create_ignores_an_orphaned_temp_file(tmp_path):
    """A leftover temp from a crashed run must not wedge the next start.

    ``mkstemp`` gives every temp a unique name in the target directory, so a
    temp orphaned by a crash (SIGKILL between creation and ``os.replace``) can
    never collide with a later write: the identity is created next to it and
    the orphan is left untouched.
    """
    path = tmp_path / "identity.pem"
    orphan = tmp_path / ".identity.pem.orphan.tmp"
    orphan.write_bytes(b"partial write from a killed process")

    node = load_or_create_identity(path, host="127.0.0.1")
    assert path.is_file()
    assert len(str(node.fingerprint)) == 64
    assert orphan.exists()  # never cleared: it is not ours to touch
    # and no temp from this write survives
    assert list(tmp_path.glob(f".{path.name}.*.tmp")) == [orphan]


def test_rotate_ignores_an_orphaned_temp_file(tmp_path):
    """Rotation also survives an orphaned temp and stays atomic."""
    path = tmp_path / "identity.pem"
    load_or_create_identity(path)
    orphan = tmp_path / ".identity.pem.orphan.tmp"
    orphan.write_bytes(b"junk")

    rotated = rotate_identity(path, host="127.0.0.1")
    assert str(load_identity(path).fingerprint) == str(rotated.fingerprint)
    assert orphan.exists()  # never cleared: it is not ours to touch
    assert list(tmp_path.glob(f".{path.name}.*.tmp")) == [orphan]


def test_rotate_recovers_from_a_mismatched_key_certificate(tmp_path):
    """Rotation is the recovery for a corrupted (key/cert mismatch) identity.

    ``load_identity`` refuses the mismatched pair, but ``identity rotate`` must
    still replace it — otherwise a corrupted file would be unrecoverable.
    """
    cert_key = ssl_utils.generate_ecdsa_private_key()
    other_key = ssl_utils.generate_ecdsa_private_key()
    cert = ssl_utils.build_self_signed_certificate(
        cert_key,
        subject_attrs=[x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "hsync-rendezvous")],
        san_list=[x509.DNSName("hsync-rendezvous")],
        validity_days=30,
    )
    path = tmp_path / "identity.pem"
    path.write_bytes(
        ssl_utils.serialize_cert_pem(cert)
        + b"\n"
        + ssl_utils.serialize_private_key_unencrypted(other_key)
    )
    with pytest.raises(IdentityError, match="does not match its certificate"):
        load_identity(path)
    rotated = rotate_identity(path, host="127.0.0.1")
    assert str(load_identity(path).fingerprint) == str(rotated.fingerprint)


def test_rotate_refuses_a_non_identity_file(tmp_path):
    """Rotate must not overwrite a file that is not a PEM identity (safety)."""
    path = tmp_path / "not-an-identity.pem"
    original = b"just some text, not a PEM identity\n"
    path.write_bytes(original)
    with pytest.raises(IdentityError, match="must contain a certificate"):
        rotate_identity(path, host="127.0.0.1")
    assert path.read_bytes() == original  # untouched


def test_load_identity_rejects_a_malformed_pem(tmp_path):
    """A corrupted PEM block raises IdentityError, not a raw ValueError traceback."""
    path = tmp_path / "identity.pem"
    path.write_bytes(
        b"-----BEGIN CERTIFICATE-----\nnot!valid!base64!\n-----END CERTIFICATE-----\n"
        b"-----BEGIN PRIVATE KEY-----\nnot!valid!base64!\n-----END PRIVATE KEY-----\n"
    )
    with pytest.raises(IdentityError, match="not a valid PEM identity"):
        load_identity(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_an_existing_identity_directory_is_never_re_permissioned(tmp_path):
    """--identity may point into a directory we do not own: leave its mode alone."""
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    os.chmod(shared, 0o755)
    load_or_create_identity(shared / "identity.pem", host="127.0.0.1")
    assert stat.S_IMODE(shared.stat().st_mode) == 0o755
    # The key itself is still owner-only.
    assert stat.S_IMODE((shared / "identity.pem").stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_created_identity_directory_is_owner_only(tmp_path):
    path = tmp_path / "fresh" / "state" / "identity.pem"
    load_or_create_identity(path, host="127.0.0.1")
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_too_open_identity_is_hardened_on_load(tmp_path):
    path = tmp_path / "identity.pem"
    load_or_create_identity(path, host="127.0.0.1")
    os.chmod(path, 0o644)
    load_identity(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics")
def test_loading_a_symlinked_identity_is_refused(tmp_path):
    """The identity is opened without following a symlink (read and chmod)."""
    real = tmp_path / "real.pem"
    load_or_create_identity(real, host="127.0.0.1")
    os.chmod(real, 0o644)
    link = tmp_path / "link.pem"
    os.symlink(real, link)
    with pytest.raises(IdentityError, match="could not read identity file"):
        load_identity(link)
    # Hardening must not have followed the link and re-permissioned the target.
    assert stat.S_IMODE(real.stat().st_mode) == 0o644
