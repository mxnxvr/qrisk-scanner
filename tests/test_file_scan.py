from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from qrisk.models import Rating
from qrisk.scanners.certs import scan_path


def test_scan_folder(tmp_path, cert_factory):
    _, weak = cert_factory(rsa.generate_private_key(public_exponent=65537, key_size=1024),
                           cn="weak")
    (tmp_path / "weak.crt").write_bytes(weak.public_bytes(serialization.Encoding.PEM))

    _, ec_cert = cert_factory(ec.generate_private_key(ec.SECP384R1()), cn="ec")
    (tmp_path / "ec.der").write_bytes(ec_cert.public_bytes(serialization.Encoding.DER))

    _, old = cert_factory(cn="old", expired=True)
    (tmp_path / "old.pem").write_bytes(old.public_bytes(serialization.Encoding.PEM))

    key = ed25519.Ed25519PrivateKey.generate()
    (tmp_path / "id.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "id_ed25519.pub").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH))

    p12_key, p12_cert = cert_factory(cn="p12")
    (tmp_path / "bundle.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"bundle", p12_key, p12_cert, None, serialization.NoEncryption()))
    (tmp_path / "locked.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"x", p12_key, p12_cert, None, serialization.BestAvailableEncryption(b"secret")))
    (tmp_path / "store.jks").write_bytes(b"\xfe\xed\xfe\xed")
    (tmp_path / "ignored.txt").write_text("nothing")

    findings, notes = scan_path(tmp_path)

    def has(pred):
        return any(pred(f) for f in findings)

    assert has(lambda f: f.asset.startswith("RSA-1024 certificate") and f.rating is Rating.CRITICAL)
    assert has(lambda f: f.asset.startswith("ECDSA-P-384 certificate") and f.location.endswith("ec.der"))
    assert has(lambda f: f.category == "certificate-validity" and "old" in f.asset)
    assert has(lambda f: f.asset == "Ed25519 private key")
    assert has(lambda f: f.asset == "Ed25519 public key" and f.location.endswith(".pub"))
    assert has(lambda f: f.location.endswith("bundle.p12") and f.category == "private-key")
    assert any("password-protected" in n.message for n in notes)
    assert any("Could not parse Java keystore" in n.message for n in notes)
    assert all(f.target == f"path:{tmp_path}" for f in findings)


def test_missing_path(tmp_path):
    findings, notes = scan_path(tmp_path / "nope")
    assert findings == [] and notes[0].level == "error"


def _jks(entries, magic=b"\xfe\xed\xfe\xed"):
    """Build a JKS file by hand: magic, version 2, entries, 20-byte digest."""
    import struct

    def utf(s):
        b = s.encode()
        return struct.pack("!H", len(b)) + b

    def cert(der):
        return utf("X.509") + struct.pack("!I", len(der)) + der

    out = magic + struct.pack("!II", 2, len(entries))
    for kind, alias, ders in entries:
        if kind == "trusted":
            out += struct.pack("!I", 2) + utf(alias) + struct.pack("!Q", 0) + cert(ders[0])
        else:
            enc = b"\x30\x03\x02\x01\x00"  # stand-in for the encrypted key
            out += struct.pack("!I", 1) + utf(alias) + struct.pack("!Q", 0) + struct.pack("!I", len(enc)) + enc
            out += struct.pack("!I", len(ders)) + b"".join(cert(d) for d in ders)
    return out + b"\x00" * 20


def test_java_keystore_read_without_password(tmp_path, cert_factory):
    _, server = cert_factory(rsa.generate_private_key(public_exponent=65537, key_size=1024), cn="server")
    _, ca = cert_factory(ec.generate_private_key(ec.SECP384R1()), cn="ca")
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    (tmp_path / "app.jks").write_bytes(_jks([("key", "server", [der(server), der(ca)]), ("trusted", "rootca", [der(ca)])]))
    (tmp_path / "legacy.jceks").write_bytes(_jks([("trusted", "ca", [der(ca)])], magic=b"\xce\xce\xce\xce"))

    findings, notes = scan_path(tmp_path)
    fmt = {f.asset: f for f in findings if f.category == "keystore"}
    assert fmt["JKS keystore format"].rating is Rating.CRITICAL
    assert "PKCS12" in fmt["JKS keystore format"].recommendation
    assert fmt["JCEKS keystore format"].rating is Rating.CRITICAL
    server_key = next(f for f in findings if f.asset.startswith("RSA-1024 certificate (server)"))
    assert server_key.details["keystore_alias"] == "server" and server_key.details["keystore_entry"] == "private-key"
    assert sum(1 for f in findings if f.asset.startswith("ECDSA-P-384 certificate (ca)")) == 3
    assert any("read without the password" in n.message for n in notes)


def test_post_quantum_private_key_identified_by_oid(tmp_path):
    import base64
    # Minimal PKCS#8 for ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18): cryptography can't load it, QRisk reads the OID.
    der = bytes.fromhex("3018020100300b0609608648016503040312" + "0406deadbeef0000")
    pem = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(der) + b"-----END PRIVATE KEY-----\n"
    (tmp_path / "mldsa.key").write_bytes(pem)
    findings, notes = scan_path(tmp_path)
    key = next(f for f in findings if f.category == "private-key")
    assert key.asset == "ML-DSA-65 private key" and key.rating is Rating.QUANTUM_SAFE
    assert not any("Could not parse" in n.message for n in notes)
