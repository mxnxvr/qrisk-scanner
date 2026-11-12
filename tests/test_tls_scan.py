import pytest

from qrisk.models import Rating
from qrisk.scanners.tls import parse_target, scan_tls


def test_parse_target():
    assert parse_target("example.com", 443) == ("example.com", 443)
    assert parse_target("https://example.com:8443/path", 443) == ("example.com", 8443)
    assert parse_target("[::1]:4433", 443) == ("::1", 4433)


def test_scan_local_server(tls_server):
    findings, notes = scan_tls(tls_server, timeout=3)
    assets = {f.asset for f in findings}
    assert {"TLS 1.2", "TLS 1.3"} <= assets
    assert "TLS 1.0" not in assets
    assert any(f.category == "key-exchange" and f.asset.startswith("x25519") for f in findings)
    assert "TLS_AES_256_GCM_SHA384" in assets
    assert "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" in assets
    cert = next(f for f in findings if f.category == "certificate-key")
    assert cert.asset.startswith("RSA-2048") and cert.rating is Rating.QUANTUM_VULNERABLE
    assert cert.cert.key_size == 2048
    # Python's bundled OpenSSL has no ML-KEM, so the scanner should warn about it.
    assert any("no post-quantum key exchange" in n.message for n in notes)
    assert any("not trusted" in n.message for n in notes)


def test_unreachable():
    findings, notes = scan_tls("127.0.0.1:1", timeout=1)
    assert findings == [] and notes[0].level == "error"


@pytest.mark.network
def test_live_pq_server():
    findings, _ = scan_tls("pq.cloudflareresearch.com", timeout=10)
    assert any(f.asset.startswith("X25519MLKEM768") and f.rating is Rating.HYBRID for f in findings)


def test_tls12_curves_from_server_key_exchange(tls_server):
    findings, _ = scan_tls(tls_server, timeout=3)
    kex12 = {f.asset: f for f in findings if f.category == "key-exchange" and "TLS 1.2" in f.asset}
    assert "x25519 (TLS 1.2)" in kex12 and "secp256r1 (TLS 1.2)" in kex12
    assert "ECDHE (TLS 1.2)" not in kex12, "generic ECDHE replaced by the real curves"
    assert "post-quantum" in kex12["x25519 (TLS 1.2)"].reason


# RFC 2409 Oakley group 2: a 1024-bit MODP prime, i.e. a Logjam-weak DHE server.
_P1024 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)


def _dh_params_pem(p: int, g: int) -> bytes:
    """PKCS#3 DHParameter ::= SEQUENCE { prime INTEGER, base INTEGER }, DER-encoded by hand."""
    import base64

    def length(n: int) -> bytes:
        return bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")

    def integer(n: int) -> bytes:
        b = n.to_bytes(n.bit_length() // 8 + 1, "big")
        return bytes([0x02]) + length(len(b)) + b  # INTEGER

    body = integer(p) + integer(g)
    der = bytes([0x30]) + length(len(body)) + body  # SEQUENCE
    pem = base64.encodebytes(der)
    return b"-----BEGIN DH PARAMETERS-----" + bytes([10]) + pem + b"-----END DH PARAMETERS-----" + bytes([10])


@pytest.fixture
def dhe_server(tmp_path):
    import socket
    import ssl
    import threading

    from conftest import make_cert, write_pem

    key, cert = make_cert(cn="localhost")
    pem = tmp_path / "s.pem"
    write_pem(pem, key, cert)
    dhfile = tmp_path / "dh.pem"
    dhfile.write_bytes(_dh_params_pem(_P1024, 2))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pem)
    ctx.set_ciphers("DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0")
    ctx.load_dh_params(str(dhfile))
    listener = socket.create_server(("127.0.0.1", 0))

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            try:
                conn.settimeout(3)
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(1)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield f"127.0.0.1:{listener.getsockname()[1]}"
    listener.close()


def test_dhe_prime_size_logjam(dhe_server):
    findings, _ = scan_tls(dhe_server, timeout=3)
    dhe = next(f for f in findings if f.asset == "DHE-1024 (TLS 1.2)")
    assert dhe.rating is Rating.CRITICAL and "Logjam" in dhe.reason
