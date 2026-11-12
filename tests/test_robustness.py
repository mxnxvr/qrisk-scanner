"""A scan must survive flaky targets, and must not under-report weak servers."""

import os
import socket
import struct
import threading

import pytest
from cryptography.hazmat.primitives import serialization

from qrisk.models import Rating
from qrisk.scan import run_scan
from qrisk.scanners import config as config_mod
from qrisk.scanners import tls as tls_mod
from qrisk.scanners.config import scan_config
from qrisk.scanners.tls import scan_tls


# --- review #2: one failed target must not crash the whole scan ---------------------------

def test_failing_target_becomes_error_note_and_others_survive(tmp_path, cert_factory, monkeypatch):
    _, cert = cert_factory(cn="survivor")
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def explode(target, timeout):
        raise TimeoutError("timed out after 40 handshakes")

    monkeypatch.setattr("qrisk.scan.scan_tls", explode)
    result = run_scan(tls=["flaky.example"], paths=[str(tmp_path)])
    assert any(f.asset.startswith("RSA-2048 certificate (survivor)") for f in result.findings)
    err = next(n for n in result.notes if n.level == "error")
    assert "TLS scan failed: TimeoutError" in err.message
    assert ("tls", "flaky.example") in result.targets


def test_tls_keeps_partial_results_when_server_starts_resetting(tls_server, monkeypatch):
    real_probe, calls = tls_mod.probe, {"n": 0}

    def flaky_probe(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 5:  # the 5 version probes succeed, then the "firewall" kicks in
            raise ConnectionResetError("connection reset by peer")
        return real_probe(*args, **kwargs)

    monkeypatch.setattr(tls_mod, "probe", flaky_probe)
    findings, notes = scan_tls(tls_server, timeout=3)
    assets = {f.asset for f in findings}
    assert {"TLS 1.2", "TLS 1.3"} <= assets                       # step 1 kept
    assert any(f.category == "certificate-key" for f in findings)  # step 4 still ran
    assert any("interrupted" in n.message and n.level == "warning" for n in notes)


def test_config_unreadable_file_is_a_note_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "_candidates", lambda root: [tmp_path / "vanished.conf"])
    findings, notes = scan_config(tmp_path)
    assert findings == [] and any("Could not read" in n.message for n in notes)


# --- review #4: weak suites on older TLS versions only ---------------------------------------

# Fake server policy: version -> suites it accepts, in preference order.
POLICY = {
    0x0303: [0xC02F],                          # TLS 1.2: ECDHE-RSA-AES128-GCM only
    0x0301: [0xC02F, 0x0005, 0x0003],          # TLS 1.0: also RC4 and EXPORT-RC4-40
}


def _client_hello(data: bytes) -> tuple[int, list[int], bool]:
    body = data[9:]  # 5-byte record header + 4-byte handshake header
    version = int.from_bytes(body[0:2], "big")
    p = 34 + 1 + body[34]
    n = int.from_bytes(body[p:p + 2], "big")
    suites = [int.from_bytes(body[p + 2 + i:p + 4 + i], "big") for i in range(0, n, 2)]
    p += 2 + n
    p += 1 + body[p]  # compression methods
    end, p = p + 2 + int.from_bytes(body[p:p + 2], "big"), p + 2
    tls13 = False
    while p + 4 <= end:  # walk the extensions; 43 = supported_versions (a TLS 1.3 ClientHello)
        ext_type, ext_len = struct.unpack("!HH", body[p:p + 4])
        tls13 = tls13 or ext_type == 43
        p += 4 + ext_len
    return version, suites, tls13


@pytest.fixture
def legacy_tls_server():
    listener = socket.create_server(("127.0.0.1", 0))

    def handle(conn):
        try:
            conn.settimeout(3)
            f = conn.makefile("rb")
            header = f.read(5)
            if len(header) < 5:  # plain TCP connect, e.g. the scanner checking which address works
                return
            data = header + f.read(int.from_bytes(header[3:5], "big"))
            version, offered, tls13 = _client_hello(data)
            choice = None if tls13 else next((c for c in POLICY.get(version, []) if c in offered), None)
            if choice is None:
                conn.sendall(b"\x15\x03\x01\x00\x02\x02\x28")  # alert: handshake_failure
                return
            sh = struct.pack("!H", version) + os.urandom(32) + b"\x00" + struct.pack("!HB", choice, 0)
            hs = b"\x02" + struct.pack("!I", len(sh))[1:] + sh
            conn.sendall(b"\x16" + struct.pack("!HH", version, len(hs)) + hs)
        except OSError:
            pass
        finally:
            conn.close()

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    yield f"127.0.0.1:{listener.getsockname()[1]}"
    listener.close()


def test_weak_suites_allowed_only_on_tls10_are_found(legacy_tls_server):
    findings, _ = scan_tls(legacy_tls_server, timeout=3)
    by_asset = {f.asset: f for f in findings if f.category == "cipher"}
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in by_asset            # found at TLS 1.2
    rc4 = by_asset["TLS_RSA_WITH_RC4_128_SHA (TLS 1.0)"]                  # only on TLS 1.0
    assert rc4.rating is Rating.CRITICAL and rc4.details["version"] == "1.0"
    export = by_asset["TLS_RSA_EXPORT_WITH_RC4_40_MD5 (TLS 1.0)"]
    assert export.rating is Rating.CRITICAL and "Export" in export.reason
    # Static RSA key exchange, seen only on TLS 1.0, is still reported.
    assert any(f.asset == "RSA key transport (TLS 1.0)" and f.rating is Rating.CRITICAL for f in findings)


def test_dangerous_suites_are_offered():
    names = set(tls_mod.LEGACY_SUITES.values())
    for needle in ("NULL", "EXPORT", "_DES_CBC_", "CAMELLIA", "ARIA", "SEED", "CCM", "anon", "IDEA"):
        assert any(needle in n for n in names), needle


# --- review #8: includes and referenced files stay inside the scanned folder -----------------

def test_external_includes_need_an_explicit_flag(tmp_path, cert_factory):
    outside, scanned = tmp_path / "outside", tmp_path / "copied-config"
    outside.mkdir()
    scanned.mkdir()
    (outside / "evil.conf").write_text("ssl_ciphers 'RC4-SHA';\n")
    _, cert = cert_factory(cn="scanner-machine")
    (outside / "host.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (scanned / "nginx.conf").write_text(
        "http {\n"
        f"  include {(outside / 'evil.conf').as_posix()};\n"
        "  server {\n"
        "    listen 443 ssl;\n"
        f"    ssl_certificate ../outside/host.pem;\n"
        "  }\n"
        "}\n")

    findings, notes = scan_config(scanned)
    assert not any(f.asset == "RC4-SHA" for f in findings)
    assert not any("scanner-machine" in f.asset for f in findings)
    messages = " ".join(n.message for n in notes)
    assert "Include" in messages and "--config-follow-external" in messages
    assert "Referenced file ../outside/host.pem is outside the scanned folder" in messages

    findings, _ = scan_config(scanned, follow_external=True)
    assert any(f.asset == "RC4-SHA" for f in findings)
    assert any("scanner-machine" in f.asset for f in findings)


# --- found running the lab: `localhost` on an IPv4-only server cost ~2 s per connection ------

def test_localhost_scan_of_ipv4_only_server_is_fast(legacy_tls_server):
    """On Windows `localhost` resolves to ::1 first. Docker (and this fake server) listen on IPv4
    only, so every one of ~40 connections used to wait ~2 s for IPv6 to fail: 80+ s per server."""
    import time

    from qrisk.scanners.tlswire import pick_address

    port = int(legacy_tls_server.rsplit(":", 1)[1])
    assert pick_address("localhost", port, timeout=5) == "127.0.0.1"
    start = time.monotonic()
    findings, _ = scan_tls(f"localhost:{port}", timeout=5)
    assert findings and time.monotonic() - start < 5
