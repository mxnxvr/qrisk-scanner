"""Shared fixtures: certificate factory plus local TLS and SSH servers (no internet needed)."""

from __future__ import annotations

import os
import socket
import ssl
import struct
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_cert(key=None, *, cn="test.local", days=365, hash_alg=None, expired=False):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    if expired:
        start, end = now - timedelta(days=400), now - timedelta(days=30)
    else:
        start, end = now - timedelta(days=1), now + timedelta(days=days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("localhost")]), critical=False)
        .sign(key, hash_alg or hashes.SHA256())
    )
    return key, cert


def write_pem(path: Path, key, cert) -> None:
    path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    )


@pytest.fixture
def cert_factory():
    return make_cert


def _serve(listener: socket.socket, handle) -> None:
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


@pytest.fixture
def tls_server(tmp_path):
    """A local TLS 1.2/1.3 server (Python's OpenSSL) with an RSA-2048 certificate. Yields 'localhost:PORT'."""
    key, cert = make_cert(cn="localhost")
    pem = tmp_path / "server.pem"
    write_pem(pem, key, cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pem)
    pem.unlink()

    # "localhost" may resolve to ::1 first (Windows), so listen on both stacks to avoid slow fallbacks.
    if socket.has_dualstack_ipv6():
        listener = socket.create_server(("::", 0), family=socket.AF_INET6, dualstack_ipv6=True)
    else:
        listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def handle(conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(1)
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    threading.Thread(target=_serve, args=(listener, handle), daemon=True).start()
    yield f"localhost:{port}"
    listener.close()


def kexinit_payload(kex, hostkeys, ciphers, macs=("hmac-sha2-256",)) -> bytes:
    def namelist(items):
        raw = ",".join(items).encode()
        return struct.pack("!I", len(raw)) + raw

    body = bytes([20]) + b"\x00" * 16
    for lst in (kex, hostkeys, ciphers, ciphers, macs, macs, ["none"], ["none"], [], []):
        body += namelist(lst)
    return body + b"\x00" + b"\x00\x00\x00\x00"


@pytest.fixture
def ssh_server():
    """A fake SSH server that sends a banner and KEXINIT. Yields (target, mutable algorithm config)."""
    config = {
        "kex": ["mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256",
                "diffie-hellman-group1-sha1", "ext-info-s", "kex-strict-s-v00@openssh.com"],
        "hostkeys": ["ssh-ed25519", "rsa-sha2-512", "ssh-rsa"],
        "ciphers": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "3des-cbc"],
        "macs": ["hmac-sha2-256-etm@openssh.com", "hmac-sha1", "hmac-md5", "hmac-sha1-96"],
        "rsa_bits": 1024,  # size of the RSA host key returned in the key exchange
    }
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    rsa_keys: dict[int, rsa.RSAPublicKey] = {}

    def packet(payload: bytes) -> bytes:
        padding = 8 - ((len(payload) + 5) % 8) + 8
        return struct.pack("!IB", len(payload) + padding + 1, padding) + payload + b"\x00" * padding

    def string(b: bytes) -> bytes:
        return struct.pack("!I", len(b)) + b

    def mpint(n: int) -> bytes:
        return string(n.to_bytes(n.bit_length() // 8 + 1, "big"))

    def handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            conn.sendall(b"Welcome!\r\nSSH-2.0-OpenSSH_9.9 FakeServer\r\n")
            conn.sendall(packet(kexinit_payload(config["kex"], config["hostkeys"], config["ciphers"], config["macs"])))
            f = conn.makefile("rb")
            f.readline()  # client banner
            for _ in range(3):  # client KEXINIT, then KEX_ECDH_INIT
                header = f.read(5)
                if len(header) < 5:
                    return
                length, pad = struct.unpack("!IB", header)
                payload = f.read(length - 1)[: length - 1 - pad]
                if payload[:1] == bytes([30]):
                    bits = config["rsa_bits"]
                    if bits not in rsa_keys:
                        rsa_keys[bits] = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
                    nums = rsa_keys[bits].public_numbers()
                    blob = string(b"ssh-rsa") + mpint(nums.e) + mpint(nums.n)
                    reply = bytes([31]) + string(blob) + string(os.urandom(32)) + string(b"not-a-real-signature")
                    conn.sendall(packet(reply))
                    return
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=_serve, args=(listener, handle), daemon=True).start()
    yield f"127.0.0.1:{port}", config
    listener.close()
