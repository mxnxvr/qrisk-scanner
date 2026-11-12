"""Layer 3: SSH servers.

The server's SSH_MSG_KEXINIT is sent in clear text before any key exchange,
so we read it straight off the socket. No SSH library or login needed.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, replace

from ..models import Finding, Note, Rating
from ..rules import REC_SSH_HOSTKEY, rate_public_key, rate_ssh_cipher, rate_ssh_hostkey, rate_ssh_kex, rate_ssh_mac
from .tls import parse_target
from .tlswire import pick_address

CLIENT_BANNER = b"SSH-2.0-QRiskScanner_0.1\r\n"
MSG_KEXINIT = 20
_PSEUDO = ("ext-info-", "kex-strict-")  # protocol extensions, not algorithms


@dataclass
class KexInit:
    banner: str
    kex: list[str]
    host_keys: list[str]
    ciphers_c2s: list[str]
    ciphers_s2c: list[str]
    macs_c2s: list[str]
    macs_s2c: list[str]


def parse_kexinit(payload: bytes, banner: str = "") -> KexInit:
    if not payload or payload[0] != MSG_KEXINIT:
        raise ValueError("not an SSH_MSG_KEXINIT packet")
    p = 1 + 16  # message type + cookie
    lists: list[list[str]] = []
    for _ in range(10):
        (n,) = struct.unpack("!I", payload[p : p + 4])
        raw = payload[p + 4 : p + 4 + n].decode("ascii", "replace")
        lists.append([a for a in raw.split(",") if a])
        p += 4 + n
    kex = [a for a in lists[0] if not a.startswith(_PSEUDO)]
    return KexInit(banner, kex, lists[1], lists[2], lists[3], lists[4], lists[5])


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by server")
        buf += chunk
    return buf


def fetch_kexinit(host: str, port: int, timeout: float) -> KexInit:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        # Servers may print other lines before the version banner (RFC 4253 section 4.2).
        banner = ""
        f = sock.makefile("rb")
        for _ in range(50):
            line = f.readline(1024)
            if not line:
                raise ConnectionError("no SSH banner received")
            if line.startswith(b"SSH-"):
                banner = line.decode("ascii", "replace").strip()
                break
        else:
            raise ValueError("no SSH banner found")
        sock.sendall(CLIENT_BANNER)
        header = f.read(5)
        if len(header) < 5:
            raise ConnectionError("connection closed before KEXINIT")
        packet_len, padding_len = struct.unpack("!IB", header)
        if packet_len > 35000:
            raise ValueError("SSH packet too large")
        rest = f.read(packet_len - 1)
        payload = rest[: packet_len - 1 - padding_len]
        return parse_kexinit(payload, banner)


# --- host key size (needs one key-exchange round trip) -------------------------------------
# The KEXINIT only names algorithms. To learn an RSA host key's size we start a real key
# exchange: the server's KEX_ECDH_REPLY carries its public host key. We stop right there:
# nothing is authenticated and no session is set up.

MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY = 30, 31
_OUR_KEX = ["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"]


def _string(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def _namelist(items: list[str]) -> bytes:
    return _string(",".join(items).encode())


def _packet(payload: bytes) -> bytes:
    pad = 8 - ((len(payload) + 5) % 8)
    if pad < 4:
        pad += 8
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + os.urandom(pad)


def _read_packet(f) -> bytes:
    header = f.read(5)
    if len(header) < 5:
        raise ConnectionError("connection closed")
    packet_len, padding_len = struct.unpack("!IB", header)
    if packet_len > 35000:
        raise ValueError("SSH packet too large")
    rest = f.read(packet_len - 1)
    return rest[: packet_len - 1 - padding_len]


def _read_string(buf: bytes, p: int) -> tuple[bytes, int]:
    (n,) = struct.unpack("!I", buf[p : p + 4])
    return buf[p + 4 : p + 4 + n], p + 4 + n


def parse_host_key_blob(blob: bytes) -> tuple[str, int | None]:
    """(key type, size in bits) from an SSH public key blob."""
    key_type, p = _read_string(blob, 0)
    kt = key_type.decode("ascii", "replace")
    if kt == "ssh-rsa":
        _e, p = _read_string(blob, p)
        n, _ = _read_string(blob, p)
        return kt, int.from_bytes(n, "big").bit_length()
    if kt == "ssh-dss":
        prime, _ = _read_string(blob, p)
        return kt, int.from_bytes(prime, "big").bit_length()
    return kt, None


def fetch_host_key(host: str, port: int, timeout: float, host_key_alg: str, server_kex: list[str],
                   server: KexInit) -> bytes | None:
    """Run the key exchange far enough to receive the server's host key blob for ``host_key_alg``."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519

    kex = next((k for k in _OUR_KEX if k in server_kex), None)
    if kex is None:
        return None
    # Throwaway classical keys: needed to speak the server's own (classical) key exchange.
    if kex.startswith("curve25519"):
        q_c = x25519.X25519PrivateKey.generate().public_key().public_bytes(  # qrisk: ignore
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        curve = {"nistp256": ec.SECP256R1(), "nistp384": ec.SECP384R1(), "nistp521": ec.SECP521R1()}[kex[-8:]]
        q_c = ec.generate_private_key(curve).public_key().public_bytes(  # qrisk: ignore
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    with socket.create_connection((host, port), timeout=timeout) as sock:
        f = sock.makefile("rb")
        for _ in range(50):
            line = f.readline(1024)
            if not line:
                return None
            if line.startswith(b"SSH-"):
                break
        sock.sendall(CLIENT_BANNER)
        _read_packet(f)  # server KEXINIT
        # Offer the server's own symmetric lists back so negotiation can't fail on them.
        kexinit = (bytes([MSG_KEXINIT]) + os.urandom(16) + _namelist([kex]) + _namelist([host_key_alg])
                   + _namelist(server.ciphers_c2s) + _namelist(server.ciphers_s2c)
                   + _namelist(server.macs_c2s) + _namelist(server.macs_s2c)
                   + _namelist(["none"]) + _namelist(["none"]) + _namelist([]) + _namelist([])
                   + b"\x00" + struct.pack("!I", 0))
        sock.sendall(_packet(kexinit) + _packet(bytes([MSG_KEX_ECDH_INIT]) + _string(q_c)))
        for _ in range(5):
            payload = _read_packet(f)
            if payload and payload[0] == MSG_KEX_ECDH_REPLY:
                blob, _ = _read_string(payload, 1)
                return blob
    return None


def scan_ssh(target: str, timeout: float = 5.0) -> tuple[list[Finding], list[Note]]:
    host, port = parse_target(target, 22)
    label = f"{host}:{port}"
    try:
        host = pick_address(host, port, timeout)  # one working address for every connection
        info = fetch_kexinit(host, port, timeout)
    except (OSError, ValueError, struct.error) as exc:
        return [], [Note(label, f"SSH scan failed: {exc}", "error")]

    findings: list[Finding] = []
    for i, name in enumerate(info.kex):
        v = rate_ssh_kex(name)
        findings.append(Finding(label, "ssh", "key-exchange", name, v.rating, v.reason, v.recommendation,
                                v.nist, v.algo, details={"server_preference": i + 1}))
    for name in info.host_keys:
        v = rate_ssh_hostkey(name)
        findings.append(Finding(label, "ssh", "host-key", name, v.rating, v.reason, v.recommendation,
                                v.nist, v.algo))
    for name in dict.fromkeys(info.ciphers_s2c + info.ciphers_c2s):
        v = rate_ssh_cipher(name)
        findings.append(Finding(label, "ssh", "cipher", name, v.rating, v.reason, v.recommendation,
                                v.nist, v.algo))
    for name in dict.fromkeys(info.macs_s2c + info.macs_c2s):
        v = rate_ssh_mac(name)
        findings.append(Finding(label, "ssh", "mac", name, v.rating, v.reason, v.recommendation, v.nist, v.algo))

    notes = [Note(label, f"Server banner: {info.banner}", "info")]

    # RSA/DSA host key sizes vary, so fetch the actual key. (Ed25519/ECDSA sizes are fixed by their name.)
    for family in (("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"), ("ssh-dss",)):
        alg = next((a for a in family if a in info.host_keys), None)
        if not alg:
            continue
        try:
            blob = fetch_host_key(host, port, timeout, alg, info.kex, info)
        except (OSError, ValueError, struct.error) as exc:
            notes.append(Note(label, f"Could not read the {alg} host key: {exc}", "info"))
            continue
        if not blob:
            continue
        key_type, bits = parse_host_key_blob(blob)
        if bits:
            v = rate_public_key("RSA" if key_type == "ssh-rsa" else "DSA", bits)
            if v.rating is Rating.CRITICAL:
                v = replace(v, recommendation="Replace the host key: `ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key` "
                                              "(or RSA-3072+), then remove the weak HostKey line.")
            else:
                v = replace(v, recommendation=REC_SSH_HOSTKEY)
            findings.append(Finding(label, "ssh", "host-key-size", f"{v.algo.name} host key", v.rating, v.reason,
                                    v.recommendation, v.nist, v.algo, details={"key_type": key_type, "bits": bits}))
    if not any(n.startswith(("mlkem", "sntrup")) for n in info.kex):
        notes.append(Note(label, "No post-quantum key exchange offered (mlkem768x25519-sha256 / sntrup761x25519-sha512).",
                          "warning"))
    return findings, notes
