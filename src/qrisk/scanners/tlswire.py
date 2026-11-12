"""Minimal raw TLS ClientHello / ServerHello handling.

We speak just enough TLS to learn what a server *accepts*, without needing a
local OpenSSL that supports every algorithm. That's how we detect
post-quantum groups such as X25519MLKEM768 even though Python's bundled
OpenSSL may not support them.

Trick for TLS 1.3 groups: send a ClientHello that lists groups in
``supported_groups`` but has an *empty* ``key_share``. A server that supports
one of the groups must answer with a HelloRetryRequest that names the group
it picked; otherwise it sends an alert.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import struct
from dataclasses import dataclass

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

# ECDSA, EdDSA, RSA-PSS, RSA-PKCS1, ML-DSA (44/65/87), legacy SHA-1
SIGNATURE_ALGORITHMS = [
    0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806,
    0x0401, 0x0501, 0x0601, 0x0904, 0x0905, 0x0906, 0x0203, 0x0201,
]


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _vec8(b: bytes) -> bytes:
    return struct.pack("!B", len(b)) + b


def _vec16(b: bytes) -> bytes:
    return _u16(len(b)) + b


def _ext(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _vec16(data)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def build_client_hello(
    host: str | None,
    *,
    version: int,
    cipher_suites: list[int],
    groups: list[int],
    tls13: bool = False,
) -> bytes:
    """Build a complete TLS record holding a ClientHello.

    ``tls13=True`` offers *only* TLS 1.3 (via supported_versions) with an empty
    key_share. Otherwise ``version`` is the legacy version we ask for.
    """
    exts = b""
    if host and not is_ip(host):
        name = host.encode("idna")
        exts += _ext(EXT_SERVER_NAME, _vec16(b"\x00" + _vec16(name)))
    if groups:
        exts += _ext(EXT_SUPPORTED_GROUPS, _vec16(b"".join(_u16(g) for g in groups)))
    exts += _ext(EXT_EC_POINT_FORMATS, _vec8(b"\x00"))
    exts += _ext(EXT_SIGNATURE_ALGORITHMS, _vec16(b"".join(_u16(s) for s in SIGNATURE_ALGORITHMS)))
    exts += _ext(EXT_RENEGOTIATION_INFO, b"\x00")
    if tls13:
        exts += _ext(EXT_SUPPORTED_VERSIONS, _vec8(_u16(0x0304)))
        exts += _ext(EXT_PSK_MODES, _vec8(b"\x01"))
        exts += _ext(EXT_KEY_SHARE, _vec16(b""))

    legacy_version = 0x0303 if tls13 else version
    body = (
        _u16(legacy_version)
        + os.urandom(32)
        + _vec8(os.urandom(32))
        + _vec16(b"".join(_u16(c) for c in cipher_suites))
        + b"\x01\x00"  # compression methods: null
        + _vec16(exts)
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record_version = 0x0300 if (not tls13 and version == 0x0300) else 0x0301
    return b"\x16" + _u16(record_version) + _vec16(handshake)


@dataclass
class ServerHello:
    version: int  # negotiated version (from supported_versions when present)
    legacy_version: int
    cipher_suite: int
    extensions: dict[int, bytes]
    is_hrr: bool

    @property
    def selected_group(self) -> int | None:
        ks = self.extensions.get(EXT_KEY_SHARE)
        if ks and len(ks) >= 2:
            return int.from_bytes(ks[:2], "big")
        return None


def parse_server_hello(body: bytes) -> ServerHello:
    legacy = int.from_bytes(body[0:2], "big")
    random = body[2:34]
    p = 34
    sid_len = body[p]
    p += 1 + sid_len
    cipher = int.from_bytes(body[p : p + 2], "big")
    p += 3  # cipher suite + compression method
    exts: dict[int, bytes] = {}
    if p + 2 <= len(body):
        end = p + 2 + int.from_bytes(body[p : p + 2], "big")
        p += 2
        while p + 4 <= end:
            ext_type = int.from_bytes(body[p : p + 2], "big")
            ext_len = int.from_bytes(body[p + 2 : p + 4], "big")
            exts[ext_type] = body[p + 4 : p + 4 + ext_len]
            p += 4 + ext_len
    version = legacy
    sv = exts.get(EXT_SUPPORTED_VERSIONS)
    if sv and len(sv) == 2:
        version = int.from_bytes(sv, "big")
    return ServerHello(version, legacy, cipher, exts, random == HRR_RANDOM)


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_server_hello(sock: socket.socket) -> ServerHello | None:
    """Read records until a full ServerHello arrives. Returns None on alert/close."""
    hs = b""
    while len(hs) < 70_000:
        header = _recv_exact(sock, 5)
        if header is None:
            return None
        content_type, _, length = struct.unpack("!BHH", header)
        payload = _recv_exact(sock, length)
        if payload is None or content_type != 22:  # 21 = alert, anything else = not TLS
            return None
        hs += payload
        if len(hs) >= 4:
            msg_len = int.from_bytes(hs[1:4], "big")
            if len(hs) >= 4 + msg_len:
                if hs[0] != 2:  # not a ServerHello
                    return None
                return parse_server_hello(hs[4 : 4 + msg_len])
    return None


HS_SERVER_HELLO, HS_CERTIFICATE, HS_SERVER_KEY_EXCHANGE, HS_SERVER_HELLO_DONE = 2, 11, 12, 14


def read_handshake(sock: socket.socket, until: tuple[int, ...] = (HS_SERVER_KEY_EXCHANGE, HS_SERVER_HELLO_DONE)
                   ) -> dict[int, bytes]:
    """Read TLS 1.2-and-below handshake messages (they're unencrypted) until one of ``until`` arrives."""
    msgs: dict[int, bytes] = {}
    buf, total = b"", 0
    while total < 200_000:
        header = _recv_exact(sock, 5)
        if header is None:
            break
        content_type, _, length = struct.unpack("!BHH", header)
        payload = _recv_exact(sock, length)
        if payload is None or content_type != 22:
            break
        total += length
        buf += payload
        while len(buf) >= 4:
            msg_len = int.from_bytes(buf[1:4], "big")
            if len(buf) < 4 + msg_len:
                break
            msg_type = buf[0]
            msgs.setdefault(msg_type, buf[4 : 4 + msg_len])
            buf = buf[4 + msg_len :]
            if msg_type in until:
                return msgs
    return msgs


def probe_handshake(host: str, port: int, hello: bytes, timeout: float) -> dict[int, bytes]:
    """Like :func:`probe` but returns every handshake message up to ServerKeyExchange / ServerHelloDone."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        try:
            sock.sendall(hello)
            return read_handshake(sock)
        except (OSError, ValueError, IndexError, struct.error):
            return {}


def ske_named_curve(ske: bytes | None) -> int | None:
    """ECDHE ServerKeyExchange: curve_type (3 = named_curve) then the 2-byte group id."""
    if ske and len(ske) >= 3 and ske[0] == 3:
        return int.from_bytes(ske[1:3], "big")
    return None


def ske_dh_bits(ske: bytes | None) -> int | None:
    """DHE ServerKeyExchange starts with the prime p as a 2-byte-length vector."""
    if ske and len(ske) >= 2:
        p_len = int.from_bytes(ske[:2], "big")
        p = ske[2 : 2 + p_len]
        if len(p) == p_len and p_len:
            return int.from_bytes(p, "big").bit_length()
    return None


def pick_address(host: str, port: int, timeout: float) -> str:
    """Resolve ``host`` once and return the first address that accepts a TCP connection.

    A scan opens 30-100 connections. If the name resolves to an address that doesn't answer
    (typically IPv6 ``::1`` for ``localhost`` while the service listens on IPv4 only, or a
    host with broken IPv6), every one of them would wait for that attempt to fail first:
    about 2 s each on Windows. Picking the working address up front pays that cost once.
    """
    infos = socket.getaddrinfo(host.strip("[]"), port, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"could not resolve {host}")

    def attempt(info) -> str:
        family, socktype, proto, _, sockaddr = info
        with socket.socket(family, socktype, proto) as s:
            s.settimeout(timeout)
            s.connect(sockaddr)
        return sockaddr[0]

    # Try every address at once ("Happy Eyeballs", RFC 8305) and keep the first that connects,
    # so a dead IPv6 path doesn't cost its own timeout before IPv4 is tried.
    pool = ThreadPoolExecutor(max_workers=min(len(infos), 8))
    futures = [pool.submit(attempt, info) for info in infos]
    last_error: OSError | None = None
    try:
        for fut in as_completed(futures):
            try:
                return fut.result()
            except OSError as exc:
                last_error = exc
    finally:
        pool.shutdown(wait=False, cancel_futures=True)  # don't wait for slower losers
    raise last_error or OSError(f"could not connect to {host}")


def probe(host: str, port: int, hello: bytes, timeout: float) -> ServerHello | None:
    """Send one ClientHello. Connection errors on connect propagate (target unreachable)."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        try:
            sock.sendall(hello)
            return read_server_hello(sock)
        except (OSError, ValueError, IndexError, struct.error):
            return None
