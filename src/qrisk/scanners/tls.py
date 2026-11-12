"""Layer 1: TLS endpoints.

Finds supported protocol versions, TLS 1.3 key-exchange groups (including
post-quantum hybrids), accepted cipher suites, and the server certificate.
"""

from __future__ import annotations

import socket
import struct
import ssl
import warnings
from collections.abc import Callable
from dataclasses import replace

from cryptography import x509

from ..models import Finding, Note, Rating
from ..rules import (
    REC_TLS13, TLS_VERSIONS, Verdict, rate_bulk_cipher, rate_public_key, rate_tls12_kex, rate_tls_group, rate_tls_version,
    split_tls12_suite,
)
from .certs import analyze_certificate
from .tlswire import (
    HS_SERVER_KEY_EXCHANGE, ServerHello, build_client_hello, is_ip, pick_address, probe, probe_handshake, ske_dh_bits, ske_named_curve,
)

TLS13_SUITES: dict[int, str] = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

LEGACY_SUITES: dict[int, str] = {
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    # NULL (no encryption)
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    # EXPORT (deliberately weakened, FREAK / Logjam)
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    # Single DES, more 3DES / RC4, IDEA
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0x0007: "TLS_RSA_WITH_IDEA_CBC_SHA",
    # Camellia, ARIA, SEED (sound but not NIST-approved)
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0xC050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0x0096: "TLS_RSA_WITH_SEED_CBC_SHA",
    # AES-CCM and more ChaCha20
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

# Ordered like a modern browser: post-quantum hybrids first.
ALL_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0200, 0x0202, 0x6399,
              0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101, 0x0102]
CLASSIC_GROUPS = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
SCSV = 0x00FF  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV


def parse_target(target: str, default_port: int) -> tuple[str, int]:
    target = target.strip()
    for prefix in ("https://", "http://", "ssh://", "tls://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/", 1)[0]
    if target.startswith("["):  # [IPv6]:port
        host, _, rest = target[1:].partition("]")
        return host, int(rest.lstrip(":") or default_port)
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default_port


def _enumerate(make_hello: Callable[[list[int]], bytes], items: list[int],
               pick: Callable[[ServerHello], int | None], send: Callable[[bytes], ServerHello | None]) -> list[int]:
    """Offer everything, record what the server picks, remove it, repeat."""
    remaining, found = list(items), []
    while remaining:
        sh = send(make_hello(remaining))
        chosen = pick(sh) if sh else None
        if chosen is None or chosen not in remaining:
            break
        found.append(chosen)
        remaining.remove(chosen)
    return found


def scan_tls(target: str, timeout: float = 5.0) -> tuple[list[Finding], list[Note]]:
    host, port = parse_target(target, 443)
    label = f"{host}:{port}"
    findings: list[Finding] = []
    notes: list[Note] = []

    # Connect to one working address for the whole scan (SNI still uses the hostname).
    try:
        addr = pick_address(host, port, timeout)
    except OSError as exc:
        return [], [Note(label, f"Could not connect: {exc}", "error")]

    def send(hello: bytes) -> ServerHello | None:
        return probe(addr, port, hello, timeout)

    sni = None if is_ip(host) else host
    legacy_codes = list(LEGACY_SUITES)

    def guarded(step: str, fn: Callable[[], None]) -> None:
        """Servers and firewalls often time out or reset after many handshakes. Keep what we have."""
        try:
            fn()
        except (OSError, ValueError, struct.error) as exc:
            notes.append(Note(label, f"Scan interrupted during {step} ({type(exc).__name__}: {exc}). "
                                     "Results gathered so far are kept; re-run to complete them.", "warning"))

    def tls13_hello(groups: list[int], suites: list[int] | None = None) -> bytes:
        return build_client_hello(sni, version=0x0304, cipher_suites=suites or list(TLS13_SUITES),
                                  groups=groups, tls13=True)

    # 1. Protocol versions -----------------------------------------------------
    versions: list[int] = []
    probes = [(code, build_client_hello(sni, version=code, cipher_suites=legacy_codes + [SCSV], groups=CLASSIC_GROUPS))
              for code in (0x0300, 0x0301, 0x0302, 0x0303)] + [(0x0304, tls13_hello(ALL_GROUPS))]
    for i, (code, hello) in enumerate(probes):
        try:
            sh = send(hello)
        except OSError as exc:
            if i == 0:  # can't connect at all
                return [], [Note(label, f"Could not connect: {exc}", "error")]
            notes.append(Note(label, f"Could not test {TLS_VERSIONS[code]} ({type(exc).__name__}: {exc}).", "warning"))
            continue
        if sh and sh.version == code and (code == 0x0304 or not sh.is_hrr):
            versions.append(code)

    if not versions:
        return [], notes + [Note(label, "No TLS handshake succeeded. Is this a TLS port?", "error")]

    for code in versions:
        v = rate_tls_version(code)
        findings.append(Finding(label, "tls", "protocol", TLS_VERSIONS[code], v.rating, v.reason,
                                v.recommendation, v.nist,
                                details={"protocol": "tls", "version": TLS_VERSIONS[code].split()[1]}))

    # 2. TLS 1.3 key-exchange groups and cipher suites ---------------------------
    def tls13_details() -> None:
        groups = _enumerate(tls13_hello, ALL_GROUPS,
                            lambda s: s.selected_group if s.version == 0x0304 else None, send)
        for i, g in enumerate(groups):
            name, v = rate_tls_group(g)
            findings.append(Finding(label, "tls", "key-exchange", f"{name} (TLS 1.3)", v.rating, v.reason,
                                    v.recommendation, v.nist, v.algo,
                                    details={"code": f"0x{g:04x}", "server_preference": i + 1,
                                             "version": "1.3"}))
        if groups and not any(rate_tls_group(g)[1].rating in (Rating.HYBRID, Rating.QUANTUM_SAFE)
                              for g in groups):
            notes.append(Note(label, "TLS 1.3 is enabled but no post-quantum key exchange is offered.", "warning"))

        suites13 = _enumerate(lambda s: tls13_hello(ALL_GROUPS, s), list(TLS13_SUITES),
                              lambda s: s.cipher_suite if s.version == 0x0304 else None, send)
        for c in suites13:
            _add_suite(findings, label, c, TLS13_SUITES[c], "1.3")

    if 0x0304 in versions:
        guarded("TLS 1.3 group and cipher enumeration", tls13_details)

    # 3. TLS 1.2-and-below cipher suites, for EVERY older version the server allows ------
    # (a server may allow RC4 or EXPORT suites only on TLS 1.0). The highest version is
    # enumerated in full; lower versions only look for suites not already found.
    legacy_versions = sorted((v for v in versions if v < 0x0304), reverse=True)
    found_at: dict[int, int] = {}  # suite -> highest version it was accepted at

    def legacy_suites() -> None:
        for ver in legacy_versions:
            offer = [c for c in legacy_codes if c not in found_at]
            if not offer:
                break
            accepted = _enumerate(
                lambda s, v=ver: build_client_hello(sni, version=v, cipher_suites=s + [SCSV], groups=CLASSIC_GROUPS),
                offer, lambda s, v=ver: s.cipher_suite if s.version == v and not s.is_hrr else None, send)
            for c in accepted:
                found_at[c] = ver
                suffix = "" if ver == legacy_versions[0] else f" ({TLS_VERSIONS[ver]})"
                _add_suite(findings, label, c, LEGACY_SUITES[c], TLS_VERSIONS[ver].split()[1], suffix)

    def legacy_key_exchange() -> None:
        kexes: dict[str, list[int]] = {}
        for c in found_at:
            kexes.setdefault(split_tls12_suite(LEGACY_SUITES[c])[0], []).append(c)
        for kex, codes in kexes.items():
            ver = max(found_at[c] for c in codes)
            codes = [c for c in codes if found_at[c] == ver]
            details = {"suites": [LEGACY_SUITES[c] for c in codes], "version": TLS_VERSIONS[ver].split()[1]}
            # Read the ServerKeyExchange to learn the real curve / DH prime size behind ECDHE and DHE.
            exact = _tls12_key_exchange(addr, port, sni, ver, kex, codes, timeout) if kex in ("ECDHE", "DHE") else []
            if exact:
                for asset, v in exact:
                    findings.append(Finding(label, "tls", "key-exchange", f"{asset} ({TLS_VERSIONS[ver]})", v.rating,
                                            v.reason, v.recommendation, v.nist, v.algo, details=dict(details)))
                continue
            v = rate_tls12_kex(kex)
            asset = f"{v.algo.name if v.algo else kex} ({TLS_VERSIONS[ver]})"
            findings.append(Finding(label, "tls", "key-exchange", asset, v.rating, v.reason,
                                    v.recommendation, v.nist, v.algo, details=details))

    if legacy_versions:
        guarded("cipher-suite enumeration", legacy_suites)
        guarded("TLS 1.2 key-exchange analysis", legacy_key_exchange)

    # 4. Certificate --------------------------------------------------------------
    try:
        cert, trusted, why = fetch_certificate(host, port, timeout, connect_to=addr)
        f, n = analyze_certificate(cert, target=label, layer="tls")
        findings += f
        notes += n
        if not trusted:
            notes.append(Note(label, f"Certificate is not trusted by this machine: {why}", "warning"))
    except (OSError, ssl.SSLError, ValueError) as exc:
        notes.append(Note(label, f"Could not retrieve the certificate: {exc}", "warning"))

    return findings, notes


TLS12_CURVES = [0x001D, 0x0017, 0x0018, 0x0019, 0x001E]  # x25519, P-256, P-384, P-521, x448


def _tls12_key_exchange(host: str, port: int, sni: str | None, version: int, kex: str, codes: list[int],
                        timeout: float) -> list[tuple[str, Verdict]]:
    """ECDHE: every curve the server accepts in TLS 1.2. DHE: the size of its DH prime (Logjam check)."""
    note = " TLS 1.2 cannot negotiate post-quantum key exchange."

    def hello(groups: list[int]) -> bytes:
        return build_client_hello(sni, version=version, cipher_suites=codes + [SCSV], groups=groups)

    out: list[tuple[str, Verdict]] = []
    if kex == "ECDHE":
        remaining = list(TLS12_CURVES)
        while remaining:
            curve = ske_named_curve(probe_handshake(host, port, hello(remaining), timeout).get(HS_SERVER_KEY_EXCHANGE))
            if curve is None or curve not in remaining:
                break
            remaining.remove(curve)
            name, v = rate_tls_group(curve)
            out.append((name, replace(v, reason=v.reason + note, recommendation=REC_TLS13)))
    else:
        # Offer only EC groups so the server shows its own configured DH parameters (the Logjam-relevant ones).
        bits = ske_dh_bits(probe_handshake(host, port, hello(TLS12_CURVES), timeout).get(HS_SERVER_KEY_EXCHANGE))
        if bits:
            v = rate_public_key("DH", bits)
            if v.rating is Rating.CRITICAL:
                v = replace(v, reason=f"DHE with a {bits}-bit prime can be broken today (Logjam).",
                            recommendation="Use ECDHE, or DH parameters of at least 2048 bits (e.g. ffdhe2048+).")
            else:
                v = replace(v, reason=v.reason + note, recommendation=REC_TLS13)
            out.append((f"DHE-{bits}", v))
    return out


def _add_suite(findings: list[Finding], label: str, code: int, name: str, version: str, suffix: str = "") -> None:
    bulk = split_tls12_suite(name)[1] if "_WITH_" in name else name
    v = rate_bulk_cipher(name if "EXPORT" in name else bulk)  # "EXPORT" sits before _WITH_
    findings.append(Finding(label, "tls", "cipher", name + suffix, v.rating, v.reason, v.recommendation, v.nist, v.algo,
                            details={"code": f"0x{code:04x}", "version": version}))


def fetch_certificate(host: str, port: int, timeout: float, connect_to: str | None = None
                      ) -> tuple[x509.Certificate, bool, str]:
    """Return (leaf certificate, trusted by this machine?, reason if not trusted)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # qrisk: ignore (we inspect certs, not trust them)
    try:
        with warnings.catch_warnings():  # we deliberately allow old versions to see the cert
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1  # qrisk: ignore (must reach old servers)
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    sni = None if is_ip(host) else host
    with socket.create_connection((connect_to or host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            der = s.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)

    trusted, why = True, ""
    try:
        with socket.create_connection((connect_to or host, port), timeout=timeout) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as exc:
        trusted, why = False, exc.verify_message or str(exc)
    except (OSError, ssl.SSLError):
        pass  # can't tell (e.g. handshake needs algorithms our OpenSSL lacks)
    return cert, trusted, why
