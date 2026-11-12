"""Layer 2: certificates and key files on disk (also used for TLS server certs)."""

from __future__ import annotations

import base64
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import pkcs12

from ..models import CertInfo, Finding, Note, Rating
from ..rules import PQC_OIDS, Verdict, rate_pqc, rate_public_key, rate_signature

SCAN_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".jks", ".jceks", ".keystore",
                   ".truststore", ".pub", ".csr"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox"}
MAX_FILE_SIZE = 1_000_000
_PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


# --- key and certificate analysis -----------------------------------------------

def key_verdict(key: Any) -> tuple[Verdict, int | None]:
    """Rate a ``cryptography`` public or private key object. Returns (verdict, key size)."""
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return rate_public_key("RSA", key.key_size), key.key_size
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return rate_public_key("EC", key.key_size, key.curve.name), key.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return rate_public_key("Ed25519"), 256
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return rate_public_key("Ed448"), 456
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return rate_public_key("X25519"), 256
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return rate_public_key("X448"), 448
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return rate_public_key("DSA", key.key_size), key.key_size
    if isinstance(key, (dh.DHPublicKey, dh.DHPrivateKey)):
        return rate_public_key("DH", key.key_size), key.key_size
    return rate_public_key(type(key).__name__), None


def analyze_certificate(
    cert: x509.Certificate, *, target: str, layer: str, location: str | None = None
) -> tuple[list[Finding], list[Note]]:
    findings: list[Finding] = []
    notes: list[Note] = []
    where = location or target

    # Subject public key (cryptography can't load PQC keys yet, so fall back to the OID).
    key_oid = cert.public_key_algorithm_oid.dotted_string
    if key_oid in PQC_OIDS:
        key_v, key_size = rate_pqc(*PQC_OIDS[key_oid], oid=key_oid), None
    else:
        try:
            key_v, key_size = key_verdict(cert.public_key())
        except (UnsupportedAlgorithm, ValueError):
            key_v, key_size = rate_public_key(f"OID {key_oid}"), None

    # Signature the issuer put on the certificate.
    sig_oid = cert.signature_algorithm_oid.dotted_string
    if sig_oid in PQC_OIDS:
        sig_v = rate_pqc(*PQC_OIDS[sig_oid], oid=sig_oid)
    else:
        try:
            hash_name = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        except UnsupportedAlgorithm:
            hash_name = None
        sig_name = getattr(cert.signature_algorithm_oid, "_name", sig_oid)
        kind = "ECDSA" if "ecdsa" in sig_name.lower() else "RSA" if "rsa" in sig_name.lower() else \
            "DSA" if "dsa" in sig_name.lower() else sig_name
        sig_v = rate_signature(sig_name, hash_name, kind)

    subject = cert.subject.rfc4514_string() or "(empty subject)"
    info = CertInfo(
        subject=subject,
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        serial=format(cert.serial_number, "x"),
        key_algo=key_v.algo,
        key_size=key_size,
        sig_algo=sig_v.algo,
        self_signed=cert.subject == cert.issuer,
    )
    cn = _common_name(cert) or subject
    key_name = key_v.algo.name if key_v.algo else "unknown key"

    findings.append(Finding(
        target=target, layer=layer, category="certificate-key",
        asset=f"{key_name} certificate ({cn})", rating=key_v.rating, reason=key_v.reason,
        recommendation=key_v.recommendation, nist=key_v.nist, algorithm=key_v.algo,
        location=location, cert=info,
    ))
    findings.append(Finding(
        target=target, layer=layer, category="certificate-signature",
        asset=f"{sig_v.algo.name if sig_v.algo else sig_oid} signature ({cn})", rating=sig_v.rating,
        reason=sig_v.reason, recommendation=sig_v.recommendation, nist=sig_v.nist,
        algorithm=sig_v.algo, location=location, details={"certificate_sha256": info.sha256},
    ))

    now = datetime.now(timezone.utc)
    if info.not_after < now:
        findings.append(Finding(
            target=target, layer=layer, category="certificate-validity",
            asset=f"Expired certificate ({cn})", rating=Rating.CRITICAL,
            reason=f"Expired on {info.not_after:%Y-%m-%d}.",
            recommendation="Renew the certificate now.", location=location,
            details={"certificate_sha256": info.sha256},
        ))
    elif info.days_left < 30:
        notes.append(Note(where, f"Certificate '{cn}' expires in {info.days_left} days.", "warning"))
    if info.not_before > now:
        notes.append(Note(where, f"Certificate '{cn}' is not valid until {info.not_before:%Y-%m-%d}.", "warning"))
    return findings, notes


def _common_name(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _key_finding(key: Any, *, target: str, location: str, private: bool, extra: str = "") -> Finding:
    v, size = key_verdict(key)
    name = v.algo.name if v.algo else "unknown"
    kind = "private key" if private else "public key"
    return Finding(
        target=target, layer="file", category="private-key" if private else "public-key",
        asset=f"{name} {kind}{extra}", rating=v.rating, reason=v.reason,
        recommendation=v.recommendation, nist=v.nist, algorithm=v.algo, location=location,
        details={"key_size": size},
    )


_NIST_ALG_ARC = bytes.fromhex("060960864801650304")  # DER OID header for 2.16.840.1.101.3.4.x.y


def pqc_oid_in(der: bytes) -> str | None:
    """Find a NIST post-quantum algorithm OID (ML-DSA, ML-KEM, SLH-DSA) in a PKCS#8 / SPKI structure."""
    i = der.find(_NIST_ALG_ARC)
    if i < 0 or i + 11 > len(der):
        return None
    oid = f"2.16.840.1.101.3.4.{der[i + 9]}.{der[i + 10]}"
    return oid if oid in PQC_OIDS else None


def _pqc_key_finding(pem_body: bytes, *, target: str, location: str, private: bool) -> Finding | None:
    try:
        der = base64.b64decode(b"".join(pem_body.split()), validate=False)
    except ValueError:
        return None
    oid = pqc_oid_in(der[:64])  # the algorithm identifier sits right at the start
    if oid is None:
        return None
    v = rate_pqc(*PQC_OIDS[oid], oid=oid)
    kind = "private key" if private else "public key"
    return Finding(target=target, layer="file", category="private-key" if private else "public-key",
                   asset=f"{v.algo.name if v.algo else oid} {kind}", rating=v.rating, reason=v.reason,
                   recommendation=v.recommendation, nist=v.nist, algorithm=v.algo, location=location,
                   details={"oid": oid})


# --- file scanning ----------------------------------------------------------------

def scan_path(root: str | Path) -> tuple[list[Finding], list[Note]]:
    """Scan a file or a directory tree for certificates and keys."""
    root = Path(root)
    target = f"path:{root}"
    findings: list[Finding] = []
    notes: list[Note] = []
    if not root.exists():
        return [], [Note(target, f"Path not found: {root}", "error")]

    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in SCAN_EXTENSIONS
        and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
    )
    for path in files:
        rel = path.as_posix() if root.is_file() else (root / path.relative_to(root)).as_posix()
        try:
            too_big = path.stat().st_size > MAX_FILE_SIZE
        except OSError as exc:  # broken symlink, permission denied...
            notes.append(Note(rel, f"Could not read: {exc}", "warning"))
            continue
        if too_big:
            notes.append(Note(rel, "Skipped: file larger than 1 MB.", "warning"))
            continue
        try:
            f, n = scan_file(path, target=target, location=rel)
        except Exception as exc:  # one bad file must not stop the scan
            f, n = [], [Note(rel, f"Could not parse: {exc}", "warning")]
        findings += f
        notes += n
    if not files:
        notes.append(Note(target, "No certificate or key files found.", "info"))
    return findings, notes


JKS_MAGIC, JCEKS_MAGIC = bytes.fromhex("feedfeed"), bytes.fromhex("cececece")


def parse_java_keystore(data: bytes) -> tuple[str, list[tuple[str, str, list[bytes]]]]:
    """Parse a JKS / JCEKS keystore without its password.

    Certificates in these formats are stored in clear text; only private and secret keys are
    encrypted. Returns (format, [(entry kind, alias, [certificate DER, ...])]).
    """
    fmt = "JKS" if data[:4] == JKS_MAGIC else "JCEKS"
    version, count = struct.unpack("!II", data[4:12])
    p = 12

    def u4() -> int:
        nonlocal p
        (v,) = struct.unpack("!I", data[p:p + 4])
        p += 4
        return v

    def utf() -> str:
        nonlocal p
        (n,) = struct.unpack("!H", data[p:p + 2])
        p += 2 + n
        return data[p - n:p].decode("utf-8", "replace")

    def cert() -> bytes:
        nonlocal p
        if version == 2:
            utf()  # certificate type, "X.509"
        n = u4()
        p += n
        return data[p - n:p]

    entries: list[tuple[str, str, list[bytes]]] = []
    for _ in range(min(count, 10_000)):
        tag = u4()
        alias = utf()
        p += 8  # timestamp
        if tag == 1:  # private key + certificate chain
            key_len = u4()  # (not `p += u4()`: that reads p before u4() advances it)
            p += key_len  # skip the encrypted key
            chain = [cert() for _ in range(u4())]
            entries.append(("private-key", alias, chain))
        elif tag == 2:  # trusted certificate
            entries.append(("trusted-cert", alias, [cert()]))
        else:  # 3 = JCEKS secret key, a serialized Java object we can't skip reliably
            entries.append(("secret-key", alias, []))
            break
    return fmt, entries


def _scan_java_keystore(data: bytes, *, target: str, location: str) -> tuple[list[Finding], list[Note]]:
    findings: list[Finding] = []
    notes: list[Note] = []
    try:
        fmt, entries = parse_java_keystore(data)
    except (struct.error, IndexError) as exc:
        return [], [Note(location, f"Could not parse Java keystore: {exc}", "warning")]
    why = ("JKS protects private keys with a weak, proprietary SHA-1-based scheme." if fmt == "JKS"
           else "JCEKS protects keys with PBEWithMD5AndTripleDES (MD5 and 3DES).")
    findings.append(Finding(
        target=target, layer="file", category="keystore", asset=f"{fmt} keystore format", rating=Rating.CRITICAL,
        reason=why, recommendation=f"Convert to PKCS#12: keytool -importkeystore -srckeystore {Path(location).name} "
                                   "-destkeystore keystore.p12 -deststoretype PKCS12",
        nist=None, location=location, details={"entries": len(entries)}))
    for kind, alias, chain in entries:
        for i, der in enumerate(chain):
            try:
                cert = x509.load_der_x509_certificate(der)
            except ValueError as exc:
                notes.append(Note(location, f"Entry '{alias}': unreadable certificate ({exc}).", "warning"))
                continue
            f, n = analyze_certificate(cert, target=target, layer="file", location=location)
            for finding in f:
                finding.details.update({"keystore_alias": alias, "keystore_entry": kind if i == 0 else "chain"})
            findings += f
            notes += n
        if kind == "secret-key":
            notes.append(Note(location, f"Entry '{alias}' is a secret key (JCEKS); remaining entries were not read.",
                              "info"))
    notes.append(Note(location, f"{fmt} keystore: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} read "
                      "without the password (certificates are not encrypted in this format).", "info"))
    return findings, notes


def scan_file(path: Path, *, target: str, location: str) -> tuple[list[Finding], list[Note]]:
    data = path.read_bytes()
    suffix = path.suffix.lower()
    findings: list[Finding] = []
    notes: list[Note] = []

    def add_cert(cert: x509.Certificate) -> None:
        f, n = analyze_certificate(cert, target=target, layer="file", location=location)
        findings.extend(f)
        notes.extend(n)

    if data[:4] in (JKS_MAGIC, JCEKS_MAGIC):
        return _scan_java_keystore(data, target=target, location=location)
    if suffix in (".jks", ".jceks", ".keystore", ".truststore"):
        suffix = ".p12"  # Java 9+ writes PKCS#12 by default, whatever the file is called

    if suffix in (".p12", ".pfx"):
        for password in (None, b"", b"changeit"):
            try:
                key, cert, extra = pkcs12.load_key_and_certificates(data, password)
                break
            except (ValueError, TypeError):
                continue
        else:
            notes.append(Note(location, "PKCS#12 file is password-protected, so its contents were not inspected.", "warning"))
            return findings, notes
        if password:
            notes.append(Note(location, f"PKCS#12 file opens with a default password ({password.decode()!r}).", "warning"))
        if key is not None:
            findings.append(_key_finding(key, target=target, location=location, private=True))
        for c in [cert, *extra]:
            if c is not None:
                add_cert(c)
        return findings, notes

    if suffix == ".pub" and data.lstrip().startswith((b"ssh-", b"ecdsa-", b"sk-")):
        key = serialization.load_ssh_public_key(data.strip().split(b"\n")[0])
        findings.append(_key_finding(key, target=target, location=location, private=False))
        return findings, notes

    blocks = _PEM_RE.findall(data)
    if blocks:
        for label_b, body in blocks:
            label = label_b.decode()
            pem = b"-----BEGIN " + label_b + b"-----" + body + b"-----END " + label_b + b"-----\n"
            if label in ("CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE"):
                add_cert(x509.load_pem_x509_certificate(pem.replace(b"TRUSTED ", b"").replace(b"X509 ", b"")))
            elif label in ("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"):
                csr = x509.load_pem_x509_csr(pem.replace(b"NEW ", b""))
                findings.append(_key_finding(csr.public_key(), target=target, location=location,
                                             private=False, extra=" (CSR)"))
            elif label == "ENCRYPTED PRIVATE KEY" or b"ENCRYPTED" in body[:120]:
                notes.append(Note(location, "Encrypted private key: algorithm not inspected.", "info"))
            elif label == "OPENSSH PRIVATE KEY":
                try:
                    key = serialization.load_ssh_private_key(pem, None)
                    findings.append(_key_finding(key, target=target, location=location, private=True))
                except (TypeError, ValueError):
                    notes.append(Note(location, "Encrypted OpenSSH private key: algorithm not inspected.", "info"))
            elif label.endswith("PRIVATE KEY") or label.endswith("PUBLIC KEY"):
                private = label.endswith("PRIVATE KEY")
                try:
                    key = serialization.load_pem_private_key(pem, None) if private else serialization.load_pem_public_key(pem)
                except (ValueError, UnsupportedAlgorithm):
                    # cryptography can't load ML-DSA / ML-KEM / SLH-DSA keys yet: identify them by algorithm OID.
                    pq = _pqc_key_finding(body, target=target, location=location, private=private)
                    if pq is None:
                        raise
                    findings.append(pq)
                    continue
                findings.append(_key_finding(key, target=target, location=location, private=private))
            elif label == "DH PARAMETERS":
                params = serialization.load_pem_parameters(pem)
                v = rate_public_key("DH", params.parameter_numbers().p.bit_length())
                findings.append(Finding(target=target, layer="file", category="key-exchange",
                                        asset=f"{v.algo.name} parameters", rating=v.rating, reason=v.reason,
                                        recommendation=v.recommendation, nist=v.nist, algorithm=v.algo,
                                        location=location))
        return findings, notes

    # DER: try certificate, then private key, then public key.
    for loader, kind in (
        (x509.load_der_x509_certificate, "cert"),
        (lambda d: serialization.load_der_private_key(d, None), "private"),
        (serialization.load_der_public_key, "public"),
    ):
        try:
            obj = loader(data)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
        if kind == "cert":
            add_cert(obj)
        else:
            findings.append(_key_finding(obj, target=target, location=location, private=kind == "private"))
        return findings, notes

    notes.append(Note(location, "Not a recognised certificate or key format.", "info"))
    return findings, notes

