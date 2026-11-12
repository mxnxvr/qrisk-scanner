"""The quantum-risk engine: turns an algorithm name into a rating, a reason,
a NIST deadline and a concrete recommendation.

Deadlines follow NIST IR 8547 ("Transition to Post-Quantum Cryptography
Standards"): quantum-vulnerable public-key algorithms at 112-bit classical
security (RSA-2048, P-224, ffdhe2048) are deprecated after 2030, and all
quantum-vulnerable public-key algorithms are disallowed after 2035.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Algo, Rating

# --- NIST deadline labels ---------------------------------------------------

NIST_2030 = "NIST IR 8547: deprecated after 2030, disallowed after 2035"
NIST_2035 = "NIST IR 8547: disallowed after 2035"
NIST_NOW = "Already disallowed by NIST"
NIST_FIPS203 = "NIST FIPS 203 (ML-KEM): approved"
NIST_FIPS204 = "NIST FIPS 204 (ML-DSA): approved"
NIST_FIPS205 = "NIST FIPS 205 (SLH-DSA): approved"
NIST_SYM = "Approved symmetric algorithm (no quantum deadline)"
# Static RSA is critical *now* (no forward secrecy), so it must not carry a future deadline.
NIST_RSA_KEX = "Removed in TLS 1.3 (RFC 8446); NIST SP 800-52r2 requires forward secrecy"

# --- Recommendations ----------------------------------------------------------

REC_NONE = "No action needed."
REC_TLS_HYBRID = (
    "Enable hybrid post-quantum key exchange with OpenSSL 3.5+: "
    "`Groups = X25519MLKEM768:X25519:secp256r1` "
    "(nginx: `ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;`)."
)
REC_TLS13 = (
    "Enable TLS 1.3 and prefer it: hybrid post-quantum key exchange (X25519MLKEM768) "
    "is only defined for TLS 1.3."
)
REC_TLS_OLD = "Disable SSL 3.0 / TLS 1.0 / TLS 1.1. Set the minimum to TLS 1.2 and prefer TLS 1.3."
REC_HYBRID_KEEP = (
    "Good transitional state. Offer it first and drop classical-only fallbacks once clients allow."
)
REC_KYBER_DRAFT = "Pre-standard Kyber draft: replace with the standard X25519MLKEM768 group."
REC_PQ_CERT = (
    "Add to your migration plan for ML-DSA (FIPS 204) certificates once your CA and clients "
    "support them. Keep certificate lifetimes short so you can rotate quickly."
)
REC_WEAK_KEY = "Replace now with RSA-3072+ or ECDSA P-256/P-384, then plan migration to ML-DSA."
REC_WEAK_SIG = "Re-issue the certificate with a SHA-256 (or stronger) signature."
REC_RSA_KEX = (
    "Disable static-RSA cipher suites (TLS_RSA_WITH_*): they lack forward secrecy, so recorded "
    "traffic can be decrypted later. Use ECDHE in TLS 1.2 and hybrid ML-KEM in TLS 1.3."
)
REC_WEAK_CIPHER = "Disable this cipher. Allow only AES-GCM and ChaCha20-Poly1305."
REC_AES128 = "Acceptable. Prefer AES-256 for long-lived secrets (CNSA 2.0 requires AES-256)."
REC_SSH_HYBRID = (
    "Enable `mlkem768x25519-sha256` (OpenSSH 9.9+, default in 10.0) or "
    "`sntrup761x25519-sha512` (OpenSSH 9.0+) and list it first in `KexAlgorithms`."
)
REC_SSH_REMOVE = "Remove it from sshd_config (`KexAlgorithms`, `HostKeyAlgorithms` or `Ciphers`)."
REC_SSH_HOSTKEY = (
    "No standard post-quantum SSH host key exists yet. Prefer ssh-ed25519, keep keys rotatable, "
    "and track OpenSSH's ML-DSA work."
)


@dataclass(frozen=True)
class Verdict:
    rating: Rating
    reason: str
    recommendation: str
    nist: str | None = None
    algo: Algo | None = None


# --- Public keys and signatures ------------------------------------------------

_CURVE_ALIASES = {
    "secp256r1": ("P-256", 128),
    "prime256v1": ("P-256", 128),
    "secp384r1": ("P-384", 192),
    "secp521r1": ("P-521", 256),
    "secp224r1": ("P-224", 112),
    "secp192r1": ("P-192", 96),
    "prime192v1": ("P-192", 96),
    "brainpoolP256r1": ("brainpoolP256r1", 128),
    "brainpoolP384r1": ("brainpoolP384r1", 192),
    "brainpoolP512r1": ("brainpoolP512r1", 256),
    "secp256k1": ("secp256k1", 128),
}

# OID -> (name, NIST quantum security level, FIPS label, primitive)
PQC_OIDS: dict[str, tuple[str, int, str, str]] = {
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", 2, NIST_FIPS204, "signature"),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", 3, NIST_FIPS204, "signature"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", 5, NIST_FIPS204, "signature"),
    "2.16.840.1.101.3.4.4.1": ("ML-KEM-512", 1, NIST_FIPS203, "kem"),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM-768", 3, NIST_FIPS203, "kem"),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM-1024", 5, NIST_FIPS203, "kem"),
}
for _i, _name in enumerate(
    [
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
    ]
):
    _lvl = {"128": 1, "192": 3, "256": 5}[_name.rsplit("-", 1)[1][:3]]
    PQC_OIDS[f"2.16.840.1.101.3.4.3.{20 + _i}"] = (_name, _lvl, NIST_FIPS205, "signature")


def _rsa_bits_to_security(bits: int) -> int:
    if bits >= 15360:
        return 256
    if bits >= 7680:
        return 192
    if bits >= 3072:
        return 128
    if bits >= 2048:
        return 112
    if bits >= 1024:
        return 80
    return 0


def rate_pqc(name: str, level: int, fips: str, primitive: str, oid: str | None = None) -> Verdict:
    funcs = ("sign", "verify") if primitive == "signature" else ("encapsulate", "decapsulate")
    algo = Algo(name, primitive, parameter_set=name.split("-", 2)[-1], nist_qsl=level,
                functions=funcs, oid=oid)
    return Verdict(Rating.QUANTUM_SAFE, f"{name} is a NIST post-quantum standard.", REC_NONE, fips, algo)


def rate_public_key(kind: str, bits: int | None = None, curve: str | None = None) -> Verdict:
    """Rate an asymmetric key. ``kind`` is RSA, EC, Ed25519, Ed448, DSA, DH, X25519, X448."""
    kind_u = kind.upper()
    if kind_u == "RSA":
        bits = bits or 0
        sec = _rsa_bits_to_security(bits)
        algo = Algo(f"RSA-{bits}", "pke", parameter_set=str(bits), classical_bits=sec,
                    functions=("sign", "verify", "encrypt", "decrypt"))
        if bits < 2048:
            return Verdict(Rating.CRITICAL,
                           f"RSA-{bits} gives under 112-bit security and can be broken with classical computers.",
                           REC_WEAK_KEY, NIST_NOW, algo)
        nist = NIST_2030 if sec == 112 else NIST_2035
        return Verdict(Rating.QUANTUM_VULNERABLE,
                       f"RSA-{bits} is safe today but Shor's algorithm breaks RSA on a quantum computer.",
                       REC_PQ_CERT, nist, algo)
    if kind_u in ("EC", "ECDSA"):
        pretty, sec = _CURVE_ALIASES.get(curve or "", (curve or f"EC-{bits}", (bits or 0) // 2))
        algo = Algo(f"ECDSA-{pretty}", "signature", curve=curve, classical_bits=sec,
                    functions=("sign", "verify"))
        if sec < 112:
            return Verdict(Rating.CRITICAL, f"ECDSA on {pretty} gives under 112-bit security.",
                           REC_WEAK_KEY, NIST_NOW, algo)
        return Verdict(Rating.QUANTUM_VULNERABLE,
                       f"ECDSA ({pretty}) is safe today but Shor's algorithm breaks elliptic curves.",
                       REC_PQ_CERT, NIST_2030 if sec == 112 else NIST_2035, algo)
    if kind_u in ("ED25519", "ED448"):
        name = "Ed25519" if kind_u == "ED25519" else "Ed448"
        algo = Algo(name, "signature", curve=name.replace("Ed", "Curve"),
                    classical_bits=128 if name == "Ed25519" else 224, functions=("sign", "verify"))
        return Verdict(Rating.QUANTUM_VULNERABLE,
                       f"{name} is safe today but Shor's algorithm breaks elliptic curves.",
                       REC_PQ_CERT, NIST_2035, algo)
    if kind_u in ("X25519", "X448"):
        algo = Algo(kind, "key-agree", curve=kind, classical_bits=128 if kind_u == "X25519" else 224,
                    functions=("keygen",))
        return Verdict(Rating.QUANTUM_VULNERABLE,
                       f"{kind} key agreement is broken by a quantum computer.",
                       REC_TLS_HYBRID, NIST_2035, algo)
    if kind_u == "DSA":
        algo = Algo(f"DSA-{bits}", "signature", parameter_set=str(bits), functions=("sign", "verify"))
        return Verdict(Rating.CRITICAL, "DSA is no longer approved for signing (FIPS 186-5).",
                       REC_WEAK_KEY, NIST_NOW, algo)
    if kind_u == "DH":
        sec = _rsa_bits_to_security(bits or 0)
        algo = Algo(f"DH-{bits}", "key-agree", parameter_set=str(bits), classical_bits=sec)
        if sec < 112:
            return Verdict(Rating.CRITICAL, f"DH-{bits} gives under 112-bit security.",
                           REC_WEAK_KEY, NIST_NOW, algo)
        return Verdict(Rating.QUANTUM_VULNERABLE, f"DH-{bits} is broken by a quantum computer.",
                       REC_TLS_HYBRID, NIST_2030 if sec == 112 else NIST_2035, algo)
    return Verdict(Rating.QUANTUM_VULNERABLE, f"Unrecognised key type {kind}. Review it manually.",
                   REC_PQ_CERT, None, Algo(kind, "unknown"))


_WEAK_HASHES = {"md2", "md4", "md5", "sha1"}


def rate_signature(sig_name: str, hash_name: str | None, key_kind: str | None) -> Verdict:
    """Rate the algorithm a certificate is signed with (issuer's signature)."""
    h = (hash_name or "").lower()
    pretty = f"{(key_kind or 'unknown').upper()}-{h.upper()}" if h else sig_name
    algo = Algo(pretty, "signature", functions=("sign", "verify"))
    if h in _WEAK_HASHES:
        return Verdict(Rating.CRITICAL,
                       f"Signed with {h.upper()}, which has practical collision attacks.",
                       REC_WEAK_SIG, NIST_NOW, algo)
    if (key_kind or "").upper() == "DSA":
        return Verdict(Rating.CRITICAL, "DSA signatures are no longer approved (FIPS 186-5).",
                       REC_WEAK_SIG, NIST_NOW, algo)
    return Verdict(Rating.QUANTUM_VULNERABLE,
                   f"{pretty} signatures can be forged by a quantum computer.",
                   REC_PQ_CERT, NIST_2035, algo)


# --- TLS ------------------------------------------------------------------------

TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def rate_tls_version(code: int) -> Verdict:
    name = TLS_VERSIONS.get(code, f"0x{code:04x}")
    if code < 0x0303:
        return Verdict(Rating.CRITICAL, f"{name} is obsolete and has known attacks (RFC 8996).",
                       REC_TLS_OLD, "Disallowed by NIST SP 800-52r2")
    if code == 0x0303:
        return Verdict(Rating.QUANTUM_VULNERABLE,
                       "TLS 1.2 is fine today, but it has no standard post-quantum key exchange.",
                       REC_TLS13, NIST_2035)
    return Verdict(Rating.QUANTUM_SAFE,
                   "TLS 1.3 supports hybrid post-quantum key exchange (check the key-exchange findings).",
                   REC_NONE, None)


# code -> (name, verdict)
def _group(name: str, rating: Rating, reason: str, rec: str, nist: str | None,
           qsl: int, classical: int | None, primitive: str = "key-agree") -> tuple[str, Verdict]:
    algo = Algo(name, primitive, classical_bits=classical, nist_qsl=qsl,
                functions=("keygen",) if primitive == "key-agree" else ("encapsulate", "decapsulate"))
    return name, Verdict(rating, reason, rec, nist, algo)


_QV = Rating.QUANTUM_VULNERABLE
_ECDH_REASON = "Classical elliptic-curve key exchange: recorded traffic can be decrypted later by a quantum computer (harvest now, decrypt later)."
_FFDH_REASON = "Classical finite-field Diffie-Hellman: broken by a quantum computer."

TLS_GROUPS: dict[int, tuple[str, Verdict]] = {
    0x11EC: _group("X25519MLKEM768", Rating.HYBRID,
                   "Hybrid X25519 + ML-KEM-768: stays secure if either part holds.",
                   REC_HYBRID_KEEP, NIST_FIPS203, 3, 128, "kem"),
    0x11EB: _group("SecP256r1MLKEM768", Rating.HYBRID,
                   "Hybrid P-256 + ML-KEM-768: stays secure if either part holds.",
                   REC_HYBRID_KEEP, NIST_FIPS203, 3, 128, "kem"),
    0x11ED: _group("SecP384r1MLKEM1024", Rating.HYBRID,
                   "Hybrid P-384 + ML-KEM-1024: stays secure if either part holds.",
                   REC_HYBRID_KEEP, NIST_FIPS203, 5, 192, "kem"),
    0x0200: _group("MLKEM512", Rating.QUANTUM_SAFE, "Pure ML-KEM-512 (FIPS 203).",
                   REC_NONE, NIST_FIPS203, 1, None, "kem"),
    0x0201: _group("MLKEM768", Rating.QUANTUM_SAFE, "Pure ML-KEM-768 (FIPS 203).",
                   REC_NONE, NIST_FIPS203, 3, None, "kem"),
    0x0202: _group("MLKEM1024", Rating.QUANTUM_SAFE, "Pure ML-KEM-1024 (FIPS 203).",
                   REC_NONE, NIST_FIPS203, 5, None, "kem"),
    0x6399: _group("X25519Kyber768Draft00", Rating.HYBRID,
                   "Hybrid using the pre-standard Kyber draft.",
                   REC_KYBER_DRAFT, "Pre-standard draft, superseded by FIPS 203", 0, 128, "kem"),
    0x001D: _group("x25519", _QV, _ECDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 128),
    0x001E: _group("x448", _QV, _ECDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 224),
    0x0017: _group("secp256r1", _QV, _ECDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 128),
    0x0018: _group("secp384r1", _QV, _ECDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 192),
    0x0019: _group("secp521r1", _QV, _ECDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 256),
    0x0100: _group("ffdhe2048", _QV, _FFDH_REASON, REC_TLS_HYBRID, NIST_2030, 0, 112),
    0x0101: _group("ffdhe3072", _QV, _FFDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 128),
    0x0102: _group("ffdhe4096", _QV, _FFDH_REASON, REC_TLS_HYBRID, NIST_2035, 0, 152),
}


def rate_tls_group(code: int) -> tuple[str, Verdict]:
    if code in TLS_GROUPS:
        return TLS_GROUPS[code]
    name = f"group-0x{code:04x}"
    return name, Verdict(_QV, "Unrecognised key-exchange group. Review it manually.",
                         REC_TLS_HYBRID, None, Algo(name, "key-agree"))


def rate_tls12_kex(kex: str) -> Verdict:
    """``kex`` is the key-exchange part of a TLS 1.2 suite name: ECDHE, DHE, RSA, ..."""
    if kex == "RSA":
        return Verdict(Rating.CRITICAL,
                       "Static RSA key exchange has no forward secrecy: a leaked or quantum-broken key "
                       "decrypts all recorded traffic.",
                       REC_RSA_KEX, NIST_RSA_KEX, Algo("RSA key transport", "pke", functions=("encrypt", "decrypt")))
    if kex in ("DH_anon", "ECDH_anon"):
        return Verdict(Rating.CRITICAL, "Anonymous key exchange has no authentication.",
                       REC_WEAK_CIPHER, NIST_NOW, Algo(kex, "key-agree"))
    if kex == "DHE":
        return Verdict(_QV, f"{_FFDH_REASON} TLS 1.2 cannot negotiate post-quantum key exchange.",
                       REC_TLS13, NIST_2030, Algo("DHE", "key-agree", functions=("keygen",)))
    return Verdict(_QV, f"{_ECDH_REASON} TLS 1.2 cannot negotiate post-quantum key exchange.",
                   REC_TLS13, NIST_2035, Algo("ECDHE", "key-agree", functions=("keygen",)))


def rate_bulk_cipher(text: str) -> Verdict:
    """Rate the symmetric part of a TLS suite or an SSH cipher name."""
    t = text.upper().replace("-", "_")
    for bad, why in (
        ("NULL", "NULL cipher: no encryption at all."),
        ("EXPORT", "Export-grade cipher: deliberately weakened."),
        ("RC4", "RC4 has practical plaintext-recovery attacks (RFC 7465)."),
        ("ARCFOUR", "RC4 has practical plaintext-recovery attacks (RFC 7465)."),
        ("3DES", "3DES has a 64-bit block size (Sweet32)."),
        ("DES_CBC", "Single DES uses a 56-bit key and is brute-forceable."),
        ("BLOWFISH", "Blowfish has a 64-bit block size."),
        ("CAST128", "CAST-128 has a 64-bit block size."),
        ("IDEA", "IDEA is obsolete."),
        ("_MD5", "MD5-based integrity is broken."),
    ):
        if bad in t:
            return Verdict(Rating.CRITICAL, why, REC_WEAK_CIPHER, NIST_NOW, Algo(bad.strip("_"), "block-cipher"))
    if "RC2" in t:
        return Verdict(Rating.CRITICAL, "RC2 is obsolete and weak.", REC_WEAK_CIPHER, NIST_NOW, Algo("RC2", "block-cipher"))
    for other in ("CAMELLIA", "ARIA", "SEED"):
        if other in t:
            size = 256 if "256" in t else 128
            name = f"{other.title()}-{size}" if other != "SEED" else "SEED"
            return Verdict(Rating.QUANTUM_SAFE,
                           f"{name} is a sound {size}-bit cipher, but it is not NIST-approved.",
                           "Prefer AES-GCM or ChaCha20-Poly1305 (NIST-approved, hardware-accelerated).", None,
                           Algo(name, "block-cipher", classical_bits=size, nist_qsl=5 if size == 256 else 1,
                                functions=("encrypt", "decrypt")))
    if "CHACHA20" in t:
        return Verdict(Rating.QUANTUM_SAFE, "ChaCha20-Poly1305 with a 256-bit key resists quantum attacks.",
                       REC_NONE, NIST_SYM,
                       Algo("ChaCha20-Poly1305", "ae", classical_bits=256, nist_qsl=5,
                            functions=("encrypt", "decrypt")))
    size = 256 if "AES_256" in t or "AES256" in t else 192 if "AES192" in t or "AES_192" in t else 128 if "AES" in t else None
    if size:
        mode = "gcm" if "GCM" in t else "ccm" if "CCM" in t else "ctr" if "CTR" in t else "cbc" if "CBC" in t else None
        name = f"AES-{size}" + (f"-{mode.upper()}" if mode else "")
        primitive = "ae" if mode in ("gcm", "ccm") else "block-cipher"
        algo = Algo(name, primitive, parameter_set=str(size), mode=mode, classical_bits=size,
                    nist_qsl={128: 1, 192: 3, 256: 5}[size], functions=("encrypt", "decrypt"))
        if mode == "cbc" and "SSH" in t:
            return Verdict(Rating.CRITICAL, "CBC mode in SSH allows plaintext recovery (CVE-2008-5161).",
                           REC_SSH_REMOVE, NIST_SYM, algo)
        if size == 128:
            return Verdict(Rating.QUANTUM_SAFE,
                           "AES-128 keeps about 64-bit security against Grover's algorithm, which NIST still accepts.",
                           REC_AES128, NIST_SYM, algo)
        return Verdict(Rating.QUANTUM_SAFE, f"AES-{size} resists quantum attacks.", REC_NONE, NIST_SYM, algo)
    return Verdict(_QV, f"Unrecognised cipher {text}. Review it manually.", REC_WEAK_CIPHER, None,
                   Algo(text, "unknown"))


def split_tls12_suite(name: str) -> tuple[str, str]:
    """``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`` -> ("ECDHE", "AES_128_GCM_SHA256")."""
    body = name.removeprefix("TLS_")
    if "_WITH_" not in body:
        return "", body
    kex_auth, bulk = body.split("_WITH_", 1)
    kex = kex_auth.split("_")[0]
    if kex_auth.endswith("_anon"):
        kex = kex_auth
    return kex, bulk


# --- SSH ------------------------------------------------------------------------

def rate_ssh_kex(name: str) -> Verdict:
    n = name.lower()
    algo = Algo(name, "kem" if ("mlkem" in n or "sntrup" in n) else "key-agree")
    if n.startswith("mlkem") or n.startswith("sntrup761x25519"):
        nist = NIST_FIPS203 if n.startswith("mlkem") else "Streamlined NTRU Prime (not a NIST standard)"
        rec = REC_HYBRID_KEEP if n.startswith("mlkem") else "Good. Prefer mlkem768x25519-sha256 where available (FIPS 203)."
        return Verdict(Rating.HYBRID, "Hybrid post-quantum key exchange.", rec, nist, algo)
    if "sha1" in n or "group1-" in n:
        return Verdict(Rating.CRITICAL, "Uses SHA-1 or a 1024-bit group, which is weak today.",
                       REC_SSH_REMOVE, NIST_NOW, algo)
    if "group14" in n or n == "diffie-hellman-group-exchange-sha256":
        return Verdict(_QV, "Classical Diffie-Hellman (2048-bit or negotiated) is broken by a quantum computer.",
                       REC_SSH_HYBRID, NIST_2030, algo)
    if n.startswith(("curve25519", "curve448", "ecdh-sha2", "diffie-hellman")):
        return Verdict(_QV, "Classical key exchange: recorded sessions can be decrypted later by a quantum computer.",
                       REC_SSH_HYBRID, NIST_2035, algo)
    return Verdict(_QV, "Unrecognised key exchange. Review it manually.", REC_SSH_HYBRID, None, algo)


def rate_ssh_hostkey(name: str) -> Verdict:
    base = name.lower().replace("-cert-v01@openssh.com", "")
    algo = Algo(name, "signature", functions=("sign", "verify"))
    if base in ("ssh-rsa",):
        return Verdict(Rating.CRITICAL, "ssh-rsa signs with SHA-1 (disabled by default since OpenSSH 8.8).",
                       REC_SSH_REMOVE, NIST_NOW, algo)
    if base in ("ssh-dss",):
        return Verdict(Rating.CRITICAL, "DSA host keys are 1024-bit and deprecated.", REC_SSH_REMOVE, NIST_NOW, algo)
    if "mldsa" in base or "ml-dsa" in base:
        return Verdict(Rating.QUANTUM_SAFE, "ML-DSA post-quantum signature.", REC_NONE, NIST_FIPS204, algo)
    if base.startswith(("rsa-sha2", "ssh-ed25519", "ecdsa-sha2", "sk-", "ssh-ed448")):
        return Verdict(_QV, "Classical host-key signature: forgeable by a quantum computer.",
                       REC_SSH_HOSTKEY, NIST_2035, algo)
    return Verdict(_QV, "Unrecognised host-key algorithm. Review it manually.", REC_SSH_HOSTKEY, None, algo)


REC_SSH_MAC = ("Use `hmac-sha2-256-etm@openssh.com` / `hmac-sha2-512-etm@openssh.com` and remove this MAC "
               "from `MACs` in sshd_config.")


def rate_ssh_mac(name: str) -> Verdict:
    """Shared by the live SSH scan and the sshd_config audit, so the two can't disagree."""
    n = name.lower()
    algo = Algo(name, "mac", functions=("tag",))
    if "md5" in n or "ripemd" in n:
        return Verdict(Rating.CRITICAL, "MD5/RIPEMD-based MACs are obsolete.", REC_SSH_MAC, NIST_NOW, algo)
    if "-96" in n or n.startswith("umac-64"):
        return Verdict(Rating.CRITICAL, "Truncated MAC tag (96 or 64 bits) gives too little forgery resistance.",
                       REC_SSH_MAC, NIST_NOW, algo)
    if "sha1" in n:
        return Verdict(Rating.QUANTUM_SAFE, "HMAC-SHA1 is still secure as a MAC, but SHA-1 is being phased out.",
                       "Prefer `hmac-sha2-256-etm@openssh.com`.", NIST_SYM, algo)
    if "sha2" in n or n.startswith("umac-128"):
        return Verdict(Rating.QUANTUM_SAFE, "Strong MAC.", REC_NONE, NIST_SYM, algo)
    return Verdict(Rating.QUANTUM_VULNERABLE, "Unrecognised MAC. Review it manually.", REC_SSH_MAC, None, algo)


def rate_ssh_cipher(name: str) -> Verdict:
    return rate_bulk_cipher("SSH_" + name)
