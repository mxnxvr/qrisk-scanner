"""Layer 4: source code.

Regex rules find crypto API calls in Python, Java/Kotlin, JavaScript/TypeScript
and Go, and report the file and line. Patterns run on the whole file, so a call
split over several lines (``generate_private_key(\\n key_size=1024)``) still
matches, and key sizes and curves are read from the call's arguments.
"""

from __future__ import annotations

import ast
import functools
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from ..models import Algo, Finding, Note, Rating
from ..rules import (
    NIST_2035, NIST_NOW, Verdict, rate_bulk_cipher, rate_pqc, rate_public_key, rate_signature,
    NIST_FIPS203, NIST_FIPS204, NIST_FIPS205,
)

LANGUAGES = {
    ".py": "python",
    ".java": "java", ".kt": "java", ".scala": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript",
    ".go": "go",
}
SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", "vendor", "dist",
             "build", "target", ".next", "site-packages", ".mypy_cache", ".pytest_cache"}
MAX_FILE_SIZE = 2_000_000

REC_HASH = ("Use SHA-256 or SHA-3 for anything security-related. If this is only a non-security checksum, "
            "say so explicitly (Python: `hashlib.md5(data, usedforsecurity=False)`).")
REC_ECB = "ECB leaks patterns in the plaintext. Use an authenticated mode such as AES-GCM."
REC_CIPHER = "Replace with AES-256-GCM or ChaCha20-Poly1305."
REC_PQ_SIG = ("Plan migration to ML-DSA (FIPS 204). Put signing behind one interface so the algorithm "
              "can be swapped (crypto-agility).")
REC_PQ_KEX = ("Plan migration to hybrid ML-KEM key establishment (e.g. X25519 + ML-KEM-768, FIPS 203). "
              "Put key exchange behind one interface so it can be swapped.")
REC_TLS = "Require TLS 1.2 or newer and prefer TLS 1.3 (needed for post-quantum key exchange)."
REC_VERIFY = "Never disable certificate verification outside local tests. Fix the trust store instead."
REC_SECRET = "Remove the key from source control, rotate it, and load keys from a secrets manager."
REC_CREATECIPHER = "crypto.createCipher derives keys with MD5 and was removed in Node 22. Use createCipheriv with AES-256-GCM."

Hit = tuple[str, str, Verdict]  # (category, asset, verdict)
Handler = Callable[[re.Match, str], "Hit | None"]


@dataclass(frozen=True)
class CodeRule:
    id: str
    languages: frozenset[str]
    pattern: re.Pattern[str]
    handler: Handler


# --- verdict helpers -----------------------------------------------------------------

def _hash(name: str) -> Hit:
    return "hash", name, Verdict(Rating.CRITICAL, f"{name} is broken for security use (practical collisions).",
                                 REC_HASH, NIST_NOW, Algo(name, "hash", functions=("digest",)))


_CURVES = {
    "P256": ("secp256r1", 256), "P-256": ("secp256r1", 256), "SECP256R1": ("secp256r1", 256),
    "PRIME256V1": ("secp256r1", 256), "P384": ("secp384r1", 384), "P-384": ("secp384r1", 384),
    "SECP384R1": ("secp384r1", 384), "P521": ("secp521r1", 521), "P-521": ("secp521r1", 521),
    "SECP521R1": ("secp521r1", 521), "P224": ("secp224r1", 224), "P-224": ("secp224r1", 224),
    "SECP224R1": ("secp224r1", 224), "SECP256K1": ("secp256k1", 256), "SECP192R1": ("secp192r1", 192),
    "PRIME192V1": ("secp192r1", 192),
}


def _int(pattern: str, text: str) -> int | None:
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


# --- constant resolution ---------------------------------------------------------------
# Real code rarely writes `key_size=2048` inline; it uses `KEY_BITS = 2048` or a default
# argument. For Python we evaluate constants with the AST; for other languages a regex
# finds `NAME = 1234`, `const NAME = 1234`, `final int NAME = 1234;` or `name := 1234`.

_OPS = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
        ast.FloorDiv: lambda a, b: a // b, ast.Pow: lambda a, b: a ** b, ast.LShift: lambda a, b: a << b}


def _eval(node: ast.AST, env: dict[str, int]) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.Attribute):  # self.KEY_BITS, Config.KEY_BITS
        return env.get(node.attr)
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        a, b = _eval(node.left, env), _eval(node.right, env)
        if a is not None and b is not None and abs(b) < 100_000:
            return _OPS[type(node.op)](a, b)
    return None


@functools.lru_cache(maxsize=256)
def python_constants(text: str) -> dict[str, int] | None:
    """Integer constants, class attributes and argument defaults in a Python file (None if it doesn't parse)."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    env: dict[str, int] = {}
    for _ in range(3):  # a few passes so constants built from other constants resolve in any order
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args.args[-len(node.args.defaults):] if node.args.defaults else []
                pairs = list(zip(args, node.args.defaults)) + [
                    (a, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None]
                for arg, default in pairs:
                    v = _eval(default, env)
                    if v is not None:
                        env.setdefault(arg.arg, v)
                continue
            else:
                continue
            v = _eval(value, env)
            if v is None:
                continue
            for t in targets:
                name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
                if name:
                    env.setdefault(name, v)
    return env


def _python_curve(name: str, text: str) -> str | None:
    """Resolve a curve held in a variable, e.g. `CURVE = ec.SECP384R1()`, so a later key-generation
    call that passes CURVE is rated with the right curve."""
    m = re.search(rf"\b{re.escape(name)}\s*(?::\s*[\w.]+\s*)?=\s*ec\.(\w+)", text)
    return m.group(1) if m else None


def resolve_int(token: str | None, text: str) -> int | None:
    """Turn an argument (`2048`, `KEY_BITS`, `self.bits`, `Config.KEY_SIZE`) into an int, if possible."""
    if not token:
        return None
    token = token.strip()
    if token.isdigit():
        return int(token)
    name = token.split(".")[-1]
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return None
    consts = python_constants(text)
    if consts is not None and name in consts:
        return consts[name]
    m = re.search(rf"\b{re.escape(name)}\s*(?::\s*\w+\s*)?(?::=|=)\s*(\d{{3,5}})\b", text)
    return int(m.group(1)) if m else None


def _size_arg(args: str, text: str, keyword: str | None = None) -> int | None:
    """Key size from call arguments: a keyword (`key_size=...`) or else the last positional argument."""
    if keyword:
        m = re.search(rf"\b{keyword}\s*[=:]\s*([\w.]+)", args)
        if m:
            return resolve_int(m.group(1), text)
    parts = [p.strip() for p in args.split(",") if p.strip()]
    last = parts[-1] if parts else ""
    if "=" not in last and re.fullmatch(r"[\w.]+", last):
        return resolve_int(last, text)
    return None


def _first(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def _for_code(v: Verdict, rec: str) -> Verdict:
    """Swap certificate-oriented advice for code-oriented advice on quantum-vulnerable findings."""
    return replace(v, recommendation=rec) if v.rating is Rating.QUANTUM_VULNERABLE else v


def _unknown_size(name: str, primitive: str, rec: str) -> Verdict:
    return Verdict(Rating.QUANTUM_VULNERABLE,
                   f"{name} is broken by a quantum computer (key size not found in the code; check it).",
                   rec, NIST_2035, Algo(name, primitive))


def _pqc(name: str) -> Hit | None:
    n = name.upper().replace("_", "-")
    digits = re.search(r"(\d+)", n)
    d = digits.group(1) if digits else ""
    if n.startswith(("ML-KEM", "MLKEM", "KYBER")):
        lvl = {"512": 1, "768": 3, "1024": 5}.get(d, 3)
        return "key-exchange", f"ML-KEM-{d or '768'}", rate_pqc(f"ML-KEM-{d or '768'}", lvl, NIST_FIPS203, "kem")
    if n.startswith(("ML-DSA", "MLDSA", "DILITHIUM")):
        d = {"2": "44", "3": "65", "5": "87"}.get(d, d)
        lvl = {"44": 2, "65": 3, "87": 5}.get(d, 3)
        return "signature", f"ML-DSA-{d or '65'}", rate_pqc(f"ML-DSA-{d or '65'}", lvl, NIST_FIPS204, "signature")
    if n.startswith(("SLH-DSA", "SPHINCS")):
        return "signature", "SLH-DSA", rate_pqc("SLH-DSA", 1, NIST_FIPS205, "signature")
    if n.startswith(("FALCON", "FN-DSA")):
        return "signature", "FN-DSA (Falcon)", Verdict(
            Rating.QUANTUM_SAFE, "Falcon / FN-DSA is a NIST post-quantum signature (FIPS 206, in progress).",
            "No action needed.", "NIST FIPS 206 (draft)", Algo("FN-DSA", "signature", nist_qsl=1))
    return None


def _asym(name: str, size: int | None = None, curve: str | None = None) -> Hit | None:
    """Rate an asymmetric algorithm named in code (Java/JS algorithm strings, Python/Go APIs)."""
    pq = _pqc(name)
    if pq:
        return pq
    n = name.upper().replace("_", "-")
    if n in ("RSA", "RSA-PSS", "RSA-OAEP", "RSASSA-PKCS1-V1-5", "RSASSA-PSS"):
        v = rate_public_key("RSA", size) if size else _unknown_size("RSA", "pke", REC_PQ_SIG)
        return "public-key", v.algo.name if size else "RSA", _for_code(v, REC_PQ_SIG)
    if n in ("EC", "ECDSA", "ECDH"):
        c, bits = _CURVES.get((curve or "").upper().replace("_", ""), (None, None)) if curve else (None, None)
        if n == "ECDH":
            pretty = c or "curve not found"
            return "key-exchange", f"ECDH ({pretty})", Verdict(
                Rating.QUANTUM_VULNERABLE, "ECDH key agreement: recorded traffic can be decrypted by a future "
                "quantum computer.", REC_PQ_KEX, NIST_2035, Algo(f"ECDH-{c}" if c else "ECDH", "key-agree", curve=c))
        v = rate_public_key("EC", bits, c) if c else _unknown_size("ECDSA", "signature", REC_PQ_SIG)
        return "public-key", v.algo.name if c else "ECDSA", _for_code(v, REC_PQ_SIG)
    if n in ("ED25519", "EDDSA", "ED448"):
        v = rate_public_key("Ed448" if n == "ED448" else "Ed25519")
        return "public-key", v.algo.name, _for_code(v, REC_PQ_SIG)
    if n in ("X25519", "XDH", "X448"):
        v = rate_public_key("X448" if n == "X448" else "X25519")
        return "key-exchange", v.algo.name, _for_code(v, REC_PQ_KEX)
    if n == "DSA":
        v = rate_public_key("DSA", size)
        return "public-key", "DSA", v
    if n in ("DH", "DIFFIEHELLMAN"):
        v = rate_public_key("DH", size) if size else _unknown_size("DH", "key-agree", REC_PQ_KEX)
        return "key-exchange", v.algo.name if size else "DH", _for_code(v, REC_PQ_KEX)
    return None


def _cipher(name: str) -> Hit | None:
    u = name.upper().replace("-", "_").replace("/", "_")
    if u.startswith("RSA"):
        return _asym("RSA")
    if "ECB" in u or u == "AES":  # Java: Cipher.getInstance("AES") silently means AES/ECB
        why = "ECB mode leaks patterns in the plaintext." + (" `AES` alone defaults to ECB in Java." if u == "AES" else "")
        return "cipher", "AES-ECB", Verdict(Rating.CRITICAL, why, REC_ECB, NIST_NOW,
                                            Algo("AES-ECB", "block-cipher", mode="ecb"))
    if "DES" in u.replace("AES", ""):
        triple = "EDE" in u or "3DES" in u or "TRIPLE" in u
        label = "3DES" if triple else "DES"
        why = "3DES has a 64-bit block size (Sweet32) and is withdrawn by NIST." if triple else "DES uses a 56-bit key."
        return "cipher", label, Verdict(Rating.CRITICAL, why, REC_CIPHER, NIST_NOW, Algo(label, "block-cipher"))
    if u.startswith(("RC4", "ARC4", "ARCFOUR")):
        return "cipher", "RC4", Verdict(Rating.CRITICAL, "RC4 has practical plaintext-recovery attacks.",
                                        REC_CIPHER, NIST_NOW, Algo("RC4", "stream-cipher"))
    if u.startswith(("BF_", "BLOWFISH")) or u == "BF":
        return "cipher", "Blowfish", Verdict(Rating.CRITICAL, "Blowfish has a 64-bit block size.",
                                             REC_CIPHER, NIST_NOW, Algo("Blowfish", "block-cipher"))
    if "AES" in u and not re.search(r"AES_?(128|192|256)", u):
        mode = next((m for m in ("GCM", "CCM", "CBC", "CTR", "OFB", "CFB") if m in u), None)
        label = f"AES-{mode}" if mode else "AES"
        return "cipher", label, Verdict(
            Rating.QUANTUM_SAFE, "AES resists quantum attacks (use 256-bit keys for long-lived secrets).",
            "Acceptable. Use 256-bit keys for long-lived data (CNSA 2.0).", "Approved symmetric algorithm",
            Algo(label, "ae" if mode in ("GCM", "CCM") else "block-cipher", mode=mode.lower() if mode else None,
                 nist_qsl=1, functions=("encrypt", "decrypt")))
    v = rate_bulk_cipher(u)
    if v.algo and v.algo.primitive == "unknown":
        return None
    return "cipher", v.algo.name if v.algo else name, v


_TLS_NAMES = {"SSLV2": "SSL 2.0", "SSLV3": "SSL 3.0", "SSL": "SSL 3.0", "SSL30": "SSL 3.0", "TLSV1": "TLS 1.0",
              "TLS10": "TLS 1.0", "TLSV1.1": "TLS 1.1", "TLSV1_1": "TLS 1.1", "TLS11": "TLS 1.1"}


def _tls(raw: str) -> Hit:
    version = _TLS_NAMES.get(raw.upper(), raw)
    return "tls-config", f"{version} enabled in code", Verdict(
        Rating.CRITICAL, f"{version} is obsolete and has known attacks (RFC 8996).", REC_TLS,
        "Disallowed by NIST SP 800-52r2")


def _noverify(what: str) -> Hit:
    return "tls-config", what, Verdict(
        Rating.CRITICAL, "Certificate verification is disabled, so anyone on the network can intercept "
        "the connection.", REC_VERIFY, None)


# --- rules ------------------------------------------------------------------------------

PY, JAVA, JS, GO = frozenset({"python"}), frozenset({"java"}), frozenset({"javascript"}), frozenset({"go"})
ALL = PY | JAVA | JS | GO
_Q = r"""['"`]"""  # any quote


def _r(id_: str, langs: frozenset[str], pattern: str, handler: Handler) -> CodeRule:
    return CodeRule(id_, langs, re.compile(pattern), handler)


def _py_hash(name: str) -> Handler:
    def h(m: re.Match, _t: str) -> Hit | None:
        return None if re.search(r"usedforsecurity\s*=\s*False", m.group(0)) else _hash(name)
    return h


RULES: list[CodeRule] = [
    # Hashes
    _r("py-md5", PY, r"\bhashlib\.md5\s*\([^)]*\)|\bhashlib\.new\(\s*['\"]md5['\"][^)]*\)|\bMD5\.new\s*\(|\bhashes\.MD5\s*\(", _py_hash("MD5")),
    _r("py-sha1", PY, r"\bhashlib\.sha1\s*\([^)]*\)|\bhashlib\.new\(\s*['\"]sha1['\"][^)]*\)|\bSHA1?\.new\s*\(|\bhashes\.SHA1\s*\(", _py_hash("SHA-1")),
    _r("java-hash", JAVA, r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|DigestUtils\.(md5|sha1)\w*\(',
       lambda m, t: _hash("MD5" if "MD5" in m.group(0).upper() else "SHA-1")),
    _r("js-hash", JS, rf"create(?:Hash|Hmac)\(\s*{_Q}(md5|sha1){_Q}",
       lambda m, t: _hash("MD5" if m.group(1).lower() == "md5" else "SHA-1")),
    _r("go-hash", GO, r"\b(md5|sha1)\.(?:New|Sum)\s*\(", lambda m, t: _hash("MD5" if m.group(1) == "md5" else "SHA-1")),

    # Asymmetric key generation and use: Python
    _r("py-rsa-gen", PY, r"\brsa\.generate_private_key\s*\(([^)]*)\)",
       lambda m, t: _asym("RSA", _size_arg(m.group(1), t, "key_size"))),
    _r("py-rsa-gen2", PY, r"\bRSA\.generate\s*\(\s*(?:bits\s*=\s*)?([\w.]+)|\brsa\.newkeys\s*\(\s*([\w.]+)",
       lambda m, t: _asym("RSA", resolve_int(m.group(1) or m.group(2), t))),
    _r("py-ec-gen", PY, r"\bec\.generate_private_key\s*\(\s*(?:curve\s*=\s*)?([\w.]+)",
       lambda m, t: _asym("ECDSA", curve=m.group(1)[3:] if m.group(1).startswith("ec.") else _python_curve(m.group(1), t))),
    _r("py-ecc-gen", PY, r"\bECC\.generate\s*\(\s*curve\s*=\s*['\"]([\w-]+)['\"]", lambda m, t: _asym("ECDSA", curve=m.group(1))),
    _r("py-ecdh", PY, r"\bec\.ECDH\s*\(", lambda m, t: _asym("ECDH")),
    _r("py-ed", PY, r"\b(Ed25519|Ed448|X25519|X448)PrivateKey\.generate\s*\(", lambda m, t: _asym(m.group(1))),
    _r("py-dsa", PY, r"\bdsa\.generate_private_key\s*\(([^)]*)\)|\bDSA\.generate\s*\(\s*([\w.]+)",
       lambda m, t: _asym("DSA", _size_arg(m.group(1), t, "key_size") if m.group(1) is not None
                          else resolve_int(m.group(2), t))),
    _r("py-dh", PY, r"\bdh\.generate_parameters\s*\(([^)]*)\)",
       lambda m, t: _asym("DH", _size_arg(m.group(1), t, "key_size"))),
    _r("py-oqs", PY, r"\boqs\.(?:KeyEncapsulation|Signature)\(\s*['\"]([\w-]+)['\"]", lambda m, t: _pqc(m.group(1))),

    # Java / Kotlin (JCA)
    _r("java-keypair", JAVA, r'\b(KeyPairGenerator|KeyAgreement|KeyFactory)\.getInstance\(\s*"([\w-]+)"',
       lambda m, t: _asym("ECDH" if m.group(1) == "KeyAgreement" and m.group(2) == "ECDH" else m.group(2),
                          size=resolve_int(_first(r"\.initialize\(\s*([\w.]+)", t[m.end(): m.end() + 400]), t),
                          curve=(re.search(r'ECGenParameterSpec\(\s*"([\w-]+)"', t[m.end(): m.end() + 400])
                                 or [None, None])[1])),
    _r("java-signature", JAVA, r'\bSignature\.getInstance\(\s*"(\w+?)with(RSA|ECDSA|DSA)\w*"',
       lambda m, t: ("signature", f"{m.group(1)}with{m.group(2)}",
                     _for_code(rate_signature(m.group(0), m.group(1).replace("-", "").lower(), m.group(2)),
                               REC_PQ_SIG))),
    _r("java-pq-spec", JAVA, r"\b(?:MLKEM|MLDSA|Kyber|Dilithium)ParameterSpec\.(\w+)", lambda m, t: _pqc(m.group(1))),
    _r("java-cipher", JAVA, r'\bCipher\.getInstance\(\s*"([^"]+)"', lambda m, t: _cipher(m.group(1))),

    # JavaScript / TypeScript (Node crypto, WebCrypto, noble)
    _r("js-keypair", JS, rf"\bgenerateKeyPair(?:Sync)?\(\s*{_Q}([\w-]+){_Q}\s*(?:,\s*\{{([^}}]*)\}})?",
       lambda m, t: _asym(m.group(1), size=resolve_int(_first(r"modulusLength\s*:\s*([\w.]+)", m.group(2) or ""), t),
                          curve=(re.search(rf"namedCurve\s*:\s*{_Q}([\w-]+){_Q}", m.group(2) or "") or [None, None])[1])),
    _r("js-webcrypto", JS, rf"\bname\s*:\s*{_Q}(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDSA|ECDH|Ed25519|X25519){_Q}([^}}]*)",
       lambda m, t: _asym(m.group(1), size=resolve_int(_first(r"modulusLength\s*:\s*([\w.]+)", m.group(2)), t),
                          curve=(re.search(rf"namedCurve\s*:\s*{_Q}([\w-]+){_Q}", m.group(2)) or [None, None])[1])),
    _r("js-ecdh", JS, rf"\bcreateECDH\(\s*{_Q}([\w-]+){_Q}", lambda m, t: _asym("ECDH", curve=m.group(1))),
    _r("js-dh", JS, r"\bcreateDiffieHellman\(\s*([\w.]+)", lambda m, t: _asym("DH", resolve_int(m.group(1), t))),
    _r("js-cipheriv", JS, rf"\bcreate(?:Cipher|Decipher)iv\(\s*{_Q}([\w-]+){_Q}", lambda m, t: _cipher(m.group(1))),
    _r("js-createcipher", JS, r"\bcrypto\.create(?:Cipher|Decipher)\(", lambda m, t: ("cipher", "crypto.createCipher", Verdict(
        Rating.CRITICAL, "Deprecated API with MD5-based key derivation and no IV.", REC_CREATECIPHER, NIST_NOW,
        Algo("EVP_BytesToKey-MD5", "kdf")))),
    _r("js-noble-pq", JS, r"\b(ml_kem(?:512|768|1024)|ml_dsa(?:44|65|87)|slh_dsa_\w+)\b", lambda m, t: _pqc(m.group(1))),

    # Go
    _r("go-rsa", GO, r"\brsa\.GenerateKey\s*\(\s*[^,]+,\s*([\w.]+)", lambda m, t: _asym("RSA", resolve_int(m.group(1), t))),
    _r("go-rsa-use", GO, r"\brsa\.(?:EncryptPKCS1v15|EncryptOAEP|SignPKCS1v15|SignPSS)\s*\(", lambda m, t: _asym("RSA")),
    _r("go-ecdsa", GO, r"\becdsa\.GenerateKey\s*\(\s*elliptic\.(P\d+)\(", lambda m, t: _asym("ECDSA", curve=m.group(1))),
    _r("go-ecdh", GO, r"\becdh\.(P256|P384|P521|X25519)\(\)",
       lambda m, t: _asym("X25519") if m.group(1) == "X25519" else _asym("ECDH", curve=m.group(1))),
    _r("go-ed25519", GO, r"\bed25519\.GenerateKey\s*\(", lambda m, t: _asym("Ed25519")),
    _r("go-dsa", GO, r"\bdsa\.GenerateKey\s*\(", lambda m, t: _asym("DSA")),
    _r("go-mlkem", GO, r"\bmlkem\.(?:GenerateKey|NewEncapsulationKey|NewDecapsulationKey)(768|1024)\b",
       lambda m, t: _pqc(f"ML-KEM-{m.group(1)}")),
    _r("go-weak-cipher", GO, r"\b(des\.NewTripleDESCipher|des\.NewCipher|rc4\.NewCipher|blowfish\.NewCipher)\s*\(",
       lambda m, t: _cipher({"des.NewTripleDESCipher": "3DES", "des.NewCipher": "DES", "rc4.NewCipher": "RC4",
                             "blowfish.NewCipher": "Blowfish"}[m.group(1)])),
    _r("go-gcm", GO, r"\bcipher\.NewGCM\s*\(", lambda m, t: _cipher("AES/GCM")),
    _r("go-chacha", GO, r"\bchacha20poly1305\.New(?:X)?\s*\(", lambda m, t: _cipher("CHACHA20_POLY1305")),

    # Python symmetric ciphers
    _r("py-weak-cipher", PY, r"\b(DES3|DES|ARC4|Blowfish)\.new\s*\(|\balgorithms\.(TripleDES|ARC4|Blowfish|IDEA|CAST5)\s*\(",
       lambda m, t: _cipher({"DES3": "3DES", "TripleDES": "3DES", "ARC4": "RC4", "IDEA": "IDEA_CBC",
                             "CAST5": "CAST128"}.get(m.group(1) or m.group(2), m.group(1) or m.group(2)))),
    _r("py-mode", PY, r"\bmodes\.(ECB|GCM|CBC|CTR|OFB|CFB)\s*\(|\bAES\.MODE_(ECB|GCM|CBC|CTR|OFB|CFB|EAX|CCM)\b",
       lambda m, t: _cipher(f"AES/{m.group(1) or m.group(2)}")),
    _r("py-aead", PY, r"\b(AESGCM|AESCCM|ChaCha20Poly1305)\s*\(",
       lambda m, t: _cipher({"AESGCM": "AES/GCM", "AESCCM": "AES/CCM"}.get(m.group(1), "CHACHA20_POLY1305"))),

    # TLS configuration in code
    # Only flag configuration (assignments, constructor args), not libraries that merely name the constants.
    _r("py-tls-old", PY, r"(?:\bminimum_version\s*=\s*ssl\.TLSVersion\.|\bssl_version\s*=\s*ssl\.PROTOCOL_|"
                         r"\bSSLContext\(\s*(?:ssl\.)?PROTOCOL_)(SSLv2|SSLv3|TLSv1_1|TLSv1)\b",
       lambda m, t: _tls(m.group(1))),
    _r("py-noverify", PY, r"\bverify\s*=\s*False\b|(?<![=!<>])=\s*ssl\.CERT_NONE\b|\b_create_unverified_context\s*\(",
       lambda m, t: _noverify(m.group(0).lstrip("= ").strip())),
    _r("java-tls-old", JAVA, r'\bSSLContext\.getInstance\(\s*"(SSL|SSLv3|TLSv1|TLSv1\.1)"', lambda m, t: _tls(m.group(1))),
    _r("java-noverify", JAVA, r"\b(NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllStrategy)\b",
       lambda m, t: _noverify(m.group(1))),
    _r("js-noverify", JS, r"\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
       lambda m, t: _noverify(m.group(0).strip())),
    _r("js-tls-old", JS, rf"\b(?:minVersion|maxVersion)\s*:\s*{_Q}(TLSv1(?:\.1)?){_Q}|\bsecureProtocol\s*:\s*{_Q}(SSLv3|TLSv1|TLSv1_1)_method{_Q}",
       lambda m, t: _tls(m.group(1) or m.group(2))),
    _r("go-noverify", GO, r"\bInsecureSkipVerify\s*:\s*true\b", lambda m, t: _noverify("InsecureSkipVerify: true")),
    _r("go-tls-old", GO, r"\bMinVersion\s*:\s*tls\.Version(SSL30|TLS10|TLS11)\b",
       lambda m, t: _tls(m.group(1))),

    # Secrets
    _r("private-key-in-code", ALL, r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\\n|\s)+(?:Proc-Type|[A-Za-z0-9+/]{20,})",
       lambda m, t: ("secret", "Private key in source code", Verdict(
           Rating.CRITICAL, "A private key is committed to source code, so anyone with repository access has it.",
           REC_SECRET, None))),
]


# --- scanning ----------------------------------------------------------------------------

SUPPRESS = "qrisk: ignore"  # put this in a comment to silence findings on that line


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("#", "//", "/*", "* ", "*/")) or s == "*"


def scan_source(text: str, language: str) -> list[tuple[int, str, str, str, Verdict]]:
    """Return (line, rule id, category, asset, verdict) for every rule hit in ``text``."""
    lines = text.splitlines()
    hits: list[tuple[int, str, str, str, Verdict]] = []
    seen: set[tuple[int, str]] = set()
    for rule in RULES:
        if language not in rule.languages:
            continue
        for m in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            if line_no <= len(lines) and (_is_comment(lines[line_no - 1]) or SUPPRESS in lines[line_no - 1]):
                continue
            hit = rule.handler(m, text)
            if hit is None:
                continue
            category, asset, verdict = hit
            if (line_no, asset) in seen:
                continue
            seen.add((line_no, asset))
            hits.append((line_no, rule.id, category, asset, verdict))
    return sorted(hits, key=lambda h: h[0])


def scan_code(root: str | Path) -> tuple[list[Finding], list[Note]]:
    root = Path(root)
    target = f"code:{root}"
    if not root.exists():
        return [], [Note(target, f"Path not found: {root}", "error")]
    files = [root] if root.is_file() else sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in LANGUAGES and not p.name.endswith(".min.js")
        and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
    )
    findings: list[Finding] = []
    notes: list[Note] = []
    for path in files:
        rel = path.as_posix() if root.is_file() else (root / path.relative_to(root)).as_posix()
        try:
            too_big = path.stat().st_size > MAX_FILE_SIZE
        except OSError as exc:  # broken symlink, permission denied...
            notes.append(Note(rel, f"Could not read: {exc}", "warning"))
            continue
        if too_big:
            notes.append(Note(rel, "Skipped: file larger than 2 MB.", "warning"))
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            notes.append(Note(rel, f"Could not read: {exc}", "warning"))
            continue
        language = LANGUAGES[path.suffix.lower()]
        lines = text.splitlines()
        for line_no, rule_id, category, asset, v in scan_source(text, language):
            snippet = lines[line_no - 1].strip()[:160] if line_no <= len(lines) else ""
            findings.append(Finding(
                target=target, layer="code", category=category, asset=asset, rating=v.rating,
                reason=v.reason, recommendation=v.recommendation, nist=v.nist, algorithm=v.algo,
                location=f"{rel}:{line_no}",
                details={"file": rel, "line": line_no, "rule": rule_id, "language": language, "snippet": snippet},
            ))
    notes.append(Note(target, f"Scanned {len(files)} source file(s); {len(findings)} crypto finding(s).", "info"))
    return findings, notes
