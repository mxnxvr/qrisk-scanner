import json
import textwrap

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from qrisk.models import Rating
from qrisk.reports.cbom import build_cbom
from qrisk.scan import run_scan
from qrisk.scanners.code import scan_code, scan_source

PYTHON = '''\
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

digest = hashlib.md5(data).hexdigest()
etag = hashlib.md5(data, usedforsecurity=False).hexdigest()
# hashlib.sha1(b"commented out")
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
)
strong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
signer = ec.generate_private_key(ec.SECP384R1())
cipher = Cipher(algorithms.AES(k), modes.ECB())
box = AESGCM(k)
requests.get(url, verify=False)
ctx.verify_mode = ssl.CERT_NONE
if ctx.verify_mode == ssl.CERT_NONE: pass
ctx.minimum_version = ssl.TLSVersion.TLSv1_1
legacy = hashlib.sha1(x)  # qrisk: ignore
'''

JAVA = '''\
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
Cipher c = Cipher.getInstance("AES");
Cipher g = Cipher.getInstance("AES/GCM/NoPadding");
Cipher d = Cipher.getInstance("DESede/CBC/PKCS5Padding");
Signature s = Signature.getInstance("SHA1withRSA");
MessageDigest md = MessageDigest.getInstance("SHA-256");
KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM-768");
SSLContext ctx = SSLContext.getInstance("TLSv1");
'''

JS = '''\
const crypto = require("crypto");
const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 4096 });
const ecdh = crypto.createECDH("prime256v1");
const h = crypto.createHash('sha1').update(x).digest('hex');
const c = crypto.createCipheriv("aes-256-gcm", key, iv);
const agent = new https.Agent({ rejectUnauthorized: false });
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
'''

GO = '''\
package main

func main() {
\tpriv, _ := rsa.GenerateKey(rand.Reader, 2048)
\tk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
\tsum := md5.Sum(data)
\tdk, _ := mlkem.GenerateKey768()
\tcfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
}
'''


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "app"
    (src / "node_modules" / "dep").mkdir(parents=True)
    (src / "app.py").write_text(PYTHON)
    (src / "Main.java").write_text(JAVA)
    (src / "index.ts").write_text(JS)
    (src / "main.go").write_text(GO)
    (src / "node_modules" / "dep" / "x.js").write_text('crypto.createHash("md5")')
    (src / "keys.py").write_text('KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxQ3fakefakefake\n"""\n'
                                 'HEADER = b"-----BEGIN OPENSSH PRIVATE KEY-----"\n')
    return src


def _by(findings):
    return {(f.details["file"].rsplit("/", 1)[-1], f.details["line"], f.asset): f for f in findings}


def test_python_rules(repo):
    findings, _ = scan_code(repo)
    got = _by(findings)
    assert got[("app.py", 6, "MD5")].rating is Rating.CRITICAL
    assert not any(k[0] == "app.py" and k[1] in (7, 8) for k in got), "usedforsecurity=False and comments are skipped"
    assert got[("app.py", 9, "RSA-1024")].rating is Rating.CRITICAL  # multi-line call, size read from kwargs
    assert got[("app.py", 13, "RSA-3072")].rating is Rating.QUANTUM_VULNERABLE
    assert got[("app.py", 14, "ECDSA-P-384")].rating is Rating.QUANTUM_VULNERABLE
    assert got[("app.py", 15, "AES-ECB")].rating is Rating.CRITICAL
    assert got[("app.py", 16, "AES-GCM")].rating is Rating.QUANTUM_SAFE
    assert got[("app.py", 17, "verify=False")].category == "tls-config"
    assert got[("app.py", 18, "ssl.CERT_NONE")].rating is Rating.CRITICAL
    assert not any(k[0] == "app.py" and k[1] in (19, 21) for k in got), "comparisons and suppressed lines are skipped"
    assert got[("app.py", 20, "TLS 1.1 enabled in code")].rating is Rating.CRITICAL


def test_java_rules(repo):
    got = _by(scan_code(repo)[0])
    assert got[("Main.java", 1, "RSA-2048")].rating is Rating.QUANTUM_VULNERABLE  # size from .initialize()
    assert "ML-DSA" in got[("Main.java", 1, "RSA-2048")].recommendation
    assert got[("Main.java", 3, "AES-ECB")].rating is Rating.CRITICAL  # "AES" defaults to ECB
    assert got[("Main.java", 4, "AES-GCM")].rating is Rating.QUANTUM_SAFE
    assert got[("Main.java", 5, "3DES")].rating is Rating.CRITICAL
    assert got[("Main.java", 6, "SHA1withRSA")].rating is Rating.CRITICAL
    assert not any(k[0] == "Main.java" and k[1] == 7 for k in got), "SHA-256 is not reported"
    assert got[("Main.java", 8, "ML-KEM-768")].rating is Rating.QUANTUM_SAFE
    assert got[("Main.java", 9, "TLS 1.0 enabled in code")].rating is Rating.CRITICAL


def test_javascript_rules(repo):
    got = _by(scan_code(repo)[0])
    assert got[("index.ts", 2, "RSA-4096")].rating is Rating.QUANTUM_VULNERABLE
    assert got[("index.ts", 3, "ECDH (secp256r1)")].category == "key-exchange"
    assert got[("index.ts", 4, "SHA-1")].rating is Rating.CRITICAL
    assert got[("index.ts", 5, "AES-256-GCM")].rating is Rating.QUANTUM_SAFE
    assert got[("index.ts", 6, "rejectUnauthorized: false")].rating is Rating.CRITICAL
    assert got[("index.ts", 7, "ML-KEM-768")].rating is Rating.QUANTUM_SAFE


def test_go_rules(repo):
    got = _by(scan_code(repo)[0])
    assert got[("main.go", 4, "RSA-2048")].rating is Rating.QUANTUM_VULNERABLE
    assert got[("main.go", 5, "ECDSA-P-256")].rating is Rating.QUANTUM_VULNERABLE
    assert got[("main.go", 6, "MD5")].rating is Rating.CRITICAL
    assert got[("main.go", 7, "ML-KEM-768")].rating is Rating.QUANTUM_SAFE
    assert got[("main.go", 8, "InsecureSkipVerify: true")].rating is Rating.CRITICAL
    assert got[("main.go", 8, "TLS 1.0 enabled in code")].rating is Rating.CRITICAL


def test_secrets_and_skipped_dirs(repo):
    findings, notes = scan_code(repo)
    secrets = [f for f in findings if f.category == "secret"]
    assert len(secrets) == 1 and secrets[0].location.endswith("keys.py:1"), "a bare PEM header is not a key"
    assert not any("node_modules" in f.location for f in findings)
    assert any("Scanned 5 source file(s)" in n.message for n in notes)


def test_snippet_and_location(repo):
    f = next(f for f in scan_code(repo)[0] if f.asset == "RSA-1024")
    assert f.location.endswith("app.py:9")
    assert f.details["snippet"].startswith("key = rsa.generate_private_key(")
    assert f.target == f"code:{repo}"


def test_scan_source_unknown_language_is_empty():
    assert scan_source(textwrap.dedent(PYTHON), "cobol") == []


def test_cbom_includes_code_with_line_numbers(repo):
    bom = build_cbom(run_scan(code=[str(repo)]))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom)) is None
    rsa1024 = next(c for c in bom["components"] if c["name"] == "RSA-1024")
    occ = rsa1024["evidence"]["occurrences"][0]
    assert occ["location"].endswith("app.py") and occ["line"] == 9


# --- constant resolution (Python AST + regex for other languages) ---------------------

def _assets(src, lang):
    return {(line, asset) for line, _rule, _cat, asset, _v in scan_source(textwrap.dedent(src), lang)}


def test_python_constants_via_ast():
    src = """
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
        BASE = 512
        KEY_BITS = BASE * 2
        CURVE = ec.SECP384R1()

        class Settings:
            DH_BITS: int = 2 ** 11

        def make(bits=4096):
            weak = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
            ok = rsa.generate_private_key(65537, bits)
            sig = ec.generate_private_key(CURVE)
            params = dh.generate_parameters(generator=2, key_size=Settings.DH_BITS)
        """
    got = _assets(src, "python")
    assert (11, "RSA-1024") in got   # BASE * 2
    assert (12, "RSA-4096") in got   # default argument
    assert (13, "ECDSA-P-384") in got
    assert (14, "DH-2048") in got    # class attribute, 2 ** 11


def test_constants_in_other_languages():
    java = """
        private static final int KEY_SIZE = 1024;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(KEY_SIZE);
        """
    go = """
        const bits = 3072
        k, _ := rsa.GenerateKey(rand.Reader, bits)
        """
    js = """
        const MODULUS = 1024;
        crypto.generateKeyPairSync("rsa", { modulusLength: MODULUS });
        """
    assert (3, "RSA-1024") in _assets(java, "java")
    assert (3, "RSA-3072") in _assets(go, "go")
    assert (3, "RSA-1024") in _assets(js, "javascript")


def test_unresolvable_size_stays_unknown():
    got = _assets("k = rsa.generate_private_key(65537, load_size())\n", "python")
    assert (1, "RSA") in got
