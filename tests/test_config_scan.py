import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from qrisk.models import Rating
from qrisk.reports.cbom import build_cbom
from qrisk.scan import run_scan
from qrisk.scanners.config import _apache_protocols, detect_kind, parse_nginx, scan_config

NGINX_LEGACY = """\
server {
    listen 443 ssl;
    server_name legacy.example.com;
    ssl_certificate     certs/legacy.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;   # old clients
    ssl_ciphers 'HIGH:RC4-SHA:AES256-SHA:!aNULL';
    ssl_ecdh_curve prime256v1:secp384r1;
}
"""

NGINX_MODERN = """\
server {
    listen 443 ssl;
    ssl_protocols TLSv1.2
                  TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL;
    ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
}
"""

APACHE = """\
<VirtualHost *:443>
    SSLEngine on
    SSLProtocol all -SSLv3
    SSLCipherSuite HIGH:!aNULL:!MD5
    SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519
</VirtualHost>
"""

OPENSSL = """\
openssl_conf = default_conf

[ req ]
default_bits = 1024
default_md   = sha1

[ system_default_sect ]
MinProtocol = TLSv1
CipherString = DEFAULT@SECLEVEL=1
"""

SSHD = """\
Port 22
HostKey keys/ssh_host_ed25519_key
KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group1-sha1
Ciphers aes256-gcm@openssh.com,3des-cbc
MACs hmac-sha2-256-etm@openssh.com,hmac-md5
HostKeyAlgorithms -ssh-rsa
"""


@pytest.fixture
def etc(tmp_path, cert_factory):
    root = tmp_path / "etc"
    (root / "nginx" / "sites-enabled").mkdir(parents=True)
    (root / "nginx" / "certs").mkdir()
    (root / "apache2" / "sites-enabled").mkdir(parents=True)
    (root / "ssh" / "keys").mkdir(parents=True)
    (root / "ssl").mkdir()

    (root / "nginx" / "sites-enabled" / "legacy").write_text(NGINX_LEGACY)  # no extension, like Debian
    (root / "nginx" / "sites-enabled" / "modern.conf").write_text(NGINX_MODERN)
    _, cert = cert_factory(rsa.generate_private_key(public_exponent=65537, key_size=2048), cn="legacy.example.com")
    (root / "nginx" / "certs" / "legacy.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "apache2" / "sites-enabled" / "default-ssl.conf").write_text(APACHE)
    (root / "ssl" / "openssl.cnf").write_text(OPENSSL)
    (root / "ssh" / "sshd_config").write_text(SSHD)
    pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    (root / "ssh" / "keys" / "ssh_host_ed25519_key.pub").write_bytes(pub)
    (root / "nginx" / "mime.types.conf").write_text("types { text/html html; }\n")  # nginx, but no TLS
    (root / "random.conf").write_text("foo = bar\n")
    return root


def _find(findings, file_part, asset):
    return [f for f in findings if file_part in f.location and f.asset == asset]


def test_nginx(etc):
    findings, notes = scan_config(etc)
    tls10 = _find(findings, "legacy", "TLS 1.0 enabled")[0]
    assert tls10.rating is Rating.CRITICAL and tls10.location.endswith("legacy:5")
    assert "ssl_protocols TLSv1.2 TLSv1.3" in tls10.recommendation
    assert _find(findings, "legacy", "RC4-SHA")[0].rating is Rating.CRITICAL
    assert _find(findings, "legacy", "Static RSA suites (AES256-SHA)")[0].rating is Rating.CRITICAL
    assert _find(findings, "legacy", "secp256r1 (configured group)")[0].rating is Rating.QUANTUM_VULNERABLE
    assert any("No post-quantum" in n.message and "legacy:7" in n.target for n in notes)
    # The referenced certificate is inspected too.
    cert = next(f for f in findings if f.category == "certificate-key")
    assert cert.asset.startswith("RSA-2048") and cert.details["referenced_from"].endswith("legacy:4")

    # Multi-line directive: line number is where it starts.
    assert _find(findings, "modern", "TLS 1.3 enabled")[0].location.endswith("modern.conf:3")
    assert _find(findings, "modern", "X25519MLKEM768 (configured group)")[0].rating is Rating.HYBRID
    assert _find(findings, "modern", "Cipher list")[0].rating is Rating.QUANTUM_SAFE


def test_apache(etc):
    findings, _ = scan_config(etc / "apache2")
    assets = {f.asset for f in findings}
    # "all -SSLv3" still enables TLS 1.0 and 1.1.
    assert {"TLS 1.0 enabled", "TLS 1.1 enabled", "TLS 1.2 enabled", "TLS 1.3 enabled"} <= assets
    assert "SSLProtocol -all +TLSv1.2 +TLSv1.3" in _find(findings, "", "TLS 1.0 enabled")[0].recommendation
    assert _find(findings, "", "X25519MLKEM768 (configured group)")[0].rating is Rating.HYBRID
    assert _find(findings, "", "Cipher list")[0].rating is Rating.QUANTUM_SAFE


def test_openssl_cnf(etc):
    findings, _ = scan_config(etc / "ssl" / "openssl.cnf")
    by_asset = {f.asset: f for f in findings}
    assert by_asset["default_bits = 1024 (new RSA keys)"].rating is Rating.CRITICAL
    assert by_asset["default_md = sha1"].rating is Rating.CRITICAL
    assert by_asset["MinProtocol TLSv1"].rating is Rating.CRITICAL
    assert by_asset["@SECLEVEL=1"].rating is Rating.CRITICAL


def test_sshd(etc):
    findings, notes = scan_config(etc / "ssh")
    by_asset = {f.asset: f for f in findings}
    assert by_asset["mlkem768x25519-sha256"].rating is Rating.HYBRID
    assert by_asset["diffie-hellman-group1-sha1"].rating is Rating.CRITICAL
    assert by_asset["3des-cbc"].rating is Rating.CRITICAL
    assert by_asset["hmac-md5"].rating is Rating.CRITICAL
    assert by_asset["hmac-sha2-256-etm@openssh.com"].rating is Rating.QUANTUM_SAFE
    assert "ssh-rsa" not in by_asset, "'-ssh-rsa' removes an algorithm, it doesn't enable it"
    assert by_asset["Ed25519 public key"].location.endswith("ssh_host_ed25519_key.pub")
    assert by_asset["mlkem768x25519-sha256"].location.endswith("sshd_config:3")


def test_unrecognised_files_are_ignored(etc):
    findings, notes = scan_config(etc)
    assert not any("random.conf" in f.location for f in findings)
    summary = next(n.message for n in notes if n.message.startswith("Config files recognised"))
    assert "1 apache" in summary and "1 openssl" in summary and "1 sshd" in summary


def test_defaults_notes(tmp_path):
    (tmp_path / "sshd_config").write_text("Port 22\n")
    (tmp_path / "site.conf").write_text("server { listen 443 ssl; ssl_certificate missing.pem; }\n")
    findings, notes = scan_config(tmp_path)
    messages = " ".join(n.message for n in notes)
    assert "KexAlgorithms is not set" in messages
    assert "protocols are not set" in messages and "groups are not set" in messages
    assert "not readable here: missing.pem" in messages


def test_parsers():
    dirs = parse_nginx("http {\n ssl_ciphers 'A:B';  # comment ; here\n}\n")
    assert dirs[0].name == "ssl_ciphers" and dirs[0].args == ["A:B"] and dirs[0].line == 2
    assert _apache_protocols(["-all", "+TLSv1.2", "+TLSv1.3"]) == ["TLSv1.2", "TLSv1.3"]
    assert _apache_protocols(["all", "-TLSv1", "-TLSv1.1"]) == ["TLSv1.2", "TLSv1.3"]


def test_detect_kind(tmp_path):
    p = tmp_path / "x.conf"
    assert detect_kind(p, "SSLProtocol all\n") == "apache"
    assert detect_kind(p, "server {\n listen 80;\n}\n") == "nginx"
    assert detect_kind(p, "KexAlgorithms curve25519-sha256\n") == "sshd"
    assert detect_kind(tmp_path / "a.cnf", "[x]\n") == "openssl"
    assert detect_kind(p, "foo = bar\n") is None


def test_cbom_and_cli(etc):
    bom = build_cbom(run_scan(config=[str(etc)]))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom)) is None
    mlkem = next(c for c in bom["components"] if c["name"] == "mlkem768x25519-sha256")
    assert mlkem["evidence"]["occurrences"][0]["line"] == 3


# --- includes and block context ---------------------------------------------------------

def test_follows_includes_and_records_context(tmp_path):
    nginx = tmp_path / "nginx"
    (nginx / "snippets").mkdir(parents=True)
    (nginx / "nginx.conf").write_text(
        "http {\n"
        "  include snippets/*.conf;\n"
        "  server {\n"
        "    listen 443 ssl;\n"
        "    server_name shop.example.com;\n"
        "    ssl_protocols TLSv1.1 TLSv1.2;\n"
        "  }\n"
        "}\n")
    # Only reachable through the include; on its own it has no nginx markers beyond ssl_*.
    (nginx / "snippets" / "tls-params.conf").write_text("ssl_ciphers 'HIGH:RC4-SHA';\n")

    findings, notes = scan_config(nginx / "nginx.conf")  # scan just the main file
    rc4 = next(f for f in findings if f.asset == "RC4-SHA")
    assert rc4.details["included_from"].endswith("nginx.conf")
    assert rc4.location.endswith("tls-params.conf:1")
    tls11 = next(f for f in findings if f.asset == "TLS 1.1 enabled")
    assert tls11.details["context"] == "server shop.example.com"


def test_ssh_host_and_apache_vhost_context(tmp_path):
    (tmp_path / "ssh_config").write_text(
        "Host legacy.example.com\n  HostKeyAlgorithms +ssh-rsa\nHost *\n  Ciphers aes256-gcm@openssh.com\n")
    (tmp_path / "site.conf").write_text(
        "<VirtualHost *:443>\n  SSLEngine on\n  SSLProtocol all\n</VirtualHost>\nSSLCipherSuite HIGH\n")
    findings, _ = scan_config(tmp_path)
    assert next(f for f in findings if f.asset == "ssh-rsa").details["context"] == "Host legacy.example.com"
    assert next(f for f in findings if f.asset == "TLS 1.0 enabled").details["context"] == "VirtualHost *:443"
    assert "context" not in next(f for f in findings if f.asset == "Cipher list").details


def test_ssh_include(tmp_path):
    (tmp_path / "sshd_config.d").mkdir()
    (tmp_path / "sshd_config").write_text("Include sshd_config.d/*.conf\nPort 22\n")
    (tmp_path / "sshd_config.d" / "crypto.conf").write_text("Ciphers 3des-cbc\n")
    findings, _ = scan_config(tmp_path / "sshd_config")
    assert next(f for f in findings if f.asset == "3des-cbc").rating is Rating.CRITICAL
