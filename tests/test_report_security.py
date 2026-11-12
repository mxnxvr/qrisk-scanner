"""The report shows text controlled by the systems being scanned (certificate names, SSH
banners, file paths, code snippets). None of it may be able to inject HTML or script."""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from qrisk.models import Finding, Note, Rating, ScanResult
from qrisk.reports.html import render_html
from qrisk.rules import REC_TLS_OLD
from qrisk.scanners.certs import analyze_certificate

PAYLOAD = '<script>alert("pwned")</script>'
IMG = '<img src=x onerror=alert(1)>'


def _hostile_result(cert_factory):
    # A real certificate whose common name is a script tag, as a malicious server could present.
    _, cert = cert_factory(rsa.generate_private_key(public_exponent=65537, key_size=2048), cn=PAYLOAD)
    findings, notes = analyze_certificate(cert, target="evil.example:443", layer="tls")
    r = ScanResult(targets=[("tls", "evil.example:443"), ("ssh", "evil.example:22")])
    r.findings = findings + [
        Finding("evil.example:22", "ssh", "key-exchange", f"curve25519{IMG}", Rating.QUANTUM_VULNERABLE,
                "Classical.", REC_TLS_OLD, None, location=f"src/{IMG}.py:3",
                details={"context": f"server {PAYLOAD}"}),
    ]
    r.notes = notes + [Note("evil.example:22", f"Server banner: SSH-2.0-{PAYLOAD}", "info")]
    return r


@pytest.mark.parametrize("lang", ["en", "ar"])
def test_scanned_text_is_escaped_in_report(cert_factory, lang):
    page = render_html(_hostile_result(cert_factory), lang)
    assert "<script>" not in page and "onerror=alert" not in page.replace("onerror=alert(1)&gt;", "")
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(&#34;pwned&#34;)&lt;/script&gt;" in page   # still shown, as text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page


def test_report_still_renders_its_own_markup(cert_factory):
    """Escaping must not break the report's intended HTML (badges, code spans, gauge)."""
    page = render_html(_hostile_result(cert_factory))
    assert '<span class="badge">' in page
    assert "<svg class=\"gauge\"" in page
    assert '<code dir="ltr">' in page  # recommendation commands rendered by the `code` filter
