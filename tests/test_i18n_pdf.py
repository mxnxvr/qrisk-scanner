import pytest

from qrisk import i18n
from qrisk.cli import main
from qrisk.models import Finding, Rating, ScanResult
from qrisk.reports import pdf
from qrisk.reports.html import render_html
from qrisk.rules import REC_RSA_KEX, REC_TLS_OLD
from qrisk.scanners.config import FIX


def _result():
    r = ScanResult(targets=[("tls", "shop.example.com:443")])
    r.findings = [
        Finding("shop.example.com:443", "tls", "protocol", "TLS 1.0", Rating.CRITICAL,
                "TLS 1.0 is obsolete.", REC_TLS_OLD, "Disallowed by NIST SP 800-52r2"),
        Finding("shop.example.com:443", "tls", "key-exchange", "RSA key transport (TLS 1.2)", Rating.CRITICAL,
                "No forward secrecy.", REC_RSA_KEX, None),
        Finding("shop.example.com:443", "tls", "key-exchange", "X25519MLKEM768 (TLS 1.3)", Rating.HYBRID,
                "Hybrid.", i18n.REC_HYBRID_KEEP, None),
    ]
    return r


def test_arabic_report_is_rtl_and_translated():
    html = render_html(_result(), "ar")
    assert '<html lang="ar" dir="rtl">' in html
    assert "تقرير الجاهزية الكمّية" in html and "الإجراءات ذات الأولوية" in html
    assert "حرج" in html and "هجين" in html                     # rating labels
    assert i18n.RECOMMENDATION_AR[REC_TLS_OLD] in html          # translated recommendation
    assert '<code dir="ltr">TLS_RSA_WITH_*</code>' in html     # commands stay left-to-right
    assert "⁦" in html                                     # date isolated as LTR
    assert "TLS 1.0 is obsolete." in html                       # technical reason kept in English


def test_english_report_unchanged_by_default():
    html = render_html(_result())
    assert '<html lang="en" dir="ltr">' in html and "Priority actions" in html


def test_every_standard_recommendation_has_arabic():
    for fixes in FIX.values():
        for text in fixes.values():
            assert i18n.recommendation(text, "ar") != text
    assert i18n.recommendation("Some custom advice.", "ar") == "Some custom advice."  # graceful fallback


def test_unknown_language_rejected():
    with pytest.raises(ValueError):
        render_html(_result(), "fr")


def test_pdf_error_without_browser(monkeypatch, tmp_path):
    monkeypatch.setattr(pdf, "find_browser", lambda: None)
    with pytest.raises(pdf.PdfError, match="Print > Save as PDF"):
        pdf.write_pdf(_result(), str(tmp_path / "x.pdf"))


@pytest.mark.skipif(pdf.find_browser() is None, reason="no Chrome/Edge/Chromium installed")
@pytest.mark.parametrize("lang", ["en", "ar"])
def test_pdf_export(tmp_path, lang):
    out = pdf.write_pdf(_result(), str(tmp_path / f"report-{lang}.pdf"), lang)
    data = out.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 10_000


@pytest.mark.skipif(pdf.find_browser() is None, reason="no Chrome/Edge/Chromium installed")
def test_cli_arabic_pdf(tmp_path, cert_factory):
    from cryptography.hazmat.primitives import serialization
    _, cert = cert_factory()
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    out = tmp_path / "r.pdf"
    assert main(["scan", "--path", str(tmp_path), "-q", "--lang", "ar", "--pdf", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF")
