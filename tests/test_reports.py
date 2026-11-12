import json

from cryptography.hazmat.primitives import serialization
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from rich.console import Console

from qrisk.cli import main
from qrisk.reports.cbom import build_cbom
from qrisk.reports.html import render_html
from qrisk.reports.json_report import build_json
from qrisk.reports.terminal import render
from qrisk.scan import run_scan


def _result(tmp_path, cert_factory, tls=None, ssh=None):
    certs = tmp_path / "certs"
    certs.mkdir(exist_ok=True)
    key, cert = cert_factory(cn="files")
    (certs / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (certs / "k.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return run_scan(tls=[tls] if tls else [], ssh=[ssh] if ssh else [], paths=[str(certs)], timeout=3)


def test_cbom_is_valid_cyclonedx_16(tmp_path, cert_factory, tls_server, ssh_server):
    result = _result(tmp_path, cert_factory, tls_server, ssh_server[0])
    bom = build_cbom(result)
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert error is None, error
    types = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert types == {"algorithm", "certificate", "protocol", "related-crypto-material"}
    tls13 = next(c for c in bom["components"] if c["name"] == "TLS 1.3")
    assert tls13["cryptoProperties"]["protocolProperties"]["cipherSuites"]
    refs = {c["bom-ref"] for c in bom["components"]}
    for dep in bom["dependencies"]:
        assert dep["ref"] in refs and set(dep["dependsOn"]) <= refs


def test_json_and_html(tmp_path, cert_factory):
    result = _result(tmp_path, cert_factory)
    data = build_json(result)
    assert data["score"] == 25 and data["grade"] == "Quantum-vulnerable"
    json.dumps(data)
    html = render_html(result)
    assert "Quantum Readiness Report" in html and "RSA-2048" in html and "2035" in html


def test_terminal_render(tmp_path, cert_factory):
    console = Console(record=True, width=140)
    render(_result(tmp_path, cert_factory), console)
    text = console.export_text()
    assert "Quantum Readiness: 25/100" in text and "Top recommendations" in text


def test_cli_end_to_end(tmp_path, cert_factory):
    _result(tmp_path, cert_factory)
    certs, out = tmp_path / "certs", tmp_path / "out"
    out.mkdir()
    code = main(["scan", "--path", str(certs), "-q", "--json", str(out / "r.json"),
                 "--cbom", str(out / "c.json"), "--html", str(out / "r.html"), "--fail-under", "10"])
    assert code == 0
    assert (out / "r.html").exists()
    assert json.loads((out / "c.json").read_text())["specVersion"] == "1.6"
    assert main(["scan", "--path", str(certs), "-q", "--fail-under", "90"]) == 2
