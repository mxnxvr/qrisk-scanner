"""Checks for the Docker lab in lab/.

Offline tests (always run) check that the lab's configs and sample code give the
ratings the lab promises. Live tests (marker ``lab``) scan the running
containers and are skipped unless the lab is up:

    docker compose -f lab/docker-compose.yml up -d --build
    pytest -m lab
"""

import os
import socket
from pathlib import Path

import pytest

from qrisk.models import Rating
from qrisk.scanners.code import scan_code
from qrisk.scanners.config import scan_config
from qrisk.scanners.ssh import scan_ssh
from qrisk.scanners.tls import scan_tls

LAB = Path(__file__).resolve().parents[1] / "lab"


def _rating(findings, asset, file_part=""):
    matches = [f.rating for f in findings if f.asset == asset and file_part in (f.location or "")]
    assert matches, f"no finding {asset!r} in {file_part or 'any file'}"
    return matches[0]


# --- offline: lab files ---------------------------------------------------------------

def test_compose_file_is_valid():
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((LAB / "docker-compose.yml").read_text())
    services = compose["services"]
    assert set(services) == {"certgen", "weak-tls", "modern-tls", "pq-tls", "weak-ssh", "pq-ssh"}
    for name, svc in services.items():
        for port in svc.get("ports", []):
            assert port.startswith("127.0.0.1:"), f"{name} must only listen on localhost"
        for vol in svc.get("volumes", []):
            assert (LAB / vol.split(":")[0]).exists() or vol.startswith("./nginx/certs"), vol


def test_lab_configs_rate_as_promised():
    findings, notes = scan_config(LAB)
    assert _rating(findings, "TLS 1.0 enabled", "weak.conf") is Rating.CRITICAL
    assert _rating(findings, "DES-CBC3-SHA", "weak.conf") is Rating.CRITICAL
    assert _rating(findings, "@SECLEVEL=0", "weak.conf") is Rating.CRITICAL
    assert _rating(findings, "x25519 (configured group)", "modern.conf") is Rating.QUANTUM_VULNERABLE
    assert _rating(findings, "X25519MLKEM768 (configured group)", "pq.conf") is Rating.HYBRID
    assert _rating(findings, "MLKEM1024 (configured group)", "pq.conf") is Rating.QUANTUM_SAFE
    assert _rating(findings, "diffie-hellman-group1-sha1", "weak/sshd_config") is Rating.CRITICAL
    assert _rating(findings, "hmac-md5", "weak/sshd_config") is Rating.CRITICAL
    assert _rating(findings, "mlkem768x25519-sha256", "pq/sshd_config") is Rating.HYBRID
    assert not any(n.level == "warning" and "pq.conf" in n.target for n in notes)


def test_sample_app_rates_as_promised():
    findings, _ = scan_code(LAB / "sample-app")
    expected = {
        ("payments.py", "RSA-1024"): Rating.CRITICAL,
        ("payments.py", "ECDSA-P-256"): Rating.QUANTUM_VULNERABLE,
        ("payments.py", "MD5"): Rating.CRITICAL,
        ("payments.py", "AES-ECB"): Rating.CRITICAL,
        ("payments.py", "AES-GCM"): Rating.QUANTUM_SAFE,
        ("payments.py", "TLS 1.0 enabled in code"): Rating.CRITICAL,
        ("payments.py", "verify=False"): Rating.CRITICAL,
        ("TokenService.java", "RSA-2048"): Rating.QUANTUM_VULNERABLE,
        ("TokenService.java", "3DES"): Rating.CRITICAL,
        ("TokenService.java", "SHA1withRSA"): Rating.CRITICAL,
        ("TokenService.java", "ML-KEM-768"): Rating.QUANTUM_SAFE,
        ("auth.js", "RSA-3072"): Rating.QUANTUM_VULNERABLE,
        ("auth.js", "rejectUnauthorized: false"): Rating.CRITICAL,
        ("auth.js", "ML-KEM-768"): Rating.QUANTUM_SAFE,
        ("server.go", "ECDSA-P-384"): Rating.QUANTUM_VULNERABLE,
        ("server.go", "InsecureSkipVerify: true"): Rating.CRITICAL,
        ("server.go", "ML-KEM-768"): Rating.QUANTUM_SAFE,
    }
    for (file, asset), rating in expected.items():
        assert _rating(findings, asset, file) is rating, (file, asset)
    md5_lines = [f.details["line"] for f in findings if f.asset == "MD5" and "payments.py" in f.location]
    assert len(md5_lines) == 1, "usedforsecurity=False must not be reported"


# --- live: running containers ----------------------------------------------------------

def _up(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _needs(port: int):
    # In CI set QRISK_LAB_REQUIRED=1 so a lab that failed to start fails the run instead of skipping.
    required = os.environ.get("QRISK_LAB_REQUIRED") == "1"
    return pytest.mark.skipif(
        not required and not _up(port),
        reason=f"lab not running on 127.0.0.1:{port}: start it with `docker compose -f lab/docker-compose.yml up -d --build`",
    )


@pytest.mark.lab
@_needs(8443)
def test_live_weak_tls():
    findings, _ = scan_tls("localhost:8443", timeout=5)
    assets = {f.asset: f.rating for f in findings}
    assert assets["TLS 1.0"] is Rating.CRITICAL and assets["TLS 1.1"] is Rating.CRITICAL
    assert "TLS 1.3" not in assets
    assert assets["RSA key transport (TLS 1.2)"] is Rating.CRITICAL
    cert = next(f for f in findings if f.category == "certificate-key")
    assert cert.asset.startswith("RSA-1024") and cert.rating is Rating.CRITICAL


@pytest.mark.lab
@_needs(8444)
def test_live_modern_tls():
    findings, notes = scan_tls("localhost:8444", timeout=5)
    assets = {f.asset: f.rating for f in findings}
    assert assets["TLS 1.3"] is Rating.QUANTUM_SAFE
    assert assets["x25519 (TLS 1.3)"] is Rating.QUANTUM_VULNERABLE
    assert not any(r in (Rating.HYBRID,) for r in assets.values())
    assert any("no post-quantum" in n.message for n in notes)


@pytest.mark.lab
@_needs(8445)
def test_live_pq_tls():
    findings, _ = scan_tls("localhost:8445", timeout=5)
    assets = {f.asset: f.rating for f in findings}
    assert assets["X25519MLKEM768 (TLS 1.3)"] is Rating.HYBRID
    assert assets["SecP384r1MLKEM1024 (TLS 1.3)"] is Rating.HYBRID
    assert assets["MLKEM1024 (TLS 1.3)"] is Rating.QUANTUM_SAFE
    assert "TLS 1.2" not in assets


@pytest.mark.lab
@_needs(2222)
def test_live_weak_ssh():
    findings, _ = scan_ssh("127.0.0.1:2222", timeout=5)
    assets = {f.asset: f.rating for f in findings}
    assert assets["diffie-hellman-group1-sha1"] is Rating.CRITICAL
    assert assets["ssh-rsa"] is Rating.CRITICAL
    assert assets["3des-cbc"] is Rating.CRITICAL


@pytest.mark.lab
@_needs(2223)
def test_live_pq_ssh():
    findings, notes = scan_ssh("127.0.0.1:2223", timeout=5)
    assets = {f.asset: f.rating for f in findings}
    assert assets["mlkem768x25519-sha256"] is Rating.HYBRID
    assert not any("No post-quantum" in n.message for n in notes)
