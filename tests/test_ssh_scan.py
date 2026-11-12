from conftest import kexinit_payload

from qrisk.models import Rating
from qrisk.scanners.ssh import parse_kexinit, scan_ssh


def test_parse_kexinit_filters_pseudo_algorithms():
    info = parse_kexinit(kexinit_payload(["curve25519-sha256", "ext-info-s"], ["ssh-ed25519"], ["aes128-ctr"]))
    assert info.kex == ["curve25519-sha256"]
    assert info.host_keys == ["ssh-ed25519"]


def test_scan_fake_server(ssh_server):
    target, _ = ssh_server
    findings, notes = scan_ssh(target, timeout=3)
    by_asset = {f.asset: f for f in findings}
    assert by_asset["mlkem768x25519-sha256"].rating is Rating.HYBRID
    assert by_asset["diffie-hellman-group1-sha1"].rating is Rating.CRITICAL
    assert by_asset["ssh-rsa"].rating is Rating.CRITICAL
    assert by_asset["3des-cbc"].rating is Rating.CRITICAL
    assert "ext-info-s" not in by_asset
    assert any("OpenSSH_9.9" in n.message for n in notes)


def test_no_pq_warning(ssh_server):
    target, config = ssh_server
    config["kex"] = ["curve25519-sha256"]
    _, notes = scan_ssh(target, timeout=3)
    assert any("No post-quantum" in n.message for n in notes)


def test_unreachable():
    findings, notes = scan_ssh("127.0.0.1:1", timeout=1)
    assert findings == [] and notes[0].level == "error"


def test_rsa_host_key_size_from_key_exchange(ssh_server):
    target, config = ssh_server
    findings, _ = scan_ssh(target, timeout=3)
    key = next(f for f in findings if f.category == "host-key-size")
    assert key.asset == "RSA-1024 host key" and key.rating is Rating.CRITICAL
    assert "ssh-keygen -t ed25519" in key.recommendation

    config["rsa_bits"] = 3072
    findings, _ = scan_ssh(target, timeout=3)
    key = next(f for f in findings if f.category == "host-key-size")
    assert key.asset == "RSA-3072 host key" and key.rating is Rating.QUANTUM_VULNERABLE


def test_no_rsa_host_key_means_no_size_probe(ssh_server):
    target, config = ssh_server
    config["hostkeys"] = ["ssh-ed25519"]
    findings, _ = scan_ssh(target, timeout=3)
    assert not any(f.category == "host-key-size" for f in findings)


def test_live_scan_rates_macs_like_the_config_scan(ssh_server, tmp_path):
    """Review #5: MACs were collected but never rated, so live and config scans disagreed."""
    from qrisk.scanners.config import scan_config

    target, config = ssh_server
    live = {f.asset: f.rating for f in scan_ssh(target, timeout=3)[0] if f.category == "mac"}
    assert live == {
        "hmac-sha2-256-etm@openssh.com": Rating.QUANTUM_SAFE,
        "hmac-sha1": Rating.QUANTUM_SAFE,
        "hmac-md5": Rating.CRITICAL,
        "hmac-sha1-96": Rating.CRITICAL,
    }
    (tmp_path / "sshd_config").write_text("MACs " + ",".join(config["macs"]) + "\n")
    audited = {f.asset: f.rating for f in scan_config(tmp_path)[0] if f.category == "mac"}
    assert audited == live
