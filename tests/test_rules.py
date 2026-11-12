from qrisk.models import Rating
from qrisk.rules import (
    NIST_2030, NIST_2035, rate_bulk_cipher, rate_public_key, rate_signature, rate_ssh_cipher,
    rate_ssh_hostkey, rate_ssh_kex, rate_tls12_kex, rate_tls_group, rate_tls_version, split_tls12_suite,
)


def test_rsa_sizes():
    assert rate_public_key("RSA", 1024).rating is Rating.CRITICAL
    v = rate_public_key("RSA", 2048)
    assert v.rating is Rating.QUANTUM_VULNERABLE and v.nist == NIST_2030
    assert v.algo.name == "RSA-2048"
    assert rate_public_key("RSA", 3072).nist == NIST_2035


def test_ecdsa_curves():
    v = rate_public_key("EC", 256, "secp256r1")
    assert v.rating is Rating.QUANTUM_VULNERABLE and v.algo.name == "ECDSA-P-256"
    assert rate_public_key("EC", 192, "secp192r1").rating is Rating.CRITICAL


def test_signatures():
    assert rate_signature("sha1WithRSAEncryption", "sha1", "RSA").rating is Rating.CRITICAL
    assert rate_signature("sha256WithRSAEncryption", "sha256", "RSA").rating is Rating.QUANTUM_VULNERABLE


def test_tls_versions():
    assert rate_tls_version(0x0301).rating is Rating.CRITICAL
    assert rate_tls_version(0x0302).rating is Rating.CRITICAL
    assert rate_tls_version(0x0303).rating is Rating.QUANTUM_VULNERABLE
    assert rate_tls_version(0x0304).rating is Rating.QUANTUM_SAFE


def test_tls_groups():
    name, v = rate_tls_group(0x11EC)
    assert name == "X25519MLKEM768" and v.rating is Rating.HYBRID
    assert rate_tls_group(0x0201)[1].rating is Rating.QUANTUM_SAFE
    assert rate_tls_group(0x001D)[1].rating is Rating.QUANTUM_VULNERABLE
    assert rate_tls_group(0xABCD)[0] == "group-0xabcd"


def test_cipher_suites():
    assert split_tls12_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == ("ECDHE", "AES_128_GCM_SHA256")
    assert rate_bulk_cipher("RC4_128_SHA").rating is Rating.CRITICAL
    assert rate_bulk_cipher("3DES_EDE_CBC_SHA").rating is Rating.CRITICAL
    v = rate_bulk_cipher("TLS_AES_256_GCM_SHA384")
    assert v.rating is Rating.QUANTUM_SAFE and v.algo.name == "AES-256-GCM" and v.algo.nist_qsl == 5
    assert rate_tls12_kex("RSA").rating is Rating.CRITICAL
    assert rate_tls12_kex("ECDHE").rating is Rating.QUANTUM_VULNERABLE


def test_ssh():
    assert rate_ssh_kex("mlkem768x25519-sha256").rating is Rating.HYBRID
    assert rate_ssh_kex("sntrup761x25519-sha512@openssh.com").rating is Rating.HYBRID
    assert rate_ssh_kex("curve25519-sha256").rating is Rating.QUANTUM_VULNERABLE
    assert rate_ssh_kex("diffie-hellman-group1-sha1").rating is Rating.CRITICAL
    assert rate_ssh_hostkey("ssh-rsa").rating is Rating.CRITICAL
    assert rate_ssh_hostkey("ssh-ed25519-cert-v01@openssh.com").rating is Rating.QUANTUM_VULNERABLE
    assert rate_ssh_cipher("aes256-gcm@openssh.com").rating is Rating.QUANTUM_SAFE
    assert rate_ssh_cipher("aes128-cbc").rating is Rating.CRITICAL
    assert rate_ssh_cipher("3des-cbc").rating is Rating.CRITICAL
