"""DELIBERATELY INSECURE sample code for the QRisk lab. Do not copy."""

import hashlib
import ssl

import requests
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def legacy_signing_key():
    # Critical: RSA-1024
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )


def signing_key():
    # Quantum-vulnerable: fine today, broken by Shor's algorithm
    return ec.generate_private_key(ec.SECP256R1())


def card_fingerprint(pan: bytes) -> str:
    return hashlib.md5(pan).hexdigest()  # critical: MD5 for a security purpose


def cache_key(body: bytes) -> str:
    return hashlib.md5(body, usedforsecurity=False).hexdigest()  # fine: not security-related


def encrypt_token(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # critical: ECB
    return enc.update(data) + enc.finalize()


def encrypt_record(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, data, None)  # quantum-safe


def call_partner(url: str):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # critical: TLS 1.0
    return requests.get(url, verify=False)  # critical: no certificate check
