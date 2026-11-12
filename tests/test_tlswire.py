import struct

from qrisk.scanners.tlswire import HRR_RANDOM, build_client_hello, parse_server_hello


def test_client_hello_structure():
    rec = build_client_hello("example.com", version=0x0303, cipher_suites=[0x1301], groups=[0x11EC], tls13=True)
    content_type, record_version, length = struct.unpack("!BHH", rec[:5])
    assert content_type == 22 and record_version == 0x0301 and length == len(rec) - 5
    assert rec[5] == 1  # ClientHello
    assert b"example.com" in rec
    assert b"\x11\xec" in rec


def test_no_sni_for_ip():
    rec = build_client_hello("127.0.0.1", version=0x0303, cipher_suites=[0x002F], groups=[])
    assert b"127.0.0.1" not in rec


def _server_hello(random: bytes, exts: bytes, cipher: int = 0x1301, legacy: int = 0x0303) -> bytes:
    return (struct.pack("!H", legacy) + random + b"\x00" + struct.pack("!H", cipher) + b"\x00"
            + struct.pack("!H", len(exts)) + exts)


def test_parse_hello_retry_request():
    exts = struct.pack("!HHH", 43, 2, 0x0304) + struct.pack("!HHH", 51, 2, 0x11EC)
    sh = parse_server_hello(_server_hello(HRR_RANDOM, exts))
    assert sh.is_hrr and sh.version == 0x0304 and sh.selected_group == 0x11EC


def test_parse_tls12_server_hello():
    sh = parse_server_hello(_server_hello(b"\x01" * 32, b"", cipher=0xC02F))
    assert not sh.is_hrr and sh.version == 0x0303 and sh.cipher_suite == 0xC02F and sh.selected_group is None
