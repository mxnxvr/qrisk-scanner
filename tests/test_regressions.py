"""Regression tests for the bugs recorded in NOTES.md (numbers match the entries there).

Each test is written to fail if its bug comes back. Some also prove the test can fail at all,
by re-creating the bug and checking that the assertion would catch it.
"""

import html
import re
import shutil
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from qrisk.cli import main
from qrisk.models import Finding, Rating, ScanResult
from qrisk.reports.html import render_html
from qrisk.rules import REC_TLS_OLD
from qrisk.scanners.certs import parse_java_keystore

ROOT = Path(__file__).resolve().parents[1]


# --- #8: `p += u4()` lost the 4-byte length advance in the JKS parser ----------------------

def test_08_jks_private_key_entry_followed_by_more_entries():
    """The bug only showed when a private-key entry (which has an encrypted-key length) was
    followed by another entry: the parser landed 4 bytes short and read garbage."""
    def utf(s: str) -> bytes:
        return struct.pack("!H", len(s)) + s.encode()

    def cert(der: bytes) -> bytes:
        return utf("X.509") + struct.pack("!I", len(der)) + der

    enc_key = b"\x01" * 37                      # length deliberately not a multiple of 4
    data = bytes.fromhex("feedfeed") + struct.pack("!II", 2, 3)
    data += struct.pack("!I", 1) + utf("server") + struct.pack("!Q", 0)
    data += struct.pack("!I", len(enc_key)) + enc_key + struct.pack("!I", 2) + cert(b"leaf") + cert(b"ca")
    data += struct.pack("!I", 2) + utf("root") + struct.pack("!Q", 0) + cert(b"root-der")
    data += struct.pack("!I", 2) + utf("other") + struct.pack("!Q", 0) + cert(b"other-der")
    data += b"\x00" * 20                        # integrity digest

    fmt, entries = parse_java_keystore(data)
    assert fmt == "JKS"
    assert entries == [
        ("private-key", "server", [b"leaf", b"ca"]),
        ("trusted-cert", "root", [b"root-der"]),
        ("trusted-cert", "other", [b"other-der"]),
    ]


# --- #9: the date printed backwards in the Arabic report -----------------------------------
# The HTML looked fine; the bug only appeared when a browser applied the Unicode
# bidirectional algorithm. So test what the reader *sees*: run the same algorithm
# (python-bidi) over the rendered text and check the visual order.

def _arabic_generated_line(strip_isolates: bool = False) -> str:
    result = ScanResult(targets=[("tls", "a:443")], finished_at=datetime(2026, 11, 6, 20, 8, tzinfo=timezone.utc))
    result.findings = [Finding("a:443", "tls", "protocol", "TLS 1.0", Rating.CRITICAL, "Old.", REC_TLS_OLD)]
    page = render_html(result, "ar")
    line = html.unescape(re.search(r'<h1>.*?</h1>\s*<div class="muted small">(.*?)</div>', page, re.S).group(1))
    return line.replace("⁦", "").replace("⁩", "") if strip_isolates else line


def test_09_arabic_report_shows_latin_dates_in_reading_order():
    bidi = pytest.importorskip("bidi")
    visual = bidi.get_display(_arabic_generated_line())
    assert "2026-11-06 20:08 UTC" in visual
    assert "0.1.0" in visual or "QRisk" in visual


def test_09_the_check_catches_the_original_bug():
    """Without the LRI/PDI isolates the same check must fail, as the screenshot did."""
    bidi = pytest.importorskip("bidi")
    visual = bidi.get_display(_arabic_generated_line(strip_isolates=True))
    assert "2026-11-06" not in visual
    assert "06-11-2026" in visual


# --- #10: the PDF would have inherited dark mode ----------------------------------------

def test_10_dark_mode_is_screen_only_so_print_and_pdf_are_light():
    page = render_html(ScanResult())
    assert "@media screen and (prefers-color-scheme: dark)" in page
    assert not re.search(r"@media\s*\(prefers-color-scheme:\s*dark\)", page), "dark colours must not apply to print"


# --- #12: --fail-under failed a scan with no findings ----------------------------------------

def test_12_fail_under_never_passes_when_nothing_was_checked(tmp_path, capsys):
    """Revised after code review: an empty scan used to pass, which turns an unreachable server
    into a green CI build. Now it fails unless --allow-empty says empty is expected."""
    (tmp_path / "readme.txt").write_text("no certificates here")
    assert main(["scan", "--path", str(tmp_path), "-q", "--fail-under", "80"]) == 2
    assert "nothing to rate" in capsys.readouterr().err
    assert main(["scan", "--path", str(tmp_path), "-q", "--fail-under", "80", "--allow-empty"]) == 0


def test_12_fail_under_fails_when_a_target_is_unreachable(capsys):
    # Port 1 on localhost is closed: no findings, one error note.
    assert main(["scan", "--tls", "127.0.0.1:1", "-q", "--timeout", "1", "--fail-under", "50", "--allow-empty"]) == 2
    assert "could not be scanned" in capsys.readouterr().err


# --- #13: CRLF line endings would break the lab's Linux containers ---------------------------

LF_FILES = ["lab/certgen.sh", "lab/nginx/Dockerfile", "lab/ssh/Dockerfile", "lab/nginx/nginx.conf",
            "lab/nginx/sites/weak.conf", "lab/ssh/weak/sshd_config", "lab/ssh/pq/sshd_config"]


@pytest.mark.skipif(shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a git checkout")
def test_13_lab_files_are_checked_out_with_lf_endings():
    """Ask git, not the disk: what matters is what a fresh clone on Windows will produce."""
    out = subprocess.run(["git", "check-attr", "eol", "--", *LF_FILES], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    for f in LF_FILES:
        assert f"{f}: eol: lf" in out, f"{f} must be forced to LF in .gitattributes"


# --- #23: Hybrid (gold) and Quantum-vulnerable (orange) looked alike in the report -----------
# The palette was chosen with a colour-blindness validator. This test re-checks the two rules
# that matter most, in pure Python, so a future colour tweak can't quietly undo it:
#  - neighbouring ratings must differ by >= 15 OKLab Delta E (x100) for normal vision
#  - each rating colour needs >= 3:1 contrast against its card surface (WCAG)

def _lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _rgb(hex_: str) -> tuple[float, float, float]:
    h = hex_.lstrip("#")
    return tuple(_lin(int(h[i:i + 2], 16) / 255) for i in (0, 2, 4))


def _oklab(hex_: str) -> tuple[float, float, float]:
    r, g, b = _rgb(hex_)
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return (0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
            1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
            0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s)


def _delta_e(a: str, b: str) -> float:
    return 100 * sum((x - y) ** 2 for x, y in zip(_oklab(a), _oklab(b))) ** 0.5


def _contrast(a: str, b: str) -> float:
    la, lb = (0.2126 * r + 0.7152 * g + 0.0722 * b_ for r, g, b_ in (_rgb(a), _rgb(b)))
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _palettes(page: str) -> list[tuple[str, dict[str, str]]]:
    blocks = re.findall(r"(--card: (#[0-9a-f]{6});.*?--critical: (#[0-9a-f]{6}); --vulnerable: (#[0-9a-f]{6}); "
                        r"--hybrid: (#[0-9a-f]{6}); --safe: (#[0-9a-f]{6}))", page, re.S)
    return [(card, {"critical": c, "vulnerable": v, "hybrid": h, "safe": s}) for _, card, c, v, h, s in blocks]


def test_23_rating_colours_are_distinguishable_in_light_and_dark_mode():
    palettes = _palettes(render_html(ScanResult()))
    assert len(palettes) == 2, "expected a light and a dark palette"
    order = ["critical", "vulnerable", "hybrid", "safe"]
    for card, colours in palettes:
        for a, b in zip(order, order[1:]):
            assert _delta_e(colours[a], colours[b]) >= 15, (card, a, b)
        for name, colour in colours.items():
            assert _contrast(colour, card) >= 3, (card, name)


def test_23_the_check_catches_the_original_colours():
    assert _delta_e("#b08f00", "#e8710a") < 15  # the old gold Hybrid vs orange Quantum-vulnerable
