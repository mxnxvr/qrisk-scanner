"""PDF export by printing the HTML report with a headless Chromium browser (Chrome, Edge, Chromium).

Why a browser: it is already installed on almost every machine, needs no extra Python
dependencies, and shapes Arabic text correctly (pure-Python PDF libraries don't).
Set ``QRISK_BROWSER`` to a browser executable to override the search.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..models import ScanResult
from .html import render_html

_NAMES = ["chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge",
          "microsoft-edge", "microsoft-edge-stable"]


def _candidates() -> list[str]:
    paths: list[str] = []
    env = os.environ.get("QRISK_BROWSER")
    if env:
        paths.append(env)
    paths += [p for p in (shutil.which(n) for n in _NAMES) if p]
    system = platform.system()
    if system == "Windows":
        for base in (os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"), os.environ.get("LOCALAPPDATA")):
            if base:
                paths += [str(Path(base) / "Google/Chrome/Application/chrome.exe"),
                          str(Path(base) / "Microsoft/Edge/Application/msedge.exe"),
                          str(Path(base) / "Chromium/Application/chrome.exe")]
    elif system == "Darwin":
        paths += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                  "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    return paths


def find_browser() -> str | None:
    return next((p for p in _candidates() if Path(p).is_file()), None)


class PdfError(RuntimeError):
    pass


def html_to_pdf(html: str, out_path: str | Path, timeout: float = 90) -> Path:
    browser = find_browser()
    if not browser:
        raise PdfError("No Chrome, Edge or Chromium found for PDF export. Install one, set QRISK_BROWSER, "
                       "or open the --html report and use Print > Save as PDF.")
    out = Path(out_path).resolve()
    out.unlink(missing_ok=True)
    deadline = time.monotonic() + timeout
    # ignore_cleanup_errors: a browser helper (e.g. Crashpad) may still hold the profile folder for a moment.
    with tempfile.TemporaryDirectory(prefix="qrisk-pdf-", ignore_cleanup_errors=True) as tmp:
        page = Path(tmp) / "report.html"
        page.write_text(html, encoding="utf-8")
        args = [
            browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
            f"--user-data-dir={Path(tmp) / 'profile'}",  # don't touch the user's real browser profile
            "--no-pdf-header-footer", "--print-to-pdf-no-header",  # new and old spellings of the same option
            f"--print-to-pdf={out}", page.as_uri(),
        ]
        if platform.system() == "Linux" and hasattr(os, "geteuid") and os.geteuid() == 0:
            args.insert(1, "--no-sandbox")  # Chromium refuses to run as root (e.g. in CI containers) otherwise
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise PdfError(f"{Path(browser).name} did not finish printing within {timeout:.0f}s") from exc
        # Some browsers (Edge 157+) hand the job to a background process and return before the PDF
        # is written. Wait, still inside the temp folder (the browser is reading report.html from it),
        # until the file exists and its size has stopped changing.
        _wait_for_file(out, deadline)
    if not out.is_file() or out.stat().st_size == 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] if proc else []
        raise PdfError(f"{Path(browser).name} did not produce a PDF. {' '.join(detail)}".strip())
    return out


def _wait_for_file(path: Path, deadline: float, settle: float = 0.5) -> None:
    last = -1
    while time.monotonic() < deadline:
        size = path.stat().st_size if path.is_file() else -1
        if size > 0 and size == last:
            return
        last = size
        time.sleep(settle)


def write_pdf(result: ScanResult, path: str, lang: str = "en") -> Path:
    return html_to_pdf(render_html(result, lang), path)
