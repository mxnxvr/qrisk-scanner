"""Command-line interface: ``qrisk scan --tls example.com --path ./certs --html report.html``."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from . import __version__
from .reports.cbom import write_cbom
from .reports.html import write_html
from .reports.pdf import PdfError, write_pdf
from .reports.json_report import write_json
from .reports.terminal import render
from .scan import run_scan
from .scoring import readiness_score

EXAMPLES = """examples:
  qrisk scan --tls example.com
  qrisk scan --tls example.com:8443 --ssh github.com --path ./certs
  qrisk scan --tls example.com --html report.html --cbom cbom.json --json results.json
  qrisk scan --code ./src --html code-report.html
  qrisk scan --tls example.com --pdf report.pdf --lang ar   # Arabic PDF
  qrisk scan --config /etc/nginx --config /etc/ssh/sshd_config --config /etc/ssl/openssl.cnf
  qrisk scan --path /etc/ssl --fail-under 50   # exit code 2 if the score is below 50
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qrisk",
        description="Find the cryptography you use and rate its quantum risk.",
    )
    parser.add_argument("--version", action="version", version=f"qrisk {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan TLS endpoints, SSH servers, certificate/key files, source code and config files",
                          epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    scan.add_argument("--tls", action="append", default=[], metavar="HOST[:PORT]",
                      help="TLS endpoint to scan (default port 443). Repeatable.")
    scan.add_argument("--ssh", action="append", default=[], metavar="HOST[:PORT]",
                      help="SSH server to scan (default port 22). Repeatable.")
    scan.add_argument("--path", action="append", default=[], metavar="PATH",
                      help="file or folder of certificates/keys to scan. Repeatable.")
    scan.add_argument("--code", action="append", default=[], metavar="PATH",
                      help="source folder to scan for crypto API usage (Python, Java/Kotlin, JS/TS, Go). Repeatable.")
    scan.add_argument("--config", action="append", default=[], metavar="PATH",
                      help="nginx / Apache / openssl.cnf / sshd_config file or folder to audit. Repeatable.")
    scan.add_argument("--config-follow-external", action="store_true",
                      help="let --config follow include directives and certificate paths outside the scanned folder")
    scan.add_argument("--json", metavar="FILE", help="write results as JSON")
    scan.add_argument("--cbom", metavar="FILE", help="write a CycloneDX 1.6 CBOM")
    scan.add_argument("--html", metavar="FILE", help="write an HTML report")
    scan.add_argument("--pdf", metavar="FILE", help="write a PDF report (uses an installed Chrome, Edge or Chromium)")
    scan.add_argument("--lang", choices=["en", "ar"], default="en",
                      help="language of the HTML/PDF report: en (default) or ar (Arabic, right-to-left)")
    scan.add_argument("--timeout", type=float, default=5.0, help="network timeout in seconds (default 5)")
    scan.add_argument("--fail-under", type=int, metavar="SCORE",
                      help="exit with code 2 if the readiness score is below SCORE (useful in CI)")
    scan.add_argument("--allow-empty", action="store_true",
                      help="with --fail-under: pass when nothing cryptographic was found (errors still fail)")
    scan.add_argument("-q", "--quiet", action="store_true", help="don't print the terminal summary")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not (args.tls or args.ssh or args.path or args.code or args.config):
        parser.error("give at least one target: --tls, --ssh, --path, --code or --config")

    console = Console(stderr=args.quiet)
    with console.status("Scanning…") as status:
        result = run_scan(
            args.tls, args.ssh, args.path, args.code, args.config, args.timeout,
            follow_external=args.config_follow_external,
            on_target=lambda layer, t: status.update(f"Scanning {layer.upper()} {t}…"),
        )
    if not args.quiet:
        render(result, console)

    outputs = ((args.json, lambda r, p: write_json(r, p), "JSON"), (args.cbom, lambda r, p: write_cbom(r, p), "CBOM"),
               (args.html, lambda r, p: write_html(r, p, args.lang), "HTML report"),
               (args.pdf, lambda r, p: write_pdf(r, p, args.lang), "PDF report"))
    for path, writer, label in outputs:
        if path:
            try:
                writer(result, path)
            except PdfError as exc:
                console.print(f"[red]✗ PDF report not written:[/red] {exc}", highlight=False)
                return 1
            console.print(f"[green]✓[/green] {label} written to {path}", highlight=False)

    if args.fail_under is not None:
        reason = gate_failure(result, args.fail_under, allow_empty=args.allow_empty)
        if reason:
            console.print(f"[red]✗ --fail-under {args.fail_under}: {reason}[/red]", highlight=False)
            return 2
    return 0


def gate_failure(result, threshold: int, *, allow_empty: bool = False) -> str | None:
    """Why a CI gate should fail, or None. An unreachable target or an empty scan must never pass
    silently: that would show a green build when nothing was actually checked."""
    errors = [n for n in result.notes if n.level == "error"]
    if errors:
        return (f"{len(errors)} target(s) could not be scanned, so the result is incomplete "
                f"(first: {errors[0].target}: {errors[0].message})")
    score = readiness_score(result.findings)
    if score is None:
        return None if allow_empty else ("no cryptography was found, so there is nothing to rate. "
                                         "If that is expected (e.g. scanning your own code), add --allow-empty")
    if score < threshold:
        return f"readiness score {score} is below {threshold}"
    return None


if __name__ == "__main__":
    sys.exit(main())
