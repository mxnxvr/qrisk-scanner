"""Runs the scanners and collects everything into one ScanResult."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from .models import Note, ScanResult
from .scanners.certs import scan_path
from .scanners.code import scan_code
from .scanners.config import scan_config
from .scanners.ssh import scan_ssh
from .scanners.tls import scan_tls


def run_scan(
    tls: Iterable[str] = (),
    ssh: Iterable[str] = (),
    paths: Iterable[str] = (),
    code: Iterable[str] = (),
    config: Iterable[str] = (),
    timeout: float = 5.0,
    follow_external: bool = False,
    on_target: Callable[[str, str], None] | None = None,
) -> ScanResult:
    result = ScanResult()
    jobs = [("tls", t) for t in tls] + [("ssh", t) for t in ssh] + [("file", p) for p in paths]
    jobs += [("code", c) for c in code] + [("config", c) for c in config]
    for layer, target in jobs:
        if on_target:
            on_target(layer, target)
        try:
            if layer == "tls":
                findings, notes = scan_tls(target, timeout)
            elif layer == "ssh":
                findings, notes = scan_ssh(target, timeout)
            elif layer == "code":
                findings, notes = scan_code(target)
            elif layer == "config":
                findings, notes = scan_config(target, follow_external=follow_external)
            else:
                findings, notes = scan_path(target)
        except Exception as exc:  # one bad target (timeout, reset, permission error...) must not lose the rest
            findings, notes = [], [Note(target, f"{layer.upper()} scan failed: {type(exc).__name__}: {exc}", "error")]
        result.targets.append((layer, target))
        result.extend(findings, notes)
    result.finished_at = datetime.now(timezone.utc)
    return result
