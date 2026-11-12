"""Machine-readable JSON output."""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..models import ScanResult
from ..scoring import grade, readiness_score


def build_json(result: ScanResult) -> dict[str, Any]:
    score = readiness_score(result.findings)
    return {
        "tool": "qrisk-scanner",
        "version": __version__,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "score": score,
        "grade": grade(score),
        "summary": {r.value: n for r, n in result.counts().items()},
        "targets": [{"layer": layer, "target": t} for layer, t in result.targets],
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "notes": [n.to_dict() for n in result.notes],
    }


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_json(result), fh, indent=2)
