"""Quantum Readiness score (0-100).

How it works, so the number can be explained to a client:

1. Every finding earns points: quantum-safe 100, hybrid 100, quantum-vulnerable 25,
   critical 0. Hybrid (classical + ML-KEM) is the recommended deployment today, so it
   must not score below pure ML-KEM.
2. Only *public-key* categories measure quantum readiness: key exchange, certificate
   keys and signatures, host keys and other key pairs. Hygiene categories (protocol
   version, symmetric ciphers, MACs, hashes, TLS settings, ...) are already safe against
   quantum attacks when they are sound, so they only count when they are critical.
   Otherwise a classical TLS 1.3 server would look "in transition" thanks to AES-GCM.
3. Findings are averaged per category inside a target (so 15 cipher suites don't outweigh
   one certificate), then categories per target, then targets. Every target counts equally.
4. Any critical finding caps the score at 49: you can't be "ready" for quantum computers
   while something is already broken today.
"""

from __future__ import annotations

from collections import defaultdict
from statistics import mean

from .models import Finding, Rating

CRITICAL_CAP = 49

# Categories whose algorithms a quantum computer actually breaks.
QUANTUM_CATEGORIES = {
    "key-exchange", "certificate-key", "certificate-signature", "host-key", "host-key-size",
    "public-key", "private-key", "signature",
}


def _counts_toward_score(f: Finding, has_quantum: bool) -> bool:
    return f.category in QUANTUM_CATEGORIES or f.rating is Rating.CRITICAL or not has_quantum


def readiness_score(findings: list[Finding]) -> int | None:
    if not findings:
        return None
    by_target: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_target[f.target].append(f)
    target_scores = []
    for items in by_target.values():
        # A target with no public-key findings at all (e.g. code that only uses AES) is scored on what it has.
        has_quantum = any(f.category in QUANTUM_CATEGORIES for f in items)
        cats: dict[str, list[int]] = defaultdict(list)
        for f in items:
            if _counts_toward_score(f, has_quantum):
                cats[f.category].append(f.rating.points)
        target_scores.append(mean(mean(pts) for pts in cats.values()))
    score = round(mean(target_scores))
    if any(f.rating is Rating.CRITICAL for f in findings):
        score = min(score, CRITICAL_CAP)
    return score


def grade(score: int | None) -> str:
    if score is None:
        return "No findings"
    if score >= 80:
        return "Quantum-ready"
    if score >= 50:
        return "In transition"
    if score >= 25:
        return "Quantum-vulnerable"
    return "At risk"
