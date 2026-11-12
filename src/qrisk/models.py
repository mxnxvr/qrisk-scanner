"""Core data model shared by scanners, the risk engine and the reporters."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class Rating(str, enum.Enum):
    """Quantum-risk rating for a single finding, worst first."""

    CRITICAL = "critical"
    QUANTUM_VULNERABLE = "quantum-vulnerable"
    HYBRID = "hybrid"
    QUANTUM_SAFE = "quantum-safe"

    @property
    def label(self) -> str:
        return {
            Rating.CRITICAL: "Critical",
            Rating.QUANTUM_VULNERABLE: "Quantum-vulnerable",
            Rating.HYBRID: "Hybrid",
            Rating.QUANTUM_SAFE: "Quantum-safe",
        }[self]

    @property
    def meaning(self) -> str:
        return {
            Rating.CRITICAL: "Weak even today",
            Rating.QUANTUM_VULNERABLE: "Fine today, broken by a quantum computer",
            Rating.HYBRID: "Post-quantum + classical combined (the recommended transition)",
            Rating.QUANTUM_SAFE: "Post-quantum or quantum-resistant",
        }[self]

    @property
    def severity(self) -> int:
        """0 = worst. Used for sorting."""
        return list(Rating).index(self)

    @property
    def points(self) -> int:
        """Contribution to the readiness score (0-100)."""
        return {
            Rating.CRITICAL: 0,
            Rating.QUANTUM_VULNERABLE: 25,
            Rating.HYBRID: 100,  # hybrid is today's recommended deployment: never below pure ML-KEM
            Rating.QUANTUM_SAFE: 100,
        }[self]


@dataclass(frozen=True)
class Algo:
    """A cryptographic algorithm, described the way CycloneDX 1.6 CBOM wants it."""

    name: str
    primitive: str  # CycloneDX primitive: pke, signature, kem, key-agree, ae, block-cipher, hash, ...
    parameter_set: str | None = None
    curve: str | None = None
    mode: str | None = None
    classical_bits: int | None = None
    nist_qsl: int = 0  # NIST quantum security level 0-6 (0 = broken by a quantum computer)
    functions: tuple[str, ...] = ()
    oid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if v not in (None, ())}
        if self.functions:
            d["functions"] = list(self.functions)
        return d


@dataclass
class CertInfo:
    """Facts about one X.509 certificate."""

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    sha256: str
    serial: str
    key_algo: Algo | None
    key_size: int | None
    sig_algo: Algo | None
    self_signed: bool

    @property
    def days_left(self) -> int:
        return (self.not_after - datetime.now(timezone.utc)).days

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "days_left": self.days_left,
            "sha256": self.sha256,
            "serial": self.serial,
            "key_algorithm": self.key_algo.name if self.key_algo else None,
            "key_size": self.key_size,
            "signature_algorithm": self.sig_algo.name if self.sig_algo else None,
            "self_signed": self.self_signed,
        }


@dataclass
class Finding:
    """One piece of cryptography found somewhere, with its quantum-risk verdict."""

    target: str  # "example.com:443", "github.com:22", "path:./certs"
    layer: str  # "tls" | "ssh" | "file"
    category: str  # protocol, key-exchange, cipher, certificate-key, certificate-signature, host-key, ...
    asset: str  # human-readable, e.g. "TLS 1.2", "X25519MLKEM768", "RSA-2048"
    rating: Rating
    reason: str
    recommendation: str
    nist: str | None = None
    algorithm: Algo | None = None
    location: str | None = None  # file path for file findings
    cert: CertInfo | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def where(self) -> str:
        """Location for display: ``file:line`` plus the config block it sits in, if any."""
        base = self.location or self.target
        ctx = self.details.get("context")
        return f"{base} [{ctx}]" if ctx else base

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "layer": self.layer,
            "category": self.category,
            "asset": self.asset,
            "rating": self.rating.value,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "nist": self.nist,
            "algorithm": self.algorithm.to_dict() if self.algorithm else None,
            "location": self.location,
            "certificate": self.cert.to_dict() if self.cert else None,
            "details": self.details,
        }


@dataclass
class Note:
    """Something worth telling the user that is not a rated finding."""

    target: str
    message: str
    level: str = "info"  # info | warning | error

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "message": self.message, "level": self.level}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    notes: list[Note] = field(default_factory=list)
    targets: list[tuple[str, str]] = field(default_factory=list)  # (layer, target)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    def extend(self, findings: list[Finding], notes: list[Note]) -> None:
        self.findings.extend(findings)
        self.notes.extend(notes)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rating.severity, f.target, f.category, f.asset))

    def counts(self) -> dict[Rating, int]:
        counts = {r: 0 for r in Rating}
        for f in self.findings:
            counts[f.rating] += 1
        return counts
