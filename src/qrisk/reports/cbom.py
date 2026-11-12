"""CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) output."""

from __future__ import annotations

import json
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..models import Algo, CertInfo, Finding, ScanResult
from ..scoring import grade, readiness_score


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Builder:
    def __init__(self) -> None:
        self.components: dict[str, dict[str, Any]] = {}
        self.deps: dict[str, set[str]] = defaultdict(set)

    def _component(self, ref: str, name: str, crypto: dict[str, Any], location: str,
                   rating: str | None = None, line: int | None = None) -> dict[str, Any]:
        comp = self.components.get(ref)
        if comp is None:
            comp = {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": name,
                "cryptoProperties": crypto,
                "evidence": {"occurrences": []},
            }
            if rating:
                comp["properties"] = [{"name": "qrisk:rating", "value": rating}]
            self.components[ref] = comp
        occ = comp["evidence"]["occurrences"]
        if not any(o["location"] == location and o.get("line") == line for o in occ):
            occ.append({"location": location, "line": line} if line else {"location": location})
        return comp

    def algorithm(self, algo: Algo, location: str, rating: str | None = None, line: int | None = None) -> str:
        ref = f"crypto/algorithm/{_slug(algo.name)}"
        props: dict[str, Any] = {"primitive": algo.primitive}
        if algo.parameter_set:
            props["parameterSetIdentifier"] = algo.parameter_set
        if algo.curve:
            props["curve"] = algo.curve
        if algo.mode:
            props["mode"] = algo.mode
        if algo.functions:
            props["cryptoFunctions"] = list(algo.functions)
        if algo.classical_bits is not None:
            props["classicalSecurityLevel"] = algo.classical_bits
        props["nistQuantumSecurityLevel"] = algo.nist_qsl
        crypto: dict[str, Any] = {"assetType": "algorithm", "algorithmProperties": props}
        if algo.oid:
            crypto["oid"] = algo.oid
        self._component(ref, algo.name, crypto, location, rating, line)
        return ref

    def key(self, ref: str, name: str, kind: str, algo: Algo | None, size: int | None,
            location: str, rating: str, expires: datetime | None = None) -> str:
        props: dict[str, Any] = {"type": kind}
        if algo:
            props["algorithmRef"] = self.algorithm(algo, location, rating)
        if size:
            props["size"] = size
        if expires:
            props["expirationDate"] = _ts(expires)
        self._component(ref, name, {"assetType": "related-crypto-material",
                                    "relatedCryptoMaterialProperties": props}, location, rating)
        return ref

    def certificate(self, cert: CertInfo, location: str, rating: str) -> str:
        short = cert.sha256[:16]
        ref = f"crypto/certificate/{short}"
        props: dict[str, Any] = {
            "subjectName": cert.subject,
            "issuerName": cert.issuer,
            "notValidBefore": _ts(cert.not_before),
            "notValidAfter": _ts(cert.not_after),
            "certificateFormat": "X.509",
        }
        if cert.sig_algo:
            props["signatureAlgorithmRef"] = self.algorithm(cert.sig_algo, location)
        key_name = f"{cert.key_algo.name if cert.key_algo else 'unknown'} public key ({short})"
        props["subjectPublicKeyRef"] = self.key(f"crypto/key/{short}", key_name, "public-key",
                                                cert.key_algo, cert.key_size, location, rating)
        comp = self._component(ref, cert.subject, {"assetType": "certificate", "certificateProperties": props},
                               location, rating)
        extra = comp.setdefault("properties", [])
        if not any(p["name"] == "qrisk:sha256" for p in extra):
            extra.append({"name": "qrisk:sha256", "value": cert.sha256})
        return ref


def build_cbom(result: ScanResult) -> dict[str, Any]:
    b = _Builder()
    by_target: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_target[f.target].append(f)

    for target, findings in by_target.items():
        protocol_refs: dict[str, str] = {}
        layer = findings[0].layer

        # Protocol components (one per target + version).
        if layer == "tls":
            for f in findings:
                if f.category == "protocol":
                    ver = f.details["version"]
                    ref = f"crypto/protocol/tls/{_slug(target)}/{ver}"
                    suites = [
                        {"name": c.asset, "algorithms": [b.algorithm(c.algorithm, target, c.rating.value)],
                         "identifiers": ["0x" + c.details["code"][2:4], "0x" + c.details["code"][4:6]]}
                        for c in findings
                        if c.category == "cipher" and c.algorithm and c.details.get("version") == ver
                    ]
                    props: dict[str, Any] = {"type": "tls", "version": ver}
                    if suites:
                        props["cipherSuites"] = suites
                    b._component(ref, f"TLS {ver}", {"assetType": "protocol", "protocolProperties": props},
                                 target, f.rating.value)
                    protocol_refs[ver] = ref
        elif layer == "ssh":
            ref = f"crypto/protocol/ssh/{_slug(target)}"
            b._component(ref, "SSH 2.0", {"assetType": "protocol",
                                          "protocolProperties": {"type": "ssh", "version": "2.0"}}, target)
            protocol_refs["2.0"] = ref

        for f in findings:
            where = f.location or target
            if f.layer in ("code", "config"):
                if f.algorithm:
                    b.algorithm(f.algorithm, f.details["file"], f.rating.value, f.details["line"])
                continue
            if f.cert:
                ref = b.certificate(f.cert, where, f.rating.value)
            elif f.category in ("private-key", "public-key") and f.algorithm:
                ref = b.key(f"crypto/key/{_slug(where)}/{_slug(f.asset)}", f.asset, f.category,
                            f.algorithm, f.details.get("key_size"), where, f.rating.value)
            elif f.algorithm and f.category not in ("certificate-signature",):
                ref = b.algorithm(f.algorithm, where, f.rating.value)
            else:
                continue
            ver = f.details.get("version", "2.0" if layer == "ssh" else None)
            parents = [protocol_refs[ver]] if ver in protocol_refs else list(protocol_refs.values())
            for parent in parents:
                if parent != ref:
                    b.deps[parent].add(ref)

    score = readiness_score(result.findings)
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _ts(result.finished_at or result.started_at),
            "tools": {"components": [{
                "type": "application", "name": "qrisk-scanner", "version": __version__,
                "description": "Quantum-risk crypto scanner",
            }]},
            "properties": [
                {"name": "qrisk:readiness-score", "value": "n/a" if score is None else str(score)},
                {"name": "qrisk:grade", "value": grade(score)},
            ],
        },
        "components": list(b.components.values()),
    }
    if b.deps:
        bom["dependencies"] = [{"ref": ref, "dependsOn": sorted(children)} for ref, children in b.deps.items()]
    return bom


def write_cbom(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_cbom(result), fh, indent=2)
