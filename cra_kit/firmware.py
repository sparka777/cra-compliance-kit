"""Firmware Health and Vulnerability Management (CRA Article 13).
Open source under MIT License.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
import logging, json

logger = logging.getLogger("cra_kit.firmware")

@dataclass
class FirmwareVulnerability:
    cve_id: str
    description: str
    cvss_score: float
    affected_product: str
    affected_versions: list
    fixed_version: str = None
    severity: str = "medium"

    def __post_init__(self):
        if self.cvss_score >= 9.0:
            self.severity = "critical"
        elif self.cvss_score >= 7.0:
            self.severity = "high"
        elif self.cvss_score >= 4.0:
            self.severity = "medium"
        else:
            self.severity = "low"

@dataclass
class DeviceCheckResult:
    device_id: str
    device_type: str
    current_version: str
    timestamp: str = ""
    vulnerabilities_found: list = field(default_factory=list)
    is_critical: bool = False
    passed: bool = True
    message: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

def _parse_semver(v):
    parts = v.split("-", 1)[0].split(".")
    while len(parts) < 3:
        parts.append("0")
    return tuple(int(p) for p in parts[:3])

def _compare_versions(a, b):
    ta, tb = _parse_semver(a), _parse_semver(b)
    if ta < tb: return -1
    if ta > tb: return 1
    return 0

def _satisfies_constraint(version, constraint):
    constraint = constraint.strip()
    if constraint.startswith(">="):
        return _compare_versions(version, constraint[2:]) >= 0
    if constraint.startswith("<="):
        return _compare_versions(version, constraint[2:]) <= 0
    if constraint.startswith(">"):
        return _compare_versions(version, constraint[1:]) > 0
    if constraint.startswith("<"):
        return _compare_versions(version, constraint[1:]) < 0
    return _compare_versions(version, constraint[2:].lstrip("= ")) == 0 if constraint.startswith("==") else False

class CVEDatabase:
    def __init__(self, cves=None):
        self._cves = cves or self._build_default()
    def _build_default(self):
        return [
            FirmwareVulnerability("CVE-2024-0001", "Auth bypass in gateway pre-2.0.0", 9.8, "gateway", [">=1.0.0", "<2.0.0"], "2.0.0"),
            FirmwareVulnerability("CVE-2024-0002", "Buffer overflow in sensor 1.5.x", 8.5, "sensor", [">=1.5.0", "<1.6.0"], "1.6.0"),
            FirmwareVulnerability("CVE-2025-1001", "Privilege escalation in gateway 2.1.x", 7.2, "gateway", [">=2.1.0", "<2.1.4"], "2.1.4"),
        ]
    def find_matches(self, product, version):
        matches = []
        for cve in self._cves:
            if cve.affected_product != product:
                continue
            if all(_satisfies_constraint(version, r) for r in cve.affected_versions):
                matches.append(cve)
        return matches
    def list_all(self):
        return list(self._cves)

class FirmwareHealthService:
    def __init__(self, cve_db=None, db_path=None):
        self._cve_db = cve_db or CVEDatabase()
    def check_device(self, device_id, device_type, current_version):
        result = DeviceCheckResult(device_id=device_id, device_type=device_type, current_version=current_version)
        matched = self._cve_db.find_matches(device_type, current_version)
        if matched:
            for cve in matched:
                result.vulnerabilities_found.append({
                    "cve_id": cve.cve_id,
                    "description": cve.description,
                    "cvss_score": cve.cvss_score,
                    "severity": cve.severity,
                    "fixed_version": cve.fixed_version,
                })
                if cve.severity == "critical":
                    result.is_critical = True
            result.passed = not result.is_critical
            cve_list = ", ".join(v["cve_id"] for v in result.vulnerabilities_found)
            result.message = f"Vulnerabilities found: {cve_list}"
        else:
            result.message = "No known vulnerabilities found."
        return result
