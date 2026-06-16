# CRA Compliance Kit for IoT Devices

**Meet EU Cyber Resilience Act (CRA) requirements in one pip install.**

[![PyPI version](https://img.shields.io/pypi/v/cra-compliance-kit)](https://pypi.org/project/cra-compliance-kit/)
[![Python](https://img.shields.io/pypi/pyversions/cra-compliance-kit)](https://pypi.org/project/cra-compliance-kit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Key Deadlines

| Obligation | Date | Status |
|-----------|------|--------|
| Vulnerability reporting (24h to ENISA) | **September 11, 2026** | 87 days |
| Full CRA conformity assessment | **December 11, 2027** | 18 months |
| Penalties for non-compliance | Up to **EUR 15M or 2.5% of global turnover** | Active |

## What This Kit Provides

| Module | CRA Requirement | License |
|--------|-----------------|---------|
| `DeviceIdentityService` (identity.py) | Device identity, access control — Art. 10(2-3) | MIT |
| `FirmwareHealthService` (firmware.py) | Vulnerability tracking, CVE matching — Art. 13(1-3) | MIT |
| `InputClassifier` (input_guard.py) | Secure by default input handling — Art. 10(1) | MIT |
| `PhysicalActionGuard` (action_guard.py) | Hard-blocked & confirm-required actions — Art. 10(3) | MIT |
| `CycloneDX SBOM Generator` (sbom/generator.py) | SBOM maintenance for ENISA — Art. 13(8) | MIT |
| `GuardianSubsystem` *(commercial)* | Central security health scoring | Gated — contact sydney@starcaller.uk |
| `BehaviouralBaselineService` *(commercial)* | Welford anomaly detection | Gated — contact sydney@starcaller.uk |
| `MemoryProvenance` *(commercial)* | HMAC-SHA256 audit chain | Gated — contact sydney@starcaller.uk |
| `CrossOracleSigner` *(commercial)* | Inter-service request signing | Gated — contact sydney@starcaller.uk |

## Quickstart

```bash
pip install cra-compliance-kit
```

```python
from cra_kit.identity import DeviceIdentityService, TrustTier
from cra_kit.firmware import FirmwareHealthService
from cra_kit.input_guard import InputClassifier
from cra_kit.action_guard import PhysicalActionGuard

# 1. Enrol devices with tiered trust
identity = DeviceIdentityService()
identity.enrol_device("sensor-01", "temperature_sensor", trust_tier=TrustTier.ENVIRONMENTAL)

# 2. Check firmware against CVE database
fw = FirmwareHealthService()
check = fw.check_device("sensor-01", "gateway", "1.5.3")
print(f"Vulnerable to {len(check.vulnerabilities_found)} CVEs")

# 3. Sanitize every input
classifier = InputClassifier()
safe, findings = classifier.is_safe(user_input)

# 4. Restrict dangerous actions
guard = PhysicalActionGuard()
result = guard.check_action("format_storage")
assert result["allowed"] == False  # Hard blocked

# 5. Generate SBOM
python -m sbom.generator --product "MyIoTGateway" --version "2.1.0" --output sbom.xml
```

## CRA Article Mapping

| Article | Requirement | How We Satisfy It |
|---------|-------------|-------------------|
| **Article 10(1)** | Secure by default configuration | InputClassifier blocks injection, sanitises inputs before processing |
| **Article 10(2)** | Device identity & authentication | DeviceIdentityService — 5-tier trust model with certificate-based enrollment |
| **Article 10(3)** | Access control mechanisms | PhysicalActionGuard — 10 hard-blocked + 11 confirm-required actions, time-aware |
| **Article 13(1-3)** | Vulnerability handling & remediation | FirmwareHealthService — CVE matching, semantic version gating, severity scoring |
| **Article 13(8)** | SBOM accessible to ENISA on request | CycloneDX 1.5 generator with automatic installed-package scanning |

## Architecture Overview

Each module is self-contained with zero external dependencies (stdlib only).
Modules store state in SQLite at `~/.cra_kit/` for persistence.

```
User Input
    |
    v
InputClassifier  ── detects 8 injection families (prompt, code, SQL, command, XSS, SSRF, traversal, format string)
    |
    v
DeviceIdentityService  ── authenticates, checks trust tier (0-4)
    |
    v
PhysicalActionGuard  ── blocks/confirms dangerous actions, time-gated at night
    |
    v
FirmwareHealthService  ── matches version against CVE database
    |
    v
SBOM Generator (CycloneDX 1.5 XML)
```

## Open-Core Licensing

| Package Type | Modules | License | Price |
|-------------|---------|---------|-------|
| **Open Source** | identity.py, firmware.py, input_guard.py, action_guard.py, sbom/generator.py | MIT | Free |
| **Professional** (coming soon) | Guardian + Baselines + Provenance + Signing | Commercial | 1,500/yr |
| **Enterprise** (coming soon) | All pro + priority support + SLA | Commercial | 7,500/yr |

## Requirements

- Python 3.9+
- SQLite (built into Python standard library)
- Zero external dependencies

## Who Built This

StarTeQ Ltd — the team behind Starcaller, a privacy-first AI appliance with
a 9.3/10 security trust score and 8-module security stack in production.

**Contact:** sydney@starcaller.uk
**Website:** [starcaller.uk/cra-compliance](https://starcaller.uk/cra-compliance)


## CRA Watch — Live Vulnerability Monitoring

Monitor your registered products in real time at the **[CRA Watch Dashboard](https://cra-watch.starcaller-teq.workers.dev/dashboard)**.

- Daily CISA KEV polling at 06:00 UTC
- NVD + EPSS enrichment on-demand
- CycloneDX VEX generation
- ENISA Article 14 notification drafts
- 24hr / 72hr / 14-day deadline tracking

[![CRA Watch](https://img.shields.io/badge/CRA_Watch-live-brightgreen)](https://cra-watch.starcaller-teq.workers.dev/dashboard)
