"""
CRA Compliance Kit for IoT Devices.

Meet EU Cyber Resilience Act (CRA) requirements in one pip install.

Open-Source Modules (MIT License):
    identity.py    5-tier device trust with certificate-based auth
    firmware.py    CVE matching + semantic version gating
    input_guard.py Input classification + 8 injection family detection
    action_guard.py Hard-blocked and confirm-required action lists

Commercial Modules (license required):
    provenance.py  HMAC-SHA256 audit chain for tamper-evident logging
    guardian.py    Aggregation + security health scoring 0-100
    baselines.py   Welford online anomaly detection
    signing.py     Inter-service request signing + escalation matrix

Quickstart:
    from cra_kit.identity import DeviceIdentityService, TrustTier
    identity = DeviceIdentityService()
    identity.enrol_device("sensor-01", "temperature_sensor", trust_tier=1)

    from cra_kit.firmware import FirmwareHealthService
    fw = FirmwareHealthService()
    result = fw.check_device("sensor-01", "gateway", "1.5.3")

    from cra_kit.input_guard import InputClassifier
    safe, findings = InputClassifier().is_safe(user_input)

    from cra_kit.action_guard import check_physical_action
    check_physical_action("format_storage")  # -> {"allowed": False}
"""

from .identity import DeviceIdentityService, TrustTier
from .firmware import FirmwareHealthService, CVEDatabase
from .input_guard import InputClassifier, sanitize_input, OriginCategory, InjectionType
from .action_guard import PhysicalActionGuard, check_physical_action

__all__ = [
    "DeviceIdentityService", "TrustTier",
    "FirmwareHealthService", "CVEDatabase",
    "InputClassifier", "sanitize_input", "OriginCategory", "InjectionType",
    "PhysicalActionGuard", "check_physical_action",
]
