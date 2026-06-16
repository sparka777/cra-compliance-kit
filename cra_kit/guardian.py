"""
guardian.py - Central Security Health Scoring (0-100)

COMMERCIAL MODULE — Requires a license from StarTeQ Ltd.

This module aggregates security signals from all other modules into
unified SecurityDigest reports and health scores. It satisfies CRA
Article 13 continuous monitoring requirements.

To unlock:
    contact sydney@starcaller.uk
    or visit https://starcaller.uk/cra-compliance
"""

import warnings

__all__ = ["GuardianSubsystem"]

LICENSE_MSG = (
    "GuardianSubsystem is a commercial module. "
    "Contact sydney@starcaller.uk for licensing."
)


class GuardianSubsystem:
    """Central security monitoring oracle with 0-100 health scoring.

    Commercial license required. See https://starcaller.uk/cra-compliance
    """

    def __init__(self, *args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def integrate_module(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def run_security_scan(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def get_security_digest(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)
