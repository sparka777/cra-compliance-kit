"""
baselines.py - Welford Online Anomaly Detection

COMMERCIAL MODULE — Requires a license from StarTeQ Ltd.

This module provides behavioural baseline tracking using Welford's
online algorithm with z-score anomaly detection (threshold 3.0).
It satisfies CRA Article 13 continuous monitoring requirements.

To unlock:
    contact sydney@starcaller.uk
    or visit https://starcaller.uk/cra-compliance
"""

import warnings

__all__ = ["BehaviouralBaselineService"]

LICENSE_MSG = (
    "BehaviouralBaselineService is a commercial module. "
    "Contact sydney@starcaller.uk for licensing."
)


class BehaviouralBaselineService:
    """Online anomaly detection using Welford's algorithm.

    Commercial license required. See https://starcaller.uk/cra-compliance
    """

    def __init__(self, *args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def record_event(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def get_anomalies(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def get_stats(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)
