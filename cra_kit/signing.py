"""
signing.py - Inter-Service Request Signing & Escalation

COMMERCIAL MODULE — Requires a license from StarTeQ Ltd.

This module provides HMAC-based inter-service request signing with
an escalation matrix for cross-domain operation authorization.
It satisfies CRA Article 10(3) access control requirements.

To unlock:
    contact sydney@starcaller.uk
    or visit https://starcaller.uk/cra-compliance
"""

import warnings

__all__ = ["CrossOracleSigner"]

LICENSE_MSG = (
    "CrossOracleSigner is a commercial module. "
    "Contact sydney@starcaller.uk for licensing."
)


class CrossOracleSigner:
    """HMAC inter-service request signing with escalation matrix.

    Commercial license required. See https://starcaller.uk/cra-compliance
    """

    def __init__(self, *args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def sign_request(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def verify_request(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def trace_chain(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)
