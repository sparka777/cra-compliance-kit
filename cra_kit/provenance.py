"""
provenance.py - HMAC-SHA256 Tamper-Evident Audit Chain

COMMERCIAL MODULE — Requires a license from StarTeQ Ltd.

This module provides tamper-evident audit logging with HMAC-SHA256
signed entries and hash-chain verification. It satisfies CRA Article
13(8) vulnerability reporting requirements.

To unlock:
    contact sydney@starcaller.uk
    or visit https://starcaller.uk/cra-compliance
"""

import warnings

__all__ = ["MemoryProvenance", "WritePermissionError", "IntegrityViolationError"]

LICENSE_MSG = (
    "MemoryProvenance is a commercial module. "
    "Contact sydney@starcaller.uk for licensing."
)


class MemoryProvenance:
    """HMAC-SHA256 signed vault entries with hash-chain audit.

    Commercial license required. See https://starcaller.uk/cra-compliance
    """

    def __init__(self, *args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def sign_write(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)

    @staticmethod
    def verify_integrity(*args, **kwargs):
        raise RuntimeError(LICENSE_MSG)


class WritePermissionError(RuntimeError):
    """Raised when a write operation is not permitted."""


class IntegrityViolationError(RuntimeError):
    """Raised when a hash-chain integrity check fails."""
