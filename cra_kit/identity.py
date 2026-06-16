"""Device Identity and Trust-Tier Authorization (CRA Article 10).
Open source under MIT License.
"""

import hashlib, json, logging, os, sqlite3
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cra_kit.identity")

class TrustTier(IntEnum):
    UNTRUSTED = 0
    READ_ONLY = 1
    ENVIRONMENTAL = 2
    SECURITY = 3
    ADMIN = 4

ACTION_TIER_REQUIREMENTS = {
    "read": TrustTier.READ_ONLY,
    "write": TrustTier.ENVIRONMENTAL,
    "execute": TrustTier.SECURITY,
    "admin": TrustTier.ADMIN,
}

class DeviceIdentityService:
    """5-tier trust model with certificate-based enrollment."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = Path.home() / ".cra_kit" / "device_identity.db"
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._migrate()

    def _migrate(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_type TEXT NOT NULL,
                trust_tier INTEGER NOT NULL DEFAULT 1,
                cert_fingerprint TEXT,
                enrolled_at TEXT NOT NULL,
                last_seen TEXT,
                metadata TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS action_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT,
                tier_required INTEGER,
                tier_actual INTEGER,
                allowed INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            );
        """)
        self._conn.commit()

    def enroll_device(self, device_id, device_type, cert_fingerprint=None,
                      trust_tier=TrustTier.READ_ONLY):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT OR REPLACE INTO devices "
            "(device_id, device_type, trust_tier, cert_fingerprint, enrolled_at, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (device_id, device_type, int(trust_tier), cert_fingerprint, now, now),
        )
        self._conn.commit()
        return True

    def authenticate(self, device_id, cert_fingerprint=None):
        row = self._conn.execute(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        if row is None:
            return TrustTier.UNTRUSTED
        if cert_fingerprint and row["cert_fingerprint"] and row["cert_fingerprint"] != cert_fingerprint:
            return TrustTier.UNTRUSTED
        self._conn.execute(
            "UPDATE devices SET last_seen = ? WHERE device_id = ?",
            (datetime.now(timezone.utc).isoformat(), device_id),
        )
        self._conn.commit()
        return TrustTier(row["trust_tier"])

    def check_action(self, device_id, action, target_type="general"):
        tier = self.authenticate(device_id)
        required = ACTION_TIER_REQUIREMENTS.get(action, TrustTier.ADMIN)
        allowed = tier >= required
        self._conn.execute(
            "INSERT INTO action_log (device_id, action, target_type, tier_required, tier_actual, allowed, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (device_id, action, target_type, int(required), int(tier), int(allowed),
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()
        return allowed

    def get_device(self, device_id):
        row = self._conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None

    def list_devices(self):
        return [dict(r) for r in self._conn.execute("SELECT * FROM devices ORDER BY enrolled_at DESC").fetchall()]
