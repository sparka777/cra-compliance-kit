"""Physical Action Blacklist and Access Control (CRA Article 10).
Open source under MIT License.
"""

from datetime import datetime, timezone
import logging
logger = logging.getLogger("cra_kit.action_guard")

HARD_BLOCKED_ACTIONS = [
    "lock_out_user", "delete_user_account", "format_storage",
    "disable_security_logging", "disable_firmware_updates",
    "modify_kernel_parameters", "disable_encryption",
    "override_safety_limits", "delete_system_partition", "disable_secure_boot",
]

CONFIRMATION_REQUIRED_ACTIONS = [
    "reboot_device", "factory_reset", "update_firmware",
    "modify_network_config", "enable_remote_access",
    "disable_network_interface", "change_admin_password",
    "modify_access_controls", "export_user_data",
    "downgrade_security_policy", "batch_delete_logs",
]

class PhysicalActionGuard:
    def __init__(self, time_restrictions=None):
        self._time_restrictions = time_restrictions or {}
        self._night_hour_start = 22
        self._night_hour_end = 7

    def check_action(self, action, user_tier=4):
        now = datetime.now(timezone.utc)
        hour = now.hour
        if action in HARD_BLOCKED_ACTIONS:
            return {"allowed": False, "reason": "hard_blocked", "severity": "critical"}
        needs_confirm = action in CONFIRMATION_REQUIRED_ACTIONS
        if action in self._time_restrictions:
            if hour >= self._night_hour_start or hour < self._night_hour_end:
                return {"allowed": False, "reason": "time_restricted", "severity": "high"}
        return {"allowed": True, "needs_confirmation": needs_confirm, "severity": "info"}

def check_physical_action(action, user_tier=4):
    return PhysicalActionGuard().check_action(action, user_tier)
