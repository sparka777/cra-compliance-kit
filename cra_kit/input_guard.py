"""Input Sanitisation and Injection Detection (CRA Article 10).
Open source under MIT License.
"""

from enum import Enum, auto
from typing import Optional
import logging

logger = logging.getLogger("cra_kit.input_guard")

class OriginCategory(Enum):
    UNKNOWN = auto()
    LOCAL_USER = auto()
    REMOTE_API = auto()
    SYSTEM_INTERNAL = auto()
    AUTOMATED_AGENT = auto()

class InjectionType(Enum):
    PROMPT_INJECTION = auto()
    CODE_INJECTION = auto()
    SQL_INJECTION = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    XSS = auto()
    FORMAT_STRING = auto()
    SSRF = auto()

INJECTION_PATTERNS = {
    InjectionType.CODE_INJECTION: ["__import__", "eval(", "exec(", "os.system(", "subprocess."],
    InjectionType.SQL_INJECTION: ["' OR", " OR 1=1", "' --", "UNION SELECT", "DROP TABLE", "DELETE FROM"],
    InjectionType.COMMAND_INJECTION: ["; rm ", "; wget ", "; curl ", "`", "$("],
    InjectionType.PATH_TRAVERSAL: ["../", "..\\", "~.."],
    InjectionType.XSS: ["<script", "javascript:", "onerror="],
    InjectionType.FORMAT_STRING: ["%n"],
    InjectionType.SSRF: ["169.254.", "10.", "192.168."],
    InjectionType.PROMPT_INJECTION: ["ignore previous instructions", "forget all prior", "you are now", "system prompt"],
}

class InputClassifier:
    def __init__(self, custom_patterns=None):
        self._patterns = {}
        for k, v in INJECTION_PATTERNS.items():
            self._patterns[k] = list(v)
        if custom_patterns:
            for k, v in custom_patterns.items():
                self._patterns[k] = self._patterns.get(k, []) + v

    def classify_origin(self, source_ip="", user_agent="", endpoint=""):
        if source_ip.startswith(("127.", "::1", "10.", "192.168.")):
            return OriginCategory.LOCAL_USER
        return OriginCategory.REMOTE_API

    def detect_injections(self, text):
        findings = []
        text_lower = text.lower()
        for inject_type, patterns in self._patterns.items():
            for pattern in patterns:
                idx = text_lower.find(pattern.lower())
                if idx >= 0:
                    findings.append((inject_type, idx))
        return findings

    def sanitize(self, text, mask_sensitive=True):
        if mask_sensitive:
            import re
            text = re.sub(r'\\b\\d{16}\\b', '****-****-****-****', text)
        return text

    def is_safe(self, text):
        findings = self.detect_injections(text)
        return len(findings) == 0, findings

def sanitize_input(text, classifier=None):
    c = classifier or InputClassifier()
    return c.sanitize(text)
