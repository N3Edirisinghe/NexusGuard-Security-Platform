import re
from typing import Dict, List, Optional
import json

class WAFEngine:
    # SQL Injection Patterns
    SQLI_PATTERNS = [
        r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE|EXEC|DESCRIBE).*(FROM|TABLE|INTO|SET|WHERE)",
        r"(?i)--",
        r"(?i)'.*OR.*=.*'",
        r"(?i)\".*OR.*=.*\"",
        r"(?i)WAITFOR\s+DELAY",
        r"(?i)UNION\s+SELECT",
    ]

    # Cross-Site Scripting (XSS) Patterns
    XSS_PATTERNS = [
        r"(?i)<script.*?>.*?</script.*?>",
        r"(?i)javascript:",
        r"(?i)onerror=",
        r"(?i)onload=",
        r"(?i)alert\(",
        r"(?i)eval\(",
        r"(?i)onmouseover=",
    ]

    # Path Traversal Patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"C:\\Windows\\",
        r"/var/www/html",
    ]

    def __init__(self):
        self.sqli_regex = [re.compile(p) for p in self.SQLI_PATTERNS]
        self.xss_regex = [re.compile(p) for p in self.XSS_PATTERNS]
        self.path_regex = [re.compile(p) for p in self.PATH_TRAVERSAL_PATTERNS]

    def check_value(self, value: str) -> Optional[str]:
        """Checks a single string value for malicious patterns."""
        if not isinstance(value, str):
            return None

        for regex in self.sqli_regex:
            if regex.search(value):
                return "SQL Injection Attempt Detected"
        
        for regex in self.xss_regex:
            if regex.search(value):
                return "XSS Attempt Detected"
        
        for regex in self.path_regex:
            if regex.search(value):
                return "Path Traversal Attempt Detected"
        
        return None

    def inspect_payload(self, data: Dict) -> Optional[str]:
        """Recursively inspects a dictionary/list payload."""
        if isinstance(data, dict):
            for k, v in data.items():
                res = self.inspect_payload(v)
                if res: return f"{res} in key '{k}'"
        elif isinstance(data, list):
            for i, v in enumerate(data):
                res = self.inspect_payload(v)
                if res: return f"{res} at index {i}"
        elif isinstance(data, str):
            return self.check_value(data)
        
        return None
