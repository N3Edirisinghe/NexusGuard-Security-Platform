import pytest
from security.waf_engine import WAFEngine

@pytest.fixture
def engine():
    return WAFEngine()

def test_sqli_detection(engine):
    payloads = [
        "SELECT * FROM users",
        "' OR '1'='1",
        "UNION SELECT password FROM users",
        "DROP TABLE users"
    ]
    for p in payloads:
        assert engine.check_value(p) == "SQL Injection Attempt Detected"

def test_xss_detection(engine):
    payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<body onload=alert(1)>"
    ]
    for p in payloads:
        assert engine.check_value(p) == "XSS Attempt Detected"

def test_path_traversal_detection(engine):
    payloads = [
        "../../etc/passwd",
        "C:\\Windows\\System32",
        "/var/www/html/index.php"
    ]
    for p in payloads:
        assert engine.check_value(p) == "Path Traversal Attempt Detected"

def test_safe_values(engine):
    safe_values = [
        "Hello World",
        "user_123",
        "https://example.com",
        "just a normal sentence."
    ]
    for v in safe_values:
        assert engine.check_value(v) is None

def test_recursive_payload_inspection(engine):
    malicious_data = {
        "user": {
            "name": "Admin",
            "bio": "<script>alert('xss')</script>"
        }
    }
    result = engine.inspect_payload(malicious_data)
    assert "XSS Attempt Detected" in result
    assert "key 'bio'" in result
