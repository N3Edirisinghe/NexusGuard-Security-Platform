from pydantic import BaseModel, field_validator
from security.waf_engine import WAFEngine
import re

# Instantiate WAF engine for use in validators
waf = WAFEngine()

class SecureMessage(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def check_security(cls, v: str) -> str:
        # Behavioral Heuristic: Check for potential injection in Pydantic tier
        threat = waf.check_value(v)
        if threat:
            raise ValueError(f"Security validation failed: {threat}")
        
        # Additional heuristic: check for excessive special characters (potential obfuscation)
        special_chars = len(re.findall(r'[<>{}\[\];]', v))
        if special_chars > 10:
            raise ValueError("Potential injection obfuscation detected")
            
        return v

class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        # Usernames should be alphanumeric + underscores
        if not re.match(r"^\w+$", v):
            raise ValueError("Username must be alphanumeric")
        return v
