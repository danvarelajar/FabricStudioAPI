"""Utility functions for log sanitization and security"""
import re
from typing import Any

def sanitize_for_logging(data: Any) -> str:
    """
    Remove sensitive patterns from logs to prevent credential leakage.
    
    Args:
        data: The data to sanitize (will be converted to string)
    
    Returns:
        Sanitized string with sensitive data masked
    """
    if data is None:
        return "None"
    
    # Convert to string
    text = str(data)
    
    # Patterns to mask (case-insensitive)
    patterns = [
        # Passwords
        (r'"password"\s*:\s*"[^"]*"', '"password": "***"'),
        (r"'password'\s*:\s*'[^']*'", "'password': '***'"),
        (r'password\s*=\s*[^\s&]+', 'password=***'),
        
        # Client secrets
        (r'"client_secret"\s*:\s*"[^"]*"', '"client_secret": "***"'),
        (r"'client_secret'\s*:\s*'[^']*'", "'client_secret': '***'"),
        (r'client_secret\s*=\s*[^\s&]+', 'client_secret=***'),
        
        # Tokens
        (r'"token"\s*:\s*"[^"]*"', '"token": "***"'),
        (r"'token'\s*:\s*'[^']*'", "'token': '***'"),
        (r'Bearer\s+[A-Za-z0-9\-._~+/]+', 'Bearer ***'),
        (r'access_token\s*=\s*[^\s&]+', 'access_token=***'),
        
        # SSH keys (private keys)
        (r'-----BEGIN\s+\w+\s+PRIVATE KEY-----[\s\S]*?-----END\s+\w+\s+PRIVATE KEY-----', 
         '-----BEGIN *** PRIVATE KEY----- (REDACTED) -----END *** PRIVATE KEY-----'),
        
        # Encryption keys
        (r'"encryption_password"\s*:\s*"[^"]*"', '"encryption_password": "***"'),
        (r"'encryption_password'\s*:\s*'[^']*'", "'encryption_password': '***'"),
        
        # Session keys
        (r'"session_key"\s*:\s*"[^"]*"', '"session_key": "***"'),
        (r"'session_key'\s*:\s*'[^']*'", "'session_key': '***'"),
    ]
    
    # Apply all patterns
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE | re.MULTILINE)
    
    return text

