"""Unit tests for utility functions"""
import sys
from pathlib import Path

import pytest

# Ensure project root is available on sys.path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.utils import sanitize_for_logging

def test_sanitize_for_logging_password():
    """Test password sanitization"""
    data = '{"password": "secret123"}'
    result = sanitize_for_logging(data)
    assert "password" in result
    assert "secret123" not in result
    assert "***" in result

def test_sanitize_for_logging_client_secret():
    """Test client secret sanitization"""
    data = '{"client_secret": "abc123xyz"}'
    result = sanitize_for_logging(data)
    assert "client_secret" in result
    assert "abc123xyz" not in result
    assert "***" in result

def test_sanitize_for_logging_token():
    """Test token sanitization"""
    data = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    result = sanitize_for_logging(data)
    assert "Bearer" in result
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
    assert "***" in result

def test_sanitize_for_logging_ssh_key():
    """Test SSH key sanitization"""
    data = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----'
    result = sanitize_for_logging(data)
    assert "BEGIN" in result
    assert "MIIEpAIBAAKCAQEA" not in result
    assert "REDACTED" in result

def test_sanitize_for_logging_no_sensitive_data():
    """Test sanitization with no sensitive data"""
    data = '{"name": "test", "value": "123"}'
    result = sanitize_for_logging(data)
    assert result == data  # Should remain unchanged

def test_sanitize_for_logging_none():
    """Test sanitization with None"""
    result = sanitize_for_logging(None)
    assert result == "None"

