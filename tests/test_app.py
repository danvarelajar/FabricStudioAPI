"""Basic unit tests for FabricStudio API"""
import pytest
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fastapi.testclient import TestClient
from app import app, validate_fabric_host, validate_template_name, validate_version, validate_name
from fastapi import HTTPException

client = TestClient(app)

def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code in [200, 503]  # May be 503 if DB not initialized in test
    data = response.json()
    assert "status" in data
    assert "timestamp" in data
    assert "version" in data

def test_validate_fabric_host_valid():
    """Test fabric host validation with valid inputs"""
    assert validate_fabric_host("example.com") == "example.com"
    assert validate_fabric_host("192.168.1.1") == "192.168.1.1"
    assert validate_fabric_host("fs1.fortipoc.io") == "fs1.fortipoc.io"

def test_validate_fabric_host_invalid():
    """Test fabric host validation with invalid inputs"""
    with pytest.raises(HTTPException):
        validate_fabric_host("invalid..host")
    with pytest.raises(HTTPException):
        validate_fabric_host("")
    with pytest.raises(HTTPException):
        validate_fabric_host("a" * 256)  # Too long

def test_validate_template_name_valid():
    """Test template name validation with valid inputs"""
    assert validate_template_name("FortiGate") == "FortiGate"
    assert validate_template_name("FortiAppSec Cloud WAF") == "FortiAppSec Cloud WAF"  # Spaces allowed
    assert validate_template_name("Template-v1.0") == "Template-v1.0"

def test_validate_template_name_invalid():
    """Test template name validation with invalid inputs"""
    with pytest.raises(HTTPException):
        validate_template_name("")
    with pytest.raises(HTTPException):
        validate_template_name("a" * 101)  # Too long
    with pytest.raises(HTTPException):
        validate_template_name("@invalid")  # Invalid character

def test_validate_version_valid():
    """Test version validation with valid inputs"""
    assert validate_version("1.0.0") == "1.0.0"
    assert validate_version("1.0") == "1.0"
    assert validate_version("2.1.3-beta") == "2.1.3-beta"

def test_validate_version_invalid():
    """Test version validation with invalid inputs"""
    with pytest.raises(HTTPException):
        validate_version("")
    with pytest.raises(HTTPException):
        validate_version("invalid")
    with pytest.raises(HTTPException):
        validate_version("1")

def test_validate_name_valid():
    """Test name validation with valid inputs"""
    assert validate_name("test-name") == "test-name"
    assert validate_name("test_name") == "test_name"
    assert validate_name("test123") == "test123"

def test_validate_name_invalid():
    """Test name validation with invalid inputs"""
    with pytest.raises(HTTPException):
        validate_name("")
    with pytest.raises(HTTPException):
        validate_name("test name")  # Spaces not allowed
    with pytest.raises(HTTPException):
        validate_name("test@name")  # Invalid character

def test_root_endpoint():
    """Test root endpoint returns index.html"""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")

def test_docs_endpoint():
    """Test OpenAPI docs endpoint"""
    response = client.get("/docs")
    assert response.status_code == 200

def test_openapi_endpoint():
    """Test OpenAPI schema endpoint"""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "openapi" in data
    assert "info" in data

