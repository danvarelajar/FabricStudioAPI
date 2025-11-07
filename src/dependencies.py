"""FastAPI dependencies for common operations"""
from fastapi import Depends, HTTPException, Query, Request
from typing import Optional
from .app import get_access_token_from_request
from .config import Config

def get_access_token_dependency(
    request: Request,
    fabric_host: str = Query(..., description="Fabric host address")
) -> str:
    """
    Dependency to extract and validate access token from request.
    
    Raises:
        HTTPException: If token is missing or invalid
    """
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    return token

def get_fabric_host_dependency(
    fabric_host: str = Query(..., description="Fabric host address")
) -> str:
    """
    Dependency to validate fabric host format.
    
    Raises:
        HTTPException: If host format is invalid
    """
    from .app import validate_fabric_host
    return validate_fabric_host(fabric_host)

def get_template_params_dependency(
    template_name: str = Query(..., description="Template name"),
    repo_name: str = Query(..., description="Repository name"),
    version: str = Query(..., description="Template version")
):
    """
    Dependency to validate template parameters.
    
    Returns:
        Tuple of (template_name, repo_name, version)
    """
    from .app import validate_template_name, validate_version
    
    # Validate template name
    validated_template_name = validate_template_name(template_name)
    
    # Validate version
    validated_version = validate_version(version)
    
    # Validate repo_name (basic check)
    if not repo_name or not repo_name.strip():
        raise HTTPException(400, "Repository name is required")
    repo_name = repo_name.strip()
    
    return validated_template_name, repo_name, validated_version

