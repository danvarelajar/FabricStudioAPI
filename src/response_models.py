"""Pydantic response models for API endpoints"""
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

# Common response models
class StatusResponse(BaseModel):
    """Standard status response"""
    status: str
    message: Optional[str] = None

class ErrorResponse(BaseModel):
    """Error response model"""
    detail: str
    errors: Optional[List[str]] = None

# NHI Credential models
class NhiCredentialResponse(BaseModel):
    """NHI credential response (without sensitive data)"""
    id: int
    name: str
    fabric_hosts: str
    client_id: str
    # Note: client_secret excluded for security

class NhiListResponse(BaseModel):
    """List of NHI credentials"""
    credentials: List[NhiCredentialResponse]

class NhiSaveResponse(BaseModel):
    """Response after saving NHI credential"""
    id: int
    message: str = "NHI credential saved successfully"

# SSH Key models
class SshKeyResponse(BaseModel):
    """SSH key response (without private key)"""
    id: int
    name: str
    public_key: Optional[str] = None
    created_at: str

class SshKeyListResponse(BaseModel):
    """List of SSH keys"""
    keys: List[SshKeyResponse]

class SshKeySaveResponse(BaseModel):
    """Response after saving SSH key"""
    id: int
    message: str = "SSH key saved successfully"

# SSH Command Profile models
class SshCommandProfileResponse(BaseModel):
    """SSH command profile response"""
    id: int
    name: str
    commands: str
    ssh_key_id: Optional[int] = None
    created_at: str

class SshCommandProfileListResponse(BaseModel):
    """List of SSH command profiles"""
    profiles: List[SshCommandProfileResponse]

class SshCommandProfileSaveResponse(BaseModel):
    """Response after saving SSH command profile"""
    id: int
    message: str = "SSH command profile saved successfully"

# Configuration models
class ConfigurationResponse(BaseModel):
    """Configuration response"""
    id: int
    name: str
    configuration_data: Dict[str, Any]
    created_at: str
    updated_at: str

class ConfigurationListResponse(BaseModel):
    """List of configurations"""
    configurations: List[ConfigurationResponse]

class ConfigurationSaveResponse(BaseModel):
    """Response after saving configuration"""
    id: int
    message: str = "Configuration saved successfully"

# Event Schedule models
class EventScheduleResponse(BaseModel):
    """Event schedule response"""
    id: int
    name: str
    event_date: str
    event_time: Optional[str] = None
    configuration_id: int
    auto_run: bool
    created_at: str
    updated_at: str

class EventScheduleListResponse(BaseModel):
    """List of event schedules"""
    events: List[EventScheduleResponse]

class EventScheduleSaveResponse(BaseModel):
    """Response after saving event schedule"""
    id: int
    message: str = "Event schedule saved successfully"

# Session models
class SessionStatusResponse(BaseModel):
    """Session status response"""
    active: bool
    session_id: Optional[str] = None
    expires_at: Optional[str] = None
    nhi_credential_id: Optional[int] = None

class SessionCreateResponse(BaseModel):
    """Response after creating session"""
    session_id: str
    expires_at: str

# Template cache models
class CachedTemplateResponse(BaseModel):
    """Cached template response"""
    repo_id: int
    repo_name: str
    template_id: int
    template_name: str
    version: Optional[str] = None
    cached_at: str

class CachedTemplateListResponse(BaseModel):
    """List of cached templates"""
    templates: List[CachedTemplateResponse]
    count: int

# Run report models
class RunReportResponse(BaseModel):
    """Run report response"""
    run_id: int
    run_type: str  # "event" or "manual"
    status: str
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None

class RunReportListResponse(BaseModel):
    """List of run reports"""
    reports: List[RunReportResponse]

# Health check model
class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    database: str = "ok"
    version: str

