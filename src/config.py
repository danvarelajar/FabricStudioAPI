"""Configuration module for FabricStudio API"""
import os

class Config:
    """Centralized configuration constants"""
    
    # Database Configuration
    DB_PATH = os.environ.get("DB_PATH", "fabricstudio_ui.db")
    DB_TIMEOUT = float(os.environ.get("DB_TIMEOUT", "30.0"))
    DB_MAX_RETRIES = int(os.environ.get("DB_MAX_RETRIES", "5"))
    DB_RETRY_DELAY = float(os.environ.get("DB_RETRY_DELAY", "0.1"))
    DB_MAX_CONNECTIONS = int(os.environ.get("DB_MAX_CONNECTIONS", "20"))
    DB_BACKUP_RETENTION_DAYS = int(os.environ.get("DB_BACKUP_RETENTION_DAYS", "7"))
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
    RATE_LIMIT_CLEANUP_INTERVAL = int(os.environ.get("RATE_LIMIT_CLEANUP_INTERVAL", "300"))
    
    # Per-endpoint rate limits
    RATE_LIMITS = {
        "/auth/token": {"requests": 10, "window": 60},
        "/nhi/save": {"requests": 5, "window": 60},
        "/event/save": {"requests": 5, "window": 60},
        "/ssh-keys/save": {"requests": 5, "window": 60},
        "/ssh-command-profiles/save": {"requests": 5, "window": 60},
    }
    
    # Input Validation Limits
    MAX_HOSTS_PER_CONFIG = 100
    MAX_SSH_COMMAND_LENGTH = 10000
    MAX_SSH_COMMANDS = 100
    MAX_TOTAL_COMMANDS_SIZE = 100000
    
    # SSH Configuration
    SSH_OPERATION_TIMEOUT = int(os.environ.get("SSH_OPERATION_TIMEOUT", "300"))
    
    # Session Configuration
    SESSION_KEY_TTL = int(os.environ.get("SESSION_KEY_TTL", "3600"))  # 1 hour
    MAX_SESSION_KEYS = int(os.environ.get("MAX_SESSION_KEYS", "1000"))
    
    # Audit Log Configuration
    AUDIT_LOG_BATCH_SIZE = int(os.environ.get("AUDIT_LOG_BATCH_SIZE", "50"))
    AUDIT_LOG_BATCH_TIMEOUT = float(os.environ.get("AUDIT_LOG_BATCH_TIMEOUT", "5.0"))
    
    # Cleanup Configuration
    CLEANUP_EXECUTION_RETENTION_DAYS = int(os.environ.get("CLEANUP_EXECUTION_RETENTION_DAYS", "90"))
    
    # Security
    FS_SERVER_SECRET = os.environ.get("FS_SERVER_SECRET", "").strip()
    CSRF_SECRET = os.environ.get("CSRF_SECRET", FS_SERVER_SECRET or "csrf_secret_change_me")
    
    # API Configuration
    API_VERSION = "1.1.0"
    API_TITLE = "FabricStudio API"
    API_DESCRIPTION = "API for managing FabricStudio configurations, events, and SSH operations"
    
    # Frontend Configuration
    FRONTEND_REQUEST_TIMEOUT = int(os.environ.get("FRONTEND_REQUEST_TIMEOUT", "30000"))  # 30 seconds

