from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Header
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from typing import Optional, List
from pydantic import BaseModel
import sqlite3
import json
from datetime import datetime, date, time as dt_time, timedelta, timezone
import paramiko
import io
import threading
import time
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

from fabricstudio.auth import get_access_token
from fabricstudio.fabricstudio_api import (
    query_hostname, change_hostname, get_userId, change_password,
    reset_fabric, batch_delete, refresh_repositories,
    get_template, create_fabric, install_fabric, check_tasks, get_running_task_count,
    get_recent_task_errors,
    list_all_templates, list_templates_for_repo, get_repositoryId, list_repositories
)
import sqlite3
import time
import logging

logger = logging.getLogger(__name__)
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# HTTP request logging middleware removed - now using INFO log handler instead

# Exception handler for request validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error on {request.method} {request.url.path}: {exc.errors()}")
    try:
        body = await request.body()
        logger.error(f"Request body: {body.decode() if body else 'empty'}")
    except Exception as e:
        logger.error(f"Could not read request body: {e}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()}
    )

# Helper function to extract access_token from Authorization header or session
def get_access_token_from_request(request: Request, fabric_host: str = None) -> Optional[str]:
    """
    Extract access_token from session (preferred) or Authorization header (fallback).
    Returns the token string or None if not found.
    """
    # First try session (if fabric_host provided)
    if fabric_host:
        session = get_session_from_request(request)
        if session:
            session_key = get_session_key_temp(session['session_id'])
            if session_key:
                try:
                    tokens = decrypt_tokens_from_session(session['tokens_encrypted'], session_key)
                    token_info = tokens.get(fabric_host)
                    
                    if token_info:
                        # Check if token expired or expiring soon - refresh if needed
                        needs_refresh = False
                        if not is_token_valid(token_info):
                            # Token expired - try to refresh
                            # Token expired - refresh silently
                            needs_refresh = True
                        elif is_token_expiring_soon(token_info, minutes=1):
                            # Token expiring soon - refresh proactively
                            needs_refresh = True
                        
                        if needs_refresh:
                            if refresh_token_for_host(session['session_id'], fabric_host):
                                # Re-read session to get updated tokens
                                updated_session = get_session(session['session_id'])
                                if updated_session:
                                    tokens = decrypt_tokens_from_session(updated_session['tokens_encrypted'], session_key)
                                    token_info = tokens.get(fabric_host)
                                    if token_info and is_token_valid(token_info):
                                        update_session_activity(session['session_id'])
                                        return token_info.get('token')
                                    else:
                                        logger.error(f"Token refresh failed for {fabric_host} - refreshed token still invalid")
                                        return None
                                else:
                                    logger.error(f"Failed to retrieve updated session after refresh")
                                    return None
                            else:
                                logger.error(f"Failed to refresh token for {fabric_host}")
                                return None
                        
                        update_session_activity(session['session_id'])
                        return token_info.get('token')
                except Exception as e:
                    logger.error(f"Error getting token from session: {e}")
    
    # Fallback to Authorization header (backward compatibility)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.replace("Bearer ", "", 1).strip()
    
    return None

# Database setup - use environment variable or default to current directory
DB_PATH = os.environ.get("DB_PATH", "fabricstudio_ui.db")

# Custom logging handler to capture INFO logs to database
class DatabaseLogHandler(logging.Handler):
    """Custom logging handler that writes INFO level logs to database"""
    
    def emit(self, record):
        try:
            # Only log INFO level messages
            if record.levelno == logging.INFO:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                try:
                    # Format log message
                    message = self.format(record)
                    logger_name = record.name
                    level = record.levelname
                    created_at = datetime.now(timezone.utc).isoformat()
                    
                    c.execute('''
                        INSERT INTO app_logs (level, logger_name, message, created_at)
                        VALUES (?, ?, ?, ?)
                    ''', (level, logger_name, message, created_at))
                    conn.commit()
                except Exception:
                    pass
                finally:
                    conn.close()
        except Exception:
            pass

def init_db():
    """Initialize the SQLite database with configurations and event_schedules tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Migrate existing 'description' column to 'name' if it exists
    c.execute("PRAGMA table_info(configurations)")
    columns = [column[1] for column in c.fetchall()]
    if 'description' in columns and 'name' not in columns:
        # Remove UNIQUE constraint if it exists on description, then rename
        # SQLite doesn't support direct constraint removal, so we need to recreate the table
        try:
            c.execute('ALTER TABLE configurations RENAME COLUMN description TO name')
            conn.commit()
        except sqlite3.OperationalError:
            # If rename fails (e.g., due to constraints), create new table and migrate data
            c.execute('''
                CREATE TABLE IF NOT EXISTS configurations_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    config_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            c.execute('INSERT INTO configurations_new (id, name, config_data, created_at, updated_at) SELECT id, description, config_data, created_at, updated_at FROM configurations')
            c.execute('DROP TABLE configurations')
            c.execute('ALTER TABLE configurations_new RENAME TO configurations')
            conn.commit()
    c.execute('''
        CREATE TABLE IF NOT EXISTS event_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            event_date DATE NOT NULL,
            event_time TIME,
            configuration_id INTEGER NOT NULL,
            auto_run INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (configuration_id) REFERENCES configurations(id)
        )
    ''')
    
    # Migrate existing event_schedules table to add event_time column if it doesn't exist
    c.execute("PRAGMA table_info(event_schedules)")
    columns = [column[1] for column in c.fetchall()]
    if 'event_time' not in columns:
        try:
            c.execute('ALTER TABLE event_schedules ADD COLUMN event_time TIME')
            conn.commit()
        except sqlite3.OperationalError as e:
            # Column might already exist or other error
            print(f"Warning: Could not add event_time column: {e}")
    
    # Migrate existing event_schedules table to add auto_run column if it doesn't exist
    if 'auto_run' not in columns:
        try:
            c.execute('ALTER TABLE event_schedules ADD COLUMN auto_run INTEGER DEFAULT 0')
            conn.commit()
        except sqlite3.OperationalError as e:
            print(f"Warning: Could not add auto_run column: {e}")
    
    # Create NHI credentials table
    c.execute('''
        CREATE TABLE IF NOT EXISTS nhi_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            client_id TEXT NOT NULL,
            client_secret_encrypted TEXT NOT NULL,
            tokens_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create NHI tokens table to store tokens per host
    c.execute('''
        CREATE TABLE IF NOT EXISTS nhi_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nhi_credential_id INTEGER NOT NULL,
            fabric_host TEXT NOT NULL,
            token_encrypted TEXT NOT NULL,
            token_expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id) ON DELETE CASCADE,
            UNIQUE(nhi_credential_id, fabric_host)
        )
    ''')
    
    # Create SSH keys table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            private_key_encrypted TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create SSH command profiles table
    c.execute('''
        CREATE TABLE IF NOT EXISTS ssh_command_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            commands TEXT NOT NULL,
            description TEXT,
            ssh_key_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ssh_key_id) REFERENCES ssh_keys(id) ON DELETE SET NULL
        )
    ''')
    
    # Migrate existing ssh_command_profiles table - add ssh_key_id column if it doesn't exist
    c.execute("PRAGMA table_info(ssh_command_profiles)")
    columns = [column[1] for column in c.fetchall()]
    if 'ssh_key_id' not in columns:
        try:
            c.execute('ALTER TABLE ssh_command_profiles ADD COLUMN ssh_key_id INTEGER')
            # Add foreign key constraint (SQLite doesn't support adding FK constraints to existing tables easily,
            # but we can recreate the table if needed, or just document it)
            conn.commit()
        except sqlite3.OperationalError as e:
            print(f"Warning: Could not add ssh_key_id column: {e}")
    
    # Migrate existing nhi_credentials table - remove old token columns if they exist and create nhi_tokens table
    c.execute("PRAGMA table_info(nhi_credentials)")
    columns = [column[1] for column in c.fetchall()]
    
    # If old token columns exist, migrate data to nhi_tokens table
    if 'token_encrypted' in columns and 'token_expires_at' in columns:
        try:
            # Get all credentials with old token data
            c.execute('SELECT id, token_encrypted, token_expires_at FROM nhi_credentials WHERE token_encrypted IS NOT NULL')
            old_tokens = c.fetchall()
            for nhi_id, token_encrypted, token_expires_at in old_tokens:
                # Try to insert into nhi_tokens (host will be empty, we'll handle this)
                # Actually, we can't migrate without knowing the host, so we'll just leave it
                pass
            # Remove old columns (SQLite doesn't support DROP COLUMN easily, so we'll leave them for now)
        except Exception as e:
            print(f"Warning: Could not migrate old token data: {e}")
    
    # Add tokens_json column if it doesn't exist (for backward compatibility)
    if 'tokens_json' not in columns:
        try:
            c.execute('ALTER TABLE nhi_credentials ADD COLUMN tokens_json TEXT')
            conn.commit()
        except sqlite3.OperationalError as e:
            print(f"Warning: Could not add tokens_json column: {e}")
    
    # Create cached templates table (independent of hosts - just a list of unique templates)
    c.execute('''
        CREATE TABLE IF NOT EXISTS cached_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_id TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            template_id TEXT NOT NULL,
            template_name TEXT NOT NULL,
            version TEXT,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(repo_name, template_name, version)
        )
    ''')
    
    # Migrate existing table if it has fabric_host column (drop and recreate)
    c.execute("PRAGMA table_info(cached_templates)")
    columns = [column[1] for column in c.fetchall()]
    if 'fabric_host' in columns:
        try:
            # Drop old table and recreate without fabric_host
            c.execute('DROP TABLE IF EXISTS cached_templates')
            c.execute('''
                CREATE TABLE cached_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id TEXT NOT NULL,
                    repo_name TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    template_name TEXT NOT NULL,
                    version TEXT,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(repo_name, template_name, version)
                )
            ''')
            conn.commit()
        except sqlite3.OperationalError as e:
            print(f"Warning: Could not migrate cached_templates table: {e}")
    
    conn.commit()
    
    # Create table to store encrypted NHI passwords per event (for auto-run)
    # Uses a server-managed secret to encrypt/decrypt
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS event_nhi_passwords (
            event_id INTEGER PRIMARY KEY,
            nhi_credential_id INTEGER NOT NULL,
            password_encrypted TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES event_schedules(id) ON DELETE CASCADE,
            FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id) ON DELETE CASCADE
        )
    ''')
    
    # Create audit_logs table to track all application activities
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user)')
    
    # Create table to store execution records for scheduled events
    c.execute('''
        CREATE TABLE IF NOT EXISTS event_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            message TEXT,
            errors TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            execution_details TEXT,
            FOREIGN KEY (event_id) REFERENCES event_schedules(id) ON DELETE CASCADE
        )
    ''')
    
    # Create sessions table for session-based token management
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            nhi_credential_id INTEGER NOT NULL,
            tokens_encrypted TEXT NOT NULL,
            session_key_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id) ON DELETE CASCADE
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_nhi_credential_id ON sessions(nhi_credential_id)')

    # Create application logs table (replaces http_logs)
    c.execute('''
        CREATE TABLE IF NOT EXISTS app_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            logger_name TEXT,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_app_logs_created_at ON app_logs(created_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_app_logs_level ON app_logs(level)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_app_logs_logger_name ON app_logs(logger_name)')
    
    # Drop old http_logs table if it exists (replaced by app_logs)
    c.execute('DROP TABLE IF EXISTS http_logs')
    
    conn.commit()
    conn.close()

# Encryption/Decryption functions for NHI credentials
def derive_key_from_password(password: str, salt: bytes = None) -> bytes:
    """Derive a Fernet key from a password using PBKDF2"""
    if salt is None:
        # Use a fixed salt for this application (in production, consider storing salt per record)
        salt = b'fabricstudio_nhi_salt_2024'  # Fixed salt for simplicity
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_client_secret(client_secret: str, password: str) -> str:
    """Encrypt client secret using password-derived key"""
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(client_secret.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_client_secret(encrypted_secret: str, password: str) -> str:
    """Decrypt client secret using password-derived key"""
    try:
        key = derive_key_from_password(password)
        fernet = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_secret.encode())
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"Decryption failed. Incorrect password or corrupted data: {str(e)}")

# Server-managed secret for encrypting sensitive data at rest
def _get_server_fernet() -> Fernet:
    secret = os.environ.get('FS_SERVER_SECRET', '').strip()
    if not secret:
        # Warning: for development only. In production, set FS_SERVER_SECRET environment variable.
        logger.warning("FS_SERVER_SECRET not set - using a weak in-process default. Set FS_SERVER_SECRET for security.")
        secret = 'fabricstudio_dev_server_secret'
    key = derive_key_from_password(secret, b'fabricstudio_server_secret_2024')
    return Fernet(key)

def encrypt_with_server_secret(plaintext: str) -> str:
    f = _get_server_fernet()
    enc = f.encrypt(plaintext.encode())
    return base64.urlsafe_b64encode(enc).decode()

def decrypt_with_server_secret(ciphertext_b64: str) -> str:
    f = _get_server_fernet()
    enc_bytes = base64.urlsafe_b64decode(ciphertext_b64.encode())
    dec = f.decrypt(enc_bytes)
    return dec.decode()

# Audit logging helper function
def log_audit(action: str, user: str = None, details: str = None, ip_address: str = None):
    """Log an audit event to the database, with deduplication for fabric creation"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Check for duplicate entries within the last 5 seconds for fabric_created action
        if action == "fabric_created" and details:
            # Extract host, template, and version from details string
            # Format: "host=X template=Y version=Z" or "host=X template=Y version=Z event=W"
            c.execute('''
                SELECT id FROM audit_logs
                WHERE action = ? AND details = ?
                AND created_at > datetime('now', '-5 seconds')
                LIMIT 1
            ''', (action, details))
            if c.fetchone():
                # Duplicate found within 5 seconds, skip logging
                conn.close()
                return
        
        # Use timezone-aware timestamp
        now_utc = datetime.now(timezone.utc)
        c.execute('''
            INSERT INTO audit_logs (action, user, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (action, user, details, ip_address, now_utc.isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}", exc_info=True)

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    # Check for forwarded IP first (for proxies/load balancers)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    # Fallback to direct client
    if request.client:
        return request.client.host
    return "unknown"

# Session Management Functions
def generate_session_id() -> str:
    """Generate a secure random session ID"""
    return secrets.token_urlsafe(32)

def derive_session_key(encryption_password: str, session_id: str) -> bytes:
    """Derive encryption key for session from password and session ID"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode(),
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(encryption_password.encode()))

def hash_session_key(session_key: bytes) -> str:
    """Hash session key for storage (one-way hash)"""
    return hashlib.sha256(session_key).hexdigest()

def encrypt_tokens_for_session(tokens: dict, session_key: bytes) -> str:
    """Encrypt tokens dictionary for storage in session"""
    tokens_json = json.dumps(tokens)
    fernet = Fernet(session_key)
    encrypted = fernet.encrypt(tokens_json.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_tokens_from_session(encrypted_tokens: str, session_key: bytes) -> dict:
    """Decrypt tokens dictionary from session storage"""
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_tokens.encode())
        fernet = Fernet(session_key)
        decrypted = fernet.decrypt(encrypted_bytes)
        return json.loads(decrypted.decode())
    except Exception as e:
        logger.error(f"Error decrypting session tokens: {e}")
        raise ValueError(f"Failed to decrypt session tokens: {e}")

def create_token_info(token_data: dict) -> dict:
    """Create token info dictionary with expiration times"""
    expires_at = datetime.now() + timedelta(seconds=token_data.get('expires_in', 3600))
    refresh_at = expires_at - timedelta(minutes=5)  # Refresh 5 minutes before expiration
    
    return {
        "token": token_data.get('access_token'),
        "expires_at": expires_at.isoformat(),
        "refresh_at": refresh_at.isoformat(),
        "created_at": datetime.now().isoformat()
    }

def is_token_valid(token_info: dict) -> bool:
    """Check if token is still valid"""
    if not token_info:
        return False
    try:
        expires_at = datetime.fromisoformat(token_info.get('expires_at', ''))
        return datetime.now() < expires_at
    except:
        return False

def is_token_expiring_soon(token_info: dict, minutes: int = 5) -> bool:
    """Check if token should be refreshed soon"""
    if not token_info:
        return False
    try:
        refresh_at = datetime.fromisoformat(token_info.get('refresh_at', ''))
        return datetime.now() >= refresh_at
    except:
        return False

def refresh_token_for_host(session_id: str, fabric_host: str) -> bool:
    """Refresh an expired or expiring token for a specific host"""
    try:
        session = get_session(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found for token refresh")
            return False
        
        session_key = get_session_key_temp(session_id)
        if not session_key:
            logger.warning(f"Session key not found for session {session_id}")
            return False
        
        # Decrypt tokens to get credentials
        tokens = decrypt_tokens_from_session(session['tokens_encrypted'], session_key)
        credentials = tokens.get('_credentials')
        
        if not credentials:
            logger.warning(f"No credentials stored in session {session_id} for token refresh")
            return False
        
        client_id = credentials.get('client_id')
        client_secret = credentials.get('client_secret')
        
        if not client_id or not client_secret:
            logger.warning(f"Missing client_id or client_secret in session {session_id}")
            return False
        
        # Get new token from FabricStudio API
        token_data = get_access_token(client_id, client_secret, fabric_host)
        if not token_data or not isinstance(token_data, dict) or not token_data.get("access_token"):
            logger.error(f"Failed to get new token for {fabric_host} in session {session_id}")
            return False
        
        # Update token in session
        tokens[fabric_host] = create_token_info(token_data)
        
        # Re-encrypt and save
        tokens_encrypted = encrypt_tokens_for_session(tokens, session_key)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute('''
                UPDATE sessions 
                SET tokens_encrypted = ?, last_used = CURRENT_TIMESTAMP
                WHERE session_id = ?
            ''', (tokens_encrypted, session_id))
            conn.commit()
            # Token refreshed successfully
            return True
        finally:
            conn.close()
            
    except Exception as e:
        logger.error(f"Error refreshing token for {fabric_host} in session {session_id}: {e}", exc_info=True)
        return False

def calculate_expires_in(expires_at_str: str) -> int:
    """Calculate expires_in seconds from expires_at ISO string"""
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        delta = expires_at - datetime.now()
        return max(0, int(delta.total_seconds()))
    except:
        return 3600  # Default 1 hour

def create_session(nhi_credential_id: int, encryption_password: str, tokens_by_host: dict = None, client_id: str = None, client_secret: str = None) -> tuple:
    """Create a new session and return (session_id, session_key, expires_at)"""
    session_id = generate_session_id()
    session_key = derive_session_key(encryption_password, session_id)
    session_key_hash = hash_session_key(session_key)
    
    # Encrypt tokens if provided
    tokens_to_store = {}
    if tokens_by_host:
        for host, token_info in tokens_by_host.items():
            if isinstance(token_info, dict) and token_info.get('token'):
                expires_in = calculate_expires_in(token_info.get('expires_at', '')) if token_info.get('expires_at') else 3600
                tokens_to_store[host] = create_token_info({
                    'access_token': token_info['token'],
                    'expires_in': expires_in
                })
    
    # Store client credentials for token refresh (encrypted with session_key)
    if client_id and client_secret:
        tokens_to_store['_credentials'] = {
            'client_id': client_id,
            'client_secret': client_secret  # Will be encrypted when stored
        }
    
    tokens_encrypted = encrypt_tokens_for_session(tokens_to_store, session_key)
    
    # Session expires after 1 hour of inactivity
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO sessions 
            (session_id, nhi_credential_id, tokens_encrypted, session_key_hash, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, nhi_credential_id, tokens_encrypted, session_key_hash, expires_at.isoformat()))
        conn.commit()
    finally:
        conn.close()
    
    # Store session key temporarily (in production, use better approach)
    store_session_key_temp(session_id, session_key)
    
    return session_id, session_key, expires_at

def get_session(session_id: str) -> Optional[dict]:
    """Get session data from database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            SELECT session_id, nhi_credential_id, tokens_encrypted, session_key_hash, 
                   created_at, last_used, expires_at
            FROM sessions
            WHERE session_id = ?
        ''', (session_id,))
        row = c.fetchone()
        if not row:
            return None
        
        expires_at_str = row[6]
        expires_at = datetime.fromisoformat(expires_at_str)
        # If naive datetime, assume UTC (from old code)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        # Compare with timezone-aware datetime
        now = datetime.now(timezone.utc)
        if now >= expires_at:
            # Session expired, delete it
            delete_session(session_id)
            return None
        
        return {
            "session_id": row[0],
            "nhi_credential_id": row[1],
            "tokens_encrypted": row[2],
            "session_key_hash": row[3],
            "created_at": row[4],
            "last_used": row[5],
            "expires_at": row[6]  # Return original string, will be formatted in endpoint
        }
    finally:
        conn.close()

def update_session_activity(session_id: str):
    """Update last_used timestamp for session"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            UPDATE sessions 
            SET last_used = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (session_id,))
        conn.commit()
    finally:
        conn.close()

def update_session_tokens(session_id: str, tokens_encrypted: str):
    """Update tokens in session"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            UPDATE sessions 
            SET tokens_encrypted = ?, last_used = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (tokens_encrypted, session_id))
        conn.commit()
    finally:
        conn.close()

def refresh_session(session_id: str) -> Optional[datetime]:
    """Refresh session expiration time"""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            UPDATE sessions 
            SET expires_at = ?, last_used = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (expires_at.isoformat(), session_id))
        conn.commit()
        return expires_at
    finally:
        conn.close()

def delete_session(session_id: str):
    """Delete session from database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        # Remove from temp storage
        if session_id in _session_keys:
            del _session_keys[session_id]
    finally:
        conn.close()

def get_session_from_request(request: Request) -> Optional[dict]:
    """Get session from request cookie"""
    session_id = request.cookies.get("fabricstudio_session")
    if not session_id:
        return None
    return get_session(session_id)

# Store session keys temporarily in memory (will be replaced with better approach)
# In production, consider using Redis or storing encrypted session key
_session_keys: dict[str, bytes] = {}

def store_session_key_temp(session_id: str, session_key: bytes):
    """Temporarily store session key in memory (for testing)"""
    _session_keys[session_id] = session_key

def get_session_key_temp(session_id: str) -> Optional[bytes]:
    """Get temporarily stored session key"""
    return _session_keys.get(session_id)

# Initialize database on startup
init_db()

# Add database handler to root logger after DB is initialized
db_handler = DatabaseLogHandler()
db_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
db_handler.setFormatter(formatter)
logging.getLogger().addHandler(db_handler)

# Adjust allowed origins to your frontend(s)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5500",
        "http://localhost:8001",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the frontend under /frontend (for direct access)
app.mount("/frontend", StaticFiles(directory="frontend", html=True), name="frontend")

# Serve static assets at root paths for index.html references
@app.get("/app.js")
def serve_app_js():
    return FileResponse("frontend/app.js", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

@app.get("/styles.css")
def serve_styles_css():
    return FileResponse("frontend/styles.css", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

@app.get("/Fortinet-logomark-rgb-red.svg")
@app.get("/frontend/images/Fortinet-logomark-rgb-red.svg")
def serve_fortinet_logo():
    import os
    # Try images directory first, then fallback to frontend root
    svg_path = "frontend/images/Fortinet-logomark-rgb-red.svg"
    if not os.path.exists(svg_path):
        svg_path = "frontend/Fortinet-logomark-rgb-red.svg"
    if not os.path.exists(svg_path):
        raise HTTPException(404, "Fortinet logo not found")
    return FileResponse(svg_path, media_type="image/svg+xml", headers={
        "Cache-Control": "public, max-age=3600"
    })

# Root: serve the SPA index
@app.get("/")
def root():
    return FileResponse("frontend/index.html", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

# Global no-cache for HTML/JSON/JS/CSS responses to avoid stale frontend
@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    ct = response.headers.get("content-type", "")
    path = request.url.path
    # Add no-cache headers for frontend files (HTML, JSON, JS, CSS)
    if ("text/html" in ct or "application/json" in ct or 
        "application/javascript" in ct or "text/css" in ct or
        path in {"/", "/frontend/index.html", "/app.js", "/styles.css"} or
        path.startswith("/frontend/")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Serve section HTML files for dynamic loading
@app.get("/frontend/preparation.html")
def serve_preparation():
    return FileResponse("frontend/preparation.html", media_type="text/html")

@app.get("/frontend/configurations.html")
def serve_configurations():
    return FileResponse("frontend/configurations.html", media_type="text/html")

@app.get("/frontend/event-schedule.html")
def serve_event_schedule():
    return FileResponse("frontend/event-schedule.html", media_type="text/html")

@app.get("/frontend/nhi-management.html")
def serve_nhi_management():
    return FileResponse("frontend/nhi-management.html", media_type="text/html")

@app.get("/frontend/ssh-keys.html")
def serve_ssh_keys():
    return FileResponse("frontend/ssh-keys.html", media_type="text/html")

@app.get("/frontend/ssh-command-profiles.html")
def serve_ssh_command_profiles():
    return FileResponse("frontend/ssh-command-profiles.html", media_type="text/html")

@app.get("/frontend/server-logs.html")
def serve_server_logs_page():
    return FileResponse("frontend/server-logs.html", media_type="text/html")

@app.get("/frontend/audit-logs.html")
def serve_audit_logs():
    return FileResponse("frontend/audit-logs.html", media_type="text/html")


class TokenReq(BaseModel):
    client_id: str
    client_secret: str
    fabric_host: str


class HostnameReq(BaseModel):
    fabric_host: str
    hostname: str


class UserPassReq(BaseModel):
    fabric_host: str
    username: str
    new_password: str


class TemplateReq(BaseModel):
    fabric_host: str
    access_token: str
    template_name: str
    repo_name: str
    version: str


class CreateFabricReq(BaseModel):
    fabric_host: str
    template_id: int
    template_name: str
    version: str


class InstallFabricReq(BaseModel):
    fabric_host: str
    template_name: str
    version: str


@app.post("/auth/token")
def auth_token(req: TokenReq):
    token_data = get_access_token(req.client_id, req.client_secret, req.fabric_host)
    if not token_data or not token_data.get("access_token"):
        raise HTTPException(400, "Failed to get token")
    return {
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")  # Seconds until expiration
    }


@app.get("/system/hostname")
def get_hostname(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    value = query_hostname(fabric_host, token)
    if value is None:
        raise HTTPException(400, "Failed to query hostname")
    return {"hostname": value}


@app.post("/system/hostname")
def set_hostname(request: Request, req: HostnameReq):
    token = get_access_token_from_request(request, req.fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    change_hostname(req.fabric_host, token, req.hostname)
    return {"status": "ok"}


@app.post("/user/password")
def set_password(request: Request, req: UserPassReq):
    token = get_access_token_from_request(request, req.fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    user_id = get_userId(req.fabric_host, token, req.username)
    if not user_id:
        raise HTTPException(404, "User not found")
    change_password(req.fabric_host, token, user_id, req.new_password)
    return {"status": "ok"}


@app.post("/runtime/reset")
def runtime_reset(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    reset_fabric(fabric_host, token)
    return {"status": "ok"}


@app.delete("/model/fabric/batch")
def model_batch_delete(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    batch_delete(fabric_host, token)
    return {"status": "ok"}


@app.post("/repo/refresh")
def repo_refresh(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    refresh_repositories(fabric_host, token)
    return {"status": "ok"}


@app.get("/repo/template")
def repo_template(request: Request, fabric_host: str, template_name: str, repo_name: str, version: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    tid = get_template(fabric_host, token, template_name, repo_name, version)
    if tid is None:
        raise HTTPException(404, "Template not found")
    return {"template_id": tid}


@app.post("/model/fabric")
def model_fabric_create(request: Request, req: CreateFabricReq):
    token = get_access_token_from_request(request, req.fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    create_start = datetime.now(timezone.utc)
    result = create_fabric(req.fabric_host, token, req.template_id, req.template_name, req.version)
    create_end = datetime.now(timezone.utc)
    create_duration = (create_end - create_start).total_seconds()
    
    if isinstance(result, tuple):
        success, errors = result
    else:
        # Backward compatibility with old return format
        success = result
        errors = []
    
    if not success:
        try:
            log_audit("fabric_create_error", details=f"host={req.fabric_host} template={req.template_name} version={req.version} errors={' ; '.join(errors) if errors else 'unknown'} duration_s={create_duration:.1f}", ip_address=get_client_ip(request))
        except Exception:
            pass
        error_msg = "Failed to create fabric"
        if errors:
            error_msg += ": " + "; ".join(errors)
        else:
            error_msg += ": creation timed out or encountered an error"
        raise HTTPException(500, error_msg)
    try:
        log_audit("fabric_created", details=f"host={req.fabric_host} template={req.template_name} version={req.version} duration_s={create_duration:.1f}", ip_address=get_client_ip(request))
    except Exception:
        pass
    return {"status": "ok", "message": "Fabric created successfully"}


@app.post("/runtime/fabric/install")
def model_fabric_install(request: Request, req: InstallFabricReq):
    token = get_access_token_from_request(request, req.fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    install_start = datetime.now(timezone.utc)
    result = install_fabric(req.fabric_host, token, req.template_name, req.version)
    install_end = datetime.now(timezone.utc)
    install_duration = (install_end - install_start).total_seconds()
    
    if isinstance(result, tuple):
        success, errors = result
    else:
        # Backward compatibility with old return format
        success = result
        errors = []
    
    if not success:
        try:
            log_audit("fabric_install_error", details=f"host={req.fabric_host} template={req.template_name} version={req.version} errors={' ; '.join(errors) if errors else 'unknown'} duration_s={install_duration:.1f}", ip_address=get_client_ip(request))
        except Exception:
            pass
        error_msg = "Failed to install fabric"
        if errors:
            error_msg += ": " + "; ".join(errors)
        else:
            error_msg += ": installation timed out or encountered an error"
        raise HTTPException(500, error_msg)
    try:
        log_audit("fabric_installed", details=f"host={req.fabric_host} template={req.template_name} version={req.version} duration_s={install_duration:.1f}", ip_address=get_client_ip(request))
    except Exception:
        pass
    return {"status": "ok", "message": "Fabric installed successfully"}


@app.get("/tasks/progress")
def tasks_progress(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    mins = check_tasks(fabric_host, token, display_progress=False)
    return {"elapsed_minutes": mins}


@app.get("/tasks/status")
def tasks_status(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    count = get_running_task_count(fabric_host, token)
    if count is None:
        raise HTTPException(400, "Failed to get task status")
    return {"running_count": count}


@app.get("/tasks/errors")
def tasks_errors(request: Request, fabric_host: str, limit: int = 20, fabric_name: Optional[str] = None, since_timestamp: Optional[str] = None):
    """Get recent task errors from the FabricStudio host"""
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    
    # Parse since_timestamp if provided
    since_dt = None
    if since_timestamp:
        try:
            since_dt = datetime.fromisoformat(since_timestamp.replace('Z', '+00:00'))
        except Exception:
            pass
    
    errors = get_recent_task_errors(fabric_host, token, limit=limit, since_timestamp=since_dt, fabric_name=fabric_name)
    return {"errors": errors, "count": len(errors)}


def _init_db():
    cache_db_path = os.environ.get("CACHE_DB_PATH", "cache.db")
    # In Docker, store cache.db in data directory (same location as main DB)
    if DB_PATH and "/app/data" in DB_PATH:
        cache_db_path = os.path.join(os.path.dirname(DB_PATH), "cache.db")
    elif DB_PATH and DB_PATH != "fabricstudio_ui.db":
        # If DB_PATH is customized, put cache.db in same directory
        cache_db_path = os.path.join(os.path.dirname(DB_PATH), "cache.db")
    conn = sqlite3.connect(cache_db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY,
            name TEXT,
            version TEXT,
            repository_id INTEGER,
            repository_name TEXT,
            raw_json TEXT,
            updated_at INTEGER
        )
        """
    )
    conn.commit()
    return conn


@app.post("/preparation/confirm")
def preparation_confirm(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    # 1) refresh repos (async on host)
    refresh_repositories(fabric_host, token)
    # Wait for background repo refresh tasks to complete to ensure templates are up to date
    try:
        check_tasks(fabric_host, token, display_progress=False)
    except Exception:
        # Best-effort wait; continue even if polling fails
        pass
    # 2) fetch all templates across repos
    templates = list_all_templates(fabric_host, token)
    # 3) store/refresh cache
    conn = _init_db()
    cur = conn.cursor()
    # Only replace cache if we actually fetched templates
    if templates:
        cur.execute("DELETE FROM templates")
    now = int(time.time())
    for t in templates:
        cur.execute(
            "INSERT OR REPLACE INTO templates (id, name, version, repository_id, repository_name, raw_json, updated_at) VALUES (?,?,?,?,?,?,?)",
            (
                t.get('id'), t.get('name'), t.get('version'),
                t.get('repository') or t.get('repository_id'), t.get('repository_name'),
                str(t), now
            )
        )
    conn.commit()
    conn.close()
    return {"count": len(templates)}


@app.get("/cache/templates")
def cache_templates_get():
    conn = _init_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, version, repository_id, repository_name FROM templates")
    rows = cur.fetchall()
    conn.close()
    templates = [
        {
            "template_id": r[0],
            "template_name": r[1],
            "version": r[2],
            "repo_id": r[3],
            "repo_name": r[4],
        }
        for r in rows
    ]
    return {"templates": templates}


class CacheTemplatesReq(BaseModel):
    templates: list


@app.post("/cache/templates")
def cache_templates_post(req: CacheTemplatesReq):
    conn = _init_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM templates")
    now = int(time.time())
    count = 0
    for t in req.templates:
        cur.execute(
            "INSERT OR REPLACE INTO templates (id, name, version, repository_id, repository_name, raw_json, updated_at) VALUES (?,?,?,?,?,?,?)",
            (
                t.get('template_id'), t.get('template_name'), t.get('version'),
                None, t.get('repo_name'), str(t), now
            )
        )
        count += 1
    conn.commit()
    conn.close()
    return {"count": count}


@app.get("/repo/templates/list")
def repo_templates_list(request: Request, fabric_host: str, repo_name: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    repo_id = get_repositoryId(fabric_host, token, repo_name)
    if not repo_id:
        # Fallback: list repos and try case-insensitive/alt-field match
        repos = list_repositories(fabric_host, token)
        target = None
        for r in repos:
            name = (r.get("name") or "").strip()
            code = (r.get("code") or "").strip()
            if name.lower() == repo_name.strip().lower() or code.lower() == repo_name.strip().lower():
                target = r
                break
        if target:
            repo_id = target.get("id")
        if not repo_id:
            raise HTTPException(404, "Repository not found")
    templates = list_templates_for_repo(fabric_host, token, repo_id)
    # Normalize response to include name, version, id
    out = [
        {"id": t.get("id"), "name": t.get("name"), "version": t.get("version")}
        for t in templates
    ]
    return {"templates": out}


@app.get("/repo/remotes")
def repo_remotes(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    repos = list_repositories(fabric_host, token)
    out = [
        {"id": r.get("id"), "name": r.get("name")}
        for r in repos
    ]
    return {"repositories": out}


# Compatibility endpoint used by preparation flow to resolve a single template_id
@app.get("/repo/template")
def repo_template_single(request: Request, fabric_host: str, template_name: str, repo_name: str, version: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    # Resolve repository by name/code (case-insensitive)
    repos = list_repositories(fabric_host, token)
    repo_input = (repo_name or "").strip()
    match = None
    for r in repos:
        name = (r.get("name") or "").strip()
        code = (r.get("code") or "").strip()
        if name.lower() == repo_input.lower() or code.lower() == repo_input.lower():
            match = r
            break
    if not match:
        logger.warning("Repository not found for repo_name='%s'. Available repos: %s", repo_input, [ (r.get('id'), r.get('name')) for r in repos ])
        raise HTTPException(404, "Repository not found")

    rid = match.get("id")
    templates = list_templates_for_repo(fabric_host, token, rid)
    tname_norm = (template_name or "").strip().lower()
    ver_norm = (version or "").strip()
    for t in templates:
        name_norm = (t.get("name") or "").strip().lower()
        ver_val = (t.get("version") or "").strip()
        if name_norm == tname_norm and ver_val == ver_norm:
            return {"template_id": t.get("id")}
    sample = [{"id": x.get("id"), "name": x.get("name"), "version": x.get("version")} for x in templates[:5]]
    logger.warning("Template not found in repo '%s'. Looking for name='%s' version='%s'. Sample: %s", match.get("name"), template_name, version, sample)
    raise HTTPException(404, "Template not found")


# New lightweight proxy endpoints for repository/template metadata
@app.get("/repo/remotes")
def repo_remotes_proxy(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    url = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {
        "Authorization": f"Bearer {token}",
        "Cache-Control": "no-cache",
    }
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        raise HTTPException(400, f"Error listing repositories: {exc}")
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    try:
        data = resp.json()
    except ValueError:
        raise HTTPException(500, "Invalid JSON from repository list")
    objects = data.get("object", [])
    # Return minimal info: id and name
    return {"repositories": [{"id": o.get("id"), "name": o.get("name")} for o in objects]}


@app.get("/repo/templates/list")
def repo_templates_list(request: Request, fabric_host: str, repo_name: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    # Resolve repo id first
    url_repo = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {"Authorization": f"Bearer {token}", "Cache-Control": "no-cache"}
    try:
        r = requests.get(url_repo, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        raise HTTPException(400, f"Error listing repositories: {exc}")
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.text)
    try:
        repo_data = r.json()
    except ValueError:
        raise HTTPException(500, "Invalid JSON from repository list")
    repo_id = None
    for o in repo_data.get("object", []):
        if o.get("name") == repo_name:
            repo_id = o.get("id")
            break
    if repo_id is None:
        raise HTTPException(404, "Repository not found")
    # List templates for repo
    url_tpl = f"https://{fabric_host}/api/v1/system/repository/template?select=repository={repo_id}"
    try:
        t = requests.get(url_tpl, headers=headers, verify=False, timeout=30)
    except requests.RequestException as exc:
        raise HTTPException(400, f"Error listing templates: {exc}")
    if t.status_code != 200:
        raise HTTPException(t.status_code, t.text)
    try:
        tdata = t.json()
    except ValueError:
        raise HTTPException(500, "Invalid JSON from templates list")
    objects = tdata.get("object", [])
    # Return minimal info
    return {"templates": [{"id": o.get("id"), "name": o.get("name"), "version": o.get("version")} for o in objects]}


@app.get("/repo/versions")
def repo_versions(request: Request, fabric_host: str, repo_name: str, template_name: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    # Reuse templates/list and filter versions - need to call with request and token
    # Create a temporary request-like object or call the function directly
    # For now, call the underlying function directly
    repo_id = get_repositoryId(fabric_host, token, repo_name)
    if not repo_id:
        repos = list_repositories(fabric_host, token)
        target = None
        for r in repos:
            name = (r.get("name") or "").strip()
            code = (r.get("code") or "").strip()
            if name.lower() == repo_name.strip().lower() or code.lower() == repo_name.strip().lower():
                target = r
                break
        if target:
            repo_id = target.get("id")
        if not repo_id:
            raise HTTPException(404, "Repository not found")
    templates = list_templates_for_repo(fabric_host, token, repo_id)
    versions = sorted({t.get("version") for t in templates if t.get("name") == template_name and t.get("version")})
    return {"versions": list(versions)}


# Template caching endpoints
class CacheTemplatesReq(BaseModel):
    templates: List[dict]  # List of {repo_id, repo_name, template_id, template_name, version}


@app.post("/cache/templates")
def cache_templates(req: CacheTemplatesReq):
    """Cache templates in the database - purges all existing templates and replaces with new ones"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Purge all existing cached templates
        c.execute('DELETE FROM cached_templates')
        
        # Insert new cached templates (already deduplicated by frontend)
        inserted_count = 0
        for tpl in req.templates:
            repo_id = tpl.get("repo_id")
            repo_name = tpl.get("repo_name")
            template_id = tpl.get("template_id")
            template_name = tpl.get("template_name")
            version = tpl.get("version")
            
            if not all([repo_id, repo_name, template_id, template_name]):
                continue  # Skip invalid entries
            
            try:
                c.execute('''
                    INSERT OR REPLACE INTO cached_templates 
                    (repo_id, repo_name, template_id, template_name, version, cached_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (repo_id, repo_name, template_id, template_name, version))
                inserted_count += 1
            except sqlite3.Error as e:
                print(f"Error inserting template {template_name}: {e}")
                continue
        
        conn.commit()
        return {"message": f"Cached {inserted_count} templates successfully", "count": inserted_count}
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"Error caching templates: {str(e)}")
    finally:
        conn.close()


@app.get("/cache/templates")
def get_cached_templates():
    """Get all cached templates (independent of hosts)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT repo_id, repo_name, template_id, template_name, version, cached_at
            FROM cached_templates
            ORDER BY repo_name, template_name, version
        ''')
        
        rows = c.fetchall()
        templates = [
            {
                "repo_id": row[0],
                "repo_name": row[1],
                "template_id": row[2],
                "template_name": row[3],
                "version": row[4],
                "cached_at": row[5]
            }
            for row in rows
        ]
        return {"templates": templates, "count": len(templates)}
    except Exception as e:
        raise HTTPException(500, f"Error retrieving cached templates: {str(e)}")
    finally:
        conn.close()


# Configuration management endpoints
class SaveConfigReq(BaseModel):
    name: str
    config_data: dict
    id: Optional[int] = None  # Optional ID for updating existing configuration


class ConfigListItem(BaseModel):
    id: int
    name: str
    created_at: str
    updated_at: str


@app.post("/config/save")
def save_config(req: SaveConfigReq, request: Request):
    """Save a configuration with a name, using ID for updates"""
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Name is required")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        if req.id is not None:
            # Update existing configuration by ID
            c.execute('SELECT id FROM configurations WHERE id = ?', (req.id,))
            existing = c.fetchone()
            
            if not existing:
                raise HTTPException(404, f"Configuration with id {req.id} not found")
            
            c.execute('''
                UPDATE configurations 
                SET name = ?, config_data = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (req.name.strip(), json.dumps(req.config_data), req.id))
            action = "updated"
            log_action = "configuration_updated"
        else:
            # Insert new configuration
            c.execute('''
                INSERT INTO configurations (name, config_data, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (req.name.strip(), json.dumps(req.config_data)))
            action = "saved"
            log_action = "configuration_saved"
        
        conn.commit()
        config_id = req.id if req.id is not None else c.lastrowid
        
        # Log audit event
        log_audit(log_action, details=f"Configuration '{req.name}' (ID: {config_id})", ip_address=get_client_ip(request))
        
        return {
            "status": "ok", 
            "message": f"Configuration '{req.name}' {action} successfully",
            "id": config_id
        }
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/config/list")
def list_configs():
    """List all saved configurations"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT id, name, created_at, updated_at
            FROM configurations
            ORDER BY updated_at DESC
        ''')
        rows = c.fetchall()
        return {
            "configurations": [
                {
                    "id": row[0],
                    "name": row[1],
                    "created_at": row[2],
                    "updated_at": row[3]
                }
                for row in rows
            ]
        }
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/config/get/{config_id}")
def get_config(config_id: int):
    """Retrieve a configuration by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT name, config_data, created_at, updated_at
            FROM configurations
            WHERE id = ?
        ''', (config_id,))
        row = c.fetchone()
        
        if not row:
            raise HTTPException(404, f"Configuration with id {config_id} not found")
        
        return {
            "id": config_id,
            "name": row[0],
            "config_data": json.loads(row[1]),
            "created_at": row[2],
            "updated_at": row[3]
        }
    except json.JSONDecodeError:
        raise HTTPException(500, "Invalid configuration data")
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.delete("/config/delete/{config_id}")
def delete_config(config_id: int, request: Request):
    """Delete a configuration by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Get config name before deleting for audit log
        c.execute('SELECT name FROM configurations WHERE id = ?', (config_id,))
        config_row = c.fetchone()
        config_name = config_row[0] if config_row else f"ID {config_id}"
        
        c.execute('DELETE FROM configurations WHERE id = ?', (config_id,))
        conn.commit()
        
        if c.rowcount == 0:
            raise HTTPException(404, f"Configuration with id {config_id} not found")
        
        # Log audit event
        log_audit("configuration_deleted", details=f"Configuration '{config_name}' (ID: {config_id})", ip_address=get_client_ip(request))
        
        return {"status": "ok", "message": f"Configuration {config_id} deleted successfully"}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


# Event Schedule management endpoints
class CreateEventReq(BaseModel):
    name: str
    event_date: str
    event_time: str = None
    configuration_id: int
    auto_run: bool = False
    id: int = None  # Optional ID for updating existing event
    nhi_password: Optional[str] = None  # Optional password to decrypt NHI client secret for auto-run


class EventListItem(BaseModel):
    id: int
    name: str
    event_date: str
    configuration_id: int
    configuration_name: str
    created_at: str
    updated_at: str


@app.post("/event/save")
def save_event(req: CreateEventReq, request: Request):
    """Save an event schedule"""
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Event name is required")
    if not req.event_date:
        raise HTTPException(400, "Event date is required")
    if not req.configuration_id:
        raise HTTPException(400, "Configuration is required")
    
    # Validate that event date/time is not in the past
    try:
        event_time_str = req.event_time if req.event_time else "00:00:00"
        # Normalize time format: HTML5 time input returns HH:MM, but we need HH:MM:SS
        if event_time_str and len(event_time_str.split(':')) == 2:
            event_time_str = event_time_str + ":00"
        event_datetime_str = f"{req.event_date} {event_time_str}"
        event_datetime = datetime.strptime(event_datetime_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        if event_datetime < now:
            raise HTTPException(400, "Event date and time cannot be in the past")
    except ValueError as e:
        raise HTTPException(400, f"Invalid date/time format: {str(e)}")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Verify configuration exists
        c.execute('SELECT id, name FROM configurations WHERE id = ?', (req.configuration_id,))
        config = c.fetchone()
        if not config:
            raise HTTPException(404, f"Configuration with id {req.configuration_id} not found")
        
        if req.id is not None:
            # Update existing event
            c.execute('SELECT id FROM event_schedules WHERE id = ?', (req.id,))
            existing = c.fetchone()
            
            if not existing:
                raise HTTPException(404, f"Event with id {req.id} not found")
            
            c.execute('''
                UPDATE event_schedules 
                SET name = ?, event_date = ?, event_time = ?, configuration_id = ?, auto_run = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (req.name.strip(), req.event_date, req.event_time, req.configuration_id, 1 if req.auto_run else 0, req.id))
            
            # Clear execution records when event is updated so badge returns to green
            c.execute('DELETE FROM event_executions WHERE event_id = ?', (req.id,))
            
            action = "updated"
            event_id = req.id
        else:
            # Insert new event
            c.execute('''
                INSERT INTO event_schedules (name, event_date, event_time, configuration_id, auto_run, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (req.name.strip(), req.event_date, req.event_time, req.configuration_id, 1 if req.auto_run else 0))
            action = "saved"
            event_id = c.lastrowid
        
        # If an NHI password was provided, find the configuration's NHI credential and store password encrypted
        try:
            if req.nhi_password and req.nhi_password.strip():
                # Load configuration to extract nhiCredentialId
                c.execute('SELECT config_data FROM configurations WHERE id = ?', (req.configuration_id,))
                cfg_row = c.fetchone()
                if cfg_row:
                    cfg = json.loads(cfg_row[0])
                    nhi_cred_id = cfg.get('nhiCredentialId')
                    if nhi_cred_id:
                        pwd_enc = encrypt_with_server_secret(req.nhi_password.strip())
                        # Upsert into event_nhi_passwords
                        c.execute('''
                            INSERT INTO event_nhi_passwords (event_id, nhi_credential_id, password_encrypted, updated_at)
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(event_id) DO UPDATE SET
                                nhi_credential_id=excluded.nhi_credential_id,
                                password_encrypted=excluded.password_encrypted,
                                updated_at=CURRENT_TIMESTAMP
                        ''', (event_id, int(nhi_cred_id), pwd_enc))
                    else:
                        logger.warning(f"Configuration {req.configuration_id} has no nhiCredentialId; skipping password store")
        except Exception as e:
            logger.error(f"Error storing NHI password for event {event_id}: {e}", exc_info=True)
        
        conn.commit()
        
        # Log audit event
        log_action = "event_created" if action == "saved" else "event_updated"
        config_name = config[1] if config else f"ID {req.configuration_id}"
        log_audit(log_action, details=f"Event '{req.name}' (ID: {event_id}) - Configuration: {config_name}", ip_address=get_client_ip(request))
        
        return {"status": "ok", "message": f"Event '{req.name}' {action} successfully", "id": event_id}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/event/list")
def list_events():
    """List all event schedules"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT 
                e.id, 
                e.name, 
                e.event_date, 
                e.event_time,
                e.configuration_id,
                e.auto_run,
                c.name as configuration_name,
                e.created_at, 
                e.updated_at,
                (SELECT COUNT(*) FROM event_executions WHERE event_id = e.id) as execution_count
            FROM event_schedules e
            LEFT JOIN configurations c ON e.configuration_id = c.id
            ORDER BY e.event_date ASC, COALESCE(e.event_time, '') ASC, e.name ASC
        ''')
        rows = c.fetchall()
        events_list = []
        for row in rows:
            execution_count = row[9] if row[9] is not None else 0
            events_list.append({
                "id": row[0],
                "name": row[1],
                "event_date": row[2],
                "event_time": row[3] if row[3] else None,
                "configuration_id": row[4],
                "auto_run": bool(row[5]),
                "configuration_name": row[6] if row[6] else "Unknown",
                "created_at": row[7],
                "updated_at": row[8],
                "has_executions": execution_count > 0
            })
        return {"events": events_list}
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        print(f"Error in list_events: {error_detail}")
        raise HTTPException(500, f"Error listing events: {str(e)}")
    finally:
        conn.close()


@app.get("/event/get/{event_id}")
def get_event(event_id: int):
    """Retrieve an event by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT 
                e.name, 
                e.event_date, 
                e.event_time,
                e.configuration_id,
                e.auto_run,
                c.name as configuration_name,
                e.created_at, 
                e.updated_at
            FROM event_schedules e
            LEFT JOIN configurations c ON e.configuration_id = c.id
            WHERE e.id = ?
        ''', (event_id,))
        row = c.fetchone()
        
        if not row:
            raise HTTPException(404, f"Event with id {event_id} not found")
        
        return {
            "id": event_id,
            "name": row[0],
            "event_date": row[1],
            "event_time": row[2] if row[2] else None,
            "configuration_id": row[3],
            "auto_run": bool(row[4]),
            "configuration_name": row[5] if row[5] else "Unknown",
            "created_at": row[6],
            "updated_at": row[7]
        }
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.delete("/event/delete/{event_id}")
def delete_event(event_id: int, request: Request):
    """Delete an event by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Get event name before deleting for audit log
        c.execute('SELECT name FROM event_schedules WHERE id = ?', (event_id,))
        event_row = c.fetchone()
        event_name = event_row[0] if event_row else f"ID {event_id}"
        
        c.execute('DELETE FROM event_schedules WHERE id = ?', (event_id,))
        conn.commit()
        
        if c.rowcount == 0:
            raise HTTPException(404, f"Event with id {event_id} not found")
        
        # Log audit event
        log_audit("event_deleted", details=f"Event '{event_name}' (ID: {event_id})", ip_address=get_client_ip(request))
        
        return {"status": "ok", "message": f"Event {event_id} deleted successfully"}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/event/executions/{event_id}")
def get_event_executions(event_id: int):
    """Get all execution records for an event"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Verify event exists
        c.execute('SELECT id, name FROM event_schedules WHERE id = ?', (event_id,))
        event_row = c.fetchone()
        if not event_row:
            raise HTTPException(404, f"Event with id {event_id} not found")
        
        # Get all executions for this event
        c.execute('''
            SELECT 
                id,
                status,
                message,
                errors,
                started_at,
                completed_at,
                execution_details
            FROM event_executions
            WHERE event_id = ?
            ORDER BY started_at DESC
        ''', (event_id,))
        rows = c.fetchall()
        
        executions = []
        for row in rows:
            exec_id, status, message, errors_json, started_at, completed_at, details_json = row
            errors = json.loads(errors_json) if errors_json else []
            details = json.loads(details_json) if details_json else {}
            
            executions.append({
                "id": exec_id,
                "status": status,
                "message": message or "",
                "errors": errors,
                "started_at": started_at,
                "completed_at": completed_at,
                "execution_details": details
            })
        
        return {
            "event_id": event_id,
            "event_name": event_row[1],
            "executions": executions
        }
    except HTTPException:
        raise
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


# Auto-run execution endpoint
@app.post("/event/execute/{event_id}")
def execute_event(event_id: int, background_tasks: BackgroundTasks):
    """Execute an event's configuration automatically"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Get event and its configuration
        c.execute('''
            SELECT e.configuration_id, c.config_data, e.name
            FROM event_schedules e
            JOIN configurations c ON e.configuration_id = c.id
            WHERE e.id = ? AND e.auto_run = 1
        ''', (event_id,))
        row = c.fetchone()
        
        if not row:
            raise HTTPException(404, f"Event with id {event_id} not found or auto_run is disabled")
        
        config_id, config_data_json, event_name = row
        config_data = json.loads(config_data_json)
        
        # Execute synchronously to return detailed status
        result = run_configuration(config_data, event_name, event_id)
        if isinstance(result, dict):
            return result
        return {"status": "ok", "message": f"Event '{event_name}' executed"}
    except json.JSONDecodeError:
        raise HTTPException(500, "Invalid configuration data")
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


def run_configuration(config_data: dict, event_name: str, event_id: Optional[int] = None):
    """Execute a configuration (same logic as frontend Run button)"""
    
    execution_record_id = None
    started_at = datetime.now(timezone.utc)
    
    try:
        errors = []
        
        # Create execution record in database
        if event_id is not None:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                c.execute('''
                    INSERT INTO event_executions (event_id, status, started_at)
                    VALUES (?, ?, ?)
                ''', (event_id, 'running', started_at.isoformat()))
                execution_record_id = c.lastrowid
                conn.commit()
                # Audit: event run started
                try:
                    log_audit(
                        "event_run_started",
                        details=f"event_id={event_id} event_name={event_name}",
                        ip_address=None
                    )
                except Exception:
                    pass
            except sqlite3.Error as e:
                logger.error(f"Failed to create execution record: {e}")
            finally:
                conn.close()
        # Extract configuration data
        hosts = config_data.get('confirmedHosts', [])
        if not hosts:
            logger.warning(f"No hosts configured for event {event_name}")
            completed_at = datetime.now(timezone.utc)
            if execution_record_id is not None:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                try:
                    c.execute('''
                        UPDATE event_executions
                        SET status = ?, message = ?, errors = ?, completed_at = ?
                        WHERE id = ?
                    ''', (
                        'error',
                        "No hosts configured",
                        json.dumps(["No hosts configured"]),
                        completed_at.isoformat(),
                        execution_record_id
                    ))
                    conn.commit()
                except sqlite3.Error as e:
                    logger.error(f"Failed to update execution record: {e}")
                finally:
                    conn.close()
            return {"status": "error", "message": "No hosts configured", "errors": ["No hosts configured"], "event": event_name}
        
        client_id = config_data.get('clientId', '')
        client_secret = config_data.get('clientSecret', '')
        new_hostname = config_data.get('newHostname', '')
        new_password = config_data.get('chgPass', '')
        templates_list = config_data.get('templates', [])
        install_select = config_data.get('installSelect', '')
        
        # If client_secret missing, try retrieving from stored NHI password and credential
        if not client_secret and event_id is not None:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                # Get stored password and related credential id
                c.execute('SELECT nhi_credential_id, password_encrypted FROM event_nhi_passwords WHERE event_id = ?', (event_id,))
                row = c.fetchone()
                if row:
                    nhi_cred_id, pwd_enc = row
                    nhi_password = decrypt_with_server_secret(pwd_enc)
                    # Fetch encrypted client secret and client_id
                    c.execute('SELECT client_id, client_secret_encrypted FROM nhi_credentials WHERE id = ?', (nhi_cred_id,))
                    cred = c.fetchone()
                    if cred:
                        client_id_db, client_secret_encrypted = cred
                        if not client_id:
                            client_id = client_id_db or client_id
                        if client_secret_encrypted:
                            client_secret = decrypt_client_secret(client_secret_encrypted, nhi_password)
                conn.close()
            except Exception as e:
                logger.error(f"Event '{event_name}': Failed to retrieve/decrypt client secret for event {event_id}: {e}", exc_info=True)

        # Step 1: Get tokens for all hosts (reuse stored if valid, otherwise fetch new)
        host_tokens = {}
        
        # Check if we have NHI credential ID to look up stored tokens
        nhi_cred_id = None
        nhi_password = None
        if event_id is not None:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('SELECT nhi_credential_id, password_encrypted FROM event_nhi_passwords WHERE event_id = ?', (event_id,))
                nhi_row = c.fetchone()
                if nhi_row:
                    nhi_cred_id = nhi_row[0]
                    nhi_password = decrypt_with_server_secret(nhi_row[1])
                conn.close()
            except Exception as e:
                logger.warning(f"Event '{event_name}': Could not retrieve NHI credential info: {e}")
        
        for host_info in hosts:
            host = host_info.get('host', '')
            token_fetched = False
            
            # First, try to reuse stored token from NHI credential if available
            if nhi_cred_id and nhi_password:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute('SELECT token_encrypted, token_expires_at FROM nhi_tokens WHERE nhi_credential_id = ? AND fabric_host = ?', (nhi_cred_id, host))
                    token_row = c.fetchone()
                    if token_row:
                        token_encrypted, token_expires_at_str = token_row
                        if token_expires_at_str:
                            expires_at = datetime.fromisoformat(token_expires_at_str)
                            now = datetime.now()
                            if expires_at > now:
                                # Token is still valid, reuse it
                                decrypted_token = decrypt_client_secret(token_encrypted, nhi_password)
                                host_tokens[host] = decrypted_token
                                delta = expires_at - now
                                hours = int(delta.total_seconds() // 3600)
                                minutes = int((delta.total_seconds() % 3600) // 60)
                                token_fetched = True
                    conn.close()
                except Exception as e:
                    logger.warning(f"Event '{event_name}': Error checking stored token for {host}: {e}, will fetch new token")
            
            # If no valid stored token, fetch a new one
            if not token_fetched:
                try:
                    token_data = get_access_token(client_id, client_secret, host)
                    if token_data and token_data.get("access_token"):
                        host_tokens[host] = token_data.get("access_token")
                        
                        # Store the new token in nhi_tokens if we have NHI credential
                        if nhi_cred_id and nhi_password:
                            try:
                                expires_in = token_data.get("expires_in")
                                if expires_in:
                                    expires_at = datetime.now() + timedelta(seconds=expires_in)
                                    token_expires_at = expires_at.isoformat()
                                    token_encrypted = encrypt_client_secret(token_data.get("access_token"), nhi_password)
                                    
                                    conn = sqlite3.connect(DB_PATH)
                                    c = conn.cursor()
                                    c.execute('''
                                        INSERT OR REPLACE INTO nhi_tokens 
                                        (nhi_credential_id, fabric_host, token_encrypted, token_expires_at, updated_at)
                                        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                                    ''', (nhi_cred_id, host, token_encrypted, token_expires_at))
                                    conn.commit()
                                    conn.close()
                            except Exception as e:
                                logger.warning(f"Event '{event_name}': Failed to store token for {host}: {e}")
                    else:
                        msg = f"Failed to acquire token for host {host}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                        completed_at = datetime.now(timezone.utc)
                        if execution_record_id is not None:
                            conn = sqlite3.connect(DB_PATH)
                            c = conn.cursor()
                            try:
                                c.execute('''
                                    UPDATE event_executions
                                    SET status = ?, message = ?, errors = ?, completed_at = ?
                                    WHERE id = ?
                                ''', (
                                    'error',
                                    msg,
                                    json.dumps(errors),
                                    completed_at.isoformat(),
                                    execution_record_id
                                ))
                                conn.commit()
                            except sqlite3.Error as db_err:
                                logger.error(f"Failed to update execution record: {db_err}")
                            finally:
                                conn.close()
                        return {"status": "error", "message": msg, "errors": errors, "event": event_name}
                except Exception as e:
                    msg = f"Error acquiring token for host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
                    completed_at = datetime.now(timezone.utc)
                    if execution_record_id is not None:
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        try:
                            c.execute('''
                                UPDATE event_executions
                                SET status = ?, message = ?, errors = ?, completed_at = ?
                                WHERE id = ?
                            ''', (
                                'error',
                                msg,
                                json.dumps(errors),
                                completed_at.isoformat(),
                                execution_record_id
                            ))
                            conn.commit()
                        except sqlite3.Error as db_err:
                            logger.error(f"Failed to update execution record: {db_err}")
                        finally:
                            conn.close()
                    return {"status": "error", "message": msg, "errors": errors, "event": event_name}
        
        # Step 2: Execute preparation steps
        
        # Refresh repositories
        for host in host_tokens.keys():
            try:
                refresh_repositories(host, host_tokens[host])
            except Exception as e:
                msg = f"Error refreshing repositories on host {host}: {e}"
                logger.error(f"Event '{event_name}': {msg}")
                errors.append(msg)
        
        # Uninstall workspaces (reset)
        for host in host_tokens.keys():
            try:
                reset_fabric(host, host_tokens[host])
            except Exception as e:
                msg = f"Error uninstalling workspaces on host {host}: {e}"
                logger.error(f"Event '{event_name}': {msg}")
                errors.append(msg)
        
        # Remove workspaces (batch delete)
        for host in host_tokens.keys():
            try:
                batch_delete(host, host_tokens[host])
            except Exception as e:
                msg = f"Error removing workspaces on host {host}: {e}"
                logger.error(f"Event '{event_name}': {msg}")
                errors.append(msg)
        
        # Change hostname if provided
        if new_hostname:
            for i, host in enumerate(host_tokens.keys()):
                try:
                    hostname = f"{new_hostname}{i + 1}"
                    change_hostname(host, host_tokens[host], hostname)
                except Exception as e:
                    msg = f"Error changing hostname on host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
        
        # Change password if provided
        if new_password:
            for host in host_tokens.keys():
                try:
                    # Resolve user id for 'guest' first
                    user_id = get_userId(host, host_tokens[host], 'guest')
                    if not user_id:
                        msg = f"Guest user not found on host {host}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                        continue
                    change_password(host, host_tokens[host], user_id, new_password)
                except Exception as e:
                    msg = f"Error changing password on host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
        
        # Step 3: Create all workspace templates
        fabric_creation_details = []  # Track fabric creation details
        failed_hosts = set()  # Track hosts that failed during creation
        if templates_list:
            for template_info in templates_list:
                template_name = template_info.get('template_name', '')
                repo_name = template_info.get('repo_name', '')
                version = template_info.get('version', '')
                
                if not (template_name and repo_name and version):
                    continue
                
                # Check for running tasks before creating
                for host in host_tokens.keys():
                    try:
                        running_count = get_running_task_count(host, host_tokens[host])
                        if running_count > 0:
                            check_tasks(host, host_tokens[host], display_progress=False)
                    except Exception as e:
                        msg = f"Error checking tasks on host {host}: {e}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                
                # Create template on all hosts
                for host in host_tokens.keys():
                    # Skip hosts that have already failed
                    if host in failed_hosts:
                        continue
                    
                    try:
                        # Get template ID
                        template_id = get_template(host, host_tokens[host], template_name, repo_name, version)
                        if template_id:
                            # Create fabric (pass template name and version per API signature)
                            fabric_create_start = datetime.now(timezone.utc)
                            result = create_fabric(host, host_tokens[host], template_id, template_name, version)
                            fabric_create_end = datetime.now(timezone.utc)
                            fabric_duration = (fabric_create_end - fabric_create_start).total_seconds()
                            
                            if isinstance(result, tuple):
                                success, task_errors = result
                            else:
                                success = result
                                task_errors = []
                            
                            # Track fabric creation details
                            fabric_creation_details.append({
                                "host": host,
                                "template_name": template_name,
                                "repo_name": repo_name,
                                "version": version,
                                "success": success,
                                "duration_seconds": fabric_duration,
                                "created_at": fabric_create_start.isoformat(),
                                "errors": task_errors if task_errors else None
                            })
                            
                            if success:
                                # Log audit event for fabric creation in scheduled event
                                try:
                                    log_audit("fabric_created", details=f"host={host} template={template_name} version={version} event={event_name} duration_s={fabric_duration:.1f}", ip_address=None)
                                except Exception:
                                    pass
                            else:
                                # Mark host as failed - will skip this host for remaining templates and installation
                                failed_hosts.add(host)
                                if task_errors:
                                    msg = f"Failed to create template '{template_name}' v{version} on host {host}: " + "; ".join(task_errors)
                                else:
                                    msg = f"Failed to create template '{template_name}' v{version} on host {host}: creation timed out or encountered an error"
                                logger.error(f"Event '{event_name}': {msg}")
                                errors.append(msg)
                                if task_errors:
                                    errors.extend(task_errors)
                                # Continue to next host (this host will be skipped in future templates)
                                continue
                        else:
                            msg = f"Template '{template_name}' v{version} not found on host {host}"
                            logger.error(f"Event '{event_name}': {msg}")
                            errors.append(msg)
                    except Exception as e:
                        # Mark host as failed on exception
                        failed_hosts.add(host)
                        msg = f"Error creating template '{template_name}' v{version} on host {host}: {e}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                
                # Wait for tasks to complete after each template
                for host in host_tokens.keys():
                    try:
                        result = check_tasks(host, host_tokens[host], display_progress=False)
                        if result is not None:
                            elapsed_time, success = result if isinstance(result, tuple) else (result, True)
                            if not success:
                                msg = f"Timed out waiting for tasks on host {host} after template creation"
                                logger.warning(f"Event '{event_name}': {msg}")
                                errors.append(msg)
                    except Exception as e:
                        msg = f"Error waiting for tasks on host {host}: {e}"
                        logger.warning(f"Event '{event_name}': {msg}")
                        errors.append(msg)
        
        # Step 4: Execute SSH Profiles (if selected) BEFORE Install Workspace
        ssh_profile_id = config_data.get('sshProfileId', '')
        ssh_wait_time = config_data.get('sshWaitTime', 0)  # Get wait time from config (default: 0)
        ssh_execution_details = None  # Track SSH execution details
        if ssh_profile_id:
            # Execute SSH profiles before Install Workspace
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                
                try:
                    # Get SSH profile
                    c.execute('''
                        SELECT name, commands, ssh_key_id
                        FROM ssh_command_profiles
                        WHERE id = ?
                    ''', (int(ssh_profile_id),))
                    profile_row = c.fetchone()
                    
                    if profile_row:
                        profile_name = profile_row[0]
                        commands = profile_row[1]
                        ssh_key_id = profile_row[2]
                        
                        # Initialize SSH execution tracking
                        ssh_execution_details = {
                            "profile_id": int(ssh_profile_id),
                            "profile_name": profile_name,
                            "wait_time_seconds": ssh_wait_time,
                            "commands": [cmd.strip() for cmd in commands.split('\n') if cmd.strip()],
                            "hosts": []
                        }
                        
                        if ssh_key_id:
                            # Get SSH key
                            c.execute('''
                                SELECT private_key_encrypted
                                FROM ssh_keys
                                WHERE id = ?
                            ''', (ssh_key_id,))
                            key_row = c.fetchone()
                            
                            if key_row:
                                encrypted_private_key = key_row[0]
                                # Get encryption password from event_nhi_passwords if available
                                encryption_password = None
                                if event_id:
                                    c.execute('''
                                        SELECT password_encrypted
                                        FROM event_nhi_passwords
                                        WHERE event_id = ?
                                    ''', (event_id,))
                                    pwd_row = c.fetchone()
                                    if pwd_row:
                                        encryption_password = decrypt_with_server_secret(pwd_row[0])
                                
                                if encryption_password:
                                    try:
                                        private_key = decrypt_client_secret(encrypted_private_key, encryption_password)
                                        
                                        # Execute SSH commands on each host (skip failed hosts)
                                        for host in host_tokens.keys():
                                            # Skip hosts that failed during template creation
                                            if host in failed_hosts:
                                                logger.info(f"Event '{event_name}': Skipping SSH execution on failed host {host}")
                                                continue
                                            
                                            host_result = {
                                                "host": host,
                                                "success": False,
                                                "commands_executed": 0,
                                                "commands_failed": 0,
                                                "error": None
                                            }
                                            try:
                                                # Parse commands
                                                command_list = [cmd.strip() for cmd in commands.split('\n') if cmd.strip()]
                                                
                                                if command_list:
                                                    ssh_client = paramiko.SSHClient()
                                                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                                                    
                                                    try:
                                                        # Try different key formats
                                                        private_key_obj = None
                                                        try:
                                                            private_key_obj = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
                                                        except:
                                                            try:
                                                                private_key_obj = paramiko.Ed25519Key.from_private_key(io.StringIO(private_key))
                                                            except:
                                                                try:
                                                                    private_key_obj = paramiko.DSSKey.from_private_key(io.StringIO(private_key))
                                                                except:
                                                                    try:
                                                                        private_key_obj = paramiko.ECDSAKey.from_private_key(io.StringIO(private_key))
                                                                    except:
                                                                        private_key_obj = paramiko.ssh_private_key_from_string(private_key)
                                                        
                                                        if private_key_obj:
                                                            ssh_client.connect(
                                                                hostname=host,
                                                                port=22,
                                                                username='admin',
                                                                pkey=private_key_obj,
                                                                timeout=30,
                                                                look_for_keys=False,
                                                                allow_agent=False
                                                            )
                                                            
                                                            # Execute commands
                                                            for cmd in command_list:
                                                                stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=300)
                                                                exit_status = stdout.channel.recv_exit_status()
                                                                stdout_text = stdout.read().decode('utf-8', errors='replace')
                                                                stderr_text = stderr.read().decode('utf-8', errors='replace')
                                                                
                                                                host_result["commands_executed"] += 1
                                                                
                                                                if exit_status != 0:
                                                                    host_result["commands_failed"] += 1
                                                                    msg = f"SSH command '{cmd}' on {host} exited with status {exit_status}"
                                                                    logger.warning(f"Event '{event_name}': {msg}")
                                                                    errors.append(msg)
                                                                
                                                                # Check for error indicators
                                                                output_lower = (stdout_text + stderr_text).lower()
                                                                error_indicators = ['error', 'failed', 'failure', 'exception', 'cannot', 'unable', 'denied']
                                                                if any(indicator in output_lower for indicator in error_indicators):
                                                                    if exit_status == 0:
                                                                        msg = f"Warning: Potential error detected in SSH command '{cmd}' output on {host}"
                                                                        logger.warning(f"Event '{event_name}': {msg}")
                                                                        errors.append(msg)
                                                                
                                                                # Wait after each command (including the last one)
                                                                if ssh_wait_time > 0:
                                                                    time.sleep(ssh_wait_time)
                                                            
                                                            host_result["success"] = host_result["commands_failed"] == 0
                                                    except Exception as e:
                                                        msg = f"Error executing SSH commands on {host}: {e}"
                                                        host_result["error"] = str(e)
                                                        logger.error(f"Event '{event_name}': {msg}")
                                                        errors.append(msg)
                                                    finally:
                                                        ssh_client.close()
                                            except Exception as e:
                                                msg = f"Error connecting via SSH to {host}: {e}"
                                                host_result["error"] = str(e)
                                                logger.error(f"Event '{event_name}': {msg}")
                                                errors.append(msg)
                                            
                                            ssh_execution_details["hosts"].append(host_result)
                                    except ValueError as e:
                                        msg = f"Failed to decrypt SSH key: {e}"
                                        logger.error(f"Event '{event_name}': {msg}")
                                        errors.append(msg)
                                else:
                                    msg = "Encryption password not available for SSH key decryption"
                                    logger.warning(f"Event '{event_name}': {msg}")
                                    errors.append(msg)
                            else:
                                msg = "SSH key not found in database"
                                logger.warning(f"Event '{event_name}': {msg}")
                                errors.append(msg)
                        else:
                            msg = "SSH key not assigned to profile"
                            logger.warning(f"Event '{event_name}': {msg}")
                            errors.append(msg)
                    else:
                        msg = f"SSH command profile with id {ssh_profile_id} not found"
                        logger.warning(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                except sqlite3.Error as e:
                    logger.error(f"Event '{event_name}': Database error loading SSH profile: {e}")
                    errors.append(f"Database error loading SSH profile: {e}")
                finally:
                    conn.close()
            except Exception as e:
                logger.error(f"Event '{event_name}': Error executing SSH profiles: {e}")
                errors.append(f"Error executing SSH profiles: {e}")
        
        # Step 5: Install selected workspace
        installation_details = []  # Track installation details
        if install_select:
            template_name, version = install_select.split('|||')
            # Find repo_name from templates list
            repo_name = ''
            for t in templates_list:
                if t.get('template_name') == template_name and t.get('version') == version:
                    repo_name = t.get('repo_name', '')
                    break
            
            if repo_name:
                # Filter out failed hosts
                available_hosts = [h for h in host_tokens.keys() if h not in failed_hosts]
                
                if not available_hosts:
                    msg = f"All hosts failed during template creation. Skipping installation."
                    logger.warning(f"Event '{event_name}': {msg}")
                    errors.append(msg)
                else:
                    if failed_hosts:
                        failed_host_names = ', '.join(failed_hosts)
                        logger.info(f"Event '{event_name}': Skipping installation on failed hosts: {failed_host_names}. Installing on {len(available_hosts)} remaining host(s).")
                    
                    for host in available_hosts:
                        try:
                            template_id = get_template(host, host_tokens[host], template_name, repo_name, version)
                            if template_id:
                                # install_fabric expects template name and version, not id
                                install_start = datetime.now(timezone.utc)
                                result = install_fabric(host, host_tokens[host], template_name, version)
                                install_end = datetime.now(timezone.utc)
                                install_duration = (install_end - install_start).total_seconds()
                                
                                if isinstance(result, tuple):
                                    success, task_errors = result
                                else:
                                    success = result
                                    task_errors = []
                                
                                # Track installation details
                                installation_details.append({
                                    "host": host,
                                    "template_name": template_name,
                                    "repo_name": repo_name,
                                    "version": version,
                                    "success": success,
                                    "duration_seconds": install_duration,
                                    "installed_at": install_start.isoformat(),
                                    "errors": task_errors if task_errors else None
                                })
                                
                                if success:
                                    # Log audit with duration
                                    try:
                                        log_audit("fabric_installed", details=f"host={host} template={template_name} version={version} event={event_name} duration_s={install_duration:.1f}", ip_address=None)
                                    except Exception:
                                        pass
                                else:
                                    if task_errors:
                                        msg = f"Failed to install workspace '{template_name}' v{version} on host {host}: " + "; ".join(task_errors)
                                    else:
                                        msg = f"Failed to install workspace '{template_name}' v{version} on host {host}: installation timed out or encountered an error"
                                    logger.error(f"Event '{event_name}': {msg}")
                                    errors.append(msg)
                                    if task_errors:
                                        errors.extend(task_errors)
                            else:
                                msg = f"Template '{template_name}' v{version} not found on host {host} for installation"
                                logger.error(f"Event '{event_name}': {msg}")
                                errors.append(msg)
                        except Exception as e:
                            msg = f"Error installing workspace '{template_name}' v{version} on host {host}: {e}"
                            logger.error(f"Event '{event_name}': {msg}")
                            errors.append(msg)
            else:
                msg = f"Repository name not found for template '{template_name}' v{version}"
                logger.warning(f"Event '{event_name}': {msg}")
                errors.append(msg)
        else:
            pass
        
        completed_at = datetime.now(timezone.utc)
        
        # Update execution record in database
        if execution_record_id is not None:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                if errors:
                    status = 'error'
                    message = "Auto-run completed with errors"
                else:
                    status = 'success'
                    message = "Auto-run execution completed successfully"
                
                c.execute('''
                    UPDATE event_executions
                    SET status = ?, message = ?, errors = ?, completed_at = ?, execution_details = ?
                    WHERE id = ?
                ''', (
                    status,
                    message,
                    json.dumps(errors) if errors else None,
                    completed_at.isoformat(),
                    json.dumps({
                        "hosts": [h.get('host') for h in hosts if isinstance(h, dict)] if isinstance(hosts, list) else [],
                        "hosts_count": len(hosts),
                        "templates": [
                            {
                                "repo_name": t.get('repo_name'),
                                "template_name": t.get('template_name'),
                                "version": t.get('version')
                            } for t in (templates_list or []) if isinstance(t, dict)
                        ],
                        "templates_count": len(templates_list),
                        "fabric_creations": fabric_creation_details,
                        "fabric_creations_count": len(fabric_creation_details),
                        "installed": (
                            {
                                "repo_name": repo_name if 'repo_name' in locals() else '',
                                "template_name": template_name if 'template_name' in locals() else '',
                                "version": version if 'version' in locals() else ''
                            } if install_select else None
                        ),
                        "installations": installation_details,
                        "installations_count": len(installation_details),
                        "install_select": install_select,
                        "ssh_profile": ssh_execution_details if ssh_execution_details else None,
                        "duration_seconds": (completed_at - started_at).total_seconds(),
                        "started_at": started_at.isoformat(),
                        "completed_at": completed_at.isoformat()
                    }),
                    execution_record_id
                ))
                conn.commit()
                # Audit: event run finished
                try:
                    duration = int((completed_at - started_at).total_seconds())
                    if errors:
                        log_audit(
                            "event_run_failed",
                            details=f"event_id={event_id} event_name={event_name} duration_s={duration} errors_count={len(errors)}",
                            ip_address=None
                        )
                    else:
                        log_audit(
                            "event_run_succeeded",
                            details=f"event_id={event_id} event_name={event_name} duration_s={duration} hosts_count={len(hosts)}",
                            ip_address=None
                        )
                except Exception:
                    pass
            except sqlite3.Error as e:
                logger.error(f"Failed to update execution record: {e}")
            finally:
                conn.close()
        
        if errors:
            logger.error(f"Auto-run execution completed with errors for event: {event_name}")
            return {"status": "error", "message": "Auto-run completed with errors", "errors": errors, "event": event_name}
        return {"status": "ok", "message": "Auto-run execution completed successfully", "event": event_name}
    except Exception as e:
        logger.error(f"Error executing configuration for event '{event_name}': {e}", exc_info=True)
        
        # Update execution record with error
        completed_at = datetime.now(timezone.utc)
        if execution_record_id is not None:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                c.execute('''
                    UPDATE event_executions
                    SET status = ?, message = ?, errors = ?, completed_at = ?, execution_details = ?
                    WHERE id = ?
                ''', (
                    'error',
                    str(e),
                    json.dumps([str(e)]),
                    completed_at.isoformat(),
                    json.dumps({
                        "hosts": [h.get('host') for h in hosts] if 'hosts' in locals() and isinstance(hosts, list) else [],
                        "templates": [
                            {
                                "repo_name": t.get('repo_name'),
                                "template_name": t.get('template_name'),
                                "version": t.get('version')
                            } for t in (templates_list or []) if isinstance(t, dict)
                        ] if 'templates_list' in locals() else [],
                        "install_select": install_select if 'install_select' in locals() else '',
                        "ssh_profile": ssh_execution_details if 'ssh_execution_details' in locals() and ssh_execution_details else None,
                        "duration_seconds": (completed_at - started_at).total_seconds()
                    }),
                    execution_record_id
                ))
                conn.commit()
                # Audit: event run failed (exception path)
                try:
                    duration = int((completed_at - started_at).total_seconds())
                    log_audit(
                        "event_run_failed",
                        details=f"event_id={event_id} event_name={event_name} duration_s={duration} error={str(e)}",
                        ip_address=None
                    )
                except Exception:
                    pass
            except sqlite3.Error as db_err:
                logger.error(f"Failed to update execution record with error: {db_err}")
            finally:
                conn.close()
        
        return {"status": "error", "message": str(e), "errors": [str(e)], "event": event_name}


# SSH Keys Management endpoints

class SaveSshKeyReq(BaseModel):
    id: Optional[int] = None
    name: str
    public_key: str
    private_key: Optional[str] = None  # Optional for updates
    encryption_password: str

@app.post("/ssh-keys/save")
def save_ssh_key(req: SaveSshKeyReq):
    """Save or update an SSH key"""
    import re
    
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Name is required")
    
    # Validate name: alphanumeric, dash, underscore only
    name_stripped = req.name.strip()
    if not re.match(r'^[a-zA-Z0-9_-]+$', name_stripped):
        raise HTTPException(400, "Name must contain only alphanumeric characters, dashes, and underscores")
    
    if not req.public_key or not req.public_key.strip():
        raise HTTPException(400, "Public key is required")
    
    if not req.encryption_password or not req.encryption_password.strip():
        raise HTTPException(400, "Encryption password is required")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        encrypted_private_key = None
        provided_private_key = (req.private_key or '').strip()
        
        if req.id is None:
            # Create requires a private key
            if not provided_private_key:
                raise HTTPException(400, "Private key is required for creating a new SSH key")
            encrypted_private_key = encrypt_client_secret(provided_private_key, req.encryption_password)
        else:
            # Update - use provided private key if given, otherwise keep existing
            if provided_private_key:
                encrypted_private_key = encrypt_client_secret(provided_private_key, req.encryption_password)
            else:
                # Keep existing encrypted private key
                c.execute('SELECT private_key_encrypted FROM ssh_keys WHERE id = ?', (req.id,))
                existing_row = c.fetchone()
                if not existing_row:
                    raise HTTPException(404, f"SSH key with id {req.id} not found")
                encrypted_private_key = existing_row[0]
        
        if req.id is not None:
            # Update existing SSH key
            c.execute('SELECT id FROM ssh_keys WHERE id = ?', (req.id,))
            if not c.fetchone():
                raise HTTPException(404, f"SSH key with id {req.id} not found")
            
            # Check for duplicate name (excluding current key)
            c.execute('SELECT id FROM ssh_keys WHERE name = ? AND id != ?', (name_stripped, req.id))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
            
            c.execute('''
                UPDATE ssh_keys 
                SET name = ?, public_key = ?, private_key_encrypted = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (name_stripped, req.public_key.strip(), encrypted_private_key, req.id))
            action = "updated"
            ssh_key_id = req.id
        else:
            # Insert new SSH key - check for duplicate name
            c.execute('SELECT id FROM ssh_keys WHERE name = ?', (name_stripped,))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
            
            c.execute('''
                INSERT INTO ssh_keys (name, public_key, private_key_encrypted, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (name_stripped, req.public_key.strip(), encrypted_private_key))
            action = "saved"
            ssh_key_id = c.lastrowid
        
        conn.commit()
        # Audit
        try:
            log_audit(
                "ssh_key_created" if action == "saved" else "ssh_key_updated",
                details=f"ssh_key_id={ssh_key_id} name={name_stripped}"
            )
        except Exception:
            pass
        return {"status": "ok", "message": f"SSH key {action} successfully", "id": ssh_key_id}
    except sqlite3.IntegrityError as e:
        conn.rollback()
        if "UNIQUE constraint" in str(e):
            raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
        raise HTTPException(500, f"Database constraint error: {str(e)}")
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

class GetSshKeyReq(BaseModel):
    encryption_password: str

@app.post("/ssh-keys/get/{ssh_key_id}")
async def get_ssh_key(ssh_key_id: int, request: Request):
    """Retrieve an SSH key by ID without returning the private key"""
    try:
        body = await request.json()
        encryption_password = body.get("encryption_password", "").strip() if body else ""
        
        if not encryption_password:
            raise HTTPException(400, "Encryption password is required")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            c.execute('''
                SELECT name, public_key, created_at, updated_at
                FROM ssh_keys
                WHERE id = ?
            ''', (ssh_key_id,))
            row = c.fetchone()
            
            if not row:
                raise HTTPException(404, f"SSH key with id {ssh_key_id} not found")
            
            result = {
                "id": ssh_key_id,
                "name": row[0],
                "public_key": row[1],
                "created_at": row[2],
                "updated_at": row[3]
            }
            
            return JSONResponse(result)
        except HTTPException:
            raise
        except sqlite3.Error as e:
            raise HTTPException(500, f"Database error: {str(e)}")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_ssh_key endpoint: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")

@app.get("/ssh-keys/list")
def list_ssh_keys():
    """List all SSH keys (without decrypting private keys)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT id, name, public_key, created_at, updated_at
            FROM ssh_keys
            ORDER BY name ASC
        ''')
        rows = c.fetchall()
        keys = []
        for row in rows:
            keys.append({
                "id": row[0],
                "name": row[1],
                "public_key": row[2],
                "created_at": row[3],
                "updated_at": row[4]
            })
        return {"keys": keys}
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.delete("/ssh-keys/delete/{ssh_key_id}")
def delete_ssh_key(ssh_key_id: int):
    """Delete an SSH key"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('SELECT id FROM ssh_keys WHERE id = ?', (ssh_key_id,))
        if not c.fetchone():
            raise HTTPException(404, f"SSH key with id {ssh_key_id} not found")
        
        c.execute('DELETE FROM ssh_keys WHERE id = ?', (ssh_key_id,))
        conn.commit()
        # Audit
        try:
            log_audit("ssh_key_deleted", details=f"ssh_key_id={ssh_key_id}")
        except Exception:
            pass
        return {"status": "ok", "message": "SSH key deleted successfully"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Error deleting SSH key: {e}")
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

# SSH Command Profiles Management endpoints

class SaveSshCommandProfileReq(BaseModel):
    id: Optional[int] = None
    name: str
    commands: str
    description: Optional[str] = None
    ssh_key_id: Optional[int] = None

@app.post("/ssh-command-profiles/save")
def save_ssh_command_profile(req: SaveSshCommandProfileReq):
    """Save or update an SSH command profile"""
    import re
    
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Name is required")
    
    # Validate name: alphanumeric, dash, underscore only
    name_stripped = req.name.strip()
    if not re.match(r'^[a-zA-Z0-9_-]+$', name_stripped):
        raise HTTPException(400, "Name must contain only alphanumeric characters, dashes, and underscores")
    
    if not req.commands or not req.commands.strip():
        raise HTTPException(400, "Commands are required")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        if req.id is not None:
            # Update existing profile
            c.execute('SELECT id FROM ssh_command_profiles WHERE id = ?', (req.id,))
            if not c.fetchone():
                raise HTTPException(404, f"SSH command profile with id {req.id} not found")
            
            # Check for duplicate name (excluding current profile)
            c.execute('SELECT id FROM ssh_command_profiles WHERE name = ? AND id != ?', (name_stripped, req.id))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
            
            c.execute('''
                UPDATE ssh_command_profiles 
                SET name = ?, commands = ?, description = ?, ssh_key_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (name_stripped, req.commands.strip(), req.description.strip() if req.description else None, req.ssh_key_id, req.id))
            action = "updated"
            profile_id = req.id
        else:
            # Insert new profile - check for duplicate name
            c.execute('SELECT id FROM ssh_command_profiles WHERE name = ?', (name_stripped,))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
            
            c.execute('''
                INSERT INTO ssh_command_profiles (name, commands, description, ssh_key_id, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (name_stripped, req.commands.strip(), req.description.strip() if req.description else None, req.ssh_key_id))
            action = "saved"
            profile_id = c.lastrowid
        
        conn.commit()
        # Audit
        try:
            log_audit(
                "ssh_profile_created" if action == "saved" else "ssh_profile_updated",
                details=f"profile_id={profile_id} name={name_stripped} ssh_key_id={req.ssh_key_id or ''}"
            )
        except Exception:
            pass
        return {"status": "ok", "message": f"SSH command profile {action} successfully", "id": profile_id}
    except sqlite3.IntegrityError as e:
        conn.rollback()
        if "UNIQUE constraint" in str(e):
            raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
        raise HTTPException(500, f"Database constraint error: {str(e)}")
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.get("/ssh-command-profiles/get/{profile_id}")
def get_ssh_command_profile(profile_id: int):
    """Retrieve an SSH command profile by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT name, commands, description, ssh_key_id, created_at, updated_at
            FROM ssh_command_profiles
            WHERE id = ?
        ''', (profile_id,))
        row = c.fetchone()
        
        if not row:
            raise HTTPException(404, f"SSH command profile with id {profile_id} not found")
        
        # Get SSH key name if ssh_key_id exists
        ssh_key_name = None
        if row[3]:  # ssh_key_id
            c.execute('SELECT name FROM ssh_keys WHERE id = ?', (row[3],))
            key_row = c.fetchone()
            if key_row:
                ssh_key_name = key_row[0]
        
        result = {
            "id": profile_id,
            "name": row[0],
            "commands": row[1],
            "description": row[2] or "",
            "ssh_key_id": row[3],
            "ssh_key_name": ssh_key_name or "",
            "created_at": row[4],
            "updated_at": row[5]
        }
        
        return result
    except HTTPException:
        raise
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.get("/ssh-command-profiles/list")
def list_ssh_command_profiles():
    """List all SSH command profiles"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT p.id, p.name, p.commands, p.description, p.ssh_key_id, p.created_at, p.updated_at, k.name as ssh_key_name
            FROM ssh_command_profiles p
            LEFT JOIN ssh_keys k ON p.ssh_key_id = k.id
            ORDER BY p.name ASC
        ''')
        rows = c.fetchall()
        profiles = []
        for row in rows:
            profiles.append({
                "id": row[0],
                "name": row[1],
                "commands": row[2],
                "description": row[3] or "",
                "ssh_key_id": row[4],
                "ssh_key_name": row[7] or "",
                "created_at": row[5],
                "updated_at": row[6]
            })
        return {"profiles": profiles}
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.delete("/ssh-command-profiles/delete/{profile_id}")
def delete_ssh_command_profile(profile_id: int):
    """Delete an SSH command profile"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('SELECT id FROM ssh_command_profiles WHERE id = ?', (profile_id,))
        if not c.fetchone():
            raise HTTPException(404, f"SSH command profile with id {profile_id} not found")
        
        c.execute('DELETE FROM ssh_command_profiles WHERE id = ?', (profile_id,))
        conn.commit()
        # Audit
        try:
            log_audit("ssh_profile_deleted", details=f"profile_id={profile_id}")
        except Exception:
            pass
        return {"status": "ok", "message": "SSH command profile deleted successfully"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Error deleting SSH command profile: {e}")
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

# SSH Profile Execution endpoints

class ExecuteSshProfileReq(BaseModel):
    fabric_host: str
    ssh_profile_id: int
    ssh_port: int = 22
    encryption_password: str
    wait_time_seconds: int = 0  # Wait time between commands (default: 0)

@app.post("/ssh-profiles/execute")
async def execute_ssh_profile(req: ExecuteSshProfileReq):
    """Execute SSH commands from a profile on a fabric host"""
    try:
        # Get SSH profile
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            c.execute('''
                SELECT commands, ssh_key_id
                FROM ssh_command_profiles
                WHERE id = ?
            ''', (req.ssh_profile_id,))
            profile_row = c.fetchone()
            
            if not profile_row:
                raise HTTPException(404, f"SSH command profile with id {req.ssh_profile_id} not found")
            
            commands = profile_row[0]
            ssh_key_id = profile_row[1]
            
            if not ssh_key_id:
                raise HTTPException(400, "SSH command profile must have an SSH key pair assigned")
            
            # Get SSH key details
            c.execute('''
                SELECT name, private_key_encrypted
                FROM ssh_keys
                WHERE id = ?
            ''', (ssh_key_id,))
            key_row = c.fetchone()
            
            if not key_row:
                raise HTTPException(404, f"SSH key with id {ssh_key_id} not found")
            
            key_name = key_row[0]
            encrypted_private_key = key_row[1]
            
            if not req.encryption_password or not req.encryption_password.strip():
                raise HTTPException(400, "Encryption password is required to decrypt SSH private key")
            
            # Decrypt private key
            try:
                private_key = decrypt_client_secret(encrypted_private_key, req.encryption_password)
            except ValueError as e:
                raise HTTPException(400, f"Failed to decrypt SSH key: {str(e)}")
            
            # Execute SSH commands
            # Parse commands (one per line)
            command_list = [cmd.strip() for cmd in commands.split('\n') if cmd.strip()]
            
            if not command_list:
                raise HTTPException(400, "No commands found in SSH profile")
            
            # Execute commands via SSH
            output_lines = []
            error_lines = []
            success = True
            
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                # Create key object from private key string - try different formats
                private_key_obj = None
                try:
                    # Try RSA key
                    private_key_obj = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
                except:
                    try:
                        # Try Ed25519 key
                        private_key_obj = paramiko.Ed25519Key.from_private_key(io.StringIO(private_key))
                    except:
                        try:
                            # Try DSA key
                            private_key_obj = paramiko.DSSKey.from_private_key(io.StringIO(private_key))
                        except:
                            try:
                                # Try ECDSA key
                                private_key_obj = paramiko.ECDSAKey.from_private_key(io.StringIO(private_key))
                            except:
                                # Last resort: try parsing as OpenSSH format
                                try:
                                    private_key_obj = paramiko.ssh_private_key_from_string(private_key)
                                except Exception as e:
                                    raise HTTPException(500, f"Failed to parse SSH private key: {str(e)}")
                
                if not private_key_obj:
                    raise HTTPException(500, "Failed to create SSH key object")
                
                # Connect to host
                ssh_client.connect(
                    hostname=req.fabric_host,
                    port=req.ssh_port,
                    username='admin',  # Default FabricStudio username
                    pkey=private_key_obj,
                    timeout=30,
                    look_for_keys=False,
                    allow_agent=False
                )
                
                # Execute each command
                for idx, cmd in enumerate(command_list):
                    stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=300)
                    exit_status = stdout.channel.recv_exit_status()
                    
                    stdout_text = stdout.read().decode('utf-8', errors='replace')
                    stderr_text = stderr.read().decode('utf-8', errors='replace')
                    
                    output_lines.append(f"$ {cmd}")
                    if stdout_text:
                        output_lines.append(stdout_text.rstrip())
                    if stderr_text:
                        error_lines.append(f"Error from '{cmd}': {stderr_text.rstrip()}")
                    
                    # Check for errors in output
                    if exit_status != 0:
                        success = False
                        error_lines.append(f"Command '{cmd}' exited with status {exit_status}")
                    
                    # Check for common error indicators in output
                    output_lower = stdout_text.lower() + stderr_text.lower()
                    error_indicators = ['error', 'failed', 'failure', 'exception', 'cannot', 'unable', 'denied', 'permission denied']
                    if any(indicator in output_lower for indicator in error_indicators):
                        # Don't fail immediately, but note it
                        if exit_status == 0:
                            error_lines.append(f"Warning: Potential error detected in output of '{cmd}'")
                    
                    # Wait after each command (including the last one)
                    if req.wait_time_seconds > 0:
                        import time
                        time.sleep(req.wait_time_seconds)
            
            except paramiko.AuthenticationException as e:
                raise HTTPException(401, f"SSH authentication failed: {str(e)}")
            except paramiko.SSHException as e:
                raise HTTPException(500, f"SSH connection error: {str(e)}")
            except Exception as e:
                raise HTTPException(500, f"Error executing SSH commands: {str(e)}")
            finally:
                ssh_client.close()
            
            output = '\n'.join(output_lines)
            errors = '\n'.join(error_lines) if error_lines else None
            
            if errors:
                success = False
            
            # Audit SSH execution
            try:
                log_audit(
                    "ssh_profile_executed",
                    details=f"host={req.fabric_host} profile_id={req.ssh_profile_id} key_name={key_name} success={success}"
                )
            except Exception:
                pass
            
            return {
                "success": success,
                "output": output,
                "error": errors,
                "key_name": key_name
            }
        
        except HTTPException:
            raise
        except sqlite3.Error as e:
            raise HTTPException(500, f"Database error: {str(e)}")
        finally:
            conn.close()
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in execute_ssh_profile endpoint: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")

# NHI Management endpoints
class SaveNhiReq(BaseModel):
    name: str
    client_id: str
    # For create this is required; for update it's optional and, if omitted, the existing secret is kept
    client_secret: Optional[str] = None
    encryption_password: str
    fabric_hosts: str = None  # Optional space-separated list of fabric hosts for getting tokens
    id: int = None  # Optional ID for updating existing credential


class NhiListItem(BaseModel):
    id: int
    name: str
    client_id: str
    created_at: str
    updated_at: str


class NhiDetailItem(BaseModel):
    id: int
    name: str
    client_id: str
    client_secret: str  # Decrypted
    created_at: str
    updated_at: str


class GetNhiReq(BaseModel):
    encryption_password: str


@app.post("/nhi/save")
def save_nhi(req: SaveNhiReq, request: Request):
    """Save or update an NHI credential"""
    import re
    
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Name is required")
    
    # Validate name: alphanumeric, dash, underscore only
    name_stripped = req.name.strip()
    if not re.match(r'^[a-zA-Z0-9_-]+$', name_stripped):
        raise HTTPException(400, "Name must contain only alphanumeric characters, dashes, and underscores")
    
    if not req.client_id or not req.client_id.strip():
        raise HTTPException(400, "Client ID is required")
    if not req.encryption_password or not req.encryption_password.strip():
        raise HTTPException(400, "Encryption password is required")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Determine operation mode (create vs update) and handle client secret accordingly
        encrypted_secret = None
        provided_client_secret = (req.client_secret or '').strip()
        if req.id is None:
            # Create requires a client secret
            if not provided_client_secret:
                raise HTTPException(400, "Client Secret is required for creating a new credential")
            encrypted_secret = encrypt_client_secret(provided_client_secret, req.encryption_password)
        
        # Get tokens for all fabric_hosts if provided
        # Parse hosts (space-separated)
        hosts_to_process = []
        if req.fabric_hosts and req.fabric_hosts.strip():
            hosts_to_process = [h.strip() for h in req.fabric_hosts.strip().split() if h.strip()]
        
        if req.id is not None:
            # Update existing credential
            c.execute('SELECT id, client_secret_encrypted FROM nhi_credentials WHERE id = ?', (req.id,))
            existing = c.fetchone()
            
            if not existing:
                raise HTTPException(404, f"NHI credential with id {req.id} not found")
            
            # Check if name is already taken by another credential
            c.execute('SELECT id FROM nhi_credentials WHERE name = ? AND id != ?', (name_stripped, req.id))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' is already in use")
            
            # If a new client_secret is provided, update it; otherwise keep existing encrypted secret
            if provided_client_secret:
                encrypted_secret = encrypt_client_secret(provided_client_secret, req.encryption_password)
                c.execute('''
                    UPDATE nhi_credentials 
                    SET name = ?, client_id = ?, client_secret_encrypted = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (name_stripped, req.client_id.strip(), encrypted_secret, req.id))
            else:
                c.execute('''
                    UPDATE nhi_credentials 
                    SET name = ?, client_id = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (name_stripped, req.client_id.strip(), req.id))
            action = "updated"
            nhi_id = req.id
            
            # Delete existing tokens for this credential
            c.execute('DELETE FROM nhi_tokens WHERE nhi_credential_id = ?', (nhi_id,))
        else:
            # Insert new credential - check for duplicate name
            c.execute('SELECT id FROM nhi_credentials WHERE name = ?', (name_stripped,))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
            
            c.execute('''
                INSERT INTO nhi_credentials (name, client_id, client_secret_encrypted, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (name_stripped, req.client_id.strip(), encrypted_secret))
            action = "saved"
            nhi_id = c.lastrowid
        
        # Now store tokens for all hosts
        tokens_stored = 0
        token_errors = []
        if nhi_id and hosts_to_process:
            # Determine the client secret to use for token retrieval
            client_secret_to_use = provided_client_secret
            if not client_secret_to_use:
                # Need to decrypt existing stored secret
                # Fetch encrypted secret if not already available
                if encrypted_secret is None:
                    c.execute('SELECT client_secret_encrypted FROM nhi_credentials WHERE id = ?', (nhi_id,))
                    row_secret = c.fetchone()
                    if not row_secret:
                        raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
                    encrypted_secret_db = row_secret[0]
                else:
                    encrypted_secret_db = encrypted_secret
                try:
                    client_secret_to_use = decrypt_client_secret(encrypted_secret_db, req.encryption_password)
                except ValueError as e:
                    raise HTTPException(400, str(e))
            for fabric_host in hosts_to_process:
                try:
                    token_data = get_access_token(req.client_id.strip(), client_secret_to_use, fabric_host)
                    if token_data and isinstance(token_data, dict) and token_data.get("access_token"):
                        # Encrypt the token using the same encryption password
                        token_encrypted = encrypt_client_secret(token_data.get("access_token"), req.encryption_password)
                        
                        # Calculate expiration time
                        expires_in = token_data.get("expires_in")
                        if expires_in:
                            from datetime import datetime, timedelta
                            expires_at = datetime.now() + timedelta(seconds=expires_in)
                            token_expires_at = expires_at.isoformat()
                            
                            # Insert or update token for this host
                            c.execute('''
                                INSERT OR REPLACE INTO nhi_tokens 
                                (nhi_credential_id, fabric_host, token_encrypted, token_expires_at, updated_at)
                                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                            ''', (nhi_id, fabric_host, token_encrypted, token_expires_at))
                            tokens_stored += 1
                        else:
                            # No expiration time in response
                            error_msg = f"Failed to retrieve token for host {fabric_host}: No expiration time in response"
                            token_errors.append(error_msg)
                            logger.warning(error_msg)
                    else:
                        # Token retrieval failed - get_access_token returned None or invalid response
                        # Check logs for more details, but provide user-friendly message
                        error_msg = f"Host {fabric_host}: Connection timeout or invalid credentials (check hostname and credentials)"
                        token_errors.append(error_msg)
                        logger.warning(f"Failed to retrieve token for host {fabric_host}: get_access_token returned None")
                except Exception as e:
                    # Collect error for this host
                    error_msg = f"Failed to retrieve token for host {fabric_host}: {str(e)}"
                    token_errors.append(error_msg)
                    logger.error(error_msg, exc_info=True)
        
        conn.commit()
        
        message = f"NHI credential '{name_stripped}' {action} successfully"
        if tokens_stored > 0:
            message += f" ({tokens_stored} token(s) stored for {tokens_stored} host(s))"
        elif hosts_to_process:
            message += " (No tokens stored - check hosts and credentials)"
        
        # Log audit event
        log_action = "nhi_credential_created" if action == "saved" else "nhi_credential_updated"
        log_audit(log_action, details=f"NHI credential '{name_stripped}' (ID: {nhi_id})", ip_address=get_client_ip(request))
        
        # Include errors in response if any occurred
        response = {"status": "ok", "message": message, "id": nhi_id}
        if token_errors:
            response["token_errors"] = token_errors
            response["warning"] = f"{len(token_errors)} host(s) failed to retrieve tokens"
        
        return response
    except sqlite3.IntegrityError as e:
        conn.rollback()
        if "UNIQUE constraint" in str(e):
            raise HTTPException(400, f"Name '{name_stripped}' already exists. Names must be unique.")
        raise HTTPException(500, f"Database constraint error: {str(e)}")
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/nhi/list")
def list_nhi():
    """List all NHI credentials (without decrypting secrets)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT id, name, client_id, created_at, updated_at
            FROM nhi_credentials
            ORDER BY name ASC
        ''')
        rows = c.fetchall()
        credentials = []
        for row in rows:
            nhi_id = row[0]
            
            # Get tokens for this credential
            c.execute('''
                SELECT fabric_host, token_expires_at
                FROM nhi_tokens
                WHERE nhi_credential_id = ?
                ORDER BY fabric_host ASC
            ''', (nhi_id,))
            token_rows = c.fetchall()
            
            # Build list of hosts with token info
            hosts_with_tokens = []
            for token_row in token_rows:
                fabric_host = token_row[0]
                token_expires_at = token_row[1]
                
                token_status = "Expired"
                if token_expires_at:
                    try:
                        from datetime import datetime
                        expires_at = datetime.fromisoformat(token_expires_at)
                        now = datetime.now()
                        if expires_at > now:
                            delta = expires_at - now
                            total_seconds = int(delta.total_seconds())
                            hours = total_seconds // 3600
                            minutes = (total_seconds % 3600) // 60
                            if hours > 0:
                                token_status = f"{hours}h {minutes}m"
                            else:
                                token_status = f"{minutes}m"
                    except:
                        pass
                
                hosts_with_tokens.append({
                    "host": fabric_host,
                    "token_lifetime": token_status
                })
            
            credentials.append({
                "id": nhi_id,
                "name": row[1],
                "client_id": row[2],
                "hosts_with_tokens": hosts_with_tokens,
                "created_at": row[3],
                "updated_at": row[4]
            })
        return {"credentials": credentials}
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.post("/nhi/get/{nhi_id}")
async def get_nhi(nhi_id: int, request: Request):
    """Retrieve an NHI credential by ID without returning the client secret"""
    try:
        body = await request.json()
        encryption_password = body.get("encryption_password", "").strip() if body else ""
        
        if not encryption_password:
            raise HTTPException(400, "Encryption password is required")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            c.execute('''
                SELECT name, client_id, client_secret_encrypted, created_at, updated_at
                FROM nhi_credentials
                WHERE id = ?
            ''', (nhi_id,))
            row = c.fetchone()
            
            if not row:
                raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
            
            # Decrypt client_secret for storing in session (needed for token refresh)
            # We don't return it to the frontend, but store it encrypted in the session
            try:
                decrypted_client_secret = decrypt_client_secret(row[2], encryption_password)
            except ValueError as e:
                raise HTTPException(400, str(e))
            
            client_id = row[1]
            
            # Get all tokens for this credential (decrypted)
            c.execute('''
                SELECT fabric_host, token_encrypted, token_expires_at
                FROM nhi_tokens
                WHERE nhi_credential_id = ?
                ORDER BY fabric_host ASC
            ''', (nhi_id,))
            token_rows = c.fetchall()
            
            # Don't return tokens to frontend - they're stored server-side in the session
            # Just collect host list for display purposes
            hosts_with_tokens = []
            for token_row in token_rows:
                fabric_host = token_row[0]
                token_encrypted = token_row[1]
                token_expires_at = token_row[2]
                
                # Check if token is valid (for display purposes only)
                try:
                    from datetime import datetime
                    expires_at = datetime.fromisoformat(token_expires_at)
                    now = datetime.now()
                    if expires_at > now:
                        # Token is valid - add to host list
                        hosts_with_tokens.append(fabric_host)
                except:
                    # If date parsing fails, skip this token
                    pass
            
            result = {
                "id": nhi_id,
                "name": row[0],
                "client_id": row[1],
                # Don't return tokens - they're stored server-side in the session
                "hosts_with_tokens": hosts_with_tokens,  # Just list of hosts that have valid tokens
                "created_at": row[3],
                "updated_at": row[4]
            }
            
            # Create session with tokens and credentials (for automatic token refresh)
            # Decrypt tokens for storing in session
            tokens_by_host_for_session = {}
            for token_row in token_rows:
                fabric_host = token_row[0]
                token_encrypted = token_row[1]
                token_expires_at = token_row[2]
                
                # Decrypt and check if valid for session storage
                try:
                    from datetime import datetime
                    expires_at = datetime.fromisoformat(token_expires_at)
                    now = datetime.now()
                    if expires_at > now:
                        # Token is valid, decrypt it for session storage
                        decrypted_token = decrypt_client_secret(token_encrypted, encryption_password)
                        tokens_by_host_for_session[fabric_host] = {
                            "token": decrypted_token,
                            "expires_at": token_expires_at
                        }
                except:
                    # If decryption or date parsing fails, skip this token
                    pass
            
            session_id, session_key, expires_at = create_session(
                nhi_id, 
                encryption_password, 
                tokens_by_host_for_session,
                client_id=client_id,
                client_secret=decrypted_client_secret
            )
            
            # Create response with cookie
            response = JSONResponse(result)
            response.set_cookie(
                key="fabricstudio_session",
                value=session_id,
                httponly=True,
                secure=False,  # Set to True in production with HTTPS
                samesite="lax",
                max_age=3600,  # 1 hour
                path="/"  # Make cookie available for all paths
            )
            
            return response
        except sqlite3.Error as e:
            raise HTTPException(500, f"Database error: {str(e)}")
        finally:
            conn.close()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_nhi endpoint: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")


@app.post("/nhi/update-token/{nhi_id}")
async def update_nhi_token(request: Request, nhi_id: int):
    """Update or add a token for a specific host in an NHI credential"""
    # Get data from request body only
    try:
        body = await request.json()
    except:
        raise HTTPException(400, "Invalid request body")
    
    fabric_host = body.get("fabric_host")
    token = body.get("token")
    expires_in = body.get("expires_in")
    encryption_password = body.get("encryption_password")
    
    if not encryption_password:
        raise HTTPException(400, "Encryption password is required")
    if not fabric_host or not fabric_host.strip():
        raise HTTPException(400, "Fabric host is required")
    if not token:
        raise HTTPException(400, "Token is required")
    if expires_in is None:
        raise HTTPException(400, "expires_in is required")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Verify the credential exists
        c.execute('SELECT id FROM nhi_credentials WHERE id = ?', (nhi_id,))
        if not c.fetchone():
            raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
        
        # Encrypt the token
        token_encrypted = encrypt_client_secret(token, encryption_password)
        
        # Calculate expiration time
        from datetime import datetime, timedelta
        expires_at = datetime.now() + timedelta(seconds=expires_in)
        token_expires_at = expires_at.isoformat()
        
        # Insert or update token for this host
        c.execute('''
            INSERT OR REPLACE INTO nhi_tokens 
            (nhi_credential_id, fabric_host, token_encrypted, token_expires_at, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (nhi_id, fabric_host.strip(), token_encrypted, token_expires_at))
        
        conn.commit()
        return {"status": "ok", "message": f"Token updated for host {fabric_host}"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.delete("/nhi/delete/{nhi_id}")
def delete_nhi(nhi_id: int):
    """Delete an NHI credential by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('DELETE FROM nhi_credentials WHERE id = ?', (nhi_id,))
        conn.commit()
        
        if c.rowcount == 0:
            raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
        
        # Also delete any sessions for this NHI credential
        c.execute('DELETE FROM sessions WHERE nhi_credential_id = ?', (nhi_id,))
        conn.commit()
        
        return {"status": "ok", "message": f"NHI credential {nhi_id} deleted successfully"}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


# Audit Logs endpoints
@app.get("/audit-logs/list")
def list_audit_logs(action: Optional[str] = None, user: Optional[str] = None, limit: int = 1000):
    """List audit logs with optional filtering"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        query = '''
            SELECT id, action, user, details, ip_address, created_at
            FROM audit_logs
            WHERE 1=1
        '''
        params = []
        
        if action:
            query += ' AND action = ?'
            params.append(action)
        
        if user:
            query += ' AND user LIKE ?'
            params.append(f'%{user}%')
        
        query += ' ORDER BY created_at DESC LIMIT ?'
        params.append(limit)
        
        c.execute(query, params)
        rows = c.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "action": row[1],
                "user": row[2],
                "details": row[3],
                "ip_address": row[4],
                "created_at": row[5]
            })
        
        return {"logs": logs}
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.post("/audit-logs/create")
def create_audit_log(request: Request, action: str, user: Optional[str] = None, details: Optional[str] = None):
    """Create an audit log entry"""
    ip_address = get_client_ip(request)
    log_audit(action, user, details, ip_address)
    return {"status": "ok", "message": "Audit log created"}

@app.get("/audit-logs/export")
def export_audit_logs(action: Optional[str] = None, user: Optional[str] = None):
    """Export audit logs as CSV"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        query = '''
            SELECT action, user, details, ip_address, created_at
            FROM audit_logs
            WHERE 1=1
        '''
        params = []
        
        if action:
            query += ' AND action = ?'
            params.append(action)
        
        if user:
            query += ' AND user LIKE ?'
            params.append(f'%{user}%')
        
        query += ' ORDER BY created_at DESC'
        
        c.execute(query, params)
        rows = c.fetchall()
        
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Action', 'User', 'Details', 'IP Address', 'Created At'])
        
        for row in rows:
            writer.writerow(row)
        
        from fastapi.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
        )
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


# Server Logs endpoints (now shows INFO level application logs)
@app.get("/server-logs/list")
def list_server_logs(level: Optional[str] = None, logger_name: Optional[str] = None, message: Optional[str] = None, limit: int = 1000):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        query = '''
            SELECT id, level, logger_name, message, created_at
            FROM app_logs
            WHERE 1=1
        '''
        params = []
        if level:
            query += ' AND level = ?'
            params.append(level)
        if logger_name:
            query += ' AND logger_name LIKE ?'
            params.append(f'%{logger_name}%')
        if message:
            query += ' AND message LIKE ?'
            params.append(f'%{message}%')
        query += ' ORDER BY id DESC LIMIT ?'
        params.append(limit)
        c.execute(query, params)
        rows = c.fetchall()
        logs = [
            {
                "id": r[0],
                "level": r[1],
                "logger_name": r[2],
                "message": r[3],
                "created_at": r[4],
            } for r in rows
        ]
        return {"logs": logs}
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.get("/server-logs/export")
def export_server_logs(level: Optional[str] = None, logger_name: Optional[str] = None, message: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        query = '''
            SELECT created_at, level, logger_name, message
            FROM app_logs WHERE 1=1
        '''
        params = []
        if level:
            query += ' AND level = ?'
            params.append(level)
        if logger_name:
            query += ' AND logger_name LIKE ?'
            params.append(f'%{logger_name}%')
        if message:
            query += ' AND message LIKE ?'
            params.append(f'%{message}%')
        query += ' ORDER BY id DESC'
        c.execute(query, params)
        rows = c.fetchall()
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Timestamp", "Level", "Logger", "Message"])
        for r in rows:
            w.writerow(r)
        from fastapi.responses import Response
        return Response(content=buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=server_logs.csv"})
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.delete("/nhi/delete/{nhi_id}")
def delete_nhi(nhi_id: int):
    """Delete an NHI credential by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('DELETE FROM nhi_credentials WHERE id = ?', (nhi_id,))
        conn.commit()
        
        if c.rowcount == 0:
            raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
        
        # Also delete any sessions for this NHI credential
        c.execute('DELETE FROM sessions WHERE nhi_credential_id = ?', (nhi_id,))
        conn.commit()
        
        return {"status": "ok", "message": f"NHI credential {nhi_id} deleted successfully"}
    except HTTPException:
        raise
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Error deleting NHI credential: {e}")
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


# Session Management Endpoints
class CreateSessionReq(BaseModel):
    nhi_credential_id: int
    encryption_password: str

@app.post("/auth/session/create")
def create_session_endpoint(req: CreateSessionReq):
    """Create a new session for an NHI credential"""
    if not req.encryption_password or not req.encryption_password.strip():
        raise HTTPException(400, "Encryption password is required")
    
    # Verify NHI credential exists
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('SELECT id FROM nhi_credentials WHERE id = ?', (req.nhi_credential_id,))
        if not c.fetchone():
            raise HTTPException(404, f"NHI credential with id {req.nhi_credential_id} not found")
        
        # Get client_id and client_secret for storing in session (needed for token refresh)
        c.execute('SELECT client_id, client_secret_encrypted FROM nhi_credentials WHERE id = ?', (req.nhi_credential_id,))
        cred_row = c.fetchone()
        if not cred_row:
            raise HTTPException(404, f"NHI credential with id {req.nhi_credential_id} not found")
        
        client_id = cred_row[0]
        try:
            decrypted_client_secret = decrypt_client_secret(cred_row[1], req.encryption_password)
        except ValueError as e:
            raise HTTPException(400, str(e))
        
        # Get tokens for this NHI credential
        tokens_by_host = {}
        c.execute('''
            SELECT fabric_host, token_encrypted, token_expires_at
            FROM nhi_tokens
            WHERE nhi_credential_id = ?
        ''', (req.nhi_credential_id,))
        
        token_rows = c.fetchall()
        now = datetime.now()
        
        for token_row in token_rows:
            fabric_host = token_row[0]
            token_encrypted = token_row[1]
            token_expires_at = token_row[2]
            
            if token_expires_at:
                try:
                    expires_at = datetime.fromisoformat(token_expires_at)
                    if expires_at > now:
                        # Token is still valid, decrypt it
                        try:
                            token = decrypt_client_secret(token_encrypted, req.encryption_password)
                            tokens_by_host[fabric_host] = {
                                "token": token,
                                "expires_at": token_expires_at
                            }
                        except ValueError:
                            # Decryption failed, skip this token
                            pass
                except (ValueError, TypeError):
                    # Invalid date format, skip this token
                    pass
    finally:
        conn.close()
    
    # Create session with tokens and credentials (for automatic token refresh)
    session_id, session_key, expires_at = create_session(
        req.nhi_credential_id, 
        req.encryption_password, 
        tokens_by_host,
        client_id=client_id,
        client_secret=decrypted_client_secret
    )
    
    # Create response with cookie
    response = JSONResponse({
        "session_id": session_id,
        "expires_at": expires_at.isoformat()
    })
    response.set_cookie(
        key="fabricstudio_session",
        value=session_id,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=3600  # 1 hour
    )
    
    return response

@app.get("/auth/session/status")
def get_session_status(request: Request):
    """Get current session status"""
    session = get_session_from_request(request)
    if not session:
        raise HTTPException(401, "No active session")
    
    # Ensure expires_at is properly formatted with timezone info
    expires_at_str = session['expires_at']
    try:
        # Parse and ensure UTC timezone
        if isinstance(expires_at_str, str):
            expires_at = datetime.fromisoformat(expires_at_str)
            # If naive datetime, assume it's UTC (from old code)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at = expires_at_str
        
        # Return ISO format with timezone (JavaScript will parse this correctly)
        expires_at_iso = expires_at.isoformat()
    except Exception as e:
        logger.error(f"Error formatting expires_at: {e}")
        expires_at_iso = expires_at_str
    
    return {
        "session_id": session['session_id'],
        "nhi_credential_id": session['nhi_credential_id'],
        "created_at": session['created_at'],
        "last_used": session['last_used'],
        "expires_at": expires_at_iso
    }

@app.post("/auth/session/refresh")
def refresh_session_endpoint(request: Request):
    """Refresh session expiration time"""
    session = get_session_from_request(request)
    if not session:
        raise HTTPException(401, "No active session")
    
    expires_at = refresh_session(session['session_id'])
    if not expires_at:
        raise HTTPException(500, "Failed to refresh session")
    
    # Update cookie
    response = JSONResponse({
        "session_id": session['session_id'],
        "expires_at": expires_at.isoformat()
    })
    response.set_cookie(
        key="fabricstudio_session",
        value=session['session_id'],
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=3600
    )
    
    return response

@app.post("/auth/session/revoke")
def revoke_session_endpoint(request: Request):
    """Revoke current session"""
    session = get_session_from_request(request)
    if not session:
        return JSONResponse({"status": "ok", "message": "No active session"})
    
    delete_session(session['session_id'])
    
    response = JSONResponse({"status": "ok", "message": "Session revoked"})
    response.delete_cookie("fabricstudio_session")
    
    return response

def refresh_nhi_tokens():
    """Refresh NHI tokens from nhi_tokens table for credentials with stored event passwords"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            now = datetime.now()
            # Check tokens expiring within 5 minutes (or already expired)
            threshold_time = now + timedelta(minutes=5)
            
            # Get all NHI tokens that are expiring soon or already expired
            c.execute('''
                SELECT nhi_credential_id, fabric_host, token_expires_at
                FROM nhi_tokens
                WHERE token_expires_at <= ?
            ''', (threshold_time.isoformat(),))
            
            expiring_tokens = c.fetchall()
            
            if not expiring_tokens:
                return 0  # No tokens to refresh
            
            refreshed_count = 0
            
            # Group tokens by credential ID to batch password lookups
            tokens_by_credential = {}
            for nhi_cred_id, fabric_host, token_expires_at in expiring_tokens:
                if nhi_cred_id not in tokens_by_credential:
                    tokens_by_credential[nhi_cred_id] = []
                tokens_by_credential[nhi_cred_id].append((fabric_host, token_expires_at))
            
            # For each credential, find events with stored passwords
            for nhi_cred_id, tokens in tokens_by_credential.items():
                # Get stored password from any event using this credential
                c.execute('''
                    SELECT password_encrypted
                    FROM event_nhi_passwords
                    WHERE nhi_credential_id = ?
                    LIMIT 1
                ''', (nhi_cred_id,))
                pwd_row = c.fetchone()
                
                if not pwd_row:
                    # No stored password for this credential, skip
                    continue
                
                try:
                    nhi_password = decrypt_with_server_secret(pwd_row[0])
                except Exception as e:
                    logger.warning(f"Failed to decrypt password for NHI credential {nhi_cred_id}: {e}")
                    continue
                
                # Get client credentials
                c.execute('''
                    SELECT client_id, client_secret_encrypted
                    FROM nhi_credentials
                    WHERE id = ?
                ''', (nhi_cred_id,))
                cred_row = c.fetchone()
                
                if not cred_row:
                    continue
                
                client_id, client_secret_encrypted = cred_row
                
                try:
                    client_secret = decrypt_client_secret(client_secret_encrypted, nhi_password)
                except Exception as e:
                    logger.warning(f"Failed to decrypt client secret for NHI credential {nhi_cred_id}: {e}")
                    continue
                
                # Refresh each token for this credential
                for fabric_host, token_expires_at in tokens:
                    try:
                        # Get new token
                        token_data = get_access_token(client_id, client_secret, fabric_host)
                        if token_data and token_data.get("access_token"):
                            expires_in = token_data.get("expires_in")
                            if expires_in:
                                expires_at = datetime.now() + timedelta(seconds=expires_in)
                                token_expires_at_new = expires_at.isoformat()
                                token_encrypted = encrypt_client_secret(token_data.get("access_token"), nhi_password)
                                
                                # Update token in nhi_tokens
                                c.execute('''
                                    UPDATE nhi_tokens 
                                    SET token_encrypted = ?, token_expires_at = ?, updated_at = CURRENT_TIMESTAMP
                                    WHERE nhi_credential_id = ? AND fabric_host = ?
                                ''', (token_encrypted, token_expires_at_new, nhi_cred_id, fabric_host))
                                conn.commit()
                                refreshed_count += 1
                                logger.info(f"Refreshed NHI token for credential {nhi_cred_id}, host {fabric_host}")
                                # Log audit event
                                log_audit("nhi_token_refreshed", details=f"NHI credential {nhi_cred_id}, host {fabric_host}")
                            else:
                                logger.warning(f"No expiration time in token response for credential {nhi_cred_id}, host {fabric_host}")
                        else:
                            logger.warning(f"Failed to get new token for credential {nhi_cred_id}, host {fabric_host}")
                    except Exception as e:
                        logger.warning(f"Error refreshing NHI token for credential {nhi_cred_id}, host {fabric_host}: {e}")
                        continue
            
            return refreshed_count
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error in NHI token refresh task: {e}", exc_info=True)
        return 0

# Background task to refresh expiring tokens proactively
def refresh_expiring_tokens():
    """Background task to refresh tokens that are expiring soon"""
    session_refreshed_count = 0
    nhi_refreshed_count = 0
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            # Get all active sessions
            now = datetime.now()
            c.execute('''
                SELECT session_id, nhi_credential_id, tokens_encrypted, expires_at
                FROM sessions
                WHERE expires_at > ?
            ''', (now.isoformat(),))
            sessions = c.fetchall()
            
            for session_row in sessions:
                session_id = session_row[0]
                tokens_encrypted = session_row[2]
                
                # Get session key
                session_key = get_session_key_temp(session_id)
                if not session_key:
                    continue  # Skip if session key not available
                
                try:
                    # Decrypt tokens
                    tokens = decrypt_tokens_from_session(tokens_encrypted, session_key)
                    
                    # Check each token for expiration
                    for host, token_info in tokens.items():
                        if host == '_credentials':
                            continue  # Skip credentials entry
                        
                        if token_info and is_token_expiring_soon(token_info, minutes=5):
                            # Refresh this token
                            if refresh_token_for_host(session_id, host):
                                session_refreshed_count += 1
                except Exception as e:
                    logger.warning(f"Error processing session {session_id} for token refresh: {e}")
                    continue
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error in proactive token refresh task: {e}", exc_info=True)
    
    # Also refresh NHI tokens from nhi_tokens table
    try:
        nhi_refreshed_count = refresh_nhi_tokens()
    except Exception as e:
        logger.error(f"Error refreshing NHI tokens: {e}", exc_info=True)
    
    if session_refreshed_count > 0 or nhi_refreshed_count > 0:
        logger.debug(f"Token refresh completed: {session_refreshed_count} session tokens, {nhi_refreshed_count} NHI tokens refreshed")

def check_and_run_token_refresh():
    """Background thread to periodically refresh expiring tokens"""
    while True:
        try:
            time.sleep(120)  # Check every 2 minutes
            refresh_expiring_tokens()
        except Exception as e:
            logger.error(f"Error in token refresh scheduler: {e}", exc_info=True)
            time.sleep(60)  # Wait 1 minute before retrying on error

# Track events that have been executed to prevent duplicates
executed_events = set()

# Background scheduler to check for events that need to run
def check_and_run_events():
    """Check for events that should run now and execute them"""
    global executed_events
    
    while True:
        try:
            now = datetime.now()
            current_date = now.date()
            current_time = now.time().replace(second=0, microsecond=0)  # Round to minute
            
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            # Find events that should run now (auto_run enabled, date matches, time matches or no time specified)
            # Compare times by converting to string format HH:MM:SS or HH:MM
            current_time_str = current_time.strftime('%H:%M:%S') if current_time else None
            
            c.execute('''
                SELECT id, name, event_date, event_time
                FROM event_schedules
                WHERE auto_run = 1
                AND event_date = ?
                AND (event_time IS NULL OR event_time = ? OR SUBSTR(event_time, 1, 5) = ?)
            ''', (str(current_date), current_time_str, current_time.strftime('%H:%M') if current_time else None))
            
            events_to_run = c.fetchall()
            
            if events_to_run:
                # Only log if there are events to run
                if len(events_to_run) > 0:
                    pass
            
            # Clean up executed events from previous days
            if events_to_run:
                today_str = str(current_date)
                executed_events = {e for e in executed_events if str(e).startswith(today_str)}
            
            for event_id, event_name, event_date, event_time in events_to_run:
                # Create unique key for this event execution
                event_key = f"{event_date}_{event_time or 'all'}_{event_id}"
                
                # Skip if already executed
                if event_key in executed_events:
                    continue
                
                # Mark as executed before starting (to prevent duplicate if scheduler runs again)
                executed_events.add(event_key)
                
                try:
                    # Execute in background thread
                    thread = threading.Thread(target=execute_event_internal, args=(event_id, event_name))
                    thread.daemon = False  # Keep thread alive until execution completes
                    thread.start()
                except Exception as e:
                    logger.error(f"Error starting execution thread for event {event_id}: {e}", exc_info=True)
                    # Remove from executed set if we failed to start
                    executed_events.discard(event_key)
            
            conn.close()
            
            # Check every 30 seconds for more accurate timing
            time.sleep(30)
            
        except Exception as e:
            logger.error(f"Error in scheduler: {e}", exc_info=True)
            time.sleep(60)


def execute_event_internal(event_id: int, event_name: str = None):
    """Internal function to execute an event"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute('''
            SELECT e.configuration_id, c.config_data, e.name
            FROM event_schedules e
            JOIN configurations c ON e.configuration_id = c.id
            WHERE e.id = ? AND e.auto_run = 1
        ''', (event_id,))
        row = c.fetchone()
        conn.close()
        
        if row:
            config_id, config_data_json, db_event_name = row
            event_name = event_name or db_event_name
            try:
                config_data = json.loads(config_data_json)
            except json.JSONDecodeError as je:
                logger.error(f"Error parsing configuration JSON for event {event_id}: {je}", exc_info=True)
                # Update execution record with error
                completed_at = datetime.now()
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                try:
                    # Find the latest running execution record
                    c.execute('SELECT id FROM event_executions WHERE event_id = ? AND status = ? ORDER BY id DESC LIMIT 1', (event_id, 'running'))
                    exec_row = c.fetchone()
                    if exec_row:
                        c.execute('''
                            UPDATE event_executions
                            SET status = ?, message = ?, errors = ?, completed_at = ?
                            WHERE id = ?
                        ''', (
                            'error',
                            f"Invalid configuration JSON: {str(je)}",
                            json.dumps([f"Invalid configuration JSON: {str(je)}"]),
                            completed_at.isoformat(),
                            exec_row[0]
                        ))
                        conn.commit()
                except sqlite3.Error as db_err:
                    logger.error(f"Failed to update execution record with JSON error: {db_err}")
                finally:
                    conn.close()
                return
            
            try:
                run_configuration(config_data, event_name, event_id)
                pass
            except Exception as run_err:
                logger.error(f"Error in run_configuration for event {event_id}: {run_err}", exc_info=True)
                # Update execution record with error if run_configuration didn't update it
                completed_at = datetime.now()
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                try:
                    # Check if record was already updated (run_configuration might have updated it)
                    c.execute('SELECT id, status FROM event_executions WHERE event_id = ? ORDER BY id DESC LIMIT 1', (event_id,))
                    exec_row = c.fetchone()
                    if exec_row and exec_row[1] == 'running':
                        # Still in running state, update it
                        c.execute('''
                            UPDATE event_executions
                            SET status = ?, message = ?, errors = ?, completed_at = ?
                            WHERE id = ?
                        ''', (
                            'error',
                            f"Execution failed: {str(run_err)}",
                            json.dumps([str(run_err)]),
                            completed_at.isoformat(),
                            exec_row[0]
                        ))
                        conn.commit()
                except sqlite3.Error as db_err:
                    logger.error(f"Failed to update execution record with run error: {db_err}")
                finally:
                    conn.close()
        else:
            logger.warning(f"Event {event_id} not found or auto_run is disabled")
            # Update execution record if it exists
            completed_at = datetime.now()
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                # Find the latest running execution record
                c.execute('SELECT id FROM event_executions WHERE event_id = ? AND status = ? ORDER BY id DESC LIMIT 1', (event_id, 'running'))
                exec_row = c.fetchone()
                if exec_row:
                    c.execute('''
                        UPDATE event_executions
                        SET status = ?, message = ?, errors = ?, completed_at = ?
                        WHERE id = ?
                    ''', (
                        'error',
                        "Event not found or auto_run is disabled",
                        json.dumps(["Event not found or auto_run is disabled"]),
                        completed_at.isoformat(),
                        exec_row[0]
                    ))
                    conn.commit()
            except sqlite3.Error as db_err:
                logger.error(f"Failed to update execution record: {db_err}")
            finally:
                conn.close()
    except Exception as e:
        logger.error(f"Error executing event {event_id}: {e}", exc_info=True)
        # Update execution record with error
        completed_at = datetime.now()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            # Find the latest running execution record
            c.execute('SELECT id FROM event_executions WHERE event_id = ? AND status = ? ORDER BY id DESC LIMIT 1', (event_id, 'running'))
            exec_row = c.fetchone()
            if exec_row:
                c.execute('''
                    UPDATE event_executions
                    SET status = ?, message = ?, errors = ?, completed_at = ?
                    WHERE id = ?
                ''', (
                    'error',
                    f"Execution failed: {str(e)}",
                    json.dumps([str(e)]),
                    completed_at.isoformat(),
                    exec_row[0]
                ))
                conn.commit()
        except sqlite3.Error as db_err:
            logger.error(f"Failed to update execution record with exception: {db_err}")
        finally:
            conn.close()


# Start scheduler in background thread on startup
scheduler_thread = None
token_refresh_thread = None

@app.on_event("startup")
def start_scheduler():
    """Start the background scheduler on application startup"""
    global scheduler_thread, token_refresh_thread
    if scheduler_thread is None or not scheduler_thread.is_alive():
        scheduler_thread = threading.Thread(target=check_and_run_events)
        scheduler_thread.daemon = True  # Allow main process to exit
        scheduler_thread.start()
        pass
    else:
        pass
    
    # Start token refresh background task
    if token_refresh_thread is None or not token_refresh_thread.is_alive():
        token_refresh_thread = threading.Thread(target=check_and_run_token_refresh)
        token_refresh_thread.daemon = True
        token_refresh_thread.start()
        pass
    else:
        pass


