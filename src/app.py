from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Header, APIRouter
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional, List
from pydantic import BaseModel
from contextlib import asynccontextmanager
import sqlite3
import json
import random
from datetime import datetime, date, time as dt_time, timedelta, timezone
import paramiko
import io
import threading
import time
import socket
import logging
import queue
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import secrets
import hashlib

# Import configuration and utilities
from .config import Config
from .utils import sanitize_for_logging
from .csrf import CSRFProtectionMiddleware
from .db_utils import get_db_connection, backup_database, backup_database_periodically
from .response_models import HealthResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

from .fabricstudio.auth import get_access_token
from .fabricstudio.fabricstudio_api import (
    query_hostname, change_hostname, get_userId, change_password as change_fabricstudio_password,
    reset_fabric, batch_delete, refresh_repositories,
    get_template, create_fabric, install_fabric, check_tasks, get_running_task_count,
    get_recent_task_errors,
    list_all_templates, list_templates_for_repo, get_repositoryId, list_repositories
)
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Lifespan handler to replace deprecated startup event
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    _start_background_threads()
    yield


# Initialize FastAPI with enhanced OpenAPI documentation
app = FastAPI(
    title=Config.API_TITLE,
    description=Config.API_DESCRIPTION,
    version=Config.API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=app_lifespan,
)

# Create API router for versioning
api_v1 = APIRouter(prefix="/api/v1")

# Rate limiting configuration (using Config)
RATE_LIMIT_REQUESTS = Config.RATE_LIMIT_REQUESTS
RATE_LIMIT_WINDOW = Config.RATE_LIMIT_WINDOW
RATE_LIMIT_CLEANUP_INTERVAL = Config.RATE_LIMIT_CLEANUP_INTERVAL

# Rate limiting storage: {ip: [(timestamp1, timestamp2, ...)]}
_rate_limit_store: dict[str, list[float]] = {}
# Per-endpoint rate limiting: {endpoint: {ip: [(timestamp1, timestamp2, ...)]}}
_endpoint_rate_limit_store: dict[str, dict[str, list[float]]] = {}
_rate_limit_lock = threading.Lock()
_last_cleanup = time.time()

def _cleanup_rate_limit_store():
    """Remove old entries from rate limit store"""
    global _last_cleanup
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    
    with _rate_limit_lock:
        for ip in list(_rate_limit_store.keys()):
            # Remove timestamps older than the window
            _rate_limit_store[ip] = [ts for ts in _rate_limit_store[ip] if ts > cutoff]
            # Remove IPs with no recent requests
            if not _rate_limit_store[ip]:
                del _rate_limit_store[ip]
    
    _last_cleanup = now

def _check_rate_limit(ip: str) -> bool:
    """Check if IP is within rate limit. Returns True if allowed, False if rate limited."""
    global _last_cleanup
    
    # Periodic cleanup
    if time.time() - _last_cleanup > RATE_LIMIT_CLEANUP_INTERVAL:
        _cleanup_rate_limit_store()
    
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    
    with _rate_limit_lock:
        # Get or create request timestamps for this IP
        if ip not in _rate_limit_store:
            _rate_limit_store[ip] = []
        
        # Remove old timestamps
        _rate_limit_store[ip] = [ts for ts in _rate_limit_store[ip] if ts > cutoff]
        
        # Check if limit exceeded
        if len(_rate_limit_store[ip]) >= RATE_LIMIT_REQUESTS:
            return False
        
        # Add current request timestamp
        _rate_limit_store[ip].append(now)
        return True

def _check_rate_limit_for_endpoint(ip: str, endpoint: str, max_requests: int, window: int) -> bool:
    """Check if IP is within rate limit for a specific endpoint."""
    now = time.time()
    cutoff = now - window
    
    with _rate_limit_lock:
        # Initialize endpoint store if needed
        if endpoint not in _endpoint_rate_limit_store:
            _endpoint_rate_limit_store[endpoint] = {}
        
        # Get or create request timestamps for this IP on this endpoint
        if ip not in _endpoint_rate_limit_store[endpoint]:
            _endpoint_rate_limit_store[endpoint][ip] = []
        
        # Remove old timestamps
        _endpoint_rate_limit_store[endpoint][ip] = [
            ts for ts in _endpoint_rate_limit_store[endpoint][ip] if ts > cutoff
        ]
        
        # Check if limit exceeded
        if len(_endpoint_rate_limit_store[endpoint][ip]) >= max_requests:
            return False
        
        # Add current request timestamp
        _endpoint_rate_limit_store[endpoint][ip].append(now)
        return True

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limiting on API endpoints"""
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for static files and frontend routes
        path = request.url.path
        if path.startswith('/static/') or path == '/' or path.endswith(('.html', '.js', '.css', '.woff2', '.svg', '.ico', '.png', '.jpg', '.jpeg')):
            return await call_next(request)
        
        # Get client IP
        ip = get_client_ip(request)
        
        # Check per-endpoint rate limit if configured
        endpoint_limit = Config.RATE_LIMITS.get(path)
        if endpoint_limit:
            # Use stricter limit for this endpoint
            limit_requests = endpoint_limit["requests"]
            limit_window = endpoint_limit["window"]
            if not _check_rate_limit_for_endpoint(ip, path, limit_requests, limit_window):
                logger.warning(f"Rate limit exceeded for IP {ip} on {request.method} {path}")
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": f"Rate limit exceeded. Maximum {limit_requests} requests per {limit_window} seconds for this endpoint."
                    },
                    headers={"Retry-After": str(limit_window)}
                )
        
        # Check global rate limit
        if not _check_rate_limit(ip):
            logger.warning(f"Rate limit exceeded for IP {ip} on {request.method} {path}")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded. Maximum {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds."
                },
                headers={"Retry-After": str(RATE_LIMIT_WINDOW)}
            )
        
        # Process request
        response = await call_next(request)
        return response

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)

# Add CSRF protection middleware (after rate limiting)
app.add_middleware(CSRFProtectionMiddleware)

# Authentication middleware
class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to require authentication for all endpoints except login and static files"""
    async def dispatch(self, request: Request, call_next):
        # Allow access to login, health check, and static files without authentication
        path = request.url.path
        if path in ["/auth/login", "/login", "/health", "/docs", "/redoc", "/openapi.json"] or \
           path.startswith("/static/") or \
           path.endswith((".woff2", ".ico", ".svg")) or \
           path in ["/images/", "/fonts/"]:
            response = await call_next(request)
            return response
        
        # Check for session cookie
        session = get_session_from_request(request)
        is_authenticated = session and session.get('user_id')
        
        # For root path and HTML/JS/CSS files, check authentication
        if path == "/" or path.endswith((".html", ".js", ".css")):
            if path == "/login.html" or path == "/login":
                # Login page is always accessible
                response = await call_next(request)
                return response
            # For other HTML/JS/CSS and root, check authentication
            if not is_authenticated:
                # Redirect to login page for HTML/frontend requests
                from fastapi.responses import RedirectResponse
                return RedirectResponse(url="/login", status_code=302)
            # Authenticated - proceed
            response = await call_next(request)
            return response
        
        # For API endpoints, check authentication
        if not is_authenticated:
            # For API endpoints, return 401 JSON
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"}
            )
        
        # Valid session - proceed
        response = await call_next(request)
        return response

app.add_middleware(AuthenticationMiddleware)

# HTTP request logging middleware removed - now using INFO log handler instead

# Exception handler for request validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Validation error on {request.method} {request.url.path}: {exc.errors()}")
    try:
        body = await request.body()
        # Sanitize request body before logging
        sanitized_body = sanitize_for_logging(body.decode() if body else 'empty')
        logger.error(f"Request body: {sanitized_body}")
    except Exception as e:
        logger.error(f"Could not read request body: {e}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()}
    )

# Helper function to extract access_token from nhi_tokens table
def get_access_token_from_request(request: Request, fabric_host: str = None, nhi_credential_id: Optional[int] = None) -> Optional[str]:
    """
    Extract access_token from nhi_tokens table (encrypted with FS_SERVER_SECRET).
    If token doesn't exist or is expired, automatically retrieves a new token using the selected NHI credential.
    Returns the token string or None if not found and cannot be retrieved.
    
    Args:
        request: FastAPI request object (used to get session and selected NHI credential)
        fabric_host: Fabric host address (required)
        nhi_credential_id: Optional NHI credential ID to use (if not provided, uses selected credential from session)
    """
    if not fabric_host:
        return None
    
    # Get selected NHI credential ID from session if not provided
    if not nhi_credential_id:
        session = get_session_from_request(request)
        if session and session.get('nhi_credential_id'):
            nhi_credential_id = session.get('nhi_credential_id')
            logger.debug(f"Using NHI credential {nhi_credential_id} from session for {fabric_host}")
    
    if not nhi_credential_id:
        logger.warning(f"No NHI credential selected in session for fabric_host {fabric_host}")
        return None
    
    # Get token from nhi_tokens table (encrypted with FS_SERVER_SECRET)
    try:
        conn = db_connect_with_retry()
        if not conn:
            logger.error("Database connection failed when retrieving token")
            return None
        
        c = conn.cursor()
        now = datetime.now()
        
        # Get token for this specific NHI credential and fabric_host
        c.execute('''
            SELECT token_encrypted, token_expires_at
            FROM nhi_tokens
            WHERE nhi_credential_id = ? AND fabric_host = ?
            ORDER BY token_expires_at DESC
            LIMIT 1
        ''', (nhi_credential_id, fabric_host))
        
        token_row = c.fetchone()
        
        if token_row:
            token_encrypted, token_expires_at_str = token_row
            if token_expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(token_expires_at_str)
                    if expires_at > now:
                        # Token is valid, decrypt it
                        try:
                            decrypted_token = decrypt_with_server_secret(token_encrypted)
                            logger.debug(f"Retrieved valid token from nhi_tokens for {fabric_host}")
                            conn.close()
                            return decrypted_token
                        except Exception as e:
                            logger.error(f"Failed to decrypt token from nhi_tokens: {e}")
                            # Token exists but can't be decrypted - try to get a new one (fall through)
                    else:
                        logger.debug(f"Token from nhi_tokens for {fabric_host} has expired")
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid token expiration date format: {e}")
        else:
            logger.debug(f"No valid token found in nhi_tokens for {fabric_host}")
        
        # Token not found or expired - try to automatically retrieve it using the selected NHI credential
        logger.info(f"Attempting to automatically retrieve token for {fabric_host} using NHI credential {nhi_credential_id}")
        
        # Get NHI credential details
        c.execute('''
            SELECT id, client_id, client_secret_encrypted
            FROM nhi_credentials
            WHERE id = ?
        ''', (nhi_credential_id,))
        
        credential_row = c.fetchone()
        
        if not credential_row:
            logger.warning(f"NHI credential {nhi_credential_id} not found")
            conn.close()
            return None
        
        cred_id, client_id, client_secret_encrypted = credential_row
        
        # Decrypt client_secret
        try:
            client_secret = decrypt_with_server_secret(client_secret_encrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt client_secret for NHI credential {cred_id}: {e}")
            conn.close()
            return None
        
        # Get new token
        try:
            token_data = get_access_token(client_id, client_secret, fabric_host)
            if not token_data or not isinstance(token_data, dict) or not token_data.get("access_token"):
                logger.error(f"Failed to get new token for {fabric_host}")
                conn.close()
                return None
            
            # Encrypt and store the new token
            token_encrypted = encrypt_with_server_secret(token_data.get("access_token"))
            expires_in = token_data.get("expires_in")
            if expires_in:
                expires_at = datetime.now() + timedelta(seconds=expires_in)
                token_expires_at = expires_at.isoformat()
                
                # Store token in nhi_tokens
                c.execute('''
                    INSERT OR REPLACE INTO nhi_tokens 
                    (nhi_credential_id, fabric_host, token_encrypted, token_expires_at, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (cred_id, fabric_host, token_encrypted, token_expires_at))
                conn.commit()
                logger.info(f"Automatically retrieved and stored new token for {fabric_host} using NHI credential {cred_id} (expires at {token_expires_at})")
                
                # Return the decrypted token
                decrypted_token = decrypt_with_server_secret(token_encrypted)
                conn.close()
                return decrypted_token
            else:
                logger.warning(f"No expiration time in token response for {fabric_host}")
                conn.close()
                return None
        except Exception as e:
            logger.error(f"Error retrieving token for {fabric_host}: {e}", exc_info=True)
            conn.close()
            return None
            
    except Exception as e:
        logger.error(f"Error retrieving token from nhi_tokens: {e}", exc_info=True)
        return None

def get_access_token_for_host(fabric_host: str, nhi_credential_id: Optional[int] = None) -> Optional[str]:
    """
    Get access token for a fabric host from nhi_tokens table (for background tasks).
    This is similar to get_access_token_from_request but doesn't require a request object.
    
    Args:
        fabric_host: Fabric host address
        nhi_credential_id: Optional NHI credential ID to use
    
    Returns:
        Access token string or None if not found
    """
    if not fabric_host:
        return None
    
    try:
        conn = db_connect_with_retry()
        if not conn:
            return None
        
        c = conn.cursor()
        now = datetime.now(timezone.utc)
        
        # Build query based on whether nhi_credential_id is provided
        if nhi_credential_id:
            c.execute('''
                SELECT token_encrypted, token_expires_at
                FROM nhi_tokens
                WHERE nhi_credential_id = ? AND fabric_host = ?
                ORDER BY token_expires_at DESC
                LIMIT 1
            ''', (nhi_credential_id, fabric_host))
        else:
            # Get most recent valid token for this fabric_host
            c.execute('''
                SELECT token_encrypted, token_expires_at
                FROM nhi_tokens
                WHERE fabric_host = ? AND token_expires_at > ?
                ORDER BY token_expires_at DESC
                LIMIT 1
            ''', (fabric_host, now.isoformat()))
        
        token_row = c.fetchone()
        
        if token_row:
            token_encrypted, token_expires_at_str = token_row
            if token_expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(token_expires_at_str)
                    if expires_at > now:
                        # Token is valid, decrypt it
                        try:
                            decrypted_token = decrypt_with_server_secret(token_encrypted)
                            # Calculate remaining seconds until expiration
                            remaining_seconds = int((expires_at - now).total_seconds())
                            logger.debug(f"Found valid cached token for {fabric_host}, expires in {remaining_seconds} seconds")
                            conn.close()
                            return decrypted_token
                        except Exception as e:
                            logger.error(f"Failed to decrypt token from nhi_tokens for {fabric_host}: {e}")
                            conn.close()
                            return None
                    else:
                        logger.debug(f"Cached token for {fabric_host} has expired")
                except (ValueError, TypeError) as e:
                    logger.error(f"Invalid token expiration date format for {fabric_host}: {e}")
        
        conn.close()
    except Exception as e:
        logger.error(f"Error retrieving token from nhi_tokens for {fabric_host}: {e}")
    
    return None

def get_or_create_system_nhi_credential(client_id: str, client_secret: str) -> Optional[int]:
    """
    Get or create a system NHI credential for LEAD_FABRIC_HOST background tasks.
    This allows tokens to be stored and reused across service restarts.
    
    Args:
        client_id: Client ID from environment
        client_secret: Client secret from environment
    
    Returns:
        NHI credential ID or None if creation fails
    """
    if not client_id or not client_secret:
        return None
    
    try:
        conn = db_connect_with_retry()
        if not conn:
            return None
        
        c = conn.cursor()
        
        # Look for existing system credential with matching client_id
        c.execute('SELECT id FROM nhi_credentials WHERE client_id = ?', (client_id,))
        row = c.fetchone()
        
        if row:
            nhi_id = row[0]
            logger.debug(f"Found existing system NHI credential {nhi_id} for client_id")
            conn.close()
            return nhi_id
        
        # Create new system credential
        from .crypto import encrypt_client_secret
        encryption_password = Config.FS_SERVER_SECRET
        encrypted_secret = encrypt_client_secret(client_secret, encryption_password)
        
        # Use a system name that won't conflict with user-created credentials
        system_name = f"__SYSTEM_LEAD_{client_id[:8]}__"
        
        try:
            c.execute('''
                INSERT INTO nhi_credentials (name, client_id, client_secret_encrypted, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (system_name, client_id, encrypted_secret))
            conn.commit()
            nhi_id = c.lastrowid
            logger.info(f"Created system NHI credential {nhi_id} for LEAD_FABRIC_HOST background tasks")
            conn.close()
            return nhi_id
        except sqlite3.IntegrityError:
            # Race condition: another thread created it
            conn.rollback()
            c.execute('SELECT id FROM nhi_credentials WHERE client_id = ?', (client_id,))
            row = c.fetchone()
            if row:
                nhi_id = row[0]
                logger.debug(f"System NHI credential was created by another thread: {nhi_id}")
                conn.close()
                return nhi_id
            conn.close()
            return None
    except Exception as e:
        logger.error(f"Error getting/creating system NHI credential: {e}", exc_info=True)
        if conn:
            conn.close()
        return None

def get_access_token_with_cache(fabric_host: str, client_id: str, client_secret: str) -> Optional[dict]:
    """
    Get access token for a fabric host, checking cache first before making OAuth2 request.
    This is used by background tasks to avoid unnecessary token requests.
    
    Args:
        fabric_host: Fabric host address
        client_id: Client ID
        client_secret: Client secret
    
    Returns:
        Token data dict with 'access_token' and 'expires_in', or None if failed
    """
    if not fabric_host or not client_id or not client_secret:
        return None
    
    # First, try to get existing valid token from database
    token = get_access_token_for_host(fabric_host)
    if token:
        logger.info(f"Using cached valid token for {fabric_host} (no OAuth2 request needed)")
        # Return token data in expected format
        # Note: expires_in is None for cached tokens, but the token is already validated as not expired
        return {"access_token": token, "expires_in": None, "from_cache": True}
    
    # No valid token found, get a new one
    logger.info(f"No valid cached token found for {fabric_host}, requesting new token from OAuth2 endpoint")
    token_data = get_access_token(client_id, client_secret, fabric_host)
    
    if not token_data or not token_data.get("access_token"):
        return None
    
    # Store the new token in database for future use
    try:
        nhi_id = get_or_create_system_nhi_credential(client_id, client_secret)
        if nhi_id:
            expires_in = token_data.get("expires_in")
            if expires_in:
                expires_at = datetime.now() + timedelta(seconds=expires_in)
                token_expires_at = expires_at.isoformat()
                token_encrypted = encrypt_with_server_secret(token_data.get("access_token"))
                
                conn = db_connect_with_retry()
                if conn:
                    try:
                        c = conn.cursor()
                        c.execute('''
                            INSERT OR REPLACE INTO nhi_tokens 
                            (nhi_credential_id, fabric_host, token_encrypted, token_expires_at, updated_at)
                            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                        ''', (nhi_id, fabric_host, token_encrypted, token_expires_at))
                        conn.commit()
                        logger.debug(f"Stored new token for {fabric_host} (expires at {token_expires_at})")
                    except Exception as e:
                        logger.warning(f"Failed to store token for {fabric_host}: {e}")
                    finally:
                        conn.close()
    except Exception as e:
        logger.warning(f"Error storing token for {fabric_host}: {e}")
    
    return token_data

# Database setup - use Config module
DB_PATH = Config.DB_PATH

# Connection pool limit to prevent exhaustion
from threading import Semaphore
_db_semaphore = Semaphore(Config.DB_MAX_CONNECTIONS)

def db_connect_with_retry(timeout=None, max_retries=None, retry_delay=None):
    """Connect to SQLite database with retry logic, timeout, and connection pooling"""
    # Use Config defaults if not specified
    timeout = timeout or Config.DB_TIMEOUT
    max_retries = max_retries or Config.DB_MAX_RETRIES
    retry_delay = retry_delay or Config.DB_RETRY_DELAY
    
    _db_semaphore.acquire()
    try:
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(DB_PATH, timeout=timeout)
                # Enable WAL mode and optimizations for better concurrency
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                conn.execute('PRAGMA cache_size=-64000')  # 64MB cache
                conn.execute('PRAGMA temp_store=MEMORY')
                conn.execute('PRAGMA mmap_size=268435456')  # 256MB memory-mapped I/O
                return conn
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                    continue
                raise
        return None
    finally:
        _db_semaphore.release()

# App log queue for batch writes (replaces synchronous DatabaseLogHandler)
_app_log_queue = queue.Queue(maxsize=Config.APP_LOG_QUEUE_SIZE)
_app_log_thread = None
_app_log_thread_lock = threading.Lock()

def _app_log_worker():
    """Background thread to batch write app logs to database"""
    batch = []
    batch_size = Config.APP_LOG_BATCH_SIZE
    batch_timeout = Config.APP_LOG_BATCH_TIMEOUT
    last_write = time.time()
    
    while True:
        try:
            # Try to get an item from queue with timeout
            try:
                item = _app_log_queue.get(timeout=1.0)
                if item is None:  # Shutdown signal
                    # Write remaining batch before exiting
                    if batch:
                        _write_app_log_batch(batch)
                    break
                
                batch.append(item)
                _app_log_queue.task_done()
            except queue.Empty:
                pass
            
            # Write batch if it's full or timeout reached
            now = time.time()
            if len(batch) >= batch_size or (batch and (now - last_write) >= batch_timeout):
                if batch:
                    _write_app_log_batch(batch)
                    batch = []
                    last_write = now
        except Exception as e:
            # Use print to avoid recursion (can't use logger here)
            print(f"Error in app log worker: {e}", file=sys.stderr)
            time.sleep(0.1)  # Brief pause on error

def _write_app_log_batch(batch: list):
    """Write a batch of app logs to the database"""
    if not batch:
        return
    
    conn = None
    try:
        conn = db_connect_with_retry(timeout=10.0, max_retries=5, retry_delay=0.05)
        if not conn:
            # Silently fail - can't log this without recursion
            return
        
        c = conn.cursor()
        
        # Insert all entries in batch
        c.executemany('''
            INSERT INTO app_logs (level, logger_name, message, created_at)
            VALUES (?, ?, ?, ?)
        ''', [
            (item['level'], item['logger_name'], item['message'], item['created_at'])
            for item in batch
        ])
        conn.commit()
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            # Put items back in queue (at front) for retry
            for item in reversed(batch):
                try:
                    _app_log_queue.put_nowait(item)
                except queue.Full:
                    # Queue is full, drop entry (can't log this)
                    pass
        # Silently fail on other errors to avoid recursion
    except Exception:
        # Silently fail to avoid recursion
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

def _start_app_log_worker():
    """Start the app log worker thread if not already running"""
    global _app_log_thread
    with _app_log_thread_lock:
        if _app_log_thread is None or not _app_log_thread.is_alive():
            _app_log_thread = threading.Thread(target=_app_log_worker, daemon=True)
            _app_log_thread.start()

# Custom logging handler to capture INFO logs to database (batched writes)
class DatabaseLogHandler(logging.Handler):
    """Custom logging handler that writes INFO level logs to database via batched queue"""
    
    def emit(self, record):
        try:
            # Only log INFO level messages
            if record.levelno == logging.INFO:
                # Ensure worker thread is running
                _start_app_log_worker()
                
                # Format log message
                message = self.format(record)
                logger_name = record.name
                level = record.levelname
                created_at = datetime.now(timezone.utc).isoformat()
                
                log_entry = {
                    'level': level,
                    'logger_name': logger_name,
                    'message': message,
                    'created_at': created_at
                }
                
                # Add to queue (non-blocking)
                try:
                    _app_log_queue.put_nowait(log_entry)
                except queue.Full:
                    # Queue is full, drop entry (can't log this to avoid recursion)
                    pass
        except Exception:
            # Silently fail to avoid recursion
            pass

# Input validation patterns and functions
import re
HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
TEMPLATE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\s\-_\.]{0,99}$')  # Allows spaces
VERSION_PATTERN = re.compile(r'^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9]+)?$')

# Limits (using Config)
MAX_HOSTS_PER_CONFIG = Config.MAX_HOSTS_PER_CONFIG
MAX_SSH_COMMAND_LENGTH = Config.MAX_SSH_COMMAND_LENGTH
MAX_SSH_COMMANDS = Config.MAX_SSH_COMMANDS
MAX_TOTAL_COMMANDS_SIZE = Config.MAX_TOTAL_COMMANDS_SIZE
SSH_OPERATION_TIMEOUT = Config.SSH_OPERATION_TIMEOUT

def validate_fabric_host(host: str) -> str:
    """Validate and sanitize fabric host input"""
    if not host or len(host) > 255:
        raise HTTPException(400, "Invalid host format or length")

    host = host.strip().lower()

    # Validate IPv4 addresses separately
    if IP_PATTERN.match(host):
        octets = host.split(".")
        if len(octets) != 4:
            raise HTTPException(400, "Invalid host format")
        try:
            if any(int(octet) > 255 for octet in octets):
                raise HTTPException(400, "Invalid host format")
        except ValueError:
            raise HTTPException(400, "Invalid host format")
        return host

    if not HOSTNAME_PATTERN.match(host):
        raise HTTPException(400, "Invalid host format")

    if ".." in host:
        raise HTTPException(400, "Invalid host format")

    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise HTTPException(400, "Invalid host format")
        if label.startswith("-") or label.endswith("-"):
            raise HTTPException(400, "Invalid host format")

    return host

def validate_template_name(name: str) -> str:
    """Validate template name format (allows spaces)"""
    if not name or len(name) > 100:
        raise HTTPException(400, "Invalid template name format or length")
    name = name.strip()
    if not TEMPLATE_NAME_PATTERN.match(name):
        raise HTTPException(400, "Invalid template name format")
    return name

def validate_version(version: str) -> str:
    """Validate version format"""
    if not version or not version.strip():
        raise HTTPException(400, "Version is required")
    version = version.strip()
    if not VERSION_PATTERN.match(version):
        raise HTTPException(400, "Invalid version format")
    return version

def validate_name(name: str, field_name: str = "name", max_length: int = 255) -> str:
    """Validate name format (alphanumeric, dash, underscore)"""
    if not name or not name.strip():
        raise HTTPException(400, f"{field_name} is required")
    name = name.strip()
    if len(name) > max_length:
        raise HTTPException(400, f"{field_name} exceeds maximum length of {max_length} characters")
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise HTTPException(400, f"{field_name} must contain only alphanumeric characters, dashes, and underscores")
    return name

def validate_hostname(hostname: str) -> str:
    """Validate hostname format"""
    if not hostname or not hostname.strip():
        raise HTTPException(400, "Hostname is required")
    hostname = hostname.strip()
    if len(hostname) > 253:
        raise HTTPException(400, "Hostname exceeds maximum length of 253 characters")
    if not HOSTNAME_PATTERN.match(hostname):
        raise HTTPException(400, "Invalid hostname format")
    return hostname

def validate_client_id(client_id: str) -> str:
    """Validate client ID"""
    if not client_id or not client_id.strip():
        raise HTTPException(400, "Client ID is required")
    client_id = client_id.strip()
    if len(client_id) > 500:
        raise HTTPException(400, "Client ID exceeds maximum length of 500 characters")
    return client_id

def validate_client_secret(client_secret: str) -> str:
    """Validate client secret"""
    if not client_secret or not client_secret.strip():
        raise HTTPException(400, "Client Secret is required")
    client_secret = client_secret.strip()
    if len(client_secret) > 1000:
        raise HTTPException(400, "Client Secret exceeds maximum length of 1000 characters")
    return client_secret

def validate_fabric_hosts_list(fabric_hosts: str) -> list[str]:
    """Validate and parse space-separated list of fabric hosts"""
    if not fabric_hosts or not fabric_hosts.strip():
        return []
    hosts = [h.strip() for h in fabric_hosts.strip().split() if h.strip()]
    validated_hosts = []
    for host in hosts:
        validated_hosts.append(validate_fabric_host(host))
    return validated_hosts

# Thread safety for event scheduler
_executed_events_lock = threading.Lock()
_executed_events: set[str] = set()

# Token refresh locks per host
_token_refresh_locks: dict[str, threading.Lock] = {}
_token_locks_lock = threading.Lock()

def get_token_refresh_lock(host: str) -> threading.Lock:
    """Get or create lock for a specific host token refresh"""
    with _token_locks_lock:
        if host not in _token_refresh_locks:
            _token_refresh_locks[host] = threading.Lock()
        return _token_refresh_locks[host]
def init_db():
    """Initialize the SQLite database with configurations and event_schedules tables"""
    conn = db_connect_with_retry()
    if not conn:
        raise RuntimeError("Failed to connect to database during initialization")
    c = conn.cursor()
    
    # Apply SQLite performance optimizations (also applied in db_connect_with_retry, but ensure they're set)
    # These are idempotent and safe to run multiple times
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA synchronous=NORMAL')
    c.execute('PRAGMA cache_size=-64000')  # 64MB cache
    c.execute('PRAGMA temp_store=MEMORY')
    c.execute('PRAGMA mmap_size=268435456')  # 256MB memory-mapped I/O
    c.execute('PRAGMA foreign_keys=ON')  # Enable foreign key constraints
    
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
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(repo_name, template_name, version)
        )
    ''')
    
    # Migrate existing table if it has fabric_host column or missing expires_at (drop and recreate)
    c.execute("PRAGMA table_info(cached_templates)")
    columns = [column[1] for column in c.fetchall()]
    if 'fabric_host' in columns or 'expires_at' not in columns:
        try:
            # Backup existing data if expires_at is missing
            existing_data = []
            if 'expires_at' not in columns:
                c.execute('SELECT repo_id, repo_name, template_id, template_name, version, cached_at FROM cached_templates')
                existing_data = c.fetchall()
            
            # Drop old table and recreate with expires_at
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
                    expires_at TIMESTAMP NOT NULL,
                    UNIQUE(repo_name, template_name, version)
                )
            ''')
            
            # Restore existing data with expires_at set to cached_at + default TTL
            if existing_data:
                from datetime import datetime, timedelta, timezone
                now = datetime.now(timezone.utc)
                default_expires = (now + timedelta(hours=Config.TEMPLATE_CACHE_TTL_HOURS)).isoformat()
                for row in existing_data:
                    repo_id, repo_name, template_id, template_name, version, cached_at = row
                    expires_at = default_expires
                    if cached_at:
                        try:
                            cached_dt = datetime.fromisoformat(cached_at) if isinstance(cached_at, str) else cached_at
                            if cached_dt.tzinfo is None:
                                cached_dt = cached_dt.replace(tzinfo=timezone.utc)
                            expires_at = (cached_dt + timedelta(hours=Config.TEMPLATE_CACHE_TTL_HOURS)).isoformat()
                        except:
                            pass
                    c.execute('''
                        INSERT INTO cached_templates 
                        (repo_id, repo_name, template_id, template_name, version, cached_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (repo_id, repo_name, template_id, template_name, version, cached_at, expires_at))
            
            conn.commit()
        except sqlite3.OperationalError as e:
            print(f"Warning: Could not migrate cached_templates table: {e}")
    
    conn.commit()
    
    # Create table to store NHI credential ID per event (for auto-run)
    # No password needed - credentials are encrypted with FS_SERVER_SECRET
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS event_nhi_passwords (
            event_id INTEGER PRIMARY KEY,
            nhi_credential_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES event_schedules(id) ON DELETE CASCADE,
            FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id) ON DELETE CASCADE
        )
    ''')
    
    # Migrate existing table to remove password_encrypted column
    try:
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='event_nhi_passwords'")
        if c.fetchone():
            # Check if password_encrypted column exists
            c.execute("PRAGMA table_info(event_nhi_passwords)")
            columns_info = c.fetchall()
            columns = [row[1] for row in columns_info]
            logger.info(f"event_nhi_passwords table columns: {columns}")
            
            # Check if password_encrypted column exists
            password_col_exists = 'password_encrypted' in columns
            
            if password_col_exists:
                logger.info("Migrating event_nhi_passwords table to remove password_encrypted column")
                try:
                    # Disable foreign keys temporarily for migration
                    c.execute('PRAGMA foreign_keys=OFF')
                    # Begin transaction
                    c.execute('BEGIN TRANSACTION')
                    
                    # Clean up any leftover table from previous failed migration
                    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='event_nhi_passwords_new'")
                    if c.fetchone():
                        logger.info("Cleaning up leftover event_nhi_passwords_new table from previous migration")
                        c.execute('DROP TABLE event_nhi_passwords_new')
                    
                    # Create new table without password_encrypted
                    c.execute('''
                        CREATE TABLE event_nhi_passwords_new (
                            event_id INTEGER PRIMARY KEY,
                            nhi_credential_id INTEGER NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (event_id) REFERENCES event_schedules(id) ON DELETE CASCADE,
                            FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id) ON DELETE CASCADE
                        )
                    ''')
                    # Copy data (excluding password_encrypted)
                    c.execute('''
                        INSERT INTO event_nhi_passwords_new 
                        (event_id, nhi_credential_id, created_at, updated_at)
                        SELECT event_id, nhi_credential_id, created_at, updated_at
                        FROM event_nhi_passwords
                    ''')
                    # Drop old table
                    c.execute('DROP TABLE event_nhi_passwords')
                    # Rename new table
                    c.execute('ALTER TABLE event_nhi_passwords_new RENAME TO event_nhi_passwords')
                    # Commit transaction
                    c.execute('COMMIT')
                    # Re-enable foreign keys
                    c.execute('PRAGMA foreign_keys=ON')
                    conn.commit()
                    logger.info("Successfully migrated event_nhi_passwords table - removed password_encrypted column")
                except Exception as migration_error:
                    try:
                        c.execute('ROLLBACK')
                    except:
                        pass
                    try:
                        c.execute('PRAGMA foreign_keys=ON')
                    except:
                        pass
                    conn.rollback()
                    logger.error(f"Error during event_nhi_passwords migration: {migration_error}", exc_info=True)
                    # Don't raise - allow app to continue, but log the error
            else:
                logger.info("event_nhi_passwords table does not have password_encrypted column - no migration needed")
    except Exception as e:
        logger.error(f"Could not migrate event_nhi_passwords table: {e}", exc_info=True)
        try:
            conn.rollback()
        except:
            pass
    
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
    
    # Create table to store execution records for manual runs (from FabricStudio Runs)
    c.execute('''
        CREATE TABLE IF NOT EXISTS manual_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            configuration_name TEXT,
            status TEXT NOT NULL,
            message TEXT,
            errors TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            execution_details TEXT
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_manual_runs_started_at ON manual_runs(started_at DESC)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_manual_runs_status ON manual_runs(status)')
    
    # Create sessions table for session-based token management
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER,
            nhi_credential_id INTEGER,
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
    
    # Migrate sessions table if needed - check if user_id column exists
    c.execute("PRAGMA table_info(sessions)")
    columns = {col[1]: col for col in c.fetchall()}
    
    # Check if we need to migrate - if user_id doesn't exist, we need to recreate the table
    needs_migration = False
    if 'user_id' not in columns:
        needs_migration = True
        logger.info("Sessions table missing user_id column - migration needed")
    else:
        # Test if we can insert NULL for nhi_credential_id (to check if constraint allows it)
        try:
            test_session_id = 'migration_test_' + str(int(time.time() * 1000))
            c.execute('''
                INSERT INTO sessions 
                (session_id, user_id, nhi_credential_id, tokens_encrypted, session_key_hash, expires_at)
                VALUES (?, ?, NULL, '', '', ?)
            ''', (test_session_id, 999999, (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()))
            c.execute('DELETE FROM sessions WHERE session_id = ?', (test_session_id,))
            conn.commit()
            logger.info("Sessions table allows NULL for nhi_credential_id - no migration needed")
        except sqlite3.IntegrityError:
            needs_migration = True
            logger.info("Sessions table does not allow NULL for nhi_credential_id - migration needed")
            conn.rollback()
        except Exception as e:
            logger.warning(f"Could not test sessions table schema: {e}")
            # Assume migration is needed to be safe
            needs_migration = True
    
    if needs_migration:
        logger.info("Migrating sessions table to add user_id and allow NULL for nhi_credential_id")
        try:
            # Create new table with correct schema
            c.execute('''
                CREATE TABLE IF NOT EXISTS sessions_new (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER,
                    nhi_credential_id INTEGER,
                    tokens_encrypted TEXT NOT NULL,
                    session_key_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            ''')
            # Copy data from old table if it exists and has data
            try:
                c.execute('SELECT COUNT(*) FROM sessions')
                count = c.fetchone()[0]
                if count > 0:
                    # Copy existing data
                    c.execute('''
                        INSERT INTO sessions_new 
                        (session_id, user_id, nhi_credential_id, tokens_encrypted, session_key_hash, created_at, last_used, expires_at)
                        SELECT 
                            session_id, 
                            COALESCE(user_id, NULL) as user_id,
                            nhi_credential_id,
                            tokens_encrypted, 
                            session_key_hash, 
                            created_at, 
                            last_used, 
                            expires_at
                        FROM sessions
                    ''')
            except Exception as copy_error:
                logger.warning(f"Could not copy existing session data: {copy_error}")
            
            # Drop old table and rename new one
            c.execute('DROP TABLE IF EXISTS sessions')
            c.execute('ALTER TABLE sessions_new RENAME TO sessions')
            # Recreate indexes
            c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_nhi_credential_id ON sessions(nhi_credential_id)')
            c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')
            conn.commit()
            logger.info("Sessions table migration completed successfully")
        except Exception as e:
            logger.error(f"Error migrating sessions table: {e}", exc_info=True)
            conn.rollback()
    
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
    
    # Additional performance indexes
    c.execute('CREATE INDEX IF NOT EXISTS idx_event_schedules_auto_run_date ON event_schedules(auto_run, event_date)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_nhi_tokens_cred_host ON nhi_tokens(nhi_credential_id, fabric_host)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_nhi_tokens_expires ON nhi_tokens(token_expires_at)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_event_executions_event_status ON event_executions(event_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_event_executions_started_at ON event_executions(started_at DESC)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_last_used ON sessions(last_used)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cached_templates_repo_name ON cached_templates(repo_name, template_name)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cached_templates_expires ON cached_templates(expires_at)')
    
    # Create repository cache table (per host)
    c.execute('''
        CREATE TABLE IF NOT EXISTS cached_repositories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fabric_host TEXT NOT NULL,
            repo_id TEXT NOT NULL,
            repo_name TEXT NOT NULL,
            repo_data TEXT NOT NULL,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            UNIQUE(fabric_host, repo_id)
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cached_repositories_host ON cached_repositories(fabric_host)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_cached_repositories_expires ON cached_repositories(expires_at)')
    
    # Create repository refresh tracking table
    c.execute('''
        CREATE TABLE IF NOT EXISTS repository_refresh_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fabric_host TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            error_message TEXT,
            repositories_count INTEGER
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_repo_refresh_host ON repository_refresh_logs(fabric_host)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_repo_refresh_started ON repository_refresh_logs(started_at DESC)')
    
    # Create users table for authentication
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_encrypted TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    
    # Note: Sessions table migration is handled above (lines 831-892)
    # It ensures user_id exists and nhi_credential_id can be NULL
    
    # Drop old http_logs table if it exists (replaced by app_logs)
    c.execute('DROP TABLE IF EXISTS http_logs')
    
    conn.commit()
    conn.close()
    
    # Create initial users if they don't exist (using create_user function for consistency)
    # Users are defined in scripts/create_users.py - import and use that logic
    try:
        import sys
        import os
        # Add project root to path to allow importing scripts
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from scripts.create_users import ensure_initial_users
        ensure_initial_users()
    except (ImportError, Exception) as e:
        # Fallback: if script can't be imported, use direct creation
        logger.warning(f"Could not import create_users script ({e}), using fallback user creation")
        initial_users = [
            ("admin", "FortinetAssistant1!")
        ]
        for username, password in initial_users:
            try:
                user = get_user_by_username(username)
                if not user:
                    create_user(username, password)
                    logger.info(f"Created initial user: {username}")
            except Exception as e:
                logger.warning(f"Failed to create initial user {username}: {e}")

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

# User authentication functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt-like approach with server secret"""
    # Use PBKDF2 with server secret as salt for password hashing
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'fabricstudio_user_password_salt_2024',
        iterations=100000,
        backend=default_backend()
    )
    hashed = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    # Encrypt the hash with server secret for additional security
    return encrypt_with_server_secret(hashed.decode())

def verify_password(password: str, password_encrypted: str) -> bool:
    """Verify a password against encrypted hash"""
    try:
        decrypted_hash = decrypt_with_server_secret(password_encrypted)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'fabricstudio_user_password_salt_2024',
            iterations=100000,
            backend=default_backend()
        )
        password_hash = base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()
        return password_hash == decrypted_hash
    except Exception as e:
        logger.error(f"Password verification error: {e}", exc_info=True)
        # If decryption fails, it's likely because FS_SERVER_SECRET changed
        # This means all existing passwords need to be reset
        return False

def get_user_by_username(username: str) -> Optional[dict]:
    """Get user by username"""
    conn = db_connect_with_retry()
    if not conn:
        return None
    c = conn.cursor()
    try:
        c.execute('SELECT id, username, password_encrypted FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "username": row[1],
            "password_encrypted": row[2]
        }
    finally:
        conn.close()

def create_user(username: str, password: str) -> int:
    """Create a new user"""
    conn = db_connect_with_retry()
    if not conn:
        raise RuntimeError("Failed to connect to database")
    c = conn.cursor()
    try:
        password_encrypted = hash_password(password)
        c.execute('''
            INSERT INTO users (username, password_encrypted)
            VALUES (?, ?)
        ''', (username, password_encrypted))
        conn.commit()
        return c.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError(f"Username '{username}' already exists")
    finally:
        conn.close()

def update_user_password(user_id: int, new_password: str):
    """Update user password"""
    conn = db_connect_with_retry()
    if not conn:
        raise RuntimeError("Failed to connect to database")
    c = conn.cursor()
    try:
        password_encrypted = hash_password(new_password)
        c.execute('''
            UPDATE users 
            SET password_encrypted = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (password_encrypted, user_id))
        conn.commit()
    finally:
        conn.close()

# Audit log queue for batch writes
_audit_log_queue = queue.Queue(maxsize=1000)
_audit_log_thread = None
_audit_log_thread_lock = threading.Lock()

def _audit_log_worker():
    """Background thread to batch write audit logs to database"""
    batch = []
    batch_size = Config.AUDIT_LOG_BATCH_SIZE
    batch_timeout = Config.AUDIT_LOG_BATCH_TIMEOUT
    last_write = time.time()
    
    while True:
        try:
            # Try to get an item from queue with timeout
            try:
                item = _audit_log_queue.get(timeout=1.0)
                if item is None:  # Shutdown signal
                    # Write remaining batch before exiting
                    if batch:
                        _write_audit_batch(batch)
                    break
                
                batch.append(item)
                _audit_log_queue.task_done()
            except queue.Empty:
                pass
            
            # Write batch if it's full or timeout reached
            now = time.time()
            if len(batch) >= batch_size or (batch and (now - last_write) >= batch_timeout):
                if batch:
                    _write_audit_batch(batch)
                    batch = []
                    last_write = now
        except Exception as e:
            logger.error(f"Error in audit log worker: {e}", exc_info=True)
            time.sleep(0.1)  # Brief pause on error
def _write_audit_batch(batch: list):
    """Write a batch of audit logs to the database"""
    if not batch:
        return
    
    conn = None
    try:
        conn = db_connect_with_retry(timeout=10.0, max_retries=5, retry_delay=0.05)
        if not conn:
            logger.error("Failed to connect to database for batch audit log write")
            return
        
        c = conn.cursor()
        now_utc = datetime.now(timezone.utc)
        
        # Prepare deduplication check for fabric_created entries
        fabric_created_details = {}
        for item in batch:
            if item['action'] == 'fabric_created' and item['details']:
                fabric_created_details[item['details']] = item
        
        # Check for duplicates if we have fabric_created entries
        if fabric_created_details:
            five_seconds_ago = (now_utc - timedelta(seconds=5)).isoformat()
            for details in list(fabric_created_details.keys()):
                c.execute('''
                    SELECT id FROM audit_logs
                    WHERE action = ? AND details = ?
                    AND created_at > ?
                    LIMIT 1
                ''', ('fabric_created', details, five_seconds_ago))
                if c.fetchone():
                    # Remove duplicate from batch
                    batch.remove(fabric_created_details[details])
        
        # Insert all non-duplicate entries
        if batch:
            c.executemany('''
                INSERT INTO audit_logs (action, user, details, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', [
                (item['action'], item['user'], item['details'], item['ip_address'], item['created_at'])
                for item in batch
            ])
            conn.commit()
    except sqlite3.OperationalError as e:
        if "database is locked" in str(e).lower():
            logger.warning(f"Database locked when writing audit log batch, retrying later")
            # Put items back in queue (at front) for retry
            for item in reversed(batch):
                try:
                    _audit_log_queue.put_nowait(item)
                except queue.Full:
                    logger.warning("Audit log queue full, dropping audit log entry")
        else:
            logger.error(f"Failed to write audit log batch: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Error writing audit log batch: {e}", exc_info=True)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

def _start_audit_log_worker():
    """Start the audit log worker thread if not already running"""
    global _audit_log_thread
    with _audit_log_thread_lock:
        if _audit_log_thread is None or not _audit_log_thread.is_alive():
            _audit_log_thread = threading.Thread(target=_audit_log_worker, daemon=True)
            _audit_log_thread.start()
            logger.info("Audit log worker thread started")

# Audit logging helper function
def log_audit(action: str, user: str = None, details: str = None, ip_address: str = None, request: Request = None):
    """Log an audit event to the database via queue (batched writes)
    
    Args:
        action: The action being logged
        user: Username (optional, will be extracted from request if not provided)
        details: Additional details about the action
        ip_address: IP address (optional, will be extracted from request if not provided)
        request: FastAPI Request object (optional, used to extract user and IP if not provided)
    """
    # Ensure worker thread is running
    _start_audit_log_worker()
    
    # Extract user from request if not provided
    if user is None and request is not None:
        user = get_current_username(request)
    
    # Extract IP from request if not provided
    if ip_address is None and request is not None:
        ip_address = get_client_ip(request)
    
    # Prepare log entry
    now_utc = datetime.now(timezone.utc)
    log_entry = {
        'action': action,
        'user': user,
        'details': details,
        'ip_address': ip_address,
        'created_at': now_utc.isoformat()
    }
    
    # Add to queue (non-blocking)
    try:
        _audit_log_queue.put_nowait(log_entry)
    except queue.Full:
        # Queue is full, log warning and drop entry
        logger.warning(f"Audit log queue full, dropping audit log entry: {action}")

def get_current_username(request: Request) -> Optional[str]:
    """Get the current logged-in username from the request session"""
    try:
        session = get_session_from_request(request)
        if session and session.get('user_id'):
            user_id = session['user_id']
            conn = db_connect_with_retry()
            if conn:
                try:
                    c = conn.cursor()
                    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
                    row = c.fetchone()
                    if row:
                        return row[0]
                finally:
                    conn.close()
    except Exception:
        pass
    return None

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
    lock = get_token_refresh_lock(fabric_host)
    with lock:
        try:
            session = get_session(session_id)
            if not session:
                logger.warning("Session not found for token refresh")
                return False
            
            session_key = get_session_key_temp(session_id)
            if not session_key:
                logger.warning("Session key not found for token refresh")
                return False
            
            # Decrypt tokens to get credentials
            tokens = decrypt_tokens_from_session(session['tokens_encrypted'], session_key)
            credentials = tokens.get('_credentials')
            
            if not credentials:
                logger.warning("No credentials stored in session for token refresh")
                return False
            
            client_id = credentials.get('client_id')
            client_secret = credentials.get('client_secret')
            
            if not client_id or not client_secret:
                logger.warning("Missing client_id or client_secret in session for token refresh")
                return False
            
            # Get new token from FabricStudio API
            token_data = get_access_token(client_id, client_secret, fabric_host)
            if not token_data or not isinstance(token_data, dict) or not token_data.get("access_token"):
                logger.error(f"Failed to get new token for {fabric_host}")
                return False
            
            # Update token in session
            tokens[fabric_host] = create_token_info(token_data)
            
            # Re-encrypt and save
            tokens_encrypted = encrypt_tokens_for_session(tokens, session_key)
            
            conn = db_connect_with_retry()
            if not conn:
                logger.error(f"Failed to connect to database for token refresh")
                return False
            
            c = conn.cursor()
            try:
                c.execute('''
                    UPDATE sessions 
                    SET tokens_encrypted = ?, last_used = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (tokens_encrypted, session_id))
                conn.commit()
                logger.info(f"Token refreshed successfully for {fabric_host}")
                return True
            except sqlite3.Error as e:
                logger.error(f"Database error refreshing token: {e}")
                conn.rollback()
                return False
            finally:
                conn.close()
        except Exception as e:
            logger.error(f"Error refreshing token for {fabric_host}: {e}", exc_info=True)
            return False

def calculate_expires_in(expires_at_str: str) -> int:
    """Calculate expires_in seconds from expires_at ISO string"""
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        delta = expires_at - datetime.now()
        return max(0, int(delta.total_seconds()))
    except:
        return 3600  # Default 1 hour

def create_user_session(user_id: int) -> tuple:
    """Create a new user session and return (session_id, expires_at)"""
    session_id = generate_session_id()
    
    # Session-based expiration: no fixed expiration, but we'll set a far future date
    # and update it on activity. For session-based, we'll extend on each activity.
    # Set initial expiration to 30 days from now (will be extended on activity)
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    
    conn = db_connect_with_retry()
    if not conn:
        raise RuntimeError("Failed to connect to database for session creation")
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO sessions 
            (session_id, user_id, nhi_credential_id, tokens_encrypted, session_key_hash, expires_at)
            VALUES (?, ?, NULL, '', '', ?)
        ''', (session_id, user_id, expires_at.isoformat()))
        conn.commit()
    finally:
        conn.close()
    
    return session_id, expires_at

def create_session(nhi_credential_id: int, encryption_password: str, tokens_by_host: dict = None, client_id: str = None, client_secret: str = None) -> tuple:
    """Create a new session and return (session_id, session_key, expires_at) - DEPRECATED: Use create_user_session"""
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
    
    conn = db_connect_with_retry()
    if not conn:
        raise RuntimeError("Failed to connect to database for session creation")
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
    conn = db_connect_with_retry()
    if not conn:
        logger.error("Failed to connect to database for session retrieval")
        return None
    c = conn.cursor()
    try:
        c.execute('''
            SELECT session_id, user_id, nhi_credential_id, tokens_encrypted, session_key_hash, 
                   created_at, last_used, expires_at
            FROM sessions
            WHERE session_id = ?
        ''', (session_id,))
        row = c.fetchone()
        if not row:
            return None
        
        expires_at_str = row[7]
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
        
        # For session-based expiration, extend session on activity (30 days from now)
        # Update last_used and extend expiration
        new_expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        c.execute('''
            UPDATE sessions 
            SET last_used = CURRENT_TIMESTAMP, expires_at = ?
            WHERE session_id = ?
        ''', (new_expires_at.isoformat(), session_id))
        conn.commit()
        
        return {
            "session_id": row[0],
            "user_id": row[1],
            "nhi_credential_id": row[2],
            "tokens_encrypted": row[3],
            "session_key_hash": row[4],
            "created_at": row[5],
            "last_used": row[6],
            "expires_at": new_expires_at.isoformat()  # Return updated expiration
        }
    finally:
        conn.close()

def update_session_activity(session_id: str):
    """Update last_used timestamp for session"""
    conn = db_connect_with_retry()
    if not conn:
        logger.error(f"Failed to connect to database for session activity update")
        return
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

def update_session_nhi_credential(session_id: str, nhi_credential_id: Optional[int]):
    """Update nhi_credential_id in session"""
    conn = db_connect_with_retry()
    if not conn:
        logger.error(f"Failed to connect to database for session NHI credential update")
        return False
    c = conn.cursor()
    try:
        c.execute('''
            UPDATE sessions 
            SET nhi_credential_id = ?, last_used = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (nhi_credential_id, session_id))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating session NHI credential: {e}")
        return False
    finally:
        conn.close()

def update_session_tokens(session_id: str, tokens_encrypted: str):
    """Update tokens in session"""
    conn = db_connect_with_retry()
    if not conn:
        logger.error(f"Failed to connect to database for session token update")
        return
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
    """Refresh session expiration time - session-based: extend 30 days from now"""
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)
    conn = db_connect_with_retry()
    if not conn:
        logger.error(f"Failed to connect to database for session refresh")
        return None
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
    conn = db_connect_with_retry()
    if not conn:
        logger.error(f"Failed to connect to database for session deletion")
        return
    c = conn.cursor()
    try:
        c.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        conn.commit()
        # Remove from temp storage
        with _session_keys_lock:
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

# Store session keys temporarily in memory with TTL-based cleanup
# In production, consider using Redis or storing encrypted session key
from collections import OrderedDict
_session_keys: dict[str, tuple[bytes, datetime]] = OrderedDict()
_session_keys_lock = threading.Lock()
_SESSION_KEY_TTL = timedelta(hours=24)
_MAX_SESSION_KEYS = 1000

def cleanup_expired_session_keys():
    """Remove expired session keys"""
    now = datetime.now()
    with _session_keys_lock:
        expired = [k for k, (_, ts) in _session_keys.items() 
                   if now - ts > _SESSION_KEY_TTL]
        for k in expired:
            _session_keys.pop(k, None)
        # Keep only last MAX_SESSION_KEYS entries
        while len(_session_keys) > _MAX_SESSION_KEYS:
            _session_keys.popitem(last=False)

def store_session_key_temp(session_id: str, session_key: bytes):
    """Store session key with TTL"""
    cleanup_expired_session_keys()
    with _session_keys_lock:
        _session_keys[session_id] = (session_key, datetime.now())

def get_session_key_temp(session_id: str) -> Optional[bytes]:
    """Get temporarily stored session key if not expired"""
    cleanup_expired_session_keys()
    with _session_keys_lock:
        entry = _session_keys.get(session_id)
        if entry:
            key, ts = entry
            if datetime.now() - ts < _SESSION_KEY_TTL:
                return key
            _session_keys.pop(session_id, None)
    return None

# Initialize database on startup
init_db()

# Add database handler to root logger after DB is initialized
db_handler = DatabaseLogHandler()
db_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
db_handler.setFormatter(formatter)
logging.getLogger().addHandler(db_handler)

# CORS middleware - configure allowed origins
def get_cors_origins():
    """Get CORS allowed origins from config or environment"""
    origins = []
    
    # If CORS_ALLOW_ORIGINS is explicitly set, use it
    if Config.CORS_ALLOW_ORIGINS:
        origins = [origin.strip() for origin in Config.CORS_ALLOW_ORIGINS.split(",") if origin.strip()]
    else:
        # Auto-generate origins based on HOSTNAME and PORT
        protocol = "https" if Config.HTTPS_ENABLED else "http"
        port = Config.PORT
        
        # Add localhost variants (common for development)
        origins.extend([
            f"http://localhost:{port}",
            f"http://127.0.0.1:{port}",
            f"https://localhost:{port}",
            f"https://127.0.0.1:{port}",
        ])
        
        # If HOSTNAME is not 0.0.0.0, add it as an origin
        if Config.HOSTNAME and Config.HOSTNAME != "0.0.0.0":
            origins.append(f"{protocol}://{Config.HOSTNAME}:{port}")
            # Also add without port if it's a standard port
            if (protocol == "http" and port == "80") or (protocol == "https" and port == "443"):
                origins.append(f"{protocol}://{Config.HOSTNAME}")
        
        # Add common development ports for frontend frameworks
        origins.extend([
            "http://localhost:5173",  # Vite default
            "http://localhost:3000",  # React default
            "http://127.0.0.1:5500",  # Live Server
            "http://localhost:8001",  # Alternative port
        ])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_origins = []
    for origin in origins:
        if origin not in seen:
            seen.add(origin)
            unique_origins.append(origin)
    
    return unique_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Note: Static files are served via explicit routes below, not via mount
# This ensures API routes take precedence

# Serve static assets at root paths for index.html references
@app.get("/app.js")
def serve_app_js():
    return FileResponse("frontend/app.js", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

@app.get("/health", response_model=HealthResponse, summary="Health check", 
         description="Check the health status of the API and database")
def health_check():
    """
    Health check endpoint for monitoring and orchestration.
    
    Returns:
        HealthResponse with status, timestamp, database status, and version
    """
    try:
        # Check database connectivity
        conn = db_connect_with_retry(timeout=5.0, max_retries=1)
        if not conn:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "database": "unavailable",
                    "version": Config.API_VERSION
                }
            )
        conn.close()
        
        return HealthResponse(
            status="healthy",
            timestamp=datetime.now(timezone.utc).isoformat(),
            database="ok",
            version=Config.API_VERSION
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "database": f"error: {str(e)}",
                "version": Config.API_VERSION
            }
        )

@app.get("/styles.css")
def serve_styles_css():
    return FileResponse("frontend/styles.css", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

@app.get("/Fortinet-logomark-rgb-red.svg")
@app.get("/images/Fortinet-logomark-rgb-red.svg")
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

# Login page
@app.get("/login")
def login_page():
    return FileResponse("frontend/login.html", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

# Root: serve the SPA index (requires authentication)
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
        path in {"/", "/index.html", "/app.js", "/styles.css"} or
        path.endswith(('.html', '.js', '.css'))):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Serve section HTML files for dynamic loading
@app.get("/preparation.html")
def serve_preparation():
    return FileResponse("frontend/preparation.html", media_type="text/html")

@app.get("/configurations.html")
def serve_configurations():
    return FileResponse("frontend/configurations.html", media_type="text/html")

@app.get("/event-schedule.html")
def serve_event_schedule():
    return FileResponse("frontend/event-schedule.html", media_type="text/html")

@app.get("/nhi-management.html")
def serve_nhi_management():
    return FileResponse("frontend/nhi-management.html", media_type="text/html")

@app.get("/ssh-keys.html")
def serve_ssh_keys():
    return FileResponse("frontend/ssh-keys.html", media_type="text/html")

@app.get("/ssh-command-profiles.html")
def serve_ssh_command_profiles():
    return FileResponse("frontend/ssh-command-profiles.html", media_type="text/html")

@app.get("/server-logs.html")
def serve_server_logs_page():
    return FileResponse("frontend/server-logs.html", media_type="text/html")

@app.get("/audit-logs.html")
def serve_audit_logs():
    return FileResponse("frontend/audit-logs.html", media_type="text/html")

@app.get("/reports.html")
def serve_reports():
    return FileResponse("frontend/reports.html", media_type="text/html")

@app.get("/favicon.ico")
def serve_favicon():
    return FileResponse("frontend/images/favicon.ico", media_type="image/x-icon")


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


# User authentication endpoints
class LoginReq(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
def login(req: LoginReq):
    """Login endpoint - authenticate user and create session"""
    try:
        user = get_user_by_username(req.username)
        if not user:
            logger.warning(f"Login attempt failed: user '{req.username}' not found")
            raise HTTPException(401, "Invalid username or password")
        
        # Debug logging for password verification
        logger.info(f"Login attempt for user '{req.username}': password length={len(req.password)}")
        password_valid = verify_password(req.password, user['password_encrypted'])
        logger.info(f"Password verification result for user '{req.username}': {password_valid}")
        if not password_valid:
            # Try to see if there's a decryption error
            try:
                from src.app import decrypt_with_server_secret
                decrypt_with_server_secret(user['password_encrypted'])
                logger.info(f"Password decryption successful, hash comparison failed")
            except Exception as e:
                logger.error(f"Password decryption failed: {e}", exc_info=True)
        
        if not password_valid:
            logger.warning(f"Login attempt failed: invalid password for user '{req.username}'")
            raise HTTPException(401, "Invalid username or password")
        
        # Create user session
        try:
            session_id, expires_at = create_user_session(user['id'])
            logger.info(f"User '{req.username}' logged in successfully")
        except Exception as e:
            logger.error(f"Failed to create session for user '{req.username}': {e}", exc_info=True)
            raise HTTPException(500, "Failed to create session")
        
        # Create response with cookie (session-based, no max_age for session cookie)
        response = JSONResponse({
            "status": "ok",
            "username": user['username'],
            "expires_at": expires_at.isoformat()
        })
        response.set_cookie(
            key="fabricstudio_session",
            value=session_id,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax"
            # No max_age - session cookie, expires when browser closes
        )
        
        # Audit log
        try:
            log_audit("user_login", user=user['username'], details=f"user_id={user['id']}")
        except Exception:
            pass
        
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {e}", exc_info=True)
        raise HTTPException(500, "Internal server error during login")

@app.post("/auth/logout")
def logout(request: Request):
    """Logout endpoint - invalidate session"""
    session = get_session_from_request(request)
    if session:
        delete_session(session['session_id'])
        try:
            # Get username from session
            username = get_current_username(request)
            log_audit("user_logout", user=username, request=request)
        except Exception:
            pass
    
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(key="fabricstudio_session")
    return response

# User Management endpoints
def validate_password_policy(password: str) -> tuple[bool, str]:
    """Validate password policy: 7 chars, 1 number, 1 special char"""
    if len(password) < 7:
        return False, "Password must be at least 7 characters long"
    
    has_number = any(c.isdigit() for c in password)
    if not has_number:
        return False, "Password must contain at least one number"
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    has_special = any(c in special_chars for c in password)
    if not has_special:
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
    
    return True, ""

class ChangePasswordReq(BaseModel):
    current_password: str
    new_password: str

@app.post("/user/change-password")
def change_password(req: ChangePasswordReq, request: Request):
    """Change user password - requires current password and validates new password policy"""
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "Authentication required")
    
    user_id = session['user_id']
    
    # Get current user
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        c.execute('SELECT username, password_encrypted FROM users WHERE id = ?', (user_id,))
        user_row = c.fetchone()
        if not user_row:
            raise HTTPException(404, "User not found")
        
        username = user_row[0]
        current_password_encrypted = user_row[1]
        
        # Verify current password
        if not verify_password(req.current_password, current_password_encrypted):
            raise HTTPException(400, "Current password is incorrect")
        
        # Validate new password policy
        is_valid, error_msg = validate_password_policy(req.new_password)
        if not is_valid:
            raise HTTPException(400, error_msg)
        
        # Update password
        update_user_password(user_id, req.new_password)
        
        # Audit log
        try:
            log_audit("user_password_changed", user=username, details=f"user_id={user_id}")
        except Exception:
            pass
        
        return {"status": "ok", "message": "Password changed successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password: {e}", exc_info=True)
        raise HTTPException(500, f"Internal server error: {str(e)}")
    finally:
        conn.close()

@app.get("/user/current")
def get_current_user(request: Request):
    """Get current user information"""
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "Authentication required")
    
    user_id = session['user_id']
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        c.execute('SELECT id, username, created_at, updated_at FROM users WHERE id = ?', (user_id,))
        user_row = c.fetchone()
        if not user_row:
            raise HTTPException(404, "User not found")
        
        return {
            "id": user_row[0],
            "username": user_row[1],
            "created_at": user_row[2],
            "updated_at": user_row[3]
        }
    finally:
        conn.close()

@app.get("/user/list")
def list_users(request: Request):
    """List all users"""
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "Authentication required")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        c.execute('SELECT id, username, created_at, updated_at FROM users ORDER BY username ASC')
        rows = c.fetchall()
        users = []
        for row in rows:
            users.append({
                "id": row[0],
                "username": row[1],
                "created_at": row[2],
                "updated_at": row[3]
            })
        return {"users": users}
    finally:
        conn.close()

class CreateUserReq(BaseModel):
    username: str
    password: str

@app.post("/user/create")
def create_user_endpoint(req: CreateUserReq, request: Request):
    """Create a new user"""
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "Authentication required")
    
    # Validate username
    if not req.username or not req.username.strip():
        raise HTTPException(400, "Username is required")
    
    username = req.username.strip()
    if len(username) > 100:
        raise HTTPException(400, "Username exceeds maximum length of 100 characters")
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise HTTPException(400, "Username must contain only alphanumeric characters, dashes, and underscores")
    
    # Validate password policy
    is_valid, error_msg = validate_password_policy(req.password)
    if not is_valid:
        raise HTTPException(400, error_msg)
    
    try:
        user_id = create_user(username, req.password)
        
        # Audit log
        try:
            current_username = get_current_username(request)
            log_audit("user_created", user=current_username, details=f"created_user={username}, user_id={user_id}", request=request)
        except Exception:
            pass
        
        return {"status": "ok", "message": f"User '{username}' created successfully", "user_id": user_id}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"Error creating user: {e}", exc_info=True)
        raise HTTPException(500, "Failed to create user")

@app.delete("/user/{user_id}")
def delete_user(user_id: int, request: Request):
    """Delete a user"""
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "Authentication required")
    
    current_user_id = session['user_id']
    
    # Prevent users from deleting themselves
    if user_id == current_user_id:
        raise HTTPException(400, "You cannot delete your own account")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        # Get username before deletion for audit log
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user_row = c.fetchone()
        if not user_row:
            raise HTTPException(404, "User not found")
        
        username = user_row[0]
        
        # Delete user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        if c.rowcount == 0:
            raise HTTPException(404, "User not found")
        
        conn.commit()
        
        # Audit log
        try:
            current_username = get_current_username(request)
            log_audit("user_deleted", user=current_username, details=f"deleted_user={username}, user_id={user_id}", request=request)
        except Exception:
            pass
        
        return {"status": "ok", "message": f"User '{username}' deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}", exc_info=True)
        raise HTTPException(500, "Failed to delete user")
    finally:
        conn.close()

@app.post("/auth/token")
def auth_token(req: TokenReq):
    # Validate inputs
    req.fabric_host = validate_fabric_host(req.fabric_host)
    req.client_id = validate_client_id(req.client_id)
    req.client_secret = validate_client_secret(req.client_secret)
    
    token_data = get_access_token(req.client_id, req.client_secret, req.fabric_host)
    if not token_data or not token_data.get("access_token"):
        raise HTTPException(400, "Failed to get token")
    return {
        "access_token": token_data.get("access_token"),
        "expires_in": token_data.get("expires_in")  # Seconds until expiration
    }


@app.get("/system/hostname")
def get_hostname(request: Request, fabric_host: str):
    fabric_host = validate_fabric_host(fabric_host)
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    value = query_hostname(fabric_host, token)
    if value is None:
        raise HTTPException(400, "Failed to query hostname")
    return {"hostname": value}


@app.post("/system/hostname")
def set_hostname(request: Request, req: HostnameReq):
    req.fabric_host = validate_fabric_host(req.fabric_host)
    req.hostname = validate_hostname(req.hostname)
    token = get_access_token_from_request(request, req.fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    change_hostname(req.fabric_host, token, req.hostname)
    return {"status": "ok"}


@app.post("/user/password")
def set_password(request: Request, req: UserPassReq):
    try:
        token = get_access_token_from_request(request, req.fabric_host)
        if not token:
            raise HTTPException(401, "Missing access_token in session or Authorization header")
        user_id = get_userId(req.fabric_host, token, req.username)
        if not user_id:
            raise HTTPException(404, f"User '{req.username}' not found on host {req.fabric_host}")
        change_fabricstudio_password(req.fabric_host, token, user_id, req.new_password)
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error changing password for user '{req.username}' on host {req.fabric_host}: {e}", exc_info=True)
        raise HTTPException(500, f"Failed to change password: {str(e)}")


@app.post("/runtime/reset")
def runtime_reset(request: Request, fabric_host: str):
    fabric_host = validate_fabric_host(fabric_host)
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    reset_fabric(fabric_host, token)
    return {"status": "ok"}


@app.delete("/model/fabric/batch")
def model_batch_delete(request: Request, fabric_host: str):
    fabric_host = validate_fabric_host(fabric_host)
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    batch_delete(fabric_host, token)
    return {"status": "ok"}


@app.post("/repo/refresh")
def repo_refresh(request: Request, fabric_host: str):
    fabric_host = validate_fabric_host(fabric_host)
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    
    # Log refresh start
    refresh_id = log_repository_refresh(fabric_host, 'started')
    
    # Refresh repositories
    success = refresh_repositories(fabric_host, token)
    
    # Invalidate repository cache after refresh (but keep template cache for durability)
    conn = db_connect_with_retry()
    if conn:
        try:
            c = conn.cursor()
            c.execute('DELETE FROM cached_repositories WHERE fabric_host = ?', (fabric_host,))
            # Don't delete template cache - it will be updated incrementally when templates are fetched
            conn.commit()
        except Exception as e:
            logger.error(f"Error invalidating cache: {e}")
        finally:
            conn.close()
    
    # Log refresh completion
    if success:
        # Get repository count after refresh (don't use cache since we just invalidated it)
        repos = list_repositories(fabric_host, token)
        repo_count = len(repos) if repos else 0
        log_repository_refresh(fabric_host, 'completed', repositories_count=repo_count)
        return {"status": "ok", "message": "Repository refresh initiated"}
    else:
        log_repository_refresh(fabric_host, 'failed', error_message="Refresh request failed")
        raise HTTPException(500, "Repository refresh failed")

@app.get("/repo/refresh/status")
def repo_refresh_status(fabric_host: str):
    """Get the latest refresh status for a fabric host"""
    fabric_host = validate_fabric_host(fabric_host)
    status = get_latest_refresh_status(fabric_host)
    if status:
        return status
    else:
        return {"status": "unknown", "message": "No refresh history found"}


@app.post("/model/fabric")
def model_fabric_create(request: Request, req: CreateFabricReq):
    req.fabric_host = validate_fabric_host(req.fabric_host)
    req.template_name = validate_template_name(req.template_name)
    if req.version:
        req.version = validate_version(req.version)
    
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
            log_audit("fabric_create_error", details=f"host={req.fabric_host} template={req.template_name} version={req.version} errors={' ; '.join(errors) if errors else 'unknown'} duration_s={create_duration:.1f}", request=request)
        except Exception:
            pass
        error_msg = "Failed to create fabric"
        if errors:
            error_msg += ": " + "; ".join(errors)
        else:
            error_msg += ": creation timed out or encountered an error"
        raise HTTPException(500, error_msg)
    try:
        log_audit("fabric_created", details=f"host={req.fabric_host} template={req.template_name} version={req.version} duration_s={create_duration:.1f}", request=request)
    except Exception:
        pass
    return {"status": "ok", "message": "Fabric created successfully"}


@app.post("/runtime/fabric/install")
def model_fabric_install(request: Request, req: InstallFabricReq):
    req.fabric_host = validate_fabric_host(req.fabric_host)
    req.template_name = validate_template_name(req.template_name)
    if req.version:
        req.version = validate_version(req.version)
    
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
            log_audit("fabric_install_error", details=f"host={req.fabric_host} template={req.template_name} version={req.version} errors={' ; '.join(errors) if errors else 'unknown'} duration_s={install_duration:.1f}", request=request)
        except Exception:
            pass
        error_msg = "Failed to install fabric"
        if errors:
            error_msg += ": " + "; ".join(errors)
        else:
            error_msg += ": installation timed out or encountered an error"
        raise HTTPException(500, error_msg)
    try:
        log_audit("fabric_installed", details=f"host={req.fabric_host} template={req.template_name} version={req.version} duration_s={install_duration:.1f}", request=request)
    except Exception:
        pass
    return {"status": "ok", "message": "Fabric installed successfully"}


@app.get("/tasks/progress")
def tasks_progress(request: Request, fabric_host: str):
    fabric_host = validate_fabric_host(fabric_host)
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    mins = check_tasks(fabric_host, token, display_progress=False)
    return {"elapsed_minutes": mins}


@app.get("/tasks/status")
def tasks_status(request: Request, fabric_host: str):
    fabric_host = validate_fabric_host(fabric_host)
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
    fabric_host = validate_fabric_host(fabric_host)
    # Validate limit
    if limit < 1 or limit > 1000:
        raise HTTPException(400, "Limit must be between 1 and 1000")
    
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


# Legacy _init_db() function removed - cache.db is deprecated
# All template caching now uses cached_templates table in main database


@app.post("/preparation/confirm")
def preparation_confirm(request: Request, fabric_host: str):
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    
    # Log refresh start
    log_repository_refresh(fabric_host, 'started')
    
    # 1) refresh repos (async on host)
    success = refresh_repositories(fabric_host, token)
    
    # Wait for background repo refresh tasks to complete to ensure templates are up to date
    try:
        check_tasks(fabric_host, token, display_progress=False)
    except Exception:
        # Best-effort wait; continue even if polling fails
        pass
    
    # Invalidate repository cache after refresh (but keep template cache for durability)
    conn = db_connect_with_retry()
    if conn:
        try:
            c = conn.cursor()
            c.execute('DELETE FROM cached_repositories WHERE fabric_host = ?', (fabric_host,))
            # Don't delete template cache - it will be updated incrementally when templates are fetched
            conn.commit()
        except Exception as e:
            logger.error(f"Error invalidating cache: {e}")
        finally:
            conn.close()
    
    # 2) fetch all templates across repos
    templates = list_all_templates(fabric_host, token)
    
    # Cache the templates
    if templates:
        cache_templates(templates)
    
    # Log refresh completion
    if success:
        repos = list_repositories(fabric_host, token)
        repo_count = len(repos) if repos else 0
        log_repository_refresh(fabric_host, 'completed', repositories_count=repo_count)
    else:
        log_repository_refresh(fabric_host, 'failed', error_message="Refresh request failed")
    
    # Cache population removed - templates are fetched but not stored in cache table
    return {"count": len(templates) if templates else 0}


# Legacy cache.db endpoints removed - now using cached_templates table only
# See get_cached_templates() and cache_templates() below for current implementation


# Repository cache functions
def get_cached_repositories(fabric_host: str):
    """Get cached repositories for a host if cache is still valid"""
    conn = db_connect_with_retry()
    if not conn:
        return None
    
    try:
        c = conn.cursor()
        now = datetime.now(timezone.utc)
        
        # Get all cached repositories for this host that haven't expired
        c.execute('''
            SELECT repo_id, repo_name, repo_data
            FROM cached_repositories
            WHERE fabric_host = ? AND expires_at > ?
            ORDER BY repo_name
        ''', (fabric_host, now.isoformat()))
        
        rows = c.fetchall()
        if rows:
            repos = []
            for repo_id, repo_name, repo_data_json in rows:
                try:
                    repo_data = json.loads(repo_data_json)
                    repos.append(repo_data)
                except (json.JSONDecodeError, TypeError):
                    continue
            logger.debug(f"Retrieved {len(repos)} cached repositories for {fabric_host}")
            return repos
        return None
    except Exception as e:
        logger.error(f"Error retrieving cached repositories: {e}")
        return None
    finally:
        conn.close()

def cache_repositories(fabric_host: str, repositories: list):
    """Cache repositories for a host with TTL"""
    if not repositories:
        return
    
    conn = db_connect_with_retry()
    if not conn:
        return
    
    try:
        c = conn.cursor()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=Config.REPO_CACHE_TTL_HOURS)
        
        # Delete existing cache for this host
        c.execute('DELETE FROM cached_repositories WHERE fabric_host = ?', (fabric_host,))
        
        # Insert new cache entries
        for repo in repositories:
            repo_id = repo.get('id')
            repo_name = repo.get('name')
            if not repo_id or not repo_name:
                continue
            
            try:
                repo_data_json = json.dumps(repo)
                c.execute('''
                    INSERT OR REPLACE INTO cached_repositories 
                    (fabric_host, repo_id, repo_name, repo_data, cached_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (fabric_host, str(repo_id), repo_name, repo_data_json, now.isoformat(), expires_at.isoformat()))
            except Exception as e:
                logger.error(f"Error caching repository {repo_name}: {e}")
                continue
        
        conn.commit()
        logger.info(f"Cached {len(repositories)} repositories for {fabric_host}")
    except Exception as e:
        logger.error(f"Error caching repositories: {e}")
        conn.rollback()
    finally:
        conn.close()

def log_repository_refresh(fabric_host: str, status: str, error_message: str = None, repositories_count: int = None):
    """Log repository refresh operation"""
    conn = db_connect_with_retry()
    if not conn:
        return None
    
    try:
        c = conn.cursor()
        now = datetime.now(timezone.utc)
        
        if status == 'started':
            c.execute('''
                INSERT INTO repository_refresh_logs 
                (fabric_host, status, started_at)
                VALUES (?, ?, ?)
            ''', (fabric_host, status, now.isoformat()))
            conn.commit()
            refresh_id = c.lastrowid
            return refresh_id
        elif status in ('completed', 'failed'):
            # Update latest refresh log for this host
            c.execute('''
                SELECT id FROM repository_refresh_logs
                WHERE fabric_host = ? AND status = 'started'
                ORDER BY started_at DESC
                LIMIT 1
            ''', (fabric_host,))
            row = c.fetchone()
            if row:
                refresh_id = row[0]
                c.execute('''
                    UPDATE repository_refresh_logs
                    SET status = ?, completed_at = ?, error_message = ?, repositories_count = ?
                    WHERE id = ?
                ''', (status, now.isoformat(), error_message, repositories_count, refresh_id))
                conn.commit()
                return refresh_id
        return None
    except Exception as e:
        logger.error(f"Error logging repository refresh: {e}")
        return None
    finally:
        conn.close()

def get_latest_refresh_status(fabric_host: str):
    """Get the latest refresh status for a host"""
    conn = db_connect_with_retry()
    if not conn:
        return None
    
    try:
        c = conn.cursor()
        c.execute('''
            SELECT status, started_at, completed_at, error_message, repositories_count
            FROM repository_refresh_logs
            WHERE fabric_host = ?
            ORDER BY started_at DESC
            LIMIT 1
        ''', (fabric_host,))
        row = c.fetchone()
        if row:
            return {
                'status': row[0],
                'started_at': row[1],
                'completed_at': row[2],
                'error_message': row[3],
                'repositories_count': row[4]
            }
        return None
    except Exception as e:
        logger.error(f"Error getting refresh status: {e}")
        return None
    finally:
        conn.close()
# Template cache functions
def cache_templates(templates: list):
    """
    Cache templates with TTL. Durable cache that compares and updates incrementally.
    - Keeps expired templates when host is unreachable
    - Updates existing templates and adds new ones
    - Only removes templates that are no longer present in the new data
    """
    if not templates:
        return
    
    conn = db_connect_with_retry()
    if not conn:
        return
    
    try:
        c = conn.cursor()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=Config.TEMPLATE_CACHE_TTL_HOURS)
        
        # Get existing templates (including expired ones) for comparison
        c.execute('''
            SELECT repo_id, repo_name, template_id, template_name, version
            FROM cached_templates
        ''')
        existing_templates = set()
        for row in c.fetchall():
            # Create a unique key: repo_name:template_name:version
            key = f"{row[1]}:{row[3]}:{row[4] or ''}"
            existing_templates.add(key)
        
        # Build set of new templates
        new_templates = set()
        templates_to_insert = []
        
        for template in templates:
            repo_id = template.get('repository_id') or template.get('repo_id')
            repo_name = template.get('repository_name') or template.get('repo_name')
            template_id = template.get('id') or template.get('template_id')
            template_name = template.get('name') or template.get('template_name')
            version = template.get('version')
            
            if not repo_id or not repo_name or not template_id or not template_name:
                continue
            
            # Create unique key
            key = f"{repo_name}:{template_name}:{version or ''}"
            new_templates.add(key)
            templates_to_insert.append((str(repo_id), repo_name, str(template_id), template_name, version))
        
        # Insert or update templates (this will refresh expires_at for existing templates)
        updated_count = 0
        new_count = 0
        for repo_id, repo_name, template_id, template_name, version in templates_to_insert:
            try:
                # Check if template already exists
                c.execute('''
                    SELECT id FROM cached_templates
                    WHERE repo_name = ? AND template_name = ? AND version = ?
                ''', (repo_name, template_name, version))
                exists = c.fetchone()
                
                if exists:
                    # Update existing template (refresh expires_at and template_id in case it changed)
                    c.execute('''
                        UPDATE cached_templates
                        SET repo_id = ?, template_id = ?, cached_at = ?, expires_at = ?
                        WHERE repo_name = ? AND template_name = ? AND version = ?
                    ''', (repo_id, template_id, now.isoformat(), expires_at.isoformat(), repo_name, template_name, version))
                    updated_count += 1
                else:
                    # Insert new template
                    c.execute('''
                        INSERT INTO cached_templates 
                        (repo_id, repo_name, template_id, template_name, version, cached_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (repo_id, repo_name, template_id, template_name, version, now.isoformat(), expires_at.isoformat()))
                    new_count += 1
            except Exception as e:
                logger.error(f"Error caching template {template_name}: {e}")
                continue
        
        # Remove templates that are no longer present in the new data
        # This ensures cache stays in sync with the source (LEAD_FABRIC_HOST)
        # Only remove if we successfully fetched new data and template is not in it
        removed_count = 0
        templates_to_remove = existing_templates - new_templates
        if templates_to_remove:
            logger.debug(f"Removing {len(templates_to_remove)} templates that are no longer in source")
            for key in templates_to_remove:
                parts = key.split(':')
                if len(parts) == 3:
                    repo_name, template_name, version = parts
                    c.execute('''
                        DELETE FROM cached_templates
                        WHERE repo_name = ? AND template_name = ? AND version = ?
                    ''', (repo_name, template_name, version if version else None))
                    removed_count += c.rowcount
        
        conn.commit()
        logger.info(f"Template cache updated: {new_count} new, {updated_count} updated, {removed_count} removed (expires at {expires_at.isoformat()})")
    except Exception as e:
        logger.error(f"Error caching templates: {e}")
        conn.rollback()
    finally:
        conn.close()

def get_cached_templates_internal():
    """
    Get all cached templates. Returns both valid and expired templates for durability.
    Expired templates are kept when host is unreachable to maintain cache availability.
    """
    conn = db_connect_with_retry()
    if not conn:
        return []
    
    try:
        c = conn.cursor()
        now = datetime.now(timezone.utc)
        
        # Get all cached templates (including expired ones for durability)
        # Expired templates are still useful when host is unreachable
        c.execute('''
            SELECT repo_id, repo_name, template_id, template_name, version, cached_at, expires_at
            FROM cached_templates
            ORDER BY repo_name, template_name, version
        ''')
        
        rows = c.fetchall()
        templates = []
        for row in rows:
            expires_at_str = row[6]
            is_expired = False
            if expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(expires_at_str)
                    is_expired = expires_at <= now
                except:
                    pass
            
            templates.append({
                "repo_id": row[0],
                "repo_name": row[1],
                "template_id": row[2],
                "template_name": row[3],
                "version": row[4],
                "cached_at": row[5],
                "expired": is_expired  # Indicate if template is expired but still available
            })
        return templates
    except Exception as e:
        logger.error(f"Error retrieving cached templates: {e}")
        return []
    finally:
        conn.close()

def get_cached_templates_for_repo(repo_name: str):
    """Get templates for a repository from cache"""
    templates = get_cached_templates_internal()
    if not templates:
        return []
    
    repo_input = (repo_name or "").strip().lower()
    repo_templates = []
    for template in templates:
        template_repo_name = (template.get("repo_name") or "").strip().lower()
        if template_repo_name == repo_input:
            repo_templates.append({
                "id": template.get("template_id"),
                "name": template.get("template_name"),
                "version": template.get("version")
            })
    return repo_templates

def get_cached_template_versions(repo_name: str, template_name: str):
    """Get versions for a template from cache"""
    templates = get_cached_templates_internal()
    if not templates:
        return []
    
    repo_input = (repo_name or "").strip().lower()
    template_input = (template_name or "").strip().lower()
    versions = set()
    
    for template in templates:
        template_repo_name = (template.get("repo_name") or "").strip().lower()
        template_template_name = (template.get("template_name") or "").strip().lower()
        if template_repo_name == repo_input and template_template_name == template_input:
            version = template.get("version")
            if version:
                versions.add(version)
    
    return sorted(list(versions))

def get_cached_template_id(repo_name: str, template_name: str, version: str):
    """Get template ID from cache by repository name, template name, and version"""
    templates = get_cached_templates_internal()
    if not templates:
        return None
    
    repo_input = (repo_name or "").strip().lower()
    template_input = (template_name or "").strip().lower()
    version_input = (version or "").strip()
    
    for template in templates:
        template_repo_name = (template.get("repo_name") or "").strip().lower()
        template_template_name = (template.get("template_name") or "").strip().lower()
        template_version = (template.get("version") or "").strip()
        
        if (template_repo_name == repo_input and 
            template_template_name == template_input and 
            template_version == version_input):
            return template.get("template_id")
    
    return None

# Duplicate GET /repo/remotes endpoint removed - using the one at line 2757 with nhi_credential_id support
# Compatibility endpoint used by preparation flow to resolve a single template_id
@app.get("/repo/template")
def repo_template_single(request: Request, fabric_host: str, template_name: str, repo_name: str, version: str):
    """
    Get template_id for a specific fabric_host.
    
    IMPORTANT: Template IDs are host-specific, so we always query the specific fabric_host
    rather than using the cache (which contains template_ids from LEAD_FABRIC_HOST only).
    The cache is useful for listing available templates, but not for getting template_ids
    for a specific host.
    """
    # Always query the specific fabric_host for template_id since template_ids are host-specific
    # The cache contains template_ids from LEAD_FABRIC_HOST, which may not match other hosts
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
        logger.warning("Repository not found for repo_name='%s' on host %s. Available repos: %s", repo_input, fabric_host, [ (r.get('id'), r.get('name')) for r in repos ])
        raise HTTPException(404, "Repository not found")

    rid = match.get("id")
    templates = list_templates_for_repo(fabric_host, token, rid)
    tname_norm = (template_name or "").strip().lower()
    ver_norm = (version or "").strip()
    for t in templates:
        name_norm = (t.get("name") or "").strip().lower()
        ver_val = (t.get("version") or "").strip()
        if name_norm == tname_norm and ver_val == ver_norm:
            template_id = t.get("id")
            logger.debug(f"Found template_id {template_id} for {template_name} v{version} in repo {repo_name} on host {fabric_host}")
            return {"template_id": template_id}
    sample = [{"id": x.get("id"), "name": x.get("name"), "version": x.get("version")} for x in templates[:5]]
    logger.warning("Template not found in repo '%s' on host %s. Looking for name='%s' version='%s'. Sample: %s", match.get("name"), fabric_host, template_name, version, sample)
    raise HTTPException(404, "Template not found")


# New lightweight proxy endpoints for repository/template metadata
@app.get("/repo/remotes")
def repo_remotes_proxy(request: Request, fabric_host: str, nhi_credential_id: Optional[int] = None):
    # Try cache first - no authentication required if cache is available
    cached_repos = get_cached_repositories(fabric_host)
    if cached_repos:
        logger.debug(f"Using cached repositories for {fabric_host}")
        repos = cached_repos
    else:
        # Fallback to API if cache is empty/expired
        token = get_access_token_from_request(request, fabric_host, nhi_credential_id)
        if not token:
            raise HTTPException(401, "Missing access_token in session or Authorization header")
        
        # Fetch from API and cache
        repos = list_repositories(fabric_host, token)
        if repos:
            cache_repositories(fabric_host, repos)
    
    # Return minimal info: id and name
    return {"repositories": [{"id": r.get("id"), "name": r.get("name")} for r in repos]}


@app.get("/repo/templates/list")
def repo_templates_list(request: Request, fabric_host: str, repo_name: str):
    # Try cache first - no authentication required if cache is available
    templates = get_cached_templates_for_repo(repo_name)
    if templates:
        logger.debug(f"Using cached templates for repository {repo_name}")
        return {"templates": templates}
    
    # Fallback to API if cache is empty/expired
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    
    # Resolve repo id using standardized function
    repo_id = get_repositoryId(fabric_host, token, repo_name)
    if repo_id is None:
        raise HTTPException(404, "Repository not found")
    
    # List templates for repo
    url_tpl = f"https://{fabric_host}/api/v1/system/repository/template?select=repository={repo_id}"
    headers = {"Authorization": f"Bearer {token}", "Cache-Control": "no-cache"}
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
    # Try cache first - no authentication required if cache is available
    versions = get_cached_template_versions(repo_name, template_name)
    if versions:
        logger.debug(f"Using cached versions for template {template_name} in repository {repo_name}")
        return {"versions": versions}
    
    # Fallback to API if cache is empty/expired
    token = get_access_token_from_request(request, fabric_host)
    if not token:
        raise HTTPException(401, "Missing access_token in session or Authorization header")
    
    # Reuse templates/list and filter versions
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


# Template cache population endpoint removed - cache is no longer populated


@app.get("/cache/templates")
def get_cached_templates():
    """Get all cached templates (independent of hosts) that haven't expired"""
    templates = get_cached_templates_internal()
    return {"templates": templates, "count": len(templates)}


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
    
    # Validate host count limit
    hosts = req.config_data.get('confirmedHosts', [])
    if len(hosts) > MAX_HOSTS_PER_CONFIG:
        raise HTTPException(400, f"Maximum {MAX_HOSTS_PER_CONFIG} hosts allowed per configuration")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
        log_audit(log_action, details=f"Configuration '{req.name}' (ID: {config_id})", request=request)
        
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    except Exception as e:
        raise HTTPException(500, f"Error listing configurations: {str(e)}")
    finally:
        conn.close()


@app.get("/config/get/{config_id}")
def get_config(config_id: int):
    """Retrieve a configuration by ID"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
        log_audit("configuration_deleted", details=f"Configuration '{config_name}' (ID: {config_id})", request=request)
        
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
    # Frontend sends date/time in UTC (converted from user's local timezone)
    try:
        event_time_str = req.event_time if req.event_time else "00:00:00"
        # Normalize time format: HTML5 time input returns HH:MM, but we need HH:MM:SS
        if event_time_str and len(event_time_str.split(':')) == 2:
            event_time_str = event_time_str + ":00"
        
        # Parse date/time as UTC (frontend sends UTC)
        event_datetime_str = f"{req.event_date} {event_time_str}"
        event_datetime = datetime.strptime(event_datetime_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        
        # Store date and time in UTC
        utc_date = event_datetime.date()
        utc_time = event_datetime.time().replace(second=0, microsecond=0)
        
        # Validate not in past (compare UTC times)
        now_utc = datetime.now(timezone.utc)
        if event_datetime < now_utc:
            raise HTTPException(400, "Event date and time cannot be in the past")
    except ValueError as e:
        raise HTTPException(400, f"Invalid date/time format: {str(e)}")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    # Flag to track if migration already committed
    migration_committed = False
    
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
            
            # Store UTC date and time
            c.execute('''
                UPDATE event_schedules 
                SET name = ?, event_date = ?, event_time = ?, configuration_id = ?, auto_run = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (req.name.strip(), utc_date.strftime('%Y-%m-%d'), utc_time.strftime('%H:%M'), req.configuration_id, 1 if req.auto_run else 0, req.id))
            
            # Clear execution records when event is updated so badge returns to green
            c.execute('DELETE FROM event_executions WHERE event_id = ?', (req.id,))
            
            action = "updated"
            event_id = req.id
        else:
            # Insert new event - store UTC date and time
            c.execute('''
                INSERT INTO event_schedules (name, event_date, event_time, configuration_id, auto_run, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (req.name.strip(), utc_date.strftime('%Y-%m-%d'), utc_time.strftime('%H:%M'), req.configuration_id, 1 if req.auto_run else 0))
            action = "saved"
            event_id = c.lastrowid
        
        # Store NHI credential ID for event (no password needed - using FS_SERVER_SECRET)
        try:
            # Load configuration to extract nhiCredentialId
            c.execute('SELECT config_data FROM configurations WHERE id = ?', (req.configuration_id,))
            cfg_row = c.fetchone()
            if cfg_row:
                cfg = json.loads(cfg_row[0])
                nhi_cred_id = cfg.get('nhiCredentialId')
                if nhi_cred_id:
                    # Store NHI credential ID
                    try:
                        c.execute('''
                            INSERT INTO event_nhi_passwords (event_id, nhi_credential_id, updated_at)
                            VALUES (?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(event_id) DO UPDATE SET
                                nhi_credential_id=excluded.nhi_credential_id,
                                updated_at=CURRENT_TIMESTAMP
                        ''', (event_id, int(nhi_cred_id)))
                    except sqlite3.IntegrityError as integrity_err:
                        if "password_encrypted" in str(integrity_err):
                            # Migration hasn't run yet - need to rollback current transaction first
                            logger.warning(f"Database migration needed - password_encrypted column still exists. Attempting migration...")
                            try:
                                # Rollback current transaction to allow migration
                                conn.rollback()
                                
                                # Check if password_encrypted column exists
                                c.execute("PRAGMA table_info(event_nhi_passwords)")
                                columns_info = c.fetchall()
                                columns = [row[1] for row in columns_info]
                                if 'password_encrypted' in columns:
                                    # Run migration in a new transaction
                                    c.execute('PRAGMA foreign_keys=OFF')
                                    c.execute('BEGIN TRANSACTION')
                                    
                                    # Clean up any leftover table from previous failed migration
                                    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='event_nhi_passwords_new'")
                                    if c.fetchone():
                                        logger.info("Cleaning up leftover event_nhi_passwords_new table from previous migration")
                                        c.execute('DROP TABLE event_nhi_passwords_new')
                                    
                                    c.execute('''
                                        CREATE TABLE event_nhi_passwords_new (
                                            event_id INTEGER PRIMARY KEY,
                                            nhi_credential_id INTEGER NOT NULL,
                                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                            FOREIGN KEY (event_id) REFERENCES event_schedules(id) ON DELETE CASCADE,
                                            FOREIGN KEY (nhi_credential_id) REFERENCES nhi_credentials(id) ON DELETE CASCADE
                                        )
                                    ''')
                                    c.execute('''
                                        INSERT INTO event_nhi_passwords_new 
                                        (event_id, nhi_credential_id, created_at, updated_at)
                                        SELECT event_id, nhi_credential_id, created_at, updated_at
                                        FROM event_nhi_passwords
                                    ''')
                                    c.execute('DROP TABLE event_nhi_passwords')
                                    c.execute('ALTER TABLE event_nhi_passwords_new RENAME TO event_nhi_passwords')
                                    c.execute('COMMIT')
                                    c.execute('PRAGMA foreign_keys=ON')
                                    conn.commit()
                                    logger.info("Successfully migrated event_nhi_passwords table during event save")
                                    
                                    # Now restart the event save transaction
                                    # Re-insert/update the event (need to redo everything since we rolled back)
                                    if req.id:
                                        # Update existing event
                                        c.execute('''
                                            UPDATE event_schedules 
                                            SET name = ?, event_date = ?, event_time = ?, configuration_id = ?, auto_run = ?, updated_at = CURRENT_TIMESTAMP
                                            WHERE id = ?
                                        ''', (req.name.strip(), utc_date.strftime('%Y-%m-%d'), utc_time.strftime('%H:%M'), req.configuration_id, 1 if req.auto_run else 0, req.id))
                                        
                                        # Clear execution records when event is updated so badge returns to green
                                        c.execute('DELETE FROM event_executions WHERE event_id = ?', (req.id,))
                                        
                                        action = "updated"
                                        event_id = req.id
                                    else:
                                        # Insert new event
                                        c.execute('''
                                            INSERT INTO event_schedules (name, event_date, event_time, configuration_id, auto_run, created_at)
                                            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                                        ''', (req.name.strip(), utc_date.strftime('%Y-%m-%d'), utc_time.strftime('%H:%M'), req.configuration_id, 1 if req.auto_run else 0))
                                        action = "saved"
                                        event_id = c.lastrowid
                                    
                                    # Now retry the NHI credential insert
                                    c.execute('''
                                        INSERT INTO event_nhi_passwords (event_id, nhi_credential_id, updated_at)
                                        VALUES (?, ?, CURRENT_TIMESTAMP)
                                        ON CONFLICT(event_id) DO UPDATE SET
                                            nhi_credential_id=excluded.nhi_credential_id,
                                            updated_at=CURRENT_TIMESTAMP
                                    ''', (event_id, int(nhi_cred_id)))
                                    
                                    # Commit the entire operation
                                    conn.commit()
                                    migration_committed = True
                                else:
                                    raise integrity_err
                            except Exception as migration_err:
                                try:
                                    c.execute('ROLLBACK')
                                except:
                                    pass
                                try:
                                    c.execute('PRAGMA foreign_keys=ON')
                                except:
                                    pass
                                conn.rollback()
                                logger.error(f"Failed to migrate during event save: {migration_err}", exc_info=True)
                                raise HTTPException(500, "Database migration failed. Please restart the application.")
                        else:
                            raise
                else:
                    logger.warning(f"Configuration {req.configuration_id} has no nhiCredentialId; skipping NHI credential store")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error storing NHI credential for event {event_id}: {e}", exc_info=True)
        
        # Only commit if migration didn't already commit
        if not migration_committed:
            conn.commit()
        
        # Log audit event
        log_action = "event_created" if action == "saved" else "event_updated"
        config_name = config[1] if config else f"ID {req.configuration_id}"
        log_audit(log_action, details=f"Event '{req.name}' (ID: {event_id}) - Configuration: {config_name}", request=request)
        
        return {"status": "ok", "message": f"Event '{req.name}' {action} successfully", "id": event_id}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()
@app.get("/event/list")
def list_events():
    """List all event schedules"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
        logger.error(f"Error in list_events: {error_detail}")
        raise HTTPException(500, f"Error listing events: {str(e)}")
    finally:
        conn.close()


@app.get("/event/get/{event_id}")
def get_event(event_id: int):
    """Retrieve an event by ID"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
        log_audit("event_deleted", details=f"Event '{event_name}' (ID: {event_id})", request=request)
        
        return {"status": "ok", "message": f"Event {event_id} deleted successfully"}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/event/executions/{event_id}")
def get_event_executions(event_id: int):
    """Get all execution records for an event"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
@app.get("/run/reports")
def list_manual_runs():
    """List all manual run reports"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT id, configuration_name, status, message, started_at, completed_at, execution_details
            FROM manual_runs
            ORDER BY started_at DESC
            LIMIT 100
        ''')
        rows = c.fetchall()
        
        runs = []
        for row in rows:
            run_id, config_name, status, message, started_at, completed_at, details_json = row
            duration = None
            if started_at and completed_at:
                try:
                    start_dt = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                    end_dt = datetime.fromisoformat(completed_at.replace('Z', '+00:00'))
                    duration = int((end_dt - start_dt).total_seconds())
                except:
                    pass
            
            runs.append({
                "id": run_id,
                "configuration_name": config_name or "Manual Run",
                "status": status,
                "message": message,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": duration
            })
        
        return {"runs": runs}
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.get("/run/reports/{run_id}")
def get_manual_run_report(run_id: int):
    """Get detailed report for a manual run"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        c.execute('''
            SELECT id, configuration_name, status, message, errors, started_at, completed_at, execution_details
            FROM manual_runs
            WHERE id = ?
        ''', (run_id,))
        row = c.fetchone()
        
        if not row:
            raise HTTPException(404, f"Run with id {run_id} not found")
        
        run_id_db, config_name, status, message, errors_json, started_at, completed_at, details_json = row
        errors = json.loads(errors_json) if errors_json else []
        details = json.loads(details_json) if details_json else {}
        
        return {
            "id": run_id_db,
            "configuration_name": config_name or "Manual Run",
            "status": status,
            "message": message,
            "errors": errors,
            "started_at": started_at,
            "completed_at": completed_at,
            "execution_details": details
        }
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.post("/run/create")
def create_manual_run(req: dict):
    """Create a manual run record"""
    try:
        configuration_name = req.get('configuration_name', 'Manual Run')
        conn = db_connect_with_retry()
        if not conn:
            raise HTTPException(500, "Database connection failed")
        c = conn.cursor()
        try:
            started_at = datetime.now(timezone.utc).isoformat()
            c.execute('''
                INSERT INTO manual_runs (configuration_name, status, started_at)
                VALUES (?, ?, ?)
            ''', (configuration_name, 'running', started_at))
            run_id = c.lastrowid
            conn.commit()
            return {"run_id": run_id, "started_at": started_at}
        except sqlite3.Error as e:
            raise HTTPException(500, f"Database error: {str(e)}")
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error creating manual run: {e}", exc_info=True)
        raise HTTPException(500, f"Error creating manual run: {str(e)}")

@app.put("/run/update/{run_id}")
def update_manual_run(run_id: int, req: dict):
    """Update a manual run record"""
    try:
        status = req.get('status', 'running')
        message = req.get('message')
        errors = req.get('errors', [])
        execution_details = req.get('execution_details', {})
        
        conn = db_connect_with_retry()
        if not conn:
            raise HTTPException(500, "Database connection failed")
        c = conn.cursor()
        try:
            completed_at = datetime.now(timezone.utc).isoformat() if status in ['success', 'error'] else None
            c.execute('''
                UPDATE manual_runs
                SET status = ?, message = ?, errors = ?, completed_at = ?, execution_details = ?
                WHERE id = ?
            ''', (
                status,
                message,
                json.dumps(errors) if errors else None,
                completed_at,
                json.dumps(execution_details) if execution_details else None,
                run_id
            ))
            conn.commit()
            return {"status": "ok", "run_id": run_id}
        except sqlite3.Error as e:
            raise HTTPException(500, f"Database error: {str(e)}")
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error updating manual run: {e}", exc_info=True)
        raise HTTPException(500, f"Error updating manual run: {str(e)}")

@app.post("/run/execute")
def execute_run(req: dict, request: Request):
    """Execute a configuration run and track it"""
    try:
        # Extract configuration data from request
        config_data = req.get('config_data', {})
        if not config_data:
            raise HTTPException(400, "config_data is required")
        
        # Execute the configuration (event_id=None means manual run)
        result = run_configuration(config_data, "Manual Run", event_id=None)
        return result
    except Exception as e:
        logger.error(f"Error executing run: {e}", exc_info=True)
        raise HTTPException(500, f"Error executing run: {str(e)}")


@app.post("/event/execute/{event_id}")
def execute_event(event_id: int, background_tasks: BackgroundTasks):
    """Execute an event's configuration automatically"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
        is_manual_run = (event_id is None)
        if event_id is not None:
            conn = db_connect_with_retry()
            if not conn:
                logger.error(f"Failed to connect to database for execution record creation")
            else:
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
        elif is_manual_run:
            # Create manual run record
            configuration_name = config_data.get('configName', 'Manual Run')
            conn = db_connect_with_retry()
            if not conn:
                logger.error(f"Failed to connect to database for manual run record creation")
            else:
                c = conn.cursor()
                try:
                    c.execute('''
                        INSERT INTO manual_runs (configuration_name, status, started_at)
                        VALUES (?, ?, ?)
                    ''', (configuration_name, 'running', started_at.isoformat()))
                    execution_record_id = c.lastrowid
                    conn.commit()
                except sqlite3.Error as e:
                    logger.error(f"Failed to create manual run record: {e}")
                finally:
                    conn.close()
        # Extract configuration data
        hosts = config_data.get('confirmedHosts', [])
        if not hosts:
            logger.warning(f"No hosts configured for event {event_name}")
            completed_at = datetime.now(timezone.utc)
            if execution_record_id is not None:
                conn = db_connect_with_retry()
                if conn:
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
        
        # Initialize nhi_cred_id early so it's available for token storage
        nhi_cred_id = None
        
        # If client_secret missing, try retrieving from NHI sources
        # For scheduled events: from event_nhi_passwords (using FS_SERVER_SECRET)
        # For manual runs: from configuration nhiCredentialId (using FS_SERVER_SECRET)
        if not client_secret or not client_secret.strip():
            try:
                conn = db_connect_with_retry()
                if conn:
                    c = conn.cursor()
                    if event_id is not None:
                        # Get NHI credential id for event (using FS_SERVER_SECRET)
                        logger.info(f"Event '{event_name}': Retrieving NHI credential for event_id={event_id}")
                        c.execute('SELECT nhi_credential_id FROM event_nhi_passwords WHERE event_id = ?', (event_id,))
                        row = c.fetchone()
                        if row:
                            nhi_cred_id = row[0]
                            logger.info(f"Event '{event_name}': Found NHI credential_id={nhi_cred_id}")
                        else:
                            # Fallback: try to get NHI credential ID from the configuration
                            logger.warning(f"Event '{event_name}': No NHI credential stored for event_id={event_id}, trying to extract from configuration")
                            try:
                                # Get the configuration ID for this event
                                c.execute('SELECT configuration_id FROM event_schedules WHERE id = ?', (event_id,))
                                config_row = c.fetchone()
                                if config_row:
                                    config_id = config_row[0]
                                    # Get configuration data
                                    c.execute('SELECT config_data FROM configurations WHERE id = ?', (config_id,))
                                    cfg_row = c.fetchone()
                                    if cfg_row:
                                        cfg = json.loads(cfg_row[0])
                                        nhi_cred_id_from_config = cfg.get('nhiCredentialId')
                                        if nhi_cred_id_from_config:
                                            nhi_cred_id = int(nhi_cred_id_from_config)
                                            logger.info(f"Event '{event_name}': Extracted NHI credential_id={nhi_cred_id} from configuration")
                                            # Store it for future use
                                            try:
                                                c.execute('''
                                                    INSERT INTO event_nhi_passwords (event_id, nhi_credential_id, updated_at)
                                                    VALUES (?, ?, CURRENT_TIMESTAMP)
                                                    ON CONFLICT(event_id) DO UPDATE SET
                                                        nhi_credential_id=excluded.nhi_credential_id,
                                                        updated_at=CURRENT_TIMESTAMP
                                                ''', (event_id, nhi_cred_id))
                                                conn.commit()
                                                logger.info(f"Event '{event_name}': Stored NHI credential_id={nhi_cred_id} for future use")
                                            except Exception as e:
                                                logger.warning(f"Event '{event_name}': Failed to store NHI credential_id: {e}")
                                        else:
                                            logger.error(f"Event '{event_name}': Configuration {config_id} has no nhiCredentialId")
                                    else:
                                        logger.error(f"Event '{event_name}': Configuration {config_id} not found")
                                else:
                                    logger.error(f"Event '{event_name}': Event {event_id} has no configuration_id")
                            except Exception as e:
                                logger.error(f"Event '{event_name}': Error extracting NHI credential from configuration: {e}", exc_info=True)
                        
                        # If we have nhi_cred_id, fetch the credentials
                        if nhi_cred_id:
                            # Fetch encrypted client secret and client_id
                            c.execute('SELECT client_id, client_secret_encrypted FROM nhi_credentials WHERE id = ?', (nhi_cred_id,))
                            cred = c.fetchone()
                            if cred:
                                client_id_db, client_secret_encrypted = cred
                                if not client_id:
                                    client_id = client_id_db or client_id
                                if client_secret_encrypted:
                                    # Decrypt using FS_SERVER_SECRET
                                    try:
                                        client_secret = decrypt_with_server_secret(client_secret_encrypted)
                                        logger.info(f"Event '{event_name}': Successfully decrypted client_secret (length={len(client_secret)})")
                                    except Exception as e:
                                        logger.error(f"Event '{event_name}': Failed to decrypt client_secret: {e}", exc_info=True)
                                else:
                                    logger.warning(f"Event '{event_name}': NHI credential {nhi_cred_id} has no encrypted client_secret")
                            else:
                                logger.error(f"Event '{event_name}': NHI credential {nhi_cred_id} not found in database")
                    else:
                        # Manual run: get NHI credential from configuration (using FS_SERVER_SECRET)
                        nhi_cred_id_payload = config_data.get('nhiCredentialId')
                        if nhi_cred_id_payload:
                            c.execute('SELECT client_id, client_secret_encrypted FROM nhi_credentials WHERE id = ?', (int(nhi_cred_id_payload),))
                            cred = c.fetchone()
                            if cred:
                                client_id_db, client_secret_encrypted = cred
                                if not client_id:
                                    client_id = client_id_db or client_id
                                if client_secret_encrypted:
                                    # Decrypt using FS_SERVER_SECRET
                                    try:
                                        client_secret = decrypt_with_server_secret(client_secret_encrypted)
                                        logger.info(f"Event '{event_name}': Successfully decrypted client_secret for manual run (length={len(client_secret)})")
                                    except Exception as e:
                                        logger.error(f"Event '{event_name}': Failed to decrypt client_secret for manual run: {e}", exc_info=True)
                    conn.close()
            except Exception as e:
                logger.error(f"Event '{event_name}': Failed to retrieve/decrypt client secret: {e}", exc_info=True)

        # Step 1: Get tokens for all hosts (reuse stored if valid, otherwise fetch new)
        host_tokens = {}
        
        # If nhi_cred_id wasn't set above (for scheduled events), try to get it now
        if nhi_cred_id is None and event_id is not None:
            try:
                conn = db_connect_with_retry()
                if conn:
                    c = conn.cursor()
                    c.execute('SELECT nhi_credential_id FROM event_nhi_passwords WHERE event_id = ?', (event_id,))
                    nhi_row = c.fetchone()
                    if nhi_row:
                        nhi_cred_id = nhi_row[0]
                    conn.close()
            except Exception as e:
                logger.warning(f"Event '{event_name}': Could not retrieve NHI credential info: {e}")
        
        for host_info in hosts:
            host = host_info.get('host', '')
            token_fetched = False
            
            # First, try to reuse stored token from NHI credential if available
            if nhi_cred_id:
                try:
                    conn = db_connect_with_retry()
                    if conn:
                        c = conn.cursor()
                        c.execute('SELECT token_encrypted, token_expires_at FROM nhi_tokens WHERE nhi_credential_id = ? AND fabric_host = ?', (nhi_cred_id, host))
                        token_row = c.fetchone()
                        if token_row:
                            token_encrypted, token_expires_at_str = token_row
                            if token_expires_at_str:
                                expires_at = datetime.fromisoformat(token_expires_at_str)
                                now = datetime.now()
                                if expires_at > now:
                                    # Token is still valid, reuse it (decrypt using FS_SERVER_SECRET)
                                    try:
                                        decrypted_token = decrypt_with_server_secret(token_encrypted)
                                        host_tokens[host] = decrypted_token
                                        delta = expires_at - now
                                        hours = int(delta.total_seconds() // 3600)
                                        minutes = int((delta.total_seconds() % 3600) // 60)
                                        token_fetched = True
                                        logger.info(f"Event '{event_name}': Reusing stored token for {host} (expires in {hours}h {minutes}m)")
                                    except Exception as e:
                                        logger.warning(f"Event '{event_name}': Failed to decrypt stored token for {host}: {e}, will fetch new token")
                        conn.close()
                except Exception as e:
                    logger.warning(f"Event '{event_name}': Error checking stored token for {host}: {e}, will fetch new token")
            
            # If no valid stored token, fetch a new one
            if not token_fetched:
                try:
                    # Verify we have credentials before attempting token fetch
                    if not client_id or not client_secret:
                        msg = f"Missing credentials for host {host}: client_id={bool(client_id)}, client_secret={bool(client_secret)}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                        completed_at = datetime.now(timezone.utc)
                        if execution_record_id is not None:
                            conn = db_connect_with_retry()
                            if conn:
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
                    
                    logger.info(f"Event '{event_name}': Fetching new token for host {host} with client_id={client_id[:10] if client_id else 'None'}...")
                    logger.info(f"Event '{event_name}': client_id length={len(client_id) if client_id else 0}, client_secret length={len(client_secret) if client_secret else 0}")
                    token_data = get_access_token(client_id, client_secret, host)
                    if token_data and isinstance(token_data, dict) and token_data.get("access_token"):
                        logger.info(f"Event '{event_name}': Successfully acquired token for host {host}")
                        host_tokens[host] = token_data.get("access_token")
                        
                        # Store the new token in nhi_tokens if we have NHI credential (encrypt with FS_SERVER_SECRET)
                        if nhi_cred_id:
                            try:
                                expires_in = token_data.get("expires_in")
                                if expires_in:
                                    expires_at = datetime.now() + timedelta(seconds=expires_in)
                                    token_expires_at = expires_at.isoformat()
                                    token_encrypted = encrypt_with_server_secret(token_data.get("access_token"))
                                    
                                    conn = db_connect_with_retry()
                                    if conn:
                                        c = conn.cursor()
                                        c.execute('''
                                            INSERT OR REPLACE INTO nhi_tokens 
                                            (nhi_credential_id, fabric_host, token_encrypted, token_expires_at, updated_at)
                                            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                                        ''', (nhi_cred_id, host, token_encrypted, token_expires_at))
                                        conn.commit()
                                        conn.close()
                                        logger.info(f"Event '{event_name}': Stored new token for {host} (expires at {token_expires_at})")
                            except Exception as e:
                                logger.warning(f"Event '{event_name}': Failed to store token for {host}: {e}")
                    else:
                        # Log what we got back for debugging
                        logger.error(f"Event '{event_name}': get_access_token returned: {token_data}")
                        if token_data is None:
                            logger.error(f"Event '{event_name}': get_access_token returned None - check logs above for OAuth2 error details")
                        elif isinstance(token_data, dict):
                            logger.error(f"Event '{event_name}': Token data missing access_token: {list(token_data.keys())}")
                        
                        msg = f"Failed to acquire token for host {host}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                        completed_at = datetime.now(timezone.utc)
                        if execution_record_id is not None:
                            conn = db_connect_with_retry()
                            if conn:
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
                        conn = db_connect_with_retry()
                        if conn:
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
        
        # Initialize caches for repository IDs and template IDs to avoid repeated API calls
        repo_id_cache = {}  # Format: {host: {repo_name: repo_id}}
        template_id_cache = {}  # Format: {host: {(template_name, repo_name, version): template_id}}
        
        # Helper function to get cached repository ID
        def get_cached_repo_id(host, repo_name):
            if host not in repo_id_cache:
                repo_id_cache[host] = {}
            if repo_name not in repo_id_cache[host]:
                repo_id = get_repositoryId(host, host_tokens[host], repo_name)
                if repo_id:
                    repo_id_cache[host][repo_name] = repo_id
                else:
                    return None
            return repo_id_cache[host].get(repo_name)
        
        # Helper function to get cached template ID
        def get_cached_template_id(host, template_name, repo_name, version):
            cache_key = (template_name, repo_name, version)
            if host not in template_id_cache:
                template_id_cache[host] = {}
            if cache_key not in template_id_cache[host]:
                # First ensure repo_id is cached
                repo_id = get_cached_repo_id(host, repo_name)
                if not repo_id:
                    return None
                # Get template ID using cached repo_id
                items = list_templates_for_repo(host, host_tokens[host], repo_id)
                t_norm = (template_name or "").strip().lower()
                v_norm = (version or "").strip()
                for item in items:
                    name_norm = (item.get('name') or "").strip().lower()
                    ver_val = (item.get('version') or "").strip()
                    if name_norm == t_norm and ver_val == v_norm:
                        template_id = item.get('id')
                        template_id_cache[host][cache_key] = template_id
                        logger.info(f"Event '{event_name}': Cached template '{template_name}' (version={version}) -> id {template_id} on host {host}")
                        return template_id
                return None
            return template_id_cache[host].get(cache_key)
        
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
        
        # Track hostname and password changes for execution report
        hostname_changes = []
        password_changes = []
        
        # Change hostname if provided
        if new_hostname:
            for i, host in enumerate(host_tokens.keys()):
                try:
                    hostname = f"{new_hostname}{i + 1}"
                    change_hostname(host, host_tokens[host], hostname)
                    hostname_changes.append({
                        "host": host,
                        "new_hostname": hostname,
                        "success": True
                    })
                except Exception as e:
                    msg = f"Error changing hostname on host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
                    hostname_changes.append({
                        "host": host,
                        "new_hostname": f"{new_hostname}{i + 1}",
                        "success": False,
                        "error": str(e)
                    })
        
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
                        password_changes.append({
                            "host": host,
                            "username": "guest",
                            "success": False,
                            "error": msg
                        })
                        continue
                    change_fabricstudio_password(host, host_tokens[host], user_id, new_password)
                    password_changes.append({
                        "host": host,
                        "username": "guest",
                        "success": True
                    })
                except Exception as e:
                    msg = f"Error changing password on host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
                    password_changes.append({
                        "host": host,
                        "username": "guest",
                        "success": False,
                        "error": str(e)
                    })
        
        # Step 3: Create all workspace templates
        fabric_creation_details = []  # Track fabric creation details
        failed_hosts = set()  # Track hosts that failed during creation
        if templates_list:
            logger.info(f"Event '{event_name}': Processing {len(templates_list)} template(s) for creation")
            for idx, template_info in enumerate(templates_list, 1):
                template_name = template_info.get('template_name', '')
                repo_name = template_info.get('repo_name', '')
                version = template_info.get('version', '')
                
                if not (template_name and repo_name and version):
                    logger.warning(f"Event '{event_name}': Skipping template {idx}/{len(templates_list)} - missing required fields (name={template_name}, repo={repo_name}, version={version})")
                    continue
                
                logger.info(f"Event '{event_name}': Processing template {idx}/{len(templates_list)}: '{template_name}' v{version} from repo '{repo_name}'")
                
                # Check for running tasks before creating (only if there are actually running tasks)
                for host in host_tokens.keys():
                    if host in failed_hosts:
                        continue
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
                        # Get template ID using cache
                        template_id = get_cached_template_id(host, template_name, repo_name, version)
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
                            # Template not found - mark host as failed and continue to next host
                            msg = f"Template '{template_name}' v{version} not found on host {host}"
                            logger.error(f"Event '{event_name}': {msg}")
                            errors.append(msg)
                            # Don't mark host as failed for template not found - it might be available on other hosts
                            # Just continue to next host
                            continue
                    except Exception as e:
                        # Mark host as failed on exception
                        failed_hosts.add(host)
                        msg = f"Error creating template '{template_name}' v{version} on host {host}: {e}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                
                # Wait for tasks to complete after each template (only check if there are running tasks)
                for host in host_tokens.keys():
                    if host in failed_hosts:
                        continue
                    try:
                        running_count = get_running_task_count(host, host_tokens[host])
                        if running_count > 0:
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
        # Convert empty string to None for proper checking
        if isinstance(ssh_profile_id, str) and not ssh_profile_id.strip():
            ssh_profile_id = None
        elif ssh_profile_id:
            try:
                ssh_profile_id = int(ssh_profile_id)
            except (ValueError, TypeError):
                ssh_profile_id = None
        ssh_wait_time = config_data.get('sshWaitTime', 0)  # Get wait time from config (default: 0)
        ssh_execution_details = None  # Track SSH execution details
        if ssh_profile_id:
            # Execute SSH profiles before Install Workspace
            try:
                conn = db_connect_with_retry()
                if not conn:
                    logger.error(f"Event '{event_name}': Failed to connect to database for SSH profile loading")
                else:
                    c = conn.cursor()
                    
                    try:
                        # Get SSH profile
                        logger.info(f"Event '{event_name}': Loading SSH profile with id {ssh_profile_id}")
                        c.execute('''
                            SELECT name, commands, ssh_key_id
                            FROM ssh_command_profiles
                            WHERE id = ?
                        ''', (ssh_profile_id,))
                        profile_row = c.fetchone()
                        
                        if profile_row:
                            profile_name = profile_row[0]
                            commands = profile_row[1]
                            ssh_key_id = profile_row[2]
                            logger.info(f"Event '{event_name}': SSH profile '{profile_name}' loaded, ssh_key_id={ssh_key_id}")
                            
                            # Initialize SSH execution tracking
                            ssh_execution_details = {
                                "profile_id": ssh_profile_id,
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
                                
                                if not key_row:
                                    error_msg = f"SSH key with id {ssh_key_id} not found"
                                    logger.error(f"Event '{event_name}': {error_msg}")
                                    errors.append(error_msg)
                                    ssh_execution_details["error"] = error_msg
                                    # Mark all hosts as failed and stop SSH execution for this profile
                                    for host in host_tokens.keys():
                                        if host not in failed_hosts:
                                            failed_hosts.add(host)
                                            host_result = {
                                                "host": host,
                                                "success": False,
                                                "commands_executed": 0,
                                                "commands_failed": 0,
                                                "error": error_msg
                                            }
                                            ssh_execution_details["hosts"].append(host_result)
                                    # Skip SSH execution - hosts are already marked as failed
                                else:
                                    encrypted_private_key = key_row[0]
                                    # Decrypt using FS_SERVER_SECRET (no password required)
                                    logger.info(f"Event '{event_name}': Decrypting SSH key and executing commands")
                                    try:
                                        private_key = decrypt_with_server_secret(encrypted_private_key)
                                        
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
                                                            if host_result["success"]:
                                                                logger.info(f"Event '{event_name}': SSH commands executed successfully on {host}")
                                                            else:
                                                                logger.warning(f"Event '{event_name}': SSH commands failed on {host}: {host_result['commands_failed']} command(s) failed")
                                                                # Mark host as failed - stop processing for this host
                                                                failed_hosts.add(host)
                                                    except Exception as e:
                                                        msg = f"Error executing SSH commands on {host}: {e}"
                                                        host_result["error"] = str(e)
                                                        logger.error(f"Event '{event_name}': {msg}")
                                                        errors.append(msg)
                                                        # Mark host as failed - stop processing for this host
                                                        failed_hosts.add(host)
                                                    finally:
                                                        ssh_client.close()
                                            except Exception as e:
                                                msg = f"Error connecting via SSH to {host}: {e}"
                                                host_result["error"] = str(e)
                                                logger.error(f"Event '{event_name}': {msg}")
                                                errors.append(msg)
                                                # Mark host as failed - stop processing for this host
                                                failed_hosts.add(host)
                                            
                                            ssh_execution_details["hosts"].append(host_result)
                                    except Exception as e:
                                        msg = f"Failed to decrypt SSH key: {e}"
                                        logger.error(f"Event '{event_name}': {msg}")
                                        errors.append(msg)
                                        ssh_execution_details["error"] = msg
                                        # Mark all hosts as failed and stop SSH execution for this profile
                                        for host in host_tokens.keys():
                                            if host not in failed_hosts:
                                                failed_hosts.add(host)
                                                host_result = {
                                                    "host": host,
                                                    "success": False,
                                                    "commands_executed": 0,
                                                    "commands_failed": 0,
                                                    "error": msg
                                                }
                                                ssh_execution_details["hosts"].append(host_result)
                            else:
                                msg = "SSH key not found in database"
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
                        if conn:
                            conn.close()
            except Exception as e:
                logger.error(f"Event '{event_name}': Error executing SSH profiles: {e}")
                errors.append(f"Error executing SSH profiles: {e}")
                # If SSH execution fails completely, stop the run
                if ssh_profile_id:
                    logger.error(f"Event '{event_name}': SSH execution failed, stopping run")
                    raise RuntimeError(f"SSH execution failed: {e}")
        
        # Step 5: Install selected workspace
        # Check if Run Workspace is enabled
        run_workspace_enabled = config_data.get('runWorkspaceEnabled', True)  # Default to True for backward compatibility
        
        if not run_workspace_enabled:
            logger.info(f"Event '{event_name}': Run Workspace is disabled - skipping workspace installation")
            installation_details = []
        else:
            # Only proceed if SSH execution succeeded (or was not required)
            # Check if all hosts failed during SSH execution
            if ssh_profile_id and ssh_execution_details:
                ssh_failed_hosts = {h["host"] for h in ssh_execution_details["hosts"] if not h.get("success", False)}
                if ssh_failed_hosts:
                    # If SSH failed on all hosts, stop the run
                    if ssh_failed_hosts == set(host_tokens.keys()):
                        logger.error(f"Event '{event_name}': SSH execution failed on all hosts, stopping run")
                        raise RuntimeError("SSH execution failed on all hosts")
                    # Otherwise, mark failed hosts and continue (some hosts succeeded)
                    failed_hosts.update(ssh_failed_hosts)
            
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
                        
                        # Install in parallel on all available hosts
                        installation_lock = threading.Lock()
                        
                        def install_on_host(host):
                            """Install fabric on a single host"""
                            try:
                                # Use cached template ID instead of fetching again
                                template_id = get_cached_template_id(host, template_name, repo_name, version)
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
                                    
                                    # Track installation details (thread-safe)
                                    with installation_lock:
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
                                        logger.info(f"Event '{event_name}': Installation successful on host {host}: {template_name} v{version}")
                                    else:
                                        # Mark host as failed - stop processing for this host
                                        with installation_lock:
                                            failed_hosts.add(host)
                                        
                                        # Build detailed error message per host
                                        if task_errors:
                                            error_details = "; ".join(task_errors)
                                            msg = f"Host {host}: Installation FAILED - {error_details}"
                                        else:
                                            msg = f"Host {host}: Installation FAILED - installation timed out or encountered an error"
                                        
                                        logger.error(f"Event '{event_name}': {msg}")
                                        with installation_lock:
                                            errors.append(msg)
                                else:
                                    # Mark host as failed - template not found
                                    with installation_lock:
                                        failed_hosts.add(host)
                                    
                                    msg = f"Host {host}: Installation FAILED - Template '{template_name}' v{version} not found"
                                    logger.error(f"Event '{event_name}': {msg}")
                                    with installation_lock:
                                        errors.append(msg)
                            except Exception as e:
                                # Mark host as failed on exception
                                with installation_lock:
                                    failed_hosts.add(host)
                                
                                msg = f"Host {host}: Installation FAILED - Error: {e}"
                                logger.error(f"Event '{event_name}': {msg}")
                                with installation_lock:
                                    errors.append(msg)
                        
                        # Start installation threads for all available hosts
                        install_threads = []
                        for host in available_hosts:
                            thread = threading.Thread(target=install_on_host, args=(host,))
                            thread.daemon = False
                            thread.start()
                            install_threads.append(thread)
                        
                        # Wait for all installation threads to complete
                        for thread in install_threads:
                            thread.join()
                        
                        # Generate per-host installation summary
                        successful_hosts = []
                        failed_hosts_for_install = []
                        for detail in installation_details:
                            if detail["success"]:
                                successful_hosts.append(detail["host"])
                            else:
                                failed_hosts_for_install.append(detail["host"])
                                # failed_hosts already updated in install_on_host
                        
                        # Log summary per host
                        if successful_hosts:
                            success_msg = f"Event '{event_name}': Installation completed successfully on {len(successful_hosts)} host(s): {', '.join(successful_hosts)}"
                            logger.info(success_msg)
                            # Don't add success messages to errors list - they're informational only
                            # Success details are already tracked in installation_details
                        
                        if failed_hosts_for_install:
                            logger.warning(f"Event '{event_name}': Installation failed on {len(failed_hosts_for_install)} host(s): {', '.join(failed_hosts_for_install)}")
                            # Per-host failure messages already added in install_on_host function
                else:
                    msg = f"Repository name not found for template '{template_name}' v{version}"
                    logger.warning(f"Event '{event_name}': {msg}")
                    errors.append(msg)
        
        completed_at = datetime.now(timezone.utc)
        
        # Update execution record in database
        if execution_record_id is not None:
            conn = db_connect_with_retry()
            if not conn:
                logger.error(f"Event '{event_name}': Failed to connect to database for execution record update")
            else:
                c = conn.cursor()
                try:
                    if errors:
                        status = 'error'
                        message = "Auto-run completed with errors"
                    else:
                        status = 'success'
                        message = "Auto-run execution completed successfully"
                    
                    execution_details_json = json.dumps({
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
                            } if (install_select and len(installation_details) > 0) else None
                        ),
                        "installations": installation_details,
                        "installations_count": len(installation_details),
                        "install_select": install_select,
                        "install_executed": len(installation_details) > 0,
                        "hostname_changes": hostname_changes if 'hostname_changes' in locals() else [],
                        "hostname_changes_count": len(hostname_changes) if 'hostname_changes' in locals() else 0,
                        "password_changes": password_changes if 'password_changes' in locals() else [],
                        "password_changes_count": len(password_changes) if 'password_changes' in locals() else 0,
                        "ssh_profile": ssh_execution_details if ssh_execution_details else None,
                        "duration_seconds": (completed_at - started_at).total_seconds(),
                        "started_at": started_at.isoformat(),
                        "completed_at": completed_at.isoformat()
                    })
                    
                    if is_manual_run:
                        # Update manual_runs table
                        c.execute('''
                            UPDATE manual_runs
                            SET status = ?, message = ?, errors = ?, completed_at = ?, execution_details = ?
                            WHERE id = ?
                        ''', (
                            status,
                            message,
                            json.dumps(errors) if errors else None,
                            completed_at.isoformat(),
                            execution_details_json,
                            execution_record_id
                        ))
                    else:
                        # Update event_executions table
                        c.execute('''
                            UPDATE event_executions
                            SET status = ?, message = ?, errors = ?, completed_at = ?, execution_details = ?
                            WHERE id = ?
                        ''', (
                            status,
                            message,
                            json.dumps(errors) if errors else None,
                            completed_at.isoformat(),
                            execution_details_json,
                            execution_record_id
                        ))
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
                    
                    conn.commit()
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
            conn = db_connect_with_retry()
            if not conn:
                logger.error(f"Event '{event_name}': Failed to connect to database for error record update")
            else:
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
                            "install_executed": len(installation_details) > 0 if 'installation_details' in locals() else False,
                            "installations_count": len(installation_details) if 'installation_details' in locals() else 0,
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

@app.post("/ssh-keys/save")
def save_ssh_key(req: SaveSshKeyReq, request: Request):
    """Save or update an SSH key - private_key encrypted with FS_SERVER_SECRET"""
    import re
    
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Name is required")
    
    # Validate name: alphanumeric, dash, underscore only
    name_stripped = req.name.strip()
    if not re.match(r'^[a-zA-Z0-9_-]+$', name_stripped):
        raise HTTPException(400, "Name must contain only alphanumeric characters, dashes, and underscores")
    
    if not req.public_key or not req.public_key.strip():
        raise HTTPException(400, "Public key is required")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        encrypted_private_key = None
        provided_private_key = (req.private_key or '').strip()
        
        if req.id is None:
            # Create requires a private key
            if not provided_private_key:
                raise HTTPException(400, "Private key is required for creating a new SSH key")
            # Encrypt with FS_SERVER_SECRET
            encrypted_private_key = encrypt_with_server_secret(provided_private_key)
        else:
            # Update - use provided private key if given, otherwise keep existing
            if provided_private_key:
                # Encrypt with FS_SERVER_SECRET
                encrypted_private_key = encrypt_with_server_secret(provided_private_key)
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
                details=f"ssh_key_id={ssh_key_id} name={name_stripped}",
                request=request
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

@app.post("/ssh-keys/get/{ssh_key_id}")
async def get_ssh_key(ssh_key_id: int, request: Request):
    """Retrieve an SSH key by ID without returning the private key - no password required"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()

@app.get("/ssh-keys/list")
def list_ssh_keys():
    """List all SSH keys (without decrypting private keys)"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
def save_ssh_command_profile(req: SaveSshCommandProfileReq, request: Request):
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
    
    # Validate command length limits
    commands_list = [cmd.strip() for cmd in req.commands.strip().split('\n') if cmd.strip()]
    if len(commands_list) > MAX_SSH_COMMANDS:
        raise HTTPException(400, f"Maximum {MAX_SSH_COMMANDS} commands allowed")
    
    total_length = sum(len(cmd) for cmd in commands_list)
    if total_length > MAX_TOTAL_COMMANDS_SIZE:
        raise HTTPException(400, f"Total commands size exceeds {MAX_TOTAL_COMMANDS_SIZE} characters")
    
    for cmd in commands_list:
        if len(cmd) > MAX_SSH_COMMAND_LENGTH:
            raise HTTPException(400, f"Command exceeds maximum length of {MAX_SSH_COMMAND_LENGTH} characters: {cmd[:50]}...")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
                details=f"profile_id={profile_id} name={name_stripped} ssh_key_id={req.ssh_key_id or ''}",
                request=request
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    wait_time_seconds: int = 0  # Wait time between commands (default: 0)

@app.post("/ssh-profiles/validate-password")
async def validate_ssh_password(req: dict):
    """Validate that password matches both NHI credential (if provided) and SSH key"""
    try:
        nhi_credential_id = req.get('nhi_credential_id')
        ssh_profile_id = req.get('ssh_profile_id')
        encryption_password = req.get('encryption_password', '').strip()
        
        if not encryption_password:
            return {"valid": False, "error": "Password is required"}
        
        conn = db_connect_with_retry()
        if not conn:
            return {"valid": False, "error": "Database connection failed"}
        c = conn.cursor()
        
        try:
            # Validate SSH key password
            if ssh_profile_id:
                c.execute('''
                    SELECT ssh_key_id
                    FROM ssh_command_profiles
                    WHERE id = ?
                ''', (ssh_profile_id,))
                profile_row = c.fetchone()
                
                if profile_row and profile_row[0]:
                    ssh_key_id = profile_row[0]
                    c.execute('''
                        SELECT private_key_encrypted
                        FROM ssh_keys
                        WHERE id = ?
                    ''', (ssh_key_id,))
                    key_row = c.fetchone()
                    
                    if key_row:
                        encrypted_private_key = key_row[0]
                        try:
                            decrypt_client_secret(encrypted_private_key, encryption_password)
                        except ValueError:
                            return {"valid": False, "error": "Password does not match SSH key password"}
            
            # Validate NHI credential password (if provided)
            if nhi_credential_id:
                c.execute('''
                    SELECT client_secret_encrypted
                    FROM nhi_credentials
                    WHERE id = ?
                ''', (nhi_credential_id,))
                nhi_row = c.fetchone()
                
                if nhi_row:
                    encrypted_client_secret = nhi_row[0]
                    try:
                        decrypt_client_secret(encrypted_client_secret, encryption_password)
                    except ValueError:
                        return {"valid": False, "error": "Password does not match NHI credential password"}
                else:
                    return {"valid": False, "error": "NHI credential not found"}
            
            return {"valid": True}
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error validating password: {e}", exc_info=True)
        return {"valid": False, "error": str(e)}

@app.post("/ssh-profiles/execute")
async def execute_ssh_profile(req: ExecuteSshProfileReq):
    """Execute SSH commands from a profile on a fabric host"""
    try:
        # Get SSH profile
        conn = db_connect_with_retry()
        if not conn:
            raise HTTPException(500, "Database connection failed")
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
            
            # Decrypt private key using FS_SERVER_SECRET
            try:
                private_key = decrypt_with_server_secret(encrypted_private_key)
            except Exception as e:
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
            
            # Overall operation timeout: 10 minutes (600 seconds)
            # This covers connection + all command executions + wait times
            SSH_OPERATION_TIMEOUT = 600
            
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
                
                # Connect to host with timeout
                ssh_client.connect(
                    hostname=req.fabric_host,
                    port=req.ssh_port,
                    username='admin',  # Default FabricStudio username
                    pkey=private_key_obj,
                    timeout=30,  # Connection timeout: 30 seconds
                    look_for_keys=False,
                    allow_agent=False
                )
                
                # Execute each command with timeout
                for idx, cmd in enumerate(command_list):
                    stdin, stdout, stderr = ssh_client.exec_command(cmd, timeout=300)  # Command timeout: 5 minutes
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
            except socket.timeout:
                raise HTTPException(504, f"SSH operation timed out after {SSH_OPERATION_TIMEOUT} seconds")
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
                    details=f"host={req.fabric_host} profile_id={req.ssh_profile_id} key_name={key_name} success={success}",
                    request=request
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
    """Save or update an NHI credential - client_secret encrypted with FS_SERVER_SECRET"""
    # Validate inputs
    name_stripped = validate_name(req.name, "Name")
    req.client_id = validate_client_id(req.client_id)
    
    # Validate fabric_hosts if provided
    hosts_to_process = []
    if req.fabric_hosts and req.fabric_hosts.strip():
        hosts_to_process = validate_fabric_hosts_list(req.fabric_hosts)
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        # Determine operation mode (create vs update) and handle client secret accordingly
        encrypted_secret = None
        provided_client_secret = (req.client_secret or '').strip()
        if req.id is None:
            # Create requires a client secret
            if not provided_client_secret:
                raise HTTPException(400, "Client Secret is required for creating a new credential")
            provided_client_secret = validate_client_secret(provided_client_secret)
            # Encrypt with FS_SERVER_SECRET
            encrypted_secret = encrypt_with_server_secret(provided_client_secret)
        elif provided_client_secret:
            # Update with new secret - validate it
            provided_client_secret = validate_client_secret(provided_client_secret)
            # Encrypt with FS_SERVER_SECRET
            encrypted_secret = encrypt_with_server_secret(provided_client_secret)
        
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
                # Need to decrypt existing stored secret using FS_SERVER_SECRET
                c.execute('SELECT client_secret_encrypted FROM nhi_credentials WHERE id = ?', (nhi_id,))
                row_secret = c.fetchone()
                if not row_secret:
                    raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
                encrypted_secret_db = row_secret[0]
                try:
                    client_secret_to_use = decrypt_with_server_secret(encrypted_secret_db)
                    logger.info(f"Decrypted client secret length: {len(client_secret_to_use) if client_secret_to_use else 0}")
                    logger.info(f"Decrypted client secret (first 5 chars): {client_secret_to_use[:5] if client_secret_to_use else 'None'}...")
                    logger.info(f"Decrypted client secret (last 5 chars): ...{client_secret_to_use[-5:] if client_secret_to_use and len(client_secret_to_use) >= 5 else 'N/A'}")
                except Exception as e:
                    logger.error(f"Failed to decrypt client secret: {str(e)}", exc_info=True)
                    raise HTTPException(400, f"Failed to decrypt client secret: {str(e)}")
            for fabric_host in hosts_to_process:
                try:
                    # Ensure client_id and client_secret are properly trimmed
                    client_id_clean = req.client_id.strip()
                    client_secret_clean = client_secret_to_use.strip() if client_secret_to_use else None
                    
                    if not client_secret_clean:
                        error_msg = f"Host {fabric_host}: Client secret is missing or empty"
                        token_errors.append(error_msg)
                        logger.warning(error_msg)
                        continue
                    
                    logger.info(f"Attempting token retrieval for host {fabric_host} with client_id: {client_id_clean[:10]}...")
                    logger.debug(f"Client ID: {client_id_clean[:20]}... (length: {len(client_id_clean)})")
                    logger.debug(f"Client Secret: {client_secret_clean[:3]}... (length: {len(client_secret_clean)})")
                    
                    # Verify decryption worked correctly by checking if secret looks reasonable
                    if len(client_secret_clean) < 10:
                        logger.warning(f"Client secret seems unusually short ({len(client_secret_clean)} chars) - decryption may have failed")
                    
                    token_data = get_access_token(client_id_clean, client_secret_clean, fabric_host)
                    if token_data and isinstance(token_data, dict) and token_data.get("access_token"):
                        # Encrypt the token using FS_SERVER_SECRET
                        token_encrypted = encrypt_with_server_secret(token_data.get("access_token"))
                        
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
        log_audit(log_action, details=f"NHI credential '{name_stripped}' (ID: {nhi_id})", request=request)
        
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
    """List all NHI credentials (without decrypting secrets). Automatically refreshes expired tokens."""
    # First, refresh any expired tokens proactively
    try:
        refresh_nhi_tokens()
    except Exception as e:
        logger.warning(f"Error refreshing NHI tokens in list endpoint: {e}")
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
@app.get("/nhi/get/{nhi_id}")
async def get_nhi(nhi_id: int, request: Request):
    """Retrieve an NHI credential by ID - no password required, uses FS_SERVER_SECRET"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
    c = conn.cursor()
    
    try:
        # Fetch credential and tokens in parallel queries (SQLite allows this)
        c.execute('''
            SELECT name, client_id, client_secret_encrypted, created_at, updated_at
            FROM nhi_credentials
            WHERE id = ?
        ''', (nhi_id,))
        row = c.fetchone()
        
        if not row:
            raise HTTPException(404, f"NHI credential with id {nhi_id} not found")
        
        # Get all tokens for this credential (decrypted)
        c.execute('''
            SELECT fabric_host, token_encrypted, token_expires_at
            FROM nhi_tokens
            WHERE nhi_credential_id = ?
            ORDER BY fabric_host ASC
        ''', (nhi_id,))
        token_rows = c.fetchall()
        
        # Decrypt client_secret using FS_SERVER_SECRET
        try:
            decrypted_client_secret = decrypt_with_server_secret(row[2])
        except Exception as e:
            raise HTTPException(400, f"Failed to decrypt client secret: {str(e)}")
        
        client_id = row[1]
        
        # Process tokens efficiently - combine validation and decryption in one pass
        from datetime import datetime
        now = datetime.now()
        hosts_with_tokens = []
        tokens_by_host_for_session = {}
        
        for token_row in token_rows:
            fabric_host = token_row[0]
            token_encrypted = token_row[1]
            token_expires_at = token_row[2]
            
            # Check if token is valid
            try:
                expires_at = datetime.fromisoformat(token_expires_at)
                if expires_at > now:
                    # Token is valid - add to host list and decrypt for session
                    hosts_with_tokens.append(fabric_host)
                    try:
                        decrypted_token = decrypt_with_server_secret(token_encrypted)
                        tokens_by_host_for_session[fabric_host] = {
                            "token": decrypted_token,
                            "expires_at": token_expires_at
                        }
                    except Exception:
                        # Decryption failed, skip this token
                        pass
            except (ValueError, TypeError):
                # Date parsing failed, skip this token
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
        
        # Note: Session is now user-based, so we don't create a new session here
        # The tokens are available for use in the current user session
        return JSONResponse(result)
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


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
    
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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


# Audit Logs endpoints
@app.get("/audit-logs/list")
def list_audit_logs(action: Optional[str] = None, user: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None, limit: int = 1000):
    """List audit logs with optional filtering"""
    conn = None
    try:
        conn = db_connect_with_retry(timeout=10.0, max_retries=5, retry_delay=0.05)
        if not conn:
            raise HTTPException(500, "Failed to connect to database")
        
        c = conn.cursor()
        
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
        
        # Add date range filters
        if date_from:
            try:
                # Convert ISO format (with or without Z) to datetime
                if date_from.endswith('Z'):
                    from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                else:
                    from_dt = datetime.fromisoformat(date_from)
                query += ' AND created_at >= ?'
                params.append(from_dt.isoformat())
            except ValueError:
                pass  # Ignore invalid date format
        
        if date_to:
            try:
                # Convert ISO format (with or without Z) to datetime
                if date_to.endswith('Z'):
                    to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                else:
                    to_dt = datetime.fromisoformat(date_to)
                # Add 1 day and subtract 1 second to include the entire end day
                to_dt = to_dt + timedelta(days=1) - timedelta(seconds=1)
                query += ' AND created_at <= ?'
                params.append(to_dt.isoformat())
            except ValueError:
                pass  # Ignore invalid date format
        
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
        if conn:
            conn.close()

@app.post("/audit-logs/create")
def create_audit_log(request: Request, action: str, user: Optional[str] = None, details: Optional[str] = None):
    """Create an audit log entry"""
    ip_address = get_client_ip(request)
    log_audit(action, user, details, ip_address)
    return {"status": "ok", "message": "Audit log created"}

@app.get("/audit-logs/export")
def export_audit_logs(action: Optional[str] = None, user: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None):
    """Export audit logs as CSV"""
    conn = None
    try:
        conn = db_connect_with_retry(timeout=10.0, max_retries=5, retry_delay=0.05)
        if not conn:
            raise HTTPException(500, "Failed to connect to database")
        
        c = conn.cursor()
        
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
        
        # Add date range filters
        if date_from:
            try:
                from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query += ' AND created_at >= ?'
                params.append(from_dt.isoformat())
            except ValueError:
                pass
        
        if date_to:
            try:
                to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                to_dt = to_dt + timedelta(days=1) - timedelta(seconds=1)
                query += ' AND created_at <= ?'
                params.append(to_dt.isoformat())
            except ValueError:
                pass
        
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
        if conn:
            conn.close()


# Server Logs endpoints (now shows INFO level application logs)
@app.get("/server-logs/list")
def list_server_logs(level: Optional[str] = None, logger_name: Optional[str] = None, message: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None, limit: int = 1000):
    conn = None
    try:
        conn = db_connect_with_retry(timeout=10.0, max_retries=5, retry_delay=0.05)
        if not conn:
            raise HTTPException(500, "Failed to connect to database")
        
        c = conn.cursor()
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
        
        # Add date range filters
        if date_from:
            try:
                from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query += ' AND created_at >= ?'
                params.append(from_dt.isoformat())
            except ValueError:
                pass
        
        if date_to:
            try:
                to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                to_dt = to_dt + timedelta(days=1) - timedelta(seconds=1)
                query += ' AND created_at <= ?'
                params.append(to_dt.isoformat())
            except ValueError:
                pass
        
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
        if conn:
            conn.close()

@app.get("/server-logs/export")
def export_server_logs(level: Optional[str] = None, logger_name: Optional[str] = None, message: Optional[str] = None, date_from: Optional[str] = None, date_to: Optional[str] = None):
    conn = None
    try:
        conn = db_connect_with_retry(timeout=10.0, max_retries=5, retry_delay=0.05)
        if not conn:
            raise HTTPException(500, "Failed to connect to database")
        
        c = conn.cursor()
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
        
        # Add date range filters
        if date_from:
            try:
                from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query += ' AND created_at >= ?'
                params.append(from_dt.isoformat())
            except ValueError:
                pass
        
        if date_to:
            try:
                to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                to_dt = to_dt + timedelta(days=1) - timedelta(seconds=1)
                query += ' AND created_at <= ?'
                params.append(to_dt.isoformat())
            except ValueError:
                pass
        
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
        if conn:
            conn.close()

@app.delete("/nhi/delete/{nhi_id}")
def delete_nhi(nhi_id: int):
    """Delete an NHI credential by ID"""
    conn = db_connect_with_retry()
    if not conn:
        raise HTTPException(500, "Database connection failed")
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
    """Create a new session for an NHI credential - No longer needed, tokens are stored in nhi_tokens table"""
    # Tokens are already stored in nhi_tokens table encrypted with FS_SERVER_SECRET
    # No need to create a separate session - return success immediately
    return JSONResponse({
        "message": "Session creation not needed - tokens are managed in nhi_tokens table"
    })

@app.get("/auth/session/status")
def get_session_status(request: Request):
    """Get current user session status - NHI tokens are stored in nhi_tokens table, not in sessions"""
    # Check user login session (for authentication)
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "No active user session")
    
    # User is authenticated - tokens are stored in nhi_tokens table, not in sessions
    return {
        "user_id": session.get('user_id'),
        "message": "User authenticated - tokens are managed in nhi_tokens table"
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

@app.put("/auth/session/nhi-credential")
def update_session_nhi_credential_endpoint(request: Request, nhi_credential_id: Optional[int] = None):
    """Update the selected NHI credential ID in the user's session"""
    session = get_session_from_request(request)
    if not session or not session.get('user_id'):
        raise HTTPException(401, "Authentication required")
    
    # If nhi_credential_id is None, clear it from session (allow clearing)
    if nhi_credential_id is not None:
        # Verify the NHI credential exists
        conn = db_connect_with_retry()
        if not conn:
            raise HTTPException(500, "Database connection failed")
        c = conn.cursor()
        try:
            c.execute('SELECT id FROM nhi_credentials WHERE id = ?', (nhi_credential_id,))
            if not c.fetchone():
                raise HTTPException(404, f"NHI credential with id {nhi_credential_id} not found")
        finally:
            conn.close()
    
    # Update session (can be None to clear)
    success = update_session_nhi_credential(session['session_id'], nhi_credential_id)
    if not success:
        raise HTTPException(500, "Failed to update session")
    
    if nhi_credential_id is None:
        return {"status": "ok", "message": "Session NHI credential cleared"}
    else:
        return {"status": "ok", "message": f"Session updated with NHI credential {nhi_credential_id}"}

def refresh_nhi_tokens():
    """Refresh NHI tokens from nhi_tokens table for credentials with stored event passwords"""
    try:
        conn = db_connect_with_retry()
        if not conn:
            logger.error("Failed to connect to database for NHI token refresh")
            return 0
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
            
            # Group tokens by credential ID
            tokens_by_credential = {}
            for nhi_cred_id, fabric_host, token_expires_at in expiring_tokens:
                if nhi_cred_id not in tokens_by_credential:
                    tokens_by_credential[nhi_cred_id] = []
                tokens_by_credential[nhi_cred_id].append((fabric_host, token_expires_at))
            
            # For each credential, refresh tokens (no password needed - using FS_SERVER_SECRET)
            for nhi_cred_id, tokens in tokens_by_credential.items():
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
                
                # Decrypt client secret using FS_SERVER_SECRET
                try:
                    client_secret = decrypt_with_server_secret(client_secret_encrypted)
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
                                token_encrypted = encrypt_with_server_secret(token_data.get("access_token"))
                                
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
        conn = db_connect_with_retry()
        if not conn:
            logger.error("Failed to connect to database for token refresh")
            return
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
                    logger.warning(f"Error processing session for token refresh: {e}")
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
            time.sleep(60)  # Wait before retrying on error

def cleanup_old_executions(days_to_keep: int = 90):
    """Clean up execution records older than specified days"""
    try:
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days_to_keep)).isoformat()
        conn = db_connect_with_retry()
        if not conn:
            logger.error("Failed to connect to database for execution cleanup")
            return
        
        c = conn.cursor()
        try:
            # Delete old event executions (only completed ones)
            c.execute('''
                DELETE FROM event_executions 
                WHERE completed_at IS NOT NULL AND completed_at < ?
            ''', (cutoff_date,))
            event_deleted = c.rowcount
            
            # Delete old manual runs (only completed ones)
            c.execute('''
                DELETE FROM manual_runs 
                WHERE completed_at IS NOT NULL AND completed_at < ?
            ''', (cutoff_date,))
            manual_deleted = c.rowcount
            
            conn.commit()
            
            if event_deleted > 0 or manual_deleted > 0:
                logger.info(f"Cleaned up {event_deleted} old event executions and {manual_deleted} old manual runs (older than {days_to_keep} days)")
        except sqlite3.Error as e:
            logger.error(f"Error cleaning up execution records: {e}")
            conn.rollback()
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error in execution cleanup: {e}", exc_info=True)

def cleanup_executions_periodically():
    """Background thread to periodically clean up old execution records"""
    while True:
        try:
            time.sleep(3600 * 24)  # Run once per day
            cleanup_old_executions(days_to_keep=90)
        except Exception as e:
            logger.error(f"Error in execution cleanup thread: {e}", exc_info=True)
            time.sleep(3600)  # Wait 1 hour before retrying on error
def refresh_repositories_periodically():
    """Background task to refresh repositories periodically for LEAD_FABRIC_HOST using CLIENT_ID and CLIENT_SECRET from .env"""
    # Run immediately on startup, then wait for interval
    first_run = True
    
    # Small delay on startup to ensure database is fully initialized
    time.sleep(2)
    
    while True:
        try:
            # Wait for interval before subsequent refreshes (but not before first run)
            if not first_run:
                time.sleep(Config.REPO_REFRESH_INTERVAL_HOURS * 60 * 60)
            first_run = False
            
            # Check if configuration is available
            fabric_host = Config.LEAD_FABRIC_HOST
            client_id = Config.LEAD_CLIENT_ID
            client_secret = Config.LEAD_CLIENT_SECRET
            
            if not fabric_host:
                logger.warning("LEAD_FABRIC_HOST not configured, skipping periodic repository refresh")
                # Wait before retrying
                time.sleep(Config.REPO_REFRESH_INTERVAL_HOURS * 60 * 60)
                continue
            
            if not client_id or not client_secret:
                logger.warning("CLIENT_ID or CLIENT_SECRET not configured, skipping periodic repository refresh")
                # Wait before retrying
                time.sleep(Config.REPO_REFRESH_INTERVAL_HOURS * 60 * 60)
                continue
            
            logger.info(f"Starting periodic repository refresh for {fabric_host}")
            
            try:
                # Get access token using credentials from .env, checking cache first
                token_data = get_access_token_with_cache(fabric_host, client_id, client_secret)
                
                if not token_data or not token_data.get("access_token"):
                    error_msg = "Failed to get access token"
                    logger.error(f"{error_msg} for {fabric_host}")
                    log_repository_refresh(fabric_host, 'failed', error_message=error_msg)
                    continue
                
                token = token_data.get("access_token")
                
                # Log refresh start
                log_repository_refresh(fabric_host, 'started')
                
                # Refresh repositories
                success = refresh_repositories(fabric_host, token)
                
                # Invalidate cache after refresh
                conn = db_connect_with_retry()
                if conn:
                    try:
                        c = conn.cursor()
                        c.execute('DELETE FROM cached_repositories WHERE fabric_host = ?', (fabric_host,))
                        # Also invalidate template cache since repositories were refreshed
                        c.execute('DELETE FROM cached_templates')
                        conn.commit()
                    except Exception as e:
                        logger.error(f"Error invalidating cache for {fabric_host}: {e}")
                    finally:
                        conn.close()
                
                # Log refresh completion
                if success:
                    repos = list_repositories(fabric_host, token)
                    repo_count = len(repos) if repos else 0
                    log_repository_refresh(fabric_host, 'completed', repositories_count=repo_count)
                    logger.info(f"Periodic repository refresh completed for {fabric_host}: {repo_count} repositories")
                    
                    # Refresh template cache after repository refresh
                    try:
                        templates = list_all_templates(fabric_host, token)
                        if templates:
                            cache_templates(templates)
                            logger.info(f"Template cache refreshed after repository refresh: {len(templates)} templates")
                    except Exception as e:
                        logger.warning(f"Failed to refresh template cache after repository refresh: {e}")
                else:
                    log_repository_refresh(fabric_host, 'failed', error_message="Refresh request failed")
                    logger.warning(f"Periodic repository refresh failed for {fabric_host}")
            
            except Exception as e:
                logger.error(f"Error refreshing repositories for {fabric_host}: {e}", exc_info=True)
                log_repository_refresh(fabric_host, 'failed', error_message=str(e))
        
        except Exception as e:
            logger.error(f"Error in repository refresh background task: {e}", exc_info=True)
            # Wait 1 hour before retrying on error
            time.sleep(60 * 60)

def refresh_template_cache_periodically():
    """Background task to refresh template cache periodically for LEAD_FABRIC_HOST using CLIENT_ID and CLIENT_SECRET from .env"""
    # Run immediately on startup, then wait for interval
    first_run = True
    
    # Small delay on startup to ensure database is fully initialized
    time.sleep(2)
    
    while True:
        try:
            # Wait for interval before subsequent refreshes (but not before first run)
            if not first_run:
                time.sleep(Config.TEMPLATE_CACHE_REFRESH_INTERVAL_HOURS * 60 * 60)
            first_run = False
            
            # Check if configuration is available
            fabric_host = Config.LEAD_FABRIC_HOST
            client_id = Config.LEAD_CLIENT_ID
            client_secret = Config.LEAD_CLIENT_SECRET
            
            if not fabric_host:
                logger.warning("LEAD_FABRIC_HOST not configured, skipping periodic template cache refresh")
                # Wait before retrying
                time.sleep(Config.TEMPLATE_CACHE_REFRESH_INTERVAL_HOURS * 60 * 60)
                continue
            
            if not client_id or not client_secret:
                logger.warning("CLIENT_ID or CLIENT_SECRET not configured, skipping periodic template cache refresh")
                # Wait before retrying
                time.sleep(Config.TEMPLATE_CACHE_REFRESH_INTERVAL_HOURS * 60 * 60)
                continue
            
            logger.info(f"Starting periodic template cache refresh for {fabric_host}")
            
            templates = []
            refresh_status = "failed"
            failure_reason = None

            try:
                # Get access token using credentials from .env, checking cache first
                logger.debug(f"Requesting access token for {fabric_host}")
                token_data = get_access_token_with_cache(fabric_host, client_id, client_secret)

                if not token_data or not token_data.get("access_token"):
                    failure_reason = "Failed to get access token"
                    logger.error(f"{failure_reason} for {fabric_host}")
                    logger.warning(f"Template cache refresh skipped for {fabric_host} - host may be unreachable or credentials invalid")
                    logger.warning(f"Check network connectivity, VPN connection, firewall rules, or verify LEAD_FABRIC_HOST is correct")
                    refresh_status = "failed"
                else:
                    token = token_data.get("access_token")
                    logger.debug(f"Access token obtained, fetching templates from {fabric_host}")

                    # Fetch all templates
                    templates = list_all_templates(fabric_host, token) or []

                    if templates:
                        # Cache the templates
                        cache_templates(templates)
                        logger.info(f"Periodic template cache refresh completed for {fabric_host}: {len(templates)} templates cached")
                        refresh_status = "completed"
                    else:
                        logger.warning(f"No templates found for {fabric_host}")
                        refresh_status = "completed"  # Still mark as completed even if no templates found

            except Exception as e:
                if failure_reason is None:
                    failure_reason = str(e)
                logger.error(f"Error refreshing template cache for {fabric_host}: {e}", exc_info=True)
                refresh_status = "failed"
            
            # Always log final status
            if refresh_status == "completed":
                logger.info(
                    f"Template cache refresh finished for {fabric_host}: {len(templates)} template(s) cached"
                )
            else:
                logger.warning(
                    f"Template cache refresh for {fabric_host} did not complete successfully: {failure_reason or 'unknown error'}"
                )
        
        except Exception as e:
            logger.error(f"Error in template cache refresh background task: {e}", exc_info=True)
            # Wait 1 hour before retrying on error
            time.sleep(60 * 60)

# Track events that have been executed to prevent duplicates
# Background scheduler to check for events that need to run
def check_and_run_events():
    """Check for events that should run now and execute them"""
    global _executed_events
    logger.info("Event scheduler started")
    
    while True:
        try:
            # Use UTC time for all date/time matching (backend stores everything in UTC)
            now = datetime.now(timezone.utc)
            current_date = now.date()
            current_time = now.time().replace(second=0, microsecond=0)  # Round to minute
            
            conn = db_connect_with_retry()
            if not conn:
                logger.error("Failed to connect to database in scheduler")
                time.sleep(60)
                continue
            
            c = conn.cursor()
            
            # Find events that should run now (auto_run enabled, date matches, time matches or no time specified)
            # Compare dates as strings (YYYY-MM-DD format) - stored in UTC
            current_date_str = current_date.strftime('%Y-%m-%d')
            current_time_str = current_time.strftime('%H:%M:%S')
            current_time_short = current_time.strftime('%H:%M')
            
            # Log scheduler check periodically (every 10 checks = ~5 minutes)
            if random.randint(1, 10) == 1:
                logger.debug(f"Scheduler checking: date={current_date_str}, time={current_time_str} (UTC)")
            
            # First, let's see what events exist in the database
            c.execute('''
                SELECT id, name, event_date, event_time, auto_run
                FROM event_schedules
                WHERE auto_run = 1
            ''')
            all_events = c.fetchall()
            if all_events:
                logger.debug(f"Found {len(all_events)} auto-run event(s) in database:")
                for evt_id, evt_name, evt_date, evt_time, evt_auto_run in all_events:
                    logger.debug(f"  - Event {evt_id}: {evt_name}, date={evt_date!r}, time={evt_time!r}, auto_run={evt_auto_run}")
            
            # Query for events - dates are stored as YYYY-MM-DD format
            # Times are stored as HH:MM format (e.g., "10:25" or "19:00"), not HH:MM:SS
            # We check every 30 seconds, so match events if current time (rounded to minute) matches event time
            # Event time might be stored as "HH:MM" (5 chars) or "HH:MM:SS" (8 chars)
            # We compare the first 5 characters (HH:MM) of both
            
            # Compare times - normalize both to HH:MM for comparison
            c.execute('''
                SELECT id, name, event_date, event_time
                FROM event_schedules
                WHERE auto_run = 1
                AND event_date = ?
                AND (
                    event_time IS NULL 
                    OR SUBSTR(event_time, 1, 5) = ?
                )
            ''', (current_date_str, current_time_short))
            
            events_to_run = c.fetchall()
            
            if events_to_run:
                logger.info(f"Found {len(events_to_run)} event(s) to run at {current_date_str} {current_time_str} (UTC)")
                for event_id, event_name, event_date, event_time in events_to_run:
                    logger.info(f"  - Event ID {event_id}: {event_name} (date={event_date}, time={event_time}, UTC)")
            else:
                # Log why no events matched (for debugging) - only log every 10th check to avoid spam
                if random.randint(1, 10) == 1:
                    logger.debug(f"No events matched: date={current_date_str}, time={current_time_short} (UTC)")
                    # Also show what events exist
                    if all_events:
                        logger.debug(f"  Available events: {[(evt_id, evt_name, evt_date, evt_time) for evt_id, evt_name, evt_date, evt_time, _ in all_events]}")
            
            # Clean up executed events from previous days (thread-safe)
            if events_to_run:
                with _executed_events_lock:
                    _executed_events = {e for e in _executed_events if str(e).startswith(current_date_str)}
            
            for event_id, event_name, event_date, event_time in events_to_run:
                # Create unique key for this event execution
                # Normalize event_time to HH:MM format to prevent duplicates (e.g., "18:43:00" -> "18:43")
                normalized_time = 'all'
                if event_time:
                    # Extract HH:MM from event_time (handles both "HH:MM" and "HH:MM:SS" formats)
                    time_parts = event_time.strip().split(':')
                    if len(time_parts) >= 2:
                        normalized_time = f"{time_parts[0]}:{time_parts[1]}"
                event_key = f"{event_date}_{normalized_time}_{event_id}"
                
                # Skip if already executed (thread-safe check)
                with _executed_events_lock:
                    if event_key in _executed_events:
                        logger.debug(f"Skipping event {event_id} - already executed (key: {event_key})")
                        continue
                    
                    # Mark as executed before starting (to prevent duplicate if scheduler runs again)
                    _executed_events.add(event_key)
                
                logger.info(f"Executing event {event_id}: {event_name} (key: {event_key})")
                
                try:
                    # Execute in background thread
                    thread = threading.Thread(target=execute_event_internal, args=(event_id, event_name))
                    thread.daemon = False  # Keep thread alive until execution completes
                    thread.start()
                except Exception as e:
                    logger.error(f"Error starting execution thread for event {event_id}: {e}", exc_info=True)
                    # Remove from executed set if we failed to start (thread-safe)
                    with _executed_events_lock:
                        _executed_events.discard(event_key)
            
            conn.close()
            
            # Check every 30 seconds for more accurate timing
            time.sleep(30)
            
        except Exception as e:
            logger.error(f"Error in scheduler: {e}", exc_info=True)
            time.sleep(60)


def execute_event_internal(event_id: int, event_name: str = None):
    """Internal function to execute an event"""
    try:
        conn = db_connect_with_retry()
        if not conn:
            logger.error(f"Failed to connect to database for event {event_id}")
            return
        
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
                completed_at = datetime.now(timezone.utc)
                conn = db_connect_with_retry()
                if conn:
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
                completed_at = datetime.now(timezone.utc)
                conn = db_connect_with_retry()
                if conn:
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
            completed_at = datetime.now(timezone.utc)
            conn = db_connect_with_retry()
            if conn:
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
        completed_at = datetime.now(timezone.utc)
        conn = db_connect_with_retry()
        if conn:
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
cleanup_thread = None
backup_thread = None
repo_refresh_thread = None
template_cache_thread = None

def _start_background_threads():
    """Start the background scheduler on application startup"""
    global scheduler_thread, token_refresh_thread, cleanup_thread, backup_thread, repo_refresh_thread, template_cache_thread
    
    # Start app log worker thread (for batched app log writes)
    _start_app_log_worker()
    
    if scheduler_thread is None or not scheduler_thread.is_alive():
        scheduler_thread = threading.Thread(target=check_and_run_events)
        scheduler_thread.daemon = True  # Allow main process to exit
        scheduler_thread.start()
        logger.info("Event scheduler thread started")
    else:
        logger.warning("Event scheduler thread already running")
    
    # Start token refresh background task
    if token_refresh_thread is None or not token_refresh_thread.is_alive():
        token_refresh_thread = threading.Thread(target=check_and_run_token_refresh)
        token_refresh_thread.daemon = True
        token_refresh_thread.start()
        logger.info("Token refresh thread started")
    else:
        logger.warning("Token refresh thread already running")
    
    # Start execution cleanup background task
    if cleanup_thread is None or not cleanup_thread.is_alive():
        cleanup_thread = threading.Thread(target=cleanup_executions_periodically)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        logger.info("Execution cleanup thread started")
    else:
        logger.warning("Execution cleanup thread already running")
    
    # Start database backup background task
    if backup_thread is None or not backup_thread.is_alive():
        backup_thread = threading.Thread(target=backup_database_periodically)
        backup_thread.daemon = True
        backup_thread.start()
        logger.info("Database backup thread started")
    else:
        logger.warning("Database backup thread already running")
    
    # Start audit log worker thread
    _start_audit_log_worker()
    
    # Start repository refresh background task
    global repo_refresh_thread
    if repo_refresh_thread is None or not repo_refresh_thread.is_alive():
        repo_refresh_thread = threading.Thread(target=refresh_repositories_periodically)
        repo_refresh_thread.daemon = True
        repo_refresh_thread.start()
        logger.info("Repository refresh thread started")
    else:
        logger.warning("Repository refresh thread already running")
    
    # Start template cache refresh background task
    global template_cache_thread
    if template_cache_thread is None or not template_cache_thread.is_alive():
        template_cache_thread = threading.Thread(target=refresh_template_cache_periodically)
        template_cache_thread.daemon = True
        template_cache_thread.start()
        logger.info("Template cache refresh thread started")
    else:
        logger.warning("Template cache refresh thread already running")
    
    # Create initial backup on startup
    try:
        backup_path = backup_database()
        if backup_path:
            logger.info(f"Initial database backup created: {backup_path}")
    except Exception as e:
        logger.warning(f"Failed to create initial backup: {e}")

# Catch-all route for static files (images, fonts, etc.) - must be last
# This route only handles files that don't match any API routes above
@app.get("/{file_path:path}")
async def serve_static_files(file_path: str):
    """
    Serve static files from frontend directory.
    This catch-all route only handles files that don't match API routes.
    """
    import os
    # Only serve files with static file extensions
    static_extensions = ('.html', '.css', '.js', '.svg', '.png', '.jpg', '.jpeg', '.ico', '.woff2', '.woff', '.ttf', '.eot')
    if not file_path or not file_path.endswith(static_extensions):
        raise HTTPException(404, "Not found")
    
    # Don't serve files that look like API routes (even with extensions)
    if file_path.startswith(('api/', 'auth/', 'system/', 'user/', 'runtime/', 'model/', 
                             'repo/', 'tasks/', 'preparation/', 'cache/', 'config/', 
                             'event/', 'run/', 'ssh-keys/', 'ssh-command-profiles/', 
                             'ssh-profiles/', 'nhi/', 'audit-logs/', 'server-logs/', 
                             'health', 'docs', 'redoc', 'openapi.json')):
        raise HTTPException(404, "Not found")
    
    # Construct file path
    full_path = os.path.join("frontend", file_path)
    
    # Security: prevent directory traversal
    if not os.path.normpath(full_path).startswith(os.path.normpath("frontend")):
        raise HTTPException(403, "Forbidden")
    
    # Check if file exists
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        raise HTTPException(404, "File not found")
    
    # Determine media type
    media_type = "application/octet-stream"
    if file_path.endswith('.html'):
        media_type = "text/html"
    elif file_path.endswith('.css'):
        media_type = "text/css"
    elif file_path.endswith('.js'):
        media_type = "application/javascript"
    elif file_path.endswith('.svg'):
        media_type = "image/svg+xml"
    elif file_path.endswith('.png'):
        media_type = "image/png"
    elif file_path.endswith('.jpg') or file_path.endswith('.jpeg'):
        media_type = "image/jpeg"
    elif file_path.endswith('.ico'):
        media_type = "image/x-icon"
    elif file_path.endswith('.woff2'):
        media_type = "font/woff2"
    
    return FileResponse(full_path, media_type=media_type)