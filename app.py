from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import json
from datetime import datetime, date, time as dt_time, timedelta
from typing import Optional, List
import threading
import time
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

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

# Database setup
DB_PATH = "fabricstudio_ui.db"

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

# Initialize database on startup
init_db()

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
    return FileResponse("frontend/app.js")

@app.get("/styles.css")
def serve_styles_css():
    return FileResponse("frontend/styles.css")

# Root: serve the SPA index
@app.get("/")
def root():
    return FileResponse("frontend/index.html", headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })

# Global no-cache for HTML/JSON responses to avoid stale frontend
@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    ct = response.headers.get("content-type", "")
    if "text/html" in ct or "application/json" in ct or request.url.path in {"/", "/frontend/index.html"}:
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


class TokenReq(BaseModel):
    client_id: str
    client_secret: str
    fabric_host: str


class HostnameReq(BaseModel):
    fabric_host: str
    access_token: str
    hostname: str


class UserPassReq(BaseModel):
    fabric_host: str
    access_token: str
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
    access_token: str
    template_id: int
    template_name: str
    version: str


class InstallFabricReq(BaseModel):
    fabric_host: str
    access_token: str
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
def get_hostname(fabric_host: str, access_token: str):
    value = query_hostname(fabric_host, access_token)
    if value is None:
        raise HTTPException(400, "Failed to query hostname")
    return {"hostname": value}


@app.post("/system/hostname")
def set_hostname(req: HostnameReq):
    change_hostname(req.fabric_host, req.access_token, req.hostname)
    return {"status": "ok"}


@app.post("/user/password")
def set_password(req: UserPassReq):
    user_id = get_userId(req.fabric_host, req.access_token, req.username)
    if not user_id:
        raise HTTPException(404, "User not found")
    change_password(req.fabric_host, req.access_token, user_id, req.new_password)
    return {"status": "ok"}


@app.post("/runtime/reset")
def runtime_reset(fabric_host: str, access_token: str):
    reset_fabric(fabric_host, access_token)
    return {"status": "ok"}


@app.delete("/model/fabric/batch")
def model_batch_delete(fabric_host: str, access_token: str):
    batch_delete(fabric_host, access_token)
    return {"status": "ok"}


@app.post("/repo/refresh")
def repo_refresh(fabric_host: str, access_token: str):
    refresh_repositories(fabric_host, access_token)
    return {"status": "ok"}


@app.get("/repo/template")
def repo_template(fabric_host: str, access_token: str, template_name: str, repo_name: str, version: str):
    tid = get_template(fabric_host, access_token, template_name, repo_name, version)
    if tid is None:
        raise HTTPException(404, "Template not found")
    return {"template_id": tid}


@app.post("/model/fabric")
def model_fabric_create(req: CreateFabricReq):
    result = create_fabric(req.fabric_host, req.access_token, req.template_id, req.template_name, req.version)
    if result is None:
        # create_fabric returns None on error, but doesn't raise - check logs for details
        # We'll still return 200 but log the error - the frontend checks tasks status
        return {"status": "ok", "message": "Fabric creation request submitted"}
    return {"status": "ok"}


@app.post("/runtime/fabric/install")
def model_fabric_install(req: InstallFabricReq):
    install_fabric(req.fabric_host, req.access_token, req.template_name, req.version)
    return {"status": "ok"}


@app.get("/tasks/progress")
def tasks_progress(fabric_host: str, access_token: str):
    mins = check_tasks(fabric_host, access_token, display_progress=False)
    return {"elapsed_minutes": mins}


@app.get("/tasks/status")
def tasks_status(fabric_host: str, access_token: str):
    count = get_running_task_count(fabric_host, access_token)
    if count is None:
        raise HTTPException(400, "Failed to get task status")
    return {"running_count": count}


def _init_db():
    conn = sqlite3.connect('cache.db')
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
def preparation_confirm(fabric_host: str, access_token: str):
    # 1) refresh repos (async on host)
    refresh_repositories(fabric_host, access_token)
    # Wait for background repo refresh tasks to complete to ensure templates are up to date
    try:
        check_tasks(fabric_host, access_token, display_progress=False)
    except Exception:
        # Best-effort wait; continue even if polling fails
        pass
    # 2) fetch all templates across repos
    templates = list_all_templates(fabric_host, access_token)
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
def repo_templates_list(fabric_host: str, access_token: str, repo_name: str):
    repo_id = get_repositoryId(fabric_host, access_token, repo_name)
    if not repo_id:
        # Fallback: list repos and try case-insensitive/alt-field match
        repos = list_repositories(fabric_host, access_token)
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
    templates = list_templates_for_repo(fabric_host, access_token, repo_id)
    # Normalize response to include name, version, id
    out = [
        {"id": t.get("id"), "name": t.get("name"), "version": t.get("version")}
        for t in templates
    ]
    return {"templates": out}


@app.get("/repo/remotes")
def repo_remotes(fabric_host: str, access_token: str):
    repos = list_repositories(fabric_host, access_token)
    out = [
        {"id": r.get("id"), "name": r.get("name")}
        for r in repos
    ]
    return {"repositories": out}


# Compatibility endpoint used by preparation flow to resolve a single template_id
@app.get("/repo/template")
def repo_template_single(fabric_host: str, access_token: str, template_name: str, repo_name: str, version: str):
    logger.info("/repo/template called with host=%s repo=%s template=%s version=%s", fabric_host, repo_name, template_name, version)
    # Strict: resolve repository by name/code (case-insensitive), but DO NOT search other repos for the template
    repos = list_repositories(fabric_host, access_token)
    logger.info("Fetched %d repositories from host %s", len(repos), fabric_host)
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
    logger.info("Matched repository id=%s name=%s", rid, match.get("name"))
    templates = list_templates_for_repo(fabric_host, access_token, rid)
    logger.info("Retrieved %d templates from repo id=%s", len(templates), rid)
    tname_norm = (template_name or "").strip().lower()
    ver_norm = (version or "").strip()
    for t in templates:
        name_norm = (t.get("name") or "").strip().lower()
        ver_val = (t.get("version") or "").strip()
        if name_norm == tname_norm and ver_val == ver_norm:
            logger.info("Template matched in repo id=%s: id=%s name='%s' version='%s'", rid, t.get("id"), t.get("name"), t.get("version"))
            return {"template_id": t.get("id")}
    sample = [{"id": x.get("id"), "name": x.get("name"), "version": x.get("version")} for x in templates[:5]]
    logger.warning("Template not found in repo '%s'. Looking for name='%s' version='%s'. Sample: %s", match.get("name"), template_name, version, sample)
    raise HTTPException(404, "Template not found")


# New lightweight proxy endpoints for repository/template metadata
@app.get("/repo/remotes")
def repo_remotes(fabric_host: str, access_token: str):
    url = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {
        "Authorization": f"Bearer {access_token}",
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
def repo_templates_list(fabric_host: str, access_token: str, repo_name: str):
    # Resolve repo id first
    url_repo = f"https://{fabric_host}/api/v1/system/repository/remote"
    headers = {"Authorization": f"Bearer {access_token}", "Cache-Control": "no-cache"}
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
def repo_versions(fabric_host: str, access_token: str, repo_name: str, template_name: str):
    # Reuse templates/list and filter versions
    data = repo_templates_list(fabric_host, access_token, repo_name)
    versions = sorted({o["version"] for o in data.get("templates", []) if o.get("name") == template_name and o.get("version") is not None})
    return {"versions": versions}


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
def save_config(req: SaveConfigReq):
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
        else:
            # Insert new configuration
            c.execute('''
                INSERT INTO configurations (name, config_data, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (req.name.strip(), json.dumps(req.config_data)))
            action = "saved"
        
        conn.commit()
        config_id = req.id if req.id is not None else c.lastrowid
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
def delete_config(config_id: int):
    """Delete a configuration by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('DELETE FROM configurations WHERE id = ?', (config_id,))
        conn.commit()
        
        if c.rowcount == 0:
            raise HTTPException(404, f"Configuration with id {config_id} not found")
        
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
def save_event(req: CreateEventReq):
    """Save an event schedule"""
    if not req.name or not req.name.strip():
        raise HTTPException(400, "Event name is required")
    if not req.event_date:
        raise HTTPException(400, "Event date is required")
    if not req.configuration_id:
        raise HTTPException(400, "Configuration is required")
    
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
                        logger.info(f"Stored encrypted NHI password for event_id={event_id}, nhi_credential_id={nhi_cred_id}")
                    else:
                        logger.warning(f"Configuration {req.configuration_id} has no nhiCredentialId; skipping password store")
        except Exception as e:
            logger.error(f"Error storing NHI password for event {event_id}: {e}", exc_info=True)
        
        conn.commit()
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
def delete_event(event_id: int):
    """Delete an event by ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('DELETE FROM event_schedules WHERE id = ?', (event_id,))
        conn.commit()
        
        if c.rowcount == 0:
            raise HTTPException(404, f"Event with id {event_id} not found")
        
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
    logger.info(f"Starting auto-run execution for event: {event_name}")
    
    execution_record_id = None
    started_at = datetime.now()
    
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
            except sqlite3.Error as e:
                logger.error(f"Failed to create execution record: {e}")
            finally:
                conn.close()
        # Extract configuration data
        hosts = config_data.get('confirmedHosts', [])
        if not hosts:
            logger.warning(f"No hosts configured for event {event_name}")
            completed_at = datetime.now()
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
        
        logger.info(f"Event '{event_name}': Configuration loaded - {len(hosts)} host(s), {len(templates_list)} template(s)")
        
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
                            logger.info(f"Event '{event_name}': Retrieved and decrypted client secret from stored credential (id={nhi_cred_id})")
                conn.close()
            except Exception as e:
                logger.error(f"Event '{event_name}': Failed to retrieve/decrypt client secret for event {event_id}: {e}", exc_info=True)

        # Step 1: Get tokens for all hosts (reuse stored if valid, otherwise fetch new)
        logger.info(f"Event '{event_name}': Acquiring tokens for {len(hosts)} host(s)...")
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
                                logger.info(f"Event '{event_name}': Reusing stored token for host {host} (expires in {hours}h {minutes}m)")
                                token_fetched = True
                            else:
                                logger.info(f"Event '{event_name}': Stored token for host {host} has expired, will fetch new token")
                    conn.close()
                except Exception as e:
                    logger.warning(f"Event '{event_name}': Error checking stored token for {host}: {e}, will fetch new token")
            
            # If no valid stored token, fetch a new one
            if not token_fetched:
                try:
                    token_data = get_access_token(client_id, client_secret, host)
                    if token_data and token_data.get("access_token"):
                        host_tokens[host] = token_data.get("access_token")
                        logger.info(f"Event '{event_name}': Token acquired for host {host}")
                        
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
                                    logger.info(f"Event '{event_name}': Stored new token for host {host} in NHI credential")
                            except Exception as e:
                                logger.warning(f"Event '{event_name}': Failed to store token for {host}: {e}")
                    else:
                        msg = f"Failed to acquire token for host {host}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                        completed_at = datetime.now()
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
                    completed_at = datetime.now()
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
        logger.info(f"Event '{event_name}': Executing preparation steps...")
        
        # Refresh repositories
        logger.info(f"Event '{event_name}': Refreshing repositories...")
        for host in host_tokens.keys():
            try:
                refresh_repositories(host, host_tokens[host])
                logger.info(f"Event '{event_name}': Repositories refreshed for host {host}")
            except Exception as e:
                msg = f"Error refreshing repositories on host {host}: {e}"
                logger.error(f"Event '{event_name}': {msg}")
                errors.append(msg)
        
        # Uninstall workspaces (reset)
        logger.info(f"Event '{event_name}': Uninstalling workspaces...")
        for host in host_tokens.keys():
            try:
                reset_fabric(host, host_tokens[host])
                logger.info(f"Event '{event_name}': Workspaces uninstalled for host {host}")
            except Exception as e:
                msg = f"Error uninstalling workspaces on host {host}: {e}"
                logger.error(f"Event '{event_name}': {msg}")
                errors.append(msg)
        
        # Remove workspaces (batch delete)
        logger.info(f"Event '{event_name}': Removing workspaces...")
        for host in host_tokens.keys():
            try:
                batch_delete(host, host_tokens[host])
                logger.info(f"Event '{event_name}': Workspaces removed for host {host}")
            except Exception as e:
                msg = f"Error removing workspaces on host {host}: {e}"
                logger.error(f"Event '{event_name}': {msg}")
                errors.append(msg)
        
        # Change hostname if provided
        if new_hostname:
            logger.info(f"Event '{event_name}': Changing hostnames to base '{new_hostname}'...")
            for i, host in enumerate(host_tokens.keys()):
                try:
                    hostname = f"{new_hostname}{i + 1}"
                    change_hostname(host, host_tokens[host], hostname)
                    logger.info(f"Event '{event_name}': Hostname changed to {hostname} for host {host}")
                except Exception as e:
                    msg = f"Error changing hostname on host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
        
        # Change password if provided
        if new_password:
            logger.info(f"Event '{event_name}': Changing guest password...")
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
                    logger.info(f"Event '{event_name}': Password changed for host {host}")
                except Exception as e:
                    msg = f"Error changing password on host {host}: {e}"
                    logger.error(f"Event '{event_name}': {msg}")
                    errors.append(msg)
        
        # Step 3: Create all workspace templates
        if templates_list:
            logger.info(f"Event '{event_name}': Creating {len(templates_list)} workspace template(s)...")
            for template_info in templates_list:
                template_name = template_info.get('template_name', '')
                repo_name = template_info.get('repo_name', '')
                version = template_info.get('version', '')
                
                if not (template_name and repo_name and version):
                    continue
                
                logger.info(f"Event '{event_name}': Creating template '{template_name}' v{version} from repo '{repo_name}'...")
                
                # Check for running tasks before creating
                for host in host_tokens.keys():
                    try:
                        running_count = get_running_task_count(host, host_tokens[host])
                        if running_count > 0:
                            logger.info(f"Event '{event_name}': Waiting for {running_count} running task(s) on host {host}...")
                            check_tasks(host, host_tokens[host], display_progress=False)
                    except Exception as e:
                        msg = f"Error checking tasks on host {host}: {e}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                
                # Create template on all hosts
                for host in host_tokens.keys():
                    try:
                        # Get template ID
                        template_id = get_template(host, host_tokens[host], template_name, repo_name, version)
                        if template_id:
                            # Create fabric (pass template name and version per API signature)
                            create_fabric(host, host_tokens[host], template_id, template_name, version)
                            logger.info(f"Event '{event_name}': Template '{template_name}' v{version} created on host {host}")
                        else:
                            msg = f"Template '{template_name}' v{version} not found on host {host}"
                            logger.error(f"Event '{event_name}': {msg}")
                            errors.append(msg)
                    except Exception as e:
                        msg = f"Error creating template '{template_name}' v{version} on host {host}: {e}"
                        logger.error(f"Event '{event_name}': {msg}")
                        errors.append(msg)
                
                # Wait for tasks to complete after each template
                for host in host_tokens.keys():
                    try:
                        check_tasks(host, host_tokens[host], display_progress=False)
                    except Exception as e:
                        msg = f"Error waiting for tasks on host {host}: {e}"
                        logger.warning(f"Event '{event_name}': {msg}")
                        errors.append(msg)
        
        # Step 4: Install selected workspace
        if install_select:
            template_name, version = install_select.split('|||')
            # Find repo_name from templates list
            repo_name = ''
            for t in templates_list:
                if t.get('template_name') == template_name and t.get('version') == version:
                    repo_name = t.get('repo_name', '')
                    break
            
            if repo_name:
                logger.info(f"Event '{event_name}': Installing workspace '{template_name}' v{version} from repo '{repo_name}'...")
                for host in host_tokens.keys():
                    try:
                        template_id = get_template(host, host_tokens[host], template_name, repo_name, version)
                        if template_id:
                            # install_fabric expects template name and version, not id
                            install_fabric(host, host_tokens[host], template_name, version)
                            logger.info(f"Event '{event_name}': Workspace '{template_name}' v{version} installed on host {host}")
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
            logger.info(f"Event '{event_name}': No workspace selected for installation")
        
        completed_at = datetime.now()
        
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
                        "installed": (
                            {
                                "repo_name": repo_name if 'repo_name' in locals() else '',
                                "template_name": template_name if 'template_name' in locals() else '',
                                "version": version if 'version' in locals() else ''
                            } if install_select else None
                        ),
                        "install_select": install_select,
                        "duration_seconds": (completed_at - started_at).total_seconds()
                    }),
                    execution_record_id
                ))
                conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Failed to update execution record: {e}")
            finally:
                conn.close()
        
        if errors:
            logger.error(f"Auto-run execution completed with errors for event: {event_name}")
            return {"status": "error", "message": "Auto-run completed with errors", "errors": errors, "event": event_name}
        logger.info(f"Auto-run execution completed successfully for event: {event_name}")
        return {"status": "ok", "message": "Auto-run execution completed successfully", "event": event_name}
    except Exception as e:
        logger.error(f"Error executing configuration for event '{event_name}': {e}", exc_info=True)
        
        # Update execution record with error
        completed_at = datetime.now()
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
                        "install_select": install_select if 'install_select' in locals() else ''
                    }),
                    execution_record_id
                ))
                conn.commit()
            except sqlite3.Error as db_err:
                logger.error(f"Failed to update execution record with error: {db_err}")
            finally:
                conn.close()
        
        return {"status": "error", "message": str(e), "errors": [str(e)], "event": event_name}


# NHI Management endpoints
class SaveNhiReq(BaseModel):
    name: str
    client_id: str
    client_secret: str
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


@app.post("/nhi/save")
def save_nhi(req: SaveNhiReq):
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
    if not req.client_secret or not req.client_secret.strip():
        raise HTTPException(400, "Client Secret is required")
    if not req.encryption_password or not req.encryption_password.strip():
        raise HTTPException(400, "Encryption password is required")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # Encrypt the client secret
        encrypted_secret = encrypt_client_secret(req.client_secret, req.encryption_password)
        
        # Get tokens for all fabric_hosts if provided
        # Parse hosts (space-separated)
        hosts_to_process = []
        if req.fabric_hosts and req.fabric_hosts.strip():
            hosts_to_process = [h.strip() for h in req.fabric_hosts.strip().split() if h.strip()]
        
        if req.id is not None:
            # Update existing credential
            c.execute('SELECT id FROM nhi_credentials WHERE id = ?', (req.id,))
            existing = c.fetchone()
            
            if not existing:
                raise HTTPException(404, f"NHI credential with id {req.id} not found")
            
            # Check if name is already taken by another credential
            c.execute('SELECT id FROM nhi_credentials WHERE name = ? AND id != ?', (name_stripped, req.id))
            if c.fetchone():
                raise HTTPException(400, f"Name '{name_stripped}' is already in use")
            
            c.execute('''
                UPDATE nhi_credentials 
                SET name = ?, client_id = ?, client_secret_encrypted = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (name_stripped, req.client_id.strip(), encrypted_secret, req.id))
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
        if nhi_id and hosts_to_process:
            for fabric_host in hosts_to_process:
                try:
                    token_data = get_access_token(req.client_id.strip(), req.client_secret.strip(), fabric_host)
                    if token_data and token_data.get("access_token"):
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
                except Exception as e:
                    # Log error but continue with other hosts
                    print(f"Warning: Could not get token for host {fabric_host}: {e}")
        
        conn.commit()
        
        message = f"NHI credential '{name_stripped}' {action} successfully"
        if tokens_stored > 0:
            message += f" ({tokens_stored} token(s) stored for {tokens_stored} host(s))"
        elif hosts_to_process:
            message += " (No tokens stored - check hosts and credentials)"
        
        return {"status": "ok", "message": message, "id": nhi_id}
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


@app.get("/nhi/get/{nhi_id}")
def get_nhi(nhi_id: int, encryption_password: str):
    """Retrieve an NHI credential by ID and decrypt the secret"""
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
        
        # Decrypt the client secret
        try:
            decrypted_secret = decrypt_client_secret(row[2], encryption_password)
        except ValueError as e:
            raise HTTPException(400, str(e))
        
        # Get all tokens for this credential (decrypted)
        c.execute('''
            SELECT fabric_host, token_encrypted, token_expires_at
            FROM nhi_tokens
            WHERE nhi_credential_id = ?
            ORDER BY fabric_host ASC
        ''', (nhi_id,))
        token_rows = c.fetchall()
        
        tokens_by_host = {}
        for token_row in token_rows:
            fabric_host = token_row[0]
            token_encrypted = token_row[1]
            token_expires_at = token_row[2]
            
            # Decrypt and check if valid
            try:
                from datetime import datetime
                expires_at = datetime.fromisoformat(token_expires_at)
                now = datetime.now()
                if expires_at > now:
                    # Token is valid, decrypt it
                    decrypted_token = decrypt_client_secret(token_encrypted, encryption_password)
                    tokens_by_host[fabric_host] = {
                        "token": decrypted_token,
                        "expires_at": token_expires_at
                    }
            except:
                # If decryption or date parsing fails, skip this token
                pass
        
        result = {
            "id": nhi_id,
            "name": row[0],
            "client_id": row[1],
            "client_secret": decrypted_secret,
            "tokens_by_host": tokens_by_host,
            "created_at": row[3],
            "updated_at": row[4]
        }
        
        return result
    except HTTPException:
        raise
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


@app.post("/nhi/update-token/{nhi_id}")
def update_nhi_token(nhi_id: int, fabric_host: str, token: str, expires_in: int, encryption_password: str):
    """Update or add a token for a specific host in an NHI credential"""
    if not encryption_password:
        raise HTTPException(400, "Encryption password is required")
    if not fabric_host or not fabric_host.strip():
        raise HTTPException(400, "Fabric host is required")
    if not token:
        raise HTTPException(400, "Token is required")
    
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
        
        return {"status": "ok", "message": f"NHI credential {nhi_id} deleted successfully"}
    except sqlite3.Error as e:
        conn.rollback()
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


# Track events that have been executed to prevent duplicates
executed_events = set()

# Background scheduler to check for events that need to run
def check_and_run_events():
    """Check for events that should run now and execute them"""
    global executed_events
    logger.info("Background event scheduler started and running...")
    
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
                logger.info(f"Scheduler check at {now.strftime('%Y-%m-%d %H:%M:%S')}: Found {len(events_to_run)} event(s) to run")
            
            # Clean up executed events from previous days
            if events_to_run:
                today_str = str(current_date)
                executed_events = {e for e in executed_events if str(e).startswith(today_str)}
            
            for event_id, event_name, event_date, event_time in events_to_run:
                # Create unique key for this event execution
                event_key = f"{event_date}_{event_time or 'all'}_{event_id}"
                
                # Skip if already executed
                if event_key in executed_events:
                    logger.info(f"Skipping event '{event_name}' (ID: {event_id}) - already executed today")
                    continue
                
                logger.info(f"Found scheduled event to run: '{event_name}' (ID: {event_id}) scheduled for {event_date} at {event_time or '00:00:00'}")
                
                # Mark as executed before starting (to prevent duplicate if scheduler runs again)
                executed_events.add(event_key)
                
                try:
                    # Execute in background thread
                    thread = threading.Thread(target=execute_event_internal, args=(event_id, event_name))
                    thread.daemon = False  # Keep thread alive until execution completes
                    thread.start()
                    logger.info(f"Started execution thread for event '{event_name}' (ID: {event_id})")
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
        logger.info(f"Executing event internally: event_id={event_id}, event_name={event_name or 'unknown'}")
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
            
            logger.info(f"Starting auto-run execution for event '{event_name}' (ID: {event_id})")
            try:
                run_configuration(config_data, event_name, event_id)
                logger.info(f"Completed auto-run execution for event '{event_name}' (ID: {event_id})")
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

@app.on_event("startup")
def start_scheduler():
    """Start the background scheduler on application startup"""
    global scheduler_thread
    if scheduler_thread is None or not scheduler_thread.is_alive():
        scheduler_thread = threading.Thread(target=check_and_run_events)
        scheduler_thread.daemon = True  # Allow main process to exit
        scheduler_thread.start()
        logger.info("Background event scheduler thread started")
    else:
        logger.info("Background event scheduler already running")


