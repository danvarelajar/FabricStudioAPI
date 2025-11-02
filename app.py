from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import json
from datetime import datetime, date, time as dt_time
from typing import Optional, List
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

from fabricstudio.auth import get_access_token
from fabricstudio.fabricstudio_api import (
    query_hostname, change_hostname, get_userId, change_password,
    reset_fabric, batch_delete, refresh_repositories,
    get_template, create_fabric, install_fabric, check_tasks, get_running_task_count
)
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
    return FileResponse("frontend/index.html")

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
                e.updated_at
            FROM event_schedules e
            LEFT JOIN configurations c ON e.configuration_id = c.id
            ORDER BY e.event_date ASC, COALESCE(e.event_time, '') ASC, e.name ASC
        ''')
        rows = c.fetchall()
        return {
            "events": [
                {
                    "id": row[0],
                    "name": row[1],
                    "event_date": row[2],
                    "event_time": row[3] if row[3] else None,
                    "configuration_id": row[4],
                    "auto_run": bool(row[5]),
                    "configuration_name": row[6] if row[6] else "Unknown",
                    "created_at": row[7],
                    "updated_at": row[8]
                }
                for row in rows
            ]
        }
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
        
        # Execute in background
        background_tasks.add_task(run_configuration, config_data, event_name)
        
        return {"status": "ok", "message": f"Event '{event_name}' execution started"}
    except json.JSONDecodeError:
        raise HTTPException(500, "Invalid configuration data")
    except sqlite3.Error as e:
        raise HTTPException(500, f"Database error: {str(e)}")
    finally:
        conn.close()


def run_configuration(config_data: dict, event_name: str):
    """Execute a configuration (same logic as frontend Run button)"""
    print(f"[AUTO-RUN] Starting execution for event: {event_name}")
    
    try:
        # Extract configuration data
        hosts = config_data.get('confirmedHosts', [])
        if not hosts:
            print(f"[AUTO-RUN] No hosts configured for event {event_name}")
            return
        
        client_id = config_data.get('clientId', '')
        client_secret = config_data.get('clientSecret', '')
        new_hostname = config_data.get('newHostname', '')
        new_password = config_data.get('chgPass', '')
        templates_list = config_data.get('templates', [])
        install_select = config_data.get('installSelect', '')
        
        # Step 1: Get fresh tokens for all hosts
        print(f"[AUTO-RUN] Acquiring tokens for {len(hosts)} host(s)...")
        host_tokens = {}
        for host_info in hosts:
            host = host_info.get('host', '')
            try:
                token_data = get_access_token(client_id, client_secret, host)
                if token_data and token_data.get("access_token"):
                    host_tokens[host] = token_data.get("access_token")
                    print(f"[AUTO-RUN] Token acquired for {host}")
                else:
                    print(f"[AUTO-RUN] Failed to acquire token for {host}")
                    return
            except Exception as e:
                print(f"[AUTO-RUN] Error acquiring token for {host}: {e}")
                return
        
        # Step 2: Execute preparation steps
        print(f"[AUTO-RUN] Executing preparation steps...")
        
        # Refresh repositories
        print(f"[AUTO-RUN] Refreshing repositories...")
        for host in host_tokens.keys():
            try:
                refresh_repositories(host, host_tokens[host])
                print(f"[AUTO-RUN] Repositories refreshed for {host}")
            except Exception as e:
                print(f"[AUTO-RUN] Error refreshing repositories on {host}: {e}")
        
        # Uninstall workspaces (reset)
        print(f"[AUTO-RUN] Uninstalling workspaces...")
        for host in host_tokens.keys():
            try:
                reset_fabric(host, host_tokens[host])
                print(f"[AUTO-RUN] Workspaces uninstalled for {host}")
            except Exception as e:
                print(f"[AUTO-RUN] Error uninstalling workspaces on {host}: {e}")
        
        # Remove workspaces (batch delete)
        print(f"[AUTO-RUN] Removing workspaces...")
        for host in host_tokens.keys():
            try:
                batch_delete(host, host_tokens[host])
                print(f"[AUTO-RUN] Workspaces removed for {host}")
            except Exception as e:
                print(f"[AUTO-RUN] Error removing workspaces on {host}: {e}")
        
        # Change hostname if provided
        if new_hostname:
            print(f"[AUTO-RUN] Changing hostnames...")
            for i, host in enumerate(host_tokens.keys()):
                try:
                    hostname = f"{new_hostname}{i + 1}"
                    change_hostname(host, host_tokens[host], hostname)
                    print(f"[AUTO-RUN] Hostname changed to {hostname} for {host}")
                except Exception as e:
                    print(f"[AUTO-RUN] Error changing hostname on {host}: {e}")
        
        # Change password if provided
        if new_password:
            print(f"[AUTO-RUN] Changing password...")
            for host in host_tokens.keys():
                try:
                    change_password(host, host_tokens[host], 'guest', new_password)
                    print(f"[AUTO-RUN] Password changed for {host}")
                except Exception as e:
                    print(f"[AUTO-RUN] Error changing password on {host}: {e}")
        
        # Step 3: Create all workspace templates
        if templates_list:
            print(f"[AUTO-RUN] Creating {len(templates_list)} workspace template(s)...")
            for template_info in templates_list:
                template_name = template_info.get('template_name', '')
                repo_name = template_info.get('repo_name', '')
                version = template_info.get('version', '')
                
                if not (template_name and repo_name and version):
                    continue
                
                print(f"[AUTO-RUN] Creating template: {template_name} v{version}")
                
                # Check for running tasks before creating
                for host in host_tokens.keys():
                    try:
                        running_count = get_running_task_count(host, host_tokens[host])
                        if running_count > 0:
                            print(f"[AUTO-RUN] Waiting for {running_count} running task(s) on {host}...")
                            check_tasks(host, host_tokens[host], display_progress=False)
                    except Exception as e:
                        print(f"[AUTO-RUN] Warning: Error checking tasks on {host}: {e}")
                
                # Create template on all hosts
                for host in host_tokens.keys():
                    try:
                        # Get template ID
                        template_id = get_template(host, host_tokens[host], template_name, repo_name, version)
                        if template_id:
                            # Create fabric
                            create_fabric(host, host_tokens[host], template_id)
                            print(f"[AUTO-RUN] Template {template_name} created on {host}")
                        else:
                            print(f"[AUTO-RUN] Template {template_name} not found on {host}")
                    except Exception as e:
                        print(f"[AUTO-RUN] Error creating template {template_name} on {host}: {e}")
                
                # Wait for tasks to complete after each template
                for host in host_tokens.keys():
                    try:
                        check_tasks(host, host_tokens[host], display_progress=False)
                    except Exception as e:
                        print(f"[AUTO-RUN] Warning: Error waiting for tasks on {host}: {e}")
        
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
                print(f"[AUTO-RUN] Installing workspace: {template_name} v{version}")
                for host in host_tokens.keys():
                    try:
                        template_id = get_template(host, host_tokens[host], template_name, repo_name, version)
                        if template_id:
                            install_fabric(host, host_tokens[host], template_id)
                            print(f"[AUTO-RUN] Workspace {template_name} installed on {host}")
                        else:
                            print(f"[AUTO-RUN] Template {template_name} not found on {host} for installation")
                    except Exception as e:
                        print(f"[AUTO-RUN] Error installing workspace {template_name} on {host}: {e}")
            else:
                print(f"[AUTO-RUN] Repository name not found for {template_name} v{version}")
        else:
            print(f"[AUTO-RUN] No workspace selected for installation")
        
        print(f"[AUTO-RUN] Execution completed for event: {event_name}")
        
    except Exception as e:
        print(f"[AUTO-RUN] Error executing configuration for event {event_name}: {e}")
        import traceback
        traceback.print_exc()


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


# Background scheduler to check for events that need to run
def check_and_run_events():
    """Check for events that should run now and execute them"""
    while True:
        try:
            now = datetime.now()
            current_date = now.date()
            current_time = now.time().replace(second=0, microsecond=0)  # Round to minute
            
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            
            # Find events that should run now (auto_run enabled, date matches, time matches or no time specified)
            c.execute('''
                SELECT id, name, event_date, event_time
                FROM event_schedules
                WHERE auto_run = 1
                AND event_date = ?
                AND (event_time IS NULL OR event_time = ?)
            ''', (str(current_date), str(current_time)))
            
            events_to_run = c.fetchall()
            conn.close()
            
            for event_id, event_name, event_date, event_time in events_to_run:
                print(f"[SCHEDULER] Found event to run: {event_name} (ID: {event_id})")
                try:
                    # Make internal request to execute endpoint
                    # We'll use threading to execute in background
                    thread = threading.Thread(target=execute_event_internal, args=(event_id,))
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    print(f"[SCHEDULER] Error executing event {event_id}: {e}")
            
            # Check every minute
            time.sleep(60)
            
        except Exception as e:
            print(f"[SCHEDULER] Error in scheduler: {e}")
            time.sleep(60)


def execute_event_internal(event_id: int):
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
            config_id, config_data_json, event_name = row
            config_data = json.loads(config_data_json)
            run_configuration(config_data, event_name)
    except Exception as e:
        print(f"[AUTO-RUN] Error executing event {event_id}: {e}")


# Start scheduler in background thread on startup
scheduler_thread = None

@app.on_event("startup")
def start_scheduler():
    """Start the background scheduler on application startup"""
    global scheduler_thread
    scheduler_thread = threading.Thread(target=check_and_run_events)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    print("[SCHEDULER] Background event scheduler started")


