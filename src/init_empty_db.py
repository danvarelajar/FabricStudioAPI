#!/usr/bin/env python3
"""
Initialize an empty database with the correct schema.
This script creates a fresh database file that matches the application schema.
"""
import sqlite3
import os

DB_PATH = "fabricstudio_ui.db"

def init_empty_db():
    """Initialize an empty SQLite database with all required tables"""
    # Remove existing database if it exists
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"Removed existing {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Create configurations table
    c.execute('''
        CREATE TABLE configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            config_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create event_schedules table
    c.execute('''
        CREATE TABLE event_schedules (
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
    
    # Create NHI credentials table
    c.execute('''
        CREATE TABLE nhi_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            client_id TEXT NOT NULL,
            client_secret_encrypted TEXT NOT NULL,
            tokens_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create NHI tokens table
    c.execute('''
        CREATE TABLE nhi_tokens (
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
    
    # Create cached templates table
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
    conn.close()
    print(f"✓ Successfully created empty database: {DB_PATH}")
    print("  The database is ready to use with the FabricStudio API application.")

if __name__ == "__main__":
    init_empty_db()

