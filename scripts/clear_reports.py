#!/usr/bin/env python3
"""
Clear all reports from the manual_runs table.
"""
import sqlite3
import os
import sys

# Add parent directory to path to import config
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.config import Config

# Use DB_PATH from config, but also check data directory if not found
DB_PATH = Config.DB_PATH
if not os.path.exists(DB_PATH):
    # Try data directory
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'fabricstudio_ui.db')
    if os.path.exists(data_path):
        DB_PATH = os.path.abspath(data_path)

def clear_reports():
    """Clear all reports from the manual_runs table"""
    if not os.path.exists(DB_PATH):
        print(f"Database file not found: {DB_PATH}")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Get count before deletion
        c.execute('SELECT COUNT(*) FROM manual_runs')
        count = c.fetchone()[0]
        
        if count == 0:
            print("No reports to clear.")
            conn.close()
            return True
        
        # Delete all reports
        c.execute('DELETE FROM manual_runs')
        conn.commit()
        conn.close()
        
        print(f"✓ Successfully cleared {count} report(s) from manual_runs table")
        return True
        
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == "__main__":
    print(f"Clearing reports from database: {DB_PATH}")
    success = clear_reports()
    sys.exit(0 if success else 1)

