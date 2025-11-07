"""Database utilities including context manager and backup functionality"""
import sqlite3
import os
import shutil
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional
import logging
from .config import Config

logger = logging.getLogger(__name__)

@contextmanager
def get_db_connection():
    """
    Context manager for database connections with automatic cleanup.
    
    Usage:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM ...")
            conn.commit()
    
    Note: This function requires db_connect_with_retry to be imported separately
    to avoid circular imports. Import it in the calling code.
    """
    # Import here to avoid circular dependency
    import sqlite3
    from threading import Semaphore
    
    _db_semaphore = Semaphore(Config.DB_MAX_CONNECTIONS)
    
    def _db_connect_with_retry(timeout=None, max_retries=None, retry_delay=None):
        """Local implementation to avoid circular import"""
        timeout = timeout or Config.DB_TIMEOUT
        max_retries = max_retries or Config.DB_MAX_RETRIES
        retry_delay = retry_delay or Config.DB_RETRY_DELAY
        
        _db_semaphore.acquire()
        try:
            import time
            for attempt in range(max_retries):
                try:
                    conn = sqlite3.connect(Config.DB_PATH, timeout=timeout)
                    conn.execute('PRAGMA journal_mode=WAL')
                    conn.execute('PRAGMA synchronous=NORMAL')
                    conn.execute('PRAGMA cache_size=-64000')
                    conn.execute('PRAGMA temp_store=MEMORY')
                    conn.execute('PRAGMA mmap_size=268435456')
                    return conn
                except sqlite3.OperationalError as e:
                    if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                        time.sleep(retry_delay * (2 ** attempt))
                        continue
                    raise
            return None
        finally:
            _db_semaphore.release()
    
    conn = _db_connect_with_retry()
    if not conn:
        from fastapi import HTTPException
        raise HTTPException(500, "Database connection failed after retries")
    
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception as e:
            logger.warning(f"Error closing database connection: {e}")

def backup_database() -> Optional[str]:
    """
    Create a backup of the database.
    
    Returns:
        Path to backup file if successful, None otherwise
    """
    try:
        if not os.path.exists(Config.DB_PATH):
            logger.warning(f"Database file not found: {Config.DB_PATH}")
            return None
        
        # Create backup directory if it doesn't exist
        backup_dir = os.path.join(os.path.dirname(Config.DB_PATH), "backups")
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate backup filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{os.path.basename(Config.DB_PATH)}.backup.{timestamp}"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Use SQLite backup API for atomic backup
        source_conn = sqlite3.connect(Config.DB_PATH)
        backup_conn = sqlite3.connect(backup_path)
        
        try:
            source_conn.backup(backup_conn)
            backup_conn.close()
            source_conn.close()
            
            logger.info(f"Database backup created: {backup_path}")
            
            # Cleanup old backups
            cleanup_old_backups(backup_dir)
            
            return backup_path
        except Exception as e:
            logger.error(f"Error during database backup: {e}")
            # Cleanup failed backup file
            try:
                if os.path.exists(backup_path):
                    os.remove(backup_path)
            except Exception:
                pass
            return None
    except Exception as e:
        logger.error(f"Error creating database backup: {e}")
        return None

def cleanup_old_backups(backup_dir: Optional[str] = None):
    """
    Remove backup files older than retention period.
    
    Args:
        backup_dir: Directory containing backups (defaults to backups/ in DB directory)
    """
    try:
        if backup_dir is None:
            backup_dir = os.path.join(os.path.dirname(Config.DB_PATH), "backups")
        
        if not os.path.exists(backup_dir):
            return
        
        cutoff_date = datetime.now() - timedelta(days=Config.DB_BACKUP_RETENTION_DAYS)
        removed_count = 0
        
        for filename in os.listdir(backup_dir):
            if not filename.endswith(".backup."):
                continue
            
            file_path = os.path.join(backup_dir, filename)
            try:
                # Extract timestamp from filename
                # Format: dbname.backup.YYYYMMDD_HHMMSS
                parts = filename.split(".")
                if len(parts) >= 3:
                    timestamp_str = parts[-1]
                    try:
                        file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                        if file_date < cutoff_date:
                            os.remove(file_path)
                            removed_count += 1
                    except ValueError:
                        # Invalid timestamp format, skip
                        pass
            except Exception as e:
                logger.warning(f"Error processing backup file {filename}: {e}")
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} old backup file(s)")
    except Exception as e:
        logger.error(f"Error cleaning up old backups: {e}")

def backup_database_periodically():
    """Background task to backup database periodically (runs daily)"""
    import time
    
    while True:
        try:
            # Backup database
            backup_path = backup_database()
            if backup_path:
                logger.info(f"Periodic backup completed: {backup_path}")
            else:
                logger.warning("Periodic backup failed")
            
            # Wait 24 hours before next backup
            time.sleep(24 * 60 * 60)
        except Exception as e:
            logger.error(f"Error in periodic backup task: {e}")
            # Wait 1 hour before retrying on error
            time.sleep(60 * 60)

