#!/usr/bin/env python3
"""
Script to create or verify users in the database
"""
import sys
import os

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.app import hash_password, verify_password, get_user_by_username, create_user, update_user_password
from src.db_utils import get_db_connection
import sqlite3
import logging

logger = logging.getLogger(__name__)

# Define initial users to create on fresh deployment
INITIAL_USERS = [
    ("admin", "FortinetAssistant1!")
]

def ensure_initial_users(users_list=None, verbose=False):
    """
    Ensure initial users exist in the database.
    If a user exists, verifies/updates password. If not, creates the user.
    
    Args:
        users_list: List of (username, password) tuples. If None, uses INITIAL_USERS.
        verbose: If True, prints messages. If False, uses logger.
    """
    if users_list is None:
        users_list = INITIAL_USERS
    
    log_func = print if verbose else logger.info
    
    for username, password in users_list:
        user = get_user_by_username(username)
        if user:
            if verbose:
                log_func(f"User '{username}' already exists")
            # Test password verification
            try:
                is_valid = verify_password(password, user['password_encrypted'])
                if is_valid:
                    if verbose:
                        log_func(f"  ✓ Password verification successful")
                else:
                    if verbose:
                        log_func(f"  ✗ Password verification failed - updating password")
                    # Update password
                    update_user_password(user['id'], password)
                    log_func(f"Updated password for user: {username}")
            except Exception as e:
                if verbose:
                    log_func(f"  ✗ Error verifying password: {e}")
                # Update password
                update_user_password(user['id'], password)
                log_func(f"Updated password for user: {username}")
        else:
            if verbose:
                log_func(f"Creating user '{username}'...")
            try:
                user_id = create_user(username, password)
                log_func(f"Created initial user: {username} (ID: {user_id})")
            except Exception as e:
                log_func(f"Failed to create initial user {username}: {e}")

def main():
    """CLI entry point for the script"""
    print("Checking and creating users...")
    ensure_initial_users(verbose=True)
    print("\nVerification complete!")

if __name__ == "__main__":
    main()

