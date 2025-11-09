#!/usr/bin/env python3
"""
Script to reset a user's password in the database
This is useful when FS_SERVER_SECRET changes and passwords can't be decrypted
"""
import sys
import os

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.app import update_user_password, get_user_by_username

def main():
    if len(sys.argv) < 3:
        print("Usage: python reset_user_password.py <username> <new_password>")
        sys.exit(1)
    
    username = sys.argv[1]
    new_password = sys.argv[2]
    
    print(f"Resetting password for user '{username}'...")
    
    user = get_user_by_username(username)
    if not user:
        print(f"Error: User '{username}' not found")
        sys.exit(1)
    
    try:
        update_user_password(user['id'], new_password)
        print(f"✓ Password reset successfully for user '{username}'")
    except Exception as e:
        print(f"✗ Error resetting password: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

