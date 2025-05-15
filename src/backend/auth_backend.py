# Updated auth_backend.py
import bcrypt
import time
from datetime import datetime, timedelta
import json
import os
import logging
from pathlib import Path
from typing import Tuple, Dict, Optional
import structlog
from src.utils.crypto import CryptoManager

logger = structlog.get_logger(__name__)

class AuthBackend:
    def __init__(self):
        self.users_file = Path("config/users.json")
        self.failed_attempts: Dict[str, Dict] = {}  # Track failed login attempts
        self.ip_attempts: Dict[str, Dict] = {}  # Track IP-based attempts
        self.lockout_duration = 300  # 5 minutes
        self.max_attempts = 3
        self.ip_max_attempts = 5
        self.crypto_manager = CryptoManager()
        self.load_users()
        
    def load_users(self):
        """Load users from JSON file or create default if not exists"""
        try:
            if not self.users_file.exists():
                # Create default users if file doesn't exist
                default_users = {
                    "junior": {
                        "password": self._hash_password("junior123"),
                        "role": "junior",
                        "failed_attempts": 0,
                        "last_attempt": None,
                        "locked_until": None
                    },
                    "senior": {
                        "password": self._hash_password("senior123"),
                        "role": "senior",
                        "failed_attempts": 0,
                        "last_attempt": None,
                        "locked_until": None
                    }
                }
                
                # Ensure config directory exists
                self.users_file.parent.mkdir(exist_ok=True)
                
                # Save default users
                with open(self.users_file, 'w') as f:
                    json.dump(default_users, f, indent=4)
                    
                self.users = default_users
            else:
                # Load existing users
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
        except Exception as e:
            logger.error("Failed to load users", error=str(e))
            raise
            
    def save_users(self):
        """Save users to JSON file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            logger.error("Failed to save users", error=str(e))
            
    def _hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()
        
    def _verify_password(self, stored_hash: str, password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False
            
    def is_account_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        """Check if account is locked and return remaining lockout time"""
        user = self.users.get(username)
        if not user:
            return False, None
            
        locked_until = user.get('locked_until')
        if locked_until:
            now = datetime.now().timestamp()
            if now < locked_until:
                return True, int(locked_until - now)
            else:
                # Reset lockout if time has passed
                user['locked_until'] = None
                user['failed_attempts'] = 0
                self.save_users()
                
        return False, None
        
    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[int]]:
        """Check if IP is blocked and return remaining block time"""
        if ip in self.ip_attempts:
            attempts = self.ip_attempts[ip]['attempts']
            last_attempt = self.ip_attempts[ip]['timestamp']
            
            if attempts >= self.ip_max_attempts:
                time_passed = time.time() - last_attempt
                if time_passed < self.lockout_duration:
                    return True, int(self.lockout_duration - time_passed)
                else:
                    # Reset if block time has passed
                    del self.ip_attempts[ip]
                    
        return False, None
        
    def record_failed_attempt(self, username: str, ip: str):
        """Record a failed login attempt"""
        # Record username-based attempt
        if username in self.users:
            user = self.users[username]
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            user['last_attempt'] = datetime.now().timestamp()
            
            # Lock account if max attempts exceeded
            if user['failed_attempts'] >= self.max_attempts:
                user['locked_until'] = (datetime.now() + 
                                      timedelta(seconds=self.lockout_duration)).timestamp()
                
            self.save_users()
            
        # Record IP-based attempt
        if ip not in self.ip_attempts:
            self.ip_attempts[ip] = {'attempts': 1, 'timestamp': time.time()}
        else:
            self.ip_attempts[ip]['attempts'] += 1
            self.ip_attempts[ip]['timestamp'] = time.time()
            
        # Log the attempt
        self._log_failed_attempt(username, ip)
        
    def _log_failed_attempt(self, username: str, ip: str):
        """Log failed login attempts"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "brute_force_logs.txt"
        try:
            with open(log_file, "a") as f:
                f.write(f"{datetime.now()} - Failed login attempt for {username} from {ip}\n")
        except Exception as e:
            logger.error("Failed to log attempt", error=str(e))
            
    def authenticate(self, username: str, encrypted_password: str, ip: str) -> Tuple[bool, str]:
        """Authenticate a user and return success status and role/error"""
        # Check IP blocking first
        ip_blocked, ip_time = self.is_ip_blocked(ip)
        if ip_blocked:
            return False, f"IP blocked for {ip_time} seconds"
            
        # Validate username exists
        if username not in self.users:
            self.record_failed_attempt(username, ip)
            return False, "Invalid credentials"
            
        user = self.users[username]
        
        # Check account lockout
        account_locked, lockout_time = self.is_account_locked(username)
        if account_locked:
            return False, f"Account locked for {lockout_time} seconds"
            
        try:
            # Decrypt the password
            decrypted_password = self.crypto_manager.decrypt(encrypted_password)
            
            # Verify password
            if not self._verify_password(user['password'], decrypted_password):
                self.record_failed_attempt(username, ip)
                return False, "Invalid credentials"
                
            # Successful login - reset counters
            user['failed_attempts'] = 0
            user['last_attempt'] = None
            user['locked_until'] = None
            self.save_users()
            
            # Clear IP attempts on successful login
            if ip in self.ip_attempts:
                del self.ip_attempts[ip]
                
            return True, user['role']
            
        except Exception as e:
            logger.error("Authentication error", error=str(e))
            return False, "An error occurred during authentication"
        
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change a user's password"""
        if username not in self.users:
            return False
            
        user = self.users[username]
        
        # Verify old password
        if not self._verify_password(user['password'], old_password):
            return False
            
        # Update to new password
        user['password'] = self._hash_password(new_password)
        self.save_users()
        return True