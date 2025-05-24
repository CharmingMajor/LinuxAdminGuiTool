import bcrypt
import time
from datetime import datetime, timedelta
import json
import os
import logging # Standard logging, though structlog is used primarily.
from pathlib import Path
from typing import Tuple, Dict, Optional
import structlog # Using structlog for more structured logging, good for parsability.
from src.utils.crypto import CryptoManager

logger = structlog.get_logger(__name__)

class AuthBackend:
    def __init__(self):
        self.users_file = Path("config/users.json")
        # In-memory tracking of failed login attempts to implement lockouts.
        # This will reset if the application restarts - for persistence, a DB or other store would be needed.
        self.failed_attempts: Dict[str, Dict] = {} # Stores {username: {'attempts': count, 'timestamp': last_attempt_ts}}
        self.ip_attempts: Dict[str, Dict] = {} # Stores {ip_address: {'attempts': count, 'timestamp': last_attempt_ts}}
        self.lockout_duration = 300  # Lockout for 5 minutes (300 seconds)
        self.max_attempts = 3 # Max failed login attempts for a user before their account is locked
        self.ip_max_attempts = 5 # Max failed login attempts from an IP before it's temporarily blocked
        self.crypto_manager = CryptoManager() # For password hashing, though bcrypt is used directly here.
        self.load_users()
        
    def load_users(self):
        try:
            if not self.users_file.exists():
                logger.info("users.json not found. Creating an empty one. Please add users.")
                default_users = {} # Start with no users if the file doesn't exist.
                self.users_file.parent.mkdir(exist_ok=True) # Ensure parent config directory exists
                with open(self.users_file, 'w') as f:
                    json.dump(default_users, f, indent=4)
                self.users = default_users
            else:
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
                    if not self.users: # Check if the file was empty, which is valid JSON but means no users.
                        logger.info("users.json is empty. Please add users.")
        except json.JSONDecodeError as e:
            logger.error("Failed to parse users.json. File might be corrupted.", error=str(e))
            # If users file is corrupt, we should probably not proceed or start with an empty set.
            # For now, re-raising to make it a critical failure.
            raise
        except Exception as e:
            logger.error("Failed to load users", error=str(e))
            raise # Re-raise other exceptions to be handled by a global handler or crash visibly.
            
    def save_users(self):
        # Save the current state of users (including any new users or changed passwords) to the JSON file.
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=4) # Use indent for human-readable JSON.
        except Exception as e:
            logger.error("Failed to save users to users.json", error=str(e))
            # This is a critical error if users can't be saved, might lead to data loss on restart.
            
    def _hash_password(self, password: str) -> str:
        # Hash a given password using bcrypt. Bcrypt is a good choice as it's slow and includes salt.
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8') # Ensure consistent encoding
        
    def _verify_password(self, stored_hash: str, password: str) -> bool:
        # Verify a provided password against a stored bcrypt hash.
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception: # bcrypt can raise various exceptions for invalid hash formats, etc.
            logger.warning("Error during password verification, likely invalid hash format or other bcrypt issue.")
            return False
            
    def is_account_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        # Check if a user's account is currently locked due to too many failed attempts.
        user = self.users.get(username)
        if not user: # If user doesn't exist, they can't be locked.
            return False, None
            
        locked_until = user.get('locked_until') # Timestamp until which the account is locked.
        if locked_until:
            now = datetime.now().timestamp()
            if now < locked_until:
                remaining_time = int(locked_until - now)
                return True, remaining_time # Account is locked, return remaining lock time.
            else:
                # Lockout has expired. Reset lockout status and failed attempts count.
                logger.info(f"Account for {username} automatically unlocked.")
                user['locked_until'] = None
                user['failed_attempts'] = 0
                self.save_users() # Persist the unlock.
                
        return False, None # Account is not locked.
        
    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[int]]:
        # Check if an IP address is currently blocked due to too many failed attempts from that IP.
        # This is an in-memory block and will reset on app restart.
        if ip in self.ip_attempts:
            attempts_info = self.ip_attempts[ip]
            
            if attempts_info['attempts'] >= self.ip_max_attempts:
                time_since_last_attempt = time.time() - attempts_info['timestamp']
                if time_since_last_attempt < self.lockout_duration:
                    remaining_time = int(self.lockout_duration - time_since_last_attempt)
                    return True, remaining_time # IP is blocked, return remaining block time.
                else:
                    # IP block has expired. Remove the IP from tracking to unblock.
                    logger.info(f"IP {ip} automatically unblocked.")
                    del self.ip_attempts[ip]
                    
        return False, None # IP is not blocked.
        
    def record_failed_attempt(self, username: str, ip: str):
        # Record a failed login attempt for both the username (if it exists) and the source IP.
        
        # User-specific tracking
        if username in self.users:
            user = self.users[username]
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            user['last_attempt'] = datetime.now().timestamp() # Record time of last attempt for this user.
            
            if user['failed_attempts'] >= self.max_attempts:
                logger.warning(f"Account for user {username} locked due to too many failed attempts.")
                user['locked_until'] = (datetime.now() + timedelta(seconds=self.lockout_duration)).timestamp()
                # Resetting failed_attempts count upon locking might be an option, or keep it to show total.
                # For now, it stays, will be reset if lock expires or successful login.
            self.save_users()
            
        # IP-specific tracking (always track IP, even for non-existent users)
        # This helps mitigate username enumeration and brute-force against common usernames.
        if ip not in self.ip_attempts:
            self.ip_attempts[ip] = {'attempts': 1, 'timestamp': time.time()}
        else:
            self.ip_attempts[ip]['attempts'] += 1
            self.ip_attempts[ip]['timestamp'] = time.time() # Update timestamp for IP's last attempt.
            if self.ip_attempts[ip]['attempts'] >= self.ip_max_attempts:
                 logger.warning(f"IP address {ip} temporarily blocked due to too many failed attempts.")
            
        self._log_failed_attempt(username, ip) # Log to a separate brute-force attempt log file.
        
    def _log_failed_attempt(self, username: str, ip: str):
        # Logs failed attempts to a dedicated file for security monitoring.
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "brute_force_logs.txt"
        try:
            # Append mode to keep a running log.
            with open(log_file, "a") as f:
                f.write(f"{datetime.now()} - Failed login attempt for user '{username}' from IP: {ip}\n")
        except Exception as e:
            logger.error("Failed to write to brute_force_logs.txt", error=str(e))
            
    def authenticate(self, username: str, password: str, ip: str) -> Tuple[bool, str]:
        # Core authentication logic.
        
        # First, check if the IP is blocked.
        ip_blocked, ip_block_time = self.is_ip_blocked(ip)
        if ip_blocked:
            logger.warning(f"Login attempt from blocked IP: {ip} for user: {username}")
            return False, f"IP blocked. Try again in {ip_block_time} seconds."
            
        # Then, check if the user exists.
        if username not in self.users:
            logger.warning(f"Login attempt for non-existent user: {username} from IP: {ip}")
            self.record_failed_attempt(username, ip) # Still record attempt to trigger IP blocking if needed.
            return False, "Invalid credentials" # Generic message to avoid user enumeration.
            
        user = self.users[username]
        
        # Next, check if the account itself is locked.
        account_locked, acc_lock_time = self.is_account_locked(username)
        if account_locked:
            logger.warning(f"Login attempt for locked account: {username} from IP: {ip}")
            return False, f"Account locked. Try again in {acc_lock_time} seconds."
            
        # Finally, verify the password.
        try:
            if not self._verify_password(user['password'], password):
                logger.warning(f"Invalid password for user: {username} from IP: {ip}")
                self.record_failed_attempt(username, ip)
                return False, "Invalid credentials" # Generic message.
                
            # Authentication successful!
            logger.info(f"User {username} authenticated successfully from IP: {ip}.")
            # Reset failed attempts for the user upon successful login.
            user['failed_attempts'] = 0
            user['last_attempt'] = None # Clear last attempt timestamp.
            user['locked_until'] = None # Ensure account is not locked.
            self.save_users() # Save these changes.
            
            # If the IP was being tracked for failed attempts, clear it now that a login was successful from it.
            if ip in self.ip_attempts:
                logger.info(f"Clearing IP {ip} from failed attempts tracking after successful login.")
                del self.ip_attempts[ip]
                
            return True, user['role'] # Return True and the user's role.
            
        except Exception as e: # Catch-all for any unexpected errors during authentication.
            logger.error("An unexpected error occurred during authentication process", error=str(e), username=username)
            return False, "An error occurred during authentication. Please try again."
        
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        # Allows a user to change their password after verifying the old one.
        if username not in self.users:
            logger.warning(f"Attempt to change password for non-existent user: {username}")
            return False # User must exist to change password.
            
        user = self.users[username]
        
        # Verify the old password first.
        if not self._verify_password(user['password'], old_password):
            logger.warning(f"Failed password change attempt for user {username} due to incorrect old password.")
            return False # Incorrect old password.
            
        # Hash the new password and save it.
        user['password'] = self._hash_password(new_password)
        self.save_users()
        logger.info(f"Password changed successfully for user {username}.")
        return True