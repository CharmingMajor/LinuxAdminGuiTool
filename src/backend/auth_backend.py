import bcrypt
import time
from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Tuple, Dict, Optional
import structlog
from src.utils.crypto import CryptoManager

logger = structlog.get_logger(__name__)


# This is a core component for the project's security model.
class AuthBackend:
    def __init__(self):
        self.users_file = Path("config/users.json")
        self.failed_attempts: Dict[str, Dict] = {}
        self.ip_attempts: Dict[str, Dict] = {}
        self.lockout_duration = 300  
        self.max_attempts = 3
        self.ip_max_attempts = 5
        self.crypto_manager = CryptoManager() 
        self.load_users() 
        
    def load_users(self):
        try:
            if not self.users_file.exists():
                logger.info("users.json not found. Creating an empty one. Please add users.")
                default_users = {}
                self.users_file.parent.mkdir(exist_ok=True) 
                with open(self.users_file, 'w') as f:
                    json.dump(default_users, f, indent=4)
                self.users = default_users
            else:
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
                    if not self.users:
                        logger.info("users.json is empty. Please add users.")
        except json.JSONDecodeError as e:
            # Critical if user data is corrupted.
            logger.error("Failed to parse users.json. File might be corrupted.", error=str(e))
            raise 
        except Exception as e:
            logger.error("Failed to load users", error=str(e))
            raise 
            
    def save_users(self):
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=4) 
        except Exception as e:
            # This is a important error if it happens.
            logger.error("Failed to save users to users.json", error=str(e))
            
    def _hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        
    def _verify_password(self, stored_hash: str, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception: # bcrypt can raise various exceptions for invalid hash formats, etc.
            logger.warning("Error during password verification, likely invalid hash format or other bcrypt issue.")
            return False
            
    # Checks if a user account is currently under a lockout.
    def is_account_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        user = self.users.get(username)
        if not user:
            return False, None # Non-existent users can't be locked.
            
        locked_until = user.get('locked_until')
        if locked_until:
            now = datetime.now().timestamp()
            if now < locked_until:
                remaining_time = int(locked_until - now)
                return True, remaining_time # Account is indeed locked.
            else:
                # Lockout period has expired. Time to auto-unlock.
                logger.info(f"Account for {username} automatically unlocked.")
                user['locked_until'] = None
                user['failed_attempts'] = 0
                self.save_users() # Important to persist this change.
                
        return False, None # Account is not locked.
        
    # Checks if an IP address is currently blocked.
    def is_ip_blocked(self, ip: str) -> Tuple[bool, Optional[int]]:
        # This is an in-memory block and will reset on app restart.
        # For a production system, a more persistent distributed cache (e.g., Redis) would be better.
        if ip in self.ip_attempts:
            attempts_info = self.ip_attempts[ip]
            
            if attempts_info['attempts'] >= self.ip_max_attempts:
                time_since_last_attempt = time.time() - attempts_info['timestamp']
                if time_since_last_attempt < self.lockout_duration:
                    remaining_time = int(self.lockout_duration - time_since_last_attempt)
                    return True, remaining_time # IP is blocked.
                else:
                    
                    logger.info(f"IP {ip} automatically unblocked.")
                    del self.ip_attempts[ip]
                    
        return False, None # IP is not blocked.
        
    # Records a failed login attempt for both user and IP.
    def record_failed_attempt(self, username: str, ip: str):
        # Track failed attempts against the specific user account.
        if username in self.users:
            user = self.users[username]
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            user['last_attempt'] = datetime.now().timestamp() 
            
            if user['failed_attempts'] >= self.max_attempts:
                logger.warning(f"Account for user {username} locked due to too many failed attempts.")
                user['locked_until'] = (datetime.now() + timedelta(seconds=self.lockout_duration)).timestamp()
            self.save_users() 
            
        # Track failed attempts against the source IP.
        if ip not in self.ip_attempts:
            self.ip_attempts[ip] = {'attempts': 1, 'timestamp': time.time()}
        else:
            self.ip_attempts[ip]['attempts'] += 1
            self.ip_attempts[ip]['timestamp'] = time.time() # Update timestamp for IP's last attempt.
            if self.ip_attempts[ip]['attempts'] >= self.ip_max_attempts:
                 logger.warning(f"IP address {ip} temporarily blocked due to too many failed attempts.")
            
        self._log_failed_attempt(username, ip) # Also log to a dedicated audit file.
        
    
    def _log_failed_attempt(self, username: str, ip: str):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True) # Ensure log directory exists.
        
        log_file = log_dir / "brute_force_logs.txt" # Simple text log for now.
        try:
            
            with open(log_file, "a") as f:
                f.write(f"{datetime.now()} - Failed login attempt for user '{username}' from IP: {ip}\n")
        except Exception as e:
            logger.error("Failed to write to brute_force_logs.txt", error=str(e))
            
    # Main authentication logic.
    # Checks IP blocks, user existence, account locks, and passwords.
    def authenticate(self, username: str, password: str, ip: str) -> Tuple[bool, str]:
        # check if the source IP is blocked. This is a quick rejection.
        ip_blocked, ip_block_time = self.is_ip_blocked(ip)
        if ip_blocked:
            logger.warning(f"Login attempt from blocked IP: {ip} for user: {username}")
            return False, f"IP blocked. Try again in {ip_block_time} seconds."
            
        # check if the user actually exists.
        if username not in self.users:
            logger.warning(f"Login attempt for non-existent user: {username} from IP: {ip}")
            # Important to record this attempt for IP-based blocking, even if user is unknown.
            self.record_failed_attempt(username, ip)
            # Generic message to prevent user enumeration. A common security practice.
            return False, "Invalid credentials"
            
        user = self.users[username]
        
        # check if the specific user account is locked.
        account_locked, acc_lock_time = self.is_account_locked(username)
        if account_locked:
            logger.warning(f"Login attempt for locked account: {username} from IP: {ip}")
            return False, f"Account locked. Try again in {acc_lock_time} seconds."
            
        # verify the password.
        try:
            if not self._verify_password(user['password'], password):
                logger.warning(f"Invalid password for user: {username} from IP: {ip}")
                self.record_failed_attempt(username, ip)
                return False, "Invalid credentials" 
                
            
            logger.info(f"User {username} authenticated successfully from IP: {ip}.")
            
            user['failed_attempts'] = 0
            user['last_attempt'] = None # Clear last attempt timestamp.
            user['last_attempt'] = None
            user['locked_until'] = None
            self.save_users()
            
            if ip in self.ip_attempts:
                logger.info(f"Clearing IP {ip} from failed attempts tracking after successful login.")
                del self.ip_attempts[ip]
                
            return True, user['role']
            
        except Exception as e:
            logger.error("An unexpected error occurred during authentication process", error=str(e), username=username)
            return False, "An error occurred during authentication. Please try again."
        
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        if username not in self.users:
            logger.warning(f"Attempt to change password for non-existent user: {username}")
            return False
            
        user = self.users[username]
        
        if not self._verify_password(user['password'], old_password):
            logger.warning(f"Failed password change attempt for user {username} due to incorrect old password.")
            return False
            
        user['password'] = self._hash_password(new_password)
        self.save_users()
        logger.info(f"Password changed successfully for user {username}.")
        return True