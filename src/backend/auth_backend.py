# Updated auth_backend.py
import hashlib
import time
from datetime import datetime

class AuthBackend:
    def __init__(self):
        # Simulated user database with hashed passwords
        self.users = {
            "junior": {
                "password": self._hash_password("junior123"), 
                "role": "junior",
                "failed_attempts": 0,
                "last_attempt": None
            },
            "senior": {
                "password": self._hash_password("senior123"), 
                "role": "senior",
                "failed_attempts": 0,
                "last_attempt": None
            },
        }
        
        # Track IP addresses with failed attempts
        self.failed_ips = {}
        
    def _hash_password(self, password):
        """Hash a password for storing."""
        return hashlib.sha256(password.encode()).hexdigest()
        
    def _check_password(self, hashed_password, user_password):
        """Verify a stored password against one provided by user"""
        return hashed_password == self._hash_password(user_password)
        
    def authenticate(self, username, password, ip):
        # Check if IP is blocked
        if ip in self.failed_ips and self.failed_ips[ip]['attempts'] >= 3:
            if time.time() - self.failed_ips[ip]['last_attempt'] < 300:  # 5 minute block
                return False, "ip_blocked"
            else:
                # Reset if block time has passed
                del self.failed_ips[ip]
                
        # Check if user exists
        if username not in self.users:
            self._log_failed_attempt(ip, username)
            return False, "invalid_credentials"
            
        user = self.users[username]
        
        # Check password
        if not self._check_password(user['password'], password):
            user['failed_attempts'] += 1
            user['last_attempt'] = datetime.now()
            self._log_failed_attempt(ip, username)
            
            if user['failed_attempts'] >= 3:
                return False, "account_locked"
            return False, "invalid_credentials"
            
        # Successful login - reset counters
        user['failed_attempts'] = 0
        user['last_attempt'] = None
        if ip in self.failed_ips:
            del self.failed_ips[ip]
            
        return True, user['role']
        
    def _log_failed_attempt(self, ip, username):
        """Log a failed login attempt"""
        if ip not in self.failed_ips:
            self.failed_ips[ip] = {'attempts': 0, 'last_attempt': time.time()}
            
        self.failed_ips[ip]['attempts'] += 1
        self.failed_ips[ip]['last_attempt'] = time.time()
        
        # Log to brute force logs
        with open("logs/brute_force_logs.txt", "a") as f:
            f.write(f"{datetime.now()} - Failed login attempt for {username} from {ip}\n")