import unittest
import os
import json
import time
from pathlib import Path
from src.backend.auth_backend import AuthBackend
from src.utils.crypto import CryptoManager
from unittest.mock import patch, mock_open, Mock

class TestAuthentication(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        # Create mock users data
        self.mock_users = {
            "junior": {
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY.5AQGHcyL4eNW",  # junior123
                "role": "junior",
                "failed_attempts": 0,
                "last_attempt": None,
                "locked_until": None
            },
            "senior": {
                "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY.5AQGHcyL4eNW",  # senior123
                "role": "senior",
                "failed_attempts": 0,
                "last_attempt": None,
                "locked_until": None
            }
        }
        
        # Mock the file operations
        patcher = patch('builtins.open', mock_open(read_data=json.dumps(self.mock_users)))
        patcher.start()
        self.addCleanup(patcher.stop)
        
        # Mock bcrypt operations
        bcrypt_patcher = patch('bcrypt.checkpw')
        self.mock_checkpw = bcrypt_patcher.start()
        self.addCleanup(bcrypt_patcher.stop)
        
        self.auth = AuthBackend()
        self.crypto = CryptoManager()
        
    @patch('bcrypt.hashpw')
    def test_password_hash(self, mock_hashpw):
        """Test password hashing"""
        # Mock hashpw to return a predictable hash
        mock_hashpw.return_value = b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY.5AQGHcyL4eNW"
        
        # Test correct password
        password = "test123"
        hashed = self.auth._hash_password(password)
        
        # Mock successful password check
        self.mock_checkpw.return_value = True
        self.assertTrue(self.auth._verify_password(hashed, password))
        
        # Mock failed password check
        self.mock_checkpw.return_value = False
        self.assertFalse(self.auth._verify_password(hashed, "wrongpass"))
        
    @patch('src.backend.auth_backend.AuthBackend.save_users')
    def test_login_success(self, mock_save):
        """Test successful login"""
        # Mock successful password verification
        self.mock_checkpw.return_value = True
        
        username = "junior"
        password = "junior123"
        # Encrypt password as it would be in real login
        encrypted_pass = self.crypto.encrypt(password)
        success, role = self.auth.authenticate(username, encrypted_pass, "127.0.0.1")
        self.assertTrue(success)
        self.assertEqual(role, "junior")
        
    @patch('src.backend.auth_backend.AuthBackend.save_users')
    def test_login_failure(self, mock_save):
        """Test failed login"""
        # Mock failed password verification
        self.mock_checkpw.return_value = False
        
        username = "junior"
        password = "wrongpass"
        encrypted_pass = self.crypto.encrypt(password)
        success, _ = self.auth.authenticate(username, encrypted_pass, "127.0.0.1")
        self.assertFalse(success)
        
    @patch('src.backend.auth_backend.AuthBackend.save_users')
    def test_brute_force_protection(self, mock_save):
        """Test brute force protection"""
        # Mock failed password verification
        self.mock_checkpw.return_value = False
        
        username = "junior"
        password = "wrongpass"
        encrypted_pass = self.crypto.encrypt(password)
        
        # Try multiple failed logins
        for _ in range(3):
            self.auth.authenticate(username, encrypted_pass, "127.0.0.1")
            
        # Check if account is locked
        is_locked, _ = self.auth.is_account_locked(username)
        self.assertTrue(is_locked)
        
    @patch('src.backend.auth_backend.AuthBackend.save_users')
    def test_ip_blocking(self, mock_save):
        """Test IP-based blocking"""
        # Mock failed password verification
        self.mock_checkpw.return_value = False
        
        test_ip = "192.168.1.1"
        username = "nonexistent"
        password = "wrongpass"
        encrypted_pass = self.crypto.encrypt(password)
        
        # Try multiple failed logins from same IP
        for _ in range(5):
            self.auth.authenticate(username, encrypted_pass, test_ip)
            
        # Check if IP is blocked
        is_blocked, _ = self.auth.is_ip_blocked(test_ip)
        self.assertTrue(is_blocked)
        
        # Try login with correct credentials from blocked IP
        success, message = self.auth.authenticate("junior", self.crypto.encrypt("junior123"), test_ip)
        self.assertFalse(success)
        self.assertTrue("blocked" in message.lower())
        
    @patch('src.backend.auth_backend.AuthBackend.save_users')
    @patch('time.time')
    def test_ip_block_timeout(self, mock_time, mock_save):
        """Test IP block timeout"""
        # Mock failed password verification
        self.mock_checkpw.return_value = False
        
        # Set initial time
        start_time = 1000000
        mock_time.return_value = start_time
        
        test_ip = "10.0.0.2"
        # Make failed attempts to block the IP
        for i in range(5):
            self.auth.authenticate(f"fake{i}", self.crypto.encrypt("wrongpass"), test_ip)
            
        # Verify IP is blocked
        success, message = self.auth.authenticate("junior", self.crypto.encrypt("junior123"), test_ip)
        self.assertFalse(success)
        self.assertTrue("blocked" in message.lower())
        
        # Move time forward past the block duration
        mock_time.return_value = start_time + self.auth.lockout_duration + 1
        
        # Mock successful password verification for final test
        self.mock_checkpw.return_value = True
        
        # Try again after timeout
        success, role = self.auth.authenticate("junior", self.crypto.encrypt("junior123"), test_ip)
        self.assertTrue(success)
        self.assertEqual(role, "junior")
        
if __name__ == "__main__":
    unittest.main() 