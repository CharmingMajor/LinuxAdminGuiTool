import unittest
import sys
import os
import time

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.backend.auth_backend import AuthBackend

class TestAuthentication(unittest.TestCase):
    """Test cases for the authentication backend"""

    def setUp(self):
        """Set up a new authentication backend for each test"""
        self.auth = AuthBackend()
        
    def test_valid_login(self):
        """Test login with valid credentials"""
        success, role = self.auth.authenticate("junior", "junior123", "127.0.0.1")
        self.assertTrue(success)
        self.assertEqual(role, "junior")
        
        success, role = self.auth.authenticate("senior", "senior123", "127.0.0.1")
        self.assertTrue(success)
        self.assertEqual(role, "senior")
        
    def test_invalid_login(self):
        """Test login with invalid credentials"""
        success, result = self.auth.authenticate("junior", "wrongpass", "127.0.0.1")
        self.assertFalse(success)
        self.assertEqual(result, "invalid_credentials")
        
    def test_nonexistent_user(self):
        """Test login with non-existent user"""
        success, result = self.auth.authenticate("nonexistent", "password", "127.0.0.1")
        self.assertFalse(success)
        self.assertEqual(result, "invalid_credentials")
        
    def test_brute_force_protection(self):
        """Test brute force protection mechanism"""
        # Attempt login 3 times with wrong password
        for _ in range(3):
            self.auth.authenticate("junior", "wrongpass", "192.168.1.1")
            
        # 4th attempt should be locked
        success, result = self.auth.authenticate("junior", "wrongpass", "192.168.1.1")
        self.assertFalse(success)
        self.assertEqual(result, "account_locked")
        
    def test_ip_blocking(self):
        """Test IP-based blocking"""
        # Make 3 failed attempts with different non-existent users
        for i in range(3):
            self.auth.authenticate(f"fake{i}", "wrongpass", "10.0.0.1")
            
        # Next attempt from same IP should be blocked
        success, result = self.auth.authenticate("junior", "junior123", "10.0.0.1")
        self.assertFalse(success)
        self.assertEqual(result, "ip_blocked")
        
    def test_hash_password(self):
        """Test password hashing"""
        hashed = self.auth._hash_password("testpassword")
        self.assertNotEqual(hashed, "testpassword")
        self.assertEqual(hashed, self.auth._hash_password("testpassword"))
        self.assertNotEqual(hashed, self.auth._hash_password("wrongpassword"))
        
    def test_ip_block_timeout(self):
        """Test IP block timeout (simplified for testing)"""
        # This test assumes the block time is modified for testing
        # In real code, you might mock the time or have a configurable timeout
        
        # Set a shorter block time for testing (normally 300 seconds)
        # WARNING: This modifies the class state - normally not good practice for unit tests
        # In a production codebase, this should be configurable or mockable
        original_time = time.time()
        
        # Make 3 failed attempts to block the IP
        for i in range(3):
            self.auth.authenticate(f"fake{i}", "wrongpass", "10.0.0.2")
            
        # Verify IP is blocked
        success, result = self.auth.authenticate("junior", "junior123", "10.0.0.2")
        self.assertFalse(success)
        self.assertEqual(result, "ip_blocked")
        
        # Simulate time passing (> 5 minutes)
        # We'll modify the timestamp of the last attempt directly
        self.auth.failed_ips["10.0.0.2"]["last_attempt"] = original_time - 301
        
        # Now the IP should be unblocked
        success, role = self.auth.authenticate("junior", "junior123", "10.0.0.2")
        self.assertTrue(success)
        self.assertEqual(role, "junior")
        
if __name__ == "__main__":
    unittest.main() 