import unittest
import sys
import os
from pathlib import Path
import paramiko
from src.utils.crypto import CryptoManager
from src.utils.remote_connection import RemoteConnection

class TestCryptoSSH(unittest.TestCase):
    def setUp(self):
        self.crypto = CryptoManager()
        
    def test_aes_encryption(self):
        """Test basic AES encryption/decryption"""
        test_password = "testpassword123"
        
        # Test encryption
        encrypted = self.crypto.encrypt(test_password)
        self.assertNotEqual(encrypted, test_password)
        
        # Test decryption
        decrypted = self.crypto.decrypt(encrypted)
        self.assertEqual(decrypted, test_password)
        
    def test_ssh_local(self):
        """Test SSH connection to localhost (if SSH server is running)"""
        remote = RemoteConnection()
        
        # Only run this test if SSH server is available
        if not os.system("systemctl is-active --quiet sshd"):
            try:
                # Try to connect to localhost
                success = remote.connect(
                    hostname="localhost",
                    username=os.getenv("USER"),
                    password="your_password"  # Replace with actual test password
                )
                self.assertTrue(success)
                
                # Try a simple command
                stdout, stderr = remote.execute_command("echo 'test'")
                self.assertEqual(stdout.strip(), "test")
                self.assertEqual(stderr, "")
                
            except Exception as e:
                self.fail(f"SSH test failed: {str(e)}")
            finally:
                remote.disconnect()
                
if __name__ == "__main__":
    unittest.main() 