import unittest
import os
from src.utils.remote_connection import RemoteConnection
from unittest.mock import Mock, patch

class TestRemoteConnection(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.remote = RemoteConnection()
        
    @patch('paramiko.SSHClient')
    def test_connection(self, mock_ssh):
        """Test SSH connection"""
        # Mock successful connection
        mock_client = Mock()
        mock_ssh.return_value = mock_client
        
        # Test password authentication
        success = self.remote.connect(
            hostname="test.host",
            username="testuser",
            password="testpass"
        )
        self.assertTrue(success)
        self.assertTrue(self.remote.connected)
        
        # Test key authentication
        with patch('paramiko.RSAKey') as mock_key:
            mock_key_instance = Mock()
            mock_key.from_private_key_file.return_value = mock_key_instance
            
            success = self.remote.connect(
                hostname="test.host",
                username="testuser",
                key_path="~/.ssh/id_rsa"
            )
            self.assertTrue(success)
            self.assertTrue(self.remote.connected)
        
    @patch('paramiko.SSHClient')
    def test_command_execution(self, mock_ssh):
        """Test remote command execution"""
        # Mock SSH client and channel
        mock_client = Mock()
        mock_ssh.return_value = mock_client
        
        # Mock successful command execution
        mock_stdout = Mock()
        mock_stdout.read.return_value = b"command output"
        mock_stderr = Mock()
        mock_stderr.read.return_value = b""
        
        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
        
        # Connect and execute command
        self.remote.connect("test.host", "testuser", "testpass")
        stdout, stderr = self.remote.execute_command("test command")
        
        self.assertEqual(stdout, "command output")
        self.assertEqual(stderr, "")
        
    @patch('paramiko.SSHClient')
    def test_system_info(self, mock_ssh):
        """Test getting system information"""
        # Mock SSH client
        mock_client = Mock()
        mock_ssh.return_value = mock_client
        
        # Mock command outputs
        def mock_exec_command(cmd):
            mock_stdout = Mock()
            mock_stderr = Mock()
            mock_stderr.read.return_value = b""
            
            if cmd == "nproc":
                mock_stdout.read.return_value = b"4\n"
            elif cmd == "free -b":
                mock_stdout.read.return_value = b"""              total        used        free
Mem:    16433577984  8216737792  8216840192"""
            elif cmd == "df -B1 /":
                mock_stdout.read.return_value = b"""Filesystem     1B-blocks      Used  Available
/dev/sda1    250790436864 100316811264 150473625600"""
                
            return None, mock_stdout, mock_stderr
            
        mock_client.exec_command.side_effect = mock_exec_command
        
        # Connect and get system info
        self.remote.connect("test.host", "testuser", "testpass")
        info = self.remote.get_system_info()
        
        self.assertEqual(info["cpu_count"], 4)
        self.assertIn("memory", info)
        self.assertIn("disk", info)
        
    def test_cleanup(self):
        """Test connection cleanup"""
        self.remote.disconnect()
        self.assertFalse(self.remote.connected)
        
if __name__ == "__main__":
    unittest.main() 