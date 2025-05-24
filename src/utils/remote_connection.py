import paramiko
from typing import Optional, Dict, List, Tuple
import logging
from pathlib import Path
import socket

class RemoteConnection:
    """Handles remote connections and command execution"""
    
    def __init__(self):
        # Initialize with no active connection
        self.client: Optional[paramiko.SSHClient] = None
        self.hostname: str = ""
        self.username: str = ""
        self.connected: bool = False
        self.last_error: str = ""
        self.password: str = ""  # We store this for sudo commands
        
    def connect(self, hostname: str, username: str, password: str = None, key_path: str = None, port: int = 22, passphrase: str = None) -> bool:
        """
        Establish SSH connection to remote host
        
        Args:
            hostname: Remote host address
            username: SSH username
            password: SSH password (optional if using key)
            key_path: Path to SSH private key (optional if using password)
            port: SSH port number (default: 22)
            passphrase: Passphrase for encrypted SSH key (optional)
        """
        try:
            self.last_error = ""
            
            # Create a new SSH client
            self.client = paramiko.SSHClient()
            # Auto-accept host keys (this is less secure but more user-friendly)
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set up connection parameters
            connect_kwargs = {
                "hostname": hostname,
                "username": username,
                "port": port,
                "timeout": 10,
                "allow_agent": False,
                "look_for_keys": False
            }
            
            # Choose between password and key authentication
            if password:
                connect_kwargs["password"] = password
                # Store password for sudo commands later
                self.password = password
            elif key_path:
                try:
                    # Try to load an RSA key first
                    if passphrase:
                        key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
                    else:
                        key = paramiko.RSAKey.from_private_key_file(key_path)
                    connect_kwargs["pkey"] = key
                except paramiko.ssh_exception.SSHException as key_error:
                    try:
                        # If RSA fails, try Ed25519 key format
                        if passphrase:
                            key = paramiko.Ed25519Key.from_private_key_file(key_path, password=passphrase)
                        else:
                            key = paramiko.Ed25519Key.from_private_key_file(key_path)
                        connect_kwargs["pkey"] = key
                    except paramiko.ssh_exception.SSHException:
                        # If we can't load the key directly, let paramiko try to figure it out
                        connect_kwargs["key_filename"] = key_path
                        if passphrase:
                            connect_kwargs["passphrase"] = passphrase
                except IOError as e:
                    self.last_error = f"Could not read key file: {str(e)}"
                    logging.error(f"Failed to read key file {key_path}: {str(e)}")
                    return False
            
            # Now actually try to connect
            self.client.connect(**connect_kwargs)
            self.hostname = hostname
            self.username = username
            self.connected = True
            
            # Test the connection with a simple command
            try:
                _, stdout, _ = self.client.exec_command('echo "Connection test"')
                stdout.read()
            except Exception as e:
                error_msg = str(e) if str(e) else "Connection test command failed after successful connect."
                self.last_error = f"Connected but command execution failed: {error_msg}"
                logging.error(f"Connection verification failed: {error_msg}")
                self.disconnect()
                return False
                
            return True
            
        except paramiko.ssh_exception.AuthenticationException as e:
            # Authentication failed - wrong username/password/key
            self.last_error = f"Authentication failed: {str(e)}. Please check your username and password/key."
            logging.error(f"Authentication failed for {username}@{hostname}: {str(e)}")
            self.connected = False
            return False
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            # Connection refused or port closed
            self.last_error = f"Could not connect to server: {str(e)}"
            logging.error(f"No valid connections to {hostname}:{port}: {str(e)}")
            self.connected = False
            return False
        except socket.gaierror as e:
            # DNS resolution failed
            self.last_error = f"Could not resolve hostname: {str(e)}"
            logging.error(f"Failed to resolve hostname {hostname}: {str(e)}")
            self.connected = False
            return False
        except socket.timeout as e:
            # Connection timed out
            self.last_error = "Connection timed out. Please check hostname and port."
            logging.error(f"Connection to {hostname}:{port} timed out: {str(e)}")
            self.connected = False
            return False
        except Exception as e:
            # Catch-all for other errors
            self.last_error = f"Connection failed: {str(e)}"
            logging.error(f"Failed to connect to {hostname}: {str(e)}")
            self.connected = False
            return False
    
    def is_really_connected(self) -> bool:
        """Check if the client is initialized and the transport is active."""
        if self.client and self.client.get_transport():
            return self.client.get_transport().is_active()
        return False
    
    def get_last_error(self) -> str:
        """Return the last error message"""
        return self.last_error
    
    def disconnect(self):
        """Close the SSH connection"""
        if self.client:
            self.client.close()
            self.connected = False
            
    def execute_command(self, command: str) -> Tuple[str, str]:
        """
        Execute command on remote host
        
        Returns:
            Tuple of (stdout, stderr)
        """
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
        
        # Special handling for sudo commands to provide the password
        if command.strip().startswith("sudo "):
            # Convert sudo command to use -S option to read password from stdin
            if " -S " not in command:
                command = command.replace("sudo ", "sudo -S ", 1)
            
            # Create a channel for more control over the command
            transport = self.client.get_transport()
            channel = transport.open_session()
            channel.exec_command(command)
            
            # Send password to stdin with newline
            if hasattr(self, 'password') and self.password:
                channel.send(f"{self.password}\n")
            
            # Get initial output
            stdout_data = channel.recv(4096).decode()
            stderr_data = channel.recv_stderr(4096).decode()
            
            # Continue reading until the command is done
            while not channel.exit_status_ready():
                if channel.recv_ready():
                    stdout_data += channel.recv(4096).decode()
                if channel.recv_stderr_ready():
                    stderr_data += channel.recv_stderr(4096).decode()
            
            # Get any remaining data
            while channel.recv_ready():
                stdout_data += channel.recv(4096).decode()
            while channel.recv_stderr_ready():
                stderr_data += channel.recv_stderr(4096).decode()
            
            channel.close()
            return stdout_data, stderr_data
        else:    
            # For non-sudo commands, use the simpler exec_command method
            stdin, stdout, stderr = self.client.exec_command(command)
            return stdout.read().decode(), stderr.read().decode()
    
    def get_system_info(self) -> Dict:
        """Get basic system information from remote host"""
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
            
        info = {}
        
        # Get CPU count
        _, stdout, _ = self.client.exec_command("nproc")
        info["cpu_count"] = int(stdout.read().decode().strip())
        
        # Get memory usage
        _, stdout, _ = self.client.exec_command("free -b")
        mem_lines = stdout.read().decode().split("\n")
        mem_values = mem_lines[1].split()[1:4]
        info["memory"] = {
            "total": int(mem_values[0]),
            "used": int(mem_values[1]),
            "free": int(mem_values[2])
        }
        
        # Get disk usage for root filesystem
        _, stdout, _ = self.client.exec_command("df -B1 /")
        disk_lines = stdout.read().decode().split("\n")
        disk_values = disk_lines[1].split()
        info["disk"] = {
            "total": int(disk_values[1]),
            "used": int(disk_values[2]),
            "free": int(disk_values[3])
        }
        
        return info
    
    # User management functions
    
    def get_users(self) -> List[Dict]:
        """Get list of users from /etc/passwd file"""
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
            
        _, stdout, _ = self.client.exec_command("cat /etc/passwd")
        users = []
        
        for line in stdout:
            if not line.startswith("#"):
                # Parse the passwd file format
                user_info = line.strip().split(":")
                users.append({
                    "username": user_info[0],
                    "uid": user_info[2],
                    "gid": user_info[3],
                    "home": user_info[5],
                    "shell": user_info[6]
                })
                
        return users
    
    def get_groups(self) -> List[Dict]:
        """Get list of groups from /etc/group file"""
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
            
        _, stdout, _ = self.client.exec_command("cat /etc/group")
        groups = []
        
        for line in stdout:
            if not line.startswith("#"):
                # Parse the group file format
                group_info = line.strip().split(":")
                groups.append({
                    "name": group_info[0],
                    "gid": group_info[2],
                    "members": group_info[3].split(",") if group_info[3] else []
                })
                
        return groups
    
    def add_user(self, username: str, password: str = None, groups: List[str] = None) -> bool:
        """Add a new user to the remote system"""
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
            
        try:
            cmd = f"sudo useradd -m {username}"
            if groups:
                cmd += f" -G {','.join(groups)}"
            stdout, stderr = self.execute_command(cmd)
            
            if stderr and "already exists" not in stderr:
                logging.error(f"Failed to create user: {stderr}")
                return False
                
            if password:
                # Use echo to pipe the password into chpasswd, with sudo using -S to read from stdin
                cmd = f"echo '{username}:{password}' | sudo chpasswd"
                stdout, stderr = self.execute_command(cmd)
                
                if stderr:
                    logging.error(f"Failed to set password: {stderr}")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Failed to add user: {str(e)}")
            return False
    
    def delete_user(self, username: str, delete_home: bool = False) -> bool:
        """Delete a user from the remote system"""
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
            
        try:
            cmd = f"sudo userdel {'--remove' if delete_home else ''} {username}"
            stdout, stderr = self.execute_command(cmd)
            
            if stderr:
                logging.error(f"Failed to delete user: {stderr}")
                return False
                
            return True
            
        except Exception as e:
            logging.error(f"Failed to delete user: {str(e)}")
            return False
    
    def modify_user(self, username: str, new_groups: List[str] = None, 
                   new_password: str = None) -> bool:
        """Modify user's groups or password on the remote system"""
        if not self.is_really_connected():
            raise ConnectionError("Not connected to remote host")
        
        try:
            if new_groups is not None:
                cmd = f"sudo usermod -G {','.join(new_groups)} {username}"
                stdout, stderr = self.execute_command(cmd)
                
                if stderr:
                    logging.error(f"Failed to modify user groups: {stderr}")
                    return False
                    
            if new_password:
                # Use echo to pipe the password into chpasswd
                cmd = f"echo '{username}:{new_password}' | sudo chpasswd"
                stdout, stderr = self.execute_command(cmd)
                
                if stderr:
                    logging.error(f"Failed to change password: {stderr}")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Failed to modify user: {str(e)}")
            return False 