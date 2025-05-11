import paramiko
from typing import Optional, Dict, List, Tuple
import logging
from pathlib import Path
import socket

class RemoteConnection:
    """Handles remote connections and command execution"""
    
    def __init__(self):
        self.client: Optional[paramiko.SSHClient] = None
        self.hostname: str = ""
        self.username: str = ""
        self.connected: bool = False
        self.last_error: str = ""
        # self.port = 22  # moved to connect() param
        
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
            # Reset last error
            self.last_error = ""
            
            # Initialize new client
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set up connection parameters
            connect_kwargs = {
                "hostname": hostname,
                "username": username,
                "port": port,
                "timeout": 10,  # might need to be configurable later
                "allow_agent": False,  # Disable SSH agent to avoid conflicts
                "look_for_keys": False  # Don't look for keys in default locations
            }
            
            # Set up authentication - explicit about which method we're using
            if password:
                connect_kwargs["password"] = password
            elif key_path:
                try:
                    if passphrase:
                        key = paramiko.RSAKey.from_private_key_file(key_path, password=passphrase)
                    else:
                        key = paramiko.RSAKey.from_private_key_file(key_path)
                    connect_kwargs["pkey"] = key
                except paramiko.ssh_exception.SSHException as key_error:
                    # Try other key types if RSA fails
                    try:
                        if passphrase:
                            key = paramiko.Ed25519Key.from_private_key_file(key_path, password=passphrase)
                        else:
                            key = paramiko.Ed25519Key.from_private_key_file(key_path)
                        connect_kwargs["pkey"] = key
                    except paramiko.ssh_exception.SSHException:
                        # As a last resort, let Paramiko figure out the key type
                        connect_kwargs["key_filename"] = key_path
                        if passphrase:
                            connect_kwargs["passphrase"] = passphrase
                except IOError as e:
                    self.last_error = f"Could not read key file: {str(e)}"
                    logging.error(f"Failed to read key file {key_path}: {str(e)}")
                    return False
            
            # Try to connect
            self.client.connect(**connect_kwargs)
            self.hostname = hostname
            self.username = username
            self.connected = True
            
            # Verify connection by running a simple command
            try:
                _, stdout, _ = self.client.exec_command('echo "Connection test"')
                stdout.read()
            except Exception as e:
                self.last_error = f"Connected but command execution failed: {str(e)}"
                logging.error(f"Connection verification failed: {str(e)}")
                self.disconnect()
                return False
                
            return True
            
        except paramiko.ssh_exception.AuthenticationException as e:
            self.last_error = f"Authentication failed: {str(e)}. Please check your username and password/key."
            logging.error(f"Authentication failed for {username}@{hostname}: {str(e)}")
            self.connected = False
            return False
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            self.last_error = f"Could not connect to server: {str(e)}"
            logging.error(f"No valid connections to {hostname}:{port}: {str(e)}")
            self.connected = False
            return False
        except socket.gaierror as e:
            self.last_error = f"Could not resolve hostname: {str(e)}"
            logging.error(f"Failed to resolve hostname {hostname}: {str(e)}")
            self.connected = False
            return False
        except socket.timeout as e:
            self.last_error = "Connection timed out. Please check hostname and port."
            logging.error(f"Connection to {hostname}:{port} timed out: {str(e)}")
            self.connected = False
            return False
        except Exception as e:
            self.last_error = f"Connection failed: {str(e)}"
            logging.error(f"Failed to connect to {hostname}: {str(e)}")
            self.connected = False
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
        if not self.connected or not self.client:
            raise ConnectionError("Not connected to remote host")
            
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode(), stderr.read().decode()
    
    def get_system_info(self) -> Dict:
        """Get system information from remote host"""
        if not self.connected:
            raise ConnectionError("Not connected to remote host")
            
        info = {}
        
        # CPU Info
        _, stdout, _ = self.client.exec_command("nproc")
        info["cpu_count"] = int(stdout.read().decode().strip())
        
        # Memory Info - this is a mess but works on most distros
        _, stdout, _ = self.client.exec_command("free -b")
        mem_lines = stdout.read().decode().split("\n")
        mem_values = mem_lines[1].split()[1:4]
        info["memory"] = {
            "total": int(mem_values[0]),
            "used": int(mem_values[1]),
            "free": int(mem_values[2])
        }
        
        # Disk Info
        _, stdout, _ = self.client.exec_command("df -B1 /")
        disk_lines = stdout.read().decode().split("\n")
        disk_values = disk_lines[1].split()
        info["disk"] = {
            "total": int(disk_values[1]),
            "used": int(disk_values[2]),
            "free": int(disk_values[3])
        }
        
        return info
    
    # Super basic user management - want to add more features later
    
    def get_users(self) -> List[Dict]:
        """Get list of users from remote host"""
        if not self.connected:
            raise ConnectionError("Not connected to remote host")
            
        _, stdout, _ = self.client.exec_command("cat /etc/passwd")
        users = []
        
        for line in stdout:
            if not line.startswith("#"):
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
        """Get list of groups from remote host"""
        if not self.connected:
            raise ConnectionError("Not connected to remote host")
            
        _, stdout, _ = self.client.exec_command("cat /etc/group")
        groups = []
        
        for line in stdout:
            if not line.startswith("#"):
                group_info = line.strip().split(":")
                groups.append({
                    "name": group_info[0],
                    "gid": group_info[2],
                    "members": group_info[3].split(",") if group_info[3] else []
                })
                
        return groups
    
    def add_user(self, username: str, password: str = None, groups: List[str] = None) -> bool:
        """Add a new user to the remote system"""
        if not self.connected:
            raise ConnectionError("Not connected to remote host")
            
        try:
            # Create user
            cmd = f"sudo useradd -m {username}"
            if groups:
                cmd += f" -G {','.join(groups)}"
            _, stderr = self.execute_command(cmd)
            
            if stderr:
                logging.error(f"Failed to create user: {stderr}")
                return False
                
            # Set password if provided
            if password:
                cmd = f"echo '{username}:{password}' | sudo chpasswd"
                _, stderr = self.execute_command(cmd)
                
                if stderr:
                    logging.error(f"Failed to set password: {stderr}")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Failed to add user: {str(e)}")
            return False
    
    def delete_user(self, username: str, delete_home: bool = False) -> bool:
        """Delete a user from the remote system"""
        if not self.connected:
            raise ConnectionError("Not connected to remote host")
            
        try:
            cmd = f"sudo userdel {'--remove' if delete_home else ''} {username}"
            _, stderr = self.execute_command(cmd)
            
            if stderr:
                logging.error(f"Failed to delete user: {stderr}")
                return False
                
            return True
            
        except Exception as e:
            logging.error(f"Failed to delete user: {str(e)}")
            return False
    
    # Originally tried to keep track of previous group membership
    # but too complicated for v1
    def modify_user(self, username: str, new_groups: List[str] = None, 
                   new_password: str = None) -> bool:
        """Modify an existing user"""
        if not self.connected:
            raise ConnectionError("Not connected to remote host")
            
        try:
            if new_groups is not None:
                cmd = f"sudo usermod -G {','.join(new_groups)} {username}"
                _, stderr = self.execute_command(cmd)
                
                if stderr:
                    logging.error(f"Failed to modify user groups: {stderr}")
                    return False
                    
            if new_password:
                cmd = f"echo '{username}:{new_password}' | sudo chpasswd"
                _, stderr = self.execute_command(cmd)
                
                if stderr:
                    logging.error(f"Failed to change password: {stderr}")
                    return False
                    
            return True
            
        except Exception as e:
            logging.error(f"Failed to modify user: {str(e)}")
            return False 