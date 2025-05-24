import paramiko
import logging
import os
import socket
# Using Fabric for connections might be an option later, but Paramiko is fine for now.
from fabric import Connection 
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class ConnectionBackend:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Store active SSH connections, keyed by a unique connection_id
        self.connections = {}
        self.profiles_file = Path("config/ssh_connections.json")
        self.ensure_profiles_file_exists()
        
    def ensure_profiles_file_exists(self):
        # Make sure the json file for storing connection profiles exists.
        if not self.profiles_file.exists():
            # Create the directory if it doesn't exist either.
            self.profiles_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.profiles_file, 'w') as f:
                json.dump({}, f) # Initialize with an empty JSON object

    def get_saved_connections(self) -> List[Dict]:
        try:
            with open(self.profiles_file, 'r') as f:
                profiles = json.load(f)
            # Convert the profiles dictionary to a list of dictionaries for easier use in UI
            return [{"name": name, **data} for name, data in profiles.items()]
        except Exception as e:
            self.logger.error(f"Failed to load SSH connection profiles: {str(e)}")
            return []

    def get_connection_by_name(self, name: str) -> Optional[Dict]:
        try:
            with open(self.profiles_file, 'r') as f:
                profiles = json.load(f)
            return profiles.get(name) # Return None if name not found, which is fine
        except Exception as e:
            self.logger.error(f"Failed to load SSH connection profile '{name}': {str(e)}")
            return None

    def save_connection_profile(self, profile_data: Dict) -> bool:
        if 'name' not in profile_data or not profile_data['name']:
            self.logger.error("Profile name is required to save.")
            return False
        try:
            profiles = {}
            if self.profiles_file.exists():
                with open(self.profiles_file, 'r') as f:
                    try:
                        profiles = json.load(f)
                    except json.JSONDecodeError: # Handle cases where the file might be corrupted
                        self.logger.warning("ssh_connections.json is corrupted, starting fresh.")
                        profiles = {} # Reset to an empty dict if corrupted
            
            profiles[profile_data['name']] = profile_data
            
            with open(self.profiles_file, 'w') as f:
                json.dump(profiles, f, indent=4) # indent for readability
            self.logger.info(f"SSH Connection profile '{profile_data['name']}' saved.")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save SSH connection profile '{profile_data['name']}': {str(e)}")
            return False

    def delete_connection_profile(self, name: str) -> bool:
        try:
            with open(self.profiles_file, 'r') as f:
                profiles = json.load(f)
            if name in profiles:
                del profiles[name]
                with open(self.profiles_file, 'w') as f:
                    json.dump(profiles, f, indent=4)
                self.logger.info(f"SSH Connection profile '{name}' deleted.")
                return True
            else:
                self.logger.warning(f"SSH Connection profile '{name}' not found for deletion.")
                return False
        except Exception as e:
            self.logger.error(f"Failed to delete SSH connection profile '{name}': {str(e)}")
            return False

    def connect_ssh(self, host, port, username, password=None, private_key_path=None, passphrase=None, timeout=10) -> Tuple[Optional[str], bool, Optional[str]]:
        try:
            ssh = paramiko.SSHClient()
            # Automatically add the server's host key (less secure, but good for a tool like this)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': host,
                'port': port,
                'username': username,
                'timeout': timeout
            }

            if private_key_path:
                # Handle private key authentication
                try:
                    private_key_path_str = str(private_key_path) if private_key_path else None
                    
                    if not private_key_path_str or not os.path.exists(private_key_path_str):
                        self.logger.error(f"Private key file not found: {private_key_path_str}")
                        if password: # Fallback to password if key is bad and password is provided
                            self.logger.info("Attempting password authentication due to key path issue.")
                            connect_kwargs['password'] = password
                        else:
                            return None, False, f"Private key file not found: {private_key_path_str}"
                    else:
                        # Attempt to load the private key, trying various types.
                        # This order is somewhat arbitrary but covers common key types.
                        # Ed25519 is tried first as it's modern and secure.
                        private_key = paramiko.Ed25519Key.from_private_key_file(private_key_path_str, password=passphrase) if passphrase else paramiko.Ed25519Key.from_private_key_file(private_key_path_str)
                        try:
                            private_key = paramiko.RSAKey.from_private_key_file(private_key_path_str, password=passphrase)
                        except paramiko.SSHException:
                            try:
                                private_key = paramiko.DSSKey.from_private_key_file(private_key_path_str, password=passphrase)
                            except paramiko.SSHException:
                                try:
                                    private_key = paramiko.ECDSAKey.from_private_key_file(private_key_path_str, password=passphrase)
                                except paramiko.SSHException:
                                    self.logger.error(f"Failed to load private key {private_key_path_str} with any common type.")
                                    if password: # Fallback to password if key loading fails and password is provided
                                        self.logger.info("Attempting password authentication as key load failed.")
                                        connect_kwargs['password'] = password
                                    else:
                                        return None, False, "Failed to load private key with any common type and no password provided."
                        connect_kwargs['pkey'] = private_key
                        
                except Exception as e:
                    self.logger.error(f"Failed to load private key {private_key_path}: {str(e)}")
                    if password: # Fallback to password if key loading throws an unexpected error
                        self.logger.info(f"Attempting password authentication for {username}@{host} as key failed.")
                        connect_kwargs['password'] = password
                    else:
                        return None, False, f"Failed to load private key and no password fallback: {str(e)}"
            elif password:
                # Use password authentication if no key path is provided
                connect_kwargs['password'] = password
            else:
                # No authentication method provided
                return None, False, "Either password or private key path must be provided."

            ssh.connect(**connect_kwargs)
            # Create a unique ID for this connection to manage it later
            connection_id = f"{username}@{host}:{port}"
            self.connections[connection_id] = ssh
            
            self.logger.info(f"Successfully connected to {connection_id}")
            return connection_id, True, None
            
        except socket.timeout:
            self.logger.error(f"Connection timeout to {host}:{port}")
            return None, False, "Connection timeout. Check network and firewall settings."
            
        except paramiko.AuthenticationException:
            self.logger.error(f"Authentication failed for {username}@{host}")
            return None, False, "Authentication failed. Check credentials or private key."
            
        except paramiko.SSHException as e:
            self.logger.error(f"SSH error connecting to {host}: {str(e)}")
            # Specific check for a common Ed25519 key issue with passphrases or incorrect key types
            if "Incorrect AES key length" in str(e) and passphrase and private_key_path:
                self.logger.error("Potential issue with passphrase for Ed25519 key or key type. Try without passphrase or use RSA/ECDSA.")
                return None, False, "SSH Key Error (AES Key Length). Try RSA/ECDSA or key without passphrase."
            return None, False, f"SSH error: {str(e)}"
            
        except Exception as e: # Catch any other unexpected errors during connection
            self.logger.error(f"Unexpected error connecting to {host}: {str(e)}")
            return None, False, f"Error: {str(e)}"
    
    def execute_command(self, connection_id, command, use_sudo=False, sudo_password=None):
        if connection_id not in self.connections:
            return False, None, "Not connected. Establish connection first."
            
        ssh = self.connections[connection_id]
        try:
            if use_sudo and sudo_password:
                # Construct the sudo command, -S makes sudo read password from stdin
                full_command = f"sudo -S {command}"
                stdin, stdout, stderr = ssh.exec_command(full_command)
                # Send the sudo password
                stdin.write(f"{sudo_password}\n")
                stdin.flush()
            else:
                stdin, stdout, stderr = ssh.exec_command(command)
                
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            
            # Return True if exit status is 0 (success), along with output and error streams
            return exit_status == 0, output, error
            
        except Exception as e:
            self.logger.error(f"Error executing command on {connection_id}: {str(e)}")
            return False, None, str(e)
    
    def disconnect(self, connection_id):
        if connection_id in self.connections:
            try:
                self.connections[connection_id].close()
                del self.connections[connection_id] # Remove from active connections
                self.logger.info(f"Disconnected from {connection_id}")
                return True, None
            except Exception as e:
                self.logger.error(f"Error disconnecting from {connection_id}: {str(e)}")
                return False, str(e)
        else:
            return False, "Not connected" # Or perhaps raise an error?
    
    def transfer_file(self, connection_id, local_path, remote_path):
        if connection_id not in self.connections:
            return False, "Not connected. Establish connection first."
        
        try:
            ssh = self.connections[connection_id]
            sftp = ssh.open_sftp() # Open an SFTP session
            sftp.put(local_path, remote_path) # Upload the file
            sftp.close()
            
            self.logger.info(f"File transferred to {connection_id}:{remote_path}")
            return True, None
        except Exception as e:
            self.logger.error(f"Error transferring file to {connection_id}: {str(e)}")
            return False, str(e)
    
    def __del__(self):
        # Ensure all connections are closed when the object is destroyed.
        # This is a fallback, explicit disconnects are preferred.
        for connection_id in list(self.connections.keys()): # Iterate over a copy of keys
            try:
                self.connections[connection_id].close()
            except: # Ignore errors during cleanup
                pass