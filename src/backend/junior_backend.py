from src.utils.remote_connection import RemoteConnection
import logging
import re
from datetime import datetime
import os
from typing import Dict, List, Tuple, Optional
from src.backend.database import DatabaseManager

# Only allow juniors to manage these groups 
JUNIOR_MANAGEABLE_GROUPS = ["users", "developers", "editors", "trainees", "guest"]
JUNIOR_NON_RESETTABLE_USERS = ["root", "admin", "senior"]

class JuniorBackend:
    """Backend implementation for Junior Administrators with limited privileges
    
    Restricted system admin functions for junior staff. Enforces security
    boundaries by preventing juniors from:
    - Touching system-critical files
    - Creating admin users or modifying privileged accounts
    - Viewing sensitive logs
    - Messing with core network config
    
    Basically keeps juniors to basic user management, monitoring,
    and reporting tasks. Anything risky requires senior approval.
    """
    
    def __init__(self, remote: RemoteConnection, db_manager: Optional[DatabaseManager] = None, logger: Optional[logging.Logger] = None, current_user: str = "junior_user"):
        """Initialize the Junior Admin backend
        
        Args:
            remote: SSH connection to the remote system
            db_manager: Database manager for storing logs and reports
            logger: Logger instance for recording actions
            current_user: Username of the current junior admin
        """
        self.remote = remote
        self.db_manager = db_manager if db_manager else DatabaseManager() 
        self.logger = logger if logger else logging.getLogger(__name__)
        self.current_user = current_user
        self.default_shell = "/bin/bash"
        
        # Commands juniors can run 
        self.allowed_commands = [
            "top", "ls", "df -h", "free -m",
            "cat /etc/passwd", "cat /etc/group", 
            "ls -l /home", "who", "whoami", "ps aux", "hostname",
            "cat /etc/os-release", "uname -r", "uptime -p",
            "ip addr", "netstat -tuln",
            "cat /var/log/syslog", "cat /var/log/messages", "cat /var/log/auth.log"
        ]
    
    def execute_command(self, command):
        """Execute an allowed command and return the result
        
        Only commands in the allowed_commands list can be executed.
        This is a security measure to prevent junior admins from
        executing arbitrary commands.
        
        Args:
            command: The command to execute
            
        Returns:
            Tuple of (output, error)
        """
        # Check if command is in the allowed list
        if not any(command.startswith(allowed) for allowed in self.allowed_commands):
            self.logger.warning(f"Junior admin attempted unauthorized command: {command}")
            return None, "Command not permitted for junior admin"
        
        try:
            # For testing/demo purposes, simulate some common commands
            if command == "cat /etc/passwd":
                return self._simulate_passwd_file(), None
            elif command == "cat /etc/group":
                return self._simulate_group_file(), None
            elif command == "ls -l /home":
                return self._simulate_home_directory(), None
            elif command == "who" or command == "whoami":
                return "admin", None
            elif command == "ps aux":
                return self._simulate_process_list(), None
            else:
                return f"Simulated output for: {command}", None
        except Exception as e:
            self.logger.error(f"Error executing command: {str(e)}")
            return None, str(e)
    
    def list_users(self) -> Tuple[List[Dict[str, str]], Optional[str]]:
        """List system users by parsing /etc/passwd from the remote system.
        
        Junior admins can see regular users but sensitive system users
        may be filtered out.
        
        Returns:
            A tuple containing (list of user dictionaries, error message if any)
        """
        if not self.remote or not self.remote.connected:
            return [], "Remote connection not available."
        try:
            users = []
            output, error_msg = self.remote.execute_command("cat /etc/passwd")
            if error_msg:
                self.logger.error(f"Failed to cat /etc/passwd: {error_msg}")
                return [], f"Failed to retrieve user list: {error_msg}"
            
            for line in output.splitlines():
                if line.strip() and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 7:
                        try:
                            uid = int(parts[2])
                            if uid < 1000 and uid !=0: 
                                if parts[6] in ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false"]:
                                    continue
                        except ValueError:
                            pass 

                        users.append({
                            'username': parts[0],
                            'uid': parts[2],
                            'gid': parts[3],
                            'comment': parts[4], 
                            'home': parts[5],
                            'shell': parts[6]
                        })
            return users, None
        except Exception as e:
            self.logger.error(f"Error listing users for Junior Admin: {str(e)}")
            return [], f"An unexpected error occurred while listing users: {str(e)}"
    
    def list_groups(self) -> Tuple[List[Dict[str, str]], Optional[str]]:
        """Lists system groups by parsing /etc/group from the remote system.
        
        Junior admins can see most groups, but can only manage a restricted subset
        defined in JUNIOR_MANAGEABLE_GROUPS.
        
        Returns:
            A tuple containing (list of group dictionaries, error message if any)
        """
        if not self.remote or not self.remote.connected:
            return [], "Remote connection not available."
        try:
            groups = []
            output, error_msg = self.remote.execute_command("cat /etc/group")
            if error_msg:
                self.logger.error(f"Failed to cat /etc/group: {error_msg}")
                return [], f"Failed to retrieve group list: {error_msg}"

            for line in output.splitlines():
                if line.strip() and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 4:
                        groups.append({
                            'name': parts[0],
                            'gid': parts[2],
                            'members': parts[3] 
                        })
            return groups, None
        except Exception as e:
            self.logger.error(f"Error listing groups for Junior Admin: {str(e)}")
            return [], f"An unexpected error occurred: {str(e)}"
    
    def get_file_permissions(self, path):
        """View file permissions in read-only mode
        
        Junior admins can only view permissions, not modify them for
        system files.
        
        Args:
            path: File or directory path to check
            
        Returns:
            Tuple of (output, error)
        """
        try:
            return f"Simulated file permissions for {path}", None
        except Exception as e:
            self.logger.error(f"Error getting file permissions: {str(e)}")
            return None, str(e)
    
    def set_file_permissions(self, path: str, permissions: str) -> Tuple[bool, str]:
        """Set file permissions for non-system files only
        
        Junior admins can only modify permissions for files in their home
        directory, not system files. This is a security measure to prevent
        junior admins from modifying critical system files.
        
        Args:
            path: File path to modify
            permissions: Octal permissions string (e.g. "755")
            
        Returns:
            Tuple of (success, message)
        """
        if not self.remote:
            return False, "Cannot set permissions without a remote connection."

        if not self.current_user:
            self.logger.error("Current user not set, cannot determine home directory for permission check.")
            return False, "Current user not set, cannot determine home directory."
        

        user_home_dir = f"/home/{self.current_user}"

  
        is_absolute_check_success, abs_path_output, abs_path_error = self.remote.execute_command(f"realpath -m {path}")
        if not is_absolute_check_success:
            if not path.startswith("/"):
                resolved_path = os.path.join(user_home_dir, path)
            else: 
                self.logger.warning(f"Could not resolve path {path} with realpath: {abs_path_error}")
                resolved_path = path 
        else:
            resolved_path = abs_path_output.strip()

        # Security check: Ensure path is within user's home directory
        if not resolved_path.startswith(user_home_dir):
            self.logger.warning(
                f"User {self.current_user} attempted to change permissions for non-home directory: {resolved_path} (original: {path})"
            )
            return False, "Permission denied: Can only change permissions for files in your home directory."

        # Validate permissions format
        if not re.match(r"^[0-7]{3,4}$", permissions):
            return False, "Invalid permissions format. Use octal (e.g., 755)."

        try:
            # Execute chmod command with proper quoting
            success, output, error = self.remote.execute_command(f"chmod {permissions} \"{resolved_path}\"")
            if success:
                # Log the action for audit purposes
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="File Permissions Changed",
                    details=f"Path: {resolved_path}, Permissions: {permissions}"
                )
                return True, f"Permissions for {resolved_path} changed to {permissions}"
            else:
                self.logger.error(f"Error changing permissions for {resolved_path}: {error}")
                return False, f"Failed to change permissions: {error}"
        except Exception as e:
            self.logger.error(f"Exception changing permissions for {resolved_path}: {str(e)}")
            return False, f"An error occurred: {str(e)}"
    
    def get_system_info(self):
        """Get basic system information"""
        try:
            if self.remote:
                # Get real system info from remote connection
                hostname_out, _ = self.remote.execute_command("hostname")
                os_out, _ = self.remote.execute_command("cat /etc/os-release | grep PRETTY_NAME")
                kernel_out, _ = self.remote.execute_command("uname -r")
                uptime_out, _ = self.remote.execute_command("uptime -p")
                
                os_name = os_out.split('=')[1].strip('"') if '=' in os_out else "Unknown"
                
                return {
                    'hostname': hostname_out.strip() if hostname_out else "Unknown",
                    'os': os_name,
                    'kernel': kernel_out.strip() if kernel_out else "Unknown",
                    'uptime': uptime_out.strip() if uptime_out else "Unknown"
                }
            else:
                # Simulate system info
                return {
                    'hostname': 'demo-server',
                    'os': 'Ubuntu 20.04 LTS',
                    'kernel': '5.4.0-42-generic',
                    'uptime': 'up 3 days, 2 hours, 15 minutes'
                }
        except Exception as e:
            self.logger.error(f"Error getting system info: {str(e)}")
            return {'error': str(e)}
    
    def get_resource_usage(self) -> Dict[str, float]:
        """Get system resource usage"""
        try:
            usage = {}
            
            if self.remote:
                # Get real resource usage
                stdout, _ = self.remote.execute_command(
                    "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
                )
                try:
                    usage['cpu'] = float(stdout.strip())
                except:
                    usage['cpu'] = 0.0
                
                stdout, _ = self.remote.execute_command(
                    "free | grep Mem | awk '{print $3/$2 * 100.0}'"
                )
                try:
                    usage['memory'] = float(stdout.strip())
                except:
                    usage['memory'] = 0.0
                
                stdout, _ = self.remote.execute_command(
                    "df / | tail -1 | awk '{print $5}' | sed 's/%//'"
                )
                try:
                    usage['disk'] = float(stdout.strip())
                except:
                    usage['disk'] = 0.0
            else:
                # Simulated data
                usage['cpu'] = 25.5
                usage['memory'] = 40.2
                usage['disk'] = 65.7
            
            return usage
        except Exception as e:
            self.logger.error(f"Error getting resource usage: {str(e)}")
            return {"error": str(e)}
    
    def get_active_services(self) -> List[Dict[str, str]]:
        """Get list of active services (read-only)"""
        try:
            services = []
            if self.remote:
                stdout, _ = self.remote.execute_command(
                    "systemctl list-units --type=service --state=running"
                )
                
                for line in stdout.splitlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        services.append({
                            'name': parts[0],
                            'status': parts[2],
                            'description': ' '.join(parts[4:])
                        })
            else:
                # Simulated services
                services = [
                    {'name': 'ssh.service', 'status': 'running', 'description': 'OpenSSH server daemon'},
                    {'name': 'apache2.service', 'status': 'running', 'description': 'The Apache HTTP Server'},
                    {'name': 'mysql.service', 'status': 'running', 'description': 'MySQL Database Server'}
                ]
            
            return services
        except Exception as e:
            self.logger.error(f"Error getting active services: {str(e)}")
            return []
    
    def get_system_logs(self, log_file: str, lines: int = 100) -> List[str]:
        """Get system log entries (except security logs)"""
        try:
            if 'auth' in log_file or 'secure' in log_file:
                return ["Access denied: Junior admins cannot view security logs"]
                
            logs = []
            if self.remote:
                stdout, _ = self.remote.execute_command(f"tail -n {lines} {log_file}")
                logs = stdout.splitlines()
            else:
                # Simulated logs
                logs = [f"Log entry {i} for {log_file}" for i in range(1, lines+1)]
            
            return logs
        except Exception as e:
            self.logger.error(f"Error getting logs: {str(e)}")
            return []
    
    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get network interfaces (read-only)"""
        try:
            interfaces = []
            if self.remote:
                stdout, _ = self.remote.execute_command("ip -o addr show")
                for line in stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        interfaces.append({
                            'name': parts[1],
                            'status': 'UP' if 'UP' in line else 'DOWN',
                            'address': parts[3] if len(parts) > 3 else 'Not assigned'
                        })
            else:
                # Simulated interfaces
                interfaces = [
                    {'name': 'eth0', 'status': 'UP', 'address': '192.168.1.100/24'},
                    {'name': 'lo', 'status': 'UP', 'address': '127.0.0.1/8'}
                ]
            
            return interfaces
        except Exception as e:
            self.logger.error(f"Error getting network interfaces: {str(e)}")
            return []
    
    def view_backups(self) -> List[Dict[str, str]]:
        """View available backups (read-only)"""
        try:
            backups = []
            if self.remote:
                stdout, _ = self.remote.execute_command("find /backup -name 'backup_*.tar.gz' -type f")
                for line in stdout.splitlines():
                    if line:
                        filename = os.path.basename(line)
                        date_parts = filename.replace('backup_', '').replace('.tar.gz', '').split('_')
                        if len(date_parts) >= 2:
                            date = date_parts[0].replace('-', '/')
                            time = date_parts[1].replace('-', ':')
                            backups.append({
                                'path': line,
                                'date': f"{date} {time}",
                                'size': "Unknown"  # Would get actual size in real implementation
                            })
            else:
                # Simulated backups
                backups = [
                    {'path': '/backup/backup_2025-05-01_10-00-00.tar.gz', 'date': '2025/05/01 10:00:00', 'size': '1.2 GB'},
                    {'path': '/backup/backup_2025-05-08_10-00-00.tar.gz', 'date': '2025/05/08 10:00:00', 'size': '1.3 GB'}
                ]
            
            return backups
        except Exception as e:
            self.logger.error(f"Error viewing backups: {str(e)}")
            return []
    
    def check_available_updates(self) -> List[Dict[str, str]]:
        """Check available updates (read-only)"""
        try:
            updates = []
            if self.remote:
                # Try apt first (Debian/Ubuntu)
                stdout, _ = self.remote.execute_command("apt list --upgradable 2>/dev/null || echo 'COMMAND_FAILED'")
                if 'COMMAND_FAILED' not in stdout:
                    for line in stdout.splitlines()[1:]:  # Skip header
                        if line:
                            parts = line.split('/')
                            if len(parts) >= 2:
                                package = parts[0]
                                versions = line.split('[')[1].split(']')[0] if '[' in line else "unknown"
                                updates.append({
                                    'package': package,
                                    'current': versions.split(' => ')[0] if ' => ' in versions else "unknown",
                                    'available': versions.split(' => ')[1] if ' => ' in versions else versions
                                })
                else:
                    # Try dnf (Red Hat/Fedora)
                    stdout, _ = self.remote.execute_command("dnf check-update -q")
                    for line in stdout.splitlines():
                        if line and not line.startswith('Last metadata'):
                            parts = line.split()
                            if len(parts) >= 2:
                                updates.append({
                                    'package': parts[0],
                                    'current': "installed",
                                    'available': parts[1]
                                })
            else:
                # Simulated updates
                updates = [
                    {'package': 'openssh-server', 'current': '8.2p1-4ubuntu0.3', 'available': '8.2p1-4ubuntu0.4'},
                    {'package': 'bash', 'current': '5.0-6ubuntu1.1', 'available': '5.0-6ubuntu1.2'},
                    {'package': 'openssl', 'current': '1.1.1f-1ubuntu2.8', 'available': '1.1.1f-1ubuntu2.9'}
                ]
            
            return updates
        except Exception as e:
            self.logger.error(f"Error checking updates: {str(e)}")
            return []
    
    def get_remote_connections(self) -> List[Dict[str, str]]:
        """Get remote connections (read-only)"""
        try:
            connections = []
            if self.remote:
                stdout, _ = self.remote.execute_command("ss -tuln | grep LISTEN")
                for line in stdout.splitlines():
                    if line:
                        parts = line.split()
                        if len(parts) >= 5:
                            address = parts[4]
                            port = address.split(':')[-1] if ':' in address else "unknown"
                            connections.append({
                                'protocol': parts[0],
                                'local_address': address,
                                'port': port,
                                'state': 'LISTEN'
                            })
            else:
                # Simulated connections
                connections = [
                    {'protocol': 'tcp', 'local_address': '0.0.0.0:22', 'port': '22', 'state': 'LISTEN'},
                    {'protocol': 'tcp', 'local_address': '127.0.0.1:3306', 'port': '3306', 'state': 'LISTEN'},
                    {'protocol': 'tcp', 'local_address': '0.0.0.0:80', 'port': '80', 'state': 'LISTEN'}
                ]
            
            return connections
        except Exception as e:
            self.logger.error(f"Error getting remote connections: {str(e)}")
            return []
            
    def get_task_history(self):
        """Get task history for the junior admin"""
        # Get task history from the database
        return self.db_manager.get_task_history(self.current_user)
        
    def get_current_time(self):
        """Get formatted current time"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def submit_task_report(self, task_type: str, description: str) -> bool:
        """Submit a task report"""
        try:
            # Save the task report to the database
            success = self.db_manager.add_report(
                from_user=self.current_user,
                to_user="senior",  # Reports are sent to the senior admin
                report_type=task_type,
                description=description
            )
            
            # add to task history
            if success:
                self.db_manager.add_task_history(
                    user=self.current_user,
                    task_type=task_type,
                    description=description
                )
                
                # Log the action
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="Task Report Submitted",
                    details=f"Type: {task_type}, Description: {description}"
                )
                
            return success
        except Exception as e:
            self.logger.error(f"Error submitting task report: {str(e)}")
            return False
    
    def set_current_user(self, username: str):
        """Set the current user"""
        self.current_user = username
    
    def cleanup(self):
        """Clean up resources, like closing the remote connection."""
        if self.remote and hasattr(self.remote, 'disconnect') and callable(self.remote.disconnect):
            self.remote.disconnect()
    
    # Simulation methods
    def _simulate_passwd_file(self):
        """Simulate the content of /etc/passwd file"""
        return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:112:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
cups-pk-helper:x:110:116:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:112:117::/nonexistent:/bin/false
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:114:119::/var/lib/saned:/usr/sbin/nologin
pulse:x:115:120:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:117:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:118:7:HPLIP system user,,,:/var/run/hplip:/bin/false
junior:x:1000:1000:Junior Admin:/home/junior:/bin/bash
senior:x:1001:1001:Senior Admin:/home/senior:/bin/bash"""

    def _simulate_group_file(self):
        """Simulate the content of /etc/group file"""
        return """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,junior
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:junior,senior
floppy:x:25:
tape:x:26:
sudo:x:27:junior,senior
audio:x:29:pulse
dip:x:30:junior
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:"""

    def _simulate_home_directory(self):
        """Simulate the content of /home directory"""
        return """total 16
drwxr-xr-x  4 root   root   4096 May  9 10:00 .
drwxr-xr-x 23 root   root   4096 May  9 10:00 ..
drwxr-xr-x 17 junior junior 4096 May  9 09:59 junior
drwxr-xr-x 19 senior senior 4096 May  9 09:58 senior"""