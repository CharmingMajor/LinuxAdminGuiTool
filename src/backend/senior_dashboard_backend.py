from src.utils.remote_connection import RemoteConnection
import logging
from typing import Optional, Dict, List, Tuple
import os
import json
from datetime import datetime
from src.backend.database import DatabaseManager

class SeniorDashboardBackend:
    """Backend functionality for Senior Dashboard"""
    
    def __init__(self, remote: RemoteConnection):
        self.remote = remote
        self.logger = logging.getLogger(__name__)
        self.db_manager = DatabaseManager()
        self.current_user = "senior"  # Default, should be set when user logs in
        
    def get_system_info(self) -> Dict[str, str]:
        """Get basic system information"""
        try:
            info = {}
            # Get hostname
            stdout, _ = self.remote.execute_command("hostname")
            info['hostname'] = stdout.strip()
            
            # Get OS info
            stdout, _ = self.remote.execute_command("cat /etc/os-release | grep PRETTY_NAME")
            if stdout:
                info['os'] = stdout.split('=')[1].strip().strip('"')
            
            # Get kernel version
            stdout, _ = self.remote.execute_command("uname -r")
            info['kernel'] = stdout.strip()
            
            # Get uptime
            stdout, _ = self.remote.execute_command("uptime -p")
            info['uptime'] = stdout.strip()
            
            return info
        except Exception as e:
            self.logger.error(f"Error getting system info: {str(e)}")
            return {"error": str(e)}
    
    def get_resource_usage(self) -> Dict[str, float]:
        """Get system resource usage"""
        try:
            usage = {}
            
            # Get CPU usage
            stdout, _ = self.remote.execute_command(
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
            )
            usage['cpu'] = float(stdout.strip())
            
            # Get memory usage
            stdout, _ = self.remote.execute_command(
                "free | grep Mem | awk '{print $3/$2 * 100.0}'"
            )
            usage['memory'] = float(stdout.strip())
            
            # Get disk usage
            stdout, _ = self.remote.execute_command(
                "df / | tail -1 | awk '{print $5}' | sed 's/%//'"
            )
            usage['disk'] = float(stdout.strip())
            
            return usage
        except Exception as e:
            self.logger.error(f"Error getting resource usage: {str(e)}")
            return {"error": str(e)}
    
    def get_active_services(self) -> List[Dict[str, str]]:
        """Get list of active services"""
        try:
            services = []
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
            
            return services
        except Exception as e:
            self.logger.error(f"Error getting active services: {str(e)}")
            return []
    
    def get_system_logs(self, limit: int = 100) -> List[Dict[str, any]]:
        """Get system logs from database"""
        return self.db_manager.get_system_logs(limit)
    
    def execute_admin_command(self, command: str, use_sudo: bool = False) -> Tuple[bool, str]:
        """Execute administrative command"""
        try:
            if use_sudo:
                command = f"sudo {command}"
            stdout, stderr = self.remote.execute_command(command)
            success = not stderr
            return success, stdout if success else stderr
        except Exception as e:
            self.logger.error(f"Error executing command: {str(e)}")
            return False, str(e)
    
    def backup_system(self, backup_path: str, backup_type: str = "full") -> Tuple[bool, str]:
        """Create system backup"""
        try:
            date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            archive_name = f"backup_{date}.tar.gz"
            full_path = os.path.join(backup_path, archive_name)
            
            # Create backup command based on type
            if backup_type == "full":
                cmd = f"tar czf {full_path} --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run --exclude=/media --exclude=/mnt /"
            else:  # incremental
                snapshot = os.path.join(backup_path, f"snapshot_{date}")
                cmd = f"tar czf {full_path} --listed-incremental={snapshot} --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run --exclude=/media --exclude=/mnt /"
            
            success, output = self.execute_admin_command(cmd, use_sudo=True)
            return success, output
        except Exception as e:
            self.logger.error(f"Error creating backup: {str(e)}")
            return False, str(e)
    
    def restore_backup(self, backup_file: str, restore_path: str) -> Tuple[bool, str]:
        """Restore system from backup"""
        try:
            cmd = f"tar xzf {backup_file} -C {restore_path}"
            success, output = self.execute_admin_command(cmd, use_sudo=True)
            return success, output
        except Exception as e:
            self.logger.error(f"Error restoring backup: {str(e)}")
            return False, str(e)
    
    def update_system(self) -> Tuple[bool, str]:
        """Update system packages"""
        try:
            # Try apt (Debian/Ubuntu)
            success, output = self.execute_admin_command("apt-get update && apt-get upgrade -y", use_sudo=True)
            if not success:
                # Try dnf (Red Hat/Fedora)
                success, output = self.execute_admin_command("dnf upgrade -y", use_sudo=True)
            return success, output
        except Exception as e:
            self.logger.error(f"Error updating system: {str(e)}")
            return False, str(e)
    
    def get_junior_reports(self) -> List[Dict[str, any]]:
        """Get reports submitted by junior admins"""
        return self.db_manager.get_reports(self.current_user, role="senior")
        
    def update_report_status(self, report_id: int, status: str) -> bool:
        """Update the status of a report"""
        try:
            conn = self.db_manager._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """UPDATE reports SET status = ? WHERE id = ?""",
                (status, report_id)
            )
            
            conn.commit()
            conn.close()
            
            # Log the action
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Report Status Updated",
                details=f"Report ID: {report_id}, New Status: {status}"
            )
            
            return True
        except Exception as e:
            self.logger.error(f"Error updating report status: {str(e)}")
            return False
    
    def set_current_user(self, username: str):
        """Set the current user"""
        self.current_user = username
    
    def cleanup(self):
        """Clean up resources"""
        if self.remote:
            self.remote.disconnect() 