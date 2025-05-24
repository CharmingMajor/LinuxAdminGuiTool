from src.utils.remote_connection import RemoteConnection
import logging
from typing import Optional, Dict, List, Tuple
import os
from datetime import datetime
from src.backend.database import DatabaseManager
import re

class SeniorDashboardBackend:
    """Backend functionality for Senior Dashboard"""
    
    def __init__(self, remote: RemoteConnection, current_user: str = "seniordefault"):
        self.remote = remote
        self.logger = logging.getLogger(__name__)
        self.db_manager = DatabaseManager()
        self.current_user = current_user  # Store username for logging
        
    def get_system_info(self) -> Dict[str, str]:
        """Get basic system information"""
        if not self.remote or not self.remote.connected:
            self.logger.error("get_system_info: Remote connection is not available.")
            return {"error": "Remote connection not available."}
        try:
            info = {}
            # Get hostname
            stdout, _ = self.remote.execute_command("hostname")
            info['hostname'] = stdout.strip()
            
            # Get OS information
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
            
            # CPU usage percentage
            stdout, _ = self.remote.execute_command(
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"
            )
            usage['cpu'] = float(stdout.strip())
            
            # Memory usage percentage
            stdout, _ = self.remote.execute_command(
                "free | grep Mem | awk '{print $3/$2 * 100.0}'"
            )
            usage['memory'] = float(stdout.strip())
            
            # Disk usage percentage
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
            
            for line in stdout.splitlines()[1:]:
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
            else:  # incremental backup
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
            # Try apt for Debian/Ubuntu
            success, output = self.execute_admin_command("apt-get update && apt-get upgrade -y", use_sudo=True)
            if not success:
                # Fall back to dnf for Red Hat/Fedora
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
            
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Report Status Updated",
                details=f"Report ID: {report_id}, New Status: {status}"
            )
            
            return True
        except Exception as e:
            self.logger.error(f"Error updating report status: {str(e)}")
            return False
    
    def get_firewall_status(self) -> Tuple[bool, str, List[Dict[str, str]]]:
        """Get UFW firewall status and rules."""
        try:
            success, output, error = self.remote.execute_command("sudo ufw status verbose")
            if not success:
                return False, f"Error getting firewall status: {error}", []

            status_line = "unknown"
            rules = []
            lines = output.splitlines()
            for i, line in enumerate(lines):
                if line.lower().startswith("status:"):
                    status_line = line.split(":")[1].strip()
                elif line.strip() == "To                         Action      From":  # Header for rules
                    # Parse firewall rules
                    for rule_line in lines[i+2:]:
                        if not rule_line.strip() or rule_line.startswith("---"):
                            continue  # Skip empty lines or separators
                        
                        # Handle complex rule formats with space in action
                        temp_rule_line = rule_line.replace(" ALLOW IN ", " ALLOW_IN ") \
                                               .replace(" DENY IN ", " DENY_IN ") \
                                               .replace(" REJECT IN ", " REJECT_IN ") \
                                               .replace(" LIMIT IN ", " LIMIT_IN ") \
                                               .replace(" ALLOW OUT ", " ALLOW_OUT ") \
                                               .replace(" DENY OUT ", " DENY_OUT ") \
                                               .replace(" REJECT OUT ", " REJECT_OUT ") \
                                               .replace(" LIMIT OUT ", " LIMIT_OUT ")

                        parts = [p.strip() for p in temp_rule_line.split() if p.strip()]

                        if not parts:
                            continue

                        # Parse rule components
                        to_val = "N/A"
                        action_val = "N/A"
                        from_val = "N/A"
                        details_val = ""

                        if len(parts) == 1:
                            to_val = parts[0]
                        elif len(parts) == 2:
                            to_val = parts[0]
                            action_val = parts[1].replace("_", " ")
                        elif len(parts) >= 3:
                            to_val = parts[0]
                            action_val = parts[1].replace("_", " ")

                            if parts[1] in ["ALLOW", "DENY", "REJECT", "LIMIT"] and parts[2] in ["IN", "OUT"]:
                                action_val = f"{parts[1]} {parts[2]}"
                                if len(parts) >= 4:
                                    from_val = parts[3]
                                    details_val = ' '.join(parts[4:]) if len(parts) > 4 else ''
                            elif not action_val.endswith(" IN") and not action_val.endswith(" OUT"):
                                from_val = parts[2]
                                details_val = ' '.join(parts[3:]) if len(parts) > 3 else ''
                            else:
                                from_val = parts[2]
                                details_val = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        
                        rule = {
                            "to": to_val,
                            "action": action_val,
                            "from": from_val,
                            "details": details_val.strip()
                        }
                        rules.append(rule)
                    break
            return True, status_line, rules
        except Exception as e:
            self.logger.error(f"Error parsing firewall status: {str(e)}")
            return False, f"An error occurred: {str(e)}", []

    def add_firewall_rule(self, rule: str) -> Tuple[bool, str]:
        """Add a UFW firewall rule (e.g., 'allow 22/tcp')."""
        try:
            if not re.match(r"^(allow|deny|reject|limit)\s+([0-9]{1,5}(/tcp|/udp)?|\w+)(\s+.*)?", rule.lower()):
                return False, "Invalid rule format. Example: 'allow 22/tcp' or 'deny from 192.168.1.100'"
            
            success, output, error = self.remote.execute_command(f"sudo ufw {rule}")
            if success:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="Firewall Rule Added",
                    details=f"Rule: {rule}"
                )
                return True, output if output else "Rule command executed."
            else:
                return False, f"Error adding firewall rule: {error}"
        except Exception as e:
            self.logger.error(f"Error adding firewall rule: {str(e)}")
            return False, f"An error occurred: {str(e)}"

    def delete_firewall_rule(self, rule: str) -> Tuple[bool, str]:
        """Delete a UFW firewall rule (e.g., 'allow 22/tcp')."""
        try:
            if not re.match(r"^(allow|deny|reject|limit)\s+([0-9]{1,5}(/tcp|/udp)?|\w+)(\s+.*)?", rule.lower()):
                return False, "Invalid rule format for deletion. Provide the rule as it was added."

            success, output, error = self.remote.execute_command(f"sudo ufw delete {rule}")
            if success:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="Firewall Rule Deleted",
                    details=f"Rule: {rule}"
                )
                return True, output if output else "Delete rule command executed."
            else:
                return False, f"Error deleting firewall rule: {error}"
        except Exception as e:
            self.logger.error(f"Error deleting firewall rule: {str(e)}")
            return False, f"An error occurred: {str(e)}"
    
    def set_current_user(self, username: str):
        """Set the current user"""
        self.current_user = username
    
    def cleanup(self):
        """Clean up resources"""
        if self.remote:
            self.remote.disconnect()

    # User Management 
    def add_system_user(self, username: str, password: Optional[str] = None, groups: Optional[List[str]] = None, shell: Optional[str] = "/bin/bash", home_dir: Optional[str] = None, comment: Optional[str] = None, create_home: bool = True) -> Tuple[bool, str]:
        """
        Add a new system user.
        Senior admin can specify more options.
        Simulates command execution and returns terminal-like output.
        """
        try:
            # Build useradd command with options
            cmd_parts = ["sudo useradd"]
            if create_home:
                cmd_parts.append("-m")
            if shell:
                cmd_parts.append(f"-s {shell}")
            if home_dir:
                cmd_parts.append(f"-d {home_dir}")
            if comment:
                # Escape quotes in comment
                escaped_comment = comment.replace('"', '\\"')
                cmd_parts.append(f'-c "{escaped_comment}"')

            if groups:
                cmd_parts.append(f"-G {','.join(groups)}")
            
            cmd_parts.append(username)
            useradd_cmd = " ".join(cmd_parts)

            # Execute the command
            useradd_output, useradd_error = self.remote.execute_command(useradd_cmd)
            
            if useradd_error: 
                self.logger.error(f"useradd command failed for {username}: {useradd_error}")
                return False, useradd_error

            # Set password if provided
            if password:
                pw_cmd = f'echo "{username}:{password}" | sudo chpasswd'
                pw_output, pw_error = self.remote.execute_command(pw_cmd)
                
                if pw_error:
                    self.logger.warning(f"User {username} created (useradd output: '{useradd_output}'), but failed to set password: {pw_error}")

                    message = f"User '{username}' created."
                    if useradd_output:
                        message += f" useradd output: '{useradd_output.strip()}'."
                    message += f"\\nWARN: Password setting failed: {pw_error.strip()}"
                    return True, message

            # Log the action
            details_dict = {
                'groups': groups,
                'shell': shell,
                'home_dir': home_dir,
                'comment': comment,
                'create_home': create_home
            }
            self.db_manager.add_system_log(
                user=self.current_user,
                action="System User Added",
                details=f"Username: {username}, Command: {useradd_cmd}, Options: {details_dict}"
            )
            return True, useradd_output.strip()

        except Exception as e:
            self.logger.error(f"Error adding system user {username}: {str(e)}")
            return False, f"An unexpected error occurred while trying to add user {username}: {str(e)}"

    def delete_system_user(self, username: str, delete_home: bool = False) -> Tuple[bool, str]:
        """Delete a system user."""
        try:
            cmd = "sudo userdel"
            if delete_home:
                cmd += " -r"
            cmd += f" {username}"
            
            output, error = self.remote.execute_command(cmd)
            success = not error

            if success:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="System User Deleted",
                    details=f"Username: {username}, Delete Home: {delete_home}"
                )
                return True, output.strip() if output else ""
            else:
                
                error_message = error.strip()
                if not error_message.lower().startswith("userdel:"):
                    error_message = f"userdel: {error_message}"
                if "does not exist" in error.lower(): 
                     return False, f"userdel: user '{username}' does not exist"
                return False, error_message
        except Exception as e:
            self.logger.error(f"Error deleting system user {username}: {str(e)}")
            return False, f"An error occurred: {str(e)}"

    def modify_system_user(self, username: str, new_password: Optional[str] = None,
                             add_groups: Optional[List[str]] = None,
                             remove_groups: Optional[List[str]] = None,
                             new_shell: Optional[str] = None,
                             new_home_dir: Optional[str] = None,
                             move_home_content: bool = False,
                             new_comment: Optional[str] = None,
                             lock_account: Optional[bool] = None,
                             unlock_account: Optional[bool] = None,
                             primary_group: Optional[str] = None
                             ) -> Tuple[bool, str]:
      
        try:
            actions_taken = []
            final_output_parts = []
            overall_success = True

            # Update password if requested
            if new_password:
                pw_cmd = f'echo "{username}:{new_password}" | sudo chpasswd'
                output, error = self.remote.execute_command(pw_cmd)
                if not error:
                    actions_taken.append("Password updated")
                    if output: final_output_parts.append(f"Pwd_Out: {output}")
                else:
                    overall_success = False
                    final_output_parts.append(f"Password update failed: {error}")
            
            # Prepare usermod options
            usermod_options = []
            if primary_group:
                usermod_options.append(f"-g {primary_group}")
            if add_groups:
                usermod_options.append(f"-aG {','.join(add_groups)}")
            if new_shell:
                usermod_options.append(f"-s {new_shell}")
            if new_home_dir:
                cmd_part = f"-d {new_home_dir}"
                if move_home_content:
                    cmd_part += " -m"
                usermod_options.append(cmd_part)
            if new_comment is not None:
                usermod_options.append(f"-c \"{new_comment}\"")

            # Execute usermod if we have options
            if usermod_options:
                cmd = f"sudo usermod {' '.join(usermod_options)} {username}"
                output, error = self.remote.execute_command(cmd)
                if not error:
                    actions_taken.append(f"User attributes modified ({' '.join(usermod_options)})")
                    if output: final_output_parts.append(f"Usermod_Out: {output}")
                else:
                    overall_success = False
                    final_output_parts.append(f"Usermod failed: {error}")
            
            # Lock account if requested
            if lock_account is True:
                lock_cmd = f"sudo passwd -l {username}"
                output, error = self.remote.execute_command(lock_cmd)
                if not error:
                    actions_taken.append("Account locked")
                    if output: final_output_parts.append(f"Lock_Out: {output}")
                else:
                    overall_success = False
                    final_output_parts.append(f"Account locking failed: {error}")
                    
            # Unlock account if requested
            if unlock_account is True:
                unlock_cmd = f"sudo passwd -u {username}"
                output, error = self.remote.execute_command(unlock_cmd)
                if not error:
                    actions_taken.append("Account unlocked")
                    if output: final_output_parts.append(f"Unlock_Out: {output}")
                else:
                    overall_success = False
                    final_output_parts.append(f"Account unlocking failed: {error}")
            
            # Handle results
            if overall_success and actions_taken:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="System User Modified",
                    details=f"Username: {username}, Actions: {', '.join(actions_taken)}"
                )
                
               
                if final_output_parts:
                    return True, "\n".join(final_output_parts).strip()
                return True, ""  # Silent success
            elif actions_taken: 
                return False, f"Some user modifications failed. Details:\n{'\n'.join(final_output_parts).strip()}"
            else:  # No actions attempted
                return False, "No modifications specified for user."
        except Exception as e:
            self.logger.error(f"Error modifying system user {username}: {str(e)}")
            return False, f"An error occurred: {str(e)}"
            
    def reset_user_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Reset password for an existing user.
        Simulates the 'passwd <username>' command interaction for the GUI.
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."

        try:
            check_cmd = f"id -u {username}"
            _, check_error = self.remote.execute_command(check_cmd)
            if check_error:
                simulated_output = f"$ passwd {username}\\n"
                simulated_output += f"passwd: user '{username}' does not exist"
                return False, simulated_output

            simulated_output = f"$ passwd {username}\\n"
            simulated_output += "Enter new UNIX password: ********\\n"
            simulated_output += "Retype new UNIX password: ********\\n"

            pw_cmd = f'echo "{username}:{new_password}" | sudo chpasswd'
            chpasswd_output, chpasswd_error = self.remote.execute_command(pw_cmd)

            if chpasswd_error:
                self.logger.error(f"Error resetting password for {username} using chpasswd: {chpasswd_error}")
                simulated_output += f"passwd: password change failed: {chpasswd_error}"
                return False, simulated_output
            
            self.db_manager.add_system_log(
                user=self.current_user,
                action="User Password Reset",
                details=f"Password reset for user: {username}"
            )
            
            simulated_output += "passwd: password updated successfully"
            return True, simulated_output

        except Exception as e:
            self.logger.error(f"Exception in reset_user_password for {username}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    # Group Management
    def add_system_group(self, group_name: str, gid: Optional[str] = None) -> Tuple[bool, str]:
        """Add a new system group."""
        try:
            # Build groupadd command
            cmd = "sudo groupadd"
            if gid:
                cmd += f" -g {gid}"
            cmd += f" {group_name}"
            
            output, error = self.remote.execute_command(cmd)
            success = not error

            if success:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="System Group Added",
                    details=f"Group Name: {group_name}, GID: {gid if gid else 'default'}"
                )
                return True, output.strip() if output else ""
            else:
                error_message = error.strip()
                if not error_message.lower().startswith("groupadd:"):
                    error_message = f"groupadd: {error_message}"
                if "already exists" in error.lower():
                    return False, f"groupadd: group '{group_name}' already exists"
                return False, error_message
        except Exception as e:
            self.logger.error(f"Error adding system group {group_name}: {str(e)}")
            return False, f"An error occurred: {str(e)}"

    def delete_system_group(self, group_name: str) -> Tuple[bool, str]:
        """Delete a system group."""
        try:
            cmd = f"sudo groupdel {group_name}"
            output, error = self.remote.execute_command(cmd)
            success = not error
            if success:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="System Group Deleted",
                    details=f"Group Name: {group_name}"
                )
                return True, output.strip() if output else ""
            else:
                error_message = error.strip()
                if not error_message.lower().startswith("groupdel:"):
                    error_message = f"groupdel: {error_message}"

                if "does not exist" in error.lower():
                    error_message = f"groupdel: group '{group_name}' does not exist"
                elif "cannot remove the primary group of user" in error.lower():
                    match = re.search(r"cannot remove the primary group of user '([^']*)'", error)
                    if match:
                        concerned_user = match.group(1)
                        error_message = f"groupdel: cannot remove the primary group of user '{concerned_user}'"
                
                return False, error_message
        except Exception as e:
            self.logger.error(f"Error deleting system group {group_name}: {str(e)}")
            return False, f"An error occurred: {str(e)}"

    def modify_system_group(self, group_name: str, new_group_name: Optional[str] = None, new_gid: Optional[str] = None) -> Tuple[bool, str]:
        """Modify an existing system group's attributes (name or GID)."""
        try:
            if not new_group_name and not new_gid:
                return False, "groupmod: no modifications specified for group"

            log_details = [f"Original Group Name: {group_name}"]
            cmd = "sudo groupmod"
            
            if new_gid:
                cmd += f" -g {new_gid}"
                log_details.append(f"New GID: {new_gid}")
            
            if new_group_name:
                cmd += f" -n {new_group_name}"
                log_details.append(f"New Name: {new_group_name}")
            
            cmd += f" {group_name}"

            output, error = self.remote.execute_command(cmd)
            success = not error
            
            if success:
                self.db_manager.add_system_log(
                    user=self.current_user,
                    action="System Group Modified",
                    details=", ".join(log_details)
                )
                return True, output.strip() if output else ""
            else:
                error_message = error.strip()
                if not error_message.lower().startswith("groupmod:"):
                    error_message = f"groupmod: {error_message}"
                return False, error_message
        except Exception as e:
            self.logger.error(f"Error modifying system group {group_name}: {str(e)}")
            return False, f"An error occurred: {str(e)}"

    def change_file_ownership(self, path: str, owner: Optional[str] = None, group: Optional[str] = None, recursive: bool = False) -> Tuple[bool, str]:
        """
        Change file or directory ownership (chown).
        Senior admins have full access to change ownership of any file/directory.
        
        Args:
            path: Path to the file or directory
            owner: New owner username (optional if only changing group)
            group: New group name (optional if only changing owner)
            recursive: Whether to apply changes recursively
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            # Validate that at least one of owner or group is provided
            if not owner and not group:
                return False, "chown: missing operand. Please specify at least one of owner or group."
                
            # Build the ownership specification
            ownership_spec = ""
            if owner and group:
                ownership_spec = f"{owner}:{group}"
            elif owner:
                ownership_spec = owner
            elif group:
                ownership_spec = f":{group}"
                
            # Build chown command
            cmd_parts = ["sudo chown"]
            if recursive:
                cmd_parts.append("-R")
            cmd_parts.append(ownership_spec)
            cmd_parts.append(f"\"{path}\"")  # Quote path to handle spaces
            
            cmd = " ".join(cmd_parts)
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error changing file ownership for {path}: {error}")
                error_message = error.strip()
                if not error_message.lower().startswith("chown:"):
                    error_message = f"chown: {error_message}"
                return False, error_message
                
            # Log the change
            self.db_manager.add_system_log(
                user=self.current_user,
                action="File Ownership Changed",
                details=f"Path: {path}, Owner: {owner}, Group: {group}, Recursive: {recursive}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in change_file_ownership for {path}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"
            
    def change_file_permissions(self, path: str, permissions: str, recursive: bool = False) -> Tuple[bool, str]:
        """
        Change file or directory permissions (chmod).
        Senior admins have full access to change permissions of any file/directory.
        
        Args:
            path: Path to the file or directory
            permissions: Permissions in octal format (e.g., "755")
            recursive: Whether to apply changes recursively
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            if not re.match(r"^[0-7]{3,4}$", permissions):
                return False, "chmod: Invalid permissions format. Use octal (e.g., 755)."
                
            cmd_parts = ["sudo chmod"]
            if recursive:
                cmd_parts.append("-R")
            cmd_parts.append(permissions)
            cmd_parts.append(f"\"{path}\"")
            
            cmd = " ".join(cmd_parts)
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error changing file permissions: {error}")
                error_message = error.strip()
                if not error_message.lower().startswith("chmod:"):
                    error_message = f"chmod: {error_message}"
                return False, error_message
                
            self.db_manager.add_system_log(
                user=self.current_user,
                action="File Permissions Changed",
                details=f"Path: {path}, Permissions: {permissions}, Recursive: {recursive}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in change_file_permissions for {path}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def get_file_acl(self, path: str) -> Tuple[bool, str]:
        """
        Get ACL (Access Control List) for a file or directory using getfacl.
        
        Args:
            path: Path to the file or directory
            
        Returns:
            Success status and command output (ACL information) or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            cmd = f"getfacl \"{path}\""
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error getting ACL for {path}: {error}")
                error_message = error.strip()
                if not error_message.lower().startswith("getfacl:"):
                    error_message = f"getfacl: {error_message}"
                return False, error_message
                
            return True, output.strip()
            
        except Exception as e:
            self.logger.error(f"Exception in get_file_acl for {path}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def set_file_acl(self, path: str, acl_spec: str, recursive: bool = False) -> Tuple[bool, str]:
        """
        Set ACL (Access Control List) for a file or directory using setfacl.
        
        Args:
            path: Path to the file or directory
            acl_spec: ACL specification (e.g., "u:user:rwx", "g:group:r--")
            recursive: Whether to apply changes recursively
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            cmd_parts = ["sudo setfacl"]
            if recursive:
                cmd_parts.append("-R")
            cmd_parts.append("-m")
            cmd_parts.append(f"\"{acl_spec}\"")
            cmd_parts.append(f"\"{path}\"")
            
            cmd = " ".join(cmd_parts)
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error setting ACL for {path}: {error}")
                error_message = error.strip()
                if not error_message.lower().startswith("setfacl:"):
                    error_message = f"setfacl: {error_message}"
                return False, error_message
                
            self.db_manager.add_system_log(
                user=self.current_user,
                action="File ACL Set",
                details=f"Path: {path}, ACL: {acl_spec}, Recursive: {recursive}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in set_file_acl for {path}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def remove_file_acl(self, path: str, acl_spec: str, recursive: bool = False) -> Tuple[bool, str]:
        """
        Remove ACL (Access Control List) entries from a file or directory using setfacl -x.
        
        Args:
            path: Path to the file or directory
            acl_spec: ACL specification to remove (e.g., "u:user", "g:group")
            recursive: Whether to apply changes recursively
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            cmd_parts = ["sudo setfacl"]
            if recursive:
                cmd_parts.append("-R")
            cmd_parts.append("-x")
            cmd_parts.append(f"\"{acl_spec}\"")
            cmd_parts.append(f"\"{path}\"")
            
            cmd = " ".join(cmd_parts)
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error removing ACL for {path}: {error}")
                error_message = error.strip()
                if not error_message.lower().startswith("setfacl:"):
                    error_message = f"setfacl: {error_message}"
                return False, error_message
                
            self.db_manager.add_system_log(
                user=self.current_user,
                action="File ACL Removed",
                details=f"Path: {path}, ACL: {acl_spec}, Recursive: {recursive}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in remove_file_acl for {path}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def remove_default_acl(self, path: str) -> Tuple[bool, str]:
        """
        Remove all default ACL entries from a directory using setfacl -k.
        Only applicable to directories.
        
        Args:
            path: Path to the directory
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            cmd = f"sudo setfacl -k \"{path}\""
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error removing default ACL for {path}: {error}")
                error_message = error.strip()
                if not error_message.lower().startswith("setfacl:"):
                    error_message = f"setfacl: {error_message}"
                return False, error_message
                
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Default ACL Removed",
                details=f"Path: {path}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in remove_default_acl for {path}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def list_users(self) -> Tuple[List[Dict[str, str]], Optional[str]]:
        """List system users by parsing /etc/passwd."""
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
                            if uid < 1000 and uid != 0:
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
            self.logger.error(f"Error listing users: {str(e)}")
            return [], f"An unexpected error occurred while listing users: {str(e)}"

    def list_groups_detail(self) -> Tuple[List[Dict[str, str]], Optional[str]]:
        """Lists system groups by parsing /etc/group."""
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
            self.logger.error(f"Error listing groups: {str(e)}")
            return [], f"An unexpected error occurred: {str(e)}"

    def check_network_connectivity(self, host: str = "8.8.8.8", count: int = 4) -> Tuple[bool, str]:
        """
        Check network connectivity to a specified host using ping.
        
        Args:
            host: The host to ping (default: 8.8.8.8 - Google DNS)
            count: Number of packets to send (default: 4)
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            # Run ping command
            cmd = f"ping -c {count} {host}"
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error pinging {host}: {error}")
                return False, error.strip()
                
            # Check if ping was successful
            success = "bytes from" in output
            
            # Log the action
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Network Connectivity Check",
                details=f"Host: {host}, Success: {success}"
            )
            
            return success, output.strip()
            
        except Exception as e:
            self.logger.error(f"Exception in check_network_connectivity for {host}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def list_network_interfaces(self) -> Tuple[List[Dict[str, str]], str]:
        """
        List all network interfaces on the system with their details.
        
        Returns:
            List of dictionaries containing interface details and any error message
        """
        if not self.remote or not self.remote.connected:
            return [], "Remote connection not available."
            
        try:
            # Get all network interfaces
            cmd = "ip -o addr show"
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error listing network interfaces: {error}")
                return [], error.strip()
                
            interfaces = []
            for line in output.strip().split("\n"):
                if not line.strip():
                    continue
                    
                # Parse interface details
                parts = line.strip().split()
                if len(parts) >= 4:
                    idx = parts[0].rstrip(":")
                    name = parts[1]
                    
                    # Find IPv4 address if available
                    ip_address = ""
                    for i, part in enumerate(parts):
                        if part == "inet" and i+1 < len(parts):
                            ip_address = parts[i+1].split("/")[0]
                            break
                    
                    # Check if interface is UP
                    state_cmd = f"ip link show {name}"
                    state_output, state_error = self.remote.execute_command(state_cmd)
                    state = "DOWN"
                    if not state_error and "state UP" in state_output:
                        state = "UP"
                    
                    interfaces.append({
                        "name": name,
                        "ip_address": ip_address,
                        "state": state
                    })
            
            return interfaces, ""
            
        except Exception as e:
            self.logger.error(f"Exception in list_network_interfaces: {str(e)}")
            return [], f"An unexpected error occurred: {str(e)}"

    def enable_interface(self, interface_name: str) -> Tuple[bool, str]:
        """
        Enable a network interface (set it to UP state).
        
        Args:
            interface_name: Name of the interface to enable
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            # Set interface to UP state
            cmd = f"sudo ip link set {interface_name} up"
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error enabling interface {interface_name}: {error}")
                # Format error for consistency
                if not error.lower().startswith("ip:"):
                    error = f"ip: {error.strip()}"
                return False, error
                
            # Log the action
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Network Interface Enabled",
                details=f"Interface: {interface_name}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in enable_interface for {interface_name}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def disable_interface(self, interface_name: str) -> Tuple[bool, str]:
        """
        Disable a network interface (set it to DOWN state).
        
        Args:
            interface_name: Name of the interface to disable
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            cmd = f"sudo ip link set {interface_name} down"
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error disabling interface {interface_name}: {error}")
                if not error.lower().startswith("ip:"):
                    error = f"ip: {error.strip()}"
                return False, error
                
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Network Interface Disabled",
                details=f"Interface: {interface_name}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in disable_interface for {interface_name}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"

    def set_interface_ip_address(self, interface_name: str, ip_address: str, netmask: str = "24") -> Tuple[bool, str]:
        """
        Set the IP address for a network interface.
        
        Args:
            interface_name: Name of the interface
            ip_address: IP address to set
            netmask: Netmask in CIDR notation (default: 24, which equals 255.255.255.0)
            
        Returns:
            Success status and command output or error message
        """
        if not self.remote or not self.remote.connected:
            return False, "Remote connection not available."
            
        try:
            # Add IP address to interface
            cmd = f"sudo ip addr add {ip_address}/{netmask} dev {interface_name}"
            output, error = self.remote.execute_command(cmd)
            
            if error:
                self.logger.error(f"Error setting IP address for {interface_name}: {error}")
                # Format error for consistency
                if not error.lower().startswith("ip:"):
                    error = f"ip: {error.strip()}"
                return False, error
                
            # Log successful IP configuration
            self.db_manager.add_system_log(
                user=self.current_user,
                action="Network Interface IP Address Set",
                details=f"Interface: {interface_name}, IP: {ip_address}/{netmask}"
            )
            
            return True, output.strip() if output else ""
            
        except Exception as e:
            self.logger.error(f"Exception in set_interface_ip_address for {interface_name}: {str(e)}")
            return False, f"An unexpected error occurred: {str(e)}"