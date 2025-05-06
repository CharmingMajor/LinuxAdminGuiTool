import subprocess
import logging
import re
import os
import grp
import random
import string

class SeniorBackend:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Commands that senior admin is allowed to execute
        self.allowed_commands = [
            "htop",
            "docker ps",
            "systemctl",
            "iptables -L",
            "useradd",
            "usermod",
            "userdel",
            "groupadd",
            "groupmod",
            "groupdel",
            "passwd",
            "chmod",
            "chown",
            "chgrp",
            "mount",
            "umount",
            "fdisk -l",
            "apt",
            "apt-get",
            "yum",
            "ls -la",
            "find",
            "grep",
            "awk",
            "sed"
        ]
    
    def execute_command(self, command):
        """Execute an allowed command and return the result"""
        # Validate command is allowed
        if not any(command.startswith(allowed) for allowed in self.allowed_commands):
            self.logger.warning(f"Senior admin attempted unauthorized command: {command}")
            return None, "Command not permitted for senior admin"
        
        # Simulate command execution for safety in demo environment
        try:
            if command.startswith("useradd"):
                return self._simulate_user_management("add", command), None
            elif command.startswith("usermod"):
                return self._simulate_user_management("modify", command), None
            elif command.startswith("userdel"):
                return self._simulate_user_management("delete", command), None
            elif command.startswith("groupadd"):
                return self._simulate_group_management("add", command), None
            elif command.startswith("groupmod"):
                return self._simulate_group_management("modify", command), None
            elif command.startswith("groupdel"):
                return self._simulate_group_management("delete", command), None
            elif command.startswith("chmod"):
                return self._simulate_permission_change("mode", command), None
            elif command.startswith("chown"):
                return self._simulate_permission_change("owner", command), None
            elif command.startswith("chgrp"):
                return self._simulate_permission_change("group", command), None
            else:
                # For other commands, provide a simple simulation
                return f"Executed: {command}", None
        except Exception as e:
            self.logger.error(f"Error executing command: {str(e)}")
            return None, str(e)
    
    def manage_user(self, action, username, options=None):
        """Manage user accounts - create, modify, delete"""
        if options is None:
            options = {}
            
        try:
            if action == "create":
                # Simulate user creation
                home_dir = options.get("home", f"/home/{username}")
                shell = options.get("shell", "/bin/bash")
                groups = options.get("groups", [])
                
                self.logger.info(f"Created user: {username} with home:{home_dir}, shell:{shell}, groups:{groups}")
                return f"User {username} created successfully", None
                
            elif action == "modify":
                # Simulate user modification
                changes = []
                if "home" in options:
                    changes.append(f"home directory → {options['home']}")
                if "shell" in options:
                    changes.append(f"shell → {options['shell']}")
                if "groups" in options:
                    changes.append(f"groups → {','.join(options['groups'])}")
                    
                self.logger.info(f"Modified user: {username} with changes: {changes}")
                return f"User {username} modified successfully", None
                
            elif action == "delete":
                # Simulate user deletion
                self.logger.info(f"Deleted user: {username}")
                return f"User {username} deleted successfully", None
                
            else:
                return None, f"Unknown action: {action}"
                
        except Exception as e:
            self.logger.error(f"Error managing user {username}: {str(e)}")
            return None, str(e)
    
    def manage_group(self, action, groupname, options=None):
        """Manage groups - create, modify, delete"""
        if options is None:
            options = {}
            
        try:
            if action == "create":
                # Simulate group creation
                gid = options.get("gid", random.randint(1000, 9999))
                
                self.logger.info(f"Created group: {groupname} with GID:{gid}")
                return f"Group {groupname} created successfully", None
                
            elif action == "modify":
                # Simulate group modification
                changes = []
                if "new_name" in options:
                    changes.append(f"name → {options['new_name']}")
                if "gid" in options:
                    changes.append(f"GID → {options['gid']}")
                    
                self.logger.info(f"Modified group: {groupname} with changes: {changes}")
                return f"Group {groupname} modified successfully", None
                
            elif action == "delete":
                # Simulate group deletion
                self.logger.info(f"Deleted group: {groupname}")
                return f"Group {groupname} deleted successfully", None
                
            else:
                return None, f"Unknown action: {action}"
                
        except Exception as e:
            self.logger.error(f"Error managing group {groupname}: {str(e)}")
            return None, str(e)
    
    def set_permissions(self, path, mode=None, owner=None, group=None):
        """Set permissions on files and directories"""
        try:
            changes = []
            
            if mode is not None:
                # Simulate chmod
                changes.append(f"mode changed to {mode}")
                
            if owner is not None:
                # Simulate chown
                changes.append(f"owner changed to {owner}")
                
            if group is not None:
                # Simulate chgrp
                changes.append(f"group changed to {group}")
                
            if changes:
                self.logger.info(f"Changed permissions on {path}: {', '.join(changes)}")
                return f"Successfully changed permissions on {path}", None
            else:
                return None, "No permission changes specified"
                
        except Exception as e:
            self.logger.error(f"Error setting permissions on {path}: {str(e)}")
            return None, str(e)
    
    def list_users(self):
        """Returns a list of all users with details appropriate for senior admin"""
        try:
            # In a real environment, would parse /etc/passwd
            # For the demo, using simulation
            passwd_content = self._simulate_passwd_file()
            users = []
            
            for line in passwd_content.splitlines():
                if line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        password = parts[1]
                        uid = parts[2]
                        gid = parts[3]
                        comment = parts[4]
                        home = parts[5]
                        shell = parts[6]
                        
                        users.append({
                            'username': username,
                            'password': password,
                            'uid': uid,
                            'gid': gid,
                            'comment': comment,
                            'home': home,
                            'shell': shell
                        })
            
            return users, None
        except Exception as e:
            self.logger.error(f"Error listing users: {str(e)}")
            return None, str(e)
    
    def list_groups(self, with_members=True):
        """Returns a list of all groups with members if requested"""
        try:
            # In a real environment, would parse /etc/group
            # For the demo, using simulation
            group_content = self._simulate_group_file()
            groups = []
            
            for line in group_content.splitlines():
                if line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        group_name = parts[0]
                        password = parts[1]
                        gid = parts[2]
                        members = parts[3].split(',') if parts[3] else []
                        
                        group_info = {
                            'name': group_name,
                            'password': password,
                            'gid': gid
                        }
                        
                        if with_members:
                            group_info['members'] = members
                            
                        groups.append(group_info)
            
            return groups, None
        except Exception as e:
            self.logger.error(f"Error listing groups: {str(e)}")
            return None, str(e)
    
    def check_filesystem_usage(self):
        """Returns filesystem usage statistics"""
        try:
            # Simulate df -h output
            usage = [
                {
                    'filesystem': '/dev/sda1',
                    'size': '50G',
                    'used': '15G',
                    'available': '33G',
                    'use_percent': '32%',
                    'mount_point': '/'
                },
                {
                    'filesystem': '/dev/sdb1',
                    'size': '1T',
                    'used': '200G',
                    'available': '750G',
                    'use_percent': '21%',
                    'mount_point': '/data'
                }
            ]
            return usage, None
        except Exception as e:
            self.logger.error(f"Error checking filesystem usage: {str(e)}")
            return None, str(e)
    
    # Simulation methods
    def _simulate_passwd_file(self):
        """Simulate the content of /etc/passwd file for senior admin"""
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
senior:x:1001:1001:Senior Admin:/home/senior:/bin/bash
test1:x:1002:1002:Test User 1:/home/test1:/bin/bash
test2:x:1003:1003:Test User 2:/home/test2:/bin/bash"""

    def _simulate_group_file(self):
        """Simulate the content of /etc/group file for senior admin"""
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
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:junior,senior
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
input:x:104:
crontab:x:105:
syslog:x:106:
messagebus:x:107:
netdev:x:108:
mlocate:x:109:
ssh:x:110:
uuidd:x:111:
avahi-autoipd:x:112:
bluetooth:x:113:
rtkit:x:114:
whoopsie:x:117:
scanner:x:118:saned
saned:x:119:
pulse:x:120:
pulse-access:x:121:
avahi:x:122:
colord:x:123:
docker:x:999:junior,senior
junior:x:1000:
senior:x:1001:
test1:x:1002:
test2:x:1003:
development:x:1004:test1,test2
devops:x:1005:senior,test1"""

    def _simulate_user_management(self, action, command):
        """Simulate user management commands"""
        parts = command.split()
        if len(parts) < 2:
            return "Invalid command format"
            
        if action == "add":
            username = parts[-1]
            return f"User {username} added successfully"
        elif action == "modify":
            for i, part in enumerate(parts):
                if part == "-l" and i+1 < len(parts):
                    return f"User {parts[i+1]} modified successfully"
            return "User modified successfully"
        elif action == "delete":
            username = parts[-1]
            return f"User {username} deleted successfully"
        else:
            return f"Unknown action: {action}"

    def _simulate_group_management(self, action, command):
        """Simulate group management commands"""
        parts = command.split()
        if len(parts) < 2:
            return "Invalid command format"
            
        if action == "add":
            groupname = parts[-1]
            return f"Group {groupname} added successfully"
        elif action == "modify":
            for i, part in enumerate(parts):
                if part == "-n" and i+1 < len(parts):
                    return f"Group renamed to {parts[i+1]} successfully"
            return "Group modified successfully"
        elif action == "delete":
            groupname = parts[-1]
            return f"Group {groupname} deleted successfully"
        else:
            return f"Unknown action: {action}"

    def _simulate_permission_change(self, change_type, command):
        """Simulate permission change commands (chmod, chown, chgrp)"""
        parts = command.split()
        if len(parts) < 3:
            return "Invalid command format"
            
        target = parts[-1]
        
        if change_type == "mode":
            mode = parts[1]
            return f"Changed mode of {target} to {mode}"
        elif change_type == "owner":
            owner = parts[1]
            return f"Changed owner of {target} to {owner}"
        elif change_type == "group":
            group = parts[1]
            return f"Changed group of {target} to {group}"
        else:
            return f"Unknown change type: {change_type}"