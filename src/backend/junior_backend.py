import subprocess
import logging
import re

class JuniorBackend:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Commands that junior admin is allowed to execute
        self.allowed_commands = [
            "top",
            "ls",
            "df -h",
            "free -m",
            "cat /etc/passwd",
            "cat /etc/group",
            "ls -l /home",
            "who",
            "whoami",
            "ps aux"
        ]
    
    def execute_command(self, command):
        """Execute an allowed command and return the result"""
        # Validate command is in allowed list
        if not any(command.startswith(allowed) for allowed in self.allowed_commands):
            self.logger.warning(f"Junior admin attempted unauthorized command: {command}")
            return None, "Command not permitted for junior admin"
        
        # Simulate command execution for safety in demo environment
        try:
            # In a real environment, you would execute the command on the target system
            # For demo purposes, we'll simulate the response
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
                # For other commands, provide a simple simulation
                return f"Simulated output for: {command}", None
        except Exception as e:
            self.logger.error(f"Error executing command: {str(e)}")
            return None, str(e)
    
    def list_users(self):
        """Return a list of users in the system"""
        try:
            # Simulate reading /etc/passwd
            passwd_content = self._simulate_passwd_file()
            users = []
            
            for line in passwd_content.splitlines():
                if line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = parts[2]
                        gid = parts[3]
                        home = parts[5]
                        shell = parts[6]
                        
                        users.append({
                            'username': username,
                            'uid': uid,
                            'gid': gid,
                            'home': home,
                            'shell': shell
                        })
            
            return users, None
        except Exception as e:
            self.logger.error(f"Error listing users: {str(e)}")
            return None, str(e)
    
    def list_groups(self):
        """Return a list of groups in the system"""
        try:
            # Simulate reading /etc/group
            group_content = self._simulate_group_file()
            groups = []
            
            for line in group_content.splitlines():
                if line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        group_name = parts[0]
                        gid = parts[2]
                        members = parts[3].split(',') if parts[3] else []
                        
                        groups.append({
                            'name': group_name,
                            'gid': gid,
                            'members': members
                        })
            
            return groups, None
        except Exception as e:
            self.logger.error(f"Error listing groups: {str(e)}")
            return None, str(e)
    
    def get_file_permissions(self, path):
        """View file permissions, read-only access"""
        try:
            # Simulate ls -la for the path
            # In a real environment, would execute ls -la on the path
            return f"Simulated file permissions for {path}", None
        except Exception as e:
            self.logger.error(f"Error getting file permissions: {str(e)}")
            return None, str(e)
    
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
senior:x:1001:"""

    def _simulate_home_directory(self):
        """Simulate the content of ls -l /home"""
        return """total 16
drwxr-xr-x 2 junior junior 4096 Oct 15 08:32 junior
drwxr-xr-x 2 senior senior 4096 Oct 15 08:35 senior"""

    def _simulate_process_list(self):
        """Simulate the output of ps aux"""
        return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 225792  9288 ?        Ss   Oct15   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Oct15   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   Oct15   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   Oct15   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   Oct15   0:00 [kworker/0:0H-kblockd]
root         9  0.0  0.0      0     0 ?        I<   Oct15   0:00 [mm_percpu_wq]
root        10  0.0  0.0      0     0 ?        S    Oct15   0:00 [ksoftirqd/0]
root        11  0.0  0.0      0     0 ?        I    Oct15   0:01 [rcu_sched]
root        12  0.0  0.0      0     0 ?        S    Oct15   0:00 [migration/0]
root        13  0.0  0.0      0     0 ?        S    Oct15   0:00 [cpuhp/0]
root        14  0.0  0.0      0     0 ?        S    Oct15   0:00 [cpuhp/1]
root        15  0.0  0.0      0     0 ?        S    Oct15   0:00 [migration/1]
root        16  0.0  0.0      0     0 ?        S    Oct15   0:00 [ksoftirqd/1]
root        18  0.0  0.0      0     0 ?        I<   Oct15   0:00 [kworker/1:0H-kblockd]
root        19  0.0  0.0      0     0 ?        S    Oct15   0:00 [kdevtmpfs]
root        20  0.0  0.0      0     0 ?        I<   Oct15   0:00 [netns]
root        21  0.0  0.0      0     0 ?        S    Oct15   0:00 [rcu_tasks_kthre]
root        22  0.0  0.0      0     0 ?        S    Oct15   0:00 [kauditd]
root        23  0.0  0.0      0     0 ?        S    Oct15   0:00 [khungtaskd]
root        24  0.0  0.0      0     0 ?        S    Oct15   0:00 [oom_reaper]
sshd      1298  0.0  0.1  72296  5728 ?        Ss   Oct15   0:00 /usr/sbin/sshd -D
root      1299  0.0  0.0  30624  3232 ?        Ss   Oct15   0:00 bash
junior    1454  0.0  0.1  72096  5204 ?        S    08:32   0:00 sshd: junior@pts/0
junior    1455  0.0  0.0  30624  3232 pts/0    Ss   08:32   0:00 -bash
senior    1580  0.0  0.1  72096  5204 ?        S    08:35   0:00 sshd: senior@pts/1
senior    1581  0.0  0.0  30624  3232 pts/1    Ss   08:35   0:00 -bash
root      1680  0.0  0.0  38384  3680 ?        Ss   08:39   0:00 /lib/systemd/systemd-logind
root      1729  0.0  0.0  14856  1968 pts/1    S+   08:56   0:00 top"""