class JuniorBackend:
    def __init__(self):
        self.allowed_commands = [
            "top",
            "ls",
            "df -h",
            "free -m"
        ]
    
    def execute_command(self, command):
        if command not in self.allowed_commands:
            return None, "Command not permitted for junior admin"