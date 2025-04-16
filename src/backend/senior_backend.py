class SeniorBackend:
    def __init__(self):
        self.allowed_commands = [
            "htop",
            "docker ps",
            "systemctl",
            "iptables -L"
        ]
    
    def execute_command(self, command):
        if command not in self.allowed_commands:
            return None, "Command not permitted for senior admin"
        
        # Simulate command execution
        try:
            # Here you would typically execute the command using subprocess or similar
            output = f"Executed: {command}"
            return output, None
        except Exception as e:
            return None, str(e)