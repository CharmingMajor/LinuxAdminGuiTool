# Authentication logic
# TODO: Implement authentication logic

class AuthBackend:
    def __init__(self):
        # Simulated user database
        self.users = {
            "junior": {"password": "junior123", "role": "junior"},
            "senior": {"password": "senior123", "role": "senior"},
        }

    def authenticate(self, username, password, ip):
        if username in self.users and self.users[username]["password"] == password:
            return True, self.users[username]["role"]
        return False, None