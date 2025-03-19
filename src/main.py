import sys
import os

# Add the project root directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from src.gui.login_window import LoginWindow
from src.gui.junior_dashboard import JuniorDashboard
from src.gui.senior_dashboard import SeniorDashboard
from src.backend.auth_backend import AuthBackend

class MainApplication:
    def __init__(self, root):
        """
        Initialize the main application.
        """
        self.root = root
        self.root.title("Linux GUI Manager")
        self.root.geometry("800x600")

        # Initialize the authentication backend
        self.auth_backend = AuthBackend()

        # Start with the login window
        self.show_login_window()

    def show_login_window(self):
        """
        Display the login window.
        """
        # Clear the current window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create and display the login window
        self.login_window = LoginWindow(self.root, self.auth_backend, self.on_login_success)
        self.login_window.pack(fill=tk.BOTH, expand=True)

    def on_login_success(self, username, role):
        """
        Callback function when login is successful.
        """
        # Clear the current window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Launch the appropriate dashboard based on the user's role
        if role == "junior":
            self.junior_dashboard = JuniorDashboard(self.root, self.show_login_window)
            self.junior_dashboard.pack(fill=tk.BOTH, expand=True)
        elif role == "senior":
            self.senior_dashboard = SeniorDashboard(self.root, self.show_login_window)
            self.senior_dashboard.pack(fill=tk.BOTH, expand=True)

    def run(self):
        """
        Run the application.
        """
        self.root.mainloop()

if __name__ == "__main__":
    # Initialize the Tkinter root window
    root = tk.Tk()

    # Create and run the main application
    app = MainApplication(root)
    app.run()