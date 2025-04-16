import sys
import os
import logging
from tkinter import messagebox

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_dependencies():
    try:
        import tkinter
        import docker
        import paramiko
    except ImportError as e:
        logger.error(f"Missing dependency: {str(e)}")
        messagebox.showerror(
            "Missing Dependencies",
            f"Required packages are missing:\n{str(e)}\nPlease run: pip install -r requirements.txt"
        )
        sys.exit(1)

def check_docker_permissions():
    try:
        docker_socket = "/var/run/docker.sock"
        if not os.path.exists(docker_socket):
            raise FileNotFoundError("Docker socket not found. Is Docker installed and running?")

        if not os.access(docker_socket, os.R_OK | os.W_OK):
            raise PermissionError("Permission denied to access Docker socket. Join 'docker' group or use sudo.")

        import docker
        docker.from_env().ping()
    except Exception as e:
        logger.error(f"Docker check failed: {str(e)}")
        messagebox.showerror("Docker Error", str(e))
        sys.exit(1)

def initialize_application():
    try:
        import tkinter as tk
        from src.gui.login_window import LoginWindow
        from src.backend.auth_backend import AuthBackend

        root = tk.Tk()
        root.title("Linux GUI Manager")
        root.geometry("800x600")

        auth_backend = AuthBackend()

        class MainApplication:
            def __init__(self, root):
                self.root = root
                self.auth_backend = auth_backend
                self.show_login()

            def show_login(self):
                for widget in self.root.winfo_children():
                    widget.destroy()
                LoginWindow(self.root, self.auth_backend, self.on_login_success).pack(fill=tk.BOTH, expand=True)

            def on_login_success(self, username, role):
                for widget in self.root.winfo_children():
                    widget.destroy()
                try:
                    if role == "junior":
                        from src.gui.junior_dashboard import JuniorDashboard
                        dashboard = JuniorDashboard(self.root, self.show_login)
                    elif role == "senior":
                        from src.gui.senior_dashboard import SeniorDashboard
                        dashboard = SeniorDashboard(self.root, self.show_login)
                    dashboard.pack(fill=tk.BOTH, expand=True)
                except Exception as e:
                    logger.error(f"Failed to load {role} dashboard: {e}")
                    messagebox.showerror("Error", f"Dashboard error: {e}")
                    self.show_login()

            def run(self):
                self.root.mainloop()

        app = MainApplication(root)
        app.run()

    except Exception as e:
        logger.critical(f"Initialization failed: {str(e)}")
        messagebox.showerror("Fatal Error", f"Initialization failed:\n{str(e)}\nSee logs/app.log for details.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        logger.info("Initializing application")
        check_dependencies()
        check_docker_permissions()
        initialize_application()
    except KeyboardInterrupt:
        logger.info("Application shutdown by user")
        sys.exit(0)
