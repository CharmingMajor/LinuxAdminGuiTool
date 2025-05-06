#!/usr/bin/env python3
import sys
import os
import logging
import tkinter as tk
from tkinter import messagebox
import traceback

# Set up logging
def setup_logging():
    """Set up logging configuration"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/app.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# Create logger
logger = setup_logging()

def check_docker():
    """Check if Docker is running and accessible"""
    try:
        from src.backend.virtual_pc_backend import VirtualPCManager
        manager = VirtualPCManager()
        manager.list_containers()
        logger.info("Docker check passed")
        return True
    except Exception as e:
        logger.warning(f"Docker check failed: {str(e)}")
        # Don't raise the exception, just return False
        return False

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import docker
        import paramiko
        import fabric
        
        # Check if tkinter is available
        try:
            import tkinter as tk
            tk.Tk().withdraw()
            logger.info("All dependencies are installed")
            return True
        except Exception as e:
            logger.error(f"Tkinter is not properly installed: {str(e)}")
            messagebox.showerror("Missing Dependency", 
                               "Tkinter is not properly installed.\n"
                               "Please install the python3-tkinter package using your system's package manager.")
            return False
            
    except ImportError as e:
        logger.error(f"Missing dependency: {str(e)}")
        messagebox.showerror("Missing Dependency", f"Missing dependency: {str(e)}\n"
                           "Please run 'pip install -r requirements.txt' to install all dependencies.")
        return False

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
                    traceback.print_exc()  # Print full stack trace to console
                    messagebox.showerror("Error", f"Dashboard error: {e}")
                    self.show_login()

            def run(self):
                self.root.mainloop()

        app = MainApplication(root)
        app.run()

    except Exception as e:
        logger.critical(f"Initialization failed: {str(e)}")
        traceback.print_exc()  # Print full stack trace to console
        messagebox.showerror("Fatal Error", f"Initialization failed:\n{str(e)}\nSee logs/app.log for details.")
        sys.exit(1)

if __name__ == "__main__":
    logger.info("Initializing application")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check Docker but continue even if it fails
    docker_available = check_docker()
    if not docker_available:
        messagebox.showwarning("Docker Warning", 
                              "Docker is not available or not properly configured.\n"
                              "Virtual PC features will be disabled.")
    
    # Initialize main application
    initialize_application()
