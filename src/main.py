#!/usr/bin/env python3

# Import necessary libraries for the application
import sys
import os
import logging
import structlog
from pathlib import Path
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PySide6.QtCore import Qt
import traceback

# Add the project root to Python path so we can use absolute imports
sys.path.insert(0, str(Path(__file__).parent.parent))

logger = structlog.get_logger(__name__)

# Set up logging for tracking errors and user actions
def setup_logging():
    """Set up logging configuration"""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # I tried different log formats, this one seems most readable
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'app.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# Import our application components
from src.ui.views.login import LoginWindow
from src.ui.views.senior_dashboard import SeniorDashboard
from src.ui.views.junior_dashboard import JuniorDashboard
from src.ui.dialogs.connect_dialog import ConnectDialog
from src.utils.remote_connection import RemoteConnection

class LinuxAdminGUI:
    """Main application class - this is the heart of our program"""
    
    def __init__(self):
        # Fix scaling issues on high-DPI screens - this makes the UI look good on modern displays
        os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
        os.environ["QT_SCALE_FACTOR"] = "1"
        
        # Set up our logging system to track errors and events
        self.logger = setup_logging()
        
        # Initialize the Qt application
        self.app = QApplication.instance()
        if not self.app:
            self.app = QApplication(sys.argv)

        # These variables will hold our application state
        self.current_username = None # Added to store logged-in username
        self.current_role = None  # Will be 'junior' or 'senior'
        self.login_window = None  # The login screen
        self.connect_dialog = None  # The SSH connection dialog
        self.dashboard = None  # The main dashboard (either junior or senior)
        self.remote = None  # Our SSH connection object
        
        # Set up global exception handling so the app doesn't crash unexpectedly
        self.setup_exception_handling()
        
        # Start by showing the login window
        self.setup_ui()
        
    def setup_exception_handling(self):
        """Set up global exception handling to prevent crashes"""
        def handle_exception(exc_type, exc_value, exc_traceback):
            # Let keyboard interrupts through normally
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            # Log any other exception
            self.logger.critical("Uncaught exception", 
                               exc_info=(exc_type, exc_value, exc_traceback))
            
        sys.excepthook = handle_exception
        
    def setup_ui(self):
        """Start the application UI by showing the login window"""
        self.login_window = LoginWindow()
        # Connect the login signal so we know when login is successful
        self.login_window.login_successful.connect(self.on_login)
        self.login_window.show()
        
    def on_login(self, username: str, role: str):
        # Store the user's role and username when they successfully log in
        self.current_username = username
        self.current_role = role  
        self.login_window.hide()
        # Now show the connection dialog to connect to a remote system
        self.show_connect_dialog()
        
    def show_connect_dialog(self):
        """Show the dialog to connect to a remote system via SSH"""
        try:
            self.connect_dialog = ConnectDialog()
            # Connect the signal so we know when SSH connection is established
            self.connect_dialog.connection_established.connect(self.on_connection_established)
            self.connect_dialog.show()
            
        except Exception as e:
            self.logger.error(f"Failed to show connection dialog: {str(e)}")
            QMessageBox.critical(None, "Error", f"Failed to show connection dialog: {str(e)}")
            
    def on_connection_established(self, remote: RemoteConnection):
        """When we successfully connect to a remote system, load the appropriate dashboard"""
        try:
            self.remote = remote
            # Create either senior or junior dashboard based on user's role
            if self.current_role == "senior":
                self.dashboard = SeniorDashboard(remote, username=self.current_username)
            else:
                self.dashboard = JuniorDashboard(remote, username=self.current_username)
            # Connect logout signal
            self.dashboard.logout_requested.connect(self.handle_logout)
            # Connect switch role signal for demo/testing
            self.dashboard.switch_role_requested.connect(self.handle_switch_role)
            self.dashboard.show()
            if self.connect_dialog:
                self.connect_dialog.close()
            if self.login_window:
                self.login_window.close()
        except Exception as e:
            self.logger.error(f"Failed to create dashboard: {str(e)}")
            self.logger.critical("Uncaught exception", exc_info=True)
            QMessageBox.critical(None, "Error", f"Failed to create dashboard: {str(e)}")

    def handle_logout(self):
        """Handle user logout by closing the dashboard and showing login window again"""
        try:
            if self.dashboard:
                self.dashboard.logout_requested.disconnect(self.handle_logout)
                self.dashboard.switch_role_requested.disconnect(self.handle_switch_role)
                self.dashboard.close()
                self.dashboard = None
            
            if hasattr(self, 'remote') and self.remote:
                self.remote = None
            
            if self.login_window and not self.login_window.isVisible():
                self.login_window.show()
            else:
                self.login_window = LoginWindow()
                self.login_window.login_successful.connect(self.on_login)
                self.login_window.show()
            
        except Exception as e:
            self.logger.error(f"Failed to handle logout: {str(e)}")
            QMessageBox.critical(None, "Error", f"Failed to handle logout: {str(e)}")
            
    def handle_switch_role(self):
        """Switch between senior and junior dashboards - useful for demo and testing"""
        self.logger.info(f"Attempting to switch role from {self.current_role}")
        try:
            if self.dashboard:
                self.logger.info("Closing existing dashboard.")
                self.dashboard.logout_requested.disconnect(self.handle_logout)
                self.dashboard.switch_role_requested.disconnect(self.handle_switch_role)
                
                current_backend = self.dashboard.backend
                if hasattr(current_backend, 'cleanup'):
                    self.logger.info("Cleaning up current backend.")
                    current_backend.cleanup() # This should disconnect the remote connection
                
                self.dashboard.close()
                self.dashboard = None
            self.logger.info("Closed existing dashboard.")

            # Toggle the role for the next login/connection attempt
            if self.current_role == "senior":
                self.current_role = "junior"
                self.logger.info(f"Role toggled to: {self.current_role}. Will show connection dialog.")
            else: # Was junior or None
                self.current_role = "senior"
                self.logger.info(f"Role toggled to: {self.current_role}. Will show connection dialog.")
            
            # Reset remote object as the previous one is disconnected by cleanup
            self.remote = None 

            # Re-show the connection dialog. on_connection_established will create the new dashboard.
            self.show_connect_dialog()
            self.logger.info(f"Connection dialog initiated for {self.current_role} role.")

        except Exception as e:
            self.logger.error(f"Failed to switch role: {str(e)}", exc_info=True)
            QMessageBox.critical(None, "Error", f"Failed to switch role: {str(e)}")
            
    def run(self):
        """Start the application main loop"""
        return self.app.exec()

# Just a quick check for deps - better than crashing with import errors
def check_dependencies():
    """Check if all required dependencies are installed before starting"""
    try:
        import docker
        import paramiko
        import psutil
        import PySide6
        return True
    except ImportError as e:
        print(f"Missing dependency: {str(e)}")
        print("Please run 'pip install -r requirements.txt' to install all dependencies.")
        return False

# Maybe add command line args later
if __name__ == "__main__":
    if not check_dependencies():
        sys.exit(1)
        
    # Create our main application object and run it
    app = LinuxAdminGUI()
    sys.exit(app.run())
