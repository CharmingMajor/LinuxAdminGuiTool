#!/usr/bin/env python3
import sys
import os
import logging
import structlog
from pathlib import Path
from PySide6.QtWidgets import QApplication, QMainWindow, QMessageBox
from PySide6.QtCore import Qt
import traceback

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# TODO: Move logging config to a separate module eventually
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = structlog.get_logger(__name__)

# Set up logging
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

from src.ui.views.login import LoginWindow
from src.ui.views.senior_dashboard import SeniorDashboard
from src.ui.views.junior_dashboard import JuniorDashboard
from src.ui.dialogs.connect_dialog import ConnectDialog
from src.utils.remote_connection import RemoteConnection

class LinuxAdminGUI:
    """Main application class"""
    
    def __init__(self):
        # Fix scaling issues on high-DPI screens
        os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"
        os.environ["QT_SCALE_FACTOR"] = "1"
        
        # Init logging
        self.logger = setup_logging()
        
        # Init app
        self.app = QApplication.instance()
        if not self.app:
            self.app = QApplication(sys.argv)
            
        # App state vars
        self.current_role = None
        self.login_window = None
        self.connect_dialog = None
        self.dashboard = None
        self.remote = None
        
        # Might consider making this optional for debugging
        self.setup_exception_handling()
        
        # Fire up the UI
        self.setup_ui()
        
    def setup_exception_handling(self):
        """Set up global exception handling"""
        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
            
            self.logger.critical("Uncaught exception", 
                               exc_info=(exc_type, exc_value, exc_traceback))
            
        sys.excepthook = handle_exception
        
    def setup_ui(self):
        """Set up the user interface"""
        self.login_window = LoginWindow()
        self.login_window.login_successful.connect(self.on_login)
        self.login_window.show()
        
    def on_login(self, role):
        # Store the role when login is successful
        self.current_role = role  
        self.login_window.hide()
        self.show_connect_dialog()
        
    def show_connect_dialog(self):
        """Show the connection dialog"""
        try:
            self.connect_dialog = ConnectDialog()
            self.connect_dialog.connection_established.connect(self.on_connection_established)
            self.connect_dialog.show()
            
        except Exception as e:
            self.logger.error(f"Failed to show connection dialog: {str(e)}")
            QMessageBox.critical(None, "Error", f"Failed to show connection dialog: {str(e)}")
            
    def on_connection_established(self, remote: RemoteConnection):
        """Handle successful remote connection"""
        try:
            # Create the right dashboard based on user role
            if self.current_role == "senior":
                self.dashboard = SeniorDashboard(remote)
                # Set the current username for the backend
                self.dashboard.backend.set_current_user("senior")
            else:
                self.dashboard = JuniorDashboard(remote)
                # Set the current username for the backend
                self.dashboard.backend.set_current_user("junior")
            
            # Connect logout signal
            self.dashboard.logout_requested.connect(self.handle_logout)
                
            self.dashboard.show()
            if self.connect_dialog:
                self.connect_dialog.close()
            if self.login_window:
                self.login_window.close()
            
        except Exception as e:
            # This error happens sometimes with older Qt versions
            self.logger.error(f"Failed to create dashboard: {str(e)}")
            self.logger.critical("Uncaught exception", exc_info=True)
            QMessageBox.critical(None, "Error", f"Failed to create dashboard: {str(e)}")
            
    def handle_logout(self):
        """Handle logout request"""
        try:
            if self.dashboard:
                # Disconnect signals before closing
                self.dashboard.logout_requested.disconnect(self.handle_logout)
                self.dashboard.close()
                self.dashboard = None
            
            # Clear the remote connection if it exists
            if hasattr(self, 'remote') and self.remote:
                self.remote = None
            
            # Show login window again - but don't create a new one if it exists
            if self.login_window and not self.login_window.isVisible():
                self.login_window.show()
            else:
                self.login_window = LoginWindow()
                self.login_window.login_successful.connect(self.on_login)
                self.login_window.show()
            
        except Exception as e:
            self.logger.error(f"Failed to handle logout: {str(e)}")
            QMessageBox.critical(None, "Error", f"Failed to handle logout: {str(e)}")
            
    def run(self):
        """Start the application"""
        return self.app.exec()

# Quick dependency check - not perfect but catches the main ones
def check_dependencies():
    """Check if all required dependencies are installed"""
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

if __name__ == "__main__":
    # May eventually replace this with proper environment detection
    # but works fine for now
    if not check_dependencies():
        sys.exit(1)
        
    app = LinuxAdminGUI()
    sys.exit(app.run())
