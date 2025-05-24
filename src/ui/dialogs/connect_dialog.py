from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, 
    QLabel, QLineEdit, QComboBox, QPushButton, QFrame, QMessageBox, QCheckBox, QProgressBar, QFileDialog)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QIcon, QFont
from pathlib import Path
from typing import Optional, Dict, List
import structlog
from src.utils.remote_connection import RemoteConnection
from src.backend.connection_backend import ConnectionBackend
from src.ui.utils.theme_manager import ThemeManager

logger = structlog.get_logger(__name__)

class ConnectDialog(QDialog):
    """Dialog for establishing SSH connections to remote servers
    
    This dialog provides a user interface for:
    1. Entering connection details (hostname, username, password/key)
    2. Loading saved connections
    3. Testing and establishing connections
    4. Saving connection details for future use
    
    The dialog uses the RemoteConnection class to handle the actual SSH connection.
    """
    
    # Signal emitted when connection is established
    connection_established = Signal(RemoteConnection)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        # Initialize connection backend
        self.connection_backend = ConnectionBackend()
        # Get theme manager for consistent styling
        self.theme_manager = ThemeManager()
        # Set up UI components
        self.setup_ui()
        # Connect signal handlers
        self.setup_signals()
        # Load saved connections from database
        self.load_saved_connections()
        self.apply_styles() # Apply theme styles
        
    def setup_ui(self):
        """Set up the dialog UI components
        
        Creates a form with:
        - Server/host address field
        - Username field
        - Password field with show/hide option
        - SSH key option with file picker
        - Port number field
        - Connection name for saving
        - Buttons for connecting, testing, and canceling
        """
        # Set window properties
        self.setWindowTitle("Connect to Remote Server")
        self.setMinimumWidth(500)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # Header section
        self.header_label = QLabel("Connect to Remote Server")
        main_layout.addWidget(self.header_label)
        
        # Description
        self.description_label = QLabel(
            "Enter the connection details for the remote server you want to manage."
        )
        self.description_label.setWordWrap(True)
        main_layout.addWidget(self.description_label)
        
        # Form layout for connection fields
        self.form_frame = QFrame()
        self.form_frame.setFrameShape(QFrame.Shape.StyledPanel)
        form_layout = QGridLayout(self.form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(10)
        
        # Saved Connections dropdown
        self.saved_connections_label = QLabel("Saved Connections:")
        form_layout.addWidget(self.saved_connections_label, 0, 0)
        self.saved_connections = QComboBox()
        self.saved_connections.setMinimumHeight(36)
        self.saved_connections.addItem("-- Select a saved connection --")

        # Layout for saved connections dropdown and delete button
        saved_conn_layout = QHBoxLayout()
        saved_conn_layout.addWidget(self.saved_connections, 1) # Give dropdown more stretch
        
        self.delete_profile_button = QPushButton("Delete")
        self.delete_profile_button.setToolTip("Delete selected profile")
        self.delete_profile_button.setEnabled(False) # Disabled by default
        self.delete_profile_button.setObjectName("delete-profile-button")
        saved_conn_layout.addWidget(self.delete_profile_button)
        
        form_layout.addLayout(saved_conn_layout, 0, 1, 1, 2)
        
        # Server/host address
        self.server_label = QLabel("Server:")
        form_layout.addWidget(self.server_label, 1, 0)
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("hostname or IP address")
        self.server_input.setMinimumHeight(36)
        form_layout.addWidget(self.server_input, 1, 1, 1, 2)
        
        # Username
        self.username_label = QLabel("Username:")
        form_layout.addWidget(self.username_label, 2, 0)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("e.g. admin")
        self.username_input.setMinimumHeight(36)
        form_layout.addWidget(self.username_input, 2, 1, 1, 2)
        
        # Password input (initially visible)
        self.password_label = QLabel("Password:")
        form_layout.addWidget(self.password_label, 3, 0)
        self.password_container = QFrame()
        password_layout = QHBoxLayout(self.password_container)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(10)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setMinimumHeight(36)
        password_layout.addWidget(self.password_input)
        
        # Show/hide password button
        self.show_password_btn = QPushButton("Show")
        self.show_password_btn.setFixedWidth(60)
        self.show_password_btn.setMinimumHeight(36)
        password_layout.addWidget(self.show_password_btn)
        
        form_layout.addWidget(self.password_container, 3, 1, 1, 2)
        
        # Port number
        self.port_label = QLabel("Port:")
        self.port_input = QLineEdit("22")  # Default SSH port
        self.port_input.setMinimumHeight(36)
        form_layout.addWidget(self.port_label, 4, 0)
        form_layout.addWidget(self.port_input, 4, 1, 1, 2)
        
        # Connection name for saving
        self.connection_name_label = QLabel("Connection Name:")
        form_layout.addWidget(self.connection_name_label, 5, 0)
        self.connection_name = QLineEdit()
        self.connection_name.setPlaceholderText("e.g. Production Server")
        self.connection_name.setMinimumHeight(36)
        form_layout.addWidget(self.connection_name, 5, 1, 1, 2)
        
        # Save connection checkbox
        self.save_connection = QCheckBox("Save connection details")
        self.save_connection.setChecked(True)
        form_layout.addWidget(self.save_connection, 6, 1)
        
        # Progress bar (initially hidden)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        form_layout.addWidget(self.progress_bar, 7, 0, 1, 3)
        
        main_layout.addWidget(self.form_frame)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)
        
        self.test_button = QPushButton("Test Connection")
        self.test_button.setMinimumHeight(40)
        
        self.connect_button = QPushButton("Connect")
        self.connect_button.setMinimumHeight(40)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setMinimumHeight(40)
        
        buttons_layout.addStretch(1)
        buttons_layout.addWidget(self.test_button)
        buttons_layout.addWidget(self.connect_button)
        buttons_layout.addWidget(self.cancel_button)
        buttons_layout.addStretch(1)
        
        main_layout.addLayout(buttons_layout)
        
    def setup_signals(self):
        """Connect UI signals to their handler methods
        
        Handles button clicks, dropdown changes, and other user interactions.
        """
        # Button connections
        self.cancel_button.clicked.connect(self.reject)
        self.connect_button.clicked.connect(self.attempt_connection)
        self.test_button.clicked.connect(self.test_connection)
        self.show_password_btn.clicked.connect(self.toggle_password_visibility)
        
        # Dropdown selections
        self.saved_connections.currentIndexChanged.connect(self.load_connection)
        # Delete profile button
        if hasattr(self, 'delete_profile_button'):
             self.delete_profile_button.clicked.connect(self.delete_selected_profile)
        
    def update_auth_ui(self):
        """Update the UI based on the selected authentication method
        
        Switches between password and SSH key fields depending on
        the authentication method selected by the user.
        """
        self.password_container.setVisible(True)
            
    def toggle_password_visibility(self):
        """Toggle password field between visible and hidden text"""
        if self.password_input.echoMode() == QLineEdit.EchoMode.Password:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_password_btn.setText("Hide")
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_password_btn.setText("Show")
            
    def load_saved_connections(self):
        """Load saved connections from the backend and populate the dropdown."""
        self.saved_connections.clear() # Clear existing items first
        self.saved_connections.addItem("-- Select a saved connection --")
        try:
            connections = self.connection_backend.get_saved_connections()
            if connections:
                for conn_profile in connections: # Iterate through profile dicts
                    self.saved_connections.addItem(conn_profile['name'])
        except Exception as e:
            logger.error(f"Error loading saved connections: {str(e)}")
            # Optionally show a message to the user
            # QMessageBox.warning(self, "Load Error", "Could not load saved connections.")
            
    def load_connection(self):
        """Load selected connection details into the form fields"""
        selected_name = self.saved_connections.currentText()
        current_index = self.saved_connections.currentIndex() # Get current index
        
        # If no item is selected (index is -1, currentText is "")
        # OR if the placeholder item is selected
        if current_index == -1 or selected_name == "-- Select a saved connection --":
            self.server_input.clear()
            self.username_input.clear()
            self.password_input.clear() # Clear password field
            self.port_input.setText("22")
            self.connection_name.setText("") # Clear profile name field
            self.save_connection.setChecked(True)
            self.update_auth_ui()
            # Disable delete button if it exists and no profile is selected
            if hasattr(self, 'delete_profile_button'):
                self.delete_profile_button.setEnabled(False)
            return
            
        try:
            # Fetch the full profile data from the backend
            connection_profile = self.connection_backend.get_connection_by_name(selected_name)
            
            if connection_profile:
                self.server_input.setText(connection_profile.get('hostname', ''))
                self.username_input.setText(connection_profile.get('username', ''))
                self.port_input.setText(str(connection_profile.get('port', '22')))
                self.connection_name.setText(connection_profile.get('name', ''))
                
                self.password_input.setText(connection_profile.get('password', '')) # Load password
                
                self.update_auth_ui() # Ensure UI visibility matches loaded auth method
                # Enable delete button if it exists
                if hasattr(self, 'delete_profile_button'):
                    self.delete_profile_button.setEnabled(True)
            else:
                QMessageBox.warning(self, "Load Error", f"Could not load details for '{selected_name}'.")
                if hasattr(self, 'delete_profile_button'):
                    self.delete_profile_button.setEnabled(False)
        except Exception as e:
            logger.error(f"Exception in load_connection for '{selected_name}': {str(e)}")
            QMessageBox.critical(self, "Error", f"An unexpected error occurred while loading '{selected_name}'.")
            if hasattr(self, 'delete_profile_button'):
                self.delete_profile_button.setEnabled(False)
            
    def get_connection_params(self):
        """Gather connection parameters from the UI fields."""
        params = {
            "name": self.connection_name.text().strip(),
            "hostname": self.server_input.text().strip(),
            "port": int(self.port_input.text().strip()),
            "username": self.username_input.text().strip(),
            "auth_method": "Password", # Hardcoded to Password
            "key_path": None, # Hardcoded to None
            "passphrase": None, # Hardcoded to None
            "password": self.password_input.text() # Do not strip password
        }
        return params
    
    def validate_form(self):
        """Validate form inputs before attempting connection
        
        Returns:
            bool: True if validation passes, False otherwise
        """
        # Check required fields
        if not self.server_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Please enter a server hostname or IP address.")
            return False
            
        if not self.username_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Please enter a username.")
            return False
            
        # Validate port number
        try:
            port = int(self.port_input.text().strip() or 22)
            if port < 1 or port > 65535:
                QMessageBox.warning(self, "Validation Error", "Port must be between 1 and 65535.")
                return False
        except ValueError:
            QMessageBox.warning(self, "Validation Error", "Port must be a valid number.")
            return False
            
        # Validate authentication fields
        if not self.password_input.text():
            QMessageBox.warning(self, "Validation Error", "Please enter a password.")
            return False
                
        return True
        
    def test_connection(self):
        """Test connection with current parameters but don't save or emit signal"""
        # Validate form first
        if not self.validate_form():
            return
            
        # Show progress bar during connection attempt
        self.progress_bar.setVisible(True)
        self.connect_button.setEnabled(False)
        self.test_button.setEnabled(False)
        
        # Get connection parameters from form
        params = self.get_connection_params()
        
        try:
            # Create connection object
            connection = RemoteConnection()
            
            # Connect using password authentication (SSH key options removed)
            success = connection.connect(
                hostname=params['hostname'],
                username=params['username'],
                password=params['password'], # Now always present
                port=params['port']
            )
                
            # Hide progress bar
            self.progress_bar.setVisible(False)
            self.connect_button.setEnabled(True)
            self.test_button.setEnabled(True)
            
            # Show result message
            if success:
                QMessageBox.information(self, "Connection Test", "Connection successful!")
                # Close the connection since this is just a test
                connection.close()
            else:
                QMessageBox.warning(self, "Connection Test", f"Connection failed: {connection.last_error}")
                
        except Exception as e:
            # Hide progress bar and show error
            self.progress_bar.setVisible(False)
            self.connect_button.setEnabled(True)
            self.test_button.setEnabled(True)
            QMessageBox.critical(self, "Connection Error", f"An error occurred: {str(e)}")
            
    def attempt_connection(self):
        """Attempt to establish connection with current parameters"""
        if not self.validate_form():
            return
            
        self.progress_bar.setVisible(True)
        self.connect_button.setEnabled(False)
        self.test_button.setEnabled(False)
        
        params = self.get_connection_params()
        
        # Save connection if checkbox is ticked
        if self.save_connection.isChecked() and params.get('name'):
            if not self.connection_backend.save_connection_profile(params):
                # Log or inform user about save failure, but proceed with connection attempt
                logger.warning(f"Failed to save connection profile: {params.get('name')}")
                QMessageBox.warning(self, "Save Failed", "Could not save the connection profile. Please check logs.")
            else:
                # Refresh saved connections dropdown if save was successful
                self.load_saved_connections()
                # Optionally, re-select the newly saved connection if it was a new one
                # self.saved_connections.setCurrentText(params.get('name'))

        try:
            connection = RemoteConnection() # This uses ConnectionBackend internally now
            
            # Connect using password authentication (SSH key options removed)
            success = connection.connect(
                hostname=params['hostname'],
                username=params['username'],
                password=params['password'], # Now always present
                port=params['port']
            )
            
            self.progress_bar.setVisible(False)
            self.connect_button.setEnabled(True)
            self.test_button.setEnabled(True)
            
            if success:
                self.connection_established.emit(connection)
                self.accept() # Close dialog on successful connection
            else:
                QMessageBox.critical(self, "Connection Failed", f"Could not connect to server: {connection.last_error}")
                
        except Exception as e:
            self.progress_bar.setVisible(False)
            self.connect_button.setEnabled(True)
            self.test_button.setEnabled(True)
            logger.error("Connection attempt failed", error=str(e), exc_info=True)
            QMessageBox.critical(self, "Connection Error", f"An unexpected error occurred: {str(e)}")

    def closeEvent(self, event):
        # Handle the close event
        super().closeEvent(event)
        # Optionally, perform any additional cleanup or logging
        logger.info("ConnectDialog closed")

    def apply_styles(self):
        """Apply custom styles to the dialog"""
        theme = self.theme_manager.get_theme_styles()
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
                font-size: {theme['font_size_md']}; /* Use themed medium font size */
            }}
            QLabel#header_label {{
                font-size: {theme['font_size_lg']}; /* Use themed large font size */
                font-weight: bold;
                padding-bottom: 5px;
                color: {theme['text_primary']};
            }}
            QLabel#description_label {{
                font-size: {theme['font_size_sm']}; /* Use themed small font size */
                color: {theme['text_secondary']};
                padding-bottom: 10px;
            }}
            QFrame {{
                background-color: {theme['bg_secondary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
            }}
            QLabel {{
                color: {theme['text_primary']};
                margin-bottom: 2px; /* Add some space below labels */
            }}
            QLineEdit, QComboBox {{
                padding: 8px;
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                min-height: 20px; /* Ensure consistent height */
            }}
            QLineEdit:focus, QComboBox:focus {{
                border-color: {theme['accent_primary']};
            }}
            QPushButton {{
                padding: 8px 16px;
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: {theme['radius_sm']};
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {theme['accent_secondary']};
            }}
            QPushButton:pressed {{
                background-color: {theme['accent_tertiary']};
            }}
            QPushButton#cancel_button {{
                background-color: {theme['bg_tertiary']};
                color: {theme['text_secondary']};
                border: 1px solid {theme['border_color']};
            }}
            QPushButton#cancel_button:hover {{
                background-color: {theme['hover_bg']};
                border-color: {theme['border_color']};
            }}
            QPushButton#delete-profile-button {{
                background-color: {theme['error_bg']};
                color: {theme['error_color']};
                border: 1px solid {theme['error_color']};
            }}
            QPushButton#delete-profile-button:hover {{
                background-color: {theme['error_color']};
                color: white;
            }}
            QPushButton#delete-profile-button:disabled {{
                background-color: {theme['disabled_bg']};
                color: {theme['disabled_text']};
                border: 1px solid {theme['disabled_border']};
            }}
            QCheckBox {{
                color: {theme['text_primary']};
                spacing: 5px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
            }}
            QProgressBar {{
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                text-align: center;
                background-color: {theme['input_bg']};
            }}
            QProgressBar::chunk {{
                background-color: {theme['accent_primary']};
                border-radius: {theme['radius_sm']};
            }}
        """)
        # Fallback for delete button icon removed as it now uses text
        # if self.delete_profile_button.icon().isNull():
        #      self.delete_profile_button.setText("Del") # Fallback text

    def delete_selected_profile(self):
        """Delete the currently selected saved connection profile."""
        selected_name = self.saved_connections.currentText()
        if selected_name == "-- Select a saved connection --":
            QMessageBox.information(self, "No Profile Selected", "Please select a profile to delete.")
            return

        reply = QMessageBox.question(self,
                                     "Confirm Delete",
                                     f"Are you sure you want to delete the profile '{selected_name}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            if self.connection_backend.delete_connection_profile(selected_name):
                QMessageBox.information(self, "Profile Deleted", f"Profile '{selected_name}' has been deleted.")
                current_idx = self.saved_connections.currentIndex()
                self.saved_connections.removeItem(current_idx)
                self.load_saved_connections() # Reload to refresh list and reset form
                self.saved_connections.setCurrentIndex(0) # Select placeholder
                self.load_connection() # Clear fields and disable delete button
            else:
                QMessageBox.warning(self, "Delete Error", f"Could not delete profile '{selected_name}'.") 