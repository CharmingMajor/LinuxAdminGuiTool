from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QComboBox, QMessageBox, QFileDialog, QWidget, QSpinBox,
    QFormLayout, QGroupBox, QCheckBox, QFrame, QProgressBar, QApplication)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QIcon, QPixmap, QPalette, QColor
from pathlib import Path

from src.utils.remote_connection import RemoteConnection

class ConnectDialog(QDialog):
    """Dialog for connecting to remote machines"""
    
    connection_established = Signal(RemoteConnection)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.remote = RemoteConnection()
        self.is_dark_mode = self.detect_dark_mode()
        self.setup_ui()
        
    def detect_dark_mode(self):
        """Detect if system is using dark mode by checking the application palette"""
        palette = QApplication.palette()
        background_color = palette.color(QPalette.Window)
        # If the background is dark (brightness < 128), consider it dark mode
        return background_color.lightness() < 128
        
    def setup_ui(self):
        """Set up the dialog UI"""
        self.setWindowTitle("Connect to Remote Machine")
        self.setModal(True)
        self.resize(550, 450)  # Slightly larger size for better layout
        
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(25, 25, 25, 25)
        
        # Top section with header and theme toggle
        top_layout = QHBoxLayout()
        
        # Header with icon and title
        header_layout = QHBoxLayout()
        icon_label = QLabel()
        # Use system icon - replace with app-specific icon if available
        icon_label.setPixmap(QIcon.fromTheme("network-server").pixmap(48, 48))
        header_layout.addWidget(icon_label)
        
        title_layout = QVBoxLayout()
        title_label = QLabel("Connect to Remote Server")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.subtitle_label = QLabel("Enter connection details to establish an SSH connection")
        self.subtitle_label.setStyleSheet("color: #666;")
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.subtitle_label)
        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        
        top_layout.addLayout(header_layout)
        
        # Theme toggle button in top right
        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("theme-button")
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.theme_btn.setFixedSize(36, 36)
        self.theme_btn.setToolTip("Toggle Dark/Light Theme")
        top_layout.addWidget(self.theme_btn)
        
        main_layout.addLayout(top_layout)
        
        # Separator
        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)
        
        # Connection details group
        conn_group = QGroupBox("Connection Details")
        form_layout = QFormLayout(conn_group)
        form_layout.setSpacing(12)
        form_layout.setContentsMargins(15, 20, 15, 15)
        
        # Host input
        self.host_input = QLineEdit()
        self.host_input.setObjectName("input-field")
        self.host_input.setPlaceholderText("e.g. localhost or 192.168.1.100")
        form_layout.addRow("Hostname:", self.host_input)
        
        # Port input
        self.port_input = QSpinBox()
        self.port_input.setObjectName("input-field")
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)
        form_layout.addRow("Port:", self.port_input)
        
        # Username input
        self.user_input = QLineEdit()
        self.user_input.setObjectName("input-field")
        self.user_input.setPlaceholderText("Remote system username")
        form_layout.addRow("Username:", self.user_input)
        
        main_layout.addWidget(conn_group)
        
        # Authentication group
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout(auth_group)
        auth_layout.setSpacing(12)
        auth_layout.setContentsMargins(15, 20, 15, 15)
        
        # Authentication method
        auth_selection = QHBoxLayout()
        auth_label = QLabel("Method:")
        self.auth_combo = QComboBox()
        self.auth_combo.setObjectName("input-field")
        self.auth_combo.addItems(["Password", "SSH Key"])
        auth_selection.addWidget(auth_label)
        auth_selection.addWidget(self.auth_combo)
        auth_selection.addStretch()
        auth_layout.addLayout(auth_selection)
        
        # Password input widget
        self.pass_widget = QWidget()
        pass_layout = QFormLayout(self.pass_widget)
        pass_layout.setSpacing(12)
        self.pass_input = QLineEdit()
        self.pass_input.setObjectName("input-field")
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setPlaceholderText("Enter remote system password")
        pass_layout.addRow("Password:", self.pass_input)
        
        # Remember password checkbox
        self.remember_pass = QCheckBox("Remember password for this session")
        pass_layout.addRow("", self.remember_pass)
        
        auth_layout.addWidget(self.pass_widget)
        
        # Key file selection widget
        self.key_widget = QWidget()
        key_layout = QVBoxLayout(self.key_widget)
        key_layout.setSpacing(12)
        
        key_select_layout = QHBoxLayout()
        self.key_input = QLineEdit()
        self.key_input.setObjectName("input-field")
        self.key_input.setReadOnly(True)
        self.key_input.setPlaceholderText("Select SSH private key file")
        browse_btn = QPushButton("Browse")
        browse_btn.setObjectName("browse-button")
        browse_btn.setIcon(QIcon.fromTheme("document-open"))
        browse_btn.clicked.connect(self.browse_key)
        key_select_layout.addWidget(self.key_input)
        key_select_layout.addWidget(browse_btn)
        
        key_layout.addLayout(key_select_layout)
        
        # Passphrase for key (optional)
        key_passphrase_layout = QFormLayout()
        key_passphrase_layout.setSpacing(12)
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setObjectName("input-field")
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.passphrase_input.setPlaceholderText("Enter passphrase (if required)")
        key_passphrase_layout.addRow("Passphrase:", self.passphrase_input)
        key_layout.addLayout(key_passphrase_layout)
        
        auth_layout.addWidget(self.key_widget)
        self.key_widget.hide()
        
        main_layout.addWidget(auth_group)
        
        # Advanced options (collapsed by default)
        advanced_group = QGroupBox("Advanced Options")
        advanced_group.setObjectName("advanced-group")
        advanced_group.setCheckable(True)
        advanced_group.setChecked(False)
        advanced_layout = QFormLayout(advanced_group)
        advanced_layout.setSpacing(12)
        advanced_layout.setContentsMargins(15, 20, 15, 15)
        
        # Timeout
        self.timeout_input = QSpinBox()
        self.timeout_input.setObjectName("input-field")
        self.timeout_input.setRange(5, 60)
        self.timeout_input.setValue(10)
        self.timeout_input.setSuffix(" seconds")
        advanced_layout.addRow("Connection Timeout:", self.timeout_input)
        
        # Keep alive
        self.keepalive_check = QCheckBox()
        self.keepalive_check.setChecked(True)
        advanced_layout.addRow("Enable Keep-Alive:", self.keepalive_check)
        
        # Debug mode
        self.debug_check = QCheckBox()
        self.debug_check.setChecked(False)
        advanced_layout.addRow("Debug Mode:", self.debug_check)
        
        main_layout.addWidget(advanced_group)
        
        # Status message area
        self.status_layout = QVBoxLayout()
        self.status_label = QLabel("")
        self.status_label.setObjectName("status-label")
        self.status_label.setStyleSheet("color: #666;")
        self.status_layout.addWidget(self.status_label)
        main_layout.addLayout(self.status_layout)
        
        # Connect authentication method change
        self.auth_combo.currentTextChanged.connect(self.on_auth_changed)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        self.save_profile_btn = QPushButton("Save Profile")
        self.save_profile_btn.setObjectName("save-button")
        self.save_profile_btn.setIcon(QIcon.fromTheme("document-save"))
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setObjectName("connect-button")
        self.connect_btn.setIcon(QIcon.fromTheme("network-connect"))
        self.connect_btn.clicked.connect(self.try_connect)
        self.connect_btn.setDefault(True)  # Make it the default button
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("cancel-button")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.save_profile_btn)
        button_layout.addWidget(self.connect_btn)
        button_layout.addWidget(cancel_btn)
        main_layout.addLayout(button_layout)
        
        # Initial state
        self.on_auth_changed(self.auth_combo.currentText())
        
        # Focus first field
        self.host_input.setFocus()
        
        # The save_profile functionality would be implemented separately
        # For now, let's just disable it
        self.save_profile_btn.setEnabled(False)
        self.save_profile_btn.setToolTip("Saving connection profiles is not yet implemented")
        
        # Connection progress dialog
        self.progress_dialog = None
        
    def toggle_theme(self):
        """Toggle between light and dark theme"""
        self.is_dark_mode = not self.is_dark_mode
        self.apply_styles()
        
    def browse_key(self):
        """Open file dialog to select SSH key"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select SSH Private Key",
            "",
            "SSH Keys (*.pem *.key *.rsa *.pub);;All Files (*)"
        )
        if file_name:
            self.key_input.setText(file_name)
            
    def on_auth_changed(self, method):
        """Handle authentication method change"""
        using_password = method == "Password"
        self.pass_widget.setVisible(using_password)
        self.key_widget.setVisible(not using_password)
        
    def show_connection_progress(self, hostname):
        """Show a progress dialog while connecting"""
        progress = QMessageBox(self)
        progress.setWindowTitle("Connecting")
        progress.setText(f"Establishing connection to {hostname}...")
        progress.setStandardButtons(QMessageBox.Cancel)
        progress.setIcon(QMessageBox.Information)
        
        # Center the dialog
        progress.move(
            self.x() + (self.width() - progress.width()) // 2,
            self.y() + (self.height() - progress.height()) // 2
        )
        
        return progress
        
    def try_connect(self):
        """Attempt to connect to remote host"""
        hostname = self.host_input.text().strip()
        username = self.user_input.text().strip()
        port = self.port_input.value()
        
        # Input validation
        if not hostname or not username:
            QMessageBox.warning(self, "Error", "Please fill in all required fields")
            return
            
        using_password = self.auth_combo.currentText() == "Password"
        
        # Update UI
        self.status_label.setText("Attempting to connect...")
        self.status_label.setStyleSheet("color: #666;")
        self.setCursor(Qt.WaitCursor)
        self.connect_btn.setEnabled(False)
        
        # Show progress dialog
        progress = self.show_connection_progress(hostname)
        progress.show()
        
        # Process events to update UI
        QApplication.processEvents()
        
        try:
            if using_password:
                password = self.pass_input.text()
                if not password:
                    progress.hide()
                    self.setCursor(Qt.ArrowCursor)
                    self.connect_btn.setEnabled(True)
                    self.status_label.setText("Please enter password")
                    self.status_label.setStyleSheet("color: #E74C3C;")
                    QMessageBox.warning(self, "Error", "Please enter password")
                    return
                    
                success = self.remote.connect(hostname, username, password=password, port=port)
            else:
                key_path = self.key_input.text()
                if not key_path:
                    progress.hide()
                    self.setCursor(Qt.ArrowCursor)
                    self.connect_btn.setEnabled(True)
                    self.status_label.setText("Please select SSH key file")
                    self.status_label.setStyleSheet("color: #E74C3C;")
                    QMessageBox.warning(self, "Error", "Please select SSH key file")
                    return
                    
                # Get passphrase if provided
                passphrase = self.passphrase_input.text() if self.passphrase_input.text() else None
                success = self.remote.connect(hostname, username, key_path=key_path, port=port, passphrase=passphrase)
                
            # Restore UI state
            progress.hide()
            self.setCursor(Qt.ArrowCursor)
            self.connect_btn.setEnabled(True)
            
            if success:
                self.status_label.setText(f"Connected to {hostname}")
                self.status_label.setStyleSheet("color: #27AE60;")
                self.connection_established.emit(self.remote)
                self.accept()
            else:
                error_message = self.remote.get_last_error()
                self.status_label.setText(f"Connection failed: {error_message}")
                self.status_label.setStyleSheet("color: #E74C3C;")
                
                # Show more details in debug mode
                if self.debug_check.isChecked():
                    QMessageBox.critical(self, "Connection Error", 
                                       f"Failed to connect to {hostname}\n\nError details:\n{error_message}")
                else:
                    QMessageBox.critical(self, "Connection Error", 
                                       f"Failed to connect to {hostname}\n\n{error_message}")
                
        except Exception as e:
            progress.hide()
            self.setCursor(Qt.ArrowCursor)
            self.connect_btn.setEnabled(True)
            self.status_label.setText(f"Connection error: {str(e)}")
            self.status_label.setStyleSheet("color: #E74C3C;")
            
            QMessageBox.critical(self, "Connection Error", f"Unexpected error: {str(e)}")
        
    def get_dark_styles(self):
        """Get dark mode styles"""
        return """
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QLabel {
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #3D3D3D;
                border-radius: 8px;
                margin-top: 20px;
                margin-bottom: 15px;
                background-color: #252526;
                padding: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #ffffff;
                font-weight: bold;
                font-size: 14px;
                background-color: #252526;
            }
            QLineEdit#input-field, QComboBox#input-field, QSpinBox#input-field {
                padding: 8px;
                border: 1px solid #3D3D3D;
                border-radius: 5px;
                background-color: #3c3c3c;
                color: #ffffff;
                selection-background-color: #0078d4;
                font-size: 13px;
            }
            QLineEdit#input-field:focus, QComboBox#input-field:focus, QSpinBox#input-field:focus {
                border: 2px solid #0078d4;
            }
            QPushButton#connect-button {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton#connect-button:hover {
                background-color: #2b88d8;
            }
            QPushButton#connect-button:pressed {
                background-color: #005a9e;
            }
            QPushButton#connect-button:disabled {
                background-color: #555555;
                color: #888888;
            }
            QPushButton#save-button, QPushButton#browse-button {
                background-color: #3c3c3c;
                color: white;
                border: 1px solid #555555;
                padding: 10px 18px;
                border-radius: 5px;
                font-size: 13px;
            }
            QPushButton#save-button:disabled {
                background-color: #333333;
                color: #555555;
                border: 1px solid #3D3D3D;
            }
            QPushButton#save-button:hover, QPushButton#browse-button:hover {
                background-color: #444444;
            }
            QPushButton#cancel-button {
                background-color: transparent;
                color: #e0e0e0;
                border: 1px solid #555555;
                padding: 10px 18px;
                border-radius: 5px;
                font-size: 13px;
            }
            QPushButton#cancel-button:hover {
                background-color: #444444;
            }
            QCheckBox {
                color: #ffffff;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 3px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #555555;
                background: #3c3c3c;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #0078d4;
                background: #0078d4;
            }
            QComboBox {
                background-color: #3c3c3c;
                selection-background-color: #0078d4;
                color: #ffffff;
            }
            QComboBox QAbstractItemView {
                background-color: #3D3D3D;
                selection-background-color: #0078d4;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QWidget#separator {
                background-color: #3D3D3D;
                margin: 5px 0px;
                height: 1px;
            }
            QMessageBox {
                background-color: #252526;
                color: #ffffff;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #3D3D3D;
                width: 16px;
                border-radius: 3px;
            }
            QToolTip {
                background-color: #252526;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 4px;
            }
            QLabel#status-label {
                padding: 8px 0px;
                font-weight: bold;
            }
            QPushButton#theme-button {
                background-color: transparent;
                border: 2px solid #555555;
                border-radius: 18px;
                padding: 4px;
                icon: url('src/assets/sun.svg');
            }
            QPushButton#theme-button:hover {
                background-color: #37373d;
            }
        """
        
    def get_light_styles(self):
        """Get light mode styles"""
        return """
            QDialog {
                background-color: #ffffff;
                color: #212529;
            }
            QLabel {
                color: #212529;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                margin-top: 20px;
                margin-bottom: 15px;
                background-color: #f8f9fa;
                padding: 0px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: #212529;
                font-weight: bold;
                font-size: 14px;
                background-color: #f8f9fa;
            }
            QLineEdit#input-field, QComboBox#input-field, QSpinBox#input-field {
                padding: 8px;
                border: 1px solid #dee2e6;
                border-radius: 5px;
                background-color: #ffffff;
                color: #212529;
                selection-background-color: #007bff;
                font-size: 13px;
            }
            QLineEdit#input-field:focus, QComboBox#input-field:focus, QSpinBox#input-field:focus {
                border: 2px solid #007bff;
            }
            QPushButton#connect-button {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 10px 18px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 13px;
            }
            QPushButton#connect-button:hover {
                background-color: #0056b3;
            }
            QPushButton#connect-button:pressed {
                background-color: #004085;
            }
            QPushButton#connect-button:disabled {
                background-color: #cccccc;
            }
            QPushButton#save-button, QPushButton#browse-button {
                background-color: #f8f9fa;
                color: #212529;
                border: 1px solid #dee2e6;
                padding: 10px 18px;
                border-radius: 5px;
                font-size: 13px;
            }
            QPushButton#save-button:disabled {
                background-color: #f8f9fa;
                color: #adb5bd;
                border: 1px solid #e9ecef;
            }
            QPushButton#save-button:hover, QPushButton#browse-button:hover {
                background-color: #e9ecef;
            }
            QPushButton#cancel-button {
                background-color: transparent;
                color: #212529;
                border: 1px solid #dee2e6;
                padding: 10px 18px;
                border-radius: 5px;
                font-size: 13px;
            }
            QPushButton#cancel-button:hover {
                background-color: #e9ecef;
            }
            QCheckBox {
                color: #212529;
                spacing: 8px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 3px;
            }
            QCheckBox::indicator:unchecked {
                border: 1px solid #dee2e6;
                background: #ffffff;
            }
            QCheckBox::indicator:checked {
                border: 1px solid #007bff;
                background: #007bff;
            }
            QComboBox {
                background-color: #ffffff;
                selection-background-color: #007bff;
                color: #212529;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                selection-background-color: #007bff;
                color: #212529;
                border: 1px solid #dee2e6;
            }
            QWidget#separator {
                background-color: #dee2e6;
                margin: 5px 0px;
                height: 1px;
            }
            QMessageBox {
                background-color: #ffffff;
                color: #212529;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #f8f9fa;
                width: 16px;
                border-radius: 3px;
            }
            QToolTip {
                background-color: #ffffff;
                color: #212529;
                border: 1px solid #dee2e6;
                padding: 4px;
            }
            QLabel#status-label {
                padding: 8px 0px;
                font-weight: bold;
            }
            QPushButton#theme-button {
                background-color: transparent;
                border: 2px solid #dee2e6;
                border-radius: 18px;
                padding: 4px;
                icon: url('src/assets/moon.svg');
            }
            QPushButton#theme-button:hover {
                background-color: #e9ecef;
            }
        """
        
    def apply_styles(self):
        """Apply consistent styles to the dialog based on theme"""
        if self.is_dark_mode:
            self.setStyleSheet(self.get_dark_styles())
            # Update specific widgets for dark mode
            self.subtitle_label.setStyleSheet("color: #AAAAAA; margin-top: 4px;")
            if self.status_label.text():
                if "Connected" in self.status_label.text():
                    self.status_label.setStyleSheet("color: #5CE28A; font-weight: bold; padding: 8px 0px;")
                elif "failed" in self.status_label.text() or "error" in self.status_label.text():
                    self.status_label.setStyleSheet("color: #E25C5C; font-weight: bold; padding: 8px 0px;")
                else:
                    self.status_label.setStyleSheet("color: #AAAAAA; font-weight: bold; padding: 8px 0px;")
        else:
            self.setStyleSheet(self.get_light_styles())
            # Reset specific widgets for light mode
            self.subtitle_label.setStyleSheet("color: #6c757d; margin-top: 4px;")
            if self.status_label.text():
                if "Connected" in self.status_label.text():
                    self.status_label.setStyleSheet("color: #28a745; font-weight: bold; padding: 8px 0px;")
                elif "failed" in self.status_label.text() or "error" in self.status_label.text():
                    self.status_label.setStyleSheet("color: #dc3545; font-weight: bold; padding: 8px 0px;")
                else:
                    self.status_label.setStyleSheet("color: #6c757d; font-weight: bold; padding: 8px 0px;")
        
    def showEvent(self, event):
        """When dialog is shown, apply styles"""
        super().showEvent(event)
        self.apply_styles()
        
    def keyPressEvent(self, event):
        """Handle key press events"""
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            # Only trigger connect if the connect button is enabled
            if self.connect_btn.isEnabled():
                self.try_connect()
        else:
            super().keyPressEvent(event) 