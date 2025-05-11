from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
    QLineEdit, QPushButton, QLabel, QMessageBox, QMainWindow)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import time
from pathlib import Path
from src.ui.utils.theme_manager import ThemeManager
from src.backend.auth_backend import AuthBackend
from src.utils.crypto import CryptoManager
import socket
import structlog

logger = structlog.get_logger(__name__)

class LoginWindow(QMainWindow):
    # Signal for successful login
    login_successful = Signal(str, str)  # Emits (username, role)
    
    def __init__(self):
        super().__init__()
        self.auth_backend = AuthBackend()
        self.theme_manager = ThemeManager()
        self.crypto_manager = CryptoManager()
        self.theme_manager.theme_changed.connect(self.apply_styles)
        
        # I like these dimensions but might need adjusting for different displays
        self.setWindowTitle("Linux Admin GUI - Login")
        self.setFixedSize(400, 500)
        self.setup_ui()
        self.apply_styles()
        
        # Uncomment for testing without auth
        # self.username_input.setText("admin")
        # self.password_input.setText("password123")
        
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Theme toggle in the corner
        theme_btn = QPushButton()
        theme_btn.setObjectName("theme-button")
        theme_btn.clicked.connect(self.theme_manager.toggle_theme)
        theme_btn.setFixedSize(30, 30)
        theme_layout = QHBoxLayout()
        theme_layout.addStretch()
        theme_layout.addWidget(theme_btn)
        layout.addLayout(theme_layout)
        
        # Make this a proper logo someday
        title_label = QLabel("Linux Admin GUI")
        title_label.setObjectName("title-label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("System Administration Tool")
        subtitle_label.setObjectName("subtitle-label")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle_label)
        
        layout.addSpacing(30)
        
        # Login form
        form_widget = QWidget()
        form_widget.setObjectName("login-form")
        form_layout = QVBoxLayout(form_widget)
        form_layout.setSpacing(15)
        
        # User
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setObjectName("login-input")
        self.username_input.returnPressed.connect(self.handle_login)
        form_layout.addWidget(self.username_input)
        
        # Pass
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setObjectName("login-input")
        self.password_input.returnPressed.connect(self.handle_login)
        form_layout.addWidget(self.password_input)
        
        # TODO: Add "remember me" checkbox?
        
        # Login button - enter key also works
        login_btn = QPushButton("Login")
        login_btn.setObjectName("login-button")
        login_btn.clicked.connect(self.handle_login)
        form_layout.addWidget(login_btn)
        
        layout.addWidget(form_widget)
        
        # Error message area
        self.error_label = QLabel("")
        self.error_label.setObjectName("error-label")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        layout.addWidget(self.error_label)
        
        layout.addStretch()
        
    def apply_styles(self):
        theme = self.theme_manager.get_theme_styles()
        
        # Not a huge fan of this stylesheet approach but it works
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {theme['bg_primary']};
            }}
            QWidget#login-form {{
                background-color: {theme['bg_secondary']};
                border-radius: 8px;
                padding: 20px;
            }}
            QLabel#title-label {{
                color: {theme['text_primary']};
                font-size: 28px;
                font-weight: bold;
                margin-bottom: 10px;
            }}
            QLabel#subtitle-label {{
                color: {theme['text_secondary']};
                font-size: 16px;
                margin-bottom: 20px;
            }}
            /* Inputs need some work - might be better with custom widgets */
            QLineEdit#login-input {{
                padding: 12px;
                border: 2px solid {theme['border_color']};
                border-radius: 6px;
                font-size: 14px;
                margin-bottom: 10px;
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
            }}
            QLineEdit#login-input:focus {{
                border: 2px solid {theme['accent_primary']};
            }}
            QPushButton#login-button {{
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px;
                font-size: 16px;
                font-weight: bold;
                margin-top: 10px;
            }}
            QPushButton#login-button:hover {{
                background-color: {theme['accent_secondary']};
            }}
            QPushButton#login-button:pressed {{
                background-color: {theme['accent_tertiary']};
            }}
            QPushButton#theme-button {{
                background-color: transparent;
                border: 2px solid {theme['border_color']};
                border-radius: 15px;
                icon: url('{"src/assets/moon.png" if self.theme_manager.current_theme == "light" else "src/assets/sun.png"}');
            }}
            QPushButton#theme-button:hover {{
                background-color: {theme['hover_bg']};
            }}
            QLabel#error-label {{
                color: {theme['error_color']};
                font-size: 14px;
                margin-top: 10px;
            }}
        """)
        
    def handle_login(self):
        """Handle login attempt with secure authentication"""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.show_error("Please enter both username and password")
            return
            
        # Add a small delay to prevent brute force
        time.sleep(0.3)
            
        try:
            # Get client IP (in real app, would get from request)
            client_ip = socket.gethostbyname(socket.gethostname())
            
            # Encrypt password before sending to auth backend
            encrypted_password = self.crypto_manager.encrypt(password)
            
            # Attempt authentication with encrypted password
            success, result = self.auth_backend.authenticate(username, encrypted_password, client_ip)
            
            if success:
                logger.info("Login successful", username=username, role=result)
                self.login_successful.emit(username, result)
                self.close()
            else:
                self.show_error(result)
                self.password_input.clear()
                
        except Exception as e:
            logger.error("Login error", error=str(e))
            self.show_error("An error occurred during login. Please try again.")
            
    def show_error(self, message):
        """Display error message to user"""
        self.error_label.setText(message)
        self.error_label.show()
        
    def closeEvent(self, event):
        """Handle window close event"""
        # Probably don't need this but keeping for future use
        super().closeEvent(event) 