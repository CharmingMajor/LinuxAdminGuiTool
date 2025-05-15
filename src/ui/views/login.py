from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
    QLineEdit, QPushButton, QLabel, QMessageBox, QMainWindow, QFrame)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon, QPixmap
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
        
        self.setWindowTitle("Linux Admin GUI - Login")
        self.setFixedSize(440, 560)
        self.setup_ui()
        self.apply_styles()
    
    def setup_ui(self):
        """Set up the login UI with a modern card-based design"""
        theme = self.theme_manager.get_theme_styles()
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout with top-aligned content and spacing
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create the login card
        login_card = QFrame()
        login_card.setObjectName("login-card")
        login_card.setFrameShape(QFrame.Shape.StyledPanel)
        
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(0)
        
        # Theme switch button (top right)
        theme_btn_container = QWidget()
        theme_btn_layout = QHBoxLayout(theme_btn_container)
        theme_btn_layout.setContentsMargins(0, 0, 0, 0)
        theme_btn_layout.addStretch()
        self.theme_btn = QPushButton()
        self.theme_btn.setObjectName("theme-button")
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.setFixedSize(36, 36)
        self.theme_btn.clicked.connect(self.theme_manager.toggle_theme)
        theme_btn_layout.addWidget(self.theme_btn)
        card_layout.addWidget(theme_btn_container)
        
        # Content container
        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(48, 32, 48, 32)
        content_layout.setSpacing(24)
        
        # Title (Linux <b>Admin GUI</b>)
        title_label = QLabel()
        title_label.setObjectName("title-label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        title_label.setText('<span style="font-weight:400;">Linux </span><b>Admin GUI</b>')
        content_layout.addWidget(title_label)
        
        # Username input with label
        username_layout = QVBoxLayout()
        username_layout.setSpacing(8)
        username_label = QLabel("User name")
        username_label.setObjectName("input-label")
        username_layout.addWidget(username_label)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setObjectName("login-input")
        self.username_input.returnPressed.connect(self.handle_login)
        username_layout.addWidget(self.username_input)
        content_layout.addLayout(username_layout)
        
        # Password input with label
        password_layout = QVBoxLayout()
        password_layout.setSpacing(8)
        password_label = QLabel("Password")
        password_label.setObjectName("input-label")
        password_layout.addWidget(password_label)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setObjectName("login-input")
        self.password_input.returnPressed.connect(self.handle_login)
        password_layout.addWidget(self.password_input)
        content_layout.addLayout(password_layout)
        
        # Login button with consistent styling
        login_btn = QPushButton("Log in")
        login_btn.setObjectName("login-button")
        login_btn.setMinimumHeight(44)
        login_btn.clicked.connect(self.handle_login)
        content_layout.addWidget(login_btn)
        
        # Error message area
        self.error_label = QLabel("")
        self.error_label.setObjectName("error-label")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        content_layout.addWidget(self.error_label)
        
        card_layout.addWidget(content_container)
        
        # Server info at bottom (gray bar)
        server_info = QWidget()
        server_info.setObjectName("server-info")
        server_info_layout = QVBoxLayout(server_info)
        server_info_layout.setContentsMargins(24, 12, 24, 12)
        server_info_layout.setSpacing(2)
        import socket
        hostname = socket.gethostname()
        server_label = QLabel(f"Server: {hostname}")
        server_label.setObjectName("server-label")
        server_info_layout.addWidget(server_label)
        subtitle_label = QLabel("Log in with your server user account.")
        subtitle_label.setObjectName("server-subtitle")
        server_info_layout.addWidget(subtitle_label)
        card_layout.addWidget(server_info)
        
        login_card.setLayout(card_layout)
        
        # Vertical centering of the login card
        main_layout.addStretch(1)
        main_layout.addWidget(login_card, 0, Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch(1)
        
    def apply_styles(self):
        theme = self.theme_manager.get_theme_styles()
        
        # Update theme button icon based on current theme
        theme_icon = "sun.svg" if self.theme_manager.current_theme == "dark" else "moon.svg"
        self.theme_btn.setIcon(QIcon(f"src/assets/{theme_icon}"))
        
        self.setStyleSheet(f"""
            QMainWindow {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {theme['bg_primary']},
                    stop:1 {theme['bg_secondary']});
                font-family: {theme['font_primary']};
            }}
            QFrame#login-card {{
                background-color: {theme['card_bg']};
                border-radius: {theme['radius_lg']};
                border: 1px solid {theme['border_color']};
                min-width: 400px;
                max-width: 420px;
            }}
            QWidget#server-info {{
                background-color: {theme['bg_secondary']};
                border-bottom-left-radius: {theme['radius_lg']};
                border-bottom-right-radius: {theme['radius_lg']};
                border-top: 1px solid {theme['border_color']};
                color: {theme['text_primary']};
            }}
            QLabel#server-label {{
                color: {theme['text_primary']};
                font-size: 13px;
                font-weight: 600;
            }}
            QLabel#server-subtitle {{
                color: {theme['text_secondary']};
                font-size: 13px;
            }}
            QLabel#title-label {{
                color: {theme['text_primary']};
                font-size: 26px;
                font-weight: 400;
                margin-bottom: 18px;
                letter-spacing: 0.2px;
            }}
            QLabel#input-label {{
                color: {theme['text_primary']};
                font-size: 14px;
                font-weight: 600;
                margin-bottom: 2px;
            }}
            QLineEdit#login-input {{
                padding: 12px 14px;
                font-size: 15px;
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                border: 1.5px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                min-height: 24px;
                margin-bottom: 8px;
            }}
            QLineEdit#login-input:focus {{
                border: 1.5px solid {theme['accent_primary']};
                background-color: {theme['bg_tertiary']};
            }}
            QLineEdit#login-input::placeholder {{
                color: {theme['text_secondary']};
                opacity: 0.7;
            }}
            QPushButton#login-button {{
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: {theme['radius_sm']};
                padding: 12px 0;
                font-size: 16px;
                font-weight: 600;
                margin-top: 12px;
                margin-bottom: 8px;
            }}
            QPushButton#login-button:hover {{
                background-color: {theme['accent_secondary']};
            }}
            QPushButton#login-button:pressed {{
                background-color: {theme['accent_tertiary']};
            }}
            QPushButton#theme-button {{
                background-color: transparent;
                border: none;
                border-radius: 50%;
                min-width: 36px;
                min-height: 36px;
                max-width: 36px;
                max-height: 36px;
                margin: 0 0 0 0;
            }}
            QPushButton#theme-button:hover {{
                background-color: {theme['hover_bg']};
            }}
            QLabel#error-label {{
                color: {theme['error_color']};
                font-size: 14px;
                margin-top: 10px;
                min-height: 20px;
                font-weight: 500;
                padding: 8px 12px;
                background-color: {theme['bg_tertiary']};
                border-radius: {theme['radius_md']};
                border: 1px solid {theme['error_color']};
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
            
            # Attempt login - handle both forms of authentication return
            result = self.auth_backend.authenticate(username, encrypted_password, client_ip)
            
            # Check if result is a tuple (success, message/role) or a dict
            if isinstance(result, tuple):
                success, data = result
                if success:
                    logger.info(f"User {username} logged in successfully")
                    self.login_successful.emit(username, data)
                else:
                    logger.warning(f"Failed login attempt for {username}")
                    self.show_error(data)
            elif isinstance(result, dict):
                if result.get('success', False):
                    logger.info(f"User {username} logged in successfully")
                    self.login_successful.emit(username, result.get('role', 'junior'))
                else:
                    logger.warning(f"Failed login attempt for {username}")
                    self.show_error(result.get('message', 'Login failed'))
            else:
                logger.error(f"Unexpected authentication result format: {type(result)}")
                self.show_error("Authentication error: Unexpected response format")
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            self.show_error(f"Authentication error: {str(e)}")
            
    def show_error(self, message):
        """Show an error message in the UI"""
        self.error_label.setText(message)
        self.error_label.show()
        
    def closeEvent(self, event):
        """Handle window close event"""
        logger.info("Login window closed")
        super().closeEvent(event) 