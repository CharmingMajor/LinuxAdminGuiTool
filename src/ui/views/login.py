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
        
        # Theme toggle in the corner as a floating button
        theme_container = QWidget()
        theme_container.setFixedHeight(50)
        theme_layout = QHBoxLayout(theme_container)
        theme_layout.setContentsMargins(20, 10, 20, 0)
        
        theme_btn = QPushButton()
        theme_btn.setObjectName("theme-button")
        theme_btn.clicked.connect(self.theme_manager.toggle_theme)
        theme_btn.setFixedSize(36, 36)
        
        theme_layout.addStretch()
        theme_layout.addWidget(theme_btn)
        
        main_layout.addWidget(theme_container)
        
        # Create the login card
        login_card = QFrame()
        login_card.setObjectName("login-card")
        login_card.setFrameShape(QFrame.Shape.StyledPanel)
        
        card_layout = QVBoxLayout(login_card)
        card_layout.setContentsMargins(40, 40, 40, 40)
        card_layout.setSpacing(20)
        
        # Logo/Icon placeholder
        logo_container = QWidget()
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        logo_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Logo image (placeholder - replace with your actual logo)
        logo_label = QLabel()
        logo_label.setFixedSize(80, 80)
        logo_label.setObjectName("logo-image")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # If you have a logo file, you can use this:
        # logo_path = Path("src/assets/logo.png")
        # if logo_path.exists():
        #     pixmap = QPixmap(str(logo_path))
        #     logo_label.setPixmap(pixmap.scaled(80, 80, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        
        logo_layout.addWidget(logo_label)
        card_layout.addWidget(logo_container)
        
        # Title and subtitle
        title_label = QLabel("Linux Admin GUI")
        title_label.setObjectName("title-label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title_label)
        
        subtitle_label = QLabel("System Administration Tool")
        subtitle_label.setObjectName("subtitle-label")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(subtitle_label)
        
        card_layout.addSpacing(20)
        
        # Username input with icon
        username_container = QWidget()
        username_container.setObjectName("input-container")
        username_layout = QHBoxLayout(username_container)
        username_layout.setContentsMargins(10, 0, 10, 0)
        username_layout.setSpacing(10)
        
        username_icon = QLabel()
        username_icon.setObjectName("input-icon")
        username_icon.setFixedSize(24, 24)
        username_layout.addWidget(username_icon)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setObjectName("login-input")
        self.username_input.returnPressed.connect(self.handle_login)
        username_layout.addWidget(self.username_input)
        
        card_layout.addWidget(username_container)
        
        # Password input with icon
        password_container = QWidget()
        password_container.setObjectName("input-container")
        password_layout = QHBoxLayout(password_container)
        password_layout.setContentsMargins(10, 0, 10, 0)
        password_layout.setSpacing(10)
        
        password_icon = QLabel()
        password_icon.setObjectName("input-icon")
        password_icon.setFixedSize(24, 24)
        password_layout.addWidget(password_icon)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setObjectName("login-input")
        self.password_input.returnPressed.connect(self.handle_login)
        password_layout.addWidget(self.password_input)
        
        card_layout.addWidget(password_container)
        
        # Login button with consistent styling
        login_btn = QPushButton("Login")
        login_btn.setObjectName("login-button")
        login_btn.setMinimumHeight(44)
        login_btn.clicked.connect(self.handle_login)
        card_layout.addWidget(login_btn)
        
        # Error message area
        self.error_label = QLabel("")
        self.error_label.setObjectName("error-label")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        card_layout.addWidget(self.error_label)
        
        # Vertical centering of the login card
        main_layout.addStretch(1)
        main_layout.addWidget(login_card, 0, Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch(1)
        
    def apply_styles(self):
        theme = self.theme_manager.get_theme_styles()
        
        # Update theme button icon based on current theme
        theme_icon = "sun.svg" if self.theme_manager.current_theme == "dark" else "moon.svg"
        for btn in self.findChildren(QPushButton):
            if btn.objectName() == "theme-button":
                btn.setIcon(QIcon(f"src/assets/{theme_icon}"))
                
        # Update input icons based on theme
        for label in self.findChildren(QLabel):
            if label.objectName() == "input-icon":
                if label.parent().layout().itemAt(1).widget() == self.username_input:
                    label.setStyleSheet(f"""
                        background-image: url(src/assets/user_icon.svg);
                        background-position: center;
                        background-repeat: no-repeat;
                    """)
                elif label.parent().layout().itemAt(1).widget() == self.password_input:
                    label.setStyleSheet(f"""
                        background-image: url(src/assets/lock_icon.svg);
                        background-position: center;
                        background-repeat: no-repeat;
                    """)
                    
        # Logo placeholder styling
        for label in self.findChildren(QLabel):
            if label.objectName() == "logo-image":
                label.setStyleSheet(f"""
                    background-color: {theme['accent_primary']};
                    border-radius: 40px;
                    color: white;
                    font-size: 36px;
                    font-weight: bold;
                """)
                label.setText("LAG")  # Placeholder text if no image
        
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {theme['bg_primary']};
                font-family: {theme['font_primary']};
            }}
            
            QFrame#login-card {{
                background-color: {theme['bg_secondary']};
                border-radius: {theme['radius_lg']};
                border: 1px solid {theme['border_color']};
                min-width: 360px;
                max-width: 360px;
            }}
            
            QLabel#title-label {{
                color: {theme['text_primary']};
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 5px;
            }}
            
            QLabel#subtitle-label {{
                color: {theme['text_secondary']};
                font-size: 14px;
                margin-bottom: 15px;
            }}
            
            QWidget#input-container {{
                background-color: {theme['input_bg']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
                min-height: 48px;
                margin-bottom: 10px;
            }}
            
            QLineEdit#login-input {{
                border: none;
                padding: 8px;
                font-size: 14px;
                background-color: transparent;
                color: {theme['text_primary']};
            }}
            
            QLineEdit#login-input:focus {{
                border: none;
                outline: none;
            }}
            
            QPushButton#login-button {{
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: {theme['radius_md']};
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
                background-color: {theme['bg_secondary']};
                border: 1px solid {theme['border_color']};
                border-radius: 18px;
            }}
            
            QPushButton#theme-button:hover {{
                background-color: {theme['hover_bg']};
            }}
            
            QLabel#error-label {{
                color: {theme['error_color']};
                font-size: 14px;
                margin-top: 10px;
                min-height: 20px;
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