from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QMessageBox, QScrollArea, QSizePolicy)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import psutil
import time
from pathlib import Path
from src.ui.utils.theme_manager import ThemeManager

class BaseDashboard(QMainWindow):
    """Base dashboard with common functionality for both Junior and Senior admins"""
    
    logout_requested = Signal()  # Signal for logout
    
    def __init__(self, username: str, role: str):
        super().__init__()
        self.username = username
        self.role = role
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.apply_styles)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the base UI components"""
        self.setWindowTitle(f"Linux Admin GUI - {self.role.title()} Dashboard")
        self.setMinimumSize(1024, 768)  # Slightly larger minimum size for better layout
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create sidebar
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)
        
        # Create main content area with scrolling capability
        content_container = QWidget()
        content_container.setObjectName("content-container")
        content_container_layout = QVBoxLayout(content_container)
        content_container_layout.setContentsMargins(0, 0, 0, 0)
        content_container_layout.setSpacing(0)
        
        # Header bar with theme toggle and user info
        header_bar = self.create_header_bar()
        content_container_layout.addWidget(header_bar)
        
        # Main content with scroll area
        content_scroll = QScrollArea()
        content_scroll.setWidgetResizable(True)
        content_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        content_scroll.setObjectName("content-scroll")
        
        content_widget = QWidget()
        content_widget.setObjectName("content-area")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(20)
        
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("content-stack")
        content_layout.addWidget(self.content_stack)
        
        content_scroll.setWidget(content_widget)
        content_container_layout.addWidget(content_scroll)
        
        main_layout.addWidget(content_container)
        
        # Set layout proportions for better responsiveness
        main_layout.setStretch(0, 1)  # Sidebar
        main_layout.setStretch(1, 4)  # Content area gets more space
        
        # Apply styles
        self.apply_styles()

    def create_header_bar(self):
        """Create the header bar with theme toggle and quick info"""
        theme = self.theme_manager.get_theme_styles()
        
        header = QWidget()
        header.setObjectName("header-bar")
        header.setMinimumHeight(50)
        header.setMaximumHeight(50)
        
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        # Page title (will be updated by child dashboards)
        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("page-title")
        
        # Right side with theme toggle
        right_widgets = QWidget()
        right_layout = QHBoxLayout(right_widgets)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(15)
        
        # User info
        user_info = QLabel(f"{self.username} ({self.role.title()})")
        user_info.setObjectName("header-user-info")
        
        # Theme toggle button
        theme_btn = QPushButton()
        theme_btn.setObjectName("theme-button")
        theme_btn.clicked.connect(self.theme_manager.toggle_theme)
        theme_btn.setFixedSize(32, 32)
        
        right_layout.addWidget(user_info)
        right_layout.addWidget(theme_btn)
        
        header_layout.addWidget(self.page_title)
        header_layout.addStretch()
        header_layout.addWidget(right_widgets)
        
        return header
        
    def create_sidebar(self):
        """Create the sidebar with navigation buttons"""
        theme = self.theme_manager.get_theme_styles()
        
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        sidebar.setFixedWidth(220)
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # App title/logo section
        logo_container = QWidget()
        logo_container.setObjectName("logo-container")
        logo_container.setMinimumHeight(64)
        logo_container.setMaximumHeight(64)
        logo_layout = QVBoxLayout(logo_container)
        logo_layout.setContentsMargins(15, 0, 15, 0)
        
        app_title = QLabel("Linux Admin GUI")
        app_title.setObjectName("app-title")
        app_title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        logo_layout.addWidget(app_title)
        
        layout.addWidget(logo_container)
        
        # User info section
        user_container = QWidget()
        user_container.setObjectName("user-info-container")
        user_container.setMinimumHeight(80)
        user_container.setMaximumHeight(80)
        user_layout = QVBoxLayout(user_container)
        user_layout.setContentsMargins(15, 10, 15, 10)
        user_layout.setSpacing(2)
        
        username_label = QLabel(f"Welcome, {self.username}")
        username_label.setObjectName("welcome-label")
        
        role_label = QLabel(f"{self.role.title()} Administrator")
        role_label.setObjectName("role-label")
        
        user_layout.addWidget(username_label)
        user_layout.addWidget(role_label)
        layout.addWidget(user_container)
        
        # Navigation section
        nav_container = QWidget()
        nav_container.setObjectName("nav-container")
        nav_layout = QVBoxLayout(nav_container)
        nav_layout.setContentsMargins(0, 10, 0, 10)
        nav_layout.setSpacing(2)
        
        # Navigation buttons - will be populated by child classes
        self.nav_buttons = {}
        
        # Will be filled with navigation buttons
        layout.addWidget(nav_container)
        
        # Add stretch to push logout to bottom
        layout.addStretch()
        
        # Logout section
        logout_container = QWidget()
        logout_container.setObjectName("logout-container")
        logout_container.setMinimumHeight(60)
        logout_container.setMaximumHeight(60)
        logout_layout = QVBoxLayout(logout_container)
        logout_layout.setContentsMargins(15, 10, 15, 10)
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("logout-button")
        logout_btn.setMinimumHeight(36)
        logout_btn.clicked.connect(self.logout_requested.emit)
        logout_layout.addWidget(logout_btn)
        
        layout.addWidget(logout_container)
        
        # Store nav_container for adding buttons later
        self.nav_container = nav_container
        
        return sidebar
        
    def add_nav_button(self, name: str, text: str, icon_path: str = None):
        """Add a navigation button to the sidebar"""
        btn = QPushButton(text)
        btn.setObjectName("nav-button")
        btn.setCheckable(True)
        btn.setMinimumHeight(40)
        
        if icon_path and Path(icon_path).exists():
            btn.setIcon(QIcon(icon_path))
        
        # Connect to change page function
        btn.clicked.connect(lambda checked, n=name: self.change_page(n))
        
        # Add to nav container
        self.nav_container.layout().addWidget(btn)
        
        self.nav_buttons[name] = btn
        return btn
    
    def change_page(self, name):
        """Change the active page and update button states"""
        # Find the index of the page
        for i in range(self.content_stack.count()):
            if self.content_stack.widget(i).objectName() == name:
                # Set the page title
                self.page_title.setText(name.replace('_', ' ').title())
                
                # Update active button
                for btn_name, btn in self.nav_buttons.items():
                    btn.setChecked(btn_name == name)
                
                # Switch to the page
                self.content_stack.setCurrentIndex(i)
                break
        
    def add_content_widget(self, name: str, widget: QWidget):
        """Add a widget to the content stack"""
        # Set object name for finding later
        widget.setObjectName(name)
        
        # Add to the stack
        self.content_stack.addWidget(widget)
        
        # If this is the first widget, select it
        if self.content_stack.count() == 1:
            self.change_page(name)
            
        return widget
        
    def apply_styles(self):
        """Apply styles to the dashboard"""
        theme = self.theme_manager.get_theme_styles()
        
        # Update theme button icon based on current theme
        theme_icon = "sun.svg" if self.theme_manager.current_theme == "dark" else "moon.svg"
        for btn in self.findChildren(QPushButton):
            if btn.objectName() == "theme-button":
                btn.setIcon(QIcon(f"src/assets/{theme_icon}"))
        
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {theme['bg_primary']};
                font-family: {theme['font_primary']};
            }}
            
            QWidget#content-container {{
                background-color: {theme['bg_primary']};
            }}
            
            QWidget#content-area {{
                background-color: {theme['bg_primary']};
            }}
            
            QScrollArea#content-scroll {{
                background-color: transparent;
                border: none;
            }}
            
            QScrollBar:vertical {{
                background-color: {theme['scrollbar_bg']};
                width: 10px;
                margin: 0px;
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {theme['scrollbar_handle']};
                min-height: 30px;
                border-radius: 5px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {theme['scrollbar_hover']};
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QWidget#sidebar {{
                background-color: {theme['sidebar_bg']};
                color: {theme['text_primary']};
            }}
            
            QWidget#logo-container {{
                background-color: {theme['sidebar_bg']};
                border-bottom: 1px solid {theme['border_color']};
            }}
            
            QLabel#app-title {{
                color: {theme['accent_primary']};
                font-size: 18px;
                font-weight: bold;
            }}
            
            QWidget#user-info-container {{
                background-color: {theme['sidebar_bg']};
                border-bottom: 1px solid {theme['border_color']};
            }}
            
            QLabel#welcome-label {{
                color: {theme['text_primary']};
                font-size: 14px;
                font-weight: bold;
            }}
            
            QLabel#role-label {{
                color: {theme['text_secondary']};
                font-size: 12px;
            }}
            
            QWidget#nav-container {{
                background-color: {theme['sidebar_bg']};
            }}
            
            QPushButton#nav-button {{
                background-color: transparent;
                border: none;
                border-radius: 0;
                padding: 10px 15px;
                text-align: left;
                color: {theme['text_secondary']};
                font-size: 13px;
            }}
            
            QPushButton#nav-button:hover {{
                background-color: {theme['sidebar_hover']};
                color: {theme['text_primary']};
            }}
            
            QPushButton#nav-button:checked {{
                background-color: {theme['active_bg']};
                border-left: 3px solid {theme['accent_primary']};
                color: {theme['accent_primary']};
                font-weight: bold;
            }}
            
            QWidget#logout-container {{
                background-color: {theme['sidebar_bg']};
                border-top: 1px solid {theme['border_color']};
            }}
            
            QPushButton#logout-button {{
                background-color: {theme['error_color']};
                color: white;
                border: none;
                border-radius: {theme['radius_sm']};
                padding: 8px;
                font-weight: bold;
                text-align: center;
            }}
            
            QPushButton#logout-button:hover {{
                background-color: #c82333;
            }}
            
            QWidget#header-bar {{
                background-color: {theme['bg_secondary']};
                border-bottom: 1px solid {theme['border_color']};
            }}
            
            QLabel#page-title {{
                font-size: 18px;
                font-weight: bold;
                color: {theme['text_primary']};
            }}
            
            QLabel#header-user-info {{
                color: {theme['text_secondary']};
                font-size: 13px;
            }}
            
            QPushButton#theme-button {{
                background-color: transparent;
                border: 1px solid {theme['border_color']};
                border-radius: 16px;
            }}
            
            QPushButton#theme-button:hover {{
                background-color: {theme['hover_bg']};
            }}
            
            QGroupBox {{
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
                margin-top: 15px;
                padding: 10px;
                background-color: {theme['bg_secondary']};
                font-weight: bold;
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: {theme['text_primary']};
                background-color: {theme['bg_secondary']};
            }}
            
            /* Card-like widgets */
            QFrame[frameShape="6"] {{  /* StyledPanel */
                background-color: {theme['bg_secondary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
            }}
        """)
        
    def show_message(self, title: str, message: str, icon: QMessageBox.Icon = QMessageBox.Icon.Information):
        """Show a message box with the given title and message"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.exec()
        
    def confirm_action(self, title: str, message: str) -> bool:
        """Show a confirmation dialog and return True if the user confirms"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Icon.Question)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        msg_box.setDefaultButton(QMessageBox.StandardButton.No)
        return msg_box.exec() == QMessageBox.StandardButton.Yes 