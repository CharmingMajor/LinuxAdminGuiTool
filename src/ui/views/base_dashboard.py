from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QMessageBox)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import psutil
import time
from pathlib import Path
from ui.utils.theme_manager import ThemeManager

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
        self.setMinimumSize(1200, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create sidebar
        sidebar = self.create_sidebar()
        main_layout.addWidget(sidebar)
        
        # Create main content area
        content_widget = QWidget()
        content_widget.setObjectName("content-area")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(25, 25, 25, 25)
        content_layout.setSpacing(25)
        
        # Add theme toggle to content area
        theme_layout = QHBoxLayout()
        theme_layout.setContentsMargins(0, 0, 0, 10)
        theme_btn = QPushButton()
        theme_btn.setObjectName("theme-button")
        theme_btn.clicked.connect(self.theme_manager.toggle_theme)
        theme_btn.setFixedSize(36, 36)
        theme_layout.addStretch()
        theme_layout.addWidget(theme_btn)
        content_layout.addLayout(theme_layout)
        
        self.content_stack = QStackedWidget()
        content_layout.addWidget(self.content_stack)
        
        main_layout.addWidget(content_widget)
        
        # Set layout proportions
        main_layout.setStretch(0, 1)  # Sidebar
        main_layout.setStretch(1, 4)  # Content
        
        # Apply styles
        self.apply_styles()
        
    def create_sidebar(self):
        """Create the sidebar with navigation buttons"""
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 25, 15, 25)
        
        # User info section
        user_section = QWidget()
        user_layout = QVBoxLayout(user_section)
        
        username_label = QLabel(f"Welcome, {self.username}")
        username_label.setObjectName("welcome-label")
        role_label = QLabel(f"{self.role.title()} Administrator")
        role_label.setObjectName("role-label")
        
        user_layout.addWidget(username_label)
        user_layout.addWidget(role_label)
        layout.addWidget(user_section)
        
        # Add separator
        separator = QWidget()
        separator.setObjectName("separator")
        separator.setFixedHeight(1)
        layout.addWidget(separator)
        
        # Navigation buttons - will be populated by child classes
        self.nav_buttons = {}
        
        # Add stretch to push logout to bottom
        layout.addStretch()
        
        # Logout button
        logout_btn = QPushButton("Logout")
        logout_btn.setObjectName("logout-button")
        logout_btn.clicked.connect(self.logout_requested.emit)
        layout.addWidget(logout_btn)
        
        return sidebar
        
    def add_nav_button(self, name: str, text: str, icon_path: str = None):
        """Add a navigation button to the sidebar"""
        btn = QPushButton(text)
        if icon_path and Path(icon_path).exists():
            btn.setIcon(QIcon(icon_path))
        btn.setCheckable(True)
        btn.setObjectName("nav-button")
        
        # Insert before the stretch that's pushing the logout button down
        sidebar_layout = self.centralWidget().layout().itemAt(0).widget().layout()
        stretch_index = sidebar_layout.count() - 2  # Account for logout button
        sidebar_layout.insertWidget(stretch_index, btn)
        
        self.nav_buttons[name] = btn
        return btn
        
    def apply_styles(self):
        """Apply styles to the dashboard"""
        theme = self.theme_manager.get_theme_styles()
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {theme['bg_primary']};
            }}
            QWidget#content-area {{
                background-color: {theme['bg_primary']};
                padding: 20px;
            }}
            QWidget#sidebar {{
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
                min-width: 250px;
                max-width: 250px;
                padding: 20px 10px;
            }}
            QLabel#welcome-label {{
                color: {theme['text_primary']};
                font-size: 18px;
                font-weight: bold;
                margin-bottom: 5px;
            }}
            QLabel#role-label {{
                color: {theme['text_secondary']};
                font-size: 14px;
                margin-bottom: 15px;
            }}
            QWidget#separator {{
                background-color: {theme['border_color']};
                margin: 10px 0px;
            }}
            QPushButton#nav-button {{
                background-color: transparent;
                border: none;
                border-radius: 6px;
                padding: 12px 20px;
                text-align: left;
                color: {theme['text_secondary']};
                font-size: 14px;
                margin: 6px 0px;
            }}
            QPushButton#nav-button:hover {{
                background-color: {theme['hover_bg']};
                color: {theme['text_primary']};
            }}
            QPushButton#nav-button:checked {{
                background-color: {theme['active_bg']};
                color: {theme['text_primary']};
                font-weight: bold;
            }}
            QPushButton#logout-button {{
                background-color: {theme['error_color']};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px;
                font-weight: bold;
                margin-top: 20px;
                text-align: center;
            }}
            QPushButton#logout-button:hover {{
                background-color: #c82333;
            }}
            QPushButton#theme-button {{
                background-color: transparent;
                border: 2px solid {theme['border_color']};
                border-radius: 15px;
                icon: url('{"src/assets/moon.svg" if self.theme_manager.current_theme == "light" else "src/assets/sun.svg"}');
            }}
            QPushButton#theme-button:hover {{
                background-color: {theme['hover_bg']};
            }}
            QGroupBox {{
                border: 1px solid {theme['border_color']};
                border-radius: 8px;
                margin-top: 20px;
                margin-bottom: 15px;
                background-color: {theme['bg_secondary']};
                padding: 0px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px;
                color: {theme['text_primary']};
                font-weight: bold;
                font-size: 16px;
                background-color: {theme['bg_secondary']};
            }}
            QTableWidget {{
                border: 1px solid {theme['border_color']};
                background-color: {theme['bg_secondary']};
                gridline-color: {theme['border_color']};
                border-radius: 8px;
                color: {theme['text_primary']};
                font-size: 13px;
                alternate-background-color: {theme['table_row_alt']};
                padding: 4px;
                selection-background-color: {theme['accent_primary']};
                selection-color: white;
            }}
            QTableWidget::item {{
                padding: 10px;
                border-bottom: 1px solid {theme['border_color']};
            }}
            QTableWidget::item:selected {{
                background-color: {theme['accent_primary']};
                color: white;
            }}
            QHeaderView::section {{
                background-color: {theme['table_header_bg']};
                color: {theme['text_primary']};
                padding: 10px;
                border: none;
                font-weight: bold;
                font-size: 14px;
                border-right: 1px solid {theme['border_color']};
                border-bottom: 1px solid {theme['border_color']};
            }}
            QHeaderView::section:last {{
                border-right: none;
            }}
            QHeaderView {{
                background-color: {theme['bg_secondary']};
            }}
            QProgressBar {{
                border: none;
                border-radius: 4px;
                background-color: {theme['bg_tertiary']};
                text-align: center;
                color: {theme['text_primary']};
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {theme['accent_primary']};
                border-radius: 4px;
            }}
            QScrollBar:vertical {{
                border: none;
                background-color: {theme['scrollbar_bg']};
                width: 8px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {theme['scrollbar_handle']};
                border-radius: 4px;
                min-height: 20px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: {theme['active_bg']};
            }}
            QPushButton {{
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 15px;
                font-weight: 500;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {theme['accent_secondary']};
            }}
            QPushButton:pressed {{
                background-color: {theme['accent_tertiary']};
            }}
            
            QLineEdit, QComboBox, QTextEdit {{
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                border-radius: 5px;
                padding: 10px;
                selection-background-color: {theme['accent_primary']};
                font-size: 14px;
            }}
            QLineEdit:focus, QComboBox:focus, QTextEdit:focus {{
                border: 2px solid {theme['accent_primary']};
            }}
            
            QCheckBox {{
                spacing: 8px;
                color: {theme['text_primary']};
                font-size: 14px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 1px solid {theme['border_color']};
                border-radius: 3px;
                background-color: {theme['input_bg']};
            }}
            QCheckBox::indicator:checked {{
                background-color: {theme['accent_primary']};
                border: 1px solid {theme['accent_primary']};
            }}
            QCheckBox::indicator:unchecked:hover {{
                border: 1px solid {theme['accent_primary']};
            }}
            
            QLabel {{
                color: {theme['text_primary']};
                font-size: 14px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid {theme['text_secondary']};
                width: 0;
                height: 0;
                margin-right: 5px;
            }}
            QLabel#section-header {{
                color: {theme['text_primary']};
                font-size: 16px;
                font-weight: bold;
                margin-top: 10px;
                margin-bottom: 10px;
                padding-bottom: 5px;
                border-bottom: 1px solid {theme['border_color']};
            }}
            
            QPushButton#delete-button {{
                background-color: {theme['error_color']};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 15px;
                font-weight: 500;
                font-size: 14px;
            }}
            QPushButton#delete-button:hover {{
                background-color: #c82333;
            }}
            
            QComboBox {{
                padding: 5px 10px;
                border: 1px solid {theme['border_color']};
                border-radius: 4px;
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                selection-background-color: {theme['accent_primary']};
                selection-color: white;
            }}
            
            QLineEdit {{
                padding: 5px 10px;
                border: 1px solid {theme['border_color']};
                border-radius: 4px;
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                selection-background-color: {theme['accent_primary']};
            }}
            
            QLineEdit:focus, QComboBox:focus {{
                border: 2px solid {theme['accent_primary']};
            }}
        """)
        
    def add_content_widget(self, name: str, widget: QWidget):
        """Add a widget to the content stack"""
        self.content_stack.addWidget(widget)
        if name in self.nav_buttons:
            self.nav_buttons[name].clicked.connect(
                lambda: self.content_stack.setCurrentWidget(widget)
            )
            
    def show_message(self, title: str, message: str, icon: QMessageBox.Icon = QMessageBox.Icon.Information):
        """Show a message box to the user"""
        msg = QMessageBox(icon, title, message, QMessageBox.StandardButton.Ok, self)
        msg.exec()
        
    def confirm_action(self, title: str, message: str) -> bool:
        """Show a confirmation dialog"""
        reply = QMessageBox.question(self, title, message,
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        return reply == QMessageBox.StandardButton.Yes 