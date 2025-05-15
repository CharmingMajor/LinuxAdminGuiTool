from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QMessageBox, QScrollArea, QSizePolicy, QGridLayout, QFrame)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import psutil
import time
from pathlib import Path
from src.ui.utils.theme_manager import ThemeManager

class BaseDashboard(QMainWindow):
    """Base dashboard with common functionality for both Junior and Senior admins"""
    
    logout_requested = Signal()  # Signal for logout
    switch_role_requested = Signal()  # Signal for switching role (for demo/testing)
    
    def __init__(self, username: str, role: str):
        super().__init__()
        self.username = username
        self.role = role
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.apply_styles)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the base UI components"""
        # Main widget
        central_widget = QWidget()
        central_widget.setObjectName("main-container")
        self.setCentralWidget(central_widget)
        
        # Modern dashboard layout with sidebar and main content area
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create fixed width sidebar first (modern approach)
        sidebar = self.create_sidebar()
        
        # Content container with header and dynamic content
        content_container = QWidget()
        content_container.setObjectName("content-container")
        content_container_layout = QVBoxLayout(content_container)
        content_container_layout.setContentsMargins(0, 0, 0, 0)
        content_container_layout.setSpacing(0)
        
        # Create header bar at top of content area, not the whole app
        header = self.create_header_bar()
        content_container_layout.addWidget(header)
        
        # Content area with stacked widget (pages)
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("content-stack")
        
        # Make stack content scrollable
        content_scroll = QScrollArea()
        content_scroll.setObjectName("content-scroll")
        content_scroll.setWidgetResizable(True)
        content_scroll.setWidget(self.content_stack)
        content_scroll.setFrameShape(QFrame.Shape.NoFrame)
        content_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Add to layout
        content_container_layout.addWidget(content_scroll)
        
        # Add sidebar and content container to main layout
        main_layout.addWidget(sidebar)
        main_layout.addWidget(content_container)
        
        # Set layout proportions for better responsiveness
        main_layout.setStretch(0, 1)  # Sidebar
        main_layout.setStretch(1, 4)  # Content area gets more space
        
        # Storage for nav buttons
        self.nav_buttons = {}
        
        # Track cards for responsive layout
        self._dashboard_cards = []
        self._dashboard_card_names = []
        
        # Apply styles
        self.apply_styles()

    def create_header_bar(self):
        """Create the header bar with theme toggle and quick info"""
        theme = self.theme_manager.get_theme_styles()
        
        header = QWidget()
        header.setObjectName("header-bar")
        header.setMinimumHeight(60)
        header.setMaximumHeight(60)
        
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 0, 24, 0)
        
        # Left side with page title and breadcrumb
        left_side = QWidget()
        left_layout = QVBoxLayout(left_side)
        left_layout.setContentsMargins(0, 8, 0, 8)
        left_layout.setSpacing(2)
        
        # Page title (will be updated by child dashboards)
        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("page-title")
        self.page_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        
        # Breadcrumb path
        self.breadcrumb = QLabel("Home")
        self.breadcrumb.setObjectName("breadcrumb")
        self.breadcrumb.setStyleSheet(f"color: {theme['text_secondary']}; font-size: 12px;")
        
        left_layout.addWidget(self.page_title)
        left_layout.addWidget(self.breadcrumb)
        
        # Right side with theme toggle, user info and role switcher
        right_widgets = QWidget()
        right_layout = QHBoxLayout(right_widgets)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)
        
        # User info with icon/avatar
        user_info = QWidget()
        user_layout = QHBoxLayout(user_info)
        user_layout.setContentsMargins(0, 0, 0, 0)
        user_layout.setSpacing(8)
        
        # User avatar placeholder (would be an image in real app)
        user_avatar = QLabel()
        user_avatar.setObjectName("user-avatar")
        user_avatar.setFixedSize(32, 32)
        user_avatar.setStyleSheet(f"""
            background-color: {theme['accent_primary']};
            color: white;
            border-radius: 16px;
            font-weight: bold;
            text-align: center;
            line-height: 32px;
        """)
        user_avatar.setText(self.username[0].upper())  # First letter of username
        user_layout.addWidget(user_avatar)
        
        # User name and role
        user_info_text = QLabel(f"{self.username}")
        user_info_text.setObjectName("header-user-info")
        role_badge = QLabel(f"{self.role.title()}")
        role_badge.setObjectName("role-badge")
        role_badge.setStyleSheet(f"""
            background-color: {theme['accent_primary']};
            color: white;
            border-radius: 10px;
            padding: 2px 8px;
            font-size: 10px;
            font-weight: bold;
        """)
        
        user_details = QWidget()
        user_details_layout = QVBoxLayout(user_details)
        user_details_layout.setContentsMargins(0, 0, 0, 0)
        user_details_layout.setSpacing(2)
        user_details_layout.addWidget(user_info_text)
        user_details_layout.addWidget(role_badge)
        
        user_layout.addWidget(user_details)
        
        # Theme toggle button with modern icon
        theme_btn = QPushButton()
        theme_btn.setObjectName("theme-button")
        theme_btn.clicked.connect(self.theme_manager.toggle_theme)
        theme_btn.setFixedSize(36, 36)
        theme_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme['bg_tertiary']};
                border: 1px solid {theme['border_color']};
                border-radius: 18px;
            }}
            QPushButton:hover {{
                background-color: {theme['hover_bg']};
            }}
        """)
        
        # Switch Role button (for demo/testing) with modern styling
        switch_btn = QPushButton(f"Switch to {'Senior' if self.role == 'junior' else 'Junior'}")
        switch_btn.setObjectName("switch-role-button")
        switch_btn.setFixedHeight(36)
        switch_btn.clicked.connect(self.switch_role_requested.emit)
        switch_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {theme['bg_tertiary']};
                border: 1px solid {theme['border_color']};
                border-radius: 18px;
                padding: 0 16px;
            }}
            QPushButton:hover {{
                background-color: {theme['hover_bg']};
            }}
        """)
        
        right_layout.addWidget(user_info)
        right_layout.addWidget(theme_btn)
        right_layout.addWidget(switch_btn)
        
        header_layout.addWidget(left_side)
        header_layout.addStretch()
        header_layout.addWidget(right_widgets)
        
        return header
        
    def create_sidebar(self):
        """Create the sidebar with navigation buttons"""
        theme = self.theme_manager.get_theme_styles()
        
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        sidebar.setFixedWidth(240)
        
        # Vertical layout for the entire sidebar
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # App logo/branding section at top
        logo_container = QWidget()
        logo_container.setObjectName("logo-container")
        logo_container.setMinimumHeight(70)
        logo_container.setMaximumHeight(70)
        logo_layout = QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(20, 0, 20, 0)
        
        # Modern logo with icon and text
        app_logo = QLabel()
        app_logo.setObjectName("app-logo")
        app_logo.setFixedSize(32, 32)
        app_logo.setStyleSheet(f"""
            background-color: {theme['accent_primary']};
            color: white;
            border-radius: 8px;
            text-align: center;
            line-height: 32px;
            font-weight: bold;
        """)
        app_logo.setText("LA") # Linux Admin initials
        
        app_title = QLabel("Linux Admin")
        app_title.setObjectName("app-title")
        app_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        
        logo_layout.addWidget(app_logo)
        logo_layout.addWidget(app_title)
        logo_layout.addStretch()
        
        layout.addWidget(logo_container)
        
        # Navigation section
        nav_section = QWidget()
        nav_section.setObjectName("nav-section")
        nav_layout = QVBoxLayout(nav_section)
        nav_layout.setContentsMargins(12, 16, 12, 16)
        nav_layout.setSpacing(4)
        
        # Navigation label
        nav_label = QLabel("NAVIGATION")
        nav_label.setObjectName("nav-label")
        nav_label.setStyleSheet(f"color: {theme['text_secondary']}; font-size: 12px; padding-left: 12px; font-weight: bold;")
        nav_layout.addWidget(nav_label)
        
        # Navigation container for buttons
        self.nav_container = QWidget()
        nav_container_layout = QVBoxLayout(self.nav_container)
        nav_container_layout.setContentsMargins(0, 8, 0, 0)
        nav_container_layout.setSpacing(2)
        
        nav_layout.addWidget(self.nav_container)
        layout.addWidget(nav_section)
        
        # User section at bottom of sidebar
        user_container = QWidget()
        user_container.setObjectName("sidebar-user-container")
        user_container.setMinimumHeight(80)
        user_container.setMaximumHeight(80)
        user_layout = QHBoxLayout(user_container)
        user_layout.setContentsMargins(20, 12, 20, 12)
        
        # User avatar in sidebar
        user_avatar = QLabel()
        user_avatar.setObjectName("sidebar-user-avatar")
        user_avatar.setFixedSize(40, 40)
        user_avatar.setStyleSheet(f"""
            background-color: {theme['accent_primary']};
            color: white;
            border-radius: 20px;
            font-weight: bold;
            text-align: center;
            line-height: 40px;
        """)
        user_avatar.setText(self.username[0].upper())
        
        # User info
        user_info = QWidget()
        user_info_layout = QVBoxLayout(user_info)
        user_info_layout.setContentsMargins(12, 0, 0, 0)
        user_info_layout.setSpacing(2)
        
        username_label = QLabel(self.username)
        username_label.setObjectName("sidebar-username")
        username_label.setStyleSheet("font-weight: bold;")
        
        role_label = QLabel(self.role.title())
        role_label.setObjectName("sidebar-role")
        role_label.setStyleSheet(f"color: {theme['text_secondary']}; font-size: 12px;")
        
        user_info_layout.addWidget(username_label)
        user_info_layout.addWidget(role_label)
        
        user_layout.addWidget(user_avatar)
        user_layout.addWidget(user_info)
        
        # Add spacer to push user section to bottom
        layout.addStretch()
        layout.addWidget(user_container)
        
        return sidebar
        
    def add_nav_button(self, name: str, text: str, icon_path: str = None):
        """Add a navigation button to the sidebar"""
        theme = self.theme_manager.get_theme_styles()
        
        # Create a container for the button to allow for custom layout
        btn_container = QWidget()
        btn_container.setObjectName(f"nav-container-{name}")
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(6, 2, 6, 2)
        btn_layout.setSpacing(0)
        
        # Create the actual button
        btn = QPushButton(text)
        btn.setObjectName(f"nav-button-{name}")
        btn.setCheckable(True)
        btn.setMinimumHeight(38)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        
        # Apply modern styling
        btn.setStyleSheet(f"""
            QPushButton {{
                text-align: left;
                padding-left: 12px;
                border-radius: {theme['radius_md']};
                border: none;
                font-weight: 500;
                color: {theme['sidebar_text']};
                background-color: transparent;
            }}
            QPushButton:hover {{
                background-color: {theme['sidebar_hover']};
            }}
            QPushButton:checked {{
                background-color: {theme['sidebar_active']};
                color: {theme['sidebar_text_active']};
                font-weight: bold;
            }}
        """)
        
        # Add icon if provided
        if icon_path and Path(icon_path).exists():
            btn.setIcon(QIcon(icon_path))
            btn.setIconSize(QSize(18, 18))
        
        # Connect to change page function
        btn.clicked.connect(lambda checked, n=name: self.change_page(n))
        
        # Add button to layout
        btn_layout.addWidget(btn)
        
        # Add to nav container
        self.nav_container.layout().addWidget(btn_container)
        
        # Store reference to button
        self.nav_buttons[name] = btn
        return btn
    
    def change_page(self, name):
        """Change the active page and update button states"""
        # Find the index of the page
        for i in range(self.content_stack.count()):
            if self.content_stack.widget(i).objectName() == name:
                # Set the page title
                title = name.replace('_', ' ').title()
                self.page_title.setText(title)
                
                # Update breadcrumb
                self.breadcrumb.setText(f"Home > {title}")
                
                # Update active button
                for btn_name, btn in self.nav_buttons.items():
                    btn.setChecked(btn_name == name)
                    
                    # Update button styling when active/inactive
                    if btn_name == name:
                        theme = self.theme_manager.get_theme_styles()
                        btn.setStyleSheet(f"""
                            QPushButton {{
                                text-align: left;
                                padding-left: 12px;
                                border-radius: {theme['radius_md']};
                                border: none;
                                font-weight: bold;
                                color: {theme['sidebar_text_active']};
                                background-color: {theme['sidebar_active']};
                            }}
                            QPushButton:hover {{
                                background-color: {theme['sidebar_hover']};
                            }}
                        """)
                    else:
                        theme = self.theme_manager.get_theme_styles()
                        btn.setStyleSheet(f"""
                            QPushButton {{
                                text-align: left;
                                padding-left: 12px;
                                border-radius: {theme['radius_md']};
                                border: none;
                                font-weight: 500;
                                color: {theme['sidebar_text']};
                                background-color: transparent;
                            }}
                            QPushButton:hover {{
                                background-color: {theme['sidebar_hover']};
                            }}
                            QPushButton:checked {{
                                background-color: {theme['sidebar_active']};
                                color: {theme['sidebar_text_active']};
                                font-weight: bold;
                            }}
                        """)
                
                # Switch to the page
                self.content_stack.setCurrentIndex(i)
                break
        
    def add_dashboard_card(self, widget: QWidget, name: str = None):
        """Add a dashboard card to the grid layout responsively."""
        widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        if name:
            widget.setObjectName(name)
            self._dashboard_card_names.append(name)
        self._dashboard_cards.append(widget)
        self._rearrange_dashboard_cards()
        return widget

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._rearrange_dashboard_cards()

    def _rearrange_dashboard_cards(self):
        """Arrange dashboard cards in a responsive grid (2 columns on wide, 1 on narrow)."""
        if not hasattr(self, 'content_grid'):
            return
        # Remove all widgets from the grid
        for i in reversed(range(self.content_grid.count())):
            item = self.content_grid.itemAt(i)
            if item:
                w = item.widget()
                if w:
                    self.content_grid.removeWidget(w)
                    w.setParent(None)
        # Determine number of columns based on width
        width = self.size().width()
        columns = 2 if width > 900 else 1
        for idx, card in enumerate(self._dashboard_cards):
            row = idx // columns
            col = idx % columns
            self.content_grid.addWidget(card, row, col)

    def add_content_widget(self, name: str, widget: QWidget):
        """Add a widget to the content stack"""
        widget.setObjectName(name)
        self.content_stack.addWidget(widget)
        # If this is the first widget, select it
        if self.content_stack.count() == 1:
            self.change_page(name)
        return widget
        
    def apply_styles(self):
        """Apply custom styles to the dashboard"""
        theme = self.theme_manager.get_theme_styles()
        
        # Apply general styles
        self.setStyleSheet(f"""
            QWidget#main-container {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
            }}
            
            QWidget#sidebar {{
                background-color: {theme['sidebar_bg']};
                border-right: 1px solid {theme['border_color']};
            }}
            
            QWidget#content-container {{
                background-color: {theme['bg_primary']};
            }}
            
            QWidget#header-bar {{
                background-color: {theme['header_bg']};
                border-bottom: 1px solid {theme['border_color']};
            }}
            
            QLabel#page-title {{
                color: {theme['text_primary']};
                font-size: 16px;
                font-weight: bold;
            }}
            
            QLabel#app-title {{
                color: {theme['text_primary']};
                font-size: 16px;
                font-weight: bold;
            }}
            
            QScrollArea#content-scroll {{
                background-color: {theme['bg_primary']};
                border: none;
            }}
            
            QScrollArea#content-scroll QScrollBar:vertical {{
                background: {theme['scrollbar_bg']};
                width: 8px;
                border-radius: 4px;
            }}
            
            QScrollArea#content-scroll QScrollBar::handle:vertical {{
                background: {theme['scrollbar_handle']};
                border-radius: 4px;
            }}
            
            QScrollArea#content-scroll QScrollBar::handle:vertical:hover {{
                background: {theme['scrollbar_hover']};
            }}
            
            QScrollArea#content-scroll QScrollBar::add-line:vertical,
            QScrollArea#content-scroll QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QScrollArea#content-scroll QScrollBar::add-page:vertical,
            QScrollArea#content-scroll QScrollBar::sub-page:vertical {{
                background: none;
            }}
            
            /* Frame & card styles */
            QFrame {{
                border-radius: {theme['radius_md']};
                background-color: {theme['bg_tertiary']};
            }}
            
            /* Widget & container styles */
            QWidget#widget-container {{
                background-color: {theme['bg_tertiary']};
                border-radius: {theme['radius_md']};
                border: 1px solid {theme['border_color']};
            }}
        """)
        
        # Apply styles to child widgets as needed
        for btn in self.nav_buttons.values():
            if btn.isChecked():
                btn.setStyleSheet(f"""
                    QPushButton {{
                        text-align: left;
                        padding-left: 12px;
                        border-radius: {theme['radius_md']};
                        border: none;
                        font-weight: bold;
                        color: {theme['sidebar_text_active']};
                        background-color: {theme['sidebar_active']};
                    }}
                    QPushButton:hover {{
                        background-color: {theme['sidebar_hover']};
                    }}
                """)
            else:
                btn.setStyleSheet(f"""
                    QPushButton {{
                        text-align: left;
                        padding-left: 12px;
                        border-radius: {theme['radius_md']};
                        border: none;
                        font-weight: 500;
                        color: {theme['sidebar_text']};
                        background-color: transparent;
                    }}
                    QPushButton:hover {{
                        background-color: {theme['sidebar_hover']};
                    }}
                    QPushButton:checked {{
                        background-color: {theme['sidebar_active']};
                        color: {theme['sidebar_text_active']};
                        font-weight: bold;
                    }}
                """)
                
        # Apply theme-specific icon to theme button
        theme_btn = self.findChild(QPushButton, "theme-button")
        if theme_btn:
            if self.theme_manager.current_theme == 'dark':
                theme_btn.setText("☀️")  # Sun emoji for light mode
            else:
                theme_btn.setText("🌙")  # Moon emoji for dark mode
        
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

    def create_card(self, title=None, content=None, icon=None):
        """Create a modern card widget for dashboard layouts"""
        theme = self.theme_manager.get_theme_styles()
        
        # Create card frame
        card = QFrame()
        card.setObjectName("dashboard-card")
        card.setFrameShape(QFrame.Shape.StyledPanel)
        card.setStyleSheet(f"""
            QFrame#dashboard-card {{
                background-color: {theme['bg_tertiary']};
                border-radius: {theme['radius_md']};
                border: 1px solid {theme['border_color']};
            }}
        """)
        
        # Card layout
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # Create header if title is provided
        if title:
            header = QWidget()
            header.setObjectName("card-header")
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(0, 0, 0, 0)
            header_layout.setSpacing(10)
            
            # Add icon if provided
            if icon:
                icon_label = QLabel()
                icon_label.setObjectName("card-icon")
                icon_label.setFixedSize(24, 24)
                icon_label.setText(icon)
                icon_label.setStyleSheet(f"""
                    QLabel#card-icon {{
                        color: {theme['accent_primary']};
                        font-size: 18px;
                        background-color: {theme['accent_primary'] + '15'};  /* 15% opacity */
                        border-radius: 12px;
                        padding: 1px;
                        qproperty-alignment: AlignCenter;
                    }}
                """)
                header_layout.addWidget(icon_label)
            
            # Add title
            title_label = QLabel(title)
            title_label.setObjectName("card-title")
            title_label.setStyleSheet(f"""
                QLabel#card-title {{
                    color: {theme['text_primary']};
                    font-size: 15px;
                    font-weight: 600;
                }}
            """)
            header_layout.addWidget(title_label)
            header_layout.addStretch()
            
            layout.addWidget(header)
            
            # Add separator
            separator = QFrame()
            separator.setFrameShape(QFrame.Shape.HLine)
            separator.setFrameShadow(QFrame.Shadow.Sunken)
            separator.setStyleSheet(f"""
                background-color: {theme['border_color']};
                border: none;
                max-height: 1px;
            """)
            layout.addWidget(separator)
        
        # Add content if provided
        if content:
            layout.addWidget(content)
        
        return card 