from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QMessageBox, QScrollArea, QSizePolicy, QGridLayout, QFrame)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QFont, QIcon
from pathlib import Path
from src.ui.utils.theme_manager import ThemeManager

class BaseDashboard(QMainWindow):
    """Base dashboard with common functionality for both Junior and Senior admins
    
    Core UI layout shared by both admin types. Handles the shared UI elements:
    - Sidebar navigation menu
    - Header with user info
    - Content area with stacked pages
    
    Junior and Senior dashboards extend this base with role-specific
    pages and functionality restrictions.
    """
    
    # Define signals that can be emitted by the dashboard
    logout_requested = Signal()  # Signal for logout
    switch_role_requested = Signal()  # Signal for switching role (for demo/testing)
    
    def __init__(self, username: str, role: str):
        super().__init__()
        # Store user information
        self.username = username
        self.role = role
        # Get theme manager for consistent styling
        self.theme_manager = ThemeManager()
        # Set up the UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the base UI components common to all dashboards"""
        # Create central widget to hold everything
        central_widget = QWidget()
        central_widget.setObjectName("main-container")
        self.setCentralWidget(central_widget)
        
        # Create main horizontal layout - sidebar on left, content on right
        main_layout = self._create_layout_with_zero_margins(QHBoxLayout, central_widget)
        main_layout.setSpacing(0)
        
        # Create fixed width sidebar for navigation
        sidebar = self.create_sidebar()
        
        # Content container holds header and dynamic content
        content_container = QWidget()
        content_container.setObjectName("content-container")
        content_container_layout = self._create_layout_with_zero_margins(QVBoxLayout, content_container)
        content_container_layout.setSpacing(0)
        
        # Create header bar at top of content area with user info
        header = self.create_header_bar()
        content_container_layout.addWidget(header)
        
        # Create stacked widget to hold different pages of content
        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("content-stack")
        
        # Make content area scrollable
        content_scroll = QScrollArea()
        content_scroll.setObjectName("content-scroll")
        content_scroll.setWidgetResizable(True)
        content_scroll.setWidget(self.content_stack)
        content_scroll.setFrameShape(QFrame.Shape.NoFrame)
        content_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Add scrollable content to layout
        content_container_layout.addWidget(content_scroll)
        
        # Add sidebar and content container to main layout
        main_layout.addWidget(sidebar)
        main_layout.addWidget(content_container)
        
        # Set layout proportions - sidebar smaller, content area larger
        main_layout.setStretch(0, 1)  # Sidebar
        main_layout.setStretch(1, 4)  # Content area gets more space
        
        # Dictionary to store navigation buttons
        self.nav_buttons = {}
        
        # Lists to track dashboard cards for responsive layout
        self._dashboard_cards = []
        self._dashboard_card_names = []
        
        # Apply theme styles
        self.apply_styles()

    def _get_current_theme(self):
        """Get the current theme styles from the theme manager"""
        return self.theme_manager.get_theme_styles()

    def create_header_bar(self):
        """Create the header bar with user info, breadcrumb, and theme toggle
        
        The header appears at the top of the content area and shows:
        - Current page title and breadcrumb
        - User information (username and role)
        - Role switcher button (for demo/testing)
        """
        theme = self._get_current_theme()
        
        # Create header widget with fixed height
        header = QWidget()
        header.setObjectName("header-bar")
        header.setMinimumHeight(60)
        header.setMaximumHeight(60)
        
        # Create header layout
        header_layout = self._create_layout_with_zero_margins(QHBoxLayout, header)
        
        # Left side of header with page title and breadcrumb
        left_side = QWidget()
        left_layout = self._create_layout_with_zero_margins(QVBoxLayout, left_side)
        left_layout.setSpacing(2)
        
        # Page title label - will be updated by child dashboards
        self.page_title = QLabel("Dashboard")
        self.page_title.setObjectName("page-title")
        self.page_title.setStyleSheet("font-weight: bold; font-size: 16px;")
        
        # Breadcrumb path
        self.breadcrumb = QLabel("Home")
        self.breadcrumb.setObjectName("breadcrumb")
        self.breadcrumb.setStyleSheet(f"color: {theme['text_secondary']}; font-size: 12px;")
        
        left_layout.addWidget(self.page_title)
        left_layout.addWidget(self.breadcrumb)
        
        # Right side with user info and role switcher
        right_widgets = QWidget()
        right_layout = self._create_layout_with_zero_margins(QHBoxLayout, right_widgets)
        right_layout.setSpacing(16)
        
        # User info with avatar
        user_info = QWidget()
        user_layout = self._create_layout_with_zero_margins(QHBoxLayout, user_info)
        user_layout.setSpacing(8)
        
        # User avatar - displays first letter of username
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
        user_info_text.setStyleSheet(f"font-weight: bold; color: {theme['text_primary']}; font-size: 14px;")
        
        role_badge = QLabel(f"{self.role.title()}")
        role_badge.setObjectName("role-badge")
        role_badge.setStyleSheet(f"""
            color: {theme['text_secondary']};
            padding: 1px 0px;
            font-size: 12px;
            font-weight: normal;
            background-color: transparent;
            border-radius: 0px;
        """)
        
        # Container for user details
        user_details = QWidget()
        user_details_layout = self._create_layout_with_zero_margins(QVBoxLayout, user_details)
        user_details_layout.setSpacing(2)
        user_details_layout.addWidget(user_info_text)
        user_details_layout.addWidget(role_badge)
        
        user_layout.addWidget(user_details)
        
        # Role switch button (for demo/testing)
        switch_btn = QPushButton(f"Switch to {'Senior' if self.role == 'junior' else 'Junior'}")
        switch_btn.setObjectName("switch-role-button")
        switch_btn.setFixedHeight(36)
        switch_btn.clicked.connect(self.switch_role_requested.emit)
        switch_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {theme['text_secondary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
                padding: 0 16px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {theme['hover_bg']};
                color: {theme['text_primary']};
                border-color: {theme['accent_primary']};
            }}
            QPushButton:pressed {{
                background-color: {theme['active_bg']};
            }}
        """)
        
        # Add user info and switch button to right side layout
        right_layout.addWidget(user_info)
        right_layout.addWidget(switch_btn)
        
        # Add left and right sides to header layout
        header_layout.addWidget(left_side)
        header_layout.addStretch()
        header_layout.addWidget(right_widgets)
        
        return header
        
    def create_sidebar(self):
        """Create the sidebar with navigation buttons
        
        The sidebar appears on the left side of the dashboard and contains:
        - App logo/branding
        - Navigation buttons for different sections
        - Logout button at the bottom
        
        Child classes add specific navigation buttons based on role.
        """
        theme = self._get_current_theme()
        
        # Create sidebar widget with fixed width
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        sidebar.setFixedWidth(240)
        
        # Create vertical layout for sidebar
        layout = self._create_layout_with_zero_margins(QVBoxLayout, sidebar)
        layout.setSpacing(0)
        
        # App logo/branding section at top
        logo_container = QWidget()
        logo_container.setObjectName("logo-container")
        logo_container.setMinimumHeight(70)
        logo_container.setMaximumHeight(70)
        logo_layout = self._create_layout_with_zero_margins(QHBoxLayout, logo_container)
        logo_layout.setContentsMargins(20, 0, 20, 0)
        # Add bottom border to logo container
        logo_container.setStyleSheet(f"""
            QWidget#logo-container {{
                border-bottom: 1px solid {theme['border_color']};
            }}
        """)

        # App logo - text and icon
        app_logo = QLabel()
        app_logo.setObjectName("app-logo")
        app_logo.setFixedSize(32, 32)
        app_logo.setStyleSheet(f"""
            background-color: {theme['accent_primary']};
            color: white;
            border-radius: 16px;
            text-align: center;
            line-height: 32px;
            font-weight: bold;
            font-size: 14px;
        """)
        app_logo.setText("LA") # Linux Admin initials
        
        # App title
        app_title = QLabel("Linux Admin")
        app_title.setObjectName("app-title")
        app_title.setStyleSheet(f"font-weight: bold; font-size: 16px; color: {theme['text_primary']};")
        
        # Add logo and title to logo container
        logo_layout.addWidget(app_logo)
        logo_layout.addSpacing(8)
        logo_layout.addWidget(app_title)
        logo_layout.addStretch()
        
        # Add logo container to sidebar
        layout.addWidget(logo_container)
        
        # Navigation section
        nav_section = QWidget()
        nav_section.setObjectName("nav-section")
        nav_layout = self._create_layout_with_zero_margins(QVBoxLayout, nav_section)
        nav_layout.setSpacing(4)
        
        # Navigation label
        nav_label = QLabel("NAVIGATION")
        nav_label.setObjectName("nav-label")
        nav_label.setStyleSheet(f"color: {theme['text_secondary']}; font-size: 12px; padding-left: 12px; font-weight: bold;")
        nav_layout.addWidget(nav_label)
        
        # Navigation container for buttons
        self.nav_container = QWidget()
        nav_container_layout = self._create_layout_with_zero_margins(QVBoxLayout, self.nav_container)
        nav_container_layout.setSpacing(2)
        
        nav_layout.addWidget(self.nav_container)
        layout.addWidget(nav_section)
        
        # Add spacer to push logout button to bottom
        layout.addStretch()

        # Logout Button at bottom of sidebar
        logout_btn_container = QWidget() # Container for padding
        logout_btn_container_layout = self._create_layout_with_zero_margins(QHBoxLayout, logout_btn_container)
        logout_btn_container_layout.setSpacing(12)

        self.logout_btn = QPushButton("Logout")
        self.logout_btn.setObjectName("logout-button")
        self.logout_btn.setMinimumHeight(40) # Make it a bit taller
        self.logout_btn.clicked.connect(self.logout_requested.emit)
        self.logout_btn.setIcon(QIcon.fromTheme("application-exit")) # Example icon
        self.logout_btn.setStyleSheet(f"""
            QPushButton#logout-button {{
                background-color: {theme['bg_secondary']}; 
                color: {theme['text_secondary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
                text-align: left;
                padding-left: 12px;
                font-weight: 500;
            }}
            QPushButton#logout-button:hover {{
                background-color: {theme['hover_bg']};
                color: {theme['error_color']}; /* Highlight with error/warning color on hover */
                border: 1px solid {theme['error_color']};
            }}
            QPushButton#logout-button:pressed {{
                background-color: {theme['active_bg']}; 
            }}
        """)
        logout_btn_container_layout.addWidget(self.logout_btn)
        layout.addWidget(logout_btn_container)
        
        return sidebar
        
    def add_nav_button(self, name: str, text: str, icon_path: str = None):
        """Add a navigation button to the sidebar"""
        theme = self._get_current_theme()
        
        # Create a container for the button to allow for custom layout
        btn_container = QWidget()
        btn_container.setObjectName(f"nav-container-{name}")
        btn_layout = self._create_layout_with_zero_margins(QHBoxLayout, btn_container)
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
    
    # Had a hard time getting this to work right - the active styling kept getting lost
    # whenever another button was clicked. Had to manually reset all styles each time.
    def change_page(self, name):
        """Change the active page and update button states"""
        theme = self._get_current_theme()  # Get theme once
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

    # Qt calls this whenever window size changes - good place to update responsive layout
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._rearrange_dashboard_cards()

    def _rearrange_dashboard_cards(self):
        """Arrange dashboard cards in a responsive grid (2 columns on wide, 1 on narrow)."""
        if not hasattr(self, 'content_grid'):
            return
        # Remove all widgets from the grid
        for i in reversed(range(self.content_grid.count())):
            if item := self.content_grid.itemAt(i):
                if w := item.widget():
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
        """Apply current theme to the dashboard and its components"""
        theme = self._get_current_theme()
        
        
        # Base styling for the main window and containers
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

    def _create_card_icon_label(self, theme: dict, icon_text: str) -> QLabel:
        """Helper method to create an icon label for a card."""
        icon_label = QLabel()
        icon_label.setObjectName("card-icon")
        icon_label.setFixedSize(24, 24)
        icon_label.setText(icon_text)
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
        return icon_label

    def _create_card_header(self, theme: dict, title: str, icon: str | None) -> QWidget:
        """Helper method to create the header for a card."""
        header = QWidget()
        header.setObjectName("card-header")
        header_layout = self._create_layout_with_zero_margins(QHBoxLayout, header)
        header_layout.setSpacing(10)

        if icon:
            icon_label = self._create_card_icon_label(theme, icon)
            header_layout.addWidget(icon_label)

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
        return header

    def _add_card_separator_and_content(self, layout: QVBoxLayout, theme: dict, content: QWidget | None):
        """Adds a separator and content widget to the card layout."""
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        separator.setStyleSheet(f"""
            background-color: {theme['border_color']};
            border: none;
            max-height: 1px;
        """)
        layout.addWidget(separator)

        if content:
            layout.addWidget(content)

    def create_card(self, title=None, content=None, icon=None):
        """Create a modern card widget for dashboard layouts"""
        theme = self._get_current_theme()
        
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
            card_header = self._create_card_header(theme, title, icon)
            layout.addWidget(card_header)
            
            self._add_card_separator_and_content(layout, theme, content)
        elif content: # If no title, but content exists, add content directly
            layout.addWidget(content)
        
        return card 

    # Made this helper method because I was setting margins=0 constantly
    # Makes code cleaner once you use it a hundred times
    def _create_layout_with_zero_margins(self, layout_class, parent_widget=None):
        """Helper to create a layout and set its content margins to zero."""
        layout = layout_class(parent_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        return layout 