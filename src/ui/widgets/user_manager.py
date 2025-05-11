from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QDialog, QFormLayout, QSpinBox, QGroupBox, QCheckBox, QInputDialog, QGridLayout,
    QFrame, QSplitter, QSizePolicy)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon, QColor
import json
import time

class UserManagerWidget(QWidget):
    """Widget for managing system users and groups"""
    
    task_created = Signal(str, str)  # Signal for task creation (type, description)
    
    def __init__(self, parent=None, is_senior=False, remote=None):
        super().__init__(parent)
        self.is_senior = is_senior
        self.remote = remote
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(30)  # Increased spacing between sections
        main_layout.setContentsMargins(20, 20, 20, 20)  # Added margins
        
        # Page title
        title_label = QLabel("USER MANAGEMENT")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold; color: white; margin-bottom: 15px;")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Status message area for feedback
        self.status_label = QLabel()
        self.status_label.setStyleSheet("""
            background-color: #f8f9fa; 
            border-radius: 8px; 
            padding: 12px; 
            margin: 5px; 
            min-height: 24px;
            font-size: 14px;
            font-weight: bold;
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setVisible(False)  # Hidden by default
        main_layout.addWidget(self.status_label)
        
        # Create a horizontal splitter for user form and list
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.setChildrenCollapsible(False)
        
        # ==================== USER MANAGEMENT SECTION ====================
        # Create a widget for the user form
        user_form = QFrame()
        user_form.setFrameShape(QFrame.Shape.Box)
        user_form.setLineWidth(2)
        user_form.setStyleSheet("""
            QFrame {
                background-color: #2a2a2a; 
                border: 2px solid #555; 
                border-radius: 10px;
            }
        """)
        user_form.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        
        user_form_layout = QVBoxLayout(user_form)
        user_form_layout.setContentsMargins(20, 20, 20, 20)
        user_form_layout.setSpacing(20)
        
        # User form header with icon
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 10)
        
        header_label = QLabel("CREATE NEW USER")
        header_label.setStyleSheet("""
            font-size: 16px; 
            font-weight: bold; 
            color: #0078d4; 
            padding-bottom: 5px;
        """)
        header_layout.addWidget(header_label)
        
        # Add a horizontal line
        header_line = QFrame()
        header_line.setFrameShape(QFrame.Shape.HLine)
        header_line.setFrameShadow(QFrame.Shadow.Sunken)
        header_line.setStyleSheet("background-color: #444;")
        
        user_form_layout.addWidget(header_widget)
        user_form_layout.addWidget(header_line)
        
        # Form fields
        form_widget = QWidget()
        form_grid = QGridLayout(form_widget)
        form_grid.setVerticalSpacing(15)
        form_grid.setHorizontalSpacing(15)
        form_grid.setContentsMargins(10, 10, 10, 10)
        
        # Username
        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
        username_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.username_input = QLineEdit()
        self.username_input.setMinimumHeight(40)
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setStyleSheet("""
            padding: 8px; 
            background-color: #333; 
            color: white; 
            border: 1px solid #555;
            border-radius: 5px;
            font-size: 14px;
        """)
        form_grid.addWidget(username_label, 0, 0)
        form_grid.addWidget(self.username_input, 0, 1)
        
        # Password
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
        password_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.password_input = QLineEdit()
        self.password_input.setMinimumHeight(40)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setStyleSheet("""
            padding: 8px; 
            background-color: #333; 
            color: white; 
            border: 1px solid #555;
            border-radius: 5px;
            font-size: 14px;
        """)
        form_grid.addWidget(password_label, 1, 0)
        form_grid.addWidget(self.password_input, 1, 1)
        
        # Group
        group_label = QLabel("Primary Group:")
        group_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
        group_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.group_combo = QComboBox()
        self.group_combo.setMinimumHeight(40)
        self.group_combo.setStyleSheet("""
            padding: 8px; 
            background-color: #333; 
            color: white; 
            border: 1px solid #555;
            border-radius: 5px;
            font-size: 14px;
        """)
        self.update_group_list()
        form_grid.addWidget(group_label, 2, 0)
        form_grid.addWidget(self.group_combo, 2, 1)
        
        # Sudo checkbox (only for senior admins)
        row = 3
        if self.is_senior:
            sudo_label = QLabel("Sudo Access:")
            sudo_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
            sudo_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.sudo_check = QCheckBox("Grant sudo privileges")
            self.sudo_check.setStyleSheet("color: white; font-size: 14px;")
            self.sudo_check.setMinimumHeight(40)
            form_grid.addWidget(sudo_label, row, 0)
            form_grid.addWidget(self.sudo_check, row, 1)
            row += 1
        
        user_form_layout.addWidget(form_widget)
        
        # Action buttons
        button_widget = QWidget()
        button_layout = QHBoxLayout(button_widget)
        button_layout.setContentsMargins(0, 10, 0, 0)
        button_layout.setSpacing(15)
        
        create_user_btn = QPushButton("Create User")
        create_user_btn.setMinimumHeight(45)
        create_user_btn.setMinimumWidth(150)
        create_user_btn.setStyleSheet("""
            background-color: #0078d4; 
            color: white; 
            font-weight: bold; 
            border-radius: 6px;
            font-size: 14px;
        """)
        create_user_btn.clicked.connect(self.create_user)
        
        if self.is_senior:
            delete_user_btn = QPushButton("Delete User")
            delete_user_btn.setMinimumHeight(45)
            delete_user_btn.setMinimumWidth(150)
            delete_user_btn.setStyleSheet("""
                background-color: #dc3545; 
                color: white; 
                font-weight: bold; 
                border-radius: 6px;
                font-size: 14px;
            """)
            delete_user_btn.clicked.connect(self.delete_user)
            button_layout.addWidget(delete_user_btn)
            
        button_layout.addWidget(create_user_btn)
        user_form_layout.addWidget(button_widget, 0, Qt.AlignmentFlag.AlignCenter)
        
        # ==================== USER LIST SECTION ====================
        # User Table
        user_list = QFrame()
        user_list.setFrameShape(QFrame.Shape.Box)
        user_list.setLineWidth(2)
        user_list.setStyleSheet("""
            QFrame {
                background-color: #2a2a2a; 
                border: 2px solid #555; 
                border-radius: 10px;
            }
        """)
        user_list.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        
        user_list_layout = QVBoxLayout(user_list)
        user_list_layout.setContentsMargins(20, 20, 20, 20)
        user_list_layout.setSpacing(15)
        
        # Table header with icon
        table_header_widget = QWidget()
        table_header_layout = QHBoxLayout(table_header_widget)
        table_header_layout.setContentsMargins(0, 0, 0, 10)
        
        table_header = QLabel("CURRENT USER ACCOUNTS")
        table_header.setStyleSheet("""
            font-size: 16px; 
            font-weight: bold; 
            color: #0078d4; 
            padding-bottom: 5px;
        """)
        table_header_layout.addWidget(table_header)
        
        # Add a horizontal line
        table_header_line = QFrame()
        table_header_line.setFrameShape(QFrame.Shape.HLine)
        table_header_line.setFrameShadow(QFrame.Shadow.Sunken)
        table_header_line.setStyleSheet("background-color: #444;")
        
        user_list_layout.addWidget(table_header_widget)
        user_list_layout.addWidget(table_header_line)
        
        self.user_table = QTableWidget()
        self.user_table.setColumnCount(5 if self.is_senior else 4)
        headers = ["Username", "UID", "Primary Group", "Home Directory"]
        if self.is_senior:
            headers.append("Sudo")
        self.user_table.setHorizontalHeaderLabels(headers)
        self.user_table.horizontalHeader().setStretchLastSection(True)
        self.user_table.setAlternatingRowColors(True)
        self.user_table.verticalHeader().setVisible(False)
        self.user_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.user_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.user_table.setMinimumHeight(250)  # Increased height
        self.user_table.setStyleSheet("""
            QTableWidget {
                background-color: #333;
                color: white;
                gridline-color: #555;
                border: none;
                font-size: 13px;
            }
            QTableWidget::item {
                border-bottom: 1px solid #444;
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QHeaderView::section {
                background-color: #2c2c2c;
                color: white;
                padding: 8px;
                border: 1px solid #444;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        
        # Set column widths
        self.user_table.setColumnWidth(0, 150)  # Username
        self.user_table.setColumnWidth(1, 80)   # UID
        self.user_table.setColumnWidth(2, 150)  # Primary Group
        self.user_table.setColumnWidth(3, 300)  # Home Directory
        
        # Add refresh button
        refresh_btn = QPushButton("Refresh User List")
        refresh_btn.setMinimumHeight(40)
        refresh_btn.setStyleSheet("""
            background-color: #444; 
            color: white; 
            padding: 8px; 
            margin-top: 10px; 
            border-radius: 6px;
            font-size: 14px;
        """)
        refresh_btn.clicked.connect(self.update_user_list)
        
        user_list_layout.addWidget(self.user_table)
        user_list_layout.addWidget(refresh_btn)
        
        # Add user management widgets to the splitter
        top_splitter.addWidget(user_form)
        top_splitter.addWidget(user_list)
        
        # Set the initial sizes for the splitter
        top_splitter.setSizes([400, 800])
        
        main_layout.addWidget(top_splitter)
        
        if self.is_senior:
            # ==================== GROUP MANAGEMENT SECTION ====================
            group_section = QFrame()
            group_section.setFrameShape(QFrame.Shape.Box)
            group_section.setLineWidth(2)
            group_section.setStyleSheet("""
                QFrame {
                    background-color: #2a2a2a; 
                    border: 2px solid #555; 
                    border-radius: 10px;
                }
            """)
            
            # Create a horizontal layout for the group section
            group_horizontal_layout = QHBoxLayout()
            group_horizontal_layout.setSpacing(20)
            
            # Group section
            group_layout = QVBoxLayout(group_section)
            group_layout.setContentsMargins(20, 20, 20, 20)
            group_layout.setSpacing(15)
            
            # Section header
            group_section_header = QLabel("GROUP MANAGEMENT")
            group_section_header.setStyleSheet("""
                font-size: 16px; 
                font-weight: bold; 
                color: #0078d4; 
                padding-bottom: 5px;
            """)
            group_section_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Add a horizontal line
            group_section_line = QFrame()
            group_section_line.setFrameShape(QFrame.Shape.HLine)
            group_section_line.setFrameShadow(QFrame.Shadow.Sunken)
            group_section_line.setStyleSheet("background-color: #444;")
            
            group_layout.addWidget(group_section_header)
            group_layout.addWidget(group_section_line)
            
            # Split the group section into two parts
            group_splitter = QSplitter(Qt.Orientation.Horizontal)
            group_splitter.setChildrenCollapsible(False)
            
            # Group creation form
            group_form_widget = QFrame()
            group_form_widget.setFrameShape(QFrame.Shape.StyledPanel)
            group_form_widget.setStyleSheet("""
                QFrame {
                    background-color: #2d2d2d; 
                    border: 1px solid #444; 
                    border-radius: 8px;
                }
            """)
            group_form_widget.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
            
            group_form_layout = QVBoxLayout(group_form_widget)
            group_form_layout.setContentsMargins(15, 15, 15, 15)
            group_form_layout.setSpacing(15)
            
            group_header = QLabel("Create New Group")
            group_header.setStyleSheet("""
                font-size: 15px; 
                font-weight: bold; 
                color: white; 
                padding-bottom: 5px;
            """)
            group_form_layout.addWidget(group_header)
            
            # Group form fields
            group_form_fields = QWidget()
            group_fields_layout = QFormLayout(group_form_fields)
            group_fields_layout.setVerticalSpacing(15)
            group_fields_layout.setContentsMargins(5, 5, 5, 5)
            
            group_name_label = QLabel("Group Name:")
            group_name_label.setStyleSheet("font-weight: bold; font-size: 14px; color: white;")
            
            self.group_name_input = QLineEdit()
            self.group_name_input.setMinimumHeight(40)
            self.group_name_input.setPlaceholderText("Enter group name")
            self.group_name_input.setStyleSheet("""
                padding: 8px; 
                background-color: #333; 
                color: white; 
                border: 1px solid #555;
                border-radius: 5px;
                font-size: 14px;
            """)
            
            group_fields_layout.addRow(group_name_label, self.group_name_input)
            group_form_layout.addWidget(group_form_fields)
            
            create_group_btn = QPushButton("Create Group")
            create_group_btn.setMinimumHeight(40)
            create_group_btn.setMinimumWidth(150)
            create_group_btn.setStyleSheet("""
                background-color: #0078d4; 
                color: white; 
                font-weight: bold; 
                border-radius: 6px;
                font-size: 14px;
            """)
            create_group_btn.clicked.connect(self.create_group)
            
            group_form_layout.addWidget(create_group_btn, 0, Qt.AlignmentFlag.AlignCenter)
            group_form_layout.addStretch()
            
            # Group list
            group_list_widget = QFrame()
            group_list_widget.setFrameShape(QFrame.Shape.StyledPanel)
            group_list_widget.setStyleSheet("""
                QFrame {
                    background-color: #2d2d2d; 
                    border: 1px solid #444; 
                    border-radius: 8px;
                }
            """)
            group_list_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
            
            group_list_layout = QVBoxLayout(group_list_widget)
            group_list_layout.setContentsMargins(15, 15, 15, 15)
            group_list_layout.setSpacing(15)
            
            group_table_header = QLabel("Current Groups")
            group_table_header.setStyleSheet("""
                font-size: 15px; 
                font-weight: bold; 
                color: white; 
                padding-bottom: 5px;
            """)
            group_list_layout.addWidget(group_table_header)
            
            self.group_table = QTableWidget()
            self.group_table.setColumnCount(3)
            self.group_table.setHorizontalHeaderLabels(["Group Name", "GID", "Members"])
            self.group_table.horizontalHeader().setStretchLastSection(True)
            self.group_table.setAlternatingRowColors(True)
            self.group_table.verticalHeader().setVisible(False)
            self.group_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.group_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
            self.group_table.setMinimumHeight(250)  # Increased height
            self.group_table.setStyleSheet("""
                QTableWidget {
                    background-color: #333;
                    color: white;
                    gridline-color: #555;
                    border: none;
                    font-size: 13px;
                }
                QTableWidget::item {
                    border-bottom: 1px solid #444;
                    padding: 8px;
                }
                QTableWidget::item:selected {
                    background-color: #0078d4;
                    color: white;
                }
                QHeaderView::section {
                    background-color: #2c2c2c;
                    color: white;
                    padding: 8px;
                    border: 1px solid #444;
                    font-weight: bold;
                    font-size: 14px;
                }
            """)
            
            # Set column widths
            self.group_table.setColumnWidth(0, 150)  # Group Name
            self.group_table.setColumnWidth(1, 80)   # GID
            
            # Add refresh button
            refresh_group_btn = QPushButton("Refresh Group List")
            refresh_group_btn.setMinimumHeight(40)
            refresh_group_btn.setStyleSheet("""
                background-color: #444; 
                color: white; 
                padding: 8px; 
                margin-top: 10px; 
                border-radius: 6px;
                font-size: 14px;
            """)
            refresh_group_btn.clicked.connect(self.update_group_table)
            
            group_list_layout.addWidget(self.group_table)
            group_list_layout.addWidget(refresh_group_btn)
            
            # Add widgets to the splitter
            group_splitter.addWidget(group_form_widget)
            group_splitter.addWidget(group_list_widget)
            
            # Set initial sizes for the splitter
            group_splitter.setSizes([400, 800])
            
            group_layout.addWidget(group_splitter)
            main_layout.addWidget(group_section)
            
        # Initial data load
        self.refresh_data()
        
    def refresh_data(self):
        """Refresh all displayed data"""
        # Use QTimer to ensure the refresh happens after UI events
        QTimer.singleShot(100, self._refresh_data_implementation)
    
    def _refresh_data_implementation(self):
        """Implementation of refresh that happens after a short delay"""
        self.update_user_list()
        self.update_group_list()
        if self.is_senior:
            self.update_group_table()
        
    def update_group_list(self):
        """Update the group dropdown list"""
        try:
            if self.remote:
                stdout, _ = self.remote.execute_command("getent group")
                groups = []
                for line in stdout.splitlines():
                    group_name = line.split(":")[0]
                    groups.append(group_name)
            else:
                import grp
                groups = [g.gr_name for g in grp.getgrall()]
                
            self.group_combo.clear()
            self.group_combo.addItems(sorted(groups))
        except Exception as e:
            self.show_status(f"Failed to load groups: {str(e)}", True)
            
    def update_user_list(self):
        """Update the user list table"""
        try:
            self.user_table.setRowCount(0)
            
            if self.remote:
                stdout, stderr = self.remote.execute_command("getent passwd")
                if stderr:
                    self.show_status(f"Error getting user list: {stderr}", True)
                    return
                    
                for line in stdout.splitlines():
                    user_info = line.split(":")
                    # Skip system users
                    if int(user_info[2]) < 1000 and not self.is_senior:
                        continue
                        
                    row = self.user_table.rowCount()
                    self.user_table.insertRow(row)
                    
                    # Username
                    self.user_table.setItem(row, 0, QTableWidgetItem(user_info[0]))
                    # UID
                    self.user_table.setItem(row, 1, QTableWidgetItem(user_info[2]))
                    # Primary Group
                    stdout, _ = self.remote.execute_command(f"getent group {user_info[3]}")
                    group_name = stdout.split(":")[0] if stdout else user_info[3]
                    self.user_table.setItem(row, 2, QTableWidgetItem(group_name))
                    # Home Directory
                    self.user_table.setItem(row, 3, QTableWidgetItem(user_info[5]))
                    
                    if self.is_senior:
                        # Check sudo access
                        has_sudo = self.check_sudo_access(user_info[0])
                        self.user_table.setItem(row, 4, QTableWidgetItem("Yes" if has_sudo else "No"))
            else:
                import pwd
                import grp
                import subprocess
                
                # Use subprocess to get user list with sudo to ensure we have proper permissions
                try:
                    result = subprocess.run(['sudo', 'cat', '/etc/passwd'], 
                                           stdout=subprocess.PIPE, 
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True,
                                           check=False)
                    
                    if result.returncode != 0:
                        # If sudo fails, fall back to regular method
                        passwd_entries = pwd.getpwall()
                    else:
                        # Parse the output directly
                        passwd_entries = []
                        for line in result.stdout.splitlines():
                            fields = line.split(':')
                            if len(fields) >= 7:
                                # Create a simplified pwd entry-like object for consistent processing
                                class PwdEntry:
                                    def __init__(self, name, pw_gid, pw_uid, pw_dir):
                                        self.pw_name = name
                                        self.pw_gid = int(pw_gid)
                                        self.pw_uid = int(pw_uid)
                                        self.pw_dir = pw_dir
                                
                                passwd_entries.append(PwdEntry(
                                    fields[0],  # username
                                    fields[3],  # gid
                                    fields[2],  # uid
                                    fields[5]   # home dir
                                ))
                                
                    # Process all entries
                    for user in passwd_entries:
                        # Skip system users
                        if user.pw_uid < 1000 and not self.is_senior:
                            continue
                            
                        row = self.user_table.rowCount()
                        self.user_table.insertRow(row)
                        
                        self.user_table.setItem(row, 0, QTableWidgetItem(user.pw_name))
                        self.user_table.setItem(row, 1, QTableWidgetItem(str(user.pw_uid)))
                        
                        # Get group name - try with sudo first for better permission access
                        try:
                            group_result = subprocess.run(
                                ['sudo', 'getent', 'group', str(user.pw_gid)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                check=False
                            )
                            
                            if group_result.returncode == 0 and group_result.stdout:
                                group_name = group_result.stdout.split(':')[0]
                            else:
                                # Fallback to regular method
                                group_name = grp.getgrgid(user.pw_gid).gr_name
                                
                            self.user_table.setItem(row, 2, QTableWidgetItem(group_name))
                        except:
                            # If we can't get the group name, just show the GID
                            self.user_table.setItem(row, 2, QTableWidgetItem(str(user.pw_gid)))
                            
                        self.user_table.setItem(row, 3, QTableWidgetItem(user.pw_dir))
                        
                        if self.is_senior:
                            # Check sudo access
                            has_sudo = self.check_sudo_access(user.pw_name)
                            self.user_table.setItem(row, 4, QTableWidgetItem("Yes" if has_sudo else "No"))
                except Exception as e:
                    self.show_status(f"Error loading users: {str(e)}", True)
                    
        except Exception as e:
            self.show_status(f"Failed to load user list: {str(e)}", True)
            
    def update_group_table(self):
        """Update the group table"""
        try:
            self.group_table.setRowCount(0)
            
            if self.remote:
                stdout, stderr = self.remote.execute_command("getent group")
                if stderr:
                    self.show_status(f"Error getting group list: {stderr}", True)
                    return
                    
                for line in stdout.splitlines():
                    group_info = line.split(":")
                    row = self.group_table.rowCount()
                    self.group_table.insertRow(row)
                    
                    self.group_table.setItem(row, 0, QTableWidgetItem(group_info[0]))  # Name
                    self.group_table.setItem(row, 1, QTableWidgetItem(group_info[2]))  # GID
                    self.group_table.setItem(row, 2, QTableWidgetItem(group_info[3]))  # Members
            else:
                # Try to use sudo to get more accurate group information
                import subprocess
                
                try:
                    result = subprocess.run(['sudo', 'cat', '/etc/group'], 
                                          stdout=subprocess.PIPE, 
                                          stderr=subprocess.PIPE,
                                          universal_newlines=True,
                                          check=False)
                                          
                    if result.returncode != 0:
                        # Fallback to standard method if sudo fails
                        import grp
                        for group in grp.getgrall():
                            row = self.group_table.rowCount()
                            self.group_table.insertRow(row)
                            
                            self.group_table.setItem(row, 0, QTableWidgetItem(group.gr_name))
                            self.group_table.setItem(row, 1, QTableWidgetItem(str(group.gr_gid)))
                            self.group_table.setItem(row, 2, QTableWidgetItem(", ".join(group.gr_mem)))
                    else:
                        # Process the output directly from cat /etc/group
                        for line in result.stdout.splitlines():
                            fields = line.split(':')
                            if len(fields) >= 4:
                                row = self.group_table.rowCount()
                                self.group_table.insertRow(row)
                                
                                self.group_table.setItem(row, 0, QTableWidgetItem(fields[0]))  # Name
                                self.group_table.setItem(row, 1, QTableWidgetItem(fields[2]))  # GID
                                self.group_table.setItem(row, 2, QTableWidgetItem(fields[3]))  # Members
                except Exception as e:
                    self.show_status(f"Error loading groups: {str(e)}", True)
                
        except Exception as e:
            self.show_status(f"Failed to load group list: {str(e)}", True)
            
    def create_user(self):
        """Create a new user"""
        username = self.username_input.text()
        password = self.password_input.text()
        group = self.group_combo.currentText()
        
        if not username or not password:
            self.show_status("Please provide both username and password", True)
            return
            
        try:
            if self.is_senior:
                # Senior admins can create users directly
                if self.remote:
                    cmd = f"echo '{password}' | sudo -S useradd -m -g {group}"
                    if hasattr(self, 'sudo_check') and self.sudo_check.isChecked():
                        cmd += " -G sudo"
                    cmd += f" {username}"
                    
                    stdout, stderr = self.remote.execute_command(cmd)
                    if stderr and not "password for" in stderr:
                        raise Exception(stderr)
                        
                    # Set password
                    cmd = f"echo '{password}' | sudo -S bash -c \"echo '{username}:{password}' | chpasswd\""
                    _, stderr = self.remote.execute_command(cmd)
                    if stderr and not "password for" in stderr:
                        raise Exception(stderr)
                else:
                    import subprocess
                    # First try getting sudo password if needed
                    try:
                        # Create the user
                        cmd = ['sudo', 'useradd', '-m', '-g', group]
                        if hasattr(self, 'sudo_check') and self.sudo_check.isChecked():
                            cmd.extend(['-G', 'sudo'])
                        cmd.append(username)
                        
                        result = subprocess.run(cmd, stderr=subprocess.PIPE, universal_newlines=True, check=False)
                        if result.returncode != 0:
                            if "exists" in result.stderr:
                                self.show_status(f"User {username} already exists", True)
                                return
                            else:
                                raise Exception(f"User creation failed: {result.stderr}")
                        
                        # Set password using chpasswd
                        passwd_proc = subprocess.Popen(['sudo', 'chpasswd'], 
                                                      stdin=subprocess.PIPE,
                                                      stderr=subprocess.PIPE,
                                                      universal_newlines=True)
                        
                        stdout, stderr = passwd_proc.communicate(input=f"{username}:{password}")
                        if passwd_proc.returncode != 0:
                            raise Exception(f"Password setup failed: {stderr}")
                            
                    except Exception as e:
                        self.show_status(f"Failed during user creation: {str(e)}", True)
                        return
                
                self.show_status(f"User {username} created successfully")
                
                # Clear inputs first (before refresh)
                self.username_input.clear()
                self.password_input.clear()
                
                # Explicitly wait a moment for the system to register the new user
                import time
                time.sleep(1)
                
                # DIRECT UPDATE - manually add the new user to the table
                row = self.user_table.rowCount()
                self.user_table.insertRow(row)
                
                self.user_table.setItem(row, 0, QTableWidgetItem(username))  # Username
                
                # Get UID and other details
                import subprocess
                try:
                    uid_result = subprocess.run(['sudo', 'id', '-u', username], 
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                             universal_newlines=True, check=False)
                    uid = uid_result.stdout.strip() if uid_result.returncode == 0 else "?"
                    self.user_table.setItem(row, 1, QTableWidgetItem(uid))  # UID
                    
                    # Group
                    self.user_table.setItem(row, 2, QTableWidgetItem(group))  # Primary Group
                    
                    # Home directory
                    home_result = subprocess.run(['sudo', 'eval', 'echo', '~' + username], 
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                              universal_newlines=True, check=False)
                    home = home_result.stdout.strip() if home_result.returncode == 0 else f"/home/{username}"
                    self.user_table.setItem(row, 3, QTableWidgetItem(home))  # Home Directory
                    
                    # Sudo status
                    if self.is_senior:
                        has_sudo = hasattr(self, 'sudo_check') and self.sudo_check.isChecked()
                        self.user_table.setItem(row, 4, QTableWidgetItem("Yes" if has_sudo else "No"))  # Sudo
                except:
                    # If we can't get details, at least show the username
                    if row > 0:
                        for col in range(1, self.user_table.columnCount()):
                            self.user_table.setItem(row, col, QTableWidgetItem(""))
                
                # Highlight the new user
                self.highlight_new_item(self.user_table, username, 0)
                
                # Also do a full refresh in the background
                QTimer.singleShot(2000, self.refresh_data)
                
            else:
                # Junior admins create task requests
                description = f"Create user account: {username} with group {group}"
                self.task_created.emit("User Account Created", description)
                self.show_message("Task Request Submitted", "User creation request has been submitted")
                
                # Clear inputs
                self.username_input.clear()
                self.password_input.clear()
                
        except Exception as e:
            self.show_status(f"Failed to create user: {str(e)}", True)
            
    def delete_user(self):
        """Delete selected user (Senior only)"""
        if not self.is_senior:
            return
            
        current_row = self.user_table.currentRow()
        if current_row < 0:
            self.show_status("Please select a user to delete", True)
            return
            
        username = self.user_table.item(current_row, 0).text()
        
        # Get admin password
        password, ok = QInputDialog.getText(
            self, "Admin Password", "Enter your password:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            return
        
        if self.confirm_action(f"Are you sure you want to delete user {username}?"):
            try:
                if self.remote:
                    cmd = f"echo '{password}' | sudo -S userdel -r {username}"
                    _, stderr = self.remote.execute_command(cmd)
                    if stderr and not "password for" in stderr:
                        raise Exception(stderr)
                else:
                    import subprocess
                    subprocess.run(['sudo', 'userdel', '-r', username], check=True)
                    
                self.show_status(f"User {username} deleted successfully")
                self.refresh_data()
            except Exception as e:
                self.show_status(f"Failed to delete user: {str(e)}", True)
                
    def create_group(self):
        """Create a new group (Senior only)"""
        if not self.is_senior:
            return
            
        group_name = self.group_name_input.text()
        
        if not group_name:
            self.show_status("Please provide a group name", True)
            return
            
        # Get admin password
        password, ok = QInputDialog.getText(
            self, "Admin Password", "Enter your password:", QLineEdit.EchoMode.Password)
        if not ok or not password:
            return
            
        try:
            if self.remote:
                cmd = f"echo '{password}' | sudo -S groupadd {group_name}"
                _, stderr = self.remote.execute_command(cmd)
                if stderr and not "password for" in stderr:
                    raise Exception(stderr)
            else:
                import subprocess
                result = subprocess.run(['sudo', 'groupadd', group_name],
                                      stderr=subprocess.PIPE,
                                      universal_newlines=True,
                                      check=False)
                                      
                if result.returncode != 0:
                    if "exists" in result.stderr:
                        self.show_status(f"Group {group_name} already exists", True)
                        return
                    else:
                        raise Exception(f"Group creation failed: {result.stderr}")
                
            self.show_status(f"Group {group_name} created successfully")
            self.group_name_input.clear()
            
            # Explicitly wait a moment for the system to register the new group
            import time
            time.sleep(1)
            
            # DIRECT UPDATE - manually add the new group to the table
            row = self.group_table.rowCount()
            self.group_table.insertRow(row)
            
            self.group_table.setItem(row, 0, QTableWidgetItem(group_name))  # Group Name
            
            # Get GID
            import subprocess
            try:
                gid_result = subprocess.run(['sudo', 'getent', 'group', group_name], 
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                         universal_newlines=True, check=False)
                if gid_result.returncode == 0:
                    gid = gid_result.stdout.strip().split(':')[2]
                    self.group_table.setItem(row, 1, QTableWidgetItem(gid))  # GID
                    
                    # Members (empty for new group)
                    self.group_table.setItem(row, 2, QTableWidgetItem(""))  # Members
                else:
                    # Fallback
                    self.group_table.setItem(row, 1, QTableWidgetItem("?"))  # GID
                    self.group_table.setItem(row, 2, QTableWidgetItem(""))  # Members
            except:
                # If we can't get details, at least show the group name
                if row > 0:
                    self.group_table.setItem(row, 1, QTableWidgetItem(""))
                    self.group_table.setItem(row, 2, QTableWidgetItem(""))
            
            # Highlight the new group
            self.highlight_new_item(self.group_table, group_name, 0)
            
            # Also update the group combo box for user creation
            if self.group_combo.findText(group_name) == -1:
                self.group_combo.addItem(group_name)
                
            # Also do a full refresh in the background
            QTimer.singleShot(2000, self.refresh_data)
            
        except Exception as e:
            self.show_status(f"Failed to create group: {str(e)}", True)
            
    def check_sudo_access(self, username):
        """Check if a user has sudo access"""
        try:
            if self.remote:
                stdout, _ = self.remote.execute_command(f"groups {username}")
                groups = stdout.strip().split(":")[1].strip().split()
                return "sudo" in groups or "wheel" in groups
            else:
                import grp
                sudo_group = grp.getgrnam("sudo")
                wheel_group = grp.getgrnam("wheel")
                return username in sudo_group.gr_mem or username in wheel_group.gr_mem
        except:
            return False
            
    def show_message(self, title, message):
        """Show an information message box"""
        QMessageBox.information(self, title, message)
        
    def show_status(self, message, is_error=False):
        """Show a status message to the user"""
        if is_error:
            self.status_label.setStyleSheet("""
                background-color: #f8d7da; 
                color: #721c24; 
                border-radius: 8px; 
                padding: 12px; 
                margin: 5px; 
                font-weight: bold;
                font-size: 14px;
            """)
        else:
            self.status_label.setStyleSheet("""
                background-color: #d4edda; 
                color: #155724; 
                border-radius: 8px; 
                padding: 12px; 
                margin: 5px; 
                font-weight: bold;
                font-size: 14px;
            """)
            
        self.status_label.setText(message)
        self.status_label.setVisible(True)
        
        # Auto-hide after 5 seconds
        QTimer.singleShot(5000, lambda: self.status_label.setVisible(False))
        
    def confirm_action(self, message):
        """Show a confirmation dialog"""
        return QMessageBox.question(self, "Confirm Action", message,
            QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes 

    def highlight_new_item(self, table, item_text, column=0):
        """Highlight a newly added item in a table"""
        for row in range(table.rowCount()):
            if table.item(row, column) and table.item(row, column).text() == item_text:
                for col in range(table.columnCount()):
                    if table.item(row, col):
                        table.item(row, col).setBackground(QColor(25, 135, 84, 100))  # Green background
                table.scrollToItem(table.item(row, column))
                break 