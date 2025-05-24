from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QDialog,
    QFormLayout, QComboBox, QCheckBox, QGroupBox, QScrollArea, QTextEdit,
    QRadioButton
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from src.utils.remote_connection import RemoteConnection
from src.backend.senior_dashboard_backend import SeniorDashboardBackend
from src.backend.junior_backend import JuniorBackend, JUNIOR_MANAGEABLE_GROUPS

# Manages user and group operations within the UI.
class UserManagerWidget(QWidget):
    def __init__(self, remote: RemoteConnection, is_senior: bool, parent=None):
        super().__init__(parent)
        self.remote = remote
        self.is_senior = is_senior

        # Initialize backend based on user role (senior or junior)
        if self.is_senior:
            self.backend = SeniorDashboardBackend(remote)
        else:
            self.backend = JuniorBackend(remote)

        self.setWindowTitle("User and Group Management")
        self._setup_ui()
        self.load_users_and_groups() # Load initial data

    # Sets up the main UI layout and widgets.
    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        
        # --- Top controls --- 
        controls_layout = QHBoxLayout()
        self.add_user_button = QPushButton("Add User")
        self.add_user_button.clicked.connect(self._show_add_user_dialog)
        controls_layout.addWidget(self.add_user_button)
        
        # Add more user management buttons
        if self.is_senior:
            self.delete_user_button = QPushButton("Delete User")
            self.delete_user_button.clicked.connect(self._delete_selected_user)
            controls_layout.addWidget(self.delete_user_button)
            
            self.modify_user_button = QPushButton("Modify User")
            self.modify_user_button.clicked.connect(self._modify_selected_user)
            controls_layout.addWidget(self.modify_user_button)
        
        # Both Senior and Junior can reset passwords, but Junior has restrictions
        self.reset_password_button = QPushButton("Reset Password")
        self.reset_password_button.clicked.connect(self._reset_user_password)
        controls_layout.addWidget(self.reset_password_button)
        
        controls_layout.addStretch()
        main_layout.addLayout(controls_layout)

        # --- Role Explanation Box ---
        role_box = QGroupBox("Role-Based Permissions")
        role_layout = QVBoxLayout(role_box)
        
        if self.is_senior:
            role_text = "Senior Admin Role: You have full access to create, modify, and delete users and groups, " \
                        "and to change file and directory ownership and permissions."
        else:
            role_text = "Junior Admin Role: You can only create users and groups, reset passwords, and assign users to " \
                        "specific groups. You cannot delete or modify existing users or groups."
        
        role_label = QLabel(role_text)
        role_label.setWordWrap(True)
        role_layout.addWidget(role_label)
        main_layout.addWidget(role_box)

        # --- Users Table --- 
        users_group = QGroupBox("Users")
        users_layout = QVBoxLayout(users_group)
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(6) # Username, UID, GID, Comment, Home, Shell
        self.users_table.setHorizontalHeaderLabels(["Username", "UID", "GID", "Comment", "Home Directory", "Shell"])
        self.users_table.horizontalHeader().setStretchLastSection(False)
        self.users_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.users_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.users_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.users_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.users_table.setEditTriggers(QTableWidget.NoEditTriggers)
        users_layout.addWidget(self.users_table)
        main_layout.addWidget(users_group)

        # Add output console for terminal-like messages
        output_group = QGroupBox("Command Output")
        output_layout = QVBoxLayout(output_group)
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #121212; color: #CCCCCC; font-family: 'Courier New', monospace;")
        self.output_console.setMinimumHeight(150)
        output_layout.addWidget(self.output_console)
        main_layout.addWidget(output_group)

        # Groups section
        groups_group = QGroupBox("Groups")
        groups_layout = QVBoxLayout(groups_group)
        
        # Group controls
        group_controls = QHBoxLayout()
        self.add_group_button = QPushButton("Add Group")
        self.add_group_button.clicked.connect(self._show_add_group_dialog)
        group_controls.addWidget(self.add_group_button)
        
        if self.is_senior:
            self.delete_group_button = QPushButton("Delete Group")
            self.delete_group_button.clicked.connect(self._delete_selected_group)
            group_controls.addWidget(self.delete_group_button)
            
            self.modify_group_button = QPushButton("Modify Group")
            self.modify_group_button.clicked.connect(self._modify_selected_group)
            group_controls.addWidget(self.modify_group_button)
        
        group_controls.addStretch()
        groups_layout.addLayout(group_controls)
        
        # Groups table
        self.groups_table = QTableWidget()
        self.groups_table.setColumnCount(3)  # Name, GID, Members
        self.groups_table.setHorizontalHeaderLabels(["Group Name", "GID", "Members"])
        self.groups_table.horizontalHeader().setStretchLastSection(True)
        self.groups_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.groups_table.setEditTriggers(QTableWidget.NoEditTriggers)
        groups_layout.addWidget(self.groups_table)
        main_layout.addWidget(groups_group)
        
        self.setLayout(main_layout)

    def load_users_and_groups(self):
        self._load_users()
        self._load_groups()

    # Fetches and displays user data in the users table.
    def _load_users(self):
        self.users_table.setRowCount(0)
        try:
            users_data, error_msg = self.backend.list_users() 
            if error_msg:
                QMessageBox.warning(self, "Error Loading Users", f"Could not load users: {error_msg}")
                return
            
            users = users_data if users_data else []

            for row, user_data in enumerate(users):
                self.users_table.insertRow(row)
                self.users_table.setItem(row, 0, QTableWidgetItem(user_data.get("username", "")))
                self.users_table.setItem(row, 1, QTableWidgetItem(str(user_data.get("uid", ""))))
                self.users_table.setItem(row, 2, QTableWidgetItem(str(user_data.get("gid", ""))))
                self.users_table.setItem(row, 3, QTableWidgetItem(user_data.get("comment", "")))
                self.users_table.setItem(row, 4, QTableWidgetItem(user_data.get("home", "")))
                self.users_table.setItem(row, 5, QTableWidgetItem(user_data.get("shell", "")))
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load users: {str(e)}")

    # Fetches and displays group data in the groups table.
    def _load_groups(self):
        self.groups_table.setRowCount(0)
        try:
            if self.is_senior:
                groups_data, error_msg = self.backend.list_groups_detail()
            else:
                groups_data, error_msg = self.backend.list_groups()
                
            if error_msg:
                QMessageBox.warning(self, "Error Loading Groups", f"Could not load groups: {error_msg}")
                return
                
            groups = groups_data if groups_data else []
            
            for row, group_data in enumerate(groups):
                self.groups_table.insertRow(row)
                self.groups_table.setItem(row, 0, QTableWidgetItem(group_data.get("name", "")))
                self.groups_table.setItem(row, 1, QTableWidgetItem(str(group_data.get("gid", ""))))
                self.groups_table.setItem(row, 2, QTableWidgetItem(group_data.get("members", "")))
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load groups: {str(e)}")

    # Shows a dialog for adding a new user.
    def _show_add_user_dialog(self):
        dialog = AddUserDialog(is_senior=self.is_senior, parent=self)
        if dialog.exec() == QDialog.Accepted:
            user_data = dialog.get_user_data()
            if user_data is None: # Check if dialog validation failed
                return 

            success = False
            message = ""
            try:
                if self.is_senior:
                    success, message = self.backend.add_system_user(
                        username=user_data["username"],
                        password=user_data["password"],
                        groups=user_data.get("groups"),
                        shell=user_data.get("shell", "/bin/bash"),
                        home_dir=user_data.get("home_dir"),
                        comment=user_data.get("comment"),
                        create_home=user_data.get("create_home", True)
                    )
                else:
                    success, message = self.backend.create_user(
                        username=user_data["username"],
                        password=user_data["password"],
                        primary_group=user_data["primary_group"],
                        secondary_groups=user_data.get("secondary_groups")
                    )
                
                if success:
                    QMessageBox.information(self, "Success", message or "User action completed successfully.")
                    self.load_users_and_groups() # Refresh list
                else:
                    QMessageBox.warning(self, "Failed", message or "Could not complete user action.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
                # self.load_users_and_groups() # Optionally refresh list even on unexpected error

    # Shows a dialog for adding a new group.
    def _show_add_group_dialog(self):
        dialog = AddGroupDialog(parent=self)
        if dialog.exec() == QDialog.Accepted:
            group_data = dialog.get_group_data()
            if group_data is None:
                return
                
            success = False
            message = ""
            try:
                if self.is_senior:
                    success, message = self.backend.add_system_group(
                        group_name=group_data["group_name"],
                        gid=group_data.get("gid")
                    )
                else:
                    success, message = self.backend.create_group(
                        group_name=group_data["group_name"]
                    )
                
                self._display_output(f"$ sudo groupadd {'-g ' + group_data['gid'] + ' ' if group_data.get('gid') else ''}{group_data['group_name']}")
                self._display_output(message)
                
                if success:
                    self.load_users_and_groups()  # Refresh list
            except Exception as e:
                self._display_output(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    # Handles deletion of the selected user. (Senior admin only)
    def _delete_selected_user(self):
        if not self.is_senior:
            self._display_output("Permission denied. You are not allowed to delete users.")
            return
            
        selected_items = self.users_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user to delete.")
            return
            
        row = selected_items[0].row()
        username = self.users_table.item(row, 0).text()
        
        confirm = QMessageBox.question(
            self, 
            "Confirm Deletion", 
            f"Are you sure you want to delete the user '{username}'?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            delete_home = QMessageBox.question(
                self,
                "Delete Home Directory",
                f"Do you also want to delete the home directory for '{username}'?",
                QMessageBox.Yes | QMessageBox.No
            ) == QMessageBox.Yes
            
            try:
                success, message = self.backend.delete_system_user(username, delete_home)
                self._display_output(f"$ sudo userdel {'-r ' if delete_home else ''}{username}")
                self._display_output(message)
                
                if success:
                    self.load_users_and_groups()  # Refresh the user list
            except Exception as e:
                self._display_output(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    # Handles modification of the selected user. (Senior admin only)
    def _modify_selected_user(self):
        if not self.is_senior:
            self._display_output("Permission denied. You are not allowed to modify users.")
            return
            
        selected_items = self.users_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user to modify.")
            return
            
        row = selected_items[0].row()
        username = self.users_table.item(row, 0).text()
        shell = self.users_table.item(row, 5).text()
        comment = self.users_table.item(row, 3).text()
        
        dialog = ModifyUserDialog(username, shell, comment, parent=self)
        if dialog.exec() == QDialog.Accepted:
            try:
                # Get the modifications from the dialog
                mod_data = dialog.get_modification_data()
                
                # Show the command that would be executed in the terminal output
                cmd_parts = [f"$ sudo usermod {username}"]
                if mod_data.get("new_shell"):
                    cmd_parts.append(f"-s {mod_data['new_shell']}")
                if mod_data.get("new_comment"):
                    cmd_parts.append(f"-c \"{mod_data['new_comment']}\"")
                if mod_data.get("new_home_dir"):
                    if mod_data.get("move_home_content"):
                        cmd_parts.append(f"-d {mod_data['new_home_dir']} -m")
                    else:
                        cmd_parts.append(f"-d {mod_data['new_home_dir']}")
                if mod_data.get("add_groups"):
                    cmd_parts.append(f"-a -G {','.join(mod_data['add_groups'])}")
                if mod_data.get("remove_groups"):
                    cmd_parts.append(f"# Note: Removing from groups requires reconfiguring all groups")
                if mod_data.get("primary_group"):
                    cmd_parts.append(f"-g {mod_data['primary_group']}")
                if mod_data.get("lock_account"):
                    cmd_parts.append("-L")
                if mod_data.get("unlock_account"):
                    cmd_parts.append("-U")
                
                self._display_output(" ".join(cmd_parts))
                
                # Execute the actual modification
                success, message = self.backend.modify_system_user(
                    username=username,
                    new_shell=mod_data.get("new_shell"),
                    new_home_dir=mod_data.get("new_home_dir"),
                    move_home_content=mod_data.get("move_home_content", False),
                    new_comment=mod_data.get("new_comment"),
                    add_groups=mod_data.get("add_groups"),
                    remove_groups=mod_data.get("remove_groups"),
                    primary_group=mod_data.get("primary_group"),
                    lock_account=mod_data.get("lock_account"),
                    unlock_account=mod_data.get("unlock_account")
                )
                
                self._display_output(message)
                
                if success:
                    self.load_users_and_groups()  # Refresh the user list
            except Exception as e:
                self._display_output(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    # Handles resetting the password for the selected user.
    def _reset_user_password(self):
        selected_items = self.users_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user to reset password.")
            return
            
        row = selected_items[0].row()
        username = self.users_table.item(row, 0).text()
        
        # Simple password reset dialog
        from PySide6.QtWidgets import QInputDialog
        new_password, ok = QInputDialog.getText(
            self, 
            "Reset Password", 
            f"Enter new password for {username}:",
            QLineEdit.Password
        )
        
        if ok and new_password:
            try:
                success, message = self.backend.reset_user_password(username, new_password)
                self._display_output(message)
                
                if success and not self.is_senior:
                    QMessageBox.information(self, "Success", f"Password for {username} has been reset.")
            except Exception as e:
                self._display_output(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    # Handles deletion of the selected group. (Senior admin only)
    def _delete_selected_group(self):
        if not self.is_senior:
            self._display_output("Permission denied. You are not allowed to delete groups.")
            return
            
        selected_items = self.groups_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a group to delete.")
            return
            
        row = selected_items[0].row()
        group_name = self.groups_table.item(row, 0).text()
        
        confirm = QMessageBox.question(
            self, 
            "Confirm Deletion", 
            f"Are you sure you want to delete the group '{group_name}'?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            try:
                success, message = self.backend.delete_system_group(group_name)
                self._display_output(f"$ sudo groupdel {group_name}")
                self._display_output(message)
                
                if success:
                    self.load_users_and_groups()  # Refresh the groups list
            except Exception as e:
                self._display_output(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    # Handles modification of the selected group. (Senior admin only)
    def _modify_selected_group(self):
        if not self.is_senior:
            self._display_output("Permission denied. You are not allowed to modify groups.")
            return
            
        selected_items = self.groups_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a group to modify.")
            return
            
        row = selected_items[0].row()
        group_name = self.groups_table.item(row, 0).text()
        group_id = self.groups_table.item(row, 1).text()
        
        dialog = ModifyGroupDialog(group_name, group_id, parent=self)
        if dialog.exec() == QDialog.Accepted:
            try:
                # Get the modifications from the dialog
                mod_data = dialog.get_modification_data()
                
                # Show the command that would be executed in the terminal output
                cmd_parts = [f"$ sudo groupmod {group_name}"]
                if mod_data.get("new_group_name"):
                    cmd_parts.append(f"-n {mod_data['new_group_name']}")
                if mod_data.get("new_gid"):
                    cmd_parts.append(f"-g {mod_data['new_gid']}")
                
                self._display_output(" ".join(cmd_parts))
                
                # Execute the actual modification
                success, message = self.backend.modify_system_group(
                    group_name=group_name,
                    new_group_name=mod_data.get("new_group_name"),
                    new_gid=mod_data.get("new_gid")
                )
                
                self._display_output(message)
                
                if success:
                    self.load_users_and_groups()  # Refresh the group list
            except Exception as e:
                self._display_output(f"Error: {str(e)}")
                QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

    def _display_output(self, text):
        """Display text in the output console with appropriate formatting"""
        self.output_console.append(text)
        self.output_console.ensureCursorVisible()


# Dialog for adding a new user, with fields varying by admin role.
class AddUserDialog(QDialog):
    def __init__(self, is_senior: bool, parent=None):
        super().__init__(parent)
        self.is_senior = is_senior
        self.setWindowTitle("Add New User")
        self.setMinimumWidth(400)

        # Apply dark theme specifically to this dialog and its children
        self.setStyleSheet("""
            QDialog {
                background-color: #2E2E2E;
            }
            QWidget {
                background-color: #333;
                color: #EEE;
            }
            QLabel {
                color: #EEE;
                background-color: transparent;
            }
            QLineEdit, QComboBox {
                background-color: #444;
                color: #EEE;
                border: 1px solid #555;
                padding: 3px;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #555;
            }
            QCheckBox {
                color: #EEE;
            }
            QCheckBox::indicator {
                width: 13px;
                height: 13px;
                border: 1px solid #666;
                background-color: #444;
            }
            QCheckBox::indicator:checked {
                background-color: #0078D7;
                border: 1px solid #005A9E;
            }
            QPushButton {
                background-color: #555;
                color: #EEE;
                border: 1px solid #666;
                padding: 5px;
                min-height: 15px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)

        self.layout = QVBoxLayout(self)
        self.form_layout = QFormLayout()
        
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        
        self.form_layout.addRow("Username:", self.username_edit)
        self.form_layout.addRow("Password:", self.password_edit)

        if self.is_senior:
            self.shell_edit = QLineEdit("/bin/bash")
            self.home_dir_edit = QLineEdit() 
            self.comment_edit = QLineEdit()
            self.create_home_checkbox = QCheckBox("Create home directory")
            self.create_home_checkbox.setChecked(True)
            self.groups_edit = QLineEdit() # Comma-separated list for secondary -G

            self.form_layout.addRow("Shell:", self.shell_edit)
            self.form_layout.addRow("Home Directory (optional, e.g., /home/user):", self.home_dir_edit)
            self.form_layout.addRow("Comment (GECOS, optional):", self.comment_edit)
            self.form_layout.addRow(self.create_home_checkbox)
            self.form_layout.addRow("Secondary Groups (comma-sep):", self.groups_edit)

        else: # Junior admin
            self.primary_group_combo = QComboBox()
            if JUNIOR_MANAGEABLE_GROUPS:
                self.primary_group_combo.addItems(JUNIOR_MANAGEABLE_GROUPS)
            else:
                self.primary_group_combo.addItem("users") # Fallback if list is empty
            
            self.secondary_groups_edit = QLineEdit()
            self.secondary_groups_edit.setPlaceholderText("Comma-sep, e.g., developers,trainees")

            self.form_layout.addRow("Primary Group:", self.primary_group_combo)
            self.form_layout.addRow("Secondary Groups (optional):", self.secondary_groups_edit)

        self.buttons = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        self.buttons.addWidget(self.ok_button)
        self.buttons.addWidget(self.cancel_button)
        
        self.form_layout.addRow(self.buttons)

        self.layout.addLayout(self.form_layout)

    def _add_common_fields(self):
        self.form_layout.addRow(QLabel("Username:"), self.username_edit)
        self.form_layout.addRow(QLabel("Password:"), self.password_edit)

    def accept(self):
        # Basic validation
        if not self.username_edit.text() or not self.password_edit.text():
            QMessageBox.warning(self, "Input Error", "Username and password cannot be empty.")
            return
        super().accept()

    def get_user_data(self) -> dict:
        data = {
            "username": self.username_edit.text().strip(),
            "password": self.password_edit.text()
        }
        
        if self.is_senior:
            if self.shell_edit.text():
                data["shell"] = self.shell_edit.text()
            if self.home_dir_edit.text():
                data["home_dir"] = self.home_dir_edit.text()
            if self.comment_edit.text():
                data["comment"] = self.comment_edit.text()
                
            data["create_home"] = self.create_home_checkbox.isChecked()
            
            if self.groups_edit.text():
                data["groups"] = [g.strip() for g in self.groups_edit.text().split(",") if g.strip()]
        else:
            data["primary_group"] = self.primary_group_combo.currentText()
            
            if self.secondary_groups_edit.text():
                data["secondary_groups"] = [g.strip() for g in self.secondary_groups_edit.text().split(",") if g.strip()]
        
        return data 

# Dialog for modifying an existing user's attributes. (Senior admin only)
class ModifyUserDialog(QDialog):
    def __init__(self, username, current_shell, current_comment, parent=None):
        super().__init__(parent)
        self.username = username
        self.current_shell = current_shell
        self.current_comment = current_comment
        self.setWindowTitle(f"Modify User: {username}")
        self.setMinimumWidth(450)
        
        # Apply dark theme specifically to this dialog and its children
        self.setStyleSheet("""
            QDialog {
                background-color: #2E2E2E;
            }
            QWidget {
                background-color: #333;
                color: #EEE;
            }
            QLabel {
                color: #EEE;
                background-color: transparent;
            }
            QLineEdit, QComboBox {
                background-color: #444;
                color: #EEE;
                border: 1px solid #555;
                padding: 3px;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #555;
            }
            QCheckBox {
                color: #EEE;
            }
            QCheckBox::indicator {
                width: 13px;
                height: 13px;
                border: 1px solid #666;
                background-color: #444;
            }
            QCheckBox::indicator:checked {
                background-color: #0078D7;
                border: 1px solid #005A9E;
            }
            QPushButton {
                background-color: #555;
                color: #EEE;
                border: 1px solid #666;
                padding: 5px;
                min-height: 15px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        
        self.layout = QVBoxLayout(self)
        
        # Basic Information Group
        basic_group = QGroupBox("Basic Information")
        basic_layout = QFormLayout(basic_group)
        
        self.shell_edit = QLineEdit(current_shell)
        self.comment_edit = QLineEdit(current_comment)
        self.primary_group_edit = QLineEdit()
        self.primary_group_edit.setPlaceholderText("Leave blank to keep current")
        
        basic_layout.addRow("New Shell:", self.shell_edit)
        basic_layout.addRow("New Comment:", self.comment_edit)
        basic_layout.addRow("New Primary Group (GID or name):", self.primary_group_edit)
        
        self.layout.addWidget(basic_group)
        
        # Home Directory Group
        home_group = QGroupBox("Home Directory")
        home_layout = QFormLayout(home_group)
        
        self.home_dir_edit = QLineEdit()
        self.home_dir_edit.setPlaceholderText("Leave blank to keep current")
        self.move_home_checkbox = QCheckBox("Move contents to new location")
        self.move_home_checkbox.setChecked(True)
        
        home_layout.addRow("New Home Directory:", self.home_dir_edit)
        home_layout.addRow(self.move_home_checkbox)
        
        self.layout.addWidget(home_group)
        
        # Groups Group
        groups_group = QGroupBox("Group Membership")
        groups_layout = QFormLayout(groups_group)
        
        self.add_groups_edit = QLineEdit()
        self.add_groups_edit.setPlaceholderText("Comma-separated list of groups to add")
        self.remove_groups_edit = QLineEdit()
        self.remove_groups_edit.setPlaceholderText("Comma-separated list of groups to remove")
        
        groups_layout.addRow("Add to Groups:", self.add_groups_edit)
        groups_layout.addRow("Remove from Groups:", self.remove_groups_edit)
        
        self.layout.addWidget(groups_group)
        
        # Account Status Group
        status_group = QGroupBox("Account Status")
        status_layout = QVBoxLayout(status_group)
        
        self.lock_radio = QRadioButton("Lock Account")
        self.unlock_radio = QRadioButton("Unlock Account")
        self.no_status_change_radio = QRadioButton("No Change")
        self.no_status_change_radio.setChecked(True)
        
        status_layout.addWidget(self.lock_radio)
        status_layout.addWidget(self.unlock_radio)
        status_layout.addWidget(self.no_status_change_radio)
        
        self.layout.addWidget(status_group)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        buttons_layout.addWidget(self.ok_button)
        buttons_layout.addWidget(self.cancel_button)
        
        self.layout.addLayout(buttons_layout)
        
    def get_modification_data(self) -> dict:
        data = {}
        
        # Only include fields that have been changed
        if self.shell_edit.text() != self.current_shell:
            data["new_shell"] = self.shell_edit.text().strip()
            
        if self.comment_edit.text() != self.current_comment:
            data["new_comment"] = self.comment_edit.text().strip()
            
        if self.primary_group_edit.text():
            data["primary_group"] = self.primary_group_edit.text().strip()
            
        if self.home_dir_edit.text():
            data["new_home_dir"] = self.home_dir_edit.text().strip()
            data["move_home_content"] = self.move_home_checkbox.isChecked()
            
        if self.add_groups_edit.text():
            data["add_groups"] = [g.strip() for g in self.add_groups_edit.text().split(",") if g.strip()]
            
        if self.remove_groups_edit.text():
            data["remove_groups"] = [g.strip() for g in self.remove_groups_edit.text().split(",") if g.strip()]
            
        if self.lock_radio.isChecked():
            data["lock_account"] = True
            
        if self.unlock_radio.isChecked():
            data["unlock_account"] = True
            
        return data

# Dialog for modifying an existing group's attributes. (Senior admin only)
class ModifyGroupDialog(QDialog):
    def __init__(self, group_name, current_gid, parent=None):
        super().__init__(parent)
        self.group_name = group_name
        self.current_gid = current_gid
        self.setWindowTitle(f"Modify Group: {group_name}")
        self.setMinimumWidth(400)
        
        # Apply dark theme specifically to this dialog and its children
        self.setStyleSheet("""
            QDialog {
                background-color: #2E2E2E;
            }
            QWidget {
                background-color: #333;
                color: #EEE;
            }
            QLabel {
                color: #EEE;
                background-color: transparent;
            }
            QLineEdit, QComboBox {
                background-color: #444;
                color: #EEE;
                border: 1px solid #555;
                padding: 3px;
            }
            QPushButton {
                background-color: #555;
                color: #EEE;
                border: 1px solid #666;
                padding: 5px;
                min-height: 15px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        
        self.layout = QVBoxLayout(self)
        self.form_layout = QFormLayout()
        
        self.new_name_edit = QLineEdit(group_name)
        self.new_gid_edit = QLineEdit(current_gid)
        
        self.form_layout.addRow("New Group Name:", self.new_name_edit)
        self.form_layout.addRow("New Group ID (GID):", self.new_gid_edit)
        
        self.buttons = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        self.buttons.addWidget(self.ok_button)
        self.buttons.addWidget(self.cancel_button)
        
        self.layout.addLayout(self.form_layout)
        self.layout.addLayout(self.buttons)
        
    def accept(self):
        # Basic validation - ensure at least one field is different
        if self.new_name_edit.text() == self.group_name and self.new_gid_edit.text() == self.current_gid:
            QMessageBox.warning(self, "No Changes", "You need to change at least one field.")
            return
        super().accept()
        
    def get_modification_data(self) -> dict:
        data = {}
        
        # Only include fields that have been changed
        if self.new_name_edit.text() != self.group_name:
            data["new_group_name"] = self.new_name_edit.text().strip()
            
        if self.new_gid_edit.text() != self.current_gid:
            data["new_gid"] = self.new_gid_edit.text().strip()
            
        return data 

# Dialog for adding a new group.
class AddGroupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Group")
        self.setMinimumWidth(350)
        
        # Apply dark theme specifically to this dialog and its children
        self.setStyleSheet("""
            QDialog {
                background-color: #2E2E2E;
            }
            QWidget {
                background-color: #333;
                color: #EEE;
            }
            QLabel {
                color: #EEE;
                background-color: transparent;
            }
            QLineEdit, QComboBox {
                background-color: #444;
                color: #EEE;
                border: 1px solid #555;
                padding: 3px;
            }
            QPushButton {
                background-color: #555;
                color: #EEE;
                border: 1px solid #666;
                padding: 5px;
                min-height: 15px;
            }
            QPushButton:hover {
                background-color: #666;
            }
            QPushButton:pressed {
                background-color: #444;
            }
        """)
        
        self.layout = QVBoxLayout(self)
        self.form_layout = QFormLayout()
        
        self.group_name_edit = QLineEdit()
        self.gid_edit = QLineEdit()
        self.gid_edit.setPlaceholderText("Optional, system will assign if empty")
        
        self.form_layout.addRow("Group Name:", self.group_name_edit)
        self.form_layout.addRow("Group ID (GID):", self.gid_edit)
        
        self.buttons = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        self.buttons.addWidget(self.ok_button)
        self.buttons.addWidget(self.cancel_button)
        
        self.layout.addLayout(self.form_layout)
        self.layout.addLayout(self.buttons)
        
    def accept(self):
        # Basic validation
        if not self.group_name_edit.text():
            QMessageBox.warning(self, "Input Error", "Group name cannot be empty.")
            return
        super().accept()
        
    def get_group_data(self) -> dict:
        data = {
            "group_name": self.group_name_edit.text().strip()
        }
        
        if self.gid_edit.text():
            data["gid"] = self.gid_edit.text().strip()
            
        return data 