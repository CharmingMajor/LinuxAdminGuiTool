from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QDialog, QFormLayout, QSpinBox, QGroupBox, QCheckBox, QFileDialog, QTextEdit)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import os
import contextlib
from src.backend.senior_dashboard_backend import SeniorDashboardBackend
from src.backend.junior_backend import JuniorBackend

class PermissionsManagerWidget(QWidget):
    """Widget for managing file and directory permissions"""
    
    def __init__(self, parent=None, remote=None, is_senior=True):
        super().__init__(parent)
        self.remote = remote
        self.is_senior = is_senior
        
        # Initialize the appropriate backend based on role
        if self.is_senior:
            self.backend = SeniorDashboardBackend(remote)
        else:
            self.backend = JuniorBackend(remote=remote)
            
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # Role explanation box
        role_box = QGroupBox("Role-Based Permissions")
        role_layout = QVBoxLayout(role_box)
        
        if self.is_senior:
            role_text = "Senior Admin Role: You have full access to change file and directory ownership and permissions."
        else:
            role_text = "Junior Admin Role: You cannot change file and directory ownership and permissions."
        
        role_label = QLabel(role_text)
        role_label.setWordWrap(True)
        role_layout.addWidget(role_label)
        layout.addWidget(role_box)
        
        path_group = QGroupBox("File/Directory Path")
        path_layout = QHBoxLayout(path_group)
        
        self.path_input = QLineEdit()
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_path)
        
        path_layout.addWidget(QLabel("Path:"))
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_btn)
        
        layout.addWidget(path_group)
        
        owner_group = QGroupBox("Owner and Group")
        owner_layout = QFormLayout(owner_group)
        self.owner_group = owner_group
        
        self.owner_input = QLineEdit()
        self.group_input = QLineEdit()
        
        owner_layout.addRow("Owner:", self.owner_input)
        owner_layout.addRow("Group:", self.group_input)
        
        # Add apply ownership button
        ownership_button_layout = QHBoxLayout()
        self.recursive_ownership_checkbox = QCheckBox("Apply Recursively")
        ownership_button_layout.addWidget(self.recursive_ownership_checkbox)
        
        apply_ownership_btn = QPushButton("Apply Ownership")
        apply_ownership_btn.clicked.connect(self.apply_ownership)
        ownership_button_layout.addWidget(apply_ownership_btn)
        owner_layout.addRow("", ownership_button_layout)
        
        layout.addWidget(owner_group)
        
        perm_group = QGroupBox("Permissions")
        perm_layout = QVBoxLayout(perm_group)
        self.perm_group = perm_group
        
        grid_layout = QHBoxLayout()
        
        headers = QVBoxLayout()
        headers.addWidget(QLabel(""))
        headers.addWidget(QLabel("Owner"))
        headers.addWidget(QLabel("Group"))
        headers.addWidget(QLabel("Others"))
        grid_layout.addLayout(headers)
        
        read_layout = QVBoxLayout()
        read_layout.addWidget(QLabel("Read"))
        self.read_owner = QCheckBox()
        self.read_group = QCheckBox()
        self.read_others = QCheckBox()
        read_layout.addWidget(self.read_owner)
        read_layout.addWidget(self.read_group)
        read_layout.addWidget(self.read_others)
        grid_layout.addLayout(read_layout)
        
        write_layout = QVBoxLayout()
        write_layout.addWidget(QLabel("Write"))
        self.write_owner = QCheckBox()
        self.write_group = QCheckBox()
        self.write_others = QCheckBox()
        write_layout.addWidget(self.write_owner)
        write_layout.addWidget(self.write_group)
        write_layout.addWidget(self.write_others)
        grid_layout.addLayout(write_layout)
        
        exec_layout = QVBoxLayout()
        exec_layout.addWidget(QLabel("Execute"))
        self.exec_owner = QCheckBox()
        self.exec_group = QCheckBox()
        self.exec_others = QCheckBox()
        exec_layout.addWidget(self.exec_owner)
        exec_layout.addWidget(self.exec_group)
        exec_layout.addWidget(self.exec_others)
        grid_layout.addLayout(exec_layout)
        
        perm_layout.addLayout(grid_layout)
        
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Numeric Mode:"))
        self.mode_input = QLineEdit()
        self.mode_input.setMaxLength(3)
        self.mode_input.textChanged.connect(self.update_checkboxes)
        mode_layout.addWidget(self.mode_input)
        mode_layout.addStretch()
        
        perm_layout.addLayout(mode_layout)
        
        # Add recursive checkbox for permissions
        button_layout = QHBoxLayout()
        self.recursive_permissions_checkbox = QCheckBox("Apply Recursively")
        button_layout.addWidget(self.recursive_permissions_checkbox)
        
        apply_btn = QPushButton("Apply Permissions")
        apply_btn.clicked.connect(self.apply_permissions)
        button_layout.addWidget(apply_btn)
        
        perm_layout.addLayout(button_layout)
        
        layout.addWidget(perm_group)
        
        # Add terminal output console
        output_group = QGroupBox("Command Output")
        output_layout = QVBoxLayout(output_group)
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #121212; color: #CCCCCC; font-family: 'Courier New', monospace;")
        self.output_console.setMinimumHeight(150)
        output_layout.addWidget(self.output_console)
        layout.addWidget(output_group)
        
        for checkbox in [self.read_owner, self.read_group, self.read_others,
                        self.write_owner, self.write_group, self.write_others,
                        self.exec_owner, self.exec_group, self.exec_others]:
            checkbox.stateChanged.connect(self.update_mode_display)
        
        self.mode_input.setText("644")
        
        # Disable functionality if not a senior admin
        if not self.is_senior:
            self.owner_group.setEnabled(False)
            self.perm_group.setEnabled(False)
        
    def browse_path(self):
        """Open file dialog to select path"""
        if self.remote:
            QMessageBox.information(self, "Remote System",
                "Please enter the path manually for remote systems.")
        elif path := QFileDialog.getExistingDirectory(self, "Select Directory"):
            self.path_input.setText(path)
                
    def update_mode_display(self):
        """Update numeric mode based on checkboxes"""
        with contextlib.suppress(Exception):
            owner = 0
            if self.read_owner.isChecked():
                owner += 4
            if self.write_owner.isChecked():
                owner += 2
            if self.exec_owner.isChecked():
                owner += 1
                
            group = 0
            if self.read_group.isChecked():
                group += 4
            if self.write_group.isChecked():
                group += 2
            if self.exec_group.isChecked():
                group += 1
                
            others = 0
            if self.read_others.isChecked():
                others += 4
            if self.write_others.isChecked():
                others += 2
            if self.exec_others.isChecked():
                others += 1
                
            self.mode_input.setText(f"{owner}{group}{others}")
            
    def update_checkboxes(self):
        """Update checkboxes based on numeric mode"""
        with contextlib.suppress(Exception):
            mode = self.mode_input.text()
            if len(mode) != 3 or not mode.isdigit():
                return
                
            owner = int(mode[0])
            group = int(mode[1])
            others = int(mode[2])
            
            self.read_owner.setChecked(owner & 4)
            self.write_owner.setChecked(owner & 2)
            self.exec_owner.setChecked(owner & 1)
            
            self.read_group.setChecked(group & 4)
            self.write_group.setChecked(group & 2)
            self.exec_group.setChecked(group & 1)
            
            self.read_others.setChecked(others & 4)
            self.write_others.setChecked(others & 2)
            self.exec_others.setChecked(others & 1)
            
    def apply_permissions(self):
        """Apply the permissions to the selected path using the appropriate backend"""
        path = self.path_input.text().strip()
        mode = self.mode_input.text().strip()
        recursive = self.recursive_permissions_checkbox.isChecked()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
        
        if not mode or len(mode) != 3 or not mode.isdigit():
            QMessageBox.critical(self, "Error", "Please enter a valid numeric mode (e.g., 755)")
            return
            
        try:
            self._display_output(f"$ sudo chmod {'-R ' if recursive else ''}{mode} {path}")
            
            # Use the backend methods
            success, message = self.backend.change_file_permissions(
                path=path,
                permissions=mode,
                recursive=recursive
            )
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "Permissions updated successfully")
            
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to set permissions: {str(e)}")

    def apply_ownership(self):
        """Apply ownership changes using the appropriate backend"""
        path = self.path_input.text().strip()
        owner = self.owner_input.text().strip()
        group = self.group_input.text().strip()
        recursive = self.recursive_ownership_checkbox.isChecked()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
            
        if not owner and not group:
            QMessageBox.critical(self, "Error", "Please specify owner, group, or both")
            return
            
        try:
            ownership_spec = ""
            if owner and group:
                ownership_spec = f"{owner}:{group}"
            elif owner:
                ownership_spec = owner
            elif group:
                ownership_spec = f":{group}"
            
            self._display_output(f"$ sudo chown {'-R ' if recursive else ''}{ownership_spec} {path}")
            
            # Use the backend methods
            success, message = self.backend.change_file_ownership(
                path=path,
                owner=owner or None,
                group=group or None,
                recursive=recursive
            )
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "Ownership updated successfully")
            
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to set ownership: {str(e)}")
            
    def _display_output(self, text):
        """Display text in the output console with appropriate formatting"""
        self.output_console.append(text)
        self.output_console.ensureCursorVisible() 