from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QDialog, QFormLayout, QGroupBox, QCheckBox, QFileDialog, QTextEdit, QRadioButton)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import os
import contextlib
from typing import Optional, List
from src.backend.senior_dashboard_backend import SeniorDashboardBackend
from src.backend.junior_backend import JuniorBackend

class ACLManagerWidget(QWidget):
    """Widget for managing file and directory Access Control Lists (ACLs)"""
    
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
        role_box = QGroupBox("Role-Based ACL Permissions")
        role_layout = QVBoxLayout(role_box)
        
        if self.is_senior:
            role_text = "Senior Admin Role: You have full access to view and modify Access Control Lists (ACLs)."
        else:
            role_text = "Junior Admin Role: You can view Access Control Lists (ACLs) but cannot modify them."
        
        role_label = QLabel(role_text)
        role_label.setWordWrap(True)
        role_layout.addWidget(role_label)
        layout.addWidget(role_box)
        
        # Path selection group
        path_group = QGroupBox("File/Directory Path")
        path_layout = QHBoxLayout(path_group)
        
        self.path_input = QLineEdit()
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_path)
        view_acl_btn = QPushButton("View ACL")
        view_acl_btn.clicked.connect(self.view_acl)
        
        path_layout.addWidget(QLabel("Path:"))
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_btn)
        path_layout.addWidget(view_acl_btn)
        
        layout.addWidget(path_group)
        
        # ACL modification group
        acl_mod_group = QGroupBox("Modify ACL")
        self.acl_mod_group = acl_mod_group
        acl_mod_layout = QVBoxLayout(acl_mod_group)
        
        # ACL type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.acl_type_combo = QComboBox()
        self.acl_type_combo.addItems(["User", "Group"])
        type_layout.addWidget(self.acl_type_combo)
        type_layout.addStretch()
        acl_mod_layout.addLayout(type_layout)
        
        # User/Group name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self.acl_name_input = QLineEdit()
        self.acl_name_input.setPlaceholderText("Username or group name")
        name_layout.addWidget(self.acl_name_input)
        name_layout.addStretch()
        acl_mod_layout.addLayout(name_layout)
        
        # Permissions checkboxes
        perm_layout = QHBoxLayout()
        perm_layout.addWidget(QLabel("Permissions:"))
        self.read_checkbox = QCheckBox("Read")
        self.write_checkbox = QCheckBox("Write")
        self.execute_checkbox = QCheckBox("Execute")
        perm_layout.addWidget(self.read_checkbox)
        perm_layout.addWidget(self.write_checkbox)
        perm_layout.addWidget(self.execute_checkbox)
        perm_layout.addStretch()
        acl_mod_layout.addLayout(perm_layout)
        
        # Default ACL checkbox (only applies to directories)
        default_layout = QHBoxLayout()
        self.default_acl_checkbox = QCheckBox("Set as default ACL (applies to new files created in this directory)")
        default_layout.addWidget(self.default_acl_checkbox)
        default_layout.addStretch()
        acl_mod_layout.addLayout(default_layout)
        
        # Recursive checkbox
        recursive_layout = QHBoxLayout()
        self.recursive_checkbox = QCheckBox("Apply recursively to all files and subdirectories")
        recursive_layout.addWidget(self.recursive_checkbox)
        recursive_layout.addStretch()
        acl_mod_layout.addLayout(recursive_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.add_acl_btn = QPushButton("Add/Modify ACL Entry")
        self.add_acl_btn.clicked.connect(self.add_modify_acl)
        self.remove_acl_btn = QPushButton("Remove ACL Entry")
        self.remove_acl_btn.clicked.connect(self.remove_acl)
        self.remove_default_acl_btn = QPushButton("Remove All Default ACLs")
        self.remove_default_acl_btn.clicked.connect(self.remove_default_acl)
        
        btn_layout.addWidget(self.add_acl_btn)
        btn_layout.addWidget(self.remove_acl_btn)
        btn_layout.addWidget(self.remove_default_acl_btn)
        
        acl_mod_layout.addLayout(btn_layout)
        layout.addWidget(acl_mod_group)
        
        # Terminal output console
        output_group = QGroupBox("Command Output")
        output_layout = QVBoxLayout(output_group)
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #121212; color: #CCCCCC; font-family: 'Courier New', monospace;")
        self.output_console.setMinimumHeight(150)
        output_layout.addWidget(self.output_console)
        layout.addWidget(output_group)
        
        # Disable ACL modification controls for Junior Admins
        if not self.is_senior:
            self.acl_mod_group.setEnabled(False)
        
    def browse_path(self):
        """Open file dialog to select path"""
        if self.remote:
            QMessageBox.information(self, "Remote System",
                "Please enter the path manually for remote systems.")
        elif path := QFileDialog.getExistingDirectory(self, "Select Directory"):
            self.path_input.setText(path)
    
    def view_acl(self):
        """View ACL for the specified path"""
        path = self.path_input.text().strip()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
            
        try:
            self._display_output(f"$ getfacl {path}")
            
            # Use the backend method
            success, message = self.backend.get_file_acl(path=path)
            
            self._display_output(message)
            
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to get ACL: {str(e)}")
    
    def add_modify_acl(self):
        """Add or modify an ACL entry"""
        path = self.path_input.text().strip()
        acl_type = self.acl_type_combo.currentText().lower()
        name = self.acl_name_input.text().strip()
        is_default = self.default_acl_checkbox.isChecked()
        recursive = self.recursive_checkbox.isChecked()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
            
        if not name:
            QMessageBox.critical(self, "Error", "Please enter a user or group name")
            return
            
        # Build the permissions string
        perms = ""
        if self.read_checkbox.isChecked():
            perms += "r"
        else:
            perms += "-"
            
        if self.write_checkbox.isChecked():
            perms += "w"
        else:
            perms += "-"
            
        if self.execute_checkbox.isChecked():
            perms += "x"
        else:
            perms += "-"
            
        # Build the ACL specification
        acl_spec = ""
        if is_default:
            acl_spec += "d:"
            
        if acl_type == "user":
            acl_spec += f"u:{name}:{perms}"
        else:  # group
            acl_spec += f"g:{name}:{perms}"
            
        try:
            self._display_output(f"$ sudo setfacl {'-R ' if recursive else ''}-m {acl_spec} {path}")
            
            # Use the backend method
            success, message = self.backend.set_file_acl(
                path=path,
                acl_spec=acl_spec,
                recursive=recursive
            )
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "ACL entry added/modified successfully")
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to modify ACL: {str(e)}")
    
    def remove_acl(self):
        """Remove an ACL entry"""
        path = self.path_input.text().strip()
        acl_type = self.acl_type_combo.currentText().lower()
        name = self.acl_name_input.text().strip()
        is_default = self.default_acl_checkbox.isChecked()
        recursive = self.recursive_checkbox.isChecked()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
            
        if not name:
            QMessageBox.critical(self, "Error", "Please enter a user or group name")
            return
            
        # Build the ACL specification
        acl_spec = ""
        if is_default:
            acl_spec += "d:"
            
        if acl_type == "user":
            acl_spec += f"u:{name}"
        else:  # group
            acl_spec += f"g:{name}"
            
        try:
            self._display_output(f"$ sudo setfacl {'-R ' if recursive else ''}-x {acl_spec} {path}")
            
            # Use the backend method
            success, message = self.backend.remove_file_acl(
                path=path,
                acl_spec=acl_spec,
                recursive=recursive
            )
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "ACL entry removed successfully")
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to remove ACL: {str(e)}")
    
    def remove_default_acl(self):
        """Remove all default ACL entries from a directory"""
        path = self.path_input.text().strip()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
            
        try:
            self._display_output(f"$ sudo setfacl -k {path}")
            
            # Use the backend method
            success, message = self.backend.remove_default_acl(path=path)
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "Default ACLs removed successfully")
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to remove default ACLs: {str(e)}")
    
    def _display_output(self, text):
        """Display text in the output console with appropriate formatting"""
        self.output_console.append(text)
        self.output_console.ensureCursorVisible() 