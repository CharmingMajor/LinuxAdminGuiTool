from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QDialog, QFormLayout, QSpinBox, QGroupBox, QCheckBox, QFileDialog)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import os

class PermissionsManagerWidget(QWidget):
    """Widget for managing file and directory permissions"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # Path selection
        path_group = QGroupBox("File/Directory Path")
        path_layout = QHBoxLayout(path_group)
        
        self.path_input = QLineEdit()
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_path)
        
        path_layout.addWidget(QLabel("Path:"))
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_btn)
        
        layout.addWidget(path_group)
        
        # Owner/Group selection
        owner_group = QGroupBox("Owner and Group")
        owner_layout = QFormLayout(owner_group)
        
        self.owner_input = QLineEdit()
        self.group_input = QLineEdit()
        
        owner_layout.addRow("Owner:", self.owner_input)
        owner_layout.addRow("Group:", self.group_input)
        
        layout.addWidget(owner_group)
        
        # Permissions
        perm_group = QGroupBox("Permissions")
        perm_layout = QVBoxLayout(perm_group)
        
        # Permission grid
        grid_layout = QHBoxLayout()
        
        # Headers
        headers = QVBoxLayout()
        headers.addWidget(QLabel(""))  # Empty for spacing
        headers.addWidget(QLabel("Owner"))
        headers.addWidget(QLabel("Group"))
        headers.addWidget(QLabel("Others"))
        grid_layout.addLayout(headers)
        
        # Read permissions
        read_layout = QVBoxLayout()
        read_layout.addWidget(QLabel("Read"))
        self.read_owner = QCheckBox()
        self.read_group = QCheckBox()
        self.read_others = QCheckBox()
        read_layout.addWidget(self.read_owner)
        read_layout.addWidget(self.read_group)
        read_layout.addWidget(self.read_others)
        grid_layout.addLayout(read_layout)
        
        # Write permissions
        write_layout = QVBoxLayout()
        write_layout.addWidget(QLabel("Write"))
        self.write_owner = QCheckBox()
        self.write_group = QCheckBox()
        self.write_others = QCheckBox()
        write_layout.addWidget(self.write_owner)
        write_layout.addWidget(self.write_group)
        write_layout.addWidget(self.write_others)
        grid_layout.addLayout(write_layout)
        
        # Execute permissions
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
        
        # Numeric mode
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Numeric Mode:"))
        self.mode_input = QLineEdit()
        self.mode_input.setMaxLength(3)
        self.mode_input.textChanged.connect(self.update_checkboxes)
        mode_layout.addWidget(self.mode_input)
        mode_layout.addStretch()
        
        perm_layout.addLayout(mode_layout)
        
        layout.addWidget(perm_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        apply_btn = QPushButton("Apply Permissions")
        apply_btn.clicked.connect(self.apply_permissions)
        button_layout.addWidget(apply_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Connect checkbox signals
        for checkbox in [self.read_owner, self.read_group, self.read_others,
                        self.write_owner, self.write_group, self.write_others,
                        self.exec_owner, self.exec_group, self.exec_others]:
            checkbox.stateChanged.connect(self.update_mode_display)
        
        # Set default mode
        self.mode_input.setText("644")
        
    def browse_path(self):
        """Open file dialog to select path"""
        if self.remote:
            # For remote systems, just show a message
            QMessageBox.information(self, "Remote System",
                "Please enter the path manually for remote systems.")
        else:
            path = QFileDialog.getExistingDirectory(self, "Select Directory")
            if path:
                self.path_input.setText(path)
                
    def update_mode_display(self):
        """Update numeric mode based on checkboxes"""
        try:
            # Calculate owner permissions
            owner = 0
            if self.read_owner.isChecked():
                owner += 4
            if self.write_owner.isChecked():
                owner += 2
            if self.exec_owner.isChecked():
                owner += 1
                
            # Calculate group permissions
            group = 0
            if self.read_group.isChecked():
                group += 4
            if self.write_group.isChecked():
                group += 2
            if self.exec_group.isChecked():
                group += 1
                
            # Calculate others permissions
            others = 0
            if self.read_others.isChecked():
                others += 4
            if self.write_others.isChecked():
                others += 2
            if self.exec_others.isChecked():
                others += 1
                
            # Update mode display
            self.mode_input.setText(f"{owner}{group}{others}")
        except:
            pass
            
    def update_checkboxes(self):
        """Update checkboxes based on numeric mode"""
        try:
            mode = self.mode_input.text()
            if len(mode) != 3 or not mode.isdigit():
                return
                
            # Parse mode digits
            owner = int(mode[0])
            group = int(mode[1])
            others = int(mode[2])
            
            # Update owner checkboxes
            self.read_owner.setChecked(owner & 4)
            self.write_owner.setChecked(owner & 2)
            self.exec_owner.setChecked(owner & 1)
            
            # Update group checkboxes
            self.read_group.setChecked(group & 4)
            self.write_group.setChecked(group & 2)
            self.exec_group.setChecked(group & 1)
            
            # Update others checkboxes
            self.read_others.setChecked(others & 4)
            self.write_others.setChecked(others & 2)
            self.exec_others.setChecked(others & 1)
        except:
            pass
            
    def apply_permissions(self):
        """Apply the permissions to the selected path"""
        path = self.path_input.text().strip()
        owner = self.owner_input.text().strip()
        group = self.group_input.text().strip()
        mode = self.mode_input.text().strip()
        
        if not path:
            QMessageBox.critical(self, "Error", "Please select a path")
            return
            
        try:
            if self.remote:
                # Change owner/group if specified
                if owner or group:
                    cmd = f"chown {owner}:{group if group else owner} {path}"
                    _, stderr = self.remote.execute_command(cmd)
                    if stderr:
                        raise Exception(stderr)
                        
                # Change mode if specified
                if mode:
                    _, stderr = self.remote.execute_command(f"chmod {mode} {path}")
                    if stderr:
                        raise Exception(stderr)
            else:
                # Change owner/group if specified
                if owner or group:
                    import pwd, grp
                    uid = pwd.getpwnam(owner).pw_uid if owner else -1
                    gid = grp.getgrnam(group).gr_gid if group else -1
                    os.chown(path, uid, gid)
                    
                # Change mode if specified
                if mode:
                    os.chmod(path, int(mode, 8))
                    
            QMessageBox.information(self, "Success", "Permissions updated successfully")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to set permissions: {str(e)}") 