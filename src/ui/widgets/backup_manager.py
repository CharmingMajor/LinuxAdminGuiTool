from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QProgressBar, QMessageBox,
    QGroupBox, QTextEdit, QLineEdit, QFileDialog, QDialog, QFormLayout,
    QComboBox, QSpinBox)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
import subprocess
from pathlib import Path
import json
import os
import datetime
from src.ui.utils.theme_manager import ThemeManager

class BackupConfigDialog(QDialog):
    """Dialog for configuring backup settings"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Backup Configuration")
        self.theme_manager = ThemeManager()
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QFormLayout(self)
        
        # Apply theme styles
        self.theme_manager.apply_widget_styles(self)
        
        # Source path
        self.source_input = QLineEdit()
        browse_source = QPushButton("Browse")
        browse_source.clicked.connect(lambda: self.browse_path(self.source_input))
        source_layout = QHBoxLayout()
        source_layout.addWidget(self.source_input)
        source_layout.addWidget(browse_source)
        layout.addRow("Source Path:", source_layout)
        
        # Destination path
        self.dest_input = QLineEdit()
        browse_dest = QPushButton("Browse")
        browse_dest.clicked.connect(lambda: self.browse_path(self.dest_input))
        dest_layout = QHBoxLayout()
        dest_layout.addWidget(self.dest_input)
        dest_layout.addWidget(browse_dest)
        layout.addRow("Destination Path:", dest_layout)
        
        # Backup type
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Full", "Incremental"])
        layout.addRow("Backup Type:", self.type_combo)
        
        # Compression level
        self.compression = QSpinBox()
        self.compression.setRange(0, 9)
        self.compression.setValue(6)
        layout.addRow("Compression Level:", self.compression)
        
        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addRow("", button_layout)
        
    def browse_path(self, input_widget):
        """Open file dialog to select path"""
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if path:
            input_widget.setText(path)

class BackupManagerWidget(QWidget):
    """Widget for managing system backups"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.apply_theme)
        self.setup_ui()
        self.load_backups()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # Apply theme styles
        self.theme_manager.apply_widget_styles(self)
        
        # Backup list
        backups_group = QGroupBox("Backup History")
        backups_layout = QVBoxLayout(backups_group)
        
        self.backup_table = QTableWidget()
        self.backup_table.setColumnCount(5)
        self.backup_table.setHorizontalHeaderLabels([
            "Date", "Type", "Source", "Destination", "Status"
        ])
        self.backup_table.horizontalHeader().setStretchLastSection(True)
        
        backups_layout.addWidget(self.backup_table)
        
        # Backup controls
        controls = QHBoxLayout()
        
        create_btn = QPushButton("Create Backup")
        create_btn.clicked.connect(self.create_backup)
        
        restore_btn = QPushButton("Restore Backup")
        restore_btn.clicked.connect(self.restore_backup)
        
        delete_btn = QPushButton("Delete Backup")
        delete_btn.clicked.connect(self.delete_backup)
        
        controls.addWidget(create_btn)
        controls.addWidget(restore_btn)
        controls.addWidget(delete_btn)
        controls.addStretch()
        
        backups_layout.addLayout(controls)
        layout.addWidget(backups_group)
        
        # Progress and Output
        output_group = QGroupBox("Backup Progress")
        output_layout = QVBoxLayout(output_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        output_layout.addWidget(self.progress_bar)
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
        
    def apply_theme(self):
        """Apply current theme to the widget"""
        self.theme_manager.apply_widget_styles(self)
        
    def load_backups(self):
        """Load backup history"""
        try:
            if self.remote:
                stdout, _ = self.remote.execute_command("cat /var/log/backup.log 2>/dev/null")
                if stdout:
                    backups = json.loads(stdout)
                else:
                    backups = []
            else:
                backup_log = Path("/var/log/backup.log")
                if backup_log.exists():
                    with open(backup_log) as f:
                        backups = json.load(f)
                else:
                    backups = []
                    
            self.backup_table.setRowCount(0)
            for backup in backups:
                row = self.backup_table.rowCount()
                self.backup_table.insertRow(row)
                self.backup_table.setItem(row, 0, QTableWidgetItem(backup["date"]))
                self.backup_table.setItem(row, 1, QTableWidgetItem(backup["type"]))
                self.backup_table.setItem(row, 2, QTableWidgetItem(backup["source"]))
                self.backup_table.setItem(row, 3, QTableWidgetItem(backup["destination"]))
                self.backup_table.setItem(row, 4, QTableWidgetItem(backup["status"]))
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load backup history: {str(e)}")
            
    def save_backup_log(self, backup_info):
        """Save backup information to log"""
        try:
            if self.remote:
                # Get current log
                stdout, _ = self.remote.execute_command("cat /var/log/backup.log 2>/dev/null")
                if stdout:
                    backups = json.loads(stdout)
                else:
                    backups = []
                    
                # Add new backup
                backups.append(backup_info)
                
                # Save updated log
                log_content = json.dumps(backups)
                self.remote.execute_command(f"echo '{log_content}' | sudo tee /var/log/backup.log")
            else:
                backup_log = Path("/var/log/backup.log")
                if backup_log.exists():
                    with open(backup_log) as f:
                        backups = json.load(f)
                else:
                    backups = []
                    
                backups.append(backup_info)
                
                with open(backup_log, "w") as f:
                    json.dump(backups, f)
                    
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save backup log: {str(e)}")
            
    def create_backup(self):
        """Create a new backup"""
        dialog = BackupConfigDialog(self)
        if dialog.exec():
            source = dialog.source_input.text().strip()
            dest = dialog.dest_input.text().strip()
            backup_type = dialog.type_combo.currentText()
            compression = dialog.compression.value()
            
            if not source or not dest:
                QMessageBox.warning(self, "Error", "Please provide both source and destination paths")
                return
                
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.output_text.clear()
            self.output_text.append(f"Creating {backup_type.lower()} backup...")
            
            try:
                date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                archive_name = f"backup_{date}.tar.gz"
                
                if self.remote:
                    # Create backup directory if it doesn't exist
                    self.remote.execute_command(f"mkdir -p {dest}")
                    
                    # Create backup
                    cmd = f"tar czf {dest}/{archive_name} -C {source} ."
                    if backup_type == "Incremental":
                        snapshot = f"{dest}/snapshot_{date}"
                        cmd = f"tar czf {dest}/{archive_name} --listed-incremental={snapshot} -C {source} ."
                        
                    stdout, stderr = self.remote.execute_command(cmd)
                    if stderr:
                        raise Exception(stderr)
                else:
                    # Create backup directory if it doesn't exist
                    os.makedirs(dest, exist_ok=True)
                    
                    # Create backup
                    if backup_type == "Incremental":
                        snapshot = os.path.join(dest, f"snapshot_{date}")
                        subprocess.run([
                            "tar", "czf", os.path.join(dest, archive_name),
                            "--listed-incremental=" + snapshot,
                            "-C", source, "."
                        ], check=True)
                    else:
                        subprocess.run([
                            "tar", "czf", os.path.join(dest, archive_name),
                            "-C", source, "."
                        ], check=True)
                        
                backup_info = {
                    "date": date,
                    "type": backup_type,
                    "source": source,
                    "destination": os.path.join(dest, archive_name),
                    "status": "Completed"
                }
                
                self.save_backup_log(backup_info)
                self.load_backups()
                
                self.output_text.append("Backup completed successfully.")
                
            except Exception as e:
                self.output_text.append(f"Error creating backup: {str(e)}")
                backup_info = {
                    "date": date,
                    "type": backup_type,
                    "source": source,
                    "destination": os.path.join(dest, archive_name),
                    "status": "Failed"
                }
                self.save_backup_log(backup_info)
                self.load_backups()
                
            finally:
                self.progress_bar.setVisible(False)
                
    def restore_backup(self):
        """Restore a selected backup"""
        current_row = self.backup_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Error", "Please select a backup to restore")
            return
            
        backup_file = self.backup_table.item(current_row, 3).text()
        
        # Get restore path
        restore_path = QFileDialog.getExistingDirectory(
            self,
            "Select Restore Location",
            str(Path.home())
        )
        
        if not restore_path:
            return
            
        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Are you sure you want to restore the backup to {restore_path}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.output_text.clear()
            self.output_text.append("Restoring backup...")
            
            try:
                if self.remote:
                    # Create restore directory if it doesn't exist
                    self.remote.execute_command(f"mkdir -p {restore_path}")
                    
                    # Restore backup
                    stdout, stderr = self.remote.execute_command(
                        f"tar xzf {backup_file} -C {restore_path}"
                    )
                    if stderr:
                        raise Exception(stderr)
                else:
                    # Create restore directory if it doesn't exist
                    os.makedirs(restore_path, exist_ok=True)
                    
                    # Restore backup
                    subprocess.run([
                        "tar", "xzf", backup_file,
                        "-C", restore_path
                    ], check=True)
                    
                self.output_text.append("Backup restored successfully.")
                
            except Exception as e:
                self.output_text.append(f"Error restoring backup: {str(e)}")
                
            finally:
                self.progress_bar.setVisible(False)
                
    def delete_backup(self):
        """Delete a selected backup"""
        current_row = self.backup_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Error", "Please select a backup to delete")
            return
            
        backup_file = self.backup_table.item(current_row, 3).text()
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete the backup {backup_file}?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if self.remote:
                    stdout, stderr = self.remote.execute_command(f"rm {backup_file}")
                    if stderr:
                        raise Exception(stderr)
                else:
                    os.remove(backup_file)
                    
                # Update backup log
                if self.remote:
                    stdout, _ = self.remote.execute_command("cat /var/log/backup.log")
                    backups = json.loads(stdout)
                else:
                    with open("/var/log/backup.log") as f:
                        backups = json.load(f)
                        
                backups = [b for b in backups if b["destination"] != backup_file]
                
                if self.remote:
                    log_content = json.dumps(backups)
                    self.remote.execute_command(f"echo '{log_content}' | sudo tee /var/log/backup.log")
                else:
                    with open("/var/log/backup.log", "w") as f:
                        json.dump(backups, f)
                        
                self.load_backups()
                self.output_text.append(f"Backup {backup_file} deleted successfully.")
                
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to delete backup: {str(e)}")
                
    def cleanup(self):
        """Clean up resources"""
        pass
        
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event) 