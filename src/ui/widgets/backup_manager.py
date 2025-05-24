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
        
    def _create_path_input_row(self, label_text: str) -> tuple[QLineEdit, QHBoxLayout]:
        # Helper method to create a path input field with a browse button
        line_edit = QLineEdit()
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: self.browse_path(line_edit))
        
        layout = QHBoxLayout()
        layout.addWidget(line_edit)
        layout.addWidget(browse_btn)
        return line_edit, layout

    def setup_ui(self):
        """Set up the UI components"""
        layout = QFormLayout(self)
        
        self.theme_manager.apply_widget_styles(self)
        
        self.source_input, source_layout = self._create_path_input_row("Source Path:")
        layout.addRow("Source Path:", source_layout)
        
        self.dest_input, dest_layout = self._create_path_input_row("Destination Path:")
        layout.addRow("Destination Path:", dest_layout)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Full", "Incremental"])
        layout.addRow("Backup Type:", self.type_combo)
        
        self.compression = QSpinBox()
        self.compression.setRange(0, 9)
        self.compression.setValue(6)
        layout.addRow("Compression Level:", self.compression)
        
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
        if path := QFileDialog.getExistingDirectory(self, "Select Directory"):
            input_widget.setText(path)

class BackupManagerWidget(QWidget):
    """Widget for managing system backups"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        # Remote parameter allows managing backups on remote systems
        self.remote = remote
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.apply_theme)
        self.setup_ui()
        self.load_backups()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        self.theme_manager.apply_widget_styles(self)
        
        backups_group = QGroupBox("Backup History")
        backups_layout = QVBoxLayout(backups_group)
        
        # Table displays backup history with date, type, source, destination, and status
        self.backup_table = QTableWidget()
        self.backup_table.setColumnCount(5)
        self.backup_table.setHorizontalHeaderLabels([
            "Date", "Type", "Source", "Destination", "Status"
        ])
        self.backup_table.horizontalHeader().setStretchLastSection(True)
        
        backups_layout.addWidget(self.backup_table)
        
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
                # For remote systems, fetch backup log via command execution
                stdout, _ = self.remote.execute_command("cat /var/log/backup.log 2>/dev/null")
                backups = json.loads(stdout) if stdout else []
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
                stdout, _ = self.remote.execute_command("cat /var/log/backup.log 2>/dev/null")
                backups = json.loads(stdout) if stdout else []
                    
                backups.append(backup_info)
                
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

            self._extracted_from_restore_backup_14()
            self.output_text.append(f"Creating {backup_type.lower()} backup...")

            # Generate unique backup name based on current date/time
            date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            archive_name = f"backup_{date}.tar.gz"
            snapshot_file = f"{dest}/snapshot_{date}" if backup_type == "Incremental" else None

            try:
                self._execute_tar_backup(source, dest, archive_name, backup_type, snapshot_file)

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
                
    def _execute_tar_backup(self, source_path: str, dest_path: str, archive_name: str, backup_type: str, snapshot_file: str | None):
        """Helper function to construct and execute the tar command for backup."""
        if self.remote:
            # For remote systems, execute tar command over SSH or similar connection
            self.remote.execute_command(f"mkdir -p {dest_path}")
            full_archive_path = f"{dest_path}/{archive_name}"
            cmd_parts = ["tar", "czf", full_archive_path]
            # Add incremental backup option if needed
            if backup_type == "Incremental" and snapshot_file:
                cmd_parts.extend([f"--listed-incremental={snapshot_file}"])
            cmd_parts.extend(["-C", source_path, "."])
            cmd = " ".join(cmd_parts)
            _, stderr = self.remote.execute_command(cmd)
            if stderr:
                raise RuntimeError(f"Remote tar command failed: {stderr}")
        else:
            # For local system, run tar command directly
            os.makedirs(dest_path, exist_ok=True)
            cmd_parts = ["tar", "czf", os.path.join(dest_path, archive_name)]
            if backup_type == "Incremental" and snapshot_file:
                # Ensure snapshot file is an absolute path for local execution if dest_path is relative
                abs_snapshot_file = os.path.join(os.path.abspath(dest_path), os.path.basename(snapshot_file))
                cmd_parts.extend([f"--listed-incremental={abs_snapshot_file}"])
            cmd_parts.extend(["-C", source_path, "."])
            subprocess.run(cmd_parts, check=True)

    def restore_backup(self):
        """Restore from a selected backup"""
        selected = self.backup_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Warning", "Please select a backup to restore.")
            return

        row = selected[0].row()
        backup_file = self.backup_table.item(row, 3).text()
        dest_path, ok = QFileDialog.getExistingDirectory(self, "Select Restore Destination")

        if not ok or not dest_path:
            return

        self._start_backup_restore_process()
        self.output_text.append(f"Restoring from {backup_file} to {dest_path}...")

        try:
            # Extract the tar archive to the specified destination
            if self.remote:
                self.remote.execute_command(f"mkdir -p {dest_path}")
                cmd = f"tar xzf {backup_file} -C {dest_path}"
                _, stderr = self.remote.execute_command(cmd)
                if stderr:
                    raise Exception(f"Remote restore error: {stderr}")
            else:
                if not Path(dest_path).exists():
                    Path(dest_path).mkdir(parents=True, exist_ok=True)
                subprocess.run(["tar", "xzf", backup_file, "-C", dest_path], check=True, capture_output=True)

            self.output_text.append("Restore completed successfully.")

        except Exception as e:
            self.output_text.append(f"Error restoring backup: {str(e)}")

        finally:
            self.progress_bar.setVisible(False)

    def _start_backup_restore_process(self):
        # Initialize UI for backup/restore operation
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.output_text.clear()

    def delete_backup(self):
        """Delete selected backup entry and archive"""
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
                # Delete the backup file and update the log
                if self.remote:
                    stdout, stderr = self.remote.execute_command(f"rm {backup_file}")
                    if stderr:
                        raise RuntimeError(stderr)
                else:
                    os.remove(backup_file)
                    
                self._update_backup_log_after_deletion(backup_file)
                
                self.load_backups()
                self.output_text.append(f"Backup {backup_file} deleted successfully.")
                
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to delete backup: {str(e)}")
                
    def _update_backup_log_after_deletion(self, deleted_backup_file: str):
        """Updates the backup log after a backup file has been deleted."""
        if self.remote:
            stdout, _ = self.remote.execute_command("cat /var/log/backup.log 2>/dev/null")
            backups = json.loads(stdout) if stdout else []
        else:
            backup_log_path = Path("/var/log/backup.log")
            if backup_log_path.exists():
                with open(backup_log_path) as f:
                    backups = json.load(f)
            else:
                backups = []
                        
        # Filter out the deleted backup from the log
        backups = [b for b in backups if b.get("destination") != deleted_backup_file]
        
        if self.remote:
            log_content = json.dumps(backups)
            self.remote.execute_command(f"echo '{log_content}' | sudo tee /var/log/backup.log")
        else:
            backup_log_path = Path("/var/log/backup.log") 
            with open(backup_log_path, "w") as f:
                json.dump(backups, f)

    def cleanup(self):
        """Clean up resources"""
        pass
        
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event) 