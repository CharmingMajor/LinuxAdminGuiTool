from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QProgressBar, QMessageBox,
    QGroupBox, QTextEdit)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
import subprocess

class UpdateManagerWidget(QWidget):
    """Widget for managing system updates"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # System Information
        info_group = QGroupBox("System Information")
        info_layout = QVBoxLayout(info_group)
        
        self.os_info = QLabel()
        self.kernel_info = QLabel()
        self.last_update = QLabel()
        
        info_layout.addWidget(self.os_info)
        info_layout.addWidget(self.kernel_info)
        info_layout.addWidget(self.last_update)
        
        layout.addWidget(info_group)
        
        # Available Updates
        updates_group = QGroupBox("Available Updates")
        updates_layout = QVBoxLayout(updates_group)
        
        self.update_table = QTableWidget()
        self.update_table.setColumnCount(4)
        self.update_table.setHorizontalHeaderLabels([
            "Package", "Current Version", "New Version", "Description"
        ])
        self.update_table.horizontalHeader().setStretchLastSection(True)
        
        updates_layout.addWidget(self.update_table)
        
        # Update controls
        controls = QHBoxLayout()
        
        self.check_btn = QPushButton("Check for Updates")
        self.check_btn.clicked.connect(self.check_updates)
        
        self.update_btn = QPushButton("Install Updates")
        self.update_btn.clicked.connect(self.install_updates)
        
        controls.addWidget(self.check_btn)
        controls.addWidget(self.update_btn)
        controls.addStretch()
        
        updates_layout.addLayout(controls)
        layout.addWidget(updates_group)
        
        # Progress and Output
        output_group = QGroupBox("Update Progress")
        output_layout = QVBoxLayout(output_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        output_layout.addWidget(self.progress_bar)
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
        
        # Initial update
        self.refresh_system_info()
        
    def refresh_system_info(self):
        """Refresh system information"""
        try:
            if self.remote:
                # Get OS info
                stdout, _ = self.remote.execute_command("cat /etc/os-release | grep PRETTY_NAME")
                os_name = stdout.split('=')[1].strip().strip('"') if stdout else "Unknown"
                self.os_info.setText(f"Operating System: {os_name}")
                
                # Get kernel version
                stdout, _ = self.remote.execute_command("uname -r")
                kernel = stdout.strip() if stdout else "Unknown"
                self.kernel_info.setText(f"Kernel Version: {kernel}")
                
                # Get last update time
                stdout, _ = self.remote.execute_command("stat -c %y /var/lib/dpkg/status 2>/dev/null || stat -c %y /var/lib/rpm/Packages 2>/dev/null")
                last_update = stdout.split('.')[0] if stdout else "Unknown"
                self.last_update.setText(f"Last Updated: {last_update}")
            else:
                # Get OS info
                with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            os_name = line.split('=')[1].strip().strip('"')
                            self.os_info.setText(f"Operating System: {os_name}")
                            break
                
                # Get kernel version
                kernel = subprocess.check_output(['uname', '-r'], text=True).strip()
                self.kernel_info.setText(f"Kernel Version: {kernel}")
                
                # Get last update time
                try:
                    # Try dpkg (Debian/Ubuntu)
                    last_update = subprocess.check_output(
                        ['stat', '-c', '%y', '/var/lib/dpkg/status'],
                        text=True
                    ).split('.')[0]
                except:
                    try:
                        # Try rpm (Red Hat/Fedora)
                        last_update = subprocess.check_output(
                            ['stat', '-c', '%y', '/var/lib/rpm/Packages'],
                            text=True
                        ).split('.')[0]
                    except:
                        last_update = "Unknown"
                        
                self.last_update.setText(f"Last Updated: {last_update}")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get system info: {str(e)}")
            
    def check_updates(self):
        """Check for available system updates"""
        self.update_table.setRowCount(0)
        self.output_text.clear()
        self.output_text.append("Checking for updates...")
        
        try:
            if self.remote:
                # Try apt (Debian/Ubuntu)
                stdout, stderr = self.remote.execute_command("apt list --upgradable 2>/dev/null")
                if not stderr:
                    for line in stdout.splitlines()[1:]:  # Skip header
                        parts = line.split('/')
                        if len(parts) >= 2:
                            package = parts[0]
                            versions = parts[1].split()
                            if len(versions) >= 2:
                                current_ver = versions[0]
                                new_ver = versions[1]
                                
                                row = self.update_table.rowCount()
                                self.update_table.insertRow(row)
                                self.update_table.setItem(row, 0, QTableWidgetItem(package))
                                self.update_table.setItem(row, 1, QTableWidgetItem(current_ver))
                                self.update_table.setItem(row, 2, QTableWidgetItem(new_ver))
                else:
                    # Try dnf (Red Hat/Fedora)
                    stdout, stderr = self.remote.execute_command("dnf check-update")
                    if not stderr:
                        for line in stdout.splitlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 3:
                                package = parts[0]
                                new_ver = parts[1]
                                current_ver = parts[2]
                                
                                row = self.update_table.rowCount()
                                self.update_table.insertRow(row)
                                self.update_table.setItem(row, 0, QTableWidgetItem(package))
                                self.update_table.setItem(row, 1, QTableWidgetItem(current_ver))
                                self.update_table.setItem(row, 2, QTableWidgetItem(new_ver))
            else:
                # Try apt (Debian/Ubuntu)
                try:
                    output = subprocess.check_output(['apt', 'list', '--upgradable'], text=True)
                    for line in output.splitlines()[1:]:  # Skip header
                        parts = line.split('/')
                        if len(parts) >= 2:
                            package = parts[0]
                            versions = parts[1].split()
                            if len(versions) >= 2:
                                current_ver = versions[0]
                                new_ver = versions[1]
                                
                                row = self.update_table.rowCount()
                                self.update_table.insertRow(row)
                                self.update_table.setItem(row, 0, QTableWidgetItem(package))
                                self.update_table.setItem(row, 1, QTableWidgetItem(current_ver))
                                self.update_table.setItem(row, 2, QTableWidgetItem(new_ver))
                except:
                    # Try dnf (Red Hat/Fedora)
                    try:
                        output = subprocess.check_output(['dnf', 'check-update'], text=True)
                        for line in output.splitlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 3:
                                package = parts[0]
                                new_ver = parts[1]
                                current_ver = parts[2]
                                
                                row = self.update_table.rowCount()
                                self.update_table.insertRow(row)
                                self.update_table.setItem(row, 0, QTableWidgetItem(package))
                                self.update_table.setItem(row, 1, QTableWidgetItem(current_ver))
                                self.update_table.setItem(row, 2, QTableWidgetItem(new_ver))
                    except:
                        raise Exception("No supported package manager found")
                        
            self.output_text.append("Update check completed.")
            if self.update_table.rowCount() == 0:
                self.output_text.append("System is up to date.")
            else:
                self.output_text.append(f"Found {self.update_table.rowCount()} updates available.")
                
        except Exception as e:
            self.output_text.append(f"Error checking for updates: {str(e)}")
            
    def install_updates(self):
        """Install available system updates"""
        if self.update_table.rowCount() == 0:
            QMessageBox.information(self, "No Updates", "No updates available to install.")
            return
            
        reply = QMessageBox.question(
            self,
            "Confirm Update",
            "Are you sure you want to install all available updates?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
            self.output_text.clear()
            self.output_text.append("Installing updates...")
            
            try:
                if self.remote:
                    # Try apt (Debian/Ubuntu)
                    stdout, stderr = self.remote.execute_command("apt-get update && apt-get upgrade -y")
                    if stderr:
                        # Try dnf (Red Hat/Fedora)
                        stdout, stderr = self.remote.execute_command("dnf upgrade -y")
                        
                    self.output_text.append(stdout)
                    if stderr:
                        self.output_text.append(f"Errors: {stderr}")
                else:
                    # Try apt (Debian/Ubuntu)
                    try:
                        subprocess.run(['apt-get', 'update'], check=True, capture_output=True, text=True)
                        output = subprocess.run(
                            ['apt-get', 'upgrade', '-y'],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        self.output_text.append(output.stdout)
                        if output.stderr:
                            self.output_text.append(f"Errors: {output.stderr}")
                    except:
                        # Try dnf (Red Hat/Fedora)
                        try:
                            output = subprocess.run(
                                ['dnf', 'upgrade', '-y'],
                                check=True,
                                capture_output=True,
                                text=True
                            )
                            self.output_text.append(output.stdout)
                            if output.stderr:
                                self.output_text.append(f"Errors: {output.stderr}")
                        except:
                            raise Exception("No supported package manager found")
                            
                self.output_text.append("Update installation completed.")
                self.progress_bar.setVisible(False)
                self.refresh_system_info()
                self.check_updates()
                
            except Exception as e:
                self.output_text.append(f"Error installing updates: {str(e)}")
                self.progress_bar.setVisible(False) 