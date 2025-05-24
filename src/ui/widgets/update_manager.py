from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QProgressBar, QMessageBox,
    QGroupBox, QTextEdit)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
import subprocess

class UpdateManagerWidget(QWidget):
    """Manages system updates, local or remote."""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        info_group = QGroupBox("System Information")
        info_layout = QVBoxLayout(info_group)
        
        self.os_info = QLabel()
        self.kernel_info = QLabel()
        self.last_update = QLabel()
        
        info_layout.addWidget(self.os_info)
        info_layout.addWidget(self.kernel_info)
        info_layout.addWidget(self.last_update)
        
        layout.addWidget(info_group)
        
        updates_group = QGroupBox("Available Updates")
        updates_layout = QVBoxLayout(updates_group)
        
        self.update_table = QTableWidget()
        self.update_table.setColumnCount(4)
        self.update_table.setHorizontalHeaderLabels([
            "Package", "Current Version", "New Version", "Description"
        ])
        self.update_table.horizontalHeader().setStretchLastSection(True)
        
        updates_layout.addWidget(self.update_table)
        
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
        
        output_group = QGroupBox("Update Progress")
        output_layout = QVBoxLayout(output_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        output_layout.addWidget(self.progress_bar)
        output_layout.addWidget(self.output_text)
        
        layout.addWidget(output_group)
        
        self.refresh_system_info()
        
    def refresh_system_info(self):
        os_name = "Unknown"
        kernel = "Unknown"
        last_update = "Unknown"
        try:
            if self.remote:
                stdout, _ = self.remote.execute_command("cat /etc/os-release | grep PRETTY_NAME")
                os_name = stdout.split('=')[1].strip().strip('"') if stdout else "Unknown"
                
                stdout, _ = self.remote.execute_command("uname -r")
                kernel = stdout.strip() if stdout else "Unknown"
                
                # Attempt to get last update time from dpkg (Debian-based) or rpm (RedHat-based)
                stdout, _ = self.remote.execute_command("stat -c %y /var/lib/dpkg/status 2>/dev/null || stat -c %y /var/lib/rpm/Packages 2>/dev/null")
                last_update = stdout.split('.')[0] if stdout else "Unknown"
            else:
                with open('/etc/os-release') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            os_name = line.split('=')[1].strip().strip('"')
                            break
                
                kernel = subprocess.check_output(['uname', '-r'], text=True).strip()
                
                try:
                    # Check for Debian-based systems first
                    last_update = subprocess.check_output(
                        ['stat', '-c', '%y', '/var/lib/dpkg/status'],
                        text=True
                    ).split('.')[0]
                except subprocess.CalledProcessError:
                    try:
                        # Fallback to RedHat-based systems
                        last_update = subprocess.check_output(
                            ['stat', '-c', '%y', '/var/lib/rpm/Packages'],
                            text=True
                        ).split('.')[0]
                    except subprocess.CalledProcessError:
                        pass
                    except FileNotFoundError:
                        pass
                except FileNotFoundError:
                    pass
            
            self.os_info.setText(f"Operating System: {os_name}")
            self.kernel_info.setText(f"Kernel Version: {kernel}")
            self.last_update.setText(f"Last Updated: {last_update}")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get system info: {str(e)}")
            
    def check_updates(self):
        self.update_table.setRowCount(0)
        self.output_text.clear()
        self.output_text.append("Checking for updates...")

        try:
            if self.remote:
                # Check for apt updates remotely
                stdout, stderr = self.remote.execute_command("apt list --upgradable 2>/dev/null")
                if not stderr: # If apt command succeeded or no stderr output specific to 'command not found'
                    for line in stdout.splitlines()[1:]:
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
                    # If apt fails or not available, try dnf remotely
                    stdout, stderr = self.remote.execute_command("dnf check-update")
                    if not stderr: # Assuming dnf command success if no stderr
                        for line in stdout.splitlines()[1:]:
                            parts = line.split()
                            if len(parts) >= 3:
                                package = parts[0]
                                new_ver = parts[1]
                                current_ver = parts[2] # dnf output format is different

                                row = self.update_table.rowCount()
                                self.update_table.insertRow(row)
                                self.update_table.setItem(row, 0, QTableWidgetItem(package))
                                self.update_table.setItem(row, 1, QTableWidgetItem(current_ver))
                                self.update_table.setItem(row, 2, QTableWidgetItem(new_ver))
            else:
                # Local update check, try apt first
                try:
                    output = subprocess.check_output(['apt', 'list', '--upgradable'], text=True)
                    for line in output.splitlines()[1:]:
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
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # If apt fails or not found, try dnf
                    try:
                        output = subprocess.check_output(['dnf', 'check-update'], text=True)
                        # Skip header line of dnf output if present
                        lines_to_parse = stdout.splitlines()
                        if lines_to_parse and "Last metadata expiration check:" in lines_to_parse[0]:
                            lines_to_parse = lines_to_parse[1:]
                        
                        for line in lines_to_parse: 
                            parts = line.split()
                            if len(parts) >= 3: # package, new_ver, repo, (optional: current_ver if obsoleting)
                                package = parts[0]
                                new_ver = parts[1]
                                # current_ver might not be directly available or might be in a different format
                                # For simplicity, we might leave current_ver blank or try to infer if needed
                                current_ver = "N/A" # Placeholder

                                row = self.update_table.rowCount()
                                self.update_table.insertRow(row)
                                self.update_table.setItem(row, 0, QTableWidgetItem(package))
                                self.update_table.setItem(row, 1, QTableWidgetItem(current_ver))
                                self.update_table.setItem(row, 2, QTableWidgetItem(new_ver))
                    except (subprocess.CalledProcessError, FileNotFoundError) as e:
                        raise RuntimeError(
                            "No supported package manager found for checking updates (apt/dnf)."
                        ) from e

            self.output_text.append("Update check completed.")
            if self.update_table.rowCount() == 0:
                self.output_text.append("System is up to date.")
            else:
                self.output_text.append(f"Found {self.update_table.rowCount()} updates available.")

        except Exception as e:
            self.output_text.append(f"Error checking for updates: {str(e)}")
            
    def install_updates(self):
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
            self.progress_bar.setRange(0, 0) # Indeterminate progress
            self.output_text.clear()
            self.output_text.append("Installing updates...")

            try:
                if self.remote:
                    # Remote execution: Prioritize apt, then dnf
                    stdout_apt, stderr_apt = self.remote.execute_command("apt-get update && apt-get upgrade -y")
                    # Check if apt command indicates success or no updates
                    if not stderr_apt or "0 upgraded, 0 newly installed, 0 to remove" in stdout_apt.lower() or "is already the newest version" in stdout_apt.lower():
                        self._append_output_and_errors(stdout_apt, stderr_apt, "apt")
                    else:
                        # If apt had issues (other than no updates), try dnf
                        stdout_dnf, stderr_dnf = self.remote.execute_command("dnf upgrade -y")
                        self._append_output_and_errors(stdout_dnf, stderr_dnf, "dnf")
                else:
                    # Local execution: try apt, then dnf
                    try:
                        subprocess.run(['apt-get', 'update'], check=True, capture_output=True, text=True)
                        output = subprocess.run(
                            ['apt-get', 'upgrade', '-y'],
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        self._append_output_and_errors(output.stdout, output.stderr, "apt")
                    except subprocess.CalledProcessError as e_apt:
                        try:
                            # If apt fails, try dnf
                            output = subprocess.run(
                                ['dnf', 'upgrade', '-y'], # dnf upgrade automatically runs a makecache
                                check=True,
                                capture_output=True,
                                text=True
                            )
                            self._append_output_and_errors(output.stdout, output.stderr, "dnf")
                        except subprocess.CalledProcessError as e_dnf:
                            self.output_text.append(f"Failed with apt: {e_apt.stderr}\nFailed with dnf: {e_dnf.stderr}")
                            raise Exception("Both apt and dnf failed for local update.") from e_dnf
                        except FileNotFoundError as e:
                            self.output_text.append(f"Failed with apt: {e_apt.stderr}\ndnf command not found.")
                            raise Exception("apt failed and dnf not found for local update.") from e
                    except FileNotFoundError:
                         # apt not found, try dnf
                        try:
                            output = subprocess.run(
                                ['dnf', 'upgrade', '-y'],
                                check=True,
                                capture_output=True,
                                text=True
                            )
                            self._append_output_and_errors(output.stdout, output.stderr, "dnf")
                        except subprocess.CalledProcessError as e_dnf:
                            self.output_text.append(f"apt command not found.\nFailed with dnf: {e_dnf.stderr}")
                            raise Exception("apt not found and dnf failed for local update.") from e_dnf
                        except FileNotFoundError as e:
                            raise Exception("Neither apt nor dnf command was found locally.") from e

                self.output_text.append("Update installation completed.")
                self.progress_bar.setVisible(False)
                self.refresh_system_info()
                self.check_updates() # Refresh available updates list

            except Exception as e:
                self.output_text.append(f"Error installing updates: {str(e)}")
                self.progress_bar.setVisible(False)

    def _append_output_and_errors(self, stdout, stderr, pkg_manager_name):
        if stdout:
            self.output_text.append(f"--- {pkg_manager_name} output ---")
            self.output_text.append(stdout.strip())
        
        # Filter out dnf's "Last metadata expiration check" message from stderr
        if stderr and pkg_manager_name == "dnf":
            lines = stderr.splitlines()
            filtered_stderr = [line for line in lines if not line.startswith("Last metadata expiration check:")]
            stderr = "\\n".join(filtered_stderr).strip()

        if stderr: # If stderr still has content after filtering
            self.output_text.append(f"--- {pkg_manager_name} errors/warnings ---")
            self.output_text.append(stderr.strip()) 