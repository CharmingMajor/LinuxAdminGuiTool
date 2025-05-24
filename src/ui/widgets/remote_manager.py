import contextlib
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QTextEdit, QGroupBox, QTableWidget, QTableWidgetItem,
    QMessageBox, QDialog, QFormLayout, QSpinBox, QComboBox, QInputDialog, QProgressBar)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QIcon
import paramiko  # SSH client library
import psutil
import json
from pathlib import Path
import os

class AddHostDialog(QDialog):
    """Dialog for adding a new remote host"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Remote Host")
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout(self)
        
        # Host details
        self.name_input = QLineEdit()
        self.host_input = QLineEdit()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(22)  # Default SSH port
        self.username_input = QLineEdit()
        
        layout.addRow("Name:", self.name_input)
        layout.addRow("Host:", self.host_input)
        layout.addRow("Port:", self.port_input)
        layout.addRow("Username:", self.username_input)
        
        # Buttons
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addRow("", button_layout)

class RemoteManagerWidget(QWidget):
    """Widget for managing remote SSH connections"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.ssh_clients = {}  # Store SSH connections
        self.remote = remote  # Store the main remote connection
        self.setup_ui()
        self.load_hosts()
        
    def setup_ui(self):
        """Set up the remote manager UI"""
        layout = QVBoxLayout(self)

        # Current connection info
        if self.remote:
            info_group = QGroupBox("Current Connection")
            info_layout = QHBoxLayout(info_group)
            info_layout.addWidget(QLabel(f"Connected to: {self.remote.hostname}"))
            info_layout.addWidget(QLabel(f"as: {self.remote.username}"))
            layout.addWidget(info_group)

        # Hosts management
        hosts_group = QGroupBox("Remote Hosts")
        hosts_layout = QVBoxLayout(hosts_group)

        # Hosts table
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(5)
        self.hosts_table.setHorizontalHeaderLabels([
            "Name", "Host", "Port", "Username", "Status"
        ])
        self.hosts_table.horizontalHeader().setStretchLastSection(True)
        self.hosts_table.itemSelectionChanged.connect(self.on_host_selected)

        hosts_layout.addWidget(self.hosts_table)

        # Host controls
        host_buttons = QHBoxLayout()

        add_btn = QPushButton("Add Host")
        add_btn.clicked.connect(self.add_host)

        remove_btn = QPushButton("Remove Host")
        remove_btn.clicked.connect(self.remove_host)

        connect_btn = QPushButton("Connect")
        connect_btn.clicked.connect(self.connect_host)

        disconnect_btn = QPushButton("Disconnect")
        disconnect_btn.clicked.connect(self.disconnect_host)

        host_buttons.addWidget(add_btn)
        host_buttons.addWidget(remove_btn)
        host_buttons.addWidget(connect_btn)
        self._extracted_from_setup_ui_46(host_buttons, disconnect_btn, hosts_layout)
        layout.addWidget(hosts_group)

        # Remote management
        manage_group = QGroupBox("Remote Management")
        manage_layout = QVBoxLayout(manage_group)

        # Action selector
        action_layout = QHBoxLayout()

        self.action_selector = QComboBox()
        self.action_selector.addItems([
            "System Monitor",
            "Process Manager",
            "User Management",
            "File Browser",
            "Network Config",
            "Service Control"
        ])

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_data)

        action_layout.addWidget(QLabel("Action:"))
        action_layout.addWidget(self.action_selector)
        self._extracted_from_setup_ui_46(action_layout, refresh_btn, manage_layout)
        # Output display
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        manage_layout.addWidget(self.output_text)

        # Command input
        cmd_layout = QHBoxLayout()

        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Enter command...")
        self.cmd_input.returnPressed.connect(self.send_command)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_command)

        cmd_layout.addWidget(self.cmd_input)
        cmd_layout.addWidget(send_btn)

        manage_layout.addLayout(cmd_layout)
        layout.addWidget(manage_group)

    # Helper method to add a widget to layout with stretch
    def _extracted_from_setup_ui_46(self, arg0, arg1, arg2):
        arg0.addWidget(arg1)
        arg0.addStretch()

        arg2.addLayout(arg0)
        
    def load_hosts(self):
        """Load saved hosts from configuration"""
        config_file = Path.home() / ".remote_hosts.json"
        if config_file.exists():
            try:
                with open(config_file) as f:
                    hosts = json.load(f)
                    for host in hosts:
                        self.add_host_to_table(
                            host["name"],
                            host["host"],
                            host["port"],
                            host["username"]
                        )
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load hosts: {str(e)}")
                
    def save_hosts(self):
        """Save hosts to configuration"""
        hosts = []
        hosts.extend(
            {
                "name": self.hosts_table.item(row, 0).text(),
                "host": self.hosts_table.item(row, 1).text(),
                "port": int(self.hosts_table.item(row, 2).text()),
                "username": self.hosts_table.item(row, 3).text(),
            }
            for row in range(self.hosts_table.rowCount())
        )
        config_file = Path.home() / ".remote_hosts.json"
        try:
            with open(config_file, "w") as f:
                json.dump(hosts, f)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save hosts: {str(e)}")
            
    def add_host(self):
        """Add a new remote host"""
        dialog = AddHostDialog(self)
        if dialog.exec():
            name = dialog.name_input.text()
            host = dialog.host_input.text()
            port = dialog.port_input.value()
            username = dialog.username_input.text()
            
            if not all([name, host, username]):
                QMessageBox.warning(self, "Error", "All fields are required")
                return
                
            self.add_host_to_table(name, host, port, username)
            self.save_hosts()
            
    def add_host_to_table(self, name, host, port, username):
        """Add a host to the hosts table"""
        row = self.hosts_table.rowCount()
        self.hosts_table.insertRow(row)
        
        self.hosts_table.setItem(row, 0, QTableWidgetItem(name))
        self.hosts_table.setItem(row, 1, QTableWidgetItem(host))
        self.hosts_table.setItem(row, 2, QTableWidgetItem(str(port)))
        self.hosts_table.setItem(row, 3, QTableWidgetItem(username))
        self.hosts_table.setItem(row, 4, QTableWidgetItem("Disconnected"))
        
    def remove_host(self):
        """Remove the selected host"""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        name = self.hosts_table.item(row, 0).text()
        
        reply = QMessageBox.question(
            self,
            "Confirm Remove",
            f"Are you sure you want to remove {name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if name in self.ssh_clients:
                self.disconnect_host()
            self.hosts_table.removeRow(row)
            self.save_hosts()
            
    def connect_host(self):
        """Connect to the selected host"""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        name = self.hosts_table.item(row, 0).text()
        host = self.hosts_table.item(row, 1).text()
        port = int(self.hosts_table.item(row, 2).text())
        username = self.hosts_table.item(row, 3).text()
        
        try:
            # Try to use SSH key authentication first
            key_path = os.path.expanduser("~/.ssh/id_rsa")
            if os.path.exists(key_path):
                key = paramiko.RSAKey.from_private_key_file(key_path)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port, username, pkey=key)
            else:
                # If no key, ask for password
                password, ok = QInputDialog.getText(
                    self, "SSH Password", 
                    f"Enter password for {username}@{host}:",
                    QLineEdit.EchoMode.Password
                )
                if not ok:
                    return
                    
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(host, port, username, password)
                
            self.ssh_clients[name] = client
            self.hosts_table.setItem(row, 4, QTableWidgetItem("Connected"))
            self.output_text.append(f"Connected to {name} ({host})")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to connect: {str(e)}")
            
    def disconnect_host(self):
        """Disconnect from the selected host"""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        name = self.hosts_table.item(row, 0).text()
        
        if name in self.ssh_clients:
            try:
                self.ssh_clients[name].close()
                del self.ssh_clients[name]
                self.hosts_table.setItem(row, 4, QTableWidgetItem("Disconnected"))
                self.output_text.append(f"Disconnected from {name}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to disconnect: {str(e)}")
                
    def send_command(self):
        """Send a command to the selected host"""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        name = self.hosts_table.item(row, 0).text()
        command = self.cmd_input.text()
        
        if name not in self.ssh_clients or not command:
            return
        
        try:
            self._execute_remote_command_and_display_output(name, command)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to send command: {str(e)}")
            
    def _execute_remote_command_and_display_output(self, name, command):
        """Execute a command on the remote host and show the output"""
        client = self.ssh_clients[name]
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()

        self.output_text.append(f"\n$ {command}")
        if output:
            self.output_text.append(output)
        if error:
            self.output_text.append(f"Error: {error}")

        self.cmd_input.clear()
            
    def refresh_data(self):
        """Refresh data based on selected action"""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        name = self.hosts_table.item(row, 0).text()
        
        if name not in self.ssh_clients:
            QMessageBox.warning(self, "Error", "Not connected to host")
            return
            
        action = self.action_selector.currentText()
        
        try:
            # Route to the appropriate data retrieval method based on selected action
            if action == "System Monitor":
                self.get_system_info(name)
            elif action == "Process Manager":
                self.get_process_list(name)
            elif action == "User Management":
                self.get_user_list(name)
            elif action == "File Browser":
                self.get_file_list(name)
            elif action == "Network Config":
                self.get_network_info(name)
            elif action == "Service Control":
                self.get_service_list(name)
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to refresh data: {str(e)}")
            
    def get_system_info(self, name):
        """Get system information from remote host"""
        commands = [
            "uptime",
            "free -h",
            "df -h",
            "cat /proc/cpuinfo | grep 'model name' | head -n1",
            "uname -a",  # System kernel and version info
            "lscpu | grep 'CPU(s):' | head -n1"  # CPU count
        ]

        self.output_text.clear()
        self.output_text.append("=== System Information ===\n")

        for cmd in commands:
            try:
                stdin, stdout, stderr = self.ssh_clients[name].exec_command(cmd)
                output = stdout.read().decode()
                if error := stderr.read().decode():
                    self.output_text.append(f"Error running {cmd}: {error}\n")
                else:
                    self.output_text.append(f"$ {cmd}\n{output}\n")
            except Exception as e:
                self.output_text.append(f"Error running {cmd}: {str(e)}\n")
                
    def get_process_list(self, name):
        """Get process list from remote host"""
        try:
            # Get top processes by CPU and memory
            cmd = "ps aux --sort=-%cpu,%mem | head -n11"  # Header + 10 processes
            stdin, stdout, stderr = self.ssh_clients[name].exec_command(cmd)
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            self.output_text.clear()
            self.output_text.append("=== Process List (Top 10 by CPU/Memory) ===\n")
            if error:
                self.output_text.append(f"Error: {error}\n")
            else:
                self.output_text.append(output)
        except Exception as e:
            self.output_text.append(f"Error getting process list: {str(e)}\n")
            
    def get_user_list(self, name):
        """Get user list from remote host"""
        cmd = "cat /etc/passwd | cut -d: -f1,3,4,6,7"
        stdin, stdout, stderr = self.ssh_clients[name].exec_command(cmd)
        output = stdout.read().decode()
        
        self.output_text.clear()
        self.output_text.append("=== User List ===\n")
        self.output_text.append(output)
        
    def get_file_list(self, name):
        """Get file list from remote host"""
        cmd = "ls -la"
        stdin, stdout, stderr = self.ssh_clients[name].exec_command(cmd)
        output = stdout.read().decode()
        
        self.output_text.clear()
        self.output_text.append("=== File List ===\n")
        self.output_text.append(output)
        
    def get_network_info(self, name):
        """Get network information from remote host"""
        commands = [
            "ip addr",
            "ip route",
            "netstat -tuln",
            "ss -s",  # Socket statistics
            "cat /proc/net/dev"  # Network interface statistics
        ]

        self.output_text.clear()
        self.output_text.append("=== Network Information ===\n")

        for cmd in commands:
            try:
                stdin, stdout, stderr = self.ssh_clients[name].exec_command(cmd)
                output = stdout.read().decode()
                if error := stderr.read().decode():
                    self.output_text.append(f"Error running {cmd}: {error}\n")
                else:
                    self.output_text.append(f"$ {cmd}\n{output}\n")
            except Exception as e:
                self.output_text.append(f"Error running {cmd}: {str(e)}\n")
                
    def get_service_list(self, name):
        """Get service list from remote host"""
        commands = [
            "systemctl list-units --type=service --state=running",
            "systemctl list-units --type=service --state=failed",
            "systemctl list-timers --all"  # Show scheduled services
        ]

        self.output_text.clear()
        self.output_text.append("=== Service Status ===\n")

        for cmd in commands:
            try:
                stdin, stdout, stderr = self.ssh_clients[name].exec_command(cmd)
                output = stdout.read().decode()
                if error := stderr.read().decode():
                    self.output_text.append(f"Error running {cmd}: {error}\n")
                else:
                    self.output_text.append(f"$ {cmd}\n{output}\n")
            except Exception as e:
                self.output_text.append(f"Error running {cmd}: {str(e)}\n")
                
    def on_host_selected(self):
        """Handle host selection change"""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
            
        row = selected[0].row()
        name = self.hosts_table.item(row, 0).text()
        
        # Clear output if not connected
        if name not in self.ssh_clients:
            self.output_text.clear()
            self.output_text.append("Not connected to host")
            return
            
        # Show basic system info for new selection
        self.get_system_info(name)
        
    def cleanup(self):
        """Clean up resources"""
        # Disconnect all SSH clients
        for name, client in self.ssh_clients.items():
            with contextlib.suppress(Exception):
                client.close()
        self.ssh_clients.clear()
        
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event) 