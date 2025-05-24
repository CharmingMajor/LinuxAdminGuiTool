from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QMessageBox,
    QDialog, QFormLayout, QSpinBox, QGroupBox)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
import subprocess
import time
import re

# This module provides a GUI for configuring and managing firewall rules
# using the Uncomplicated Firewall (ufw) backend

class FirewallConfigWidget(QWidget):
    """Widget for configuring firewall rules"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote  # Store remote connection for SSH operations
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the firewall configuration UI"""
        layout = QVBoxLayout(self)
        
        # Status section shows if firewall is active and provides toggle controls
        status_group = QGroupBox("Firewall Status")
        status_layout = QHBoxLayout(status_group)
        
        self.status_label = QLabel("Status: Unknown")
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_status)
        
        toggle_btn = QPushButton("Toggle Firewall")
        toggle_btn.clicked.connect(self.toggle_firewall)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(refresh_btn)
        status_layout.addWidget(toggle_btn)
        status_layout.addStretch()
        
        layout.addWidget(status_group)
        
        # Rules section displays current firewall rules and rule management controls
        rules_group = QGroupBox("Firewall Rules")
        rules_layout = QVBoxLayout(rules_group)
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(6)
        self.rules_table.setHorizontalHeaderLabels([
            "Chain", "Protocol", "Source", "Destination", "Port", "Action"
        ])
        self.rules_table.horizontalHeader().setStretchLastSection(True)
        
        rules_layout.addWidget(self.rules_table)
        
        # Control section for creating new firewall rules
        controls_layout = QHBoxLayout()
        
        self.chain_selector = QComboBox()
        self.chain_selector.addItems(["INPUT", "OUTPUT", "FORWARD"])
        
        self.protocol_selector = QComboBox()
        self.protocol_selector.addItems(["tcp", "udp", "icmp", "all"])
        
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("Source IP/Network")
        
        self.dest_input = QLineEdit()
        self.dest_input.setPlaceholderText("Destination IP/Network")
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        
        self.action_selector = QComboBox()
        self.action_selector.addItems(["ACCEPT", "DROP", "REJECT"])
        
        controls_layout.addWidget(QLabel("Chain:"))
        controls_layout.addWidget(self.chain_selector)
        controls_layout.addWidget(QLabel("Protocol:"))
        controls_layout.addWidget(self.protocol_selector)
        controls_layout.addWidget(QLabel("Source:"))
        controls_layout.addWidget(self.source_input)
        controls_layout.addWidget(QLabel("Destination:"))
        controls_layout.addWidget(self.dest_input)
        controls_layout.addWidget(QLabel("Port:"))
        controls_layout.addWidget(self.port_input)
        controls_layout.addWidget(QLabel("Action:"))
        controls_layout.addWidget(self.action_selector)
        
        rules_layout.addLayout(controls_layout)
        
        # Buttons for rule management operations
        button_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        
        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_rule)
        
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_rules)
        
        button_layout.addWidget(add_btn)
        button_layout.addWidget(delete_btn)
        button_layout.addWidget(clear_btn)
        button_layout.addStretch()
        
        rules_layout.addLayout(button_layout)
        layout.addWidget(rules_group)
        
        self.refresh_status()
        self.load_rules()
        
    def refresh_status(self):
        """Refresh the firewall status"""
        try:
            if self.remote:
                # Handle remote system firewall status check
                stdout, stderr = self.remote.execute_command("systemctl is-active ufw")
                if not stderr:
                    status = stdout.strip()
                    self.status_label.setText(f"Status: {status.title()}")
                else:
                    self.status_label.setText("Status: Error")
            else:
                # Handle local system firewall status check
                output = subprocess.check_output(['systemctl', 'is-active', 'ufw'], text=True)
                self.status_label.setText(f"Status: {output.strip().title()}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to get firewall status: {str(e)}")
            
    def toggle_firewall(self):
        """Toggle the firewall on/off"""
        try:
            if self.remote:
                # Extract current status and toggle accordingly on remote system
                current_status = self.status_label.text().split(":")[1].strip().lower()
                command = "ufw disable" if current_status == "active" else "ufw enable"
                stdout, stderr = self.remote.execute_command(f"sudo {command}")
                if stderr:
                    raise RuntimeError(stderr)
            else:
                # Toggle firewall state on local system
                current_status = self.status_label.text().split(":")[1].strip().lower()
                command = ['ufw', 'disable' if current_status == "active" else 'enable']
                subprocess.run(command, check=True)
                
            QMessageBox.information(self, "Success", "Firewall state toggled")
            self.refresh_status()
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to toggle firewall: {str(e)}")
            
    def load_rules(self):
        """Load the current firewall rules"""
        try:
            self.rules_table.setRowCount(0)
            
            if self.remote:
                # Fetch and parse rules from remote system
                stdout, stderr = self.remote.execute_command("sudo ufw status numbered")
                if stderr:
                    raise RuntimeError(stderr)
                    
                for line in stdout.strip().split("\n"):
                    if line.startswith("["):
                        parts = line.split()
                        if len(parts) >= 4:
                            chain = "INPUT"
                            action = parts[-1]
                            protocol = "all"
                            source = parts[2]
                            dest = parts[3]
                            port = parts[4] if len(parts) > 4 else "any"
                            
                            self.add_rule_to_table(chain, protocol, source, dest, port, action)
            else:
                # Fetch and parse rules from local system
                output = subprocess.check_output(['ufw', 'status', 'numbered'], text=True)
                for line in output.strip().split("\n"):
                    if line.startswith("["):
                        parts = line.split()
                        if len(parts) >= 4:
                            chain = "INPUT"
                            action = parts[-1]
                            protocol = "all"
                            source = parts[2]
                            dest = parts[3]
                            port = parts[4] if len(parts) > 4 else "any"
                            
                            self.add_rule_to_table(chain, protocol, source, dest, port, action)
                            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load firewall rules: {str(e)}")
            
    def add_rule_to_table(self, chain, protocol, source, dest, port, action):
        """Add a rule to the rules table"""
        row = self.rules_table.rowCount()
        self.rules_table.insertRow(row)
        
        self.rules_table.setItem(row, 0, QTableWidgetItem(chain))
        self.rules_table.setItem(row, 1, QTableWidgetItem(protocol))
        self.rules_table.setItem(row, 2, QTableWidgetItem(source))
        self.rules_table.setItem(row, 3, QTableWidgetItem(dest))
        self.rules_table.setItem(row, 4, QTableWidgetItem(str(port)))
        self.rules_table.setItem(row, 5, QTableWidgetItem(action))
        
    def add_rule(self):
        """Add a new firewall rule"""
        try:
            # Collect rule parameters from UI inputs
            chain = self.chain_selector.currentText()
            protocol = self.protocol_selector.currentText()
            source = self.source_input.text() or "any"
            dest = self.dest_input.text() or "any"
            port = self.port_input.value()
            action = self.action_selector.currentText()
            
            # Build ufw command string
            cmd = f"sudo ufw {action.lower()}"
            if protocol != "all":
                cmd += f" proto {protocol}"
            if source != "any":
                cmd += f" from {source}"
            if dest != "any":
                cmd += f" to {dest}"
            if port != 0:
                cmd += f" port {port}"
                
            if self.remote:
                stdout, stderr = self.remote.execute_command(cmd)
                if stderr:
                    raise RuntimeError(stderr)
            else:
                subprocess.run(cmd.split(), check=True)
                
            self.add_rule_to_table(chain, protocol, source, dest, port, action)
            QMessageBox.information(self, "Success", "Rule added successfully")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add rule: {str(e)}")
            
    def delete_rule(self):
        """Delete the selected firewall rule"""
        try:
            selected = self.rules_table.selectedItems()
            if not selected:
                return
                
            row = selected[0].row()
            rule_number = row + 1  # UFW rules are 1-indexed
            
            if self.remote:
                stdout, stderr = self.remote.execute_command(f"sudo ufw delete {rule_number}")
                if stderr:
                    raise RuntimeError(stderr)
            else:
                subprocess.run(['ufw', 'delete', str(rule_number)], check=True)
                
            self.rules_table.removeRow(row)
            QMessageBox.information(self, "Success", "Rule deleted successfully")
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to delete rule: {str(e)}")
            
    def clear_rules(self):
        """Clear all firewall rules"""
        try:
            reply = QMessageBox.question(
                self,
                "Confirm Clear",
                "Are you sure you want to clear all rules?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                if self.remote:
                    # Use echo to automatically confirm the reset prompt on remote system
                    stdout, stderr = self.remote.execute_command("echo y | sudo ufw reset")
                    if stderr:
                        raise RuntimeError(stderr)
                else:
                    # Use echo to automatically confirm the reset prompt on local system
                    subprocess.run(['ufw', 'reset'], check=True)
                    
                self.rules_table.setRowCount(0)
                QMessageBox.information(self, "Success", "All rules cleared successfully")
                
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to clear rules: {str(e)}")
            
    def closeEvent(self, event):
        """Handle widget close event"""
        super().closeEvent(event) 