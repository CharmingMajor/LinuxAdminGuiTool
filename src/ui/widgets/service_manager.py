from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QGroupBox, QTextEdit, QHeaderView, 
    QMessageBox, QLineEdit, QComboBox, QDialog, QFormLayout)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
from typing import Optional, List, Dict
from src.backend.senior_dashboard_backend import SeniorDashboardBackend

class ServiceManagerWidget(QWidget):
    """Widget for managing system services and network configurations"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote  # For remote system management
        self.backend = SeniorDashboardBackend(remote)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # ---- Services management section ----
        services_group = QGroupBox("System Services")
        services_layout = QVBoxLayout(services_group)
        
        # Services table
        self.services_table = QTableWidget()
        self.services_table.setColumnCount(3)
        self.services_table.setHorizontalHeaderLabels(["Service Name", "Status", "Actions"])
        self.services_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.services_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        services_layout.addWidget(self.services_table)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Services")
        refresh_btn.clicked.connect(self.refresh_services)
        services_layout.addWidget(refresh_btn)
        
        layout.addWidget(services_group)
        
        # ---- Firewall management section ----
        firewall_group = QGroupBox("Firewall Management")
        firewall_layout = QVBoxLayout(firewall_group)
        
        # Firewall status
        self.firewall_status_label = QLabel("Firewall Status: Unknown")
        firewall_layout.addWidget(self.firewall_status_label)
        
        # Firewall rules table
        self.firewall_table = QTableWidget()
        self.firewall_table.setColumnCount(3)
        self.firewall_table.setHorizontalHeaderLabels(["Rule", "Action", "Source/Destination"])
        self.firewall_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        firewall_layout.addWidget(self.firewall_table)
        
        # Controls for adding/removing firewall rules
        controls_layout = QHBoxLayout()
        
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("e.g., allow 22/tcp")
        controls_layout.addWidget(self.rule_input)
        
        add_rule_btn = QPushButton("Add Rule")
        add_rule_btn.clicked.connect(self.add_firewall_rule)
        controls_layout.addWidget(add_rule_btn)
        
        delete_rule_btn = QPushButton("Delete Rule")
        delete_rule_btn.clicked.connect(self.delete_firewall_rule)
        controls_layout.addWidget(delete_rule_btn)
        
        firewall_layout.addLayout(controls_layout)
        
        layout.addWidget(firewall_group)
        
        # ---- Terminal output console section ----
        output_group = QGroupBox("Command Output")
        output_layout = QVBoxLayout(output_group)
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #121212; color: #CCCCCC; font-family: 'Courier New', monospace;")
        self.output_console.setMinimumHeight(150)
        output_layout.addWidget(self.output_console)
        layout.addWidget(output_group)
        
        # Load initial data
        self.refresh_services()
        self.refresh_firewall_status()
        
    def refresh_services(self):
        """Refresh the list of system services"""
        try:
            services = self.backend.get_active_services()
            
            self.services_table.setRowCount(0)  # Clear existing rows
            
            for service in services:
                row_position = self.services_table.rowCount()
                self.services_table.insertRow(row_position)
                
                # Add service name
                name_item = QTableWidgetItem(service["name"])
                name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)  # Make non-editable
                self.services_table.setItem(row_position, 0, name_item)
                
                # Add status
                status_item = QTableWidgetItem(service["status"])
                status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)
                self.services_table.setItem(row_position, 1, status_item)
                
                # Add action buttons (restart and stop)
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(0, 0, 0, 0)
                
                restart_btn = QPushButton("Restart")
                restart_btn.clicked.connect(lambda checked, name=service["name"]: self.restart_service(name))
                
                stop_btn = QPushButton("Stop")
                stop_btn.clicked.connect(lambda checked, name=service["name"]: self.stop_service(name))
                
                action_layout.addWidget(restart_btn)
                action_layout.addWidget(stop_btn)
                self.services_table.setCellWidget(row_position, 2, action_widget)
            
            self._display_output("Services refreshed.")
            
        except Exception as e:
            self._display_output(f"Error refreshing services: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to refresh services: {str(e)}")
    
    def restart_service(self, service_name):
        """Restart the selected service"""
        try:
            cmd = f"sudo systemctl restart {service_name}"
            self._display_output(f"$ {cmd}")
            
            # Execute command and get results
            success, output = self.backend.execute_admin_command(cmd, use_sudo=True)
            
            self._display_output(output)
            
            if success:
                QMessageBox.information(self, "Success", f"Service {service_name} restarted successfully")
                self.refresh_services()  # Update the services list
                
        except Exception as e:
            self._display_output(f"Error restarting service: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to restart service: {str(e)}")
    
    def stop_service(self, service_name):
        """Stop the selected service"""
        try:
            cmd = f"sudo systemctl stop {service_name}"
            self._display_output(f"$ {cmd}")
            
            success, output = self.backend.execute_admin_command(cmd, use_sudo=True)
            
            self._display_output(output)
            
            if success:
                QMessageBox.information(self, "Success", f"Service {service_name} stopped successfully")
                self.refresh_services()
                
        except Exception as e:
            self._display_output(f"Error stopping service: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to stop service: {str(e)}")
    
    def refresh_firewall_status(self):
        """Refresh the firewall status and rules"""
        try:
            # Get firewall status and rules from backend
            success, status, rules = self.backend.get_firewall_status()
            
            if success:
                self.firewall_status_label.setText(f"Firewall Status: {status}")
                
                # Clear and populate the rules table
                self.firewall_table.setRowCount(0)
                
                for rule in rules:
                    row_position = self.firewall_table.rowCount()
                    self.firewall_table.insertRow(row_position)
                    
                    # Add rule details to table
                    self.firewall_table.setItem(row_position, 0, QTableWidgetItem(rule["to"]))
                    self.firewall_table.setItem(row_position, 1, QTableWidgetItem(rule["action"]))
                    self.firewall_table.setItem(row_position, 2, QTableWidgetItem(rule["from"]))
            else:
                self.firewall_status_label.setText(f"Firewall Status: Error - {status}")
                
            self._display_output("Firewall status refreshed.")
            
        except Exception as e:
            self._display_output(f"Error refreshing firewall status: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to refresh firewall status: {str(e)}")
    
    def add_firewall_rule(self):
        """Add a new firewall rule"""
        rule = self.rule_input.text().strip()
        
        if not rule:
            QMessageBox.critical(self, "Error", "Please enter a firewall rule")
            return
        
        try:
            # Show command in console
            self._display_output(f"$ sudo ufw {rule}")
            
            # Execute command using backend
            success, message = self.backend.add_firewall_rule(rule)
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "Firewall rule added successfully")
                self.rule_input.clear()
                self.refresh_firewall_status()  # Update firewall status and rules display
                
        except Exception as e:
            self._display_output(f"Error adding firewall rule: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to add firewall rule: {str(e)}")
    
    def delete_firewall_rule(self):
        """Delete a firewall rule"""
        rule = self.rule_input.text().strip()
        
        if not rule:
            QMessageBox.critical(self, "Error", "Please enter a firewall rule to delete")
            return
        
        try:
            self._display_output(f"$ sudo ufw delete {rule}")
            
            success, message = self.backend.delete_firewall_rule(rule)
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", "Firewall rule deleted successfully")
                self.rule_input.clear()
                self.refresh_firewall_status()
                
        except Exception as e:
            self._display_output(f"Error deleting firewall rule: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to delete firewall rule: {str(e)}")
    
    def _display_output(self, text):
        """Display text in the output console with appropriate formatting"""
        self.output_console.append(text)
        self.output_console.ensureCursorVisible()  # Ensure the latest text is visible 