from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QTableWidget, QTableWidgetItem, QGroupBox, QLineEdit,
    QComboBox, QMessageBox, QDialog, QFormLayout, QCheckBox, QFileDialog, QTextEdit, QHeaderView)
from PySide6.QtCore import Qt, Signal
import subprocess
import re
import netifaces
import structlog
from src.ui.utils.theme_manager import ThemeManager
from PySide6.QtGui import QFont, QIcon
from typing import Optional, List, Dict
from src.backend.senior_dashboard_backend import SeniorDashboardBackend
from src.backend.junior_backend import JuniorBackend

logger = structlog.get_logger(__name__)

class NetworkManagerWidget(QWidget):
    """Widget for managing network interfaces and connectivity"""
    
    def __init__(self, parent=None, remote=None, is_senior=True):
        super().__init__(parent)
        self.remote = remote
        self.is_senior = is_senior
        
        # Initialize the appropriate backend based on role
        if self.is_senior:
            self.backend = SeniorDashboardBackend(remote)
        else:
            self.backend = JuniorBackend(remote=remote)
            
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.apply_theme)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        self.theme_manager.apply_widget_styles(self)
        
        # Role explanation box
        role_box = QGroupBox("Role-Based Network Permissions")
        role_layout = QVBoxLayout(role_box)
        
        if self.is_senior:
            role_text = "Senior Admin Role: You have full access to view and modify network configurations."
        else:
            role_text = "Junior Admin Role: You can view network information and check connectivity, but cannot modify network configurations."
        
        role_label = QLabel(role_text)
        role_label.setWordWrap(True)
        role_layout.addWidget(role_label)
        layout.addWidget(role_box)
        
        # Network interfaces table
        interfaces_group = QGroupBox("Network Interfaces")
        interfaces_layout = QVBoxLayout(interfaces_group)
        
        self.interfaces_table = QTableWidget()
        self.interfaces_table.setColumnCount(4)
        self.interfaces_table.setHorizontalHeaderLabels(["Interface", "IP Address", "State", "Actions"])
        self.interfaces_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.interfaces_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        interfaces_layout.addWidget(self.interfaces_table)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Interfaces")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        interfaces_layout.addWidget(refresh_btn)
        
        layout.addWidget(interfaces_group)
        
        # IP Configuration group
        ip_config_group = QGroupBox("IP Configuration")
        self.ip_config_group = ip_config_group
        ip_config_layout = QFormLayout(ip_config_group)
        
        self.interface_combo = QComboBox()
        self.ip_address_input = QLineEdit()
        self.netmask_input = QLineEdit()
        self.netmask_input.setText("24")
        
        ip_config_layout.addRow("Interface:", self.interface_combo)
        ip_config_layout.addRow("IP Address:", self.ip_address_input)
        ip_config_layout.addRow("Netmask (CIDR):", self.netmask_input)
        
        # Apply button
        apply_ip_btn = QPushButton("Apply IP Configuration")
        apply_ip_btn.clicked.connect(self.apply_ip_config)
        ip_config_layout.addRow("", apply_ip_btn)
        
        layout.addWidget(ip_config_group)
        
        # Connectivity check group
        connectivity_group = QGroupBox("Connectivity Check")
        connectivity_layout = QFormLayout(connectivity_group)
        
        self.host_input = QLineEdit()
        self.host_input.setText("8.8.8.8")
        self.packet_count_input = QLineEdit()
        self.packet_count_input.setText("4")
        
        connectivity_layout.addRow("Host:", self.host_input)
        connectivity_layout.addRow("Packet Count:", self.packet_count_input)
        
        # Check button
        check_btn = QPushButton("Check Connectivity")
        check_btn.clicked.connect(self.check_connectivity)
        connectivity_layout.addRow("", check_btn)
        
        layout.addWidget(connectivity_group)
        
        # Terminal output console
        output_group = QGroupBox("Command Output")
        output_layout = QVBoxLayout(output_group)
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("background-color: #121212; color: #CCCCCC; font-family: 'Courier New', monospace;")
        self.output_console.setMinimumHeight(150)
        output_layout.addWidget(self.output_console)
        layout.addWidget(output_group)
        
        # Disable configuration controls for Junior Admins
        if not self.is_senior:
            self.ip_config_group.setEnabled(False)
        
        # Initial load of interfaces
        self.refresh_interfaces()
        
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        try:
            interfaces = []
            error_message = ""

            if self.is_senior:
                interfaces, error_message = self.backend.list_network_interfaces()
            else:
                interfaces = self.backend.get_network_interfaces()
                
                if not interfaces:
                    # Check if a remote connection exists
                    if not self.remote or not self.remote.connected:
                        error_message = "Remote connection not available."
                    else:
                        # This message covers both actual empty list and silent error cases.
                        error_message = "No network interfaces found or an error occurred while fetching them."
            
            if error_message:
                self._display_output(f"Error listing network interfaces: {error_message}")
                
                if not interfaces: # Ensure table is cleared if error leads to no data
                    self.interfaces_table.setRowCount(0)
                    self.interface_combo.clear()
                return # Stop further processing if a significant error occurred
                
            self.interfaces_table.setRowCount(0)
            self.interface_combo.clear()
            
            for interface in interfaces:
                row_position = self.interfaces_table.rowCount()
                self.interfaces_table.insertRow(row_position)
                
                # Add interface name
                name_item = QTableWidgetItem(interface["name"])
                name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
                self.interfaces_table.setItem(row_position, 0, name_item)
                
                # Add IP address
                ip_item = QTableWidgetItem(interface["ip_address"])
                ip_item.setFlags(ip_item.flags() & ~Qt.ItemIsEditable)
                self.interfaces_table.setItem(row_position, 1, ip_item)
                
                # Add state
                state_item = QTableWidgetItem(interface["state"])
                state_item.setFlags(state_item.flags() & ~Qt.ItemIsEditable)
                self.interfaces_table.setItem(row_position, 2, state_item)
                
                # Add action buttons
                action_widget = QWidget()
                action_layout = QHBoxLayout(action_widget)
                action_layout.setContentsMargins(0, 0, 0, 0)
                
                if interface["state"] == "UP":
                    action_btn = QPushButton("Disable")
                    action_btn.clicked.connect(lambda checked, name=interface["name"]: self.disable_interface(name))
                else:
                    action_btn = QPushButton("Enable")
                    action_btn.clicked.connect(lambda checked, name=interface["name"]: self.enable_interface(name))
                
                action_layout.addWidget(action_btn)
                self.interfaces_table.setCellWidget(row_position, 3, action_widget)
                
                # Add to combo box
                self.interface_combo.addItem(interface["name"])
                
            self._display_output("Network interfaces refreshed.")
            
        except Exception as e:
            self._display_output(f"Error refreshing interfaces: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to refresh interfaces: {str(e)}")
    
    def enable_interface(self, interface_name: str):
        """Enable the selected network interface"""
        try:
            self._display_output(f"$ sudo ip link set {interface_name} up")
            
            success, message = self.backend.enable_interface(interface_name=interface_name)
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", f"Interface {interface_name} enabled successfully")
                self.refresh_interfaces()
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to enable interface: {str(e)}")
    
    def disable_interface(self, interface_name: str):
        """Disable the selected network interface"""
        try:
            self._display_output(f"$ sudo ip link set {interface_name} down")
            
            success, message = self.backend.disable_interface(interface_name=interface_name)
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", f"Interface {interface_name} disabled successfully")
                self.refresh_interfaces()
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to disable interface: {str(e)}")
    
    def apply_ip_config(self):
        """Apply IP configuration to the selected interface"""
        interface_name = self.interface_combo.currentText()
        ip_address = self.ip_address_input.text().strip()
        netmask = self.netmask_input.text().strip()
        
        if not interface_name:
            QMessageBox.critical(self, "Error", "Please select an interface")
            return
            
        if not ip_address:
            QMessageBox.critical(self, "Error", "Please enter an IP address")
            return
            
        if not netmask:
            QMessageBox.critical(self, "Error", "Please enter a netmask")
            return
            
        try:
            self._display_output(f"$ sudo ip addr add {ip_address}/{netmask} dev {interface_name}")
            
            success, message = self.backend.set_interface_ip_address(
                interface_name=interface_name,
                ip_address=ip_address,
                netmask=netmask
            )
            
            self._display_output(message)
            
            if success:
                QMessageBox.information(self, "Success", f"IP address {ip_address}/{netmask} set for {interface_name}")
                self.refresh_interfaces()
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to set IP address: {str(e)}")
    
    def check_connectivity(self):
        """Check network connectivity to the specified host"""
        host = self.host_input.text().strip()
        count = self.packet_count_input.text().strip()
        
        if not host:
            QMessageBox.critical(self, "Error", "Please enter a host")
            return
            
        try:
            count_int = int(count)
        except ValueError:
            QMessageBox.critical(self, "Error", "Packet count must be a number")
            return
            
        try:
            self._display_output(f"$ ping -c {count} {host}")
            
            success, message = self.backend.check_network_connectivity(
                host=host,
                count=count_int
            )
            
            self._display_output(message)
            
            if success:
                self._display_output("\nConnectivity check successful!")
                
        except Exception as e:
            self._display_output(f"Error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to check connectivity: {str(e)}")
    
    def _display_output(self, text):
        """Display text in the output console with appropriate formatting"""
        self.output_console.append(text)
        self.output_console.ensureCursorVisible()
        
    def apply_theme(self):
        """Apply current theme to the widget"""
        self.theme_manager.apply_widget_styles(self) 