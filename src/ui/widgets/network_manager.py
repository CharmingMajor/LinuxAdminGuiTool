from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QTableWidget, QTableWidgetItem, QGroupBox, QLineEdit,
    QComboBox, QMessageBox, QDialog, QFormLayout)
from PySide6.QtCore import Qt, Signal
import subprocess
import re
import netifaces
import structlog
from src.ui.utils.theme_manager import ThemeManager

logger = structlog.get_logger(__name__)

class NetworkManagerWidget(QWidget):
    """Widget for managing network interfaces and firewall rules"""
    
    def __init__(self, parent=None, remote=None):
        super().__init__(parent)
        self.remote = remote
        self.theme_manager = ThemeManager()
        self.theme_manager.theme_changed.connect(self.apply_theme)
        self.setup_ui()
        self.refresh_data()
        
    def setup_ui(self):
        """Set up the user interface"""
        layout = QVBoxLayout(self)
        
        # Apply theme styles
        self.theme_manager.apply_widget_styles(self)
        
        # Network Interfaces
        interface_group = QGroupBox("Network Interfaces")
        interface_layout = QVBoxLayout(interface_group)
        
        # Interface table
        self.interface_table = QTableWidget()
        self.interface_table.setColumnCount(5)
        self.interface_table.setHorizontalHeaderLabels([
            "Interface", "Status", "IP Address", "MAC Address", "Actions"
        ])
        interface_layout.addWidget(self.interface_table)
        
        # Interface controls
        interface_controls = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(netifaces.interfaces())
        interface_controls.addWidget(QLabel("Interface:"))
        interface_controls.addWidget(self.interface_combo)
        
        self.toggle_btn = QPushButton("Enable/Disable")
        self.toggle_btn.clicked.connect(self.toggle_interface)
        interface_controls.addWidget(self.toggle_btn)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_data)
        interface_controls.addWidget(self.refresh_btn)
        
        interface_layout.addLayout(interface_controls)
        layout.addWidget(interface_group)
        
        # Firewall Rules
        firewall_group = QGroupBox("Firewall Rules")
        firewall_layout = QVBoxLayout(firewall_group)
        
        # Rule table
        self.rule_table = QTableWidget()
        self.rule_table.setColumnCount(6)
        self.rule_table.setHorizontalHeaderLabels([
            "Chain", "Target", "Protocol", "Source", "Destination", "Actions"
        ])
        firewall_layout.addWidget(self.rule_table)
        
        # Add rule controls
        rule_controls = QHBoxLayout()
        
        self.add_rule_btn = QPushButton("Add Rule")
        self.add_rule_btn.clicked.connect(self.show_add_rule_dialog)
        rule_controls.addWidget(self.add_rule_btn)
        
        self.delete_rule_btn = QPushButton("Delete Rule")
        self.delete_rule_btn.clicked.connect(self.delete_rule)
        rule_controls.addWidget(self.delete_rule_btn)
        
        firewall_layout.addLayout(rule_controls)
        layout.addWidget(firewall_group)
        
    def refresh_data(self):
        """Refresh network interface and firewall data"""
        self.update_interface_table()
        self.update_firewall_rules()
        
    def update_interface_table(self):
        """Update the network interface table"""
        self.interface_table.setRowCount(0)
        
        for interface in netifaces.interfaces():
            try:
                # Get interface status
                status = "Up" if self.is_interface_up(interface) else "Down"
                
                # Get IP address
                addrs = netifaces.ifaddresses(interface)
                ip = addrs.get(netifaces.AF_INET, [{'addr': 'N/A'}])[0]['addr']
                
                # Get MAC address
                mac = addrs.get(netifaces.AF_LINK, [{'addr': 'N/A'}])[0]['addr']
                
                # Add to table
                row = self.interface_table.rowCount()
                self.interface_table.insertRow(row)
                
                self.interface_table.setItem(row, 0, QTableWidgetItem(interface))
                self.interface_table.setItem(row, 1, QTableWidgetItem(status))
                self.interface_table.setItem(row, 2, QTableWidgetItem(ip))
                self.interface_table.setItem(row, 3, QTableWidgetItem(mac))
                
                # Add action buttons
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(0, 0, 0, 0)
                
                toggle_btn = QPushButton("Toggle")
                toggle_btn.clicked.connect(lambda checked, i=interface: self.toggle_interface(i))
                actions_layout.addWidget(toggle_btn)
                
                self.interface_table.setCellWidget(row, 4, actions_widget)
                
            except Exception as e:
                logger.error(f"Error updating interface {interface}: {str(e)}")
                
    def update_firewall_rules(self):
        """Update the firewall rules table"""
        self.rule_table.setRowCount(0)
        
        try:
            # Get iptables rules
            output = subprocess.check_output(['iptables', '-L', '-n', '-v'], text=True)
            
            current_chain = None
            for line in output.splitlines():
                if line.startswith('Chain'):
                    current_chain = line.split()[1]
                elif line and not line.startswith('target') and not line.startswith('pkts'):
                    parts = line.split()
                    if len(parts) >= 8:
                        row = self.rule_table.rowCount()
                        self.rule_table.insertRow(row)
                        
                        self.rule_table.setItem(row, 0, QTableWidgetItem(current_chain))
                        self.rule_table.setItem(row, 1, QTableWidgetItem(parts[0]))
                        self.rule_table.setItem(row, 2, QTableWidgetItem(parts[3]))
                        self.rule_table.setItem(row, 3, QTableWidgetItem(parts[6]))
                        self.rule_table.setItem(row, 4, QTableWidgetItem(parts[7]))
                        
                        # Add delete button
                        delete_btn = QPushButton("Delete")
                        delete_btn.clicked.connect(lambda checked, r=row: self.delete_rule(r))
                        self.rule_table.setCellWidget(row, 5, delete_btn)
                        
        except Exception as e:
            logger.error(f"Error updating firewall rules: {str(e)}")
            
    def is_interface_up(self, interface):
        """Check if a network interface is up"""
        try:
            with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
                return f.read().strip() == 'up'
        except:
            return False
            
    def toggle_interface(self, interface=None):
        """Enable or disable a network interface"""
        if interface is None:
            interface = self.interface_combo.currentText()
            
        try:
            current_state = self.is_interface_up(interface)
            new_state = "down" if current_state else "up"
            
            subprocess.run(['ip', 'link', 'set', interface, new_state], check=True)
            self.refresh_data()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to toggle interface: {str(e)}")
            
    def show_add_rule_dialog(self):
        """Show dialog to add a new firewall rule"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Firewall Rule")
        layout = QFormLayout(dialog)
        
        # Form fields
        chain = QComboBox()
        chain.addItems(['INPUT', 'OUTPUT', 'FORWARD'])
        layout.addRow("Chain:", chain)
        
        target = QComboBox()
        target.addItems(['ACCEPT', 'DROP', 'REJECT'])
        layout.addRow("Target:", target)
        
        protocol = QComboBox()
        protocol.addItems(['tcp', 'udp', 'icmp', 'all'])
        layout.addRow("Protocol:", protocol)
        
        source = QLineEdit()
        source.setPlaceholderText("e.g., 192.168.1.0/24")
        layout.addRow("Source:", source)
        
        destination = QLineEdit()
        destination.setPlaceholderText("e.g., 192.168.1.1")
        layout.addRow("Destination:", destination)
        
        # Buttons
        buttons = QHBoxLayout()
        ok_btn = QPushButton("Add")
        ok_btn.clicked.connect(dialog.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        
        buttons.addWidget(ok_btn)
        buttons.addWidget(cancel_btn)
        layout.addRow(buttons)
        
        if dialog.exec():
            try:
                # Build iptables command
                cmd = ['iptables', '-A', chain.currentText()]
                
                if protocol.currentText() != 'all':
                    cmd.extend(['-p', protocol.currentText()])
                    
                if source.text():
                    cmd.extend(['-s', source.text()])
                    
                if destination.text():
                    cmd.extend(['-d', destination.text()])
                    
                cmd.extend(['-j', target.currentText()])
                
                # Execute command
                subprocess.run(cmd, check=True)
                self.refresh_data()
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add rule: {str(e)}")
                
    def delete_rule(self, row):
        """Delete a firewall rule"""
        try:
            chain = self.rule_table.item(row, 0).text()
            target = self.rule_table.item(row, 1).text()
            protocol = self.rule_table.item(row, 2).text()
            source = self.rule_table.item(row, 3).text()
            destination = self.rule_table.item(row, 4).text()
            
            # Build iptables command
            cmd = ['iptables', '-D', chain]
            
            if protocol != 'all':
                cmd.extend(['-p', protocol])
                
            if source != 'anywhere':
                cmd.extend(['-s', source])
                
            if destination != 'anywhere':
                cmd.extend(['-d', destination])
                
            cmd.extend(['-j', target])
            
            # Execute command
            subprocess.run(cmd, check=True)
            self.refresh_data()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete rule: {str(e)}")
            
    def apply_theme(self):
        """Apply current theme to the widget"""
        self.theme_manager.apply_widget_styles(self) 