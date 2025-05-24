from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
import psutil
import netifaces
import time
import socket
import subprocess

class NetworkMonitorWidget(QWidget):
    """Widget for monitoring and configuring network interfaces"""
    
    def __init__(self, parent=None, is_senior=False, remote=None):
        super().__init__(parent)
        self.is_senior = is_senior  # Controls access to advanced features
        self.remote = remote  # Reference to remote connection handler if monitoring remote system
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the network monitor UI"""
        layout = QVBoxLayout(self)
        
        # Network interface selection section
        selector_group = QGroupBox("Network Interface")
        selector_layout = QHBoxLayout(selector_group)
        
        if self.remote:
            # Get interfaces from remote system
            try:
                stdout, _ = self.remote.execute_command("ls /sys/class/net")
                interfaces = stdout.strip().split()
            except Exception as e:
                print(f"Error getting interfaces: {str(e)}")
                interfaces = ["eth0"]
        else:
            interfaces = self.get_interfaces()
            
        self.interface_selector = QComboBox()
        self.interface_selector.addItems(interfaces)
        self.interface_selector.currentTextChanged.connect(self.update_interface_info)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        
        selector_layout.addWidget(QLabel("Interface:"))
        selector_layout.addWidget(self.interface_selector)
        selector_layout.addWidget(refresh_btn)
        selector_layout.addStretch()
        
        layout.addWidget(selector_group)
        
        # Interface information display section
        info_group = QGroupBox("Interface Information")
        info_layout = QVBoxLayout(info_group)
        
        self.info_table = QTableWidget()
        self.info_table.setColumnCount(2)
        self.info_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.info_table.horizontalHeader().setStretchLastSection(True)
        
        info_layout.addWidget(self.info_table)
        layout.addWidget(info_group)
        
        # Only show advanced configuration options for senior users
        if self.is_senior:
            config_group = QGroupBox("Interface Configuration")
            config_layout = QHBoxLayout(config_group)
            
            ip_btn = QPushButton("Configure IP")
            ip_btn.clicked.connect(self.configure_ip)
            
            dns_btn = QPushButton("Configure DNS")
            dns_btn.clicked.connect(self.configure_dns)
            
            firewall_btn = QPushButton("Configure Firewall")
            firewall_btn.clicked.connect(self.configure_firewall)
            
            config_layout.addWidget(ip_btn)
            config_layout.addWidget(dns_btn)
            config_layout.addWidget(firewall_btn)
            config_layout.addStretch()
            
            layout.addWidget(config_group)
            
            # Network diagnostic tools section
            tools_group = QGroupBox("Network Tools")
            tools_layout = QHBoxLayout(tools_group)
            
            ping_btn = QPushButton("Ping Test")
            ping_btn.clicked.connect(self.run_ping_test)
            
            trace_btn = QPushButton("Traceroute")
            trace_btn.clicked.connect(self.run_traceroute)
            
            scan_btn = QPushButton("Port Scan")
            scan_btn.clicked.connect(self.run_port_scan)
            
            tools_layout.addWidget(ping_btn)
            tools_layout.addWidget(trace_btn)
            tools_layout.addWidget(scan_btn)
            tools_layout.addStretch()
            
            layout.addWidget(tools_group)
        
        # Network traffic monitoring section
        traffic_group = QGroupBox("Network Traffic")
        traffic_layout = QVBoxLayout(traffic_group)
        
        self.traffic_text = QTextEdit()
        self.traffic_text.setReadOnly(True)
        
        traffic_layout.addWidget(self.traffic_text)
        layout.addWidget(traffic_group)
        
        self.update_interface_info()
        
        # Setup timer for periodic updates of interface information
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.update_interface_info)
        self.refresh_timer.start(1000)  # Update every second
        
    def get_interfaces(self):
        """Get list of network interfaces"""
        return netifaces.interfaces()
        
    def refresh_interfaces(self):
        """Refresh the interface list"""
        current = self.interface_selector.currentText()
        self.interface_selector.clear()
        
        if self.remote:
            try:
                stdout, _ = self.remote.execute_command("ls /sys/class/net")
                interfaces = stdout.strip().split()
            except Exception as e:
                print(f"Error getting interfaces: {str(e)}")
                interfaces = ["eth0"]
        else:
            interfaces = self.get_interfaces()
            
        self.interface_selector.addItems(interfaces)
        
        # Preserve selected interface if still available
        index = self.interface_selector.findText(current)
        if index >= 0:
            self.interface_selector.setCurrentIndex(index)
            
    def update_interface_info(self):
        """Update the interface information display"""
        interface = self.interface_selector.currentText()
        if not interface:
            return
            
        self.info_table.setRowCount(0)
        
        try:
            if self.remote:
                self._update_remote_interface_info(interface)
            else:
                # Get address information using netifaces
                addrs = netifaces.ifaddresses(interface)
                
                # Display IPv4 information if available
                if netifaces.AF_INET in addrs:
                    ipv4 = addrs[netifaces.AF_INET][0]
                    self.add_info_row("IPv4 Address", ipv4.get("addr", "N/A"))
                    self.add_info_row("IPv4 Netmask", ipv4.get("netmask", "N/A"))
                    
                # Display IPv6 information if available
                if netifaces.AF_INET6 in addrs:
                    ipv6 = addrs[netifaces.AF_INET6][0]
                    self.add_info_row("IPv6 Address", ipv6.get("addr", "N/A"))
                    
                # Display MAC address if available
                if netifaces.AF_LINK in addrs:
                    link = addrs[netifaces.AF_LINK][0]
                    self.add_info_row("MAC Address", link.get("addr", "N/A"))
                    
                # Get and display network statistics
                if stats := psutil.net_io_counters(pernic=True).get(interface):
                    self.add_info_row("Bytes Sent", f"{stats.bytes_sent:,} bytes")
                    self.add_info_row("Bytes Received", f"{stats.bytes_recv:,} bytes")
                    self.add_info_row("Packets Sent", f"{stats.packets_sent:,}")
                    self.add_info_row("Packets Received", f"{stats.packets_recv:,}")
                    
                    # Append traffic information to the traffic log
                    self.traffic_text.append(
                        f"[{interface}] "
                        f"↑ {stats.bytes_sent:,} bytes "
                        f"↓ {stats.bytes_recv:,} bytes"
                    )
                    
        except Exception as e:
            self.add_info_row("Error", str(e))
            
    def add_info_row(self, property_name: str, value: str):
        """Add a row to the info table"""
        row = self.info_table.rowCount()
        self.info_table.insertRow(row)
        self.info_table.setItem(row, 0, QTableWidgetItem(property_name))
        self.info_table.setItem(row, 1, QTableWidgetItem(value))
        
    def _update_remote_interface_info(self, interface: str):
        """Fetches and displays interface information for a remote host."""
        # Get IP addresses using ip command
        stdout, _ = self.remote.execute_command(f"ip addr show {interface}")
        if stdout:
            for line in stdout.split("\n"):
                if "inet " in line:
                    ip = line.strip().split()[1]
                    self.add_info_row("IPv4 Address", ip)
                elif "inet6" in line:
                    ip = line.strip().split()[1]
                    self.add_info_row("IPv6 Address", ip)
                    
        # Get MAC address from sysfs
        stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/address")
        if stdout:
            self.add_info_row("MAC Address", stdout.strip())
            
        # Get interface state (UP/DOWN)
        stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/operstate")
        if stdout:
            self.add_info_row("Status", stdout.strip().upper())
            
        # Get traffic statistics from sysfs
        stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/statistics/tx_bytes")
        tx_bytes = int(stdout.strip() or "0")
        stdout, _ = self.remote.execute_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes")
        rx_bytes = int(stdout.strip() or "0")
        
        self.add_info_row("Bytes Sent", f"{tx_bytes:,} bytes")
        self.add_info_row("Bytes Received", f"{rx_bytes:,} bytes")
        
        # Log traffic data
        self.traffic_text.append(
            f"[{interface}] "
            f"↑ {tx_bytes:,} bytes "
            f"↓ {rx_bytes:,} bytes"
        )

    def configure_ip(self):
        """Open IP configuration dialog"""
        if not self.is_senior:
            return
        
    def configure_dns(self):
        """Open DNS configuration dialog"""
        if not self.is_senior:
            return
        
    def configure_firewall(self):
        """Open firewall configuration dialog"""
        if not self.is_senior:
            return
        
    def run_ping_test(self):
        """Run ping test"""
        if not self.is_senior:
            return
        
    def run_traceroute(self):
        """Run traceroute"""
        if not self.is_senior:
            return
        
    def run_port_scan(self):
        """Run port scan"""
        if not self.is_senior:
            return
        
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()
            self.refresh_timer.timeout.disconnect(self.update_interface_info)
            
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event) 