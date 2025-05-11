from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QIcon
from pathlib import Path

from src.ui.views.base_dashboard import BaseDashboard
from src.ui.widgets.system_monitor import SystemMonitorWidget
from src.ui.widgets.user_manager import UserManagerWidget
from src.ui.widgets.log_viewer import LogViewerWidget
from src.ui.widgets.network_monitor import NetworkMonitorWidget
from src.ui.widgets.network_manager import NetworkManagerWidget
from src.ui.widgets.firewall_config import FirewallConfigWidget
from src.ui.widgets.remote_manager import RemoteManagerWidget
from src.ui.widgets.permissions_manager import PermissionsManagerWidget
from src.ui.widgets.update_manager import UpdateManagerWidget
from src.ui.widgets.backup_manager import BackupManagerWidget
from src.ui.widgets.report_viewer import ReportViewerWidget
from src.utils.remote_connection import RemoteConnection
from src.backend.senior_dashboard_backend import SeniorDashboardBackend

class SeniorDashboard(BaseDashboard):
    """Dashboard for Senior System Administrators with advanced privileges"""
    
    def __init__(self, remote: RemoteConnection):
        super().__init__(username=remote.username, role="senior")
        self.remote = remote
        self.backend = SeniorDashboardBackend(remote)
        self.setup_senior_ui()
        
        # Add connection info to title
        self.setWindowTitle(f"Senior Dashboard - Connected to {remote.hostname}")
        
    def setup_senior_ui(self):
        """Set up the senior-specific UI components"""
        # Add navigation buttons
        self.add_nav_button("monitor", "System Monitor")
        self.add_nav_button("users", "User Management")
        self.add_nav_button("network", "Network Management")
        self.add_nav_button("logs", "System Logs")
        self.add_nav_button("reports", "Junior Reports")
        self.add_nav_button("remote", "Remote Management")
        self.add_nav_button("permissions", "Permissions")
        self.add_nav_button("updates", "System Updates")
        self.add_nav_button("backups", "Backup Manager")
        
        # Create and add content widgets
        self.setup_system_monitor()
        self.setup_user_management()
        self.setup_network_management()
        self.setup_log_management()
        self.setup_report_management()
        self.setup_remote_management()
        self.setup_permissions_management()
        self.setup_update_management()
        self.setup_backup_management()
        
        # Set default view
        self.content_stack.setCurrentIndex(0)
        self.nav_buttons["monitor"].setChecked(True)
        
        # Start system info update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_system_info)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def setup_system_monitor(self):
        """Set up the system monitoring page"""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)
        
        # System info group
        info_group = QGroupBox("System Information")
        info_layout = QVBoxLayout(info_group)
        
        self.hostname_label = QLabel()
        self.os_label = QLabel()
        self.kernel_label = QLabel()
        self.uptime_label = QLabel()
        
        info_layout.addWidget(self.hostname_label)
        info_layout.addWidget(self.os_label)
        info_layout.addWidget(self.kernel_label)
        info_layout.addWidget(self.uptime_label)
        
        layout.addWidget(info_group)
        
        # System monitor widget
        self.system_monitor = SystemMonitorWidget(advanced=True, remote=self.remote)
        layout.addWidget(self.system_monitor)
        
        self.add_content_widget("monitor", monitor_widget)
        
        # Initial update
        self.update_system_info()
        
    def update_system_info(self):
        """Update system information display"""
        info = self.backend.get_system_info()
        if 'error' not in info:
            self.hostname_label.setText(f"Hostname: {info.get('hostname', 'N/A')}")
            self.os_label.setText(f"Operating System: {info.get('os', 'N/A')}")
            self.kernel_label.setText(f"Kernel Version: {info.get('kernel', 'N/A')}")
            self.uptime_label.setText(f"Uptime: {info.get('uptime', 'N/A')}")
        
    def setup_user_management(self):
        """Set up the user management page"""
        user_widget = QWidget()
        layout = QVBoxLayout(user_widget)
        
        self.user_manager = UserManagerWidget(is_senior=True, remote=self.remote)
        layout.addWidget(self.user_manager)
        
        self.add_content_widget("users", user_widget)
        
    def setup_network_management(self):
        """Set up the network management page"""
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        self.network_manager = NetworkManagerWidget(remote=self.remote)
        layout.addWidget(self.network_manager)
        
        self.add_content_widget("network", network_widget)
        
    def setup_log_management(self):
        """Set up the log management page"""
        log_widget = QWidget()
        layout = QVBoxLayout(log_widget)
        
        self.log_viewer = LogViewerWidget(advanced=True, remote=self.remote)
        layout.addWidget(self.log_viewer)
        
        self.add_content_widget("logs", log_widget)
        
    def setup_report_management(self):
        """Set up the junior reports page"""
        reports_widget = QWidget()
        layout = QVBoxLayout(reports_widget)
        
        self.report_viewer = ReportViewerWidget(backend=self.backend)
        layout.addWidget(self.report_viewer)
        
        self.add_content_widget("reports", reports_widget)
        
    def setup_remote_management(self):
        """Set up the remote management page"""
        remote_widget = QWidget()
        layout = QVBoxLayout(remote_widget)
        
        self.remote_manager = RemoteManagerWidget(remote=self.remote)
        layout.addWidget(self.remote_manager)
        
        self.add_content_widget("remote", remote_widget)
        
    def setup_permissions_management(self):
        """Set up the permissions management page"""
        perm_widget = QWidget()
        layout = QVBoxLayout(perm_widget)
        
        self.perm_manager = PermissionsManagerWidget(remote=self.remote)
        layout.addWidget(self.perm_manager)
        
        self.add_content_widget("permissions", perm_widget)
        
    def setup_update_management(self):
        """Set up the update management page"""
        update_widget = QWidget()
        layout = QVBoxLayout(update_widget)
        
        self.update_manager = UpdateManagerWidget(remote=self.remote)
        layout.addWidget(self.update_manager)
        
        self.add_content_widget("updates", update_widget)
        
    def setup_backup_management(self):
        """Set up the backup management page"""
        backup_widget = QWidget()
        layout = QVBoxLayout(backup_widget)
        
        self.backup_manager = BackupManagerWidget(remote=self.remote)
        layout.addWidget(self.backup_manager)
        
        self.add_content_widget("backups", backup_widget)
        
    def apply_styles(self):
        """Apply custom styles to the dashboard"""
        # Call the parent's apply_styles method to use the theme system
        super().apply_styles()
        
    def closeEvent(self, event):
        """Handle dashboard close event"""
        # Stop update timer
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()
        
        # Clean up system monitor
        if hasattr(self, 'system_monitor'):
            self.system_monitor.cleanup()
        
        # Clean up backend
        if hasattr(self, 'backend'):
            self.backend.cleanup()
            
        super().closeEvent(event) 