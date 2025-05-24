from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox, QFrame, QGridLayout, QSizePolicy)
from PySide6.QtCore import Qt, Signal, QTimer, QThread
from PySide6.QtGui import QFont, QIcon
from pathlib import Path
import sys
import traceback

from src.ui.views.base_dashboard import BaseDashboard
from src.ui.widgets.system_monitor import SystemMonitorWidget
from src.ui.widgets.user_manager import UserManagerWidget
from src.ui.widgets.log_viewer import LogViewerWidget
from src.ui.widgets.network_monitor import NetworkMonitorWidget
from src.ui.widgets.network_manager import NetworkManagerWidget
from src.ui.widgets.firewall_config import FirewallConfigWidget
from src.ui.widgets.permissions_manager import PermissionsManagerWidget
from src.ui.widgets.update_manager import UpdateManagerWidget
from src.ui.widgets.backup_manager import BackupManagerWidget
from src.ui.widgets.report_viewer import ReportViewerWidget
from src.utils.remote_connection import RemoteConnection
from src.backend.senior_dashboard_backend import SeniorDashboardBackend
from src.ui.utils.worker import Worker
from src.ui.widgets.acl_manager import ACLManagerWidget
from src.ui.widgets.service_manager import ServiceManagerWidget

class SeniorDashboard(BaseDashboard):
    """Dashboard for Senior System Administrators with advanced privileges"""
    
    def __init__(self, remote: RemoteConnection, username: str):
        # Initialize the base dashboard with senior role and actual username
        super().__init__(username=username, role="senior")
        # Store the remote connection and app username
        self.remote = remote
        self.app_username = username # Store the application username
        # Create the backend for senior operations, passing the app username
        self.backend = SeniorDashboardBackend(remote, current_user=username)
        # Keep track of threads for system info updates
        self._active_sysinfo_thread = None
        self._active_sysinfo_worker = None
        # Set up the senior-specific UI components
        self.setup_senior_ui()
        
        # Set the window title with connection info
        self.setWindowTitle(f"Senior Dashboard - Connected to {remote.hostname}")
        
    def setup_senior_ui(self):
        """Set up the senior-specific UI components with full administrative capabilities"""
        # Add navigation buttons to the sidebar - seniors get all options
        self.add_nav_button("monitor", "System Monitor")
        self.add_nav_button("users", "User Management")
        self.add_nav_button("permissions", "File Permissions")
        self.add_nav_button("acl", "ACL Management")
        self.add_nav_button("service", "Network & Services")
        self.add_nav_button("updates", "System Updates")
        self.add_nav_button("backups", "Backup Manager")
        self.add_nav_button("reports", "Junior Reports")
        self.add_nav_button("logs", "Application Logs")
        
        # Create all the different content pages
        self.setup_system_monitor()
        self.setup_user_management()
        self.setup_network_management()
        self.setup_log_management()
        self.setup_report_management()
        self.setup_permissions_management()
        self.setup_update_management()
        self.setup_backup_management()
        self.setup_acl_management()
        self.setup_service_management()
        
        # Start with the system monitor page
        self.change_page("monitor")
        self.nav_buttons["monitor"].setChecked(True)
        
        # Set up a timer to update system info every 5 seconds
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_system_info)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def setup_system_monitor(self):
        """Set up the system monitoring page with advanced metrics"""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)
        
        # The advanced flag gives seniors more detailed system information
        self.system_monitor = SystemMonitorWidget(advanced=True, remote=self.remote)
        layout.addWidget(self.system_monitor)
        
        self.add_content_widget("monitor", monitor_widget)
        
        # Initial update of system info
        self.update_system_info()
        
    def update_system_info(self):
        """Update system information display asynchronously using Worker"""
        # If a worker/thread is already running, ideally we'd cancel it first
        # For now, this will create a new one. deleteLater handles old ones.
        
        # Create a new thread for the background work
        thread = QThread()
        # Create a worker to run the backend method
        worker = Worker(self.backend.get_system_info) # Assuming Worker is imported

        # Store references to active thread/worker
        self._active_sysinfo_thread = thread
        self._active_sysinfo_worker = worker

        # Move the worker to the thread
        worker.moveToThread(thread)
        # Connect signals and slots
        thread.started.connect(worker.run)
        worker.finished.connect(self.on_system_info_ready)
        worker.error.connect(self.on_system_info_error)
        
        # Clean up when finished
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._clear_active_sysinfo_references)
        
        # Start the thread
        thread.start()

    def _clear_active_sysinfo_references(self):
        # Called when the QThread emits its 'finished' signal (after it has quit)
        # Nullify references to prevent using QThread/QObject after C++ part might be deleted
        self._active_sysinfo_thread = None
        self._active_sysinfo_worker = None

    def on_system_info_ready(self, info):
        """Handle system info data when worker thread completes"""
        if 'error' in info:
            self.on_system_info_error(Exception(info['error']))

        elif hasattr(self, 'system_monitor') and self.system_monitor:
            # Update the UI with the system information
            self.system_monitor.update_static_system_info(
                hostname=info.get('hostname', 'N/A'),
                os_info=info.get('os', 'N/A'),
                kernel_info=info.get('kernel', 'N/A'),
                uptime_info=info.get('uptime', 'N/A')
            )
            # Now that static info is updated and connection seems fine, start real-time monitoring
            self.system_monitor.start_monitoring()

    def on_system_info_error(self, error_obj: Exception):
        """Handle errors from the system info worker thread"""
        # error_obj is the exception instance from the Worker
        error_type = type(error_obj).__name__
        error_msg = str(error_obj)
        log_msg = f"Failed to get system info. Type: {error_type}, Msg: '{error_msg}'"
        
        if hasattr(self, 'logger') and self.logger:
            self.logger.error("on_system_info_error: " + log_msg, exc_info=error_obj)
        else: 
            print(f"ERROR in SeniorDashboard.on_system_info_error: {log_msg}", file=sys.stderr)
            traceback.print_exc()

        # Stop the main update timer for system info in the dashboard
        if hasattr(self, 'update_timer') and self.update_timer.isActive():
            self.update_timer.stop()
            if hasattr(self, 'logger') and self.logger: self.logger.info("SeniorDashboard: Stopped system_info_timer due to error.")

        # If the system_monitor widget exists, inform it or handle its state
        if hasattr(self, 'system_monitor') and self.system_monitor:
            self.system_monitor.stop_monitoring()
            # Option 3: Force an update which will hit its internal disconnect check
            # Calling update_stats() immediately after stop_monitoring() might be counter-intuitive
            # The stop_monitoring() call should already handle UI updates to 'disconnected'.
            # self.system_monitor.update_stats()

        from PySide6.QtWidgets import QMessageBox
        QMessageBox.warning(self, "Connection Error", f"Failed to get system info: {error_msg}. Monitoring may be paused. Please check connection or try reconnecting.")
        
    def setup_user_management(self):
        """Set up the user management page with full administrative capabilities"""
        user_widget = QWidget()
        layout = QVBoxLayout(user_widget)
        
        # Senior admins get full user management capabilities
        self.user_manager = UserManagerWidget(is_senior=True, remote=self.remote)
        layout.addWidget(self.user_manager)
        
        self.add_content_widget("users", user_widget)
        
    def setup_network_management(self):
        """Set up the network management page with configuration capabilities"""
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        # Senior admins get full network configuration capabilities
        self.network_manager = NetworkManagerWidget(remote=self.remote, is_senior=True)
        layout.addWidget(self.network_manager)
        
        self.add_content_widget("network", network_widget)
        
    def setup_log_management(self):
        """Set up the log management page with advanced filtering"""
        log_widget = QWidget()
        layout = QVBoxLayout(log_widget)
        
        # Senior admins get advanced log viewing capabilities
        self.log_viewer = LogViewerWidget(advanced=True)
        layout.addWidget(self.log_viewer)
        
        self.add_content_widget("logs", log_widget)
        
    def setup_report_management(self):
        """Set up the page to view reports from junior admins"""
        reports_widget = QWidget()
        layout = QVBoxLayout(reports_widget)
        
        # This widget shows tasks reported by junior admins
        self.report_viewer = ReportViewerWidget(backend=self.backend)
        layout.addWidget(self.report_viewer)
        
        self.add_content_widget("reports", reports_widget)
        
    def setup_permissions_management(self):
        """Set up the file permissions management page"""
        perm_widget = QWidget()
        layout = QVBoxLayout(perm_widget)
        
        # Senior admins get full permissions management
        self.perm_manager = PermissionsManagerWidget(remote=self.remote, is_senior=True)
        layout.addWidget(self.perm_manager)
        
        self.add_content_widget("permissions", perm_widget)
        
    def setup_update_management(self):
        """Set up the system updates management page"""
        update_widget = QWidget()
        layout = QVBoxLayout(update_widget)
        
        # Senior admins can check and apply system updates
        self.update_manager = UpdateManagerWidget(remote=self.remote)
        layout.addWidget(self.update_manager)
        
        self.add_content_widget("updates", update_widget)
        
    def setup_backup_management(self):
        """Set up the backup management page for system backups"""
        backup_widget = QWidget()
        layout = QVBoxLayout(backup_widget)
        
        # Senior admins can create and restore system backups
        self.backup_manager = BackupManagerWidget(remote=self.remote)
        layout.addWidget(self.backup_manager)
        
        self.add_content_widget("backups", backup_widget)
        
    def setup_acl_management(self):
        """Set up the ACL management page for advanced permissions"""
        acl_widget = QWidget()
        layout = QVBoxLayout(acl_widget)
        
        # Senior admins get full ACL management capabilities
        self.acl_manager = ACLManagerWidget(remote=self.remote, is_senior=True)
        layout.addWidget(self.acl_manager)
        
        self.add_content_widget("acl", acl_widget)
        
    def setup_service_management(self):
        """Set up the service management page for system services"""
        service_widget = QWidget()
        layout = QVBoxLayout(service_widget)
        
        # Senior admins can manage system services
        self.service_manager = ServiceManagerWidget(remote=self.remote)
        layout.addWidget(self.service_manager)
        
        self.add_content_widget("service", service_widget)
        
    def apply_styles(self):
        """Apply custom styles to the dashboard"""
        super().apply_styles()
        
        theme = self._get_current_theme()
        current_stylesheet = self.styleSheet()
        new_stylesheet_parts = [current_stylesheet, f"""
            QTableWidget {{
                border: 1px solid {theme['border_color']};
                background-color: {theme['bg_secondary']};
                gridline-color: {theme['border_color']};
                border-radius: {theme['radius_sm']};
                color: {theme['text_primary']};
                font-size: 12px;
            }}
            
            QTableWidget::item {{
                padding: 4px;
                border-bottom: 1px solid {theme['border_color']};
            }}
            
            QHeaderView::section {{
                padding: 6px;
                font-size: 13px;
                font-weight: bold;
                background-color: {theme['table_header_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['table_border']};
            }}
            
            QGroupBox {{
                margin-top: 16px;
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                padding: 15px;
                font-weight: bold;
            }}
            
            QGroupBox::title {{
                color: {theme['accent_primary']};
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }}
            
            QLineEdit, QComboBox, QSpinBox {{
                padding: 6px;
                min-height: 22px;
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
            }}
            
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
                border: 1px solid {theme['accent_primary']};
            }}
            
            QTextEdit {{
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                padding: 5px;
            }}
            
            QTextEdit:focus {{
                border: 1px solid {theme['accent_primary']};
            }}
            
            QPushButton {{
                min-height: 24px;
                padding: 5px 12px;
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: {theme['radius_sm']};
                font-size: 13px;
            }}
            
            QPushButton:hover {{
                background-color: {theme['accent_secondary']};
            }}
            
            QPushButton:pressed {{
                background-color: {theme['accent_tertiary']};
            }}
            
            QPushButton[flat="true"] {{
                background-color: transparent;
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
            }}
            
            QPushButton[flat="true"]:hover {{
                background-color: {theme['hover_bg']};
                border-color: {theme['accent_primary']};
                color: {theme['accent_primary']};
            }}
            
            QLabel {{
                font-size: 13px;
                color: {theme['text_primary']};
            }}
            
            QLabel[heading="true"] {{
                font-size: 16px;
                font-weight: bold;
                color: {theme['text_primary']};
                margin-bottom: 8px;
            }}
            
            QFrame {{
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
            }}
        """]
        self.setStyleSheet("\n".join(filter(None, new_stylesheet_parts)))
        
        for obj in self.findChildren(QLabel):
            if obj.styleSheet() and "color: #0078d4" in obj.styleSheet():
                obj.setStyleSheet(f"""
                    font-size: 15px; 
                    font-weight: bold; 
                    color: {theme['accent_primary']}; 
                    padding-bottom: 5px;
                """)
            elif obj.styleSheet() and "color: #E74C3C" in obj.styleSheet():
                obj.setStyleSheet(f"""
                    font-size: 13px;
                    font-weight: normal; 
                    color: {theme['error_color']};
                    background-color: {theme['bg_secondary']};
                    border: 1px solid {theme['error_color']};
                    border-radius: {theme['radius_sm']};
                    padding: 8px;
                    margin-bottom: 10px;
                """)
        
        if hasattr(self, 'history_table'):
            header = self.history_table.horizontalHeader()
            header.setSectionResizeMode(0, header.ResizeToContents)
            header.setSectionResizeMode(1, header.ResizeToContents)
            header.setSectionResizeMode(2, header.Stretch)
        
    def closeEvent(self, event):
        """Handle the close event for the dashboard."""
        if hasattr(self, 'logger') and self.logger:
            self.logger.info("SeniorDashboard: Closing dashboard.")

        # Stop any running timers or threads
        if hasattr(self, 'update_timer') and self.update_timer:
            self.update_timer.stop()
        
        if hasattr(self, '_active_sysinfo_thread') and self._active_sysinfo_thread and self._active_sysinfo_thread.isRunning():
            self._active_sysinfo_thread.quit()
            self._active_sysinfo_thread.wait() # Wait for thread to finish

        # Stop system monitor updates
        if hasattr(self, 'system_monitor') and self.system_monitor:
            self.system_monitor.stop_monitoring()
            # Call cleanup on system_monitor if it exists
            if hasattr(self.system_monitor, 'cleanup'):
                 self.system_monitor.cleanup() # Ensure its own timer/resources are cleaned

        # Call cleanup on backend if it exists
        if hasattr(self, 'backend') and self.backend:
            if hasattr(self.backend, 'cleanup'):
                self.backend.cleanup()

        super().closeEvent(event) # Call base class closeEvent 