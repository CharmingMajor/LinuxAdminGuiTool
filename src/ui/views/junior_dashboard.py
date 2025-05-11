from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox, QMessageBox)
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
from src.utils.remote_connection import RemoteConnection
from src.backend.junior_backend import JuniorBackend
import psutil
from datetime import datetime
import time

class JuniorDashboard(BaseDashboard):
    """Dashboard for Junior System Administrators with limited privileges"""
    
    def __init__(self, remote: RemoteConnection):
        super().__init__(username=remote.username, role="junior")
        self.remote = remote
        self.backend = JuniorBackend(remote)
        self.setup_junior_ui()
        
        # Add connection info to title
        self.setWindowTitle(f"Junior Dashboard - Connected to {remote.hostname}")
        
    def setup_junior_ui(self):
        """Set up the junior-specific UI components"""
        # Add navigation buttons
        self.add_nav_button("monitor", "System Monitor")
        self.add_nav_button("users", "User Management")
        self.add_nav_button("network", "Network Management")
        self.add_nav_button("logs", "System Logs")
        self.add_nav_button("remote", "Remote Management")
        self.add_nav_button("permissions", "Permissions")
        self.add_nav_button("updates", "System Updates")
        self.add_nav_button("backups", "Backup Manager")
        self.add_nav_button("tasks", "Task Reports")
        
        # Create and add content widgets
        self.setup_system_monitor()
        self.setup_user_management()
        self.setup_network_management()
        self.setup_log_viewer()
        self.setup_remote_management()
        self.setup_permissions_management() 
        self.setup_update_management()
        self.setup_backup_management()
        self.setup_task_reports()
        
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
        
        # System monitor with basic privileges
        self.system_monitor = SystemMonitorWidget(advanced=False, remote=self.remote)
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
        """Set up the user management page with limited privileges"""
        user_widget = QWidget()
        layout = QVBoxLayout(user_widget)
        
        # User manager with junior privileges (can't modify sudo users)
        self.user_manager = UserManagerWidget(is_senior=False, remote=self.remote)
        layout.addWidget(self.user_manager)
        
        self.add_content_widget("users", user_widget)
        
    def setup_network_management(self):
        """Set up the network management page"""
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        # Add junior permissions indicator
        info_label = QLabel("Junior admins have limited network management capabilities")
        info_label.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(info_label)
        
        # Network monitor (view-only, no configuration)
        self.network_monitor = NetworkMonitorWidget(remote=self.remote)
        layout.addWidget(self.network_monitor)
        
        # Network manager
        self.network_manager = NetworkManagerWidget(remote=self.remote)
        layout.addWidget(self.network_manager)
        
        self.add_content_widget("network", network_widget)
        
    def setup_log_viewer(self):
        """Set up the log viewer page"""
        log_widget = QWidget()
        layout = QVBoxLayout(log_widget)
        
        # Log viewer with basic access (can't view security logs)
        self.log_viewer = LogViewerWidget(remote=self.remote, include_security=False)
        layout.addWidget(self.log_viewer)
        
        self.add_content_widget("logs", log_widget)
    
    def setup_remote_management(self):
        """Set up the remote management page with read-only access"""
        remote_widget = QWidget()
        layout = QVBoxLayout(remote_widget)
        
        remote_info = QLabel("Junior admins have read-only access to remote systems")
        remote_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(remote_info)
        
        self.remote_manager = RemoteManagerWidget(remote=self.remote)
        layout.addWidget(self.remote_manager)
        
        self.add_content_widget("remote", remote_widget)
        
    def setup_permissions_management(self):
        """Set up the permissions management page with limited capabilities"""
        perm_widget = QWidget()
        layout = QVBoxLayout(perm_widget)
        
        perm_info = QLabel("Junior admins have limited permission management capabilities")
        perm_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(perm_info)
        
        self.perm_manager = PermissionsManagerWidget(remote=self.remote)
        layout.addWidget(self.perm_manager)
        
        self.add_content_widget("permissions", perm_widget)
        
    def setup_update_management(self):
        """Set up the update management page with limited control"""
        update_widget = QWidget()
        layout = QVBoxLayout(update_widget)
        
        update_info = QLabel("Junior admins can view updates but require approval to install them")
        update_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(update_info)
        
        self.update_manager = UpdateManagerWidget(remote=self.remote)
        layout.addWidget(self.update_manager)
        
        self.add_content_widget("updates", update_widget)
        
    def setup_backup_management(self):
        """Set up the backup management page with view-only access"""
        backup_widget = QWidget()
        layout = QVBoxLayout(backup_widget)
        
        backup_info = QLabel("Junior admins can view and restore backups but not create new ones")
        backup_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(backup_info)
        
        self.backup_manager = BackupManagerWidget(remote=self.remote)
        layout.addWidget(self.backup_manager)
        
        self.add_content_widget("backups", backup_widget)
        
    def setup_task_reports(self):
        """Set up the task reporting page"""
        task_widget = QWidget()
        layout = QVBoxLayout(task_widget)
        
        # Task submission form
        form_group = QGroupBox("Submit Task Report")
        form_layout = QVBoxLayout(form_group)
        
        # Task type selector
        task_layout = QHBoxLayout()
        task_layout.addWidget(QLabel("Task Type:"))
        
        self.task_combo = QComboBox()
        self.task_combo.addItems([
            "User Account Created",
            "User Account Modified",
            "Network Interface Configuration",
            "Service Configuration",
            "Software Installation",
            "System Update",
            "Other"
        ])
        
        task_layout.addWidget(self.task_combo)
        task_layout.addStretch()
        form_layout.addLayout(task_layout)
        
        # Task description
        description_layout = QVBoxLayout()
        description_layout.addWidget(QLabel("Description:"))
        
        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText("Enter task details...")
        self.description_input.setMaximumHeight(100)
        
        description_layout.addWidget(self.description_input)
        form_layout.addLayout(description_layout)
        
        # Submit button
        submit_btn = QPushButton("Submit Report")
        submit_btn.clicked.connect(self.submit_task_report)
        
        form_layout.addWidget(submit_btn)
        layout.addWidget(form_group)
        
        # Task history
        history_group = QGroupBox("Task History")
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["Date/Time", "Task Type", "Description"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        
        history_layout.addWidget(self.history_table)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh History")
        refresh_btn.clicked.connect(self.refresh_task_history)
        history_layout.addWidget(refresh_btn)
        
        layout.addWidget(history_group)
        
        self.add_content_widget("tasks", task_widget)
        
        # Load initial task history
        self.refresh_task_history()
        
    def refresh_task_history(self):
        """Refresh the task history from the database"""
        task_history = self.backend.get_task_history()
        
        # Clear the table
        self.history_table.setRowCount(0)
        
        # Add new rows
        for task in task_history:
            self.add_history_entry(task['timestamp'], task['type'], task['description'])
        
    def submit_task_report(self):
        """Submit a task report to the senior admin"""
        task_type = self.task_combo.currentText()
        description = self.description_input.toPlainText()
        
        if not description:
            self.show_error_message("Please enter a description for the task.")
            return
        
        if description.strip() == "":
            self.show_error_message("Description cannot be empty.")
            return
            
        # Submit the report using our backend
        success = self.backend.submit_task_report(task_type, description)
        
        if success:
            self.show_success_message("Task report submitted successfully!")
            self.description_input.clear()  # Clear the form
            
            # Add entry to history table
            now = self.backend.get_current_time()
            self.add_history_entry(now, task_type, description)
        else:
            self.show_error_message("Failed to submit task report. Please try again.")
            
    def add_history_entry(self, timestamp, task_type, description):
        """Add a new entry to the task history table"""
        current_row = self.history_table.rowCount()
        self.history_table.insertRow(current_row)
        
        self.history_table.setItem(current_row, 0, QTableWidgetItem(timestamp))
        self.history_table.setItem(current_row, 1, QTableWidgetItem(task_type))
        self.history_table.setItem(current_row, 2, QTableWidgetItem(description))
        
    def show_error_message(self, message: str):
        """Show error message dialog"""
        self.show_message("Error", message, QMessageBox.Icon.Warning)
        
    def show_success_message(self, message: str):
        """Show success message dialog"""
        self.show_message("Success", message, QMessageBox.Icon.Information)
        
    def show_message(self, title: str, message: str, icon: QMessageBox.Icon):
        """Show message dialog"""
        msg = QMessageBox()
        msg.setIcon(icon)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec()
        
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