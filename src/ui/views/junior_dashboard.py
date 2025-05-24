from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem, QProgressBar,
    QTextEdit, QGroupBox, QMessageBox, QFrame, QGridLayout, QSizePolicy)
from PySide6.QtCore import Qt, Signal, QTimer, QThread
from PySide6.QtGui import QFont, QIcon
from pathlib import Path
from src.ui.views.base_dashboard import BaseDashboard
from src.ui.widgets.system_monitor import SystemMonitorWidget
from src.ui.widgets.user_manager import UserManagerWidget
from src.ui.widgets.network_monitor import NetworkMonitorWidget
from src.ui.widgets.network_manager import NetworkManagerWidget
from src.ui.widgets.firewall_config import FirewallConfigWidget
from src.ui.widgets.permissions_manager import PermissionsManagerWidget
from src.ui.widgets.update_manager import UpdateManagerWidget
from src.ui.widgets.backup_manager import BackupManagerWidget
from src.ui.widgets.acl_manager import ACLManagerWidget
from src.utils.remote_connection import RemoteConnection
from src.backend.junior_backend import JuniorBackend
import psutil
from datetime import datetime
import time
from src.ui.utils.worker import Worker

class JuniorDashboard(BaseDashboard):
    """Dashboard for Junior System Administrators with limited privileges"""
    # Signal for when the dashboard is closing
    closing = Signal() 
    
    def __init__(self, remote: RemoteConnection, username: str):
        super().__init__(username=username, role="junior")
        # Store the remote connection object
        self.remote = remote
        self.app_username = username
        # Initialize the backend for junior admin operations
        self.backend = JuniorBackend(remote, current_user=username)
        self.setup_junior_ui()
        
        self.setWindowTitle(f"Junior Dashboard - Connected to {remote.hostname}")
        
    def setup_junior_ui(self):
        """Set up the junior-specific UI components"""
        # Add navigation buttons for different sections of the dashboard
        self.add_nav_button("monitor", "System Monitor")
        self.add_nav_button("users", "User Management")
        self.add_nav_button("network", "Network Management")
        # self.add_nav_button("logs", "System Logs") # Removed
        self.add_nav_button("permissions", "Permissions")
        self.add_nav_button("updates", "System Updates")
        self.add_nav_button("backups", "Backup Manager")
        self.add_nav_button("tasks", "Task Reports")
        self.add_nav_button("acl", "ACL Management")
        
        # Initialize the UI for each section
        self.setup_system_monitor()
        self.setup_user_management()
        self.setup_network_management()
        # self.setup_log_viewer() # Removed
        self.setup_permissions_management() 
        self.setup_update_management()
        self.setup_backup_management()
        self.setup_task_reports()
        self.setup_acl_management()
        
        # Set the initial page to be displayed
        self.change_page("monitor")
        self.nav_buttons["monitor"].setChecked(True)
        
        # Create a timer to periodically update system information
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_system_info)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def setup_system_monitor(self):
        """Set up the system monitoring page"""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)
        
        # Initialize the system monitor widget (basic version for junior admins)
        self.system_monitor = SystemMonitorWidget(advanced=False, remote=self.remote)
        layout.addWidget(self.system_monitor)
        
        self.add_content_widget("monitor", monitor_widget)
        
        self.update_system_info()
        
    def update_system_info(self):
        """Update system information display asynchronously using Worker"""
        self.sysinfo_thread = QThread()
        # Create a Worker instance to fetch system info in the background
        self.sysinfo_worker = Worker(self.backend.get_system_info)
        self.sysinfo_worker.moveToThread(self.sysinfo_thread)
        self.sysinfo_thread.started.connect(self.sysinfo_worker.run)
        self.sysinfo_worker.finished.connect(self.on_system_info_ready)
        self.sysinfo_worker.error.connect(self.on_system_info_error)
        self.sysinfo_worker.finished.connect(self.sysinfo_thread.quit)
        # Connect the worker's finished signal to schedule its deletion
        self.sysinfo_worker.finished.connect(self.sysinfo_worker.deleteLater)
        # Connect the thread's finished signal to schedule its deletion
        self.sysinfo_thread.finished.connect(self.sysinfo_thread.deleteLater)
        self.sysinfo_thread.start()

    def on_system_info_ready(self, info):
        # Check if there was an error in the received information
        if 'error' in info:
            self.on_system_info_error(Exception(info['error']))
        elif hasattr(self, 'system_monitor') and self.system_monitor:
            # Update the static system information in the monitor widget
            self.system_monitor.update_static_system_info(
                hostname=info.get('hostname', 'N/A'),
                os_info=info.get('os', 'N/A'),
                kernel_info=info.get('kernel', 'N/A'),
                uptime_info=info.get('uptime', 'N/A')
            )
            # Start real-time monitoring after static info is updated
            self.system_monitor.start_monitoring()

    def on_system_info_error(self, error):
        from PySide6.QtWidgets import QMessageBox
        error_msg = str(error)
        # Log the error if a logger is available
        if hasattr(self, 'logger') and self.logger:
            self.logger.error(f"JuniorDashboard: Failed to get system info: {error_msg}", exc_info=error)
        else:
            print(f"ERROR in JuniorDashboard.on_system_info_error: {error_msg}")

        # Stop the update timer if it's active to prevent further errors
        if hasattr(self, 'update_timer') and self.update_timer.isActive():
            self.update_timer.stop()
            if hasattr(self, 'logger') and self.logger: self.logger.info("JuniorDashboard: Stopped system_info_timer due to error.")

        # Stop monitoring in the system monitor widget if it exists
        if hasattr(self, 'system_monitor') and self.system_monitor:
            self.system_monitor.stop_monitoring()
            # self.system_monitor.update_stats() # No need to force update, stop_monitoring handles UI state

        QMessageBox.warning(self, "Connection Error", f"Failed to get system info: {error_msg}. Monitoring may be paused. Please check connection or try reconnecting.")
        
    def setup_user_management(self):
        """Set up the user management page with limited privileges"""
        user_widget = QWidget()
        layout = QVBoxLayout(user_widget)
        
        # Initialize the user manager widget (limited functionality for junior admins)
        self.user_manager = UserManagerWidget(is_senior=False, remote=self.remote)
        layout.addWidget(self.user_manager)
        
        self.add_content_widget("users", user_widget)
        
    def setup_network_management(self):
        """Set up the network management page with limited capabilities"""
        network_widget = QWidget()
        layout = QVBoxLayout(network_widget)
        
        # Display an informational label about junior admin network capabilities
        network_info = QLabel("Junior admins can check network connectivity but cannot modify network configurations")
        network_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(network_info)
        
        # Initialize the network manager widget (limited functionality for junior admins)
        self.network_manager = NetworkManagerWidget(remote=self.remote, is_senior=False)
        layout.addWidget(self.network_manager)
        
        self.add_content_widget("network", network_widget)
        
    def setup_permissions_management(self):
        """Set up the permissions management page with limited capabilities"""
        perm_widget = QWidget()
        layout = QVBoxLayout(perm_widget)
        
        # Display an informational label about junior admin permission capabilities
        perm_info = QLabel("Junior admins have limited permission management capabilities")
        perm_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(perm_info)
        
        # Initialize the permissions manager widget (limited functionality for junior admins)
        self.perm_manager = PermissionsManagerWidget(remote=self.remote, is_senior=False)
        layout.addWidget(self.perm_manager)
        
        self.add_content_widget("permissions", perm_widget)
        
    def setup_update_management(self):
        """Set up the update management page with limited control"""
        update_widget = QWidget()
        layout = QVBoxLayout(update_widget)
        
        # Display an informational label about junior admin update capabilities
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
        
        # Display an informational label about junior admin backup capabilities
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
        
        # Create a group box for submitting new task reports
        form_group = QGroupBox("Submit Task Report")
        form_layout = QVBoxLayout(form_group)
        
        task_layout = QHBoxLayout()
        task_layout.addWidget(QLabel("Task Type:"))
        
        # Combo box for selecting the type of task
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
        task_layout.addStretch() # Add stretch to push elements to the left
        form_layout.addLayout(task_layout)
        
        description_layout = QVBoxLayout()
        description_layout.addWidget(QLabel("Description:"))
        
        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText("Enter task details...")
        self.description_input.setMaximumHeight(100) # Limit height of description input
        
        description_layout.addWidget(self.description_input)
        form_layout.addLayout(description_layout)
        
        submit_btn = QPushButton("Submit Report")
        submit_btn.clicked.connect(self.submit_task_report)
        
        form_layout.addWidget(submit_btn)
        layout.addWidget(form_group)
        
        # Create a group box for displaying task history
        history_group = QGroupBox("Task History")
        history_layout = QVBoxLayout(history_group)
        
        # Table to display the history of submitted tasks
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(3)
        self.history_table.setHorizontalHeaderLabels(["Date/Time", "Task Type", "Description"])
        self.history_table.horizontalHeader().setStretchLastSection(True) # Make last column stretch
        
        history_layout.addWidget(self.history_table)
        
        refresh_btn = QPushButton("Refresh History")
        refresh_btn.clicked.connect(self.refresh_task_history)
        history_layout.addWidget(refresh_btn)
        
        layout.addWidget(history_group)
        
        self.add_content_widget("tasks", task_widget)
        
        # Load initial task history
        self.refresh_task_history()
        
    def refresh_task_history(self):
        """Refresh the task history from the database"""
        # Fetch the task history from the backend
        task_history = self.backend.get_task_history()
        
        self.history_table.setRowCount(0)
        
        # Populate the table with new task history entries
        for task in task_history:
            self.add_history_entry(task['timestamp'], task['type'], task['description'])
        
    def submit_task_report(self):
        """Submit a task report to the senior admin"""
        task_type = self.task_combo.currentText()
        
        if not (description := self.description_input.toPlainText()):
            self.show_error_message("Please enter a description for the task.")
            return
        
        if description.strip() == "":
            self.show_error_message("Description cannot be empty.")
            return
            
        # Submit the task report via the backend
        success = self.backend.submit_task_report(task_type, description)
        
        if success:
            self.show_success_message("Task report submitted successfully!")
            self.description_input.clear()
            
            # Get current time from backend for consistency
            now = self.backend.get_current_time()
            self.add_history_entry(now, task_type, description)
        else:
            self.show_error_message("Failed to submit task report. Please try again.")
            
    def add_history_entry(self, timestamp, task_type, description):
        """Add a new entry to the task history table"""
        current_row = self.history_table.rowCount()
        self.history_table.insertRow(current_row)
        
        # Set the items for each cell in the new row
        self.history_table.setItem(current_row, 0, QTableWidgetItem(timestamp))
        self.history_table.setItem(current_row, 1, QTableWidgetItem(task_type))
        self.history_table.setItem(current_row, 2, QTableWidgetItem(description))
        
    def show_error_message(self, message: str):
        """Show error message dialog"""
        # Call the generic message display method with a Warning icon
        self.show_message("Error", message, QMessageBox.Icon.Warning)
        
    def show_success_message(self, message: str):
        """Show success message dialog"""
        # Call the generic message display method with an Information icon
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
        # Apply base styles from the parent class
        super().apply_styles()
        
        # Get the current theme dictionary
        theme = self._get_current_theme()
        # Get the currently applied stylesheet
        current_stylesheet = self.styleSheet()
        # Construct the new stylesheet parts, starting with the current one
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
        """Handle dashboard close event."""
        # Log the closing event if a logger is available
        if hasattr(self, 'logger') and self.logger:
            self.logger.info("JuniorDashboard: Closing dashboard.")

        if hasattr(self, 'update_timer') and self.update_timer:
            self.update_timer.stop()
        
        # Quit and wait for the system info thread if it's running
        if hasattr(self, 'sysinfo_thread') and self.sysinfo_thread and self.sysinfo_thread.isRunning():
            self.sysinfo_thread.quit()
            self.sysinfo_thread.wait()

        if hasattr(self, 'system_monitor') and self.system_monitor:
            self.system_monitor.stop_monitoring()
            if hasattr(self.system_monitor, 'cleanup'):
                self.system_monitor.cleanup()

        if hasattr(self, 'backend') and self.backend and hasattr(self.backend, 'cleanup'):
            self.backend.cleanup()
        
        super().closeEvent(event)

    def setup_acl_management(self):
        """Set up the ACL management page with limited capabilities"""
        acl_widget = QWidget()
        layout = QVBoxLayout(acl_widget)
        
        # Display an informational label about junior admin ACL capabilities
        acl_info = QLabel("Junior admins can view ACLs but cannot modify them")
        acl_info.setStyleSheet("font-weight: bold; color: #E74C3C;")
        layout.addWidget(acl_info)
        
        # Initialize the ACL manager widget (limited functionality for junior admins)
        self.acl_manager = ACLManagerWidget(remote=self.remote, is_senior=False)
        layout.addWidget(self.acl_manager)
        
        self.add_content_widget("acl", acl_widget) 

    def setup_navigation(self):
        """Set up the navigation sidebar with available actions for Junior Admin"""
        # Add navigation buttons for each page
        # These buttons allow the user to switch between different sections of the dashboard.
        self.add_nav_button("monitor", "System Monitor")
        self.add_nav_button("users", "User Management")
        self.add_nav_button("permissions", "File Permissions")
        self.add_nav_button("acl", "ACL Management")
        self.add_nav_button("network", "Network")
        self.add_nav_button("updates", "System Updates")
        self.add_nav_button("backups", "Backup Manager")
        self.add_nav_button("tasks", "Task Reports") 