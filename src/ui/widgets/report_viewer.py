from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                            QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
                            QComboBox, QMessageBox, QGroupBox, QTextEdit)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from src.backend.senior_dashboard_backend import SeniorDashboardBackend

class ReportViewerWidget(QWidget):
    """Widget for viewing reports from junior admins"""
    
    refresh_requested = Signal()
    
    def __init__(self, backend: SeniorDashboardBackend, parent=None):
        super().__init__(parent)
        self.backend = backend
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the UI components"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Junior Admin Reports")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.load_reports)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(refresh_button)
        layout.addLayout(header_layout)
        
        # Reports table
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(6)
        self.reports_table.setHorizontalHeaderLabels(["ID", "Date/Time", "From", "Type", "Description", "Status"])
        self.reports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.reports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.reports_table.currentCellChanged.connect(self.on_report_selected)
        
        # Adjust column widths
        header = self.reports_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # ID
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Date/Time
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # From
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Type
        header.setSectionResizeMode(4, QHeaderView.Stretch)           # Description
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Status
        
        layout.addWidget(self.reports_table)
        
        # Report details
        details_group = QGroupBox("Report Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        self.status_combo = QComboBox()
        self.status_combo.addItems(["pending", "in-progress", "completed", "rejected"])
        
        update_button = QPushButton("Update Status")
        update_button.clicked.connect(self.update_report_status)
        
        action_layout.addWidget(QLabel("Status:"))
        action_layout.addWidget(self.status_combo)
        action_layout.addWidget(update_button)
        action_layout.addStretch()
        
        details_layout.addLayout(action_layout)
        layout.addWidget(details_group)
        
        # Load reports
        self.load_reports()
        
    def load_reports(self):
        """Load reports from the database"""
        reports = self.backend.get_junior_reports()
        
        # Clear the table
        self.reports_table.setRowCount(0)
        
        # Add reports to the table
        for row, report in enumerate(reports):
            self.reports_table.insertRow(row)
            
            # Set the data
            self.reports_table.setItem(row, 0, QTableWidgetItem(str(report['id'])))
            self.reports_table.setItem(row, 1, QTableWidgetItem(report['timestamp']))
            self.reports_table.setItem(row, 2, QTableWidgetItem(report['from_user']))
            self.reports_table.setItem(row, 3, QTableWidgetItem(report['report_type']))
            self.reports_table.setItem(row, 4, QTableWidgetItem(report['description']))
            
            status_item = QTableWidgetItem(report['status'])
            
            # Color code by status
            if report['status'] == 'pending':
                status_item.setBackground(QColor(255, 255, 200))  # Light yellow
            elif report['status'] == 'in-progress':
                status_item.setBackground(QColor(200, 230, 255))  # Light blue
            elif report['status'] == 'completed':
                status_item.setBackground(QColor(200, 255, 200))  # Light green
            elif report['status'] == 'rejected':
                status_item.setBackground(QColor(255, 200, 200))  # Light red
                
            self.reports_table.setItem(row, 5, status_item)
            
        # Clear the details view
        self.details_text.clear()
        
        # Emit refresh signal
        self.refresh_requested.emit()
        
    def on_report_selected(self, currentRow, currentColumn, previousRow, previousColumn):
        """Handle report selection change"""
        if currentRow >= 0:
            report_id = self.reports_table.item(currentRow, 0).text()
            timestamp = self.reports_table.item(currentRow, 1).text()
            from_user = self.reports_table.item(currentRow, 2).text()
            report_type = self.reports_table.item(currentRow, 3).text()
            description = self.reports_table.item(currentRow, 4).text()
            status = self.reports_table.item(currentRow, 5).text()
            
            # Update status combobox
            index = self.status_combo.findText(status)
            if index >= 0:
                self.status_combo.setCurrentIndex(index)
            
            # Update details view
            details = f"""
            <h3>Report #{report_id}</h3>
            <p><b>Date/Time:</b> {timestamp}</p>
            <p><b>From:</b> {from_user}</p>
            <p><b>Type:</b> {report_type}</p>
            <p><b>Status:</b> {status}</p>
            <p><b>Description:</b><br>{description}</p>
            """
            self.details_text.setHtml(details)
            
    def update_report_status(self):
        """Update the status of the selected report"""
        current_row = self.reports_table.currentRow()
        if current_row >= 0:
            report_id = int(self.reports_table.item(current_row, 0).text())
            new_status = self.status_combo.currentText()
            
            success = self.backend.update_report_status(report_id, new_status)
            
            if success:
                # Update the status in the table
                status_item = QTableWidgetItem(new_status)
                
                # Color code by status
                if new_status == 'pending':
                    status_item.setBackground(QColor(255, 255, 200))  # Light yellow
                elif new_status == 'in-progress':
                    status_item.setBackground(QColor(200, 230, 255))  # Light blue
                elif new_status == 'completed':
                    status_item.setBackground(QColor(200, 255, 200))  # Light green
                elif new_status == 'rejected':
                    status_item.setBackground(QColor(255, 200, 200))  # Light red
                    
                self.reports_table.setItem(current_row, 5, status_item)
                
                # Update details view
                current_details = self.details_text.toHtml()
                updated_details = current_details.replace(f"<p><b>Status:</b> {new_status}</p>", 
                                                         f"<p><b>Status:</b> {new_status}</p>")
                self.details_text.setHtml(updated_details)
                
                QMessageBox.information(self, "Success", f"Report status updated to {new_status}")
            else:
                QMessageBox.warning(self, "Error", "Failed to update report status")
        else:
            QMessageBox.warning(self, "Warning", "Please select a report first") 