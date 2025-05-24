from os import stat # Seems unused, consider removing.
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                            QLabel, QTableWidget, QTableWidgetItem, QHeaderView,
                            QComboBox, QMessageBox, QGroupBox, QTextEdit)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor # For setting background colors on table items.
from src.backend.senior_dashboard_backend import SeniorDashboardBackend # Backend interface for data operations.

class ReportViewerWidget(QWidget):
    """Widget for viewing reports from junior admins""" # This is a docstring
    
    # Signal emitted when reports are reloaded, so other widgets can update if necessary.
    refresh_requested = Signal()
    
    def __init__(self, backend: SeniorDashboardBackend, parent=None):
        super().__init__(parent)
        self.backend = backend # Keep a reference to the backend for fetching/updating data.
        self.setup_ui() # Initialize the user interface for this widget.
        
    def setup_ui(self):
        """Set up the UI components""" # This is a docstring
        layout = QVBoxLayout(self) # Main vertical layout for the widget.
        
        # --- Header Section --- 
        header_layout = QHBoxLayout()
        title_label = QLabel("Junior Admin Reports")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;") # Make title prominent.
        refresh_button = QPushButton("Refresh")
        refresh_button.clicked.connect(self.load_reports) # Connect to actual data loading method.
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(refresh_button)
        layout.addLayout(header_layout)
        
        self.reports_table = QTableWidget()
        self.reports_table.setColumnCount(6)
        self.reports_table.setHorizontalHeaderLabels(["ID", "Date/Time", "From", "Type", "Description", "Status"])
        self.reports_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.reports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.reports_table.currentCellChanged.connect(self.on_report_selected)
        
        header = self.reports_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        layout.addWidget(self.reports_table)
        
        details_group = QGroupBox("Report Details")
        details_layout = QVBoxLayout(details_group)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
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
        
        self.load_reports()
        
    def load_reports(self):
        """Load reports from the database"""
        reports = self.backend.get_junior_reports()
        
        self.reports_table.setRowCount(0)
        
        for row, report in enumerate(reports):
            self.reports_table.insertRow(row)
            
            self.reports_table.setItem(row, 0, QTableWidgetItem(str(report['id'])))
            self.reports_table.setItem(row, 1, QTableWidgetItem(report['timestamp']))
            self.reports_table.setItem(row, 2, QTableWidgetItem(report['from_user']))
            self.reports_table.setItem(row, 3, QTableWidgetItem(report['report_type']))
            self.reports_table.setItem(row, 4, QTableWidgetItem(report['description']))
            
            status_item = QTableWidgetItem(report['status'])
            
            if report['status'] == 'pending':
                status_item.setBackground(QColor(255, 255, 200))
            elif report['status'] == 'in-progress':
                status_item.setBackground(QColor(200, 230, 255))
            elif report['status'] == 'completed':
                status_item.setBackground(QColor(200, 255, 200))
            elif report['status'] == 'rejected':
                status_item.setBackground(QColor(255, 200, 200))
                
            self.reports_table.setItem(row, 5, status_item)
            
        self.details_text.clear()
        
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
            
            index = self.status_combo.findText(status)
            if index >= 0:
                self.status_combo.setCurrentIndex(index)
            
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
            report_id_str = self.reports_table.item(current_row, 0).text()
            try:
                report_id = int(report_id_str)
            except ValueError:
                QMessageBox.warning(self, "Error", f"Invalid Report ID: {report_id_str}")
                return

            new_status = self.status_combo.currentText()

            if success := self.backend.update_report_status(report_id, new_status):
                self._update_ui_after_status_change(new_status, current_row)
            else:
                QMessageBox.warning(self, "Error", "Failed to update report status in the database.")
        else:
            QMessageBox.warning(self, "Warning", "Please select a report first to update its status.") 

    def _update_ui_after_status_change(self, new_status, current_row):
        status_item = QTableWidgetItem(new_status)

        if new_status == 'pending':
            status_item.setBackground(QColor(255, 255, 200))
        elif new_status == 'in-progress':
            status_item.setBackground(QColor(200, 230, 255))
        elif new_status == 'completed':
            status_item.setBackground(QColor(200, 255, 200))
        elif new_status == 'rejected':
            status_item.setBackground(QColor(255, 200, 200))

        self.reports_table.setItem(current_row, 5, status_item)

        old_status_text = self.reports_table.item(current_row, 5).text()
        report_id = self.reports_table.item(current_row, 0).text()
        timestamp = self.reports_table.item(current_row, 1).text()
        from_user = self.reports_table.item(current_row, 2).text()
        report_type = self.reports_table.item(current_row, 3).text()
        description = self.reports_table.item(current_row, 4).text()

        details = f"""
        <h3>Report #{report_id}</h3>
        <p><b>Date/Time:</b> {timestamp}</p>
        <p><b>From:</b> {from_user}</p>
        <p><b>Type:</b> {report_type}</p>
        <p><b>Status:</b> {new_status}</p>
        <p><b>Description:</b><br>{description}</p>
        """
        self.details_text.setHtml(details)

        QMessageBox.information(self, "Success", f"Report status updated to {new_status}") 