from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QComboBox, QTextEdit, QGroupBox, QFileDialog)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QIcon
import os
from pathlib import Path
import subprocess
import time

class LogViewerWidget(QWidget):
    """Widget for viewing and analyzing system logs"""
    
    def __init__(self, parent=None, advanced=False, remote=None, include_security=True):
        super().__init__(parent)
        self.advanced = advanced
        self.remote = remote
        self.include_security = include_security
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the log viewer UI"""
        layout = QVBoxLayout(self)
        
        # Controls
        controls_group = QGroupBox("Log Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        # Log file selector
        self.log_selector = QComboBox()
        log_files = [
            "/var/log/syslog",
            "/var/log/kern.log",
            "/var/log/dmesg"
        ]
        if self.include_security:
            log_files.insert(1, "/var/log/auth.log")
            
        self.log_selector.addItems(log_files)
        self.log_selector.currentTextChanged.connect(self.load_log)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_log)
        
        # Filter input
        self.filter_input = QComboBox()
        self.filter_input.setEditable(True)
        self.filter_input.addItems([
            "ERROR",
            "WARNING",
            "INFO",
            "DEBUG"
        ])
        self.filter_input.currentTextChanged.connect(self.apply_filter)
        
        controls_layout.addWidget(QLabel("Log File:"))
        controls_layout.addWidget(self.log_selector)
        controls_layout.addWidget(refresh_btn)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_input)
        controls_layout.addStretch()
        
        layout.addWidget(controls_group)
        
        # Log viewer
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        
        if self.advanced:
            # Advanced controls
            advanced_group = QGroupBox("Advanced Options")
            advanced_layout = QHBoxLayout(advanced_group)
            
            # Export button
            export_btn = QPushButton("Export Log")
            export_btn.clicked.connect(self.export_log)
            
            # Clear button
            clear_btn = QPushButton("Clear Log")
            clear_btn.clicked.connect(self.clear_log)
            
            advanced_layout.addWidget(export_btn)
            advanced_layout.addWidget(clear_btn)
            advanced_layout.addStretch()
            
            layout.addWidget(advanced_group)
        
        # Load initial log
        self.load_log()
        
        # Set up auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_log)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
    def load_log(self):
        """Load the selected log file"""
        log_file = self.log_selector.currentText()
        try:
            if self.remote:
                # For remote systems, use tail to get last 1000 lines
                stdout, stderr = self.remote.execute_command(f"tail -n 1000 {log_file}")
                if stderr:
                    raise Exception(stderr)
                self.log_text.setPlainText(stdout)
            else:
                # For local system, read the file directly
                try:
                    with open(log_file, 'r') as f:
                        content = f.readlines()[-1000:]  # Last 1000 lines
                        self.log_text.setPlainText(''.join(content))
                except PermissionError:
                    self.log_text.setPlainText(f"Permission denied: Cannot read {log_file}")
                except FileNotFoundError:
                    self.log_text.setPlainText(f"Log file not found: {log_file}")
        except Exception as e:
            self.log_text.setPlainText(f"Error loading log: {str(e)}")
            
    def apply_filter(self):
        """Apply the selected filter to the log content"""
        filter_text = self.filter_input.currentText()
        if not filter_text:
            self.load_log()
            return
            
        current_text = self.log_text.toPlainText()
        filtered_lines = [
            line for line in current_text.split("\n")
            if filter_text.lower() in line.lower()
        ]
        self.log_text.setPlainText("\n".join(filtered_lines))
        
    def export_log(self):
        """Export the current log content to a file"""
        if not self.advanced:
            return
            
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "Export Log",
            str(Path.home()),
            "Log Files (*.log);;Text Files (*.txt);;All Files (*.*)"
        )
        
        if file_name:
            try:
                with open(file_name, "w") as f:
                    f.write(self.log_text.toPlainText())
            except Exception as e:
                self.log_text.append(f"\nError exporting log: {str(e)}")
                
    def clear_log(self):
        """Clear the current log content"""
        if not self.advanced:
            return
            
        self.log_text.clear()
        
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()
            self.refresh_timer.timeout.disconnect(self.load_log)
            
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event) 