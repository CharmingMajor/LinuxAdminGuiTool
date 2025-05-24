from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QComboBox, QTextEdit, QGroupBox, QFileDialog)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QIcon
import os
from pathlib import Path
# import subprocess # No longer needed for local file reading
# import time # No longer needed

# Get the project root directory, assuming this widget is always within the project structure
# This allows us to construct paths to logs/app.log and logs/brute_force_logs.txt
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent 
LOG_DIR = PROJECT_ROOT / "logs"

class LogViewerWidget(QWidget):
    """Widget for viewing and analyzing application logs"""
    
    # Removed remote and include_security from constructor
    # backend_log_method is a callable that will fetch logs, e.g., self.backend.get_system_logs
    def __init__(self, parent=None, advanced=False, backend_log_method=None):
        super().__init__(parent)
        self.advanced = advanced
        self.backend_log_method = backend_log_method # Store the backend log fetching method
        
        # Define project-specific log files
        self.app_log_path = LOG_DIR / "app.log"
        self.brute_force_log_path = LOG_DIR / "brute_force_logs.txt"
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the log viewer UI"""
        layout = QVBoxLayout(self)
        
        controls_group = QGroupBox("Log Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.log_selector = QComboBox()
        # Update log_files to be more descriptive and use Path objects
        self.log_files_map = {
            "Application Log": self.app_log_path,
            "Brute Force Attempts": self.brute_force_log_path
        }
        self.log_selector.addItems(list(self.log_files_map.keys()))
        
        # Connect to load_log method, which will now handle Path objects
        self.log_selector.currentTextChanged.connect(self.load_log_display_name)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_log_display_name) # Connect to the new wrapper
        
        self.filter_input = QComboBox()
        self.filter_input.setEditable(True)
        self.filter_input.addItems([
            "ERROR",
            "WARNING",
            "INFO",
            "DEBUG",
            "CRITICAL" # Added critical as it's used in main.py
        ])
        self.filter_input.currentTextChanged.connect(self.apply_filter)
        
        controls_layout.addWidget(QLabel("Log File:"))
        controls_layout.addWidget(self.log_selector)
        controls_layout.addWidget(refresh_btn)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_input)
        controls_layout.addStretch()
        
        layout.addWidget(controls_group)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        # Let's use a monospaced font for better log readability
        font = QFont("Monospace")
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.log_text.setFont(font)
        layout.addWidget(self.log_text)
        
        if self.advanced:
            self._setup_advanced_options(layout)
        
        self.load_log_display_name() # Load initially selected log
        
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_log_display_name) # Connect to the new wrapper
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
    def _setup_advanced_options(self, layout: QVBoxLayout):
        """Sets up advanced log viewing options like export and clear."""
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QHBoxLayout(advanced_group)
        
        export_btn = QPushButton("Export Log")
        export_btn.clicked.connect(self.export_log)
        
        # Clear log might not be a good idea for app logs, maybe disable or remove
        # For now, let's keep it if advanced is True
        clear_btn = QPushButton("Clear Log (Display Only)") 
        clear_btn.clicked.connect(self.clear_log_display) # Renamed to avoid confusion
        
        advanced_layout.addWidget(export_btn)
        advanced_layout.addWidget(clear_btn)
        advanced_layout.addStretch()
        
        layout.addWidget(advanced_group)

    def load_log_display_name(self):
        """Wrapper to call load_log with the actual file path based on display name."""
        selected_display_name = self.log_selector.currentText()
        log_file_path = self.log_files_map.get(selected_display_name)
        if log_file_path:
            self.load_log(log_file_path)
        else:
            self.log_text.setPlainText(f"Error: Log display name '{selected_display_name}' not found in map.")

    def load_log(self, log_file_path: Path): # Takes Path object
        """Load the selected log file from the project's logs directory"""
        try:
            # Ensure logs directory exists (it should, as main.py creates it)
            LOG_DIR.mkdir(exist_ok=True)

            if log_file_path.exists():
                # Read the last N lines (e.g., 1000) for performance with large logs
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    # Reading all lines then slicing might be inefficient for huge files
                    # A more robust solution would read file in reverse or use deque
                    lines = f.readlines()
                    content = "".join(lines[-1000:]) # Display last 1000 lines
                self.log_text.setPlainText(content)
                # Scroll to the end to show the latest logs
                self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
            else:
                self.log_text.setPlainText(f"Log file not found: {log_file_path.name}\nFull path: {log_file_path}")
        except PermissionError:
            self.log_text.setPlainText(f"Permission denied: Cannot read {log_file_path.name}")
        except Exception as e:
            self.log_text.setPlainText(f"Error loading log '{log_file_path.name}': {str(e)}")
            
    def apply_filter(self):
        """Apply the selected filter to the log content"""
        filter_text = self.filter_input.currentText()
        if not filter_text:
            self.load_log_display_name()
            return
            
        # Instead of reloading, filter the currently displayed text if it's not too large
        # or reload and then filter if that's preferred.
        # For simplicity, let's re-fetch and filter. This ensures filter is applied to latest logs.
        selected_display_name = self.log_selector.currentText()
        log_file_path = self.log_files_map.get(selected_display_name)
        
        if not log_file_path:
            self.log_text.setPlainText(f"Error: Log display name '{selected_display_name}' for filtering not found.")
            return

        try:
            if log_file_path.exists():
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines() # Read all lines for filtering
                
                filter_text_lower = filter_text.lower()
                filtered_lines = [
                    line for line in lines
                    if filter_text_lower in line.lower()
                ]
                # Display last 1000 of filtered lines if too many
                self.log_text.setPlainText("".join(filtered_lines[-1000:])) 
                self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
            else:
                self.log_text.setPlainText(f"Log file for filtering not found: {log_file_path.name}")
        except Exception as e:
            self.log_text.setPlainText(f"Error applying filter to '{log_file_path.name}': {str(e)}")
            
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
                
    def clear_log_display(self): # Renamed method
        """Clear the log display text area"""
        # This only clears the display, not the actual log file
        self.log_text.clear()
        
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()
            self.refresh_timer.timeout.disconnect(self.load_log_display_name)
            
    def closeEvent(self, event):
        """Handle widget close event"""
        self.cleanup()
        super().closeEvent(event) 