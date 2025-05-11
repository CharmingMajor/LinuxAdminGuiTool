from PySide6.QtCore import QObject, Signal
from pathlib import Path
import json

class ThemeManager(QObject):
    """Singleton class to manage application theme"""
    
    theme_changed = Signal(str)  # Emits 'dark' or 'light'
    _instance = None
    _initialized = False
    _config_file = Path.home() / '.linux_admin_gui_theme.json'
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ThemeManager, cls).__new__(cls)
        return cls._instance
        
    def __init__(self):
        # Only initialize QObject once
        if not ThemeManager._initialized:
            super().__init__()
            self._theme = self._load_theme()
            ThemeManager._initialized = True
    
    def _load_theme(self):
        """Load theme from config file"""
        try:
            if self._config_file.exists():
                with open(self._config_file, 'r') as f:
                    data = json.load(f)
                    return data.get('theme', 'dark')
        except Exception:
            pass
        return 'dark'  # Default to dark theme
    
    def _save_theme(self):
        """Save theme to config file"""
        try:
            with open(self._config_file, 'w') as f:
                json.dump({'theme': self._theme}, f)
        except Exception:
            pass
    
    @property
    def current_theme(self):
        """Get current theme"""
        return self._theme
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self._theme = 'light' if self._theme == 'dark' else 'dark'
        self._save_theme()
        self.theme_changed.emit(self._theme)
    
    def get_theme_styles(self):
        """Get theme styles dictionary"""
        if self._theme == 'dark':
            return {
                'bg_primary': '#1e1e1e',
                'bg_secondary': '#252526',
                'bg_tertiary': '#333333',
                'text_primary': '#ffffff',
                'text_secondary': '#e0e0e0',
                'accent_primary': '#0078d4',
                'accent_secondary': '#2b88d8',
                'accent_tertiary': '#005a9e',
                'border_color': '#555555',
                'input_bg': '#3c3c3c',
                'hover_bg': '#3a3d3f',
                'active_bg': '#37373d',
                'error_color': '#ff5252',
                'success_color': '#4caf50',
                'warning_color': '#fb8c00',
                'info_color': '#2196f3',
                'table_header_bg': '#333333',
                'table_row_alt': '#2d2d2d',
                'scrollbar_bg': '#1e1e1e',
                'scrollbar_handle': '#555555'
            }
        else:
            return {
                'bg_primary': '#ffffff',
                'bg_secondary': '#f8f9fa',
                'bg_tertiary': '#e9ecef',
                'text_primary': '#212529',
                'text_secondary': '#6c757d',
                'accent_primary': '#007bff',
                'accent_secondary': '#0056b3',
                'accent_tertiary': '#004085',
                'border_color': '#dee2e6',
                'input_bg': '#ffffff',
                'hover_bg': '#e9ecef',
                'active_bg': '#e2e6ea',
                'error_color': '#dc3545',
                'success_color': '#28a745',
                'warning_color': '#ffc107',
                'info_color': '#17a2b8',
                'table_header_bg': '#f2f2f2',
                'table_row_alt': '#f8f9fa',
                'scrollbar_bg': '#f8f9fa',
                'scrollbar_handle': '#adb5bd'
            } 