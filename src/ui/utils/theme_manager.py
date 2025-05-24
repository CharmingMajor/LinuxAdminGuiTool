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
        if not ThemeManager._initialized:
            super().__init__()
            self._theme = self._load_theme()
            ThemeManager._initialized = True
    
    def _load_theme(self):
        """Load theme from config file"""
        return 'dark'  # Default to dark theme
    
    # def _save_theme(self):
    #     """Save theme to config file"""
    #     try:
    #         with open(self._config_file, 'w') as f:
    #             json.dump({'theme': self._theme}, f)
    #     except Exception:
    #         pass
    
    @property
    def current_theme(self):
        """Get current theme"""
        return self._theme
    
    # def toggle_theme(self):
    #     """Toggle between light and dark themes"""
    #     self._theme = 'light' if self._theme == 'dark' else 'dark'
    #     self._save_theme()
    #     self.theme_changed.emit(self._theme)
    
    def get_theme_styles(self):
        """Get theme styles dictionary"""
        return {
            'bg_primary': '#23272e',
            'bg_secondary': '#181c20',
            'bg_tertiary': '#23272e',
            'text_primary': '#f7fafd',
            'text_secondary': '#b0b8c1',
            'accent_primary': '#0071ce',
            'accent_secondary': '#005fa3',
            'accent_tertiary': '#003e6b',
            
            'border_color': '#2e333a',
            'input_bg': '#23272e',
            'hover_bg': '#232b32',
            'active_bg': '#1a1e23',
            'card_bg': '#23272e',
            'modal_bg': '#23272e',
            
            'error_color': '#e5534b',
            'success_color': '#3ecf8e',
            'warning_color': '#ffb400',
            'info_color': '#0071ce',
            
            'error_bg': '#4d2825',      # Background for error elements
            'disabled_bg': '#2c3138',   # Background for disabled elements
            'disabled_text': '#6a737d', # Text color for disabled elements
            'disabled_border': '#3a4048',# Border color for disabled elements
            
            'table_header_bg': '#232b32',
            'table_row_alt': '#1a1e23',
            'table_border': '#2e333a',
            'table_hover': '#232b32',
            'table_selected': '#003e6b',
            
            'scrollbar_bg': '#181c20',
            'scrollbar_handle': '#2e333a',
            'scrollbar_hover': '#3a4048',
            
            'chart_bg': '#23272e',
            'chart_grid': '#2e333a',
            'chart_line1': '#0071ce',
            'chart_line2': '#e5534b',
            'chart_line3': '#3ecf8e',
            'chart_line4': '#ffb400',
            
            'sidebar_bg': '#181c20',
            'sidebar_hover': '#232b32',
            'sidebar_active': '#232b32',
            'sidebar_text': '#f7fafd',
            'sidebar_text_active': '#0071ce',
            'sidebar_border': '#232b32',
            'card_shadow': '0 4px 24px rgba(0,0,0,0.18)',
            'widget_bg': '#23272e',
            'progress_track': '#2e333a',
            'header_bg': '#232b32',
            
            'shadow_light': 'rgba(0, 0, 0, 0.08)',
            'shadow_medium': 'rgba(0, 0, 0, 0.16)',
            'shadow_dark': 'rgba(0, 0, 0, 0.24)',
            
            'font_primary': '"Red Hat Text", "Segoe UI", "Inter", Arial, sans-serif',
            'font_monospace': '"Red Hat Mono", "Source Code Pro", monospace',
            
            'font_size_sm': '12px',
            'font_size_md': '13px', # Default/medium font size
            'font_size_lg': '16px',
            'font_size_xl': '20px',
            
            'radius_sm': '6px',
            'radius_md': '8px',
            'radius_lg': '12px',
            
            'transition_fast': '0.12s',
            'transition_normal': '0.22s'
        }
            
    def apply_widget_styles(self, widget):
        """Apply common theme styles to a widget and its children
        
        This centralized method ensures consistent styling across widgets
        """
        theme = self.get_theme_styles()
        
        # Set the base style for the widget
        widget.setStyleSheet(f"""
            QWidget {{
                font-family: {theme['font_primary']};
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
            }}
            
            QTableWidget {{
                border: 1px solid {theme['border_color']};
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
                gridline-color: {theme['table_border']};
                font-size: 12px;
                border-radius: {theme['radius_sm']};
                selection-background-color: {theme['table_selected']};
            }}
            
            QTableWidget::item {{
                padding: 5px;
                border-bottom: 1px solid {theme['table_border']};
            }}
            
            QTableWidget::item:hover {{
                background-color: {theme['table_hover']};
            }}
            
            QHeaderView::section {{
                background-color: {theme['table_header_bg']};
                color: {theme['text_primary']};
                padding: 5px;
                border: 1px solid {theme['table_border']};
                font-weight: bold;
            }}
            
            QScrollBar:vertical {{
                background-color: {theme['scrollbar_bg']};
                width: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {theme['scrollbar_handle']};
                min-height: 30px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {theme['scrollbar_hover']};
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QScrollBar:horizontal {{
                background-color: {theme['scrollbar_bg']};
                height: 12px;
                margin: 0px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:horizontal {{
                background-color: {theme['scrollbar_handle']};
                min-width: 30px;
                border-radius: 6px;
            }}
            
            QScrollBar::handle:horizontal:hover {{
                background-color: {theme['scrollbar_hover']};
            }}
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0px;
            }}
            
            QGroupBox {{
                font-weight: bold;
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_md']};
                margin-top: 1em;
                padding-top: 10px;
                font-size: 12px;
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 3px;
                color: {theme['text_primary']};
                background-color: {theme['bg_secondary']};
            }}
            
            QLabel {{
                color: {theme['text_primary']};
                font-size: 12px;
            }}
            
            QPushButton {{
                padding: 8px 16px;
                background-color: {theme['accent_primary']};
                color: white;
                border: none;
                border-radius: {theme['radius_sm']};
                font-weight: bold;
                min-height: 28px;
            }}
            
            QPushButton:hover {{
                background-color: {theme['accent_secondary']};
            }}
            
            QPushButton:pressed {{
                background-color: {theme['accent_tertiary']};
            }}
            
            QPushButton:disabled {{
                background-color: {theme['border_color']};
                color: {theme['text_secondary']};
            }}
            
            QLineEdit, QTextEdit, QComboBox, QSpinBox {{
                background-color: {theme['input_bg']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                padding: 6px;
                selection-background-color: {theme['accent_secondary']};
                selection-color: white;
            }}
            
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
                border: 1px solid {theme['accent_primary']};
            }}
            
            QComboBox::drop-down {{
                border: none;
                width: 20px;
            }}
            
            QComboBox::down-arrow {{
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid {theme['text_secondary']};
                width: 0;
                height: 0;
                margin-right: 5px;
            }}
            
            QProgressBar {{
                border: 1px solid {theme['border_color']};
                border-radius: {theme['radius_sm']};
                text-align: center;
                background-color: {theme['progress_track']};
                color: {theme['text_primary']};
                height: 14px;
            }}
            
            QProgressBar::chunk {{
                background-color: {theme['accent_primary']};
                border-radius: 1px;
            }}
            
            QCheckBox {{
                color: {theme['text_primary']};
                spacing: 5px;
            }}
            
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {theme['border_color']};
                border-radius: 3px;
                background-color: {theme['input_bg']};
            }}
            
            QCheckBox::indicator:checked {{
                background-color: {theme['accent_primary']};
                border-color: {theme['accent_primary']};
            }}
            
            QCheckBox::indicator:hover {{
                border-color: {theme['accent_primary']};
            }}
            
            QRadioButton {{
                color: {theme['text_primary']};
                spacing: 5px;
            }}
            
            QRadioButton::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {theme['border_color']};
                border-radius: 8px;
                background-color: {theme['input_bg']};
            }}
            
            QRadioButton::indicator:checked {{
                background-color: {theme['accent_primary']};
                border-color: {theme['accent_primary']};
            }}
            
            QRadioButton::indicator:hover {{
                border-color: {theme['accent_primary']};
            }}
        """) 