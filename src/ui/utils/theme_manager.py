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
                # Base colors
                'bg_primary': '#1a1a1a',
                'bg_secondary': '#242424',
                'bg_tertiary': '#333333',
                'text_primary': '#ffffff',
                'text_secondary': '#bbbbbb',
                'accent_primary': '#3584e4',
                'accent_secondary': '#2b6ed0',
                'accent_tertiary': '#1a4382',
                
                # UI elements
                'border_color': '#444444',
                'input_bg': '#2d2d2d',
                'hover_bg': '#383838',
                'active_bg': '#303030',
                'card_bg': '#262626',
                'modal_bg': '#242424',
                
                # Status colors
                'error_color': '#ed5e68',
                'success_color': '#57e389',
                'warning_color': '#f8e45c',
                'info_color': '#62a0ea',
                
                # Table colors
                'table_header_bg': '#303030',
                'table_row_alt': '#2a2a2a',
                'table_border': '#404040',
                'table_hover': '#353535',
                'table_selected': '#334455',
                
                # Scrollbar
                'scrollbar_bg': '#1a1a1a',
                'scrollbar_handle': '#606060',
                'scrollbar_hover': '#707070',
                
                # Charts and graphs
                'chart_bg': '#272727',
                'chart_grid': '#3a3a3a',
                'chart_line1': '#3584e4',
                'chart_line2': '#ed5e68',
                'chart_line3': '#57e389',
                'chart_line4': '#f8ae42',
                
                # Dashboard elements
                'sidebar_bg': '#1e1e1e',
                'sidebar_hover': '#323232',
                'sidebar_active': '#3584e4',
                'card_shadow': '0 2px 6px rgba(0,0,0,0.2)',
                'widget_bg': '#282828',
                'progress_track': '#353535',
                
                # Shadows
                'shadow_light': 'rgba(0, 0, 0, 0.1)',
                'shadow_medium': 'rgba(0, 0, 0, 0.2)',
                'shadow_dark': 'rgba(0, 0, 0, 0.3)',
                
                # Fonts
                'font_primary': '"Segoe UI", Roboto, -apple-system, BlinkMacSystemFont, sans-serif',
                'font_monospace': '"Cascadia Code", "Source Code Pro", monospace',
                
                # Radii
                'radius_sm': '4px', 
                'radius_md': '6px',
                'radius_lg': '8px',
                
                # Transitions
                'transition_fast': '0.15s',
                'transition_normal': '0.25s'
            }
        else:
            return {
                # Base colors
                'bg_primary': '#fafafa',
                'bg_secondary': '#ffffff',
                'bg_tertiary': '#f0f0f0',
                'text_primary': '#333333',
                'text_secondary': '#666666',
                'accent_primary': '#1a73e8',
                'accent_secondary': '#1967d2',
                'accent_tertiary': '#174ea6',
                
                # UI elements
                'border_color': '#e0e0e0',
                'input_bg': '#ffffff',
                'hover_bg': '#f5f5f5',
                'active_bg': '#e7f1fd',
                'card_bg': '#ffffff',
                'modal_bg': '#ffffff',
                
                # Status colors
                'error_color': '#d93025',
                'success_color': '#188038',
                'warning_color': '#e37400',
                'info_color': '#1a73e8',
                
                # Table colors
                'table_header_bg': '#f8f9fa',
                'table_row_alt': '#fafafa',
                'table_border': '#eeeeee',
                'table_hover': '#f5f5f5',
                'table_selected': '#e8f0fe',
                
                # Scrollbar
                'scrollbar_bg': '#fafafa',
                'scrollbar_handle': '#c0c0c0',
                'scrollbar_hover': '#a0a0a0',
                
                # Charts and graphs
                'chart_bg': '#ffffff',
                'chart_grid': '#e0e0e0',
                'chart_line1': '#1a73e8',
                'chart_line2': '#d93025',
                'chart_line3': '#188038',
                'chart_line4': '#e37400',
                
                # Dashboard elements
                'sidebar_bg': '#f5f5f5',
                'sidebar_hover': '#e0e0e0',
                'sidebar_active': '#e7f1fd',
                'card_shadow': '0 2px 6px rgba(0,0,0,0.08)',
                'widget_bg': '#ffffff',
                'progress_track': '#eeeeee',
                
                # Shadows
                'shadow_light': 'rgba(0, 0, 0, 0.05)',
                'shadow_medium': 'rgba(0, 0, 0, 0.08)',
                'shadow_dark': 'rgba(0, 0, 0, 0.12)',
                
                # Fonts
                'font_primary': '"Segoe UI", Roboto, -apple-system, BlinkMacSystemFont, sans-serif',
                'font_monospace': '"Cascadia Code", "Source Code Pro", monospace',
                
                # Radii
                'radius_sm': '4px', 
                'radius_md': '6px',
                'radius_lg': '8px',
                
                # Transitions
                'transition_fast': '0.15s',
                'transition_normal': '0.25s'
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
                transition: background-color {theme['transition_fast']} ease;
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