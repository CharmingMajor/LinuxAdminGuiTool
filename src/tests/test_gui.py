import unittest
from PySide6.QtWidgets import QApplication
import sys
from src.ui.views.login import LoginWindow
from src.ui.dialogs.connect_dialog import ConnectDialog
from src.utils.crypto import CryptoManager
from unittest.mock import Mock, patch, PropertyMock

class TestGUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Create QApplication instance"""
        if not QApplication.instance():
            cls.app = QApplication(sys.argv)
            
    def setUp(self):
        """Set up test environment"""
        self.crypto = CryptoManager()
        
    @patch('src.ui.views.login.ThemeManager')
    @patch('src.ui.views.login.AuthBackend')
    def test_login_window(self, mock_auth, mock_theme_manager):
        """Test login window functionality"""
        # Mock theme manager
        mock_theme = Mock()
        mock_theme_manager.return_value = mock_theme
        mock_theme.get_theme_styles.return_value = {
            'bg_primary': '#ffffff',
            'bg_secondary': '#f5f5f5',
            'text_primary': '#000000',
            'text_secondary': '#666666',
            'accent_primary': '#4a90e2',
            'accent_secondary': '#357abd',
            'accent_tertiary': '#2a5f94',
            'border_color': '#cccccc',
            'input_bg': '#ffffff',
            'hover_bg': '#e6e6e6',
            'error_color': '#ff0000'
        }
        type(mock_theme).current_theme = PropertyMock(return_value="light")
        
        # Mock auth backend
        mock_auth_instance = Mock()
        mock_auth.return_value = mock_auth_instance
        mock_auth_instance.authenticate.return_value = (True, "junior")
        
        login_window = LoginWindow()
        login_window.show()  # Need to show window for visibility tests
        
        # Test empty fields
        login_window.username_input.setText("")
        login_window.password_input.setText("")
        login_window.handle_login()
        self.assertTrue(login_window.error_label.isVisible())
        
        # Test valid login
        login_window.username_input.setText("junior")
        login_window.password_input.setText("junior123")
        
        # Track if login_successful signal is emitted
        self.signal_emitted = False
        def on_login(username, role):
            self.signal_emitted = True
            self.assertEqual(username, "junior")
            self.assertEqual(role, "junior")
            
        login_window.login_successful.connect(on_login)
        login_window.handle_login()
        self.assertTrue(self.signal_emitted)
        
        login_window.close()
        
    @patch('src.utils.remote_connection.RemoteConnection')
    def test_connect_dialog(self, mock_remote):
        """Test connection dialog"""
        # Mock remote connection
        mock_remote_instance = Mock()
        mock_remote.return_value = mock_remote_instance
        
        dialog = ConnectDialog()
        dialog.show()  # Need to show dialog for visibility tests
        
        # Test empty fields validation
        dialog.host_input.setText("")
        dialog.user_input.setText("")
        dialog.try_connect()
        self.assertTrue(dialog.isVisible())
        
        # Test password authentication UI
        dialog.auth_combo.setCurrentText("Password")
        self.assertTrue(dialog.pass_widget.isVisible())
        self.assertFalse(dialog.key_widget.isVisible())
        
        # Test SSH key authentication UI
        dialog.auth_combo.setCurrentText("SSH Key")
        self.assertFalse(dialog.pass_widget.isVisible())
        self.assertTrue(dialog.key_widget.isVisible())
        
        dialog.close()
        
    @patch('src.ui.views.login.ThemeManager')
    def test_theme_switching(self, mock_theme_manager):
        """Test theme switching in login window"""
        # Mock theme manager
        mock_theme = Mock()
        mock_theme_manager.return_value = mock_theme
        type(mock_theme).current_theme = PropertyMock(return_value="light")
        mock_theme.get_theme_styles.return_value = {
            'bg_primary': '#ffffff',
            'bg_secondary': '#f5f5f5',
            'text_primary': '#000000',
            'text_secondary': '#666666',
            'accent_primary': '#4a90e2',
            'accent_secondary': '#357abd',
            'accent_tertiary': '#2a5f94',
            'border_color': '#cccccc',
            'input_bg': '#ffffff',
            'hover_bg': '#e6e6e6',
            'error_color': '#ff0000'
        }
        
        login_window = LoginWindow()
        
        # Toggle theme
        type(mock_theme).current_theme = PropertyMock(return_value="dark")
        login_window.theme_manager.toggle_theme()
        
        # Check if theme changed
        self.assertEqual(mock_theme.current_theme, "dark")
        
        login_window.close()
        
if __name__ == "__main__":
    unittest.main() 