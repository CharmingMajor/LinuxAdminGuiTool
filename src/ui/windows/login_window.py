from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Signal
import logging # Using standard logging for simple info messages here.

class LoginWindow(QMainWindow):
    # This class defines the login window that users first see.
    # It handles username/password input and emits a signal upon successful login.
    
    # Signal to notify the main application when login is successful.
    # It passes the username and role of the logged-in user.
    login_successful = Signal(str, str) # Changed to emit username and role
    
    def __init__(self):
        super().__init__()
        # Basic window setup is done in setup_ui
        self.setup_ui()
        
    def setup_ui(self):
        # Configures the appearance and widgets of the login window.
        self.setWindowTitle("Linux Admin GUI - Login")
        self.setFixedSize(400, 220) # Slightly adjusted height for better spacing
        
        # Create a central widget to hold all other UI elements.
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        # Use a QVBoxLayout to arrange widgets vertically.
        layout = QVBoxLayout(central_widget)
        
        # Username input field
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username (e.g., senior or junior)")
        layout.addWidget(username_label)
        layout.addWidget(self.username_input)
        
        # Password input field
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password (e.g., senior123 or junior123)")
        self.password_input.setEchoMode(QLineEdit.Password) # Mask password input
        layout.addWidget(password_label)
        layout.addWidget(self.password_input)
        
        # Login button
        login_button = QPushButton("Login")
        # Connect the button's clicked signal to the on_login method.
        login_button.clicked.connect(self.on_login)
        layout.addWidget(login_button)

        # Add a little note about demo credentials
        note_label = QLabel("Demo users: senior/senior123, junior/junior123")
        note_label.setStyleSheet("font-size: 9pt; color: grey;")
        layout.addWidget(note_label)
        
    def on_login(self):
        # This method is called when the login button is clicked.
        # It retrieves the entered username and password and attempts to authenticate.
        username = self.username_input.text().strip() # Remove leading/trailing whitespace
        password = self.password_input.text() # Password itself shouldn't be stripped usually
        
        # Basic validation: ensure fields are not empty.
        if not username or not password:
            QMessageBox.warning(self, "Login Error", "Please enter both username and password.")
            return
            
        # This is a placeholder for actual authentication logic.
        # In a real application, this would involve checking credentials against a secure store (e.g., database, LDAP).
        # For this demo, we use hardcoded credentials.
        # TODO: Replace with call to AuthBackend for real authentication
        if username == "senior" and password == "senior123":
            logging.info(f"Senior user '{username}' logged in.")
            self.login_successful.emit(username, "senior") # Emit username and role
            self.close() # Close the login window after successful login
        elif username == "junior" and password == "junior123":
            logging.info(f"Junior user '{username}' logged in.")
            self.login_successful.emit(username, "junior") # Emit username and role
            self.close() # Close the login window
        else:
            logging.warning(f"Failed login attempt for username: {username}")
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")
            # Optionally, clear password field after a failed attempt:
            # self.password_input.clear() 