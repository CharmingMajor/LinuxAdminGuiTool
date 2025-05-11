from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QLabel, QLineEdit, QPushButton, QMessageBox
from PySide6.QtCore import Signal
import logging

class LoginWindow(QMainWindow):
    """Login window for the application"""
    
    login_successful = Signal(str)  # Signal emits the role
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the login window UI"""
        self.setWindowTitle("Linux Admin GUI - Login")
        self.setFixedSize(400, 200)
        
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Username input
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        layout.addWidget(username_label)
        layout.addWidget(self.username_input)
        
        # Password input
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(password_label)
        layout.addWidget(self.password_input)
        
        # Login button
        login_button = QPushButton("Login")
        login_button.clicked.connect(self.on_login)
        layout.addWidget(login_button)
        
    def on_login(self):
        """Handle login button click"""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please fill in all fields")
            return
            
        # Verify credentials (simplified for demo)
        if username == "senior" and password == "senior123":
            logging.info("Login successful", role="senior", username=username)
            self.login_successful.emit("senior")
        elif username == "junior" and password == "junior123":
            logging.info("Login successful", role="junior", username=username)
            self.login_successful.emit("junior")
        else:
            QMessageBox.warning(self, "Error", "Invalid credentials") 