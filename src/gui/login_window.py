# Updated login_window.py
import tkinter as tk
from tkinter import messagebox
import time

class LoginWindow(tk.Frame):
    def __init__(self, root, auth_backend, on_login_success):
        super().__init__(root)
        self.auth_backend = auth_backend
        self.on_login_success = on_login_success
        self.setup_ui()

    def setup_ui(self):
        # Add UI elements for login
        self.username_label = tk.Label(self, text="Username:")
        self.username_label.pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.password_label = tk.Label(self, text="Password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self, text="Login", command=self.on_login)
        self.login_button.pack()

    def on_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        ip = "127.0.0.1"  # In real app, get client IP

        # Authenticate the user
        success, result = self.auth_backend.authenticate(username, password, ip)
        
        if success:
            self.on_login_success(username, result)
        else:
            if result == "ip_blocked":
                messagebox.showerror("Login Failed", "Your IP is temporarily blocked due to too many failed attempts. Please try again later.")
            elif result == "account_locked":
                messagebox.showerror("Login Failed", "Account locked due to too many failed attempts.")
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")