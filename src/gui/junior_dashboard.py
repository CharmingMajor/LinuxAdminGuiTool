import tkinter as tk
from tkinter import ttk, messagebox
from src.backend.virtual_pc_backend import VirtualPCManager
from src.gui.pc_connection import ssh_into_container

class JuniorDashboard(tk.Frame):
    def __init__(self, root, show_login_window):
        super().__init__(root)
        self.root = root
        self.show_login_window = show_login_window
        self.virtual_pc_manager = VirtualPCManager()
        self.setup_ui()

    def setup_ui(self):
        # Welcome message
        self.welcome_label = tk.Label(self, text="Welcome, Junior Admin!")
        self.welcome_label.pack(pady=10)

        # Docker container management section (view-only)
        self.docker_frame = tk.LabelFrame(self, text="Docker Container Management (View Only)")
        self.docker_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # List of containers
        self.container_tree = ttk.Treeview(self.docker_frame, columns=("Name", "Status", "IP"), show="headings")
        self.container_tree.heading("Name", text="Name")
        self.container_tree.heading("Status", text="Status")
        self.container_tree.heading("IP", text="IP")
        self.container_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Refresh button
        self.refresh_button = tk.Button(self.docker_frame, text="Refresh", command=self.refresh_containers)
        self.refresh_button.pack(pady=5)

        # SSH button (limited permissions)
        self.ssh_button = tk.Button(self.docker_frame, text="SSH into Container", command=self.ssh_into_container)
        self.ssh_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Logout button
        self.logout_button = tk.Button(self, text="Logout", command=self.show_login_window)
        self.logout_button.pack(pady=10)

        # Populate the container list
        self.refresh_containers()

    def refresh_containers(self):
        """Refresh the list of Docker containers."""
        self.container_tree.delete(*self.container_tree.get_children())  # Clear the list
        containers = self.virtual_pc_manager.list_containers()
        for container in containers:
            self.container_tree.insert("", tk.END, values=(container.name, container.status, container.attrs["NetworkSettings"]["IPAddress"]))

    def ssh_into_container(self):
        """SSH into a selected Docker container with limited permissions."""
        selected_item = self.container_tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a container to SSH into.")
            return

        container_ip = self.container_tree.item(selected_item, "values")[2]

        # Junior admins can only execute basic commands (e.g., view logs)
        output, error = ssh_into_container(container_ip, "root", "root", "ls -l /var/log")
        if output:
            messagebox.showinfo("SSH Output", output)
        else:
            messagebox.showerror("SSH Error", error)