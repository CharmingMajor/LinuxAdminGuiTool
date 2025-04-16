import tkinter as tk
from tkinter import ttk, messagebox
from src.backend.virtual_pc_backend import VirtualPCManager

class VirtualPCManagerGUI(tk.Frame):
    def __init__(self, root):
        super().__init__(root)
        try:
            self.virtual_pc_manager = VirtualPCManager()
            self.setup_ui()
        except Exception as e:
            messagebox.showerror("Docker Error", str(e))
            self.destroy()

    def setup_ui(self):
        """Initialize the UI components"""
        self.docker_frame = tk.LabelFrame(self, text="Docker Container Management")
        self.docker_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Treeview setup
        self.container_tree = ttk.Treeview(
            self.docker_frame, 
            columns=("Name", "Status", "IP"), 
            show="headings"
        )
        self.container_tree.heading("Name", text="Name")
        self.container_tree.heading("Status", text="Status")
        self.container_tree.heading("IP", text="IP")
        self.container_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Buttons
        self.refresh_button = tk.Button(
            self.docker_frame, 
            text="Refresh", 
            command=self.refresh_containers
        )
        self.refresh_button.pack(pady=5)

        self.start_button = tk.Button(
            self.docker_frame,
            text="Start Container",
            command=self.start_container
        )
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = tk.Button(
            self.docker_frame,
            text="Stop Container",
            command=self.stop_container
        )
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.refresh_containers()

    def refresh_containers(self):
        """Refresh the container list with error handling"""
        try:
            self.container_tree.delete(*self.container_tree.get_children())
            containers = self.virtual_pc_manager.list_containers()
            for container in containers:
                networks = container.attrs["NetworkSettings"]["Networks"]
                ip = networks.get("admin-network", {}).get("IPAddress", "N/A")
                self.container_tree.insert(
                    "", 
                    tk.END, 
                    values=(container.name, container.status, ip)
                )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh containers: {str(e)}")

    def start_container(self):
        """Start the selected container"""
        selected_item = self.container_tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a container to start.")
            return

        container_name = self.container_tree.item(selected_item, "values")[0]
        try:
            if self.virtual_pc_manager.start_container(container_name):
                messagebox.showinfo("Success", f"Container {container_name} started")
            else:
                messagebox.showerror("Error", f"Failed to start {container_name}")
            self.refresh_containers()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def stop_container(self):
        """Stop the selected container"""
        selected_item = self.container_tree.selection()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a container to stop.")
            return

        container_name = self.container_tree.item(selected_item, "values")[0]
        try:
            if self.virtual_pc_manager.stop_container(container_name):
                messagebox.showinfo("Success", f"Container {container_name} stopped")
            else:
                messagebox.showerror("Error", f"Failed to stop {container_name}")
            self.refresh_containers()
        except Exception as e:
            messagebox.showerror("Error", str(e))