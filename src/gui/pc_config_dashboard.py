import tkinter as tk
from tkinter import ttk, messagebox

class PCConfigDashboard(tk.Frame):
    def __init__(self, root, container_info, return_callback):
        super().__init__(root)
        self.container_info = container_info
        self.return_callback = return_callback
        self.role = container_info.get('role', 'junior')
        self.setup_ui()

    def setup_ui(self):
        self.root.title(f"Container Config - {self.container_info['name']}")
        self.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, 
                 text=f"Configuring: {self.container_info['name']} ({self.role} view)", 
                 font=('Helvetica', 12, 'bold')).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Back", command=self.return_to_main).pack(side=tk.RIGHT)
        
        # Configuration tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # System Info Tab
        info_tab = ttk.Frame(notebook)
        self.create_system_info_tab(info_tab)
        notebook.add(info_tab, text="System Info")
        
        # Services Tab (only basic info for junior)
        services_tab = ttk.Frame(notebook)
        self.create_services_tab(services_tab)
        notebook.add(services_tab, text="Services")
        
        # Network Tab
        network_tab = ttk.Frame(notebook)
        self.create_network_tab(network_tab)
        notebook.add(network_tab, text="Network")
        
        # Add more tabs as needed...

    def create_system_info_tab(self, parent):
        # System information display
        info_frame = ttk.LabelFrame(parent, text="System Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add system info widgets (read-only for junior)
        ttk.Label(info_frame, text=f"Container Name: {self.container_info['name']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"Status: {self.container_info['status']}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"IP Address: {self.container_info['ip']}").pack(anchor=tk.W)
        
        # Add more system info as needed...

    def create_services_tab(self, parent):
        # Services information display
        services_frame = ttk.LabelFrame(parent, text="Running Services")
        services_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview for services
        tree = ttk.Treeview(services_frame, columns=("service", "status"), show="headings")
        tree.heading("service", text="Service")
        tree.heading("status", text="Status")
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate with example data (in real app, fetch from container)
        services = [
            ("SSH", "Running"),
            ("Web Server", "Stopped"),
            ("Database", "Running")
        ]
        
        for service, status in services:
            tree.insert("", tk.END, values=(service, status))

    def create_network_tab(self, parent):
        # Network information display
        network_frame = ttk.LabelFrame(parent, text="Network Configuration")
        network_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(network_frame, text=f"IP: {self.container_info['ip']}").pack(anchor=tk.W)
        ttk.Label(network_frame, text="Ports: 22 (SSH)").pack(anchor=tk.W)
        
        # Add more network info as needed...

    def return_to_main(self):
        self.pack_forget()
        self.return_callback()