import tkinter as tk
from tkinter import messagebox

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
        header_frame = tk.Frame(self)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, 
                 text=f"Configuring: {self.container_info['name']} ({self.role} view)", 
                 font=('Helvetica', 12, 'bold')).pack(side=tk.LEFT)
        
        tk.Button(header_frame, text="Back", command=self.return_to_main).pack(side=tk.RIGHT)
        
        # Configuration tabs - Create a simple tab system with radio buttons
        tab_frame = tk.Frame(self)
        tab_frame.pack(fill=tk.BOTH, expand=True)
        
        # Tab selector frame
        tab_selector = tk.Frame(tab_frame)
        tab_selector.pack(fill=tk.X)
        
        self.current_tab = tk.StringVar(value="System Info")
        
        tk.Radiobutton(tab_selector, text="System Info", variable=self.current_tab, 
                      value="System Info", command=self.show_tab).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(tab_selector, text="Services", variable=self.current_tab, 
                      value="Services", command=self.show_tab).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(tab_selector, text="Network", variable=self.current_tab, 
                      value="Network", command=self.show_tab).pack(side=tk.LEFT, padx=5)
        
        # Tab content frame
        self.tab_content = tk.Frame(tab_frame)
        self.tab_content.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create tab content frames - only one will be visible at a time
        self.system_tab = tk.Frame(self.tab_content)
        self.services_tab = tk.Frame(self.tab_content)
        self.network_tab = tk.Frame(self.tab_content)
        
        # Setup tab contents
        self.create_system_info_tab(self.system_tab)
        self.create_services_tab(self.services_tab)
        self.create_network_tab(self.network_tab)
        
        # Show default tab
        self.show_tab()

    def show_tab(self):
        # Hide all tab content first
        for widget in self.tab_content.winfo_children():
            widget.pack_forget()
        
        # Show the selected tab
        tab_name = self.current_tab.get()
        if tab_name == "System Info":
            self.system_tab.pack(fill=tk.BOTH, expand=True)
        elif tab_name == "Services":
            self.services_tab.pack(fill=tk.BOTH, expand=True)
        elif tab_name == "Network":
            self.network_tab.pack(fill=tk.BOTH, expand=True)

    def return_to_main(self):
        self.pack_forget()
        self.return_callback()

    def create_system_info_tab(self, parent):
        # System information display
        info_frame = tk.LabelFrame(parent, text="System Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add system info widgets (read-only for junior)
        tk.Label(info_frame, text=f"Container Name: {self.container_info['name']}").pack(anchor=tk.W)
        tk.Label(info_frame, text=f"Status: {self.container_info['status']}").pack(anchor=tk.W)
        tk.Label(info_frame, text=f"IP Address: {self.container_info['ip']}").pack(anchor=tk.W)
        
        # Add more system info as needed...

    def create_services_tab(self, parent):
        # Services information display
        services_frame = tk.LabelFrame(parent, text="Running Services")
        services_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Header for services list
        headers_frame = tk.Frame(services_frame)
        headers_frame.pack(fill=tk.X)
        
        tk.Label(headers_frame, text="Service", width=20, anchor=tk.W, 
                borderwidth=1, relief=tk.RIDGE).grid(row=0, column=0, sticky=tk.W)
        tk.Label(headers_frame, text="Status", width=10, anchor=tk.W, 
                borderwidth=1, relief=tk.RIDGE).grid(row=0, column=1, sticky=tk.W)
        
        # Services list frame
        services_list_frame = tk.Frame(services_frame)
        services_list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Populate with example data (in real app, fetch from container)
        services = [
            ("SSH", "Running"),
            ("Web Server", "Stopped"),
            ("Database", "Running")
        ]
        
        for i, (service, status) in enumerate(services):
            tk.Label(services_list_frame, text=service, width=20, anchor=tk.W).grid(row=i, column=0, sticky=tk.W)
            tk.Label(services_list_frame, text=status, width=10, anchor=tk.W).grid(row=i, column=1, sticky=tk.W)

    def create_network_tab(self, parent):
        # Network information display
        network_frame = tk.LabelFrame(parent, text="Network Configuration")
        network_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tk.Label(network_frame, text=f"IP: {self.container_info['ip']}").pack(anchor=tk.W)
        tk.Label(network_frame, text="Ports: 22 (SSH)").pack(anchor=tk.W)
        
        # Add more network info as needed...