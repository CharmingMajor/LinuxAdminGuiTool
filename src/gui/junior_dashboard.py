import tkinter as tk
from tkinter import messagebox, scrolledtext
from src.backend.virtual_pc_backend import VirtualPCManager
from src.gui.pc_config_dashboard import PCConfigDashboard  # New import for config dashboard

class JuniorDashboard(tk.Frame):
    def __init__(self, root, show_login_window):
        super().__init__(root)
        self.root = root
        self.show_login_window = show_login_window
        self.setup_ui()
        self.initialize_backend()
        self.refresh_containers()

    def initialize_backend(self):
        try:
            self.virtual_pc_manager = VirtualPCManager()
        except Exception as e:
            messagebox.showerror("Initialization Error", 
                               f"Failed to initialize Docker client:\n{str(e)}")
            self.show_login_window()

    def setup_ui(self):
        self.root.title("Junior Admin Dashboard")
        self.pack(fill=tk.BOTH, expand=True)
        
        # Main container frame
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = tk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(header_frame, text="Junior Administrator Dashboard", 
                 font=('Helvetica', 14, 'bold')).pack(side=tk.LEFT)
        
        tk.Button(header_frame, text="Logout", command=self.show_login_window).pack(side=tk.RIGHT)
        
        # Container view section (now shows all containers like senior dashboard)
        view_frame = tk.LabelFrame(main_frame, text="Container Monitoring (View Only)")
        view_frame.pack(fill=tk.BOTH, expand=True)
        
        # Listbox with scrollbars
        tree_frame = tk.Frame(view_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Headers frame
        headers_frame = tk.Frame(tree_frame)
        headers_frame.grid(row=0, column=0, sticky="ew")
        
        # Create header labels
        column_widths = {'name': 20, 'status': 15, 'ip': 15, 'image': 30}
        tk.Label(headers_frame, text="Container Name", width=column_widths['name'], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=0, sticky=tk.W)
        tk.Label(headers_frame, text="Status", width=column_widths['status'], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=1, sticky=tk.W)
        tk.Label(headers_frame, text="IP Address", width=column_widths['ip'], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=2, sticky=tk.W)
        tk.Label(headers_frame, text="Image", width=column_widths['image'], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=3, sticky=tk.W)
        
        # Container listbox
        self.container_tree = tk.Listbox(tree_frame, height=15)
        
        # Scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical", command=self.container_tree.yview)
        hsb = tk.Scrollbar(tree_frame, orient="horizontal", command=self.container_tree.xview)
        self.container_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.container_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(1, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Button panel (with View Config button)
        button_frame = tk.Frame(view_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))
        
        tk.Button(button_frame, text="Refresh", command=self.refresh_containers).pack(side=tk.LEFT, padx=2)
        tk.Button(button_frame, text="View Logs", command=self.view_container_logs).pack(side=tk.LEFT, padx=2)
        tk.Button(button_frame, text="View Config", command=self.view_container_config).pack(side=tk.LEFT, padx=2)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = tk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        self.status_var.set("Ready - View Mode")
        
        # Dictionary to store container data
        self.container_data = {}

    def refresh_containers(self):
        """Refresh container list showing all containers (like senior dashboard)"""
        try:
            self.container_tree.delete(0, tk.END)
            self.container_data = {}
            containers = self.virtual_pc_manager.list_containers(show_all=True)  # Show all containers
            
            for i, container in enumerate(containers):
                status = container.get('status', '').lower()
                display_text = f"{container.get('name', 'N/A'):<20} {container.get('status', 'N/A'):<15} {container.get('ip', 'N/A'):<15} {container.get('image', 'N/A'):<30}"
                
                # Store container data for selection
                self.container_data[i] = container
                
                # Add to listbox with different background colors based on status
                self.container_tree.insert(tk.END, display_text)
                
                # Set colors based on status
                if 'running' in status:
                    self.container_tree.itemconfig(i, {'bg': '#e6ffe6'})
                elif 'exited' in status:
                    self.container_tree.itemconfig(i, {'bg': '#ffe6e6'})
                elif 'dead' in status or 'removed' in status:
                    self.container_tree.itemconfig(i, {'bg': '#ffcccc'})
            
            self.status_var.set(f"Showing {len(containers)} containers (read-only)")
        except Exception as e:
            messagebox.showerror("Refresh Error", f"Failed to refresh containers:\n{str(e)}")
            self.status_var.set("Refresh failed")

    def view_container_logs(self):
        """View logs for selected container (read-only)"""
        selection = self.container_tree.curselection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select a container first")
            return
            
        idx = selection[0]
        if idx not in self.container_data:
            messagebox.showwarning("Invalid Selection", "Container data not found")
            return
            
        container_name = self.container_data[idx].get('name', '')
        
        try:
            logs = self.virtual_pc_manager.get_container_logs(container_name)
            
            log_window = tk.Toplevel()
            log_window.title(f"Logs: {container_name} (Read Only)")
            
            text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=80, height=25)
            text.pack(fill=tk.BOTH, expand=True)
            
            text.insert(tk.END, logs if logs else "No logs available")
            text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Log Error", f"Failed to get logs:\n{str(e)}")

    def view_container_config(self):
        """Open configuration dashboard for selected container"""
        selection = self.container_tree.curselection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select a container first")
            return
            
        idx = selection[0]
        if idx not in self.container_data:
            messagebox.showwarning("Invalid Selection", "Container data not found")
            return
            
        container = self.container_data[idx]
        container_name = container.get('name', '')
        container_status = container.get('status', '')
        container_ip = container.get('ip', '')
        
        # Create container info dictionary
        container_info = {
            'name': container_name,
            'status': container_status,
            'ip': container_ip,
            'role': 'junior'  # Pass role to limit functionality in config dashboard
        }
        
        # Hide current dashboard and show config dashboard
        self.pack_forget()
        PCConfigDashboard(
            root=self.root,
            container_info=container_info,
            return_callback=lambda: self.pack(fill=tk.BOTH, expand=True)
        )