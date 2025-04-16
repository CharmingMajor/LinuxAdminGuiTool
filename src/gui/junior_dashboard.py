import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
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
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Junior Administrator Dashboard", 
                 font=('Helvetica', 14, 'bold')).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Logout", command=self.show_login_window).pack(side=tk.RIGHT)
        
        # Container view section (now shows all containers like senior dashboard)
        view_frame = ttk.LabelFrame(main_frame, text="Container Monitoring (View Only)")
        view_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview with scrollbars
        tree_frame = ttk.Frame(view_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        self.container_tree = ttk.Treeview(
            tree_frame, 
            columns=("name", "status", "ip", "image"), 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        columns = [
            ("name", "Container Name", 150),
            ("status", "Status", 100),
            ("ip", "IP Address", 120),
            ("image", "Image", 200)
        ]
        
        for col, heading, width in columns:
            self.container_tree.heading(col, text=heading, anchor=tk.W)
            self.container_tree.column(col, width=width, anchor=tk.W)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.container_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.container_tree.xview)
        self.container_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.container_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Button panel (with View Config button)
        button_frame = ttk.Frame(view_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_containers).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="View Logs", command=self.view_container_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="View Config", command=self.view_container_config).pack(side=tk.LEFT, padx=2)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        self.status_var.set("Ready - View Mode")
        
        # Configure tags for status coloring
        self.container_tree.tag_configure('running', background='#e6ffe6')
        self.container_tree.tag_configure('exited', background='#ffe6e6')
        self.container_tree.tag_configure('dead', background='#ffcccc')

    def refresh_containers(self):
        """Refresh container list showing all containers (like senior dashboard)"""
        try:
            self.container_tree.delete(*self.container_tree.get_children())
            containers = self.virtual_pc_manager.list_containers(show_all=True)  # Show all containers
            
            for container in containers:
                status = container.get('status', '').lower()
                tags = ()
                
                if 'running' in status:
                    tags = ('running',)
                elif 'exited' in status:
                    tags = ('exited',)
                elif 'dead' in status or 'removed' in status:
                    tags = ('dead',)
                
                self.container_tree.insert("", tk.END,
                    values=(
                        container.get('name', 'N/A'),
                        container.get('status', 'N/A'),
                        container.get('ip', 'N/A'),
                        container.get('image', 'N/A')
                    ),
                    tags=tags
                )
            
            self.status_var.set(f"Showing {len(containers)} containers (read-only)")
        except Exception as e:
            messagebox.showerror("Refresh Error", f"Failed to refresh containers:\n{str(e)}")
            self.status_var.set("Refresh failed")

    def view_container_logs(self):
        """View logs for selected container (read-only)"""
        selected = self.container_tree.selection()
        if not selected:
            messagebox.showwarning("Selection Required", "Please select a container first")
            return
            
        container_name = self.container_tree.item(selected)['values'][0]
        
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
        selected = self.container_tree.selection()
        if not selected:
            messagebox.showwarning("Selection Required", "Please select a container first")
            return
            
        container_name = self.container_tree.item(selected)['values'][0]
        container_status = self.container_tree.item(selected)['values'][1]
        container_ip = self.container_tree.item(selected)['values'][2]
        
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