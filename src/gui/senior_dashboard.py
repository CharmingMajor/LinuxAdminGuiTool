import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
from src.backend.virtual_pc_backend import VirtualPCManager
from src.gui.pc_connection import ssh_into_container

class SeniorDashboard(tk.Frame):
    def __init__(self, root, show_login_window):
        super().__init__(root)
        self.root = root
        self.show_login_window = show_login_window
        self.selected_containers = []
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
        self.root.title("Senior Admin Dashboard")
        self.pack(fill=tk.BOTH, expand=True)

        # Configure grid weights
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Main container frame
        main_frame = ttk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Senior Administrator Dashboard", 
                 font=('Helvetica', 14, 'bold')).pack(side=tk.LEFT)
        
        ttk.Button(header_frame, text="Logout", command=self.show_login_window).pack(side=tk.RIGHT)

        # Container management section
        management_frame = ttk.LabelFrame(main_frame, text="Container Management")
        management_frame.pack(fill=tk.BOTH, expand=True)

        # Treeview with scrollbars
        tree_frame = ttk.Frame(management_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.container_tree = ttk.Treeview(
            tree_frame, 
            columns=("name", "status", "ip", "image"), 
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        for col in ("name", "status", "ip", "image"):
            self.container_tree.heading(col, text=col.capitalize(), anchor=tk.W)
            self.container_tree.column(col, width=150, anchor=tk.W)

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.container_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.container_tree.xview)
        self.container_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout
        self.container_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Configure treeview grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Button panel
        button_frame = ttk.Frame(management_frame)
        button_frame.pack(fill=tk.X, pady=(5, 0))

        # Action buttons
        actions = [
            ("Refresh", self.refresh_containers),
            ("Start", self.start_containers),
            ("Stop", self.stop_containers),
            ("Restart", self.restart_containers),
            ("SSH", self.ssh_to_container),
            ("Inspect", self.inspect_container),
            ("Clean Up", self.cleanup_containers)
        ]

        for text, command in actions:
            ttk.Button(button_frame, text=text, command=command).pack(
                side=tk.LEFT, padx=2)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))

        # Configure treeview tags for status coloring
        self.container_tree.tag_configure('running', background='#e6ffe6')
        self.container_tree.tag_configure('exited', background='#ffe6e6')
        self.container_tree.tag_configure('dead', background='#ffcccc')

    def refresh_containers(self):
        try:
            self.container_tree.delete(*self.container_tree.get_children())
            containers = self.virtual_pc_manager.list_containers(show_all=True)

            for container in containers:
                status = container.get('status', 'unknown').lower()
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

            self.status_var.set(f"Loaded {len(containers)} containers")
        except Exception as e:
            messagebox.showerror("Refresh Error", 
                               f"Failed to refresh containers:\n{str(e)}")
            self.status_var.set("Refresh failed")

    def get_selected_containers(self):
        return [self.container_tree.item(item)['values'][0] 
                for item in self.container_tree.selection()]

    def start_containers(self):
        self._container_operation("start")

    def stop_containers(self):
        self._container_operation("stop")

    def restart_containers(self):
        self._container_operation("restart")

    def _container_operation(self, operation):
        selected = self.get_selected_containers()
        if not selected:
            messagebox.showwarning("Selection Required", 
                                "Please select at least one container")
            return

        try:
            results = {}
            for container_name in selected:
                try:
                    container = self.virtual_pc_manager.client.containers.get(container_name)
                    getattr(container, operation)()
                    results[container_name] = "Success"
                except Exception as e:
                    results[container_name] = f"Failed: {str(e)}"

            self.show_operation_results(f"{operation.capitalize()} Results", results)
            self.refresh_containers()
        except Exception as e:
            messagebox.showerror("Operation Failed", 
                               f"Failed to {operation} containers:\n{str(e)}")

    def ssh_to_container(self):
        selected = self.get_selected_containers()
        if len(selected) != 1:
            messagebox.showwarning("Selection Error", 
                                 "Please select exactly one container")
            return

        container_name = selected[0]
        try:
            # Get container details
            container = self.virtual_pc_manager.client.containers.get(container_name)
            ip = container.attrs['NetworkSettings']['Networks'].get(
                'admin-network', {}).get('IPAddress', 'N/A')

            # Show SSH dialog
            ssh_dialog = tk.Toplevel()
            ssh_dialog.title(f"SSH to {container_name}")
            
            # SSH connection form
            ttk.Label(ssh_dialog, text="Username:").grid(row=0, column=0, padx=5, pady=5)
            username_entry = ttk.Entry(ssh_dialog)
            username_entry.grid(row=0, column=1, padx=5, pady=5)
            username_entry.insert(0, "root")

            ttk.Label(ssh_dialog, text="Password:").grid(row=1, column=0, padx=5, pady=5)
            password_entry = ttk.Entry(ssh_dialog, show="*")
            password_entry.grid(row=1, column=1, padx=5, pady=5)
            password_entry.insert(0, "password")

            def connect_ssh():
                output, error = ssh_into_container(
                    container_name=container_name,
                    username=username_entry.get(),
                    password=password_entry.get(),
                    role="senior"
                )
                
                # Show output in new window
                result_window = tk.Toplevel()
                result_window.title(f"SSH Results - {container_name}")
                
                text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
                text.pack(fill=tk.BOTH, expand=True)
                
                if error:
                    text.insert(tk.END, f"Error:\n{error}\n\n")
                if output:
                    text.insert(tk.END, f"Output:\n{output}")
                
                text.config(state=tk.DISABLED)

            ttk.Button(ssh_dialog, text="Connect", 
                      command=connect_ssh).grid(row=2, column=1, pady=10)

        except Exception as e:
            messagebox.showerror("SSH Error", 
                               f"Failed to prepare SSH connection:\n{str(e)}")

    def inspect_container(self):
        selected = self.get_selected_containers()
        if len(selected) != 1:
            messagebox.showwarning("Selection Error", 
                                "Please select exactly one container")
            return

        try:
            container_name = selected[0]
            container = self.virtual_pc_manager.client.containers.get(container_name)
            details = container.attrs

            detail_window = tk.Toplevel()
            detail_window.title(f"Container Details: {container_name}")

            text = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True)
            
            text.insert(tk.END, json.dumps(details, indent=2))
            text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Inspection Failed", 
                               f"Failed to inspect container:\n{str(e)}")

    def cleanup_containers(self):
        try:
            containers = self.virtual_pc_manager.list_containers(show_all=True)
            dead_containers = [
                c['name'] for c in containers 
                if 'dead' in c.get('status', '').lower() 
                or 'exited' in c.get('status', '').lower()
            ]

            if not dead_containers:
                messagebox.showinfo("Cleanup", "No dead/exited containers found")
                return

            if messagebox.askyesno(
                "Confirm Cleanup", 
                f"Remove {len(dead_containers)} dead/exited containers?"
            ):
                results = {}
                for name in dead_containers:
                    try:
                        container = self.virtual_pc_manager.client.containers.get(name)
                        container.remove(force=True)
                        results[name] = "Removed"
                    except Exception as e:
                        results[name] = f"Failed: {str(e)}"

                self.show_operation_results("Cleanup Results", results)
                self.refresh_containers()
        except Exception as e:
            messagebox.showerror("Cleanup Failed", 
                               f"Failed to clean up containers:\n{str(e)}")

    def show_operation_results(self, title, results):
        result_window = tk.Toplevel()
        result_window.title(title)

        text = scrolledtext.ScrolledText(result_window, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True)

        for container, result in results.items():
            text.insert(tk.END, f"{container}: {result}\n")

        text.config(state=tk.DISABLED)