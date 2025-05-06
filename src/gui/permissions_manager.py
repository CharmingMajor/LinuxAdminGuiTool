import tkinter as tk
from tkinter import messagebox, filedialog
import logging
import os

class PermissionsManager:
    def __init__(self, parent, senior_backend):
        self.logger = logging.getLogger(__name__)
        self.parent = parent
        self.backend = senior_backend
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("File Permissions Manager")
        self.dialog.geometry("700x500")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface"""
        main_frame = tk.Frame(self.dialog, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Path selection
        path_frame = tk.LabelFrame(main_frame, text="File/Directory Path")
        path_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(path_frame, text="Path:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.path_var = tk.StringVar()
        path_entry = tk.Entry(path_frame, textvariable=self.path_var, width=50)
        path_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        tk.Button(path_frame, text="Browse", command=self.browse_path).grid(row=0, column=2, padx=5, pady=5)
        
        path_frame.columnconfigure(1, weight=1)
        
        # Permissions frame
        perm_frame = tk.LabelFrame(main_frame, text="File Permissions")
        perm_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Owner/Group selection
        tk.Label(perm_frame, text="Owner:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.owner_var = tk.StringVar()
        tk.Entry(perm_frame, textvariable=self.owner_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        tk.Label(perm_frame, text="Group:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.group_var = tk.StringVar()
        tk.Entry(perm_frame, textvariable=self.group_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Permissions checkboxes
        self.perm_frame = tk.LabelFrame(perm_frame, text="Permission Modes")
        self.perm_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.NSEW)
        
        # Permission variables
        self.perm_vars = {
            'owner': {
                'read': tk.BooleanVar(value=True),
                'write': tk.BooleanVar(value=True),
                'execute': tk.BooleanVar(value=False)
            },
            'group': {
                'read': tk.BooleanVar(value=True),
                'write': tk.BooleanVar(value=False),
                'execute': tk.BooleanVar(value=False)
            },
            'others': {
                'read': tk.BooleanVar(value=True),
                'write': tk.BooleanVar(value=False),
                'execute': tk.BooleanVar(value=False)
            }
        }
        
        # Headers
        tk.Label(self.perm_frame, text="").grid(row=0, column=0)
        tk.Label(self.perm_frame, text="Read").grid(row=0, column=1)
        tk.Label(self.perm_frame, text="Write").grid(row=0, column=2)
        tk.Label(self.perm_frame, text="Execute").grid(row=0, column=3)
        
        # Owner permissions
        tk.Label(self.perm_frame, text="Owner").grid(row=1, column=0, sticky=tk.W)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['owner']['read']).grid(row=1, column=1)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['owner']['write']).grid(row=1, column=2)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['owner']['execute']).grid(row=1, column=3)
        
        # Group permissions
        tk.Label(self.perm_frame, text="Group").grid(row=2, column=0, sticky=tk.W)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['group']['read']).grid(row=2, column=1)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['group']['write']).grid(row=2, column=2)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['group']['execute']).grid(row=2, column=3)
        
        # Others permissions
        tk.Label(self.perm_frame, text="Others").grid(row=3, column=0, sticky=tk.W)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['others']['read']).grid(row=3, column=1)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['others']['write']).grid(row=3, column=2)
        tk.Checkbutton(self.perm_frame, variable=self.perm_vars['others']['execute']).grid(row=3, column=3)
        
        # Mode display
        tk.Label(perm_frame, text="Numeric Mode:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.mode_var = tk.StringVar(value="644")
        mode_display = tk.Entry(perm_frame, textvariable=self.mode_var)
        mode_display.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Update mode when checkboxes change
        for entity in self.perm_vars:
            for perm in self.perm_vars[entity]:
                self.perm_vars[entity][perm].trace_add("write", self.update_mode_display)
        
        # Update checkboxes when mode changes
        self.mode_var.trace_add("write", self.update_checkboxes)
        
        # Expandable areas
        perm_frame.columnconfigure(1, weight=1)
        perm_frame.rowconfigure(2, weight=1)
        
        # Action buttons
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        tk.Button(button_frame, text="Apply Permissions", command=self.apply_permissions).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Close", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=5)
    
    def browse_path(self):
        """Open file browser to select path"""
        path = filedialog.askdirectory(title="Select Directory")
        if path:
            self.path_var.set(path)
    
    def update_mode_display(self, *args):
        """Update the numeric mode display based on checkboxes"""
        try:
            owner = 0
            if self.perm_vars['owner']['read'].get():
                owner += 4
            if self.perm_vars['owner']['write'].get():
                owner += 2
            if self.perm_vars['owner']['execute'].get():
                owner += 1
                
            group = 0
            if self.perm_vars['group']['read'].get():
                group += 4
            if self.perm_vars['group']['write'].get():
                group += 2
            if self.perm_vars['group']['execute'].get():
                group += 1
                
            others = 0
            if self.perm_vars['others']['read'].get():
                others += 4
            if self.perm_vars['others']['write'].get():
                others += 2
            if self.perm_vars['others']['execute'].get():
                others += 1
                
            mode = f"{owner}{group}{others}"
            self.mode_var.set(mode)
        except:
            pass
    
    def update_checkboxes(self, *args):
        """Update checkboxes based on numeric mode"""
        try:
            mode = self.mode_var.get()
            if len(mode) != 3 or not mode.isdigit():
                return
                
            owner = int(mode[0])
            group = int(mode[1])
            others = int(mode[2])
            
            # Update owner checkboxes
            self.perm_vars['owner']['read'].set(owner & 4 > 0)
            self.perm_vars['owner']['write'].set(owner & 2 > 0)
            self.perm_vars['owner']['execute'].set(owner & 1 > 0)
            
            # Update group checkboxes
            self.perm_vars['group']['read'].set(group & 4 > 0)
            self.perm_vars['group']['write'].set(group & 2 > 0)
            self.perm_vars['group']['execute'].set(group & 1 > 0)
            
            # Update others checkboxes
            self.perm_vars['others']['read'].set(others & 4 > 0)
            self.perm_vars['others']['write'].set(others & 2 > 0)
            self.perm_vars['others']['execute'].set(others & 1 > 0)
        except:
            pass
    
    def apply_permissions(self):
        """Apply the permissions to the selected path"""
        path = self.path_var.get().strip()
        owner = self.owner_var.get().strip()
        group = self.group_var.get().strip()
        mode = self.mode_var.get().strip()
        
        if not path:
            messagebox.showerror("Error", "Please select a path")
            return
        
        try:
            result, error = self.backend.set_permissions(
                path=path,
                mode=mode if mode else None,
                owner=owner if owner else None,
                group=group if group else None
            )
            
            if error:
                messagebox.showerror("Error", f"Failed to set permissions: {error}")
            else:
                messagebox.showinfo("Success", "Permissions updated successfully")
        except Exception as e:
            self.logger.error(f"Error setting permissions: {str(e)}")
            messagebox.showerror("Error", f"Error setting permissions: {str(e)}") 