import tkinter as tk
from tkinter import messagebox
import logging

class UserManagementDialog:
    def __init__(self, parent, senior_backend):
        self.logger = logging.getLogger(__name__)
        self.parent = parent
        self.backend = senior_backend
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("User Management")
        self.dialog.geometry("800x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Initialize frames first to avoid AttributeError
        self.user_frame = tk.Frame(self.dialog)
        self.group_frame = tk.Frame(self.dialog)
        
        self.setup_ui()
        self.refresh_users()
        self.refresh_groups()
        
    def setup_ui(self):
        """Set up the user interface"""
        # Main container
        self.notebook = tk.Frame(self.dialog)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tab buttons at the top
        tab_button_frame = tk.Frame(self.notebook)
        tab_button_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.current_tab = tk.StringVar(value="Users")
        
        tk.Radiobutton(tab_button_frame, text="Users", variable=self.current_tab, 
                      value="Users", command=self.show_tab).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(tab_button_frame, text="Groups", variable=self.current_tab, 
                      value="Groups", command=self.show_tab).pack(side=tk.LEFT, padx=5)
        
        # Setup tabs
        self.setup_user_tab(self.user_frame)
        self.setup_group_tab(self.group_frame)
        
        # Show default tab
        self.show_tab()
        
        # Button at bottom to close dialog
        close_button = tk.Button(self.dialog, text="Close", command=self.dialog.destroy)
        close_button.pack(pady=10)
    
    def show_tab(self):
        """Show the selected tab and hide others"""
        tab = self.current_tab.get()
        
        # Hide all frames first
        self.user_frame.pack_forget()
        self.group_frame.pack_forget()
        
        # Show the selected frame
        if tab == "Users":
            self.user_frame.pack(fill=tk.BOTH, expand=True)
        elif tab == "Groups":
            self.group_frame.pack(fill=tk.BOTH, expand=True)
        
    def setup_user_tab(self, parent):
        """Set up the user management tab"""
        # Create left and right frames directly instead of using PanedWindow
        left_frame = tk.Frame(parent, width=500)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        right_frame = tk.LabelFrame(parent, text="User Actions", width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        # User Listbox with scrollbar
        user_frame = tk.Frame(left_frame)
        user_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Headers frame
        headers_frame = tk.Frame(user_frame)
        headers_frame.grid(row=0, column=0, sticky="ew")
        
        # Create header labels
        col_widths = {"username": 15, "uid": 8, "gid": 8, "home": 25, "shell": 25}
        tk.Label(headers_frame, text="Username", width=col_widths["username"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=0, sticky=tk.W)
        tk.Label(headers_frame, text="UID", width=col_widths["uid"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=1, sticky=tk.W)
        tk.Label(headers_frame, text="GID", width=col_widths["gid"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=2, sticky=tk.W)
        tk.Label(headers_frame, text="Home", width=col_widths["home"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=3, sticky=tk.W)
        tk.Label(headers_frame, text="Shell", width=col_widths["shell"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=4, sticky=tk.W)
        
        # User listbox
        self.user_list = tk.Listbox(user_frame, height=15)
        
        # Scrollbars
        vsb = tk.Scrollbar(user_frame, orient="vertical", command=self.user_list.yview)
        hsb = tk.Scrollbar(user_frame, orient="horizontal", command=self.user_list.xview)
        self.user_list.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.user_list.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")
        
        user_frame.grid_rowconfigure(1, weight=1)
        user_frame.grid_columnconfigure(0, weight=1)
        
        # Refresh button
        refresh_button = tk.Button(left_frame, text="Refresh Users", command=self.refresh_users)
        refresh_button.pack(pady=5)
        
        # User form
        tk.Label(right_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.username_var).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        tk.Label(right_frame, text="Home Directory:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.home_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.home_var).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        
        tk.Label(right_frame, text="Shell:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.shell_var = tk.StringVar(value="/bin/bash")
        tk.Entry(right_frame, textvariable=self.shell_var).grid(row=2, column=1, sticky=tk.EW, padx=5, pady=5)
        
        tk.Label(right_frame, text="Groups:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.groups_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.groups_var).grid(row=3, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Action buttons
        button_frame = tk.Frame(right_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        tk.Button(button_frame, text="Create User", command=self.create_user).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Modify User", command=self.modify_user).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Delete User", command=self.delete_user).pack(side=tk.LEFT, padx=5)
        
        # Set to selected user
        self.user_list.bind("<<ListboxSelect>>", self.on_user_select)
        
        # Make the columns expandable
        right_frame.columnconfigure(1, weight=1)
        
        # Dictionary to store user data
        self.user_data = {}
        
    def setup_group_tab(self, parent):
        """Set up the group management tab"""
        # Create left and right frames directly instead of using PanedWindow
        left_frame = tk.Frame(parent, width=500)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        right_frame = tk.LabelFrame(parent, text="Group Actions", width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=5, pady=5)
        
        # Group Listbox with scrollbar
        group_frame = tk.Frame(left_frame)
        group_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Headers frame
        headers_frame = tk.Frame(group_frame)
        headers_frame.grid(row=0, column=0, sticky="ew")
        
        # Create header labels
        col_widths = {"name": 15, "gid": 8, "members": 40}
        tk.Label(headers_frame, text="Group Name", width=col_widths["name"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=0, sticky=tk.W)
        tk.Label(headers_frame, text="GID", width=col_widths["gid"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=1, sticky=tk.W)
        tk.Label(headers_frame, text="Members", width=col_widths["members"], anchor=tk.W, borderwidth=1, relief=tk.RIDGE).grid(row=0, column=2, sticky=tk.W)
        
        # Group listbox
        self.group_list = tk.Listbox(group_frame, height=15)
        
        # Scrollbars
        vsb = tk.Scrollbar(group_frame, orient="vertical", command=self.group_list.yview)
        hsb = tk.Scrollbar(group_frame, orient="horizontal", command=self.group_list.xview)
        self.group_list.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.group_list.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")
        
        group_frame.grid_rowconfigure(1, weight=1)
        group_frame.grid_columnconfigure(0, weight=1)
        
        # Refresh button
        refresh_button = tk.Button(left_frame, text="Refresh Groups", command=self.refresh_groups)
        refresh_button.pack(pady=5)
        
        # Group form
        tk.Label(right_frame, text="Group Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.group_name_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.group_name_var).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        
        tk.Label(right_frame, text="GID:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.gid_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.gid_var).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        
        tk.Label(right_frame, text="Members:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.members_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.members_var).grid(row=2, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Action buttons
        button_frame = tk.Frame(right_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        tk.Button(button_frame, text="Create Group", command=self.create_group).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Modify Group", command=self.modify_group).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Delete Group", command=self.delete_group).pack(side=tk.LEFT, padx=5)
        
        # Set to selected group
        self.group_list.bind("<<ListboxSelect>>", self.on_group_select)
        
        # Make the columns expandable
        right_frame.columnconfigure(1, weight=1)
        
        # Dictionary to store group data
        self.group_data = {}
    
    def refresh_users(self):
        """Refresh the user list from backend"""
        try:
            # Clear existing items
            self.user_list.delete(0, tk.END)
            self.user_data = {}
                
            # Get users from backend
            users, error = self.backend.list_users()
            
            if error:
                messagebox.showerror("Error", f"Failed to get users: {error}")
                return
                
            # Add users to list
            for idx, user in enumerate(users):
                # Skip system users with UID < 1000
                if int(user['uid']) < 1000 and user['username'] != 'root':
                    continue
                
                # Format display string
                display_text = f"{user['username']:<15} {user['uid']:<8} {user['gid']:<8} {user['home']:<25} {user['shell']:<25}"
                self.user_list.insert(tk.END, display_text)
                
                # Store user data for selection
                self.user_data[idx] = user
                
        except Exception as e:
            self.logger.error(f"Error refreshing users: {str(e)}")
            messagebox.showerror("Error", f"Error refreshing users: {str(e)}")
            
    def refresh_groups(self):
        """Refresh the group list from backend"""
        try:
            # Clear existing items
            self.group_list.delete(0, tk.END)
            self.group_data = {}
                
            # Get groups from backend
            groups, error = self.backend.list_groups()
            
            if error:
                messagebox.showerror("Error", f"Failed to get groups: {error}")
                return
                
            # Add groups to list
            for idx, group in enumerate(groups):
                # Skip system groups with GID < 1000
                if int(group['gid']) < 1000 and group['name'] != 'root':
                    continue
                    
                members_str = ",".join(group.get('members', []))
                
                # Format display string
                display_text = f"{group['name']:<15} {group['gid']:<8} {members_str:<40}"
                self.group_list.insert(tk.END, display_text)
                
                # Store group data for selection
                self.group_data[idx] = group
                
        except Exception as e:
            self.logger.error(f"Error refreshing groups: {str(e)}")
            messagebox.showerror("Error", f"Error refreshing groups: {str(e)}")
            
    def on_user_select(self, event):
        """Handle user selection in listbox"""
        selection = self.user_list.curselection()
        if not selection:
            return
            
        # Get user data from dictionary
        idx = selection[0]
        if idx in self.user_data:
            user = self.user_data[idx]
            
            # Update form fields
            self.username_var.set(user['username'])
            self.home_var.set(user['home'])
            self.shell_var.set(user['shell'])
        
    def on_group_select(self, event):
        """Handle group selection in listbox"""
        selection = self.group_list.curselection()
        if not selection:
            return
            
        # Get group data from dictionary
        idx = selection[0]
        if idx in self.group_data:
            group = self.group_data[idx]
            
            # Update form fields
            self.group_name_var.set(group['name'])
            self.gid_var.set(group['gid'])
            members_str = ",".join(group.get('members', []))
            self.members_var.set(members_str)
        
    def create_user(self):
        """Create a new user"""
        username = self.username_var.get().strip()
        home = self.home_var.get().strip()
        shell = self.shell_var.get().strip()
        groups = [g.strip() for g in self.groups_var.get().split(",") if g.strip()]
        
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
            
        # Set default home if not provided
        if not home:
            home = f"/home/{username}"
            
        options = {
            "home": home,
            "shell": shell
        }
        
        if groups:
            options["groups"] = groups
            
        # Call backend
        result, error = self.backend.manage_user("create", username, options)
        
        if error:
            messagebox.showerror("Error", f"Failed to create user: {error}")
        else:
            messagebox.showinfo("Success", result)
            self.refresh_users()
            
            # Clear form
            self.username_var.set("")
            self.home_var.set("")
            self.shell_var.set("/bin/bash")
            self.groups_var.set("")
            
    def modify_user(self):
        """Modify an existing user"""
        username = self.username_var.get().strip()
        home = self.home_var.get().strip()
        shell = self.shell_var.get().strip()
        groups = [g.strip() for g in self.groups_var.get().split(",") if g.strip()]
        
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
            
        options = {}
        
        if home:
            options["home"] = home
            
        if shell:
            options["shell"] = shell
            
        if groups:
            options["groups"] = groups
            
        # Call backend
        result, error = self.backend.manage_user("modify", username, options)
        
        if error:
            messagebox.showerror("Error", f"Failed to modify user: {error}")
        else:
            messagebox.showinfo("Success", result)
            self.refresh_users()
            
    def delete_user(self):
        """Delete a user"""
        username = self.username_var.get().strip()
        
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
            
        # Confirm
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete user {username}?"):
            return
            
        # Call backend
        result, error = self.backend.manage_user("delete", username)
        
        if error:
            messagebox.showerror("Error", f"Failed to delete user: {error}")
        else:
            messagebox.showinfo("Success", result)
            self.refresh_users()
            
            # Clear form
            self.username_var.set("")
            self.home_var.set("")
            self.shell_var.set("/bin/bash")
            self.groups_var.set("")
            
    def create_group(self):
        """Create a new group"""
        groupname = self.group_name_var.get().strip()
        gid = self.gid_var.get().strip()
        members = [m.strip() for m in self.members_var.get().split(",") if m.strip()]
        
        if not groupname:
            messagebox.showerror("Error", "Group name is required")
            return
            
        options = {}
        
        if gid:
            try:
                options["gid"] = int(gid)
            except ValueError:
                messagebox.showerror("Error", "GID must be a number")
                return
                
        if members:
            options["members"] = members
            
        # Call backend
        result, error = self.backend.manage_group("create", groupname, options)
        
        if error:
            messagebox.showerror("Error", f"Failed to create group: {error}")
        else:
            messagebox.showinfo("Success", result)
            self.refresh_groups()
            
            # Clear form
            self.group_name_var.set("")
            self.gid_var.set("")
            self.members_var.set("")
            
    def modify_group(self):
        """Modify an existing group"""
        groupname = self.group_name_var.get().strip()
        gid = self.gid_var.get().strip()
        members = [m.strip() for m in self.members_var.get().split(",") if m.strip()]
        
        if not groupname:
            messagebox.showerror("Error", "Group name is required")
            return
            
        options = {}
        
        if gid:
            try:
                options["gid"] = int(gid)
            except ValueError:
                messagebox.showerror("Error", "GID must be a number")
                return
                
        if members:
            options["members"] = members
            
        # Call backend
        result, error = self.backend.manage_group("modify", groupname, options)
        
        if error:
            messagebox.showerror("Error", f"Failed to modify group: {error}")
        else:
            messagebox.showinfo("Success", result)
            self.refresh_groups()
            
    def delete_group(self):
        """Delete a group"""
        groupname = self.group_name_var.get().strip()
        
        if not groupname:
            messagebox.showerror("Error", "Group name is required")
            return
            
        # Confirm
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete group {groupname}?"):
            return
            
        # Call backend
        result, error = self.backend.manage_group("delete", groupname)
        
        if error:
            messagebox.showerror("Error", f"Failed to delete group: {error}")
        else:
            messagebox.showinfo("Success", result)
            self.refresh_groups()
            
            # Clear form
            self.group_name_var.set("")
            self.gid_var.set("")
            self.members_var.set("") 