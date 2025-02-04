import tkinter as tk
from tkinter import ttk
import ldap3

class ActiveDirectoryDebugger:

 # Define the templates for the different AD servers
    dn_templates = {
        "LUV": [
            "cn={username},ou=users,ou=field,ou=swaco,dc=luv,dc=ad,dc=swacorp,dc=com",
            "cn={username},ou=security operations,ou=security,ou=admin,dc=luv,dc=ad,dc=swacorp,dc=com"
        ],
        "QAAD": [
            "cn={username},ou=users,ou=field,ou=swaco,dc=qaad,dc=qaad,dc=swacorp,dc=com",
            "cn={username},ou=security operations,ou=security,ou=admin,dc=qaad,dc=qaad,dc=swacorp,dc=com"
        ],
        "DEVAD": [
            "cn={username},ou=users,ou=field,ou=swaco,dc=devad,dc=devad,dc=swacorp,dc=com",
            "cn={username},ou=security operations,ou=security,ou=admin,dc=devad,dc=devad,dc=swacorp,dc=com"
        ]
    }

    def __init__(self, master):
        self.master = master
        self.window = tk.Toplevel()
        self.window.title("Active Directory Debugger")
        self.window.geometry("1000x800")
        self.setup_ui()

    def toggle_debug_window(self):
        if self.debug_var.get():
            self.debug_window = tk.Toplevel(self)
            self.debug_window.title("LDAP Debug")
            self.debug_text = tk.Text(self.debug_window, wrap=tk.WORD, height=20, width=80)
            self.debug_text.pack(fill=tk.BOTH, expand=True)
        else:
            if hasattr(self, 'debug_window'):
                self.debug_window.destroy()
                del self.debug_text  # Ensure debug_text is deleted when window is closed

    def setup_ui(self):
        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.server_label = ttk.Label(self.frame, text="AD Server:")
        self.server_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.server_var = tk.StringVar()
        self.server_dropdown = ttk.Combobox(self.frame, textvariable=self.server_var)
        self.server_dropdown['values'] = ['LUV', 'QAAD', 'DEVAD']
        self.server_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.server_dropdown.bind("<<ComboboxSelected>>", self.update_server_entry)


        # Add an entry field for the selected server
        self.server_entry_label = ttk.Label(self.frame, text="Selected Server:")    
        self.server_entry_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        
        self.server_entry = ttk.Entry(self.frame, width=50)  
        self.server_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.username_label = ttk.Label(self.frame, text="Username:")
        self.username_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ttk.Entry(self.frame)
        self.username_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.password_label = ttk.Label(self.frame, text="Password:")
        self.password_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = ttk.Entry(self.frame, show="*")
        self.password_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        self.search_base_label = ttk.Label(self.frame, text="Search Base:")
        self.search_base_label.grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.search_base_entry = ttk.Entry(self.frame)
        self.search_base_entry.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
        self.search_base_entry.insert(0, "DC=SWACORP,DC=COM")  

        self.function_var = tk.StringVar(value="user")
        self.function_label = ttk.Label(self.frame, text="Function:")
        self.function_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.user_radio = ttk.Radiobutton(self.frame, text="User Lookup", variable=self.function_var, value="user", command=self.toggle_function)
        self.user_radio.grid(row=5, column=1, padx=2, pady=5, sticky="w")
        self.group_radio = ttk.Radiobutton(self.frame, text="Group Comparison", variable=self.function_var, value="group", command=self.toggle_function)
        self.group_radio.grid(row=5, column=1, padx=2, pady=5, sticky="e")

        self.user_search_label = ttk.Label(self.frame, text="User 1 to Search:")
        self.user_search_label.grid(row=6, column=0, padx=5, pady=5, sticky="w")
        self.user_search_entry = ttk.Entry(self.frame)
        self.user_search_entry.grid(row=6, column=1, padx=5, pady=5, sticky="ew")

        self.add_user_btn = ttk.Button(self.frame, text="Add User 2", command=self.add_user)
        self.add_user_btn.grid(row=7, column=0, padx=5, pady=5)

        self.user2_search_label = ttk.Label(self.frame, text="User 2 to Search:")
        self.user2_search_label.grid(row=8, column=0, padx=5, pady=5, sticky="w")
        self.user2_search_entry = ttk.Entry(self.frame)
        self.user2_search_entry.grid(row=8, column=1, padx=5, pady=5, sticky="ew")
        self.user2_search_label.grid_remove()
        self.user2_search_entry.grid_remove()

        self.search_btn = ttk.Button(self.frame, text="Search User", command=self.search_user)
        self.search_btn.grid(row=9, column=0, padx=5, pady=5)

        self.compare_group1_label = ttk.Label(self.frame, text="Group 1:")
        self.compare_group1_label.grid(row=10, column=0, padx=5, pady=5, sticky="w")
        self.compare_group1_entry = ttk.Entry(self.frame)
        self.compare_group1_entry.grid(row=10, column=1, padx=5, pady=5, sticky="ew")

        self.compare_group2_label = ttk.Label(self.frame, text="Group 2:")
        self.compare_group2_label.grid(row=11, column=0, padx=5, pady=5, sticky="w")
        self.compare_group2_entry = ttk.Entry(self.frame)
        self.compare_group2_entry.grid(row=11, column=1, padx=5, pady=5, sticky="ew")

        self.compare_btn = ttk.Button(self.frame, text="Compare Groups", command=self.compare_groups)
        self.compare_btn.grid(row=12, column=0, padx=5, pady=5)

        self.result_frame = ttk.Frame(self.frame)
        self.result_frame.grid(row=13, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.result_text = tk.Text(self.result_frame, height=15, width=80)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        result_scrollbar = ttk.Scrollbar(self.result_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=result_scrollbar.set)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.user1_frame = ttk.Frame(self.frame)
        self.user1_frame.grid(row=14, column=0, padx=5, pady=5, sticky="ew")

        self.user1_text = tk.Text(self.user1_frame, height=15, width=40)
        self.user1_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        user1_scrollbar = ttk.Scrollbar(self.user1_frame, orient="vertical", command=self.user1_text.yview)
        self.user1_text.configure(yscrollcommand=user1_scrollbar.set)
        user1_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.user2_frame = ttk.Frame(self.frame)
        self.user2_frame.grid(row=14, column=1, padx=5, pady=5, sticky="ew")

        self.user2_text = tk.Text(self.user2_frame, height=15, width=40)
        self.user2_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        user2_scrollbar = ttk.Scrollbar(self.user2_frame, orient="vertical", command=self.user2_text.yview)
        self.user2_text.configure(yscrollcommand=user2_scrollbar.set)
        user2_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.group1_frame = ttk.Frame(self.frame)
        self.group1_frame.grid(row=15, column=0, padx=5, pady=5, sticky="ew")

        self.group1_text = tk.Text(self.group1_frame, height=15, width=40)
        self.group1_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        group1_scrollbar = ttk.Scrollbar(self.group1_frame, orient="vertical", command=self.group1_text.yview)
        self.group1_text.configure(yscrollcommand=group1_scrollbar.set)
        group1_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.group2_frame = ttk.Frame(self.frame)
        self.group2_frame.grid(row=15, column=1, padx=5, pady=5, sticky="ew")

        self.group2_text = tk.Text(self.group2_frame, height=15, width=40)
        self.group2_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        group2_scrollbar = ttk.Scrollbar(self.group2_frame, orient="vertical", command=self.group2_text.yview)
        self.group2_text.configure(yscrollcommand=group2_scrollbar.set)
        group2_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.missing_frame = ttk.Frame(self.frame)
        self.missing_frame.grid(row=16, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        self.missing_text = tk.Text(self.missing_frame, height=15, width=80)
        self.missing_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        missing_scrollbar = ttk.Scrollbar(self.missing_frame, orient="vertical", command=self.missing_text.yview)
        self.missing_text.configure(yscrollcommand=missing_scrollbar.set)
        missing_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.options_frame = ttk.Frame(self.frame)
        self.options_frame.grid(row=0, column=2, rowspan=17, padx=5, pady=5, sticky="ns")

        self.export_user1_btn = ttk.Button(self.options_frame, text="Export User 1 Groups", command=self.export_user1_groups)
        self.export_user1_btn.grid(row=0, column=0, padx=5, pady=5)

        self.export_user2_btn = ttk.Button(self.options_frame, text="Export User 2 Groups", command=self.export_user2_groups)
        self.export_user2_btn.grid(row=1, column=0, padx=5, pady=5)

        self.export_missing_btn = ttk.Button(self.options_frame, text="Export Missing Groups", command=self.export_missing_groups)
        self.export_missing_btn.grid(row=2, column=0, padx=5, pady=5)


        # Add a checkbox for enabling debug mode
        self.debug_var = tk.BooleanVar()
        self.debug_check = tk.Checkbutton(self.options_frame, text="Enable Debug", variable=self.debug_var)
        self.debug_check.grid(row=3, column=0, padx=5, pady=5)

        self.toggle_function()

    def update_server_entry(self, event):
        server_map = {
            'LUV': 'LUV.AD.SWACORP.COM',
            'QAAD': 'QAADLUV.SWACORP.COM',
            'DEVAD': 'DEVAD.SWACORP.COM'
        }
        selected_server = self.server_var.get()
        self.server_entry.delete(0, tk.END)
        self.server_entry.insert(0, server_map[selected_server])

    def toggle_function(self):
        if self.function_var.get() == "user":
            self.compare_group1_entry.configure(state="disabled")
            self.compare_group2_entry.configure(state="disabled")
            self.search_btn.configure(state="normal")
            self.compare_btn.configure(state="disabled")
            self.result_frame.grid(row=12, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
            self.group1_frame.grid_remove()
            self.group2_frame.grid_remove()
            self.missing_frame.grid_remove()
        else:
            self.compare_group1_entry.configure(state="normal")
            self.compare_group2_entry.configure(state="normal")
            self.search_btn.configure(state="disabled")
            self.add_user_btn.configure(state="disabled")
            self.user_search_entry.configure(state="disabled")
            self.user2_search_entry.configure(state="disabled")
            self.compare_btn.configure(state="normal")
            self.result_frame.grid_remove()
            self.group1_frame.grid(row=14, column=0, padx=5, pady=5, sticky="ew")
            self.group2_frame.grid(row=14, column=1, padx=5, pady=5, sticky="ew")
            self.missing_frame.grid(row=15, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

    def add_user(self):
            self.user2_search_label.grid()
            self.user2_search_entry.grid()

    def search_user(self):
        server = self.server_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        search_base = self.search_base_entry.get()
        user_to_search = self.user_search_entry.get()
        debug = self.debug_var.get()

        try:
            server_obj = ldap3.Server(server)
            try: # Attempt to bind with the provided username and password
                conn = ldap3.Connection(server_obj, user=username, password=password, auto_bind=True, client_strategy=ldap3.RESTARTABLE, auto_referrals=False)
                if debug and hasattr(self, 'debug_text'):
                    debug_message = f"LDAP Bind: Server={server}, User={username}\n"
                    self.debug_text.insert(tk.END, debug_message)
            except:
                if self.server_var.get() in self.dn_templates:
                    for template in self.dn_templates[self.server_var.get()]:
                        try:
                            user_dn = template.format(username=username)
                            conn = ldap3.Connection(server_obj, user=user_dn, password=password, auto_bind=True, client_strategy=ldap3.RESTARTABLE, auto_referrals=False)
                            if debug and hasattr(self, 'debug_text'):
                                debug_message = f"LDAP Bind: Server={server}, User={user_dn}\n"
                                self.debug_text.insert(tk.END, debug_message)
                            break
                        except ldap3.core.exceptions.LDAPBindError as e:
                            log_error("LDAP Bind Error with template",e)
                            continue
                    else:
                        raise ldap3.core.exceptions.LDAPBindError("Automatic bind not successful - invalid credentials")
                    if debug and hasattr(self, 'debug_text'):
                        debug_message = f"LDAP Bind: Server={server}, User={username}\n"
                        self.debug_text.insert(tk.END, debug_message)
        except ldap3.core.exceptions.LDAPBindError as e:
            messagebox.showerror("LDAP Bind Error", "Bind not successful - invalid credentials")
            log_error("LDAP Bind Error",e)
            if debug and hasattr(self, 'debug_text'):
                debug_message = f"LDAP Bind Error: {e}\n"
                self.debug_text.insert(tk.END, debug_message)
            return

        search_filter = f'(|(sAMAccountName={user_to_search})(cn={user_to_search})(uid={user_to_search}))'
        if debug and hasattr(self, 'debug_text'):
            debug_message = f"LDAP Search: Base={search_base}, Filter={search_filter}\n"
            self.debug_text.insert(tk.END, debug_message)

        conn.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)

        if debug and hasattr(self, 'debug_text'):
            debug_message = f"LDAP Response: {conn.entries}\n"
            self.debug_text.insert(tk.END, debug_message)

        if not conn.entries:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"User {user_to_search} not found.\n")
            log_error("User not found.",user_to_search)
            return

        user_entry = conn.entries[0]

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"User {user_to_search} attributes:\n")
        for attribute in user_entry.entry_attributes:
            value = user_entry[attribute]
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            self.result_text.insert(tk.END, f"{attribute}: {value}\n")

        if self.user2_search_entry.winfo_ismapped():
            user2_to_search = self.user2_search_entry.get()
            search_filter = f'(|(sAMAccountName={user2_to_search})(cn={user2_to_search})(uid={user2_to_search}))'
            if debug and hasattr(self, 'debug_text'):
                debug_message = f"LDAP Search: Base={search_base}, Filter={search_filter}\n"
                self.debug_text.insert(tk.END, debug_message)

            conn.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)

            if debug and hasattr(self, 'debug_text'):
                debug_message = f"LDAP Response: {conn.entries}\n"
            log_error("User not found.",user_to_search)
            return

        user_entry = conn.entries[0]

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"User {user_to_search} attributes:\n")
        for attribute in user_entry.entry_attributes:
            value = user_entry[attribute]
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            self.result_text.insert(tk.END, f"{attribute}: {value}\n")

        if self.user2_search_entry.winfo_ismapped():
            user2_to_search = self.user2_search_entry.get()
            search_filter = f'(|(sAMAccountName={user2_to_search})(cn={user2_to_search})(uid={user2_to_search}))'
            if debug and hasattr(self, 'debug_text'):
                debug_message = f"LDAP Search: Base={search_base}, Filter={search_filter}\n"
                self.debug_text.insert(tk.END, debug_message)

            conn.search(search_base, search_filter, attributes=ldap3.ALL_ATTRIBUTES)

            if debug and hasattr(self, 'debug_text'):
                debug_message = f"LDAP Response: {conn.entries}\n"
                self.debug_text.insert(tk.END, debug_message)

            if not conn.entries:
                self.user2_text.delete(1.0, tk.END)
                self.user2_text.insert(tk.END, f"User {user2_to_search} not found.\n")
                log_error(f"User not found.",user2_to_search)
                return

            user2_entry = conn.entries[0]

            self.user1_text.delete(1.0, tk.END)
            self.user1_text_label = tk.Label(self.user1_frame, text=f"User {user_to_search} Attributes:")
            self.user1_text_label.pack()
            self.user1_text.insert(tk.END, f"User {user_to_search} attributes:\n")
            for attribute in user_entry.entry_attributes:
                value = user_entry[attribute]
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                self.user1_text.insert(tk.END, f"{attribute}: {value}\n")

            self.user2_text.delete(1.0, tk.END)
            self.user2_text_label = tk.Label(self.user2_frame, text=f"User {user2_to_search} Attributes:")
            self.user2_text_label.pack()
            self.user2_text.insert(tk.END, f"User {user2_to_search} attributes:\n")
            for attribute in user2_entry.entry_attributes:
                value = user2_entry[attribute]
                if isinstance(value, bytes):
                    value = value.decode('utf-8')
                self.user2_text.insert(tk.END, f"{attribute}: {value}\n")

            user1_groups = set(user_entry['memberOf']) if 'memberOf' in user_entry else set()
            user2_groups = set(user2_entry['memberOf']) if 'memberOf' in user2_entry else set()

            user1_groups = {group.decode('utf-8') if isinstance(group, bytes) else group for group in user1_groups}
            user2_groups = {group.decode('utf-8') if isinstance(group, bytes) else group for group in user2_groups}

            if not user1_groups:
                self.user1_text.insert(tk.END, "No groups found.\n")
            else:
                self.user1_text.insert(tk.END, "Groups:\n")
                for group in user1_groups:
                    self.user1_text.insert(tk.END, f"{group}\n")

            if not user2_groups:
                self.user2_text.insert(tk.END, "No groups found.\n")
            else:
                self.user2_text.insert(tk.END, "Groups:\n")
                for group in user2_groups:
                    self.user2_text.insert(tk.END, f"{group}\n")


                only_in_user1 = user1_groups - user2_groups

                self.missing_text.delete(1.0, tk.END)
                self.missing_text_label = tk.Label(self.missing_frame, text=f"Groups that User {user_to_search} has but User {user2_to_search} is missing:")
                self.missing_text_label.pack()
                self.missing_text.insert(tk.END, f"Groups that User {user_to_search} has but User {user2_to_search} is missing:\n")
                for group in only_in_user1:
                    self.missing_text.insert(tk.END, f"{group}\n")

    def compare_groups(self):
        server = self.server_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        search_base = self.search_base_entry.get()
        group1 = self.compare_group1_entry.get()
        group2 = self.compare_group2_entry.get()

        server = ldap3.Server(server)
        conn = ldap3.Connection(server, user=username, password=password, auto_bind=True)

        if group1:
            conn.search(search_base, f'(cn={group1})', attributes=['member'])
            if not conn.entries:
                self.group1_text.delete(1.0, tk.END)
                self.group1_text.insert(tk.END, f"Group {group1} not found.\n")
                return
            group1_members = set(conn.entries[0].member)
        else:
            group1_members = set()

        if group2:
            conn.search(search_base, f'(cn={group2})', attributes=['member'])
            if not conn.entries:
                self.group2_text.delete(1.0, tk.END)
                self.group2_text.insert(tk.END, f"Group {group2} not found.\n")
                return
            group2_members = set(conn.entries[0].member)
        else:
            group2_members = set()

        self.group1_text.delete(1.0, tk.END)
        self.group2_text.delete(1.0, tk.END)

        if group1 and not group2:
            self.group1_text.insert(tk.END, f"Members of Group 1 ({group1}):\n")
            for member in group1_members:
                self.group1_text.insert(tk.END, f"{member}\n")
        elif group1 and group2:
            only_in_group1 = group1_members - group2_members
            only_in_group2 = group2_members - group1_members

            self.group1_text.insert(tk.END, f"Members only in {group1}:\n")
            for member in only_in_group1:
                self.group1_text.insert(tk.END, f"{member}\n")

            self.group2_text.insert(tk.END, f"Members only in {group2}:\n")
            for member in only_in_group2:
                self.group2_text.insert(tk.END, f"{member}\n")
        else:
            self.group1_text.insert(tk.END, f"Members of Group 1 ({group1}):\n")
            for member in group1_members:
                self.group1_text.insert(tk.END, f"{member}\n")

            self.group2_text.insert(tk.END, f"Members of Group 2 ({group2}):\n")
            for member in group2_members:
                self.group2_text.insert(tk.END, f"{member}\n")

            self.missing_text.delete(1.0, tk.END)
            self.missing_text.insert(tk.END, f"Members missing between {group1} and {group2}:\n")
            for member in only_in_group1.union(only_in_group2):
                self.missing_text.insert(tk.END, f"{member}\n")

    def export_user1_groups(self):
        user1_sAMAccountName = self.user_search_entry.get()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{user1_sAMAccountName}_groups_{timestamp}.csv"
        user1_groups = self.user1_text.get(1.0, tk.END).strip().split('\n')
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["User 1 Groups"])
            for group in user1_groups:
                writer.writerow([group])
        messagebox.showinfo("Export Successful", f"User 1 groups have been exported successfully to {filename}.")

    def export_user2_groups(self):
        user2_sAMAccountName = self.user2_search_entry.get()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{user2_sAMAccountName}_groups_{timestamp}.csv"
        user2_groups = self.user2_text.get(1.0, tk.END).strip().split('\n')
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["User 2 Groups"])
            for group in user2_groups:
                writer.writerow([group])
        messagebox.showinfo("Export Successful", f"User 2 groups have been exported successfully to {filename}.")

    def export_missing_groups(self):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"missing_groups_{timestamp}.csv"
        missing_groups = self.missing_text.get(1.0, tk.END).strip().split('\n')
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Missing Groups"])
            for group in missing_groups:
                writer.writerow([group])
        messagebox.showinfo("Export Successful", f"Missing groups have been exported successfully to {filename}.")



def main():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    theme = "default"  # Set your theme here
    debugger = ActiveDirectoryDebugger(root, theme)
    root.mainloop()

if __name__ == "__main__":
    main()