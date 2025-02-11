import tkinter as tk
from tkinter import ttk
import ldap3
from ldap3 import Server, Connection
from datetime import datetime
import json
import csv
from tkinter import messagebox
import sys
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

DEBUGALL = False

class LdapLookup:
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

    NORD_STYLES = {
        "standard": {
            "background": "#2C2C2E",
            "foreground": "#F2F2F7",
            "highlight": "#1E4BC3",
            "error": "#FF453A",
            "header": "#c1cfff",
            "row_odd": "#C7E0F4",
            "row_even": "#F2F7FB",
            "button": "#FFCA4F",
            "invert_button": "#5AC8FA",
            "button_background": "#0A84FF"
        },
        "frost": {
            "background": "#8FBCBB",
            "foreground": "#2E3440",
            "highlight": "#88C0D0",
            "error": "#BF616A",
            "header": "#81a1c1",
            "row_odd": "#A3BE8C",
            "row_even": "#EBCB8B",
            "button": "#5E81AC",
            "invert_button": "#D08770",
            "button_background": "#88c0d0"
        },
        "aurora": {
            "background": "#A3BE8C",
            "foreground": "#2E3440",
            "highlight": "#88C0D0",
            "error": "#BF616A",
            "header": "#b48ead",
            "row_odd": "#A3BE8C",
            "row_even": "#EBCB8B",
            "button": "#5E81AC",
            "invert_button": "#D08770",
            "button_background": "#ebcb8b"
        }
    }

    DEFAULT_THEME = NORD_STYLES["standard"]

    def __init__(self, master, theme="standard"):
        self.master = master
        self.window = tk.Toplevel()
        self.window.title("LDAP Lookup Tool")
        self.window.geometry("1000x800")
        self.theme = theme if theme in self.NORD_STYLES else "standard"
        self.use_ldaps_var = tk.BooleanVar(value=True)
        self.port_var = tk.StringVar(value="636")
        self.apply_theme()
        self.window.resizable(True, True)
        self.setup_ui()
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.window.destroy()
        self.master.quit()
        sys.exit()

    def apply_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        colors = self.NORD_STYLES[self.theme]
        style.configure("TFrame", background=colors["background"])
        style.configure("TLabelFrame", background=colors["background"], foreground=colors["foreground"])
        style.configure("Treeview", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
        style.configure("Treeview.Heading", background=colors["header"], foreground=colors["foreground"])
        style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
        style.map("TButton", background=[("active", colors["highlight"])])
        style.configure("TEntry", background=colors["background"], foreground=colors["foreground"], fieldbackground=colors["background"])
        style.configure("TText", background=colors["background"], foreground=colors["foreground"])
        style.configure("Invert.TButton", background=colors["invert_button"], foreground=colors["foreground"])
        style.map("Invert.TButton", background=[("active", colors["highlight"])])
        style.configure("TButton", background=colors["button_background"], foreground=colors["foreground"])
        style.configure("TLabel", background=colors["button_background"], foreground=colors["foreground"])
        style.configure("TEntry", fieldbackground=colors["button_background"], foreground=colors["foreground"])

    def toggle_debug_window(self):
        if self.debug_var.get():
            self.debug_window = tk.Toplevel(self.window)
            self.debug_window.title("LDAP Debug")
            self.debug_frame = ttk.Frame(self.debug_window, padding="10")
            self.debug_frame.pack(fill=tk.BOTH, expand=True)
            self.debug_text = tk.Text(self.debug_frame, wrap=tk.WORD, height=20, width=80)
            self.debug_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            debug_scrollbar = ttk.Scrollbar(self.debug_frame, orient="vertical", command=self.debug_text.yview)
            self.debug_text.configure(yscrollcommand=debug_scrollbar.set)
            debug_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        else:
            if hasattr(self, 'debug_window'):
                self.debug_window.destroy()
                del self.debug_text

    def log_debug(self, message):
        if self.debug_var.get() and hasattr(self, 'debug_text'):
            self.debug_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        if DEBUGALL:
            print(f"DEBUG: {message}")

    def log_error(self, message, exception):
        error_entry = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "message": message,
            "exception": str(exception)
        }
        log_file = "aderrors.json"
        try:
            with open("aderrors.json", "r") as file:
                errors = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            errors = []
        errors.append(error_entry)
        with open(log_file, "w") as file:
            json.dump(errors, file, indent=4)
        self.log_debug(f"Error logged: {message} - {exception}")

    def setup_ui(self):
        self.canvas = tk.Canvas(self.window)
        self.scrollbar = ttk.Scrollbar(self.window, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.frame = ttk.Frame(self.scrollable_frame, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=1)

        self.server_label = ttk.Label(self.frame, text="AD Server:", width=50)
        self.server_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.server_var = tk.StringVar()
        self.server_dropdown = ttk.Combobox(self.frame, textvariable=self.server_var)
        self.server_dropdown['values'] = ['LUV', 'QAAD', 'DEVAD']
        self.server_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.server_dropdown.bind("<<ComboboxSelected>>", self.update_server_entry)

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
        self.result_frame.grid(row=13, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.result_frame.grid_rowconfigure(0, weight=1)
        self.result_frame.grid_columnconfigure(0, weight=1)

        self.result_text = tk.Text(self.result_frame, height=15, width=80)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        result_scrollbar = ttk.Scrollbar(self.result_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=result_scrollbar.set)
        result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.user1_frame = ttk.Frame(self.frame)
        self.user1_frame.grid(row=14, column=0, padx=5, pady=5, sticky="nsew")
        self.user1_frame.grid_rowconfigure(0, weight=1)
        self.user1_frame.grid_columnconfigure(0, weight=1)

        self.user1_text = tk.Text(self.user1_frame, height=15, width=40)
        self.user1_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        user1_scrollbar = ttk.Scrollbar(self.user1_frame, orient="vertical", command=self.user1_text.yview)
        self.user1_text.configure(yscrollcommand=user1_scrollbar.set)
        user1_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.user2_frame = ttk.Frame(self.frame)
        self.user2_frame.grid(row=14, column=1, padx=5, pady=5, sticky="nsew")
        self.user2_frame.grid_rowconfigure(0, weight=1)
        self.user2_frame.grid_columnconfigure(0, weight=1)

        self.user2_text = tk.Text(self.user2_frame, height=15, width=40)
        self.user2_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        user2_scrollbar = ttk.Scrollbar(self.user2_frame, orient="vertical", command=self.user2_text.yview)
        self.user2_text.configure(yscrollcommand=user2_scrollbar.set)
        user2_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.group1_frame = ttk.Frame(self.frame)
        self.group1_frame.grid(row=15, column=0, padx=5, pady=5, sticky="nsew")
        self.group1_frame.grid_rowconfigure(0, weight=1)
        self.group1_frame.grid_columnconfigure(0, weight=1)

        self.group1_text = tk.Text(self.group1_frame, height=15, width=40)
        self.group1_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        group1_scrollbar = ttk.Scrollbar(self.group1_frame, orient="vertical", command=self.group1_text.yview)
        self.group1_text.configure(yscrollcommand=group1_scrollbar.set)
        group1_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.group2_frame = ttk.Frame(self.frame)
        self.group2_frame.grid(row=15, column=1, padx=5, pady=5, sticky="nsew")
        self.group2_frame.grid_rowconfigure(0, weight=1)
        self.group2_frame.grid_columnconfigure(0, weight=1)

        self.group2_text = tk.Text(self.group2_frame, height=15, width=40)
        self.group2_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        group2_scrollbar = ttk.Scrollbar(self.group2_frame, orient="vertical", command=self.group2_text.yview)
        self.group2_text.configure(yscrollcommand=group2_scrollbar.set)
        group2_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.missing_frame_1 = ttk.Frame(self.frame)
        self.missing_frame_1.grid(row=16, column=0, padx=5, pady=5, sticky="nsew")
        self.missing_frame_1.grid_rowconfigure(0, weight=1)
        self.missing_frame_1.grid_columnconfigure(0, weight=1)

        self.missing_text_1 = tk.Text(self.missing_frame_1, height=15, width=40)
        self.missing_text_1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        missing_scrollbar_1 = ttk.Scrollbar(self.missing_frame_1, orient="vertical", command=self.missing_text_1.yview)
        self.missing_text_1.configure(yscrollcommand=missing_scrollbar_1.set)
        missing_scrollbar_1.pack(side=tk.RIGHT, fill=tk.Y)

        self.missing_frame_2 = ttk.Frame(self.frame)
        self.missing_frame_2.grid(row=16, column=1, padx=5, pady=5, sticky="nsew")
        self.missing_frame_2.grid_rowconfigure(0, weight=1)
        self.missing_frame_2.grid_columnconfigure(0, weight=1)

        self.missing_text_2 = tk.Text(self.missing_frame_2, height=15, width=40)
        self.missing_text_2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        missing_scrollbar_2 = ttk.Scrollbar(self.missing_frame_2, orient="vertical", command=self.missing_text_2.yview)
        self.missing_text_2.configure(yscrollcommand=missing_scrollbar_2.set)
        missing_scrollbar_2.pack(side=tk.RIGHT, fill=tk.Y)

        self.options_frame = ttk.Frame(self.frame)
        self.options_frame.grid(row=0, column=2, rowspan=17, padx=2, pady=2, sticky="ns")
        self.options_frame.grid_rowconfigure(0, weight=1)
        self.options_frame.grid_columnconfigure(0, weight=1)

        self.export_user1_btn = ttk.Button(self.options_frame, text="Export User 1 Groups", command=self.export_user1_groups)
        self.export_user1_btn.grid(row=2, column=0, padx=2, pady=2)

        self.export_user2_btn = ttk.Button(self.options_frame, text="Export User 2 Groups", command=self.export_user2_groups)
        self.export_user2_btn.grid(row=3, column=0, padx=2, pady=2)

        self.export_missing_btn = ttk.Button(self.options_frame, text="Export Missing Groups", command=self.export_missing_groups)
        self.export_missing_btn.grid(row=4, column=0, padx=2, pady=2)

        self.debug_var = tk.BooleanVar()
        self.debug_check = tk.Checkbutton(self.options_frame, text="Enable Debug", variable=self.debug_var, command=self.toggle_debug_window)
        self.debug_check.grid(row=0, column=0, padx=5, pady=5)

        self.close_btn = ttk.Button(self.options_frame, text="Close", command=self.close_application)
        self.close_btn.grid(row=1, column=0, padx=5, pady=5)

        self.use_ldaps_check = ttk.Checkbutton(self.frame, text="Use LDAPS", variable=self.use_ldaps_var, command=self.toggle_ldaps)
        self.use_ldaps_check.grid(row=0, column=2, padx=5, pady=5, sticky="w")

        self.port_label = ttk.Label(self.frame, text="Port:")
        self.port_label.grid(row=1, column=2, padx=5, pady=5, sticky="w")
        self.port_entry = ttk.Entry(self.frame, textvariable=self.port_var, width=10)
        self.port_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")

        self.toggle_function()

    def close_application(self):
        self.on_closing()

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
            self.user2_search_entry.configure(state="normal")
            self.search_btn.configure(state="normal")
            self.add_user_btn.configure(state="normal")
            self.user_search_entry.configure(state="normal")
            self.user2_search_entry.configure(state="normal")
            self.compare_btn.configure(state="disabled")
            self.result_frame.grid(row=12, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
            self.group1_frame.grid_remove()
            self.group2_frame.grid_remove()
            self.missing_frame_1.grid_remove()
            self.missing_frame_2.grid_remove()
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
            self.missing_frame_1.grid(row=16, column=0, padx=5, pady=5, sticky="ew")
            self.missing_frame_2.grid(row=16, column=1, padx=5, pady=5, sticky="ew")

    def add_user(self):
            self.user2_search_label.grid()
            self.user2_search_entry.grid()

    def toggle_ldaps(self):
        if self.use_ldaps_var.get():
            self.port_var.set("636")
        else:
            self.port_var.set("389")

    def search_user(self):
        self.missing_text_1.delete(1.0, tk.END)
        self.missing_text_2.delete(1.0, tk.END)

        server = self.server_entry.get()
        port = self.port_var.get()
        use_ssl = self.use_ldaps_var.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        search_base = self.search_base_entry.get()
        user_to_search = self.user_search_entry.get()

        if DEBUGALL:
            print(f"Executing search_user with values: server={server}, port={port}, use_ssl={use_ssl}, username={username}, password={password}, search_base={search_base}, user_to_search={user_to_search}")

        try:
            server_obj = Server(server, port=int(port), use_ssl=use_ssl, get_info=ldap3.ALL, tls=ldap3.Tls(validate=ldap3.Tls.VALIDATE_NEVER))
            try:  # Attempt to bind with the provided username and password
                conn = Connection(server_obj, user=username, password=password, auto_bind=True, client_strategy=ldap3.RESTARTABLE, auto_referrals=False)
                self.log_debug(f"LDAP Bind: Server={server}, Port={port}, Use SSL={use_ssl}, User={username}")
                self.log_debug(f"Raw Bind Result: {conn.result}")
            except:
                if self.server_var.get() in self.dn_templates:
                    for template in self.dn_templates[self.server_var.get()]:
                        try:
                            user_dn = template.format(username=username)
                            conn = Connection(server_obj, user=user_dn, password=password, auto_bind=True, client_strategy=ldap3.RESTARTABLE, auto_referrals=False)
                            self.log_debug(f"LDAP Bind: Server={server}, Port={port}, Use SSL={use_ssl}, User={user_dn}")
                            self.log_debug(f"Raw Bind Result: {conn.result}")
                            break
                        except LDAPBindError as e:
                            self.log_debug(f"LDAP Bind Error with template: {e}")
                            continue
                    else:
                        raise LDAPBindError("Automatic bind not successful - invalid credentials")
                    self.log_debug(f"LDAP Bind: Server={server}, Port={port}, Use SSL={use_ssl}, User={username}")
        except LDAPBindError as e:
            messagebox.showerror("LDAP Bind Error", "Bind not successful - invalid credentials")
            self.log_debug(f"LDAP Bind Error: {e}")
            return
        except LDAPSocketOpenError as e:
            messagebox.showerror("LDAP Connection Error", "Failed to connect to the LDAP server")
            self.log_debug(f"LDAP Connection Error: {e}")
            return

        search_filter = f'(|(sAMAccountName={user_to_search})(cn={user_to_search})(uid={user_to_search}))'
        self.log_debug(f"LDAP Search Command: ldapsearch -x -H ldap{'s' if use_ssl else ''}://{server}:{port} -b '{search_base}' -s sub '{search_filter}'")
        self.log_debug(f"LDAP Search: Base={search_base}, Filter={search_filter}")

        entries = []
        try:
            # Perform paged search
            conn.search(
                search_base,
                search_filter,
                attributes=ldap3.ALL_ATTRIBUTES,
                paged_size=5
            )
            self.log_debug(f"Raw Search Result: {conn.result}")
            cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
            
            while cookie:
                entries.extend(conn.entries)
                conn.search(
                    search_base,
                    search_filter,
                    attributes=ldap3.ALL_ATTRIBUTES,
                    paged_size=5,
                    paged_cookie=cookie
                )
                self.log_debug(f"Raw Search Result: {conn.result}")
                cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')

            entries.extend(conn.entries)
        except LDAPKeyError:
            self.log_debug("LDAP server does not support paged search, performing regular search.")
            conn.search(
                search_base,
                search_filter,
                attributes=ldap3.ALL_ATTRIBUTES
            )
            self.log_debug(f"Raw Search Result: {conn.result}")
            entries.extend(conn.entries)

        self.log_debug(f"LDAP Response: {entries}")
        if DEBUGALL:
            print(f"LDAP Response: {entries}")
        if not entries:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"User {user_to_search} not found.\n")
            self.result_text.insert(tk.END, f"Search Base: {search_base}\n")
            self.result_text.insert(tk.END, f"Search Filter: {search_filter}\n")
            self.log_debug(f"User {user_to_search} not found.")
            return
        
        user_entry = entries[0]

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"User {user_to_search} attributes:\n")

        for user_entry in entries:
                if isinstance(user_entry, bytes):
                    value = user_entry.decode('utf-8')
                    self.result_text.insert(tk.END, f"{value}\n")
                else:
                    self.result_text.insert(tk.END, f"{user_entry}\n")

        # Optional: Perform a second search for user2
        if self.user2_search_entry.winfo_ismapped():
            user2_to_search = self.user2_search_entry.get()
            search_filter = f'(|(sAMAccountName={user2_to_search})(cn={user2_to_search})(uid={user2_to_search}))'
            self.log_debug(f"LDAP Search Command: ldapsearch -x -b '{search_base}' -s sub '{search_filter}'")
            self.log_debug(f"LDAP Search: Base={search_base}, Filter={search_filter}")

            entries2 = []
            try:
                conn.search(
                    search_base,
                    search_filter,
                    attributes=ldap3.ALL_ATTRIBUTES,
                    paged_size=5
                )
                self.log_debug(f"Raw Search Result: {conn.result}")
                cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                
                while cookie:
                    entries2.extend(conn.entries)
                    conn.search(
                        search_base,
                        search_filter,
                        attributes=ldap3.ALL_ATTRIBUTES,
                        paged_size=5,
                        paged_cookie=cookie
                    )
                    self.log_debug(f"Raw Search Result: {conn.result}")
                    cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                    
                entries2.extend(conn.entries)
            except LDAPKeyError:
                self.log_debug("LDAP server does not support paged search, performing regular search.")
                conn.search(
                    search_base,
                    search_filter,
                    attributes=ldap3.ALL_ATTRIBUTES
                )
                self.log_debug(f"Raw Search Result: {conn.result}")
                entries2.extend(conn.entries)

            self.log_debug(f"LDAP Response: {entries2}")

            if not entries2:
                self.user2_text.delete(1.0, tk.END)
                self.user2_text.insert(tk.END, f"User {user2_to_search} not found.\n")
                self.user2_text.insert(tk.END, f"Search Base: {search_base}\n")
                self.user2_text.insert(tk.END, f"Search Filter: {search_filter}\n")
                self.log_debug(f"User {user2_to_search} not found.")
                return

            user2_entry = entries2[0]
            user1_groups = []

            # Handle user2 text results
            self.user1_text.delete(1.0, tk.END)
            self.user2_text.delete(1.0, tk.END)
            self.user1_text.insert(tk.END, f"User {user_to_search} Groups:\n")
            self.user2_text.insert(tk.END, f"User {user2_to_search} Groups:\n")
            if user2_entry:
                self.log_debug(f"User {user2_to_search} attributes:")
                    
                for user2_entry in entries2:
                    if isinstance(user2_entry, bytes):
                        value = user2_entry.decode('utf-8')
                        self.log_debug(f"{value}\n")
                    else:
                        self.log_debug(f"{user2_entry}\n")

            for user_entry in entries:
                if hasattr(user_entry, 'memberOf'):
                    user1_groups = user_entry.memberOf

            for user2_entry in entries2:
                if hasattr(user2_entry, 'memberOf'):
                    user2_groups = user2_entry.memberOf
            if DEBUGALL:
                print(f"Groups for User {user_to_search}: {user1_groups}")
                print(f"Groups for User {user2_to_search}: {user2_groups}")

            user1_groups = {group.decode('utf-8') if isinstance(group, bytes) else group for group in user1_groups}
            user2_groups = {group.decode('utf-8') if isinstance(group, bytes) else group for group in user2_groups}

            # Handle missing groups
            if not user1_groups:
                self.log_debug(f"No groups found for User {user_to_search}.")
                self.user1_text.insert(tk.END, "No groups found.\n")
            else:
                self.log_debug(f"Groups for User {user_to_search}: {user1_groups}")
                for group in user1_groups:
                    self.user1_text.insert(tk.END, f"{group}\n")
                    self.log_debug(f"Group: {group}")

            if not user2_groups:
                self.user2_text.insert(tk.END, "No groups found.\n")
                self.log_debug(f"No groups found for User {user2_to_search}.")
            else:
                self.log_debug(f"Groups for User {user2_to_search}: {user2_groups}")
                for group in user2_groups:
                    self.user2_text.insert(tk.END, f"{group}\n")
                    self.log_debug(f"Group: {group}")

            only_in_user1 = user1_groups - user2_groups
            only_in_user2 = user2_groups - user1_groups
            self.user1_text.insert(tk.END, f"\n")
            self.user2_text.insert(tk.END, f"\n")
            self.user1_text.insert(tk.END, f"Groups that User {user_to_search} has but User {user2_to_search} is missing:\n")
            self.user2_text.insert(tk.END, f"Groups that User {user2_to_search} has but User {user_to_search} is missing:\n")
            
            if DEBUGALL:
                print(f"Groups only in User {user_to_search}: {only_in_user1}")
                print(f"Groups only in User {user2_to_search}: {only_in_user2}")

         #   self.missing_text_1.insert(tk.END, f"Groups that User {user_to_search} has but User {user2_to_search} is missing:\n")
            self.log_debug(f"Groups only in User {user_to_search}: {only_in_user1}")
            for group in only_in_user1:
                self.user1_text.insert(tk.END, f"{group}\n")
            for group in only_in_user2:
                self.user2_text.insert(tk.END, f"{group}\n")


    def compare_groups(self):
        server = self.server_entry.get()
        port = self.port_var.get()
        use_ssl = self.use_ldaps_var.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        search_base = self.search_base_entry.get()
        group1 = self.compare_group1_entry.get()
        group2 = self.compare_group2_entry.get()

        server_obj = ldap3.Server(server, port=int(port), use_ssl=use_ssl, get_info=ldap3.ALL, tls=ldap3.Tls(validate=ldap3.Tls.VALIDATE_NEVER))
        conn = ldap3.Connection(server_obj, user=username, password=password, auto_bind=True)
        self.log_debug(f"LDAP Bind: Server={server}, Port={port}, Use SSL={use_ssl}, User={username}")
        self.log_debug(f"Raw Bind Result: {conn.result}")

        if group1:
            self.log_debug(f"LDAP Search Command: ldapsearch -x -b '{search_base}' -s sub '(cn={group1})'")
            conn.search(search_base, f'(cn={group1})', attributes=['member'])
            self.log_debug(f"LDAP Search: Base={search_base}, Filter=(cn={group1})")
            self.log_debug(f"Raw Search Result: {conn.result}")
            if not conn.entries:
                self.group1_text.delete(1.0, tk.END)
                self.group1_text.insert(tk.END, f"Group {group1} not found.\n")
                self.log_debug(f"Group {group1} not found.")
                return
            group1_members = set(conn.entries[0].member)
        else:
            group1_members = set()

        if group2:
            self.log_debug(f"LDAP Search Command: ldapsearch -x -b '{search_base}' -s sub '(cn={group2})'")
            conn.search(search_base, f'(cn={group2})', attributes=['member'])
            self.log_debug(f"LDAP Search: Base={search_base}, Filter=(cn={group2})")
            self.log_debug(f"Raw Search Result: {conn.result}")
            if not conn.entries:
                self.group2_text.delete(1.0, tk.END)
                self.group2_text.insert(tk.END, f"Group {group2} not found.\n")
                self.log_debug(f"Group {group2} not found.")
                return
            group2_members = set(conn.entries[0].member)
        else:
            group2_members = set()

        self.group1_text.delete(1.0, tk.END)
        self.group2_text.delete(1.0, tk.END)
        self.missing_text_1.delete(1.0, tk.END)
        self.missing_text_2.delete(1.0, tk.END)

        self.group1_text.insert(tk.END, f"Members of Group 1 ({group1}):\n")
        for member in group1_members:
            self.group1_text.insert(tk.END, f"{member}\n")

        self.group2_text.insert(tk.END, f"Members of Group 2 ({group2}):\n")
        for member in group2_members:
            self.group2_text.insert(tk.END, f"{member}\n")

        only_in_group1 = group1_members - group2_members
        only_in_group2 = group2_members - group1_members

        self.missing_text_1.insert(tk.END, f"Members only in {group1}:\n")
        for member in only_in_group1:
            self.missing_text_1.insert(tk.END, f"{member}\n")

        self.missing_text_2.insert(tk.END, f"Members only in {group2}:\n")
        for member in only_in_group2:
            self.missing_text_2.insert(tk.END, f"{member}\n")

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
        missing_groups_1 = self.missing_text_1.get(1.0, tk.END).strip().split('\n')
        missing_groups_2 = self.missing_text_2.get(1.0, tk.END).strip().split('\n')
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Missing Groups in Group 1"])
            for group in missing_groups_1:
                writer.writerow([group])
            writer.writerow(["--------------------"])
            writer.writerow(["Missing Groups in Group 2"])
            for group in missing_groups_2:
                writer.writerow([group])
        messagebox.showinfo("Export Successful", f"Missing groups have been exported successfully to {filename}.")



def main():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    theme = sys.argv[1] if len(sys.argv) > 1 else "standard"
    debugger = LdapLookup(root, theme)
    root.mainloop()

if __name__ == "__main__":
    main()
