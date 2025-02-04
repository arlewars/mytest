def open_hosts_file_window(theme):
    class CustomWindow(tk.Toplevel):
        def __init__(self, title, width, height, theme, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.title(title)
            self.geometry(f"{width}x{height}")
            self.frame = ttk.Frame(self)
            self.frame.grid(row=0, column=0, sticky="nsew")
            self.create_widgets()

    class CustomTable:
        def __init__(self, parent, columns, row, col, columnspan=1, title=None):
            self.parent = parent # Save reference to parent (referring instance)
            if title:
                ttk.Label(parent, text=title, font=("Helvetica", 10, "bold")).grid(row=row, column=col, columnspan=columnspan, pady=5, sticky="w")
            self.frame = ttk.Frame(parent)
            self.frame.grid(row=row, column=col, columnspan=columnspan, padx=5, pady=5, sticky="nsew")

            self.table = ttk.Treeview(self.frame, columns=columns, show="headings")
            for col in columns:
                self.table.heading(col, text=col)
                self.table.column(col, anchor=tk.W, width=150)
            self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            self.scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.table.yview)
            self.scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.table.xview)
            self.table.configure(yscroll=self.scrollbar_y.set, xscroll=self.scrollbar_x.set)
            self.scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
            self.scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

            self.table.bind("<Double-1>", self.delete_row)
            self.frame.rowconfigure(0, weight=1)
            self.frame.columnconfigure(0, weight=1)

        def delete_row(self, event):
            selected_items = self.table.selection()
            if selected_items:
                for selected_item in selected_items:
                    self.table.delete(selected_item)

        def clear_table(self):
            for item in self.table.get_children():
                self.table.delete(item)

        def insert_row(self, values):
            if all(v == "" for v in values):
                return
            self.table.insert("", "end", values=values)

    class HostsFileWindow(CustomWindow):
        def create_widgets(self):
            frame = self.frame
            
            columns = ["IP Address", "Hostname"]
            self.custom_table = CustomTable(frame, columns, row=0, col=0, columnspan=2, title="Hosts File Entries")

            # Read existing entries from hosts.json if it exists
            if os.path.exists('hosts.json'):
                with open('hosts.json', 'r') as file:
                    hosts_data = json.load(file)
                for entry in hosts_data:
                    self.custom_table.insert_row(entry)
            else:
                # Pre-add 'localhost' entry if hosts.json does not exist
                self.custom_table.insert_row(["127.0.0.1", "localhost"])

            # Add entry fields
            self.ip_entry = ttk.Entry(frame, width=20)
            self.ip_entry.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

            self.hostname_entry = ttk.Entry(frame, width=20)
            self.hostname_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

            # Add button to insert new entry
            add_button = ttk.Button(frame, text="Add Entry", command=self.add_host_entry)
            add_button.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

            # Add Save button
            save_button = ttk.Button(frame, text="Save", command=self.save_hosts_file)
            save_button.grid(row=3, column=0, padx=5, pady=5, sticky="e")

            # Add Close button
            close_button = ttk.Button(frame, text="Close", command=self.destroy)
            close_button.grid(row=3, column=1, padx=5, pady=5, sticky="w")

            frame.columnconfigure(0, weight=1)
            frame.columnconfigure(1, weight=1)
            frame.rowconfigure(0, weight=1)

        def add_host_entry(self):
            ip_address = self.ip_entry.get().strip()
            hostname = self.hostname_entry.get().strip()
            if ip_address and hostname:
                self.custom_table.insert_row([ip_address, hostname])
                self.ip_entry.delete(0, tk.END)
                self.hostname_entry.delete(0, tk.END)

        def save_hosts_file(self):
            hosts_data = []
            for item in self.custom_table.table.get_children():
                hosts_data.append(self.custom_table.table.item(item)["values"])
            with open('hosts.json', 'w') as file:
                json.dump(hosts_data, file)
            tk.messagebox.showinfo("Info", "Hosts file saved successfully.")

    hosts_window = HostsFileWindow(title="Edit Hosts File", width=800, height=600, theme=theme)
    hosts_window.grab_set()