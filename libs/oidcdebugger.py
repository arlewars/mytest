import tkinter as tk
from tkinter import ttk
import requests
import json
import base64
import hashlib
import os
import sys
import threading
import http.server
import socketserver
import socket
import ssl
import urllib.parse
import webbrowser
from OpenSSL import crypto
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from requests.auth import HTTPBasicAuth
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)


python_executable = sys.executable
current_path = os.getcwd()

https_server = None
https_server_thread = None  # Add a reference to the thread
Debug = True





class OIDCDebugger:
    # Styling configurations
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

    DEFAULT_THEME = {
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
    }

    def __init__(self, master, theme="standard"):
        self.master = master
        self.theme = theme if theme in self.NORD_STYLES else "standard"
        self.window = tk.Toplevel()
        self.window.title("OIDC Debugger")
        self.window.geometry("1400x600")
        self.server_port = 4443
        self.ssl_context = self.create_combined_ssl_context()
        self.apply_theme()
        self.setup_ui()
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.stop_https_server()
        self.master.quit()
        self.master.destroy()
        sys.exit()

    def log_error(self, message, exception):
        error_entry = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "message": message,
            "exception": str(exception)
        }
        log_file = "errors.json"
        
        #logger.error(json.dumps(error_entry))
        
        # Also write the error to errors.json
        try:
            with open("errors.json", "r") as file:
                errors = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            errors = []
        
        errors.append(error_entry)
        with open(log_file, "w") as file:
            json.dump(errors, file, indent=4)

    def create_combined_ssl_context(self):
        ssl_context = ssl.create_default_context()
        if os.path.exists("server.crt") and os.path.exists("server.key"):
            ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        return ssl_context

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

    def setup_ui(self):
        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Labels and entries
        self.endpoint_label = ttk.Label(self.frame, text="Select or enter well-known endpoint URL:")
        self.endpoint_label.grid(row=0, column=0, padx=0, pady=0, sticky="w")
        self.endpoint_entry = self.create_labeled_entry(self.frame, "Well-Known Endpoint:", 0, 1)
        self.create_well_known_dropdown(self.frame, self.endpoint_entry)
        
        self.server_name_label = ttk.Label(self.frame, text="Enter server name for redirect URL(optional):")
        self.server_name_label.grid(row=2, column=0, padx=0, pady=0, sticky="w")
        self.server_name_entry = ttk.Entry(self.frame, width=50)
        self.server_name_entry.grid(row=2, column=1, padx=0, pady=0, sticky="ew")
        
        self.client_id_label = ttk.Label(self.frame, text="Client ID:")
        self.client_id_label.grid(row=3, column=0, padx=0, pady=0, sticky="w")
        self.client_id_entry = ttk.Entry(self.frame, width=50)
        self.client_id_entry.grid(row=3, column=1, padx=0, pady=0, sticky="ew")
        
        self.client_secret_label = ttk.Label(self.frame, text="Client Secret:")
        self.client_secret_label.grid(row=4, column=0, padx=0, pady=0, sticky="w")
        self.client_secret_entry = ttk.Entry(self.frame, width=50, show="*")
        self.client_secret_entry.grid(row=4, column=1, padx=0, pady=0, sticky="ew")
        
        self.scope_label = ttk.Label(self.frame, text="Enter Scopes (e.g., openid profile email):")
        self.scope_label.grid(row=5, column=0, padx=0, pady=0, sticky="w")
        self.scope_entry = ttk.Entry(self.frame, width=50)
        self.scope_entry.grid(row=5, column=1, padx=0, pady=0, sticky="ew")

        self.aud_label = ttk.Label(self.frame, text="Audience (aud):")
        self.aud_label.grid(row=6, column=0, padx=0, pady=0, sticky="w")
        self.aud_entry = ttk.Entry(self.frame, width=50)
        self.aud_entry.grid(row=6, column=1, padx=0, pady=0, sticky="ew")

        self.use_pkce = tk.BooleanVar(value=True)
        self.use_pkce_checkbutton = ttk.Checkbutton(self.frame, text="Use PKCE", variable=self.use_pkce)
        self.use_pkce_checkbutton.grid(row=7, column=1, padx=0, pady=0, sticky="w")

        self.auth_method = tk.StringVar(value="client_secret_post")
        self.client_secret_post_radiobutton = ttk.Radiobutton(self.frame, text="Client Secret Post", variable=self.auth_method, value="client_secret_post")
        self.client_secret_post_radiobutton.grid(row=8, column=0, padx=0, pady=0, sticky="w")
        self.client_secret_basic_radiobutton = ttk.Radiobutton(self.frame, text="Client Secret Basic", variable=self.auth_method, value="client_secret_basic")
        self.client_secret_basic_radiobutton.grid(row=8, column=1, padx=0, pady=0, sticky="w")


        self.clear_text_checkbox = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Clear response text\n before next request", variable=self.clear_text_checkbox).grid(row=8, column=1, padx=0, pady=2, sticky="e")
        self.log_oidc_process = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Log OIDC process\n in separate window", variable=self.log_oidc_process).grid(row=7, column=1, padx=0, pady=2, sticky="e")
    
        self.generate_request_btn = ttk.Button(self.frame, text="Generate Auth Request", command=self.generate_auth_request)
        self.generate_request_btn.grid(row=9, column=0, padx=0, pady=2, sticky="w")

        self.auth_url_text = tk.Text(self.frame, height=5, width=80)
        self.auth_url_text.grid(row=10, column=0, columnspan=2, padx=0, pady=5, sticky="ew")

        self.submit_btn = ttk.Button(self.frame, text="Submit Auth Request", command=self.submit_auth_request)
        self.submit_btn.grid(row=11, column=1, padx=0, pady=5, sticky="w")
        
        self.response_table_frame = ttk.Frame(self.frame)
        self.response_table_frame.grid(row=0, column=2, rowspan=9, padx=5, pady=5, sticky="nsew")

        table_scrollbar_y = ttk.Scrollbar(self.response_table_frame, orient="vertical")
        table_scrollbar_x = ttk.Scrollbar(self.response_table_frame, orient="horizontal")

        self.response_table = ttk.Treeview(self.response_table_frame, columns=("Key", "Value"), show="headings", yscrollcommand=table_scrollbar_y.set, xscrollcommand=table_scrollbar_x.set)
        self.response_table.heading("Key", text="Key")
        self.response_table.heading("Value", text="Value")

        # Set column widths
        self.response_table.column("Key", width=200)
        self.response_table.column("Value", width=600)

        table_scrollbar_y.config(command=self.response_table.yview)
        table_scrollbar_x.config(command=self.response_table.xview)

        self.response_table.grid(row=0, column=1, sticky="nsew")
        table_scrollbar_y.grid(row=0, column=2, sticky="ns")
        table_scrollbar_x.grid(row=1, column=1, sticky="ew")

        self.response_text = tk.Text(self.frame, height=30, width=100)
        self.response_text.grid(row=12, column=0, columnspan=2, padx=0, pady=5, sticky="nsew")
        response_text_scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.response_text.yview)
        self.response_text.configure(yscrollcommand=response_text_scrollbar.set)
        response_text_scrollbar.grid(row=12, column=2, sticky="ns")

        self.certificate_btn = ttk.Button(self.frame, text="Show Certificate", command=self.show_certificate)
        self.certificate_btn.grid(row=13, column=1, padx=0, pady=5, sticky="w")

        self.replace_certificate_btn = ttk.Button(self.frame, text="Replace Certificate", command=self.replace_certificate)
        self.replace_certificate_btn.grid(row=14, column=1, padx=0, pady=5, sticky="w")

        self.oidc_log_window = None
        self.window.update_idletasks() 

    def create_labeled_entry(self, frame, text, row, col, width=50):
        ttk.Label(frame, text=text).grid(row=row, column=col, padx=5, pady=5)
        entry = ttk.Entry(frame, width=width)
        entry.grid(row=row + 1, column=col, padx=5, pady=5, sticky="ew")
        return entry

    def create_scrollable_text(self, frame, height, width, theme, row, col, colspan=1):
        text_widget = tk.Text(frame, wrap=tk.WORD, height=height, width=width, bg=self.NORD_STYLES[theme]["background"], fg=self.NORD_STYLES[theme]["foreground"])
        text_widget.grid(row=row, column=col, columnspan=colspan, padx=5, pady=5, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=row, column=col + colspan, sticky="ns")
        return text_widget

    def create_well_known_dropdown(self, frame, well_known_entry):
        well_known_var = tk.StringVar()
        well_known_dropdown = ttk.Combobox(frame, textvariable=well_known_var)
        well_known_dropdown['values'] = [
            'https://localhost:9031/.well-known/openid-configuration',
            'https://sso.cfi.prod.aws.southwest.com/.well-known/openid-configuration',
            'https://sso.fed.dev.aws.swacorp.com/.well-known/openid-configuration',
            'https://sso.fed.dev.aws.swalife.com/.well-known/openid-configuration',
            'https://sso.fed.prod.aws.swacorp.com/.well-known/openid-configuration',
            'https://sso.fed.prod.aws.swalife.com/.well-known/openid-configuration',
            'https://sso.fed.qa.aws.swacorp.com/.well-known/openid-configuration',
            'https://sso.fed.qa.aws.swalife.com/.well-known/openid-configuration'
        ]
        well_known_dropdown.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        def on_select(event):
            well_known_entry.delete(0, tk.END)
            well_known_entry.insert(0, well_known_var.get())

        well_known_dropdown.bind("<<ComboboxSelected>>", on_select)
        return well_known_dropdown

    def open_oidc_log_window(self):
        if self.oidc_log_window is None or not self.oidc_log_window.winfo_exists():
            self.oidc_log_window = tk.Toplevel(self.window)
            self.oidc_log_window.title("OIDC Process Log")
            self.oidc_log_window.geometry("600x400")
            self.oidc_log_window.grid_rowconfigure(0, weight=1)
            self.oidc_log_window.grid_columnconfigure(0, weight=1)
            self.oidc_log_text = tk.Text(self.oidc_log_window, wrap=tk.WORD)
            self.oidc_log_text.grid(row=0, column=0, sticky="nsew")
            oidc_log_scrollbar = ttk.Scrollbar(self.oidc_log_window, orient="vertical", command=self.oidc_log_text.yview)
            self.oidc_log_text.configure(yscrollcommand=oidc_log_scrollbar.set)
            oidc_log_scrollbar.grid(row=0, column=1, sticky="ns")

    def update_endpoint_entry(self, event):
        selected_value = self.well_known_var.get()
        if selected_value:
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, selected_value)
        else:
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, "Enter well-known endpoint URL")

    def fetch_well_known(self):
        if self.log_oidc_process.get():
            self.open_oidc_log_window()

        well_known_url = self.endpoint_entry.get().strip()

        if not well_known_url:
            self.response_text.insert(tk.END, "Please enter a well-known endpoint URL.\n")
            return

        try:
            response = requests.get(well_known_url, verify=self.ssl_context)
            response.raise_for_status()
            well_known_data = response.json()
            self.display_well_known_response(well_known_data)
            self.response_text.insert(tk.END, f"Well-known configuration loaded.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Well-known configuration response:\n{json.dumps(well_known_data, indent=4)}\n")

        except requests.exceptions.ConnectionError as e:
            messagebox.showerror("Connection Error", f"Failed to connect to {well_known_url}. Please check the URL and your network connection.")
            self.log_error("Connection Error", e)
        except urllib3.exceptions.MaxRetryError as e:
            messagebox.showerror("Max Retry Error", f"Max retries exceeded for {well_known_url}. Please check the URL and your network connection.")
            self.log_error("Max Retry Error", e)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Request Error", f"An error occurred while fetching the well-known configuration: {e}")
            self.log_error("Request Error", e)
        except requests.exceptions.InvalidURL as e:
            messagebox.showerror("Request Error", f"An error occurred while fetching the well-known configuration: {e}")
            self.log_error("Request Error", e)            
        except Exception as ssl_error:
            response = requests.get(well_known_url, verify=False)
            well_known_data = response.json()
            self.display_well_known_response(well_known_data)
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Well-known configuration response:\n{json.dumps(well_known_data, indent=4)}\n")

        if response.status_code != 200:
            self.response_text.insert(tk.END, f"Error fetching well-known configuration: {response.status_code}\n")
            self.log_error("Unable to query Well-known Endpoint", f"{response.status_code}")

        return well_known_data

    def generate_auth_request(self):
        if self.log_oidc_process.get():
            self.open_oidc_log_window()

        well_known_url = self.endpoint_entry.get().strip()
        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()
        scopes = self.scope_entry.get().strip()
        server_name = self.server_name_entry.get().strip()
        aud = self.aud_entry.get().strip()

        if not server_name:
            server_name = "localhost"

        if not well_known_url or not client_id:
            self.response_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            return

        try:
            try:
                response = requests.get(well_known_url, verify=self.ssl_context)
            except Exception as ssl_error:
                response = requests.get(well_known_url, verify=False)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching well-known configuration: {response.status_code}\n")
                self.log_error("Unable to query Well-known Endpoint", f"{response.status_code}")
                return

            config = response.json()
            self.display_well_known_response(config)
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Well-known configuration response:\n{json.dumps(config, indent=4)}\n")

            auth_endpoint = config.get("authorization_endpoint")
            token_endpoint = config.get("token_endpoint")
            introspection_endpoint = config.get("introspection_endpoint")
            userinfo_endpoint = config.get("userinfo_endpoint")

            if not auth_endpoint or not token_endpoint:
                self.response_text.insert(tk.END, "Error: Unable to find authorization or token endpoint in the configuration.\n")
                self.log_error("Missing data in OIDC Well-Known Endpoint", "Error in configuration")
                return

            state = self.generate_state()
            nonce = self.generate_nonce()
            params = {
                "client_id": client_id,
                "redirect_uri": f"https://{server_name}:{self.server_port}/callback",
                "response_type": "code",
                "scope": scopes,
                "state": state,
                "nonce": nonce,
                "aud": aud  # Add audience to the request parameters
            }

            if self.use_pkce.get():
                code_verifier, code_challenge = self.generate_pkce()
                params.update({
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256"
                })
                self.code_verifier = code_verifier
            else:
                self.code_verifier = None

            auth_url = f"{auth_endpoint}?{self.encode_params(params)}"
            self.auth_url_text.delete(1.0, tk.END)
            self.auth_url_text.insert(tk.END, auth_url)
            self.state = state
            self.token_endpoint = token_endpoint
            self.client_id = client_id
            self.client_secret = client_secret
            self.introspect_endpoint = introspection_endpoint
            self.userinfo_endpoint = userinfo_endpoint
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Authorization URL: {auth_url}\n")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error generating auth request: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error generating auth request: {e}\n")
            self.log_error("Error create OIDC Auth Request", e)

        try:
            # Generate the self-signed certificate
            self.generate_self_signed_cert() 
            # Start the HTTPS server after the certificate is created
            self.start_https_server()
        except Exception as e:
            self.response_text.insert(tk.END, "Web server failed.\n")

    def generate_state(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')

    def generate_nonce(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')

    def generate_pkce(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).decode('utf-8').rstrip('=')
        return code_verifier, code_challenge

    def encode_params(self, params):
        return '&'.join([f"{k}={requests.utils.quote(v)}" for k, v in params.items()])

    def submit_and_log(self):
        if not os.path.exists("oidc_out.json"):
            with open("oidc_out.json", "w") as file:
                json.dump([], file)
        try:
            self.submit_auth_request()
        except Exception as e:
            self.log_error("Error in submit_auth_request", e)

    def submit_auth_request(self):
        auth_url = self.auth_url_text.get(1.0, tk.END).strip()
        if not auth_url:
            self.response_text.insert(tk.END, "Please generate an authentication request URL first.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Authorization URL is empty. Generate the auth request first.\n")
            return
        webbrowser.open(auth_url)
        self.response_text.insert(tk.END, "Please complete the authentication in your browser.\n")
        if self.log_oidc_process.get():
            self.oidc_log_text.insert(tk.END, f"Opened Authorization URL: {auth_url}\n")

        self.response_text.insert(tk.END, f"Opened Authorization URL: {auth_url}\n")

    def generate_self_signed_cert(self):
        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Texas"
        cert.get_subject().L = "Dallas"
        cert.get_subject().O = "Southwest Airlines"
        cert.get_subject().OU = "CyberOps"
        cert.get_subject().CN = server_name
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        with open("server.crt", "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        with open("server.key", "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode('utf-8'))
        self.cert = cert

    def show_certificate(self):
        # Show the public certificate
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert).decode('utf-8')
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())

        # Display the certificate details
        cert_details = f"Public Certificate:\n{cert_pem}\n\n"
        cert_details += f"Issuer: {cert.issuer.rfc4514_string()}\n"
        cert_details += f"Subject: {cert.subject.rfc4514_string()}\n"
        cert_details += f"Serial Number: {cert.serial_number}\n"
        cert_details += f"Not Before: {cert.not_valid_before}\n"
        cert_details += f"Not After: {cert.not_valid_after}\n"

        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, cert_details)

    def replace_certificate(self):
        cert_file_path = tk.filedialog.askopenfilename(title="Select Certificate File", filetypes=[("Certificate Files", "*.crt *.pem")])
        key_file_path = tk.filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key *.pem")])

        if cert_file_path and key_file_path:
            with open(cert_file_path, "r") as cert_file:
                self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
            with open(key_file_path, "r") as key_file:
                self.key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(tk.END, "Certificate and key replaced successfully.\n")
        else:
            self.response_text.delete(1.0, tk.END)
            self.response_text.insert(tk.END, "Certificate or key file not selected.\n")

    def start_https_server(self):
        print("Starting HTTPS server")
        global https_server, https_server_thread
        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        # Check if the server name resolves
        try:
            print(f"Resolving server name: {server_name}")
            socket.gethostbyname(server_name)
        except socket.error:
            self.response_text.insert(tk.END, f"Server name '{server_name}' does not resolve. Using localhost instead.\n")
            server_name = "localhost"
            print(f"Server name '{server_name}' does not resolve. Using localhost instead.\n")
        print(f"Server name: {server_name}")

        if https_server is not None: 
            self.response_text.insert(tk.END, "HTTPS server is already running.\n")
            print("HTTPS server is already running.")
            return

        handler = self.create_https_handler()
        https_server = socketserver.TCPServer((server_name, self.server_port), handler)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)

        https_server_thread = threading.Thread(target=https_server.serve_forever)
        https_server_thread.daemon = True
        
        try:
            https_server_thread.start()
            if https_server_thread.is_alive():
                print(f"HTTPS server started on https://{server_name}:{self.server_port}/callback")

            self.response_text.insert(tk.END, f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
            self.response_text.insert(tk.END, f"Please confirm {self.client_id} has the redirect uri:  https://{server_name}:{self.server_port}/callback\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
                self.oidc_log_text.insert(tk.END, f"Please confirm {self.client_id} has the redirect uri:  https://{server_name}:{self.server_port}/callback\n")
                self.add_horizontal_rule()

        except Exception as e:
            print(f"HTTPS server https://{server_name}:{self.server_port} Failed.")
            self.response_text.insert(tk.END, f"HTTPS server https://{server_name}:{self.server_port} Failed.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"HTTPS server https://{server_name}:{self.server_port} Failed.: {e}\n")
                self.add_horizontal_rule()
            self.log_error("HTTPS server Failed.", e)

    def add_horizontal_rule(self):
            self.response_text.insert(tk.END, f"---------------------------------------------------\n\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"---------------------------------------------------\n\n")

    def create_https_handler(self):
        parent = self

        class HTTPSHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/callback'):
                    query = self.path.split('?')[-1]
                    params = {k: v for k, v in (item.split('=') for item in query.split('&'))}
                    code = params.get('code')
                    parent.response_text.insert(tk.END, f"Received code: {code}\n")
                    if parent.log_oidc_process.get():
                        parent.oidc_log_text.insert(tk.END, f"Received authorization code: {code}\n")
                    parent.exchange_code_for_tokens(code)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authorization code received. You can close this window.")

                else:
                    self.send_error(404, "Not Found")

            def do_POST(self):
                if self.path == '/kill_server':
                    threading.Thread(target=shutdown_https_server).start()
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Server shutdown initiated.")
                if parent.log_oidc_process.get():
                    parent.oidc_log_text.insert(tk.END, "Server shutdown initiated.\n")
        return HTTPSHandler   

    def exchange_code_for_tokens(self, code):

        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        try:
            data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"https://{server_name}:{self.server_port}/callback",
                "client_id": self.client_id,
            }
            headers = {}
            if self.code_verifier:
                data["code_verifier"] = self.code_verifier
            if self.auth_method.get() == "client_secret_post":
                data["client_secret"] = self.client_secret
            elif self.auth_method.get() == "client_secret_basic":
                basic_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
                headers["Authorization"] = f"Basic {basic_auth}"
            elif self.auth_method.get() == "client_secret_jwt":
                now = int(time.time())
                payload = {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": self.token_endpoint,
                    "exp": now + 300,  # Token expires in 5 minutes
                    "iat": now
                }

                def base64url_encode(input):
                    return base64.urlsafe_b64encode(input).decode('utf-8').rstrip('=')

                encoded_header = base64url_encode(json.dumps(headers).encode('utf-8'))
                encoded_payload = base64url_encode(json.dumps(payload).encode('utf-8'))
                signature = base64.urlsafe_b64encode(
                    hmac.new(self.client_secret.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256).digest()
                ).decode('utf-8').rstrip('=')

                client_assertion = f"{encoded_header}.{encoded_payload}.{signature}"
                data["client_assertion"] = client_assertion
                data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


            try:
                response = requests.post(self.token_endpoint, data=data, headers=headers, verify=self.ssl_context)
            except Exception as ssl_error:
                response = requests.post(self.token_endpoint, data=data, headers=headers, verify=False)
            #response = requests.post(self.token_endpoint, data=data, headers=headers, verify=False)
            
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching tokens: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error fetching tokens: {response.status_code}\n")
                    self.add_horizontal_rule()
                return

            tokens = response.json()
            self.display_tokens(tokens)
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Token Exchange Response: {json.dumps(tokens, indent=4)}\n")
                self.add_horizontal_rule()
            
        except Exception as e:
            self.response_text.insert(tk.END, f"Error exchanging code for tokens: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error exchanging code for tokens: {e}\n")
                self.add_horizontal_rule()

            self.log_error("Error exchanging code for tokens", e)

    def stop_https_server(self): 
        global https_server, https_server_thread
        if https_server:
            try:
                https_server.shutdown()
                https_server.server_close()
                https_server_thread.join()
                https_server = None
                https_server_thread = None
            except Exception as e:
                self.log_error("Error stopping HTTPS server", e)

        self.response_text.insert(tk.END, "HTTPS server stopped.\n")

    def display_tokens(self, tokens):
        self.response_text.insert(tk.END, f"Display Tokens:\n")
        if self.log_oidc_process.get():
            self.oidc_log_text.insert(tk.END, "Display Tokens:\n")
            self.add_horizontal_rule()
        try:
        # Clear the response text if the checkbox is checked 
            if self.clear_text_checkbox.get(): 
                self.response_text.delete(1.0, tk.END)
            #self.response_text.delete(1.0, tk.END)
            
            for key, value in tokens.items():
                self.response_text.insert(tk.END, f"{key}: {value}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"{key}: {value}\n")
                    self.add_horizontal_rule()

            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            id_token = tokens.get("id_token")
            atoken = self.decode_jwt(access_token)
            id = self.decode_jwt(id_token)
            if refresh_token:
                refresh = self.decode_jwt(refresh_token)
            userinfo = self.userinfo_query(access_token)
            introspect = self.introspect_token(access_token, "access" )


            self.response_text.insert(tk.END, f"Access Token: {access_token}\n")
            self.response_text.insert(tk.END, f"Refresh Token: {refresh_token}\n")
            self.response_text.insert(tk.END, f"ID Token: {id_token}\n")
            self.response_text.insert(tk.END, f"ID Token Decoded: {id}\n")
            self.response_text.insert(tk.END, f"Refresh Token Decoded: {refresh}\n")
            self.response_text.insert(tk.END, f"UserInfo: {userinfo}\n")
            self.response_text.insert(tk.END, f"Introspect: {introspect}\n")
            self.response_text.insert(tk.END, f"Tokens: {json.dumps(tokens, indent=4)}\n")

#            if "refresh_token" in tokens:
 #               self.introspect_token(tokens["refresh_token"], "refresh")
  #          if "aud" in tokens:
   #             self.response_text.insert(tk.END, f"Audience: {tokens['aud']}\n")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error displaying tokens: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error displaying tokens: {e}\n")
                self.add_horizontal_rule()
            self.log_error("Error displaying tokens", e)

        print(f"Access Token: {access_token}\n")
        print(f"Access Token: {atoken}\n")
        print("--------------------")
        print(f"Refresh Token: {refresh_token}\n")
        print(f"Refresh Token Decoded: {refresh}\n")
        print("--------------------")
        print(f"ID Token: {id_token}\n")
        print(f"ID Token Decoded: {id}\n")
        print("--------------------")
        print(f"UserInfo: {userinfo}\n")
        print(f"Introspect: {introspect}\n")
        print("--------------------")

        print(f"Tokens: {json.dumps(tokens, indent=4)}\n")

    def decode_jwt(self, token):
        try:
            if token.count('.') != 2:
                raise ValueError("Invalid JWT token format")
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            decoded = {
                "header": json.loads(header_decoded),
                "payload": json.loads(payload_decoded),
                "signature": signature
            }
            print("********************************")
            print(f"Token: {token}")
            print(f"Decoded Token: {json.dumps(decoded, indent=4)}\n")
            print("********************************")

        except Exception as e:
            print(f"Error decoding JWT: {e}")
            self.response_text.insert(tk.END, f"Error decoding JWT: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error decoding JWT: {e}\n")
                self.add_horizontal_rule()

    def userinfo_query(self, token):
        try:
            headers = {
                'Authorization': f'Bearer {token}'
            }

            #try:
            #    response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=self.ssl_context)
            #except Exception as ssl_error:
            #    response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=False)
            
            response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=False)

            response.raise_for_status()
            
            print (f"requesting userinfo from {self.userinfo_endpoint}")
            print (f"headers: {headers}")
            print (f"response: {response}")

            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error userinfo {token_type} token: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error userinfo {token_type} token: {response.status_code}\n")
                    self.add_horizontal_rule()
                return

            userinfo = response.json()
            print("userinfo", json.dumps(userinfo, indent=4))


            self.response_text.insert(tk.END, f"UserInfo {token_type.capitalize()} Token: {json.dumps(userinfo, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"UserInfo {token_type.capitalize()} Token: {json.dumps(userinfo, indent=4)}\n")
                self.add_horizontal_rule()
        except Exception as e:
            print("userinfo failed")
            self.response_text.insert(tk.END, f"Error calling UserInfo: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error calling UserInfo: {e}\n")
                self.add_horizontal_rule()
        print("********************************")
        print("userinfo", json.dumps(userinfo, indent=4))

    def introspect_token(self, token, token_type):
        try:
            data = {
                "token": token,
                "token_type_hint": "access_token",
                "client_id": self.client_id,
            }
            headers = {}
            if self.auth_method.get() == "client_secret_post":
                data["client_secret"] = self.client_secret
            elif self.auth_method.get() == "client_secret_basic":
                basic_auth = base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
                headers["Authorization"] = f"Basic {basic_auth}"
            elif self.auth_method.get() == "client_secret_jwt":
                now = int(time.time())
                payload = {
                    "iss": self.client_id,
                    "sub": self.client_id,
                    "aud": self.introspect_endpoint,
                    "exp": now + 300,  # Token expires in 5 minutes
                    "iat": now
                }
                client_assertion = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
                data["client_assertion"] = client_assertion
                data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

            try:
                response = requests.post(self.introspect_endpoint, data=data, headers=headers, verify=self.ssl_context)
            except Exception as ssl_error:
                response = requests.post(self.introspect_endpoint, data=data, headers=headers, verify=False)
            #response = requests.post(self.introspect_endpoint, data=data, headers=headers, verify=False)

            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error introspecting {token_type} token: {response.status_code}\n")
                    self.add_horizontal_rule()
                return

            introspection = response.json()
            print("introspection", introspection)
            self.response_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
                self.add_horizontal_rule()
        except Exception as e:
            self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")
                self.add_horizontal_rule()
            self.log_error("Error introspecting token", e)

    def display_well_known_response(self, config):
        # Clear only the treeview items instead of destroying all widgets
        if hasattr(self, 'response_table'):
            self.response_table.delete(*self.response_table.get_children())
        else:
            # Add scrollbars
            table_scrollbar_y = ttk.Scrollbar(self.response_table_frame, orient="vertical")
            table_scrollbar_x = ttk.Scrollbar(self.response_table_frame, orient="horizontal")

            columns = ("Key", "Value")
            self.response_table = ttk.Treeview(self.response_table_frame, columns=columns, show="headings", yscrollcommand=table_scrollbar_y.set, xscrollcommand=table_scrollbar_x.set)
            self.response_table.heading("Key", text="Key")
            self.response_table.heading("Value", text="Value")

            # Set column widths
            self.response_table.column("Key", width=200)
            self.response_table.column("Value", width=600)

            # Attach scrollbars to the table
            table_scrollbar_y.config(command=self.response_table.yview)
            table_scrollbar_x.config(command=self.response_table.xview)

            self.response_table.grid(row=1, column=1, sticky="nsew")
            table_scrollbar_y.grid(row=1, column=0, sticky="ns")
            table_scrollbar_x.grid(row=0, column=1, sticky="ew")

            # Increase the row height
            style = ttk.Style()
            style.configure("Treeview", rowheight=30)

            # Bind double-click event
            self.response_table.bind("<Double-1>", self.on_item_double_click)

        for key, value in config.items():
            self.response_table.insert("", "end", values=(key, value))


def main():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    theme = sys.argv[1] if len(sys.argv) > 1 else "standard"
    debugger = OIDCDebugger(root, theme)
    root.mainloop()

if __name__ == "__main__":
    main()