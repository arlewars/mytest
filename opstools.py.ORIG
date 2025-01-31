import os
import io
from io import BytesIO
import sys
import json
import shlex
import socket
import re  
import hashlib
import hmac
import random
import base64
#import resource
from datetime import datetime, timedelta
import time
import subprocess
import ssl
import concurrent.futures
import queue
import threading
import webbrowser
import logging
from logging.handlers import TimedRotatingFileHandler
import warnings
import aiodns
import asyncio
import aiohttp
from aiohttp import ClientConnectorCertificateError
import requests
from requests.auth import HTTPBasicAuth
import contextlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend 
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from PIL import Image, ImageTk
import dns.resolver
import socketserver
import http.server
from http.server import BaseHTTPRequestHandler, HTTPServer
import pygame
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
disable_warnings(InsecureRequestWarning)
from urllib.parse import urlencode, urlparse, parse_qs
from OpenSSL import crypto
from ping3 import ping , verbose_ping #PingError
import certifi
import yarl
import psutil
import platform

import tkinter as tk
from tkinter import ttk, colorchooser, filedialog, messagebox, Toplevel, Label

python_executable = sys.executable
current_path = os.getcwd()

VERSION = "1.3.1"
GITURL = "https://southwest.gitlab-dedicated.com/csengops/ping/opstools/"
RELEASEURL = "https://southwest.gitlab-dedicated.com/csengops/ping/opstools/release/version.json"

# Ensure errors.json exists
if not os.path.exists("errors.json"):
    with open("errors.json", "w") as file:
        json.dump([], file)

# Configure logging
logger = logging.getLogger("ErrorLogger")
logger.setLevel(logging.INFO)
handler = TimedRotatingFileHandler("errors.json", when="midnight", interval=30, backupCount=1, encoding="utf-8")
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

# Logging for aiohttp
DebugAIOHTTP = False
SetAsyncDebug = False
RequestsDebug = False
CA_path = ""

#Silence Self Signed Certificate Errors
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore")

# Check if certifi is installed and get the path to the CA certificates
try:
    def_cert_path = certifi.where() 
    cert_path = certifi.where() 
    if os.name == 'nt':
        CA_path = '"' + CA_path + '"' # Add quotes for Windows Compatibility
        cert_path = '"' + def_cert_path + '"' # Add quotes for Windows Compatibility
    else:
        cert_path = shlex.quote(def_cert_path)
        CA_path = shlex.quote(def_CA_path)
except Exception as e:
    cert_path = None

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

hanger_mappings = {
    'prod0': 'hanger0',
    'prod1': 'hanger1',
    'qa0': 'hanger0',
    'qa1': 'hanger1',
    'dev0': 'hanger0',
    'dev1': 'hanger1'
}

# Global variable for the server
env = ""
https_server = None
https_server_thread = None  # Add a reference to the thread
first_run = True
def_CA_path = ""

def log_error(message, exception):
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

def check_version():
    try:
        response = requests.get(RELEASEURL)
        response.raise_for_status()
        data = response.json()
        git_version = data.get("version")

        if git_version is None:
          log_error("Version check unavailble","Error")

        if git_version > VERSION:
            message_box.showinfo("Update Available on Git, Please refer to Confluence or Help")
    except Exception as e:
            log_error("Version check failed",e)


def validate_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def enable_aiohttp_debugging():
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('aiohttp').setLevel(logging.DEBUG)
    logging.getLogger('aiohttp.client').setLevel(logging.DEBUG)
    logging.getLogger('aiohttp.server').setLevel(logging.DEBUG)
    logging.getLogger('aiocio').setLevel(logging.DEBUG)

def shutdown_https_server():
    global https_server, https_server_thread
    if https_server:
        try:
            https_server.shutdown()
            https_server.server_close()
            https_server = None
            https_server_thread.join()  # Ensure the thread properly terminates
            https_server_thread = None
            print("HTTPS server shut down.")
        except Exception as e:
            print(f"Error during HTTPS server shutdown: {e}")
    else:
        print("No HTTPS server is running.")

def kill_me_please(server):
    server.shutdown()
    server.server_close()
    print("HTTPS server shut down.")

# Load custom theme if it exists
def load_custom_theme():
    if os.path.exists("customtheme.json"):
        with open("customtheme.json", "r") as file:
            custom_theme = json.load(file)
        if custom_theme:
            NORD_STYLES["custom"] = custom_theme
            for key in DEFAULT_THEME:
                if key not in custom_theme:
                    custom_theme[key] = DEFAULT_THEME[key]
            return "custom"
    return "standard"

# Save custom theme to a file
def save_custom_theme(theme):
    with open("customtheme.json", "w") as file:
        json.dump(theme, file)

def validate_url_and_check_sql_injection(url):
    # Step 1: Validate the URL structure
    url_regex = re.compile(
        r'^(?:http|ftp)s?://'  # scheme (http:// or https://)
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain name
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP address
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6 address
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    if not re.match(url_regex, url):
        return False  # Invalid URL format
    
    # Step 2: Detect SQL injection patterns
    sql_injection_patterns = re.compile(
        r"(?i)"  # Case insensitive flag
        r"(union|select|insert|update|delete|drop|truncate|show|--|;|#|\*|char|concat|exec|script|alert|[\'\"=])"
    )
    
    # If SQL injection patterns are found, return False
    if re.search(sql_injection_patterns, url):
        return False  # Detected potential SQL injection
    
    return True  # Valid URL and no SQL injection

def dump_all_variables():
        print("Local")
        local_vars = locals()
        json.dump(local_vars, sys.stdout, indent=1)
        print("Global")
        global_vars = globals()
        json.dump(global_vars, sys.stdout, indent=1)
        print()

async def resolve_dns(domain):
    resolver = aiodns.DNSResolver(timeout=4)
    try:
        result = await resolver.query(domain, 'A')
        return result
    except aiodns.error.DNSError as e:
        logging.error(f"Error resolving domain for {domain} {e}")
    except Exception as e:
        logging.error(f"Error resolving DNS for {domain}: {e}")
        return None

async def fetch_dns_info(domains):
    tasks = [resolve_dns(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    return results

def create_combined_ssl_context(CA_path, cert_path):
    ssl_context = ssl.create_default_context()
    if os.path.exists(CA_path):
        ssl_context.load_verify_locations(cafile=CA_path)
        ssl_context.load_verify_locations(cafile=None, capath=cert_path, cadata=None)
    else:
        ssl_context.load_verify_locations(cafile=None, capath=cert_path, cadata=None)
    return ssl_context

# Apply theme
def apply_theme(theme):
    style = ttk.Style()
    style.theme_use("clam")
    colors = NORD_STYLES[theme]
    button_background_color = colors["button_background"]
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
    background_color = colors["background"]
    foreground_color = colors["foreground"]
    highlight_color = colors["highlight"]
    error_color = colors["error"]
    header_color = colors["header"]
    row_odd_color = colors["row_odd"]
    row_even_color = colors["row_even"]
    button_color = colors["button"]
    invert_button_color = colors["invert_button"]
    custom_theme = {
        "background": background_color,
        "foreground": foreground_color,
        "highlight": highlight_color,
        "error": error_color,
        "header": header_color, 
        "row_odd": row_odd_color,
        "row_even": row_even_color,
        "button": button_color,
        "invert_button": invert_button_color,
        "button_background": button_background_color
    }
    save_custom_theme(custom_theme)
    NORD_STYLES["custom"] = custom_theme

# Custom theme window
def open_custom_theme_window():
    def load_theme_values():
        if os.path.exists("customtheme.json"):
            with open("customtheme.json", "r") as file:
                custom_theme = json.load(file)
            if not custom_theme:
                custom_theme = NORD_STYLES["standard"]
        else:
            custom_theme = NORD_STYLES["standard"]

        background_entry.insert(0, custom_theme["background"])
        foreground_entry.insert(0, custom_theme["foreground"])
        highlight_entry.insert(0, custom_theme["highlight"])
        error_entry.insert(0, custom_theme["error"])
        header_entry.insert(0, custom_theme["header"])
        row_odd_entry.insert(0, custom_theme["row_odd"])
        row_even_entry.insert(0, custom_theme["row_even"])
        button_entry.insert(0, custom_theme["button"])
        invert_button_entry.insert(0, custom_theme["invert_button"])
        button_background_entry.insert(0, custom_theme["button_background"])

    def choose_color(entry):
        color_code = colorchooser.askcolor(title="Choose color")[1]
        if color_code:
            entry.delete(0, tk.END)
            entry.insert(0, color_code)

    def apply_theme_and_save():
        custom_theme = {
            "background": background_entry.get(),
            "foreground": foreground_entry.get(),
            "highlight": highlight_entry.get(),
            "error": error_entry.get(),
            "header": header_entry.get(),
            "row_odd": row_odd_entry.get(),
            "row_even": row_even_entry.get(),
            "button": button_entry.get(),
            "invert_button": invert_button_entry.get(),
            "button_background": button_background_entry.get()
        }
        save_custom_theme(custom_theme)
        NORD_STYLES["custom"] = custom_theme
        apply_theme("custom")
        custom_theme_window.destroy()

    custom_theme_window = tk.Toplevel()
    custom_theme_window.title("Custom Theme")
    custom_theme_window.geometry("800x600")
    custom_theme_window.attributes("-topmost", True)

    frame = ttk.Frame(custom_theme_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    labels = [
        "Background", "Foreground", "Highlight", "Error", 
        "Header", "Row Odd", "Row Even", "Button", "Invert Button", "Button Background"
    ]
    entries = {}

    for i, label in enumerate(labels):
        ttk.Label(frame, text=label).grid(row=i, column=0, padx=5, pady=5)
        entry = ttk.Entry(frame, width=20)
        entry.grid(row=i, column=1, padx=5, pady=5)
        entries[label.lower().replace(" ", "_")] = entry
        ttk.Button(frame, text="Choose", command=lambda e=entry: choose_color(e)).grid(row=i, column=2, padx=5, pady=5)

    background_entry = entries["background"]
    foreground_entry = entries["foreground"]
    highlight_entry = entries["highlight"]
    error_entry = entries["error"]
    header_entry = entries["header"]
    row_odd_entry = entries["row_odd"]
    row_even_entry = entries["row_even"]
    button_entry = entries["button"]
    invert_button_entry = entries["invert_button"]
    button_background_entry = entries["button_background"]
    load_theme_values()

    ttk.Button(frame, text="Apply and Save Theme", command=apply_theme_and_save).grid(row=len(labels), column=1, pady=10)

def open_jwks_check_window(theme):
    jwks_check_window = CustomWindow("JWKS Check Tool", 1000, 600, theme)
    JWKSCheck(jwks_check_window.frame, theme)

def open_pingfederate_client_app(theme):
    pfclientapp_window = CustomWindow("PingFederate Client App", 1000, 600, theme)
    PingFederateClientApp(pfclientapp_window.frame, theme)

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

def open_tcp_tools_window(theme):
    tcp_tools_window = CustomWindow("TCP Tools", 800, 600, theme)
    frame = tcp_tools_window.frame
    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    ttk.Label(frame, text="Host: ").grid(row=0, column=0, padx=5, pady=5, sticky="w")
    host_entry = ttk.Entry(frame, width=50)
    host_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
    host_entry.insert(0, "Enter hostname")

    tool_selection = ttk.Combobox(frame, values=["Ping", "Nslookup"], state="readonly")
    tool_selection.grid(row=1, column=0, padx=5, pady=5)
    tool_selection.set("Ping")

    result_text = create_scrollable_text(frame, 20, 60, theme, 3, 0, 2)

    async def run_nslookup(host):
        resolver = aiodns.DNSResolver(timeout=4)
        try:
            result_text.delete(1.0, tk.END)
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
            for record_type in record_types:
                result_text.insert(tk.END, f"\n{record_type} Records:\n")
                try:
                    if record_type == 'CNAME':
                        response = await resolver.query(host, record_type)
                        result_text.insert(tk.END, f"{response.cname}\n")
                    else:
                        response = await resolver.query(host, record_type)
                        for answer in response:
                            if record_type == 'A' or record_type == 'AAAA':
                                result_text.insert(tk.END, f"{answer.host}\n")
                            elif record_type == 'MX':
                                result_text.insert(tk.END, f"{answer.exchange} (Priority: {answer.priority})\n")
                            elif record_type == 'TXT':
                                result_text.insert(tk.END, f"{' '.join(answer.text)}\n")
                except aiodns.error.DNSError as e:
                    result_text.insert(tk.END, f"Error fetching {record_type} records: {e}\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error running Nslookup: {e}")

    def run_ping(host):
        try:
            result_text.delete(1.0, tk.END)
            with io.StringIO() as buf, contextlib.redirect_stdout(buf):
                verbose_ping(host, count=4)
                output = buf.getvalue()
            result_text.insert(tk.END, output)
        except Exception as e:
            result_text.insert(tk.END, f"Error running Ping: {e}")

    def run_tool():
        host = host_entry.get().strip()
        tool = tool_selection.get()
        if host:
            try:
                result_text.delete(1.0, tk.END)
                if tool == "Ping":
                    run_ping(host)
                elif tool == "Nslookup":
                    asyncio.run(run_nslookup(host))
                else:
                    result_text.insert(tk.END, "Unknown tool selected.")
            except Exception as e:
                result_text.insert(tk.END, f"Error running {tool}: {e}")

    ttk.Button(frame, text="Run", command=run_tool).grid(row=1, column=1, padx=5, pady=5, sticky="e")
    ttk.Button(frame, text="Close", command=tcp_tools_window.window.destroy).grid(row=1, column=2, padx=5, pady=5, sticky="e")

def show_cert_details_window():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("1000x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    cert_pem = cert_data["certificate"]
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    public_key_pem = cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

    text_widget.insert(tk.END, "Certificate:\n")
    text_widget.insert(tk.END, cert_pem)
    text_widget.insert(tk.END, "\n\nPublic Key:\n")
    text_widget.insert(tk.END, public_key_pem)

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)

def open_saml_window(theme):
    saml_window = CustomWindow("SAML Decoder", 1000, 600, theme)
    frame = saml_window.frame
    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    saml_entry = create_labeled_entry(frame, "SAML Token:", 0, 0, width=80)
    saml_entry.insert(0,"Paste SAML Here")

    result_text = create_scrollable_text(frame, 20, 60, theme, 2, 0, 2)

    def decode_saml():
        saml_token = saml_entry.get().strip()
        if not saml_token:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a SAML token.")
            return

        try:
            # Decode the SAML token
            saml_decoded = base64.b64decode(saml_token).decode('utf-8')
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"SAML Token:\n{saml_decoded}\n\n")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error decoding SAML token: {e}")

    ttk.Button(frame, text="Decode SAML", command=decode_saml).grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=saml_window.window.destroy).grid(row=3, column=1, padx=5, pady=5, sticky="e")

def is_connected_to_vpn():
    # Get the current network connections
    connections = psutil.net_if_addrs()
    interface_stats = psutil.net_if_stats()
    interface_counters = psutil.net_io_counters()
    initial_counters = psutil.net_io_counters(pernic=True)


    # Known VPN interface names (can vary based on the VPN service)
    vpn_interfaces = ["utun0", "utun1", "utun2", "utun3", "utun4", "tun0", "tun1", "ppp0", "ppp1", "tap0", "tap1"]
    loopback = ["127.0.0.1"]
    vpn_ip = None
    primary_ip = None

    time.sleep(1)  # Wait for 1 seconds to check if counters are increasing
    final_counters = psutil.net_io_counters(pernic=True)

    # Go into the Windows IF branch
    if platform.system().lower() == 'windows':
        return is_win_connected_to_vpn()

    # ELSE your are not a Windows PC
    else:
        for interface, addrs in connections.items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # Check if it's an IPv4 address
                    ip_address = addr.address
                    if interface in vpn_interfaces:
                        if (final_counters[interface].bytes_sent > initial_counters[interface].bytes_sent or
                            final_counters[interface].bytes_recv > initial_counters[interface].bytes_recv):
                            vpn_ip = ip_address
                    if interface not in vpn_interfaces and ip_address not in loopback: 
                        primary_ip = ip_address
        if vpn_ip:
            #print(f"VPN detected: VPN IP Address {vpn_ip}, Primary Network IP Address {primary_ip}")
            return True, vpn_ip, primary_ip

        #print(f"No VPN detected: Primary Network IP Address {primary_ip}")
        return False, None, primary_ip

def is_win_connected_to_vpn():
    # Run ipconfig /all command
    ipInfo = subprocess.run(("ipconfig", "/all"), capture_output=True, text=True)
    # Extract the output from the command
    output = ipInfo.stdout
    # Define a regex to capture the PANGP interface and its IP address
    PANGP_pattern = re.compile(r"(.*?PANGP.*?)(?:\r?\n|\r)(.*?IPv4.*?(\d+\.\d+\.\d+\.\d+))", re.DOTALL)
    # Search for the interface and its IP
    PANGP_match = PANGP_pattern.search(output)
    # Search for local IP
    hostname = socket.gethostname()
    primary_ip = socket.gethostbyname(hostname)
    #If we have a VPN connection
    if PANGP_match:
        interface_name = PANGP_match.group(1).strip()
        vpn_ip = PANGP_match.group(3).strip()
        #print(f"PANGP interface detected: vpn:{vpn_ip} primary:{primary_ip}")
        return True, vpn_ip, primary_ip
    else:
        #print(f"PANGP interface not detected: primary:{primary_ip}")
        return False, None, primary_ip

def show_ip_addresses():
    ip_window = Toplevel()
    ip_window.title("IP Addresses")
    ip_window.geometry("400x300")

    frame = ttk.Frame(ip_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    connections = psutil.net_if_addrs()
    all_ips = []
    vpn_connected, vpn_ip, local_ip = is_connected_to_vpn()
    ip_text = f"VPN IP: {vpn_ip}\n\n"

    # Get all IP addresses
    for interface, addrs in connections.items():
       for addr in addrs:
            if addr.family == socket.AF_INET:  # Check if it's an IPv4 address
                ip_address = addr.address
                all_ips.append(ip_address) 

    ip_text += "All IP Addresses:\n" + "\n".join(all_ips)

    ttk.Label(frame, text=ip_text).pack(padx=5, pady=5)
    ttk.Button(frame, text="Close", command=ip_window.destroy).pack(padx=5, pady=5)

class PingFederateClientApp:
    def __init__(self, master, theme=None):
        self.master = master
        self.theme = theme or "standard"
        self.apply_theme(self.theme)
    # Apply custom theme if it exists, otherwise apply default theme
        initial_theme = load_custom_theme()
        apply_theme(initial_theme)
        self.create_toolbar()
        self.create_widgets()
        self.master.grid_rowconfigure(6, weight=1)
        self.master.grid_columnconfigure(1, weight=1)

    def apply_theme(self, theme):
            style = ttk.Style()
            style.theme_use("clam")
            colors = NORD_STYLES[theme]

            background_color = colors["background"]
            style.configure("TFrame", background=background_color)
            style.configure("TLabelFrame", background=background_color, foreground=colors["foreground"])
            style.configure("Treeview", background=background_color, foreground=colors["foreground"], fieldbackground=background_color)
            style.configure("Treeview.Heading", background=colors["header"], foreground=colors["foreground"])
            style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
            style.map("TButton", background=[("active", colors["highlight"])])
            style.configure("TEntry", background=background_color, foreground=colors["foreground"], fieldbackground=background_color)
            style.configure("TText", background=background_color, foreground=colors["foreground"])
            style.configure("Invert.TButton", background=colors["invert_button"], foreground=colors["foreground"])
            style.map("Invert.TButton", background=[("active", colors["highlight"])])
            style.configure("TButton", background=colors["button_background"], foreground=colors["foreground"])
            style.configure("TLabel", background=colors["button_background"], foreground=colors["foreground"])
            style.configure("TEntry", fieldbackground=colors["button_background"], foreground=colors["foreground"])

    def debug_requests(self, response):
        print("PingFederate OAuth Debug Output:")
        print("Request Headers:")
        for key, value in response.request.headers.items():
            print(f"{key}: {value}")
        print("\n\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        if response.headers.get('Content-Type', '').startswith('application/json'):
            print("\n\nResponse Content (JSON):")
            try:
                json_content = response.json()
                print(json.dumps(json_content, indent=4))
            except ValueError as e:
                print("Failed to Parse JSON Content:", e)
        else:
            print("\n\nResponse Content is not JSON.")
            print(response.text)

    def create_toolbar(self):
        toolbar = ttk.Frame(self.master)
        toolbar.grid(row=0, column=0, columnspan=3, sticky="ew")

        theme_var = tk.StringVar(value=self.theme)
        ttk.Label(toolbar, text="Choose Theme:").grid(row=0, column=0, padx=5, pady=5)
        themes_to_show = ["standard", "frost", "aurora"]
        for i, theme_name in enumerate(themes_to_show):
            ttk.Radiobutton(toolbar, text=theme_name.capitalize(), variable=theme_var, value=theme_name, command=lambda: self.apply_theme(theme_var.get())).grid(row=0, column=i+1, padx=5, pady=5)

        ttk.Button(toolbar, text="Customize Theme", command=self.open_customize_theme_window).grid(row=0, column=i+2, padx=5, pady=5)

    def create_widgets(self):
        ttk.Label(self.master, text="Base URL:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.base_url_combobox = ttk.Combobox(self.master, values=["https://console.fed.prod.aws.swacorp.com", "https://console.fed.qa.aws.swacorp.com", "https://console.fed.dev.aws.swacorp.com"])
        self.base_url_combobox.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.base_url_combobox.bind("<<ComboboxSelected>>", self.update_base_url_entry)
        
        self.base_url_entry = tk.Entry(self.master)
        self.base_url_entry.grid(row=1, column=2, padx=5, pady=5, sticky="ew")
        self.base_url_entry.insert(0, "type console url here")

        ttk.Label(self.master, text="User ID:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.user_id_entry = tk.Entry(self.master)
        self.user_id_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.user_id_entry.insert(0, "UserID Here")

        ttk.Label(self.master, text="Password:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = tk.Entry(self.master, show="*")
        self.password_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.password_entry.insert(0, "Password Here")

        self.ignore_cert_var = tk.IntVar()
        self.ignore_cert_check = tk.Checkbutton(self.master, text="Ignore SSL Cert", variable=self.ignore_cert_var)
        self.ignore_cert_check.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

        ttk.Label(self.master, text="Search Client:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
        self.search_entry = tk.Entry(self.master)
        self.search_entry.grid(row=5, column=1, padx=5, pady=5, sticky="ew")

        tk.Button(self.master, text="Fetch Clients", command=self.fetch_clients).grid(row=5, column=2, padx=5, pady=5)

        self.client_listbox = tk.Listbox(self.master, selectmode=tk.SINGLE)
        self.client_listbox.grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        self.scroll_y_client = tk.Scrollbar(self.master, orient=tk.VERTICAL, command=self.client_listbox.yview)
        self.scroll_y_client.grid(row=6, column=2, sticky="ns")
        self.client_listbox.configure(yscrollcommand=self.scroll_y_client.set)

        tk.Button(self.master, text="Get Client Info", command=self.get_client_info).grid(row=7, column=3, padx=5, pady=5)
        self.result_frame = tk.Frame(self.master)
        self.result_frame.grid(row=8, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.result_text = tk.Text(self.result_frame, wrap=tk.NONE)
        self.result_text.grid(row=0, column=0, sticky="nsew")

        self.scroll_x = tk.Scrollbar(self.result_frame, orient=tk.HORIZONTAL, command=self.result_text.xview)
        self.scroll_x.grid(row=1, column=0, sticky="ew")

        self.scroll_y = tk.Scrollbar(self.result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        self.scroll_y.grid(row=0, column=1, sticky="ns")

        self.result_text.configure(xscrollcommand=self.scroll_x.set, yscrollcommand=self.scroll_y.set)

        self.result_frame.grid_rowconfigure(0, weight=1)
        self.result_frame.grid_columnconfigure(0, weight=1)

    def update_base_url_entry(self, event):
        selected_url = self.base_url_combobox.get()
        self.base_url_entry.delete(0, tk.END)
        self.base_url_entry.insert(0, selected_url)

    def open_customize_theme_window(self):
        customizer = CustomizeThemeWindow(self.master, self.theme)
        self.master.wait_window(customizer.top)
        self.apply_theme(self.theme)

    def fetch_clients(self):
        base_url = self.base_url_entry.get()
        clients_url = f"{base_url}/pf-admin-api/v1/oauth/clients"
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        verify_ssl = not self.ignore_cert_var.get()
        search_pattern = self.search_entry.get()
        if RequestsDebug:
            print("\n\nPingFederate OAuth Information:")
            print(f"Fetching clients from: {clients_url}")
            print(f"Userid: {user_id}, search pattern: {search_pattern}")
            print("------------------------------------\n\n")
        try:
            response = requests.get(clients_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=False, timeout=None)
            if RequestsDebug:
                self.debug_requests(response)
                print("response code was: ",response.status_code)
            if response.status_code == 200:
                clients = response.json().get("items", [])
                if not clients:
                    messagebox.showinfo("No Clients Found")

                self.client_listbox.delete(0, tk.END)
                for client in clients:
                    if not search_pattern or re.search(search_pattern, client["clientId"]):
                        self.client_listbox.insert(tk.END, client["clientId"])
                if self.client_listbox.size() == 0:
                    messagebox.showinfo("No Matching Clients Found")
            else:
                messagebox.showerror("Error", f"Failed to fetch clients: {response.status_code}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Request failed: {str(e)}")

    def get_client_info(self):
        selected_client_index = self.client_listbox.curselection()
        if not selected_client_index:
            messagebox.showerror("Error", "Please select a client from the list")
            return
        
        selected_client = self.client_listbox.get(selected_client_index)
        base_url = self.base_url_entry.get()
        client_info_url = f"{base_url}/pf-admin-api/v1/oauth/clients/{selected_client}"
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()
        verify_ssl = not self.ignore_cert_var.get()

        client_info_response = requests.get(client_info_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=False)
        self.debug_requests(client_info_response)
        if client_info_response.status_code == 200:
            client_info = client_info_response.json()
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Client Information:\n")
            self.result_text.insert(tk.END, json.dumps(client_info, indent=4))
            access_token_manager_id = client_info.get("defaultAccessTokenManagerRef", {}).get("id")
            access_token_manager_url = f"{base_url}/pf-admin-api/v1/oauth/accessTokenManagers/{access_token_manager_id}"
            access_token_manager_response = requests.get(access_token_manager_url, auth=HTTPBasicAuth(user_id, password), headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"}, verify=False)
            policy_group = client_info.get("oidcPolicy", {}).get("policyGroup", {})
            policy_group_id = policy_group.get("id")
            policy_group_location = policy_group.get("location")
            if access_token_manager_response.status_code == 200:
                access_token_manager_info = access_token_manager_response.json()
                self.result_text.insert(tk.END, "\n\nAccess Token Manager Information:\n")
                self.result_text.insert(tk.END, json.dumps(access_token_manager_info, indent=4))
                try:
                    policy_group_data = self.fetch_policy_group_location(policy_group_location, base_url, user_id, password)
                    if policy_group_data:
                        self.result_text.insert(tk.END, "\n\nOpenID Policy Information:\n")
                        self.result_text.insert(tk.END, json.dumps(policy_group_data, indent=4))
                    else:
                        self.result_text.insert(tk.END, "\n\nOpenID Policy Information Missing.\n")
                except Exception as e:
                    self.result_text.insert(tk.END, f"\n\nError fetching OpenID Policy Information: {e}\n")
            else:
                messagebox.showerror("Error", f"Failed to fetch access token manager info: {access_token_manager_response.status_code}")
        else:
            messagebox.showerror("Error", f"Failed to fetch client info: {client_info_response.status_code}")

    def get_default_openid(self, base_url, user_id, password):
        url = f"{base_url}/pf-admin-api/v1/oauth/openIdConnect/policies"
        response = requests.get(url, auth=HTTPBasicAuth(user_id, password), verify=False, headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"})
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        
        default_openid = None
        for item in data.get("items", []):
            access_token_manager_ref = item.get("accessTokenManagerRef", {})
            if access_token_manager_ref.get("id") == "default":
                default_openid = access_token_manager_ref.get("location")
                break
        
        return default_openid

    def fetch_policy_group_location(self, policy_group_location, base_url, user_id, password):
        if policy_group_location:
            response = requests.get(policy_group_location, auth=HTTPBasicAuth(user_id, password), verify=False, headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"})
            response.raise_for_status()  # Raise an exception for HTTP errors
            policy_group_data = response.json()
            return policy_group_data
        else:
            policy_group_location = self.get_default_openid(base_url, user_id, password)
            if policy_group_location:
                response = requests.get(policy_group_location, auth=HTTPBasicAuth(user_id, password), verify=False, headers={"accept": "application/json", "X-XSRF-Header": "PingFederate"})
                response.raise_for_status()  # Raise an exception for HTTP errors
                policy_group_data = response.json()
                return policy_group_data
            else:
                return None

def open_jwt_window(theme):
    jwt_window = CustomWindow("JWT Decoder", 1000, 400, theme)
    frame = jwt_window.frame
    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    jwt_entry = create_labeled_entry(frame, "JSON Web Tokens:", 0, 0, width=80)
    jwt_entry.insert(0,"Paste JWT Here")
    result_text = create_scrollable_text(frame, 15, 60, theme, 2, 0, 2)

    def decode_jwt():
        token = jwt_entry.get().strip()
        if not token:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a JWT.")
            return

        try:
            # Split the JWT into its parts
            header_b64, payload_b64, signature_b64 = token.split('.')
            
            # Decode the JWT parts
            header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
            
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Header:\n{json.dumps(header, indent=4)}\n\n")
            result_text.insert(tk.END, f"Payload:\n{json.dumps(payload, indent=4)}\n\n")
            result_text.insert(tk.END, f"Signature:\n{signature_b64}\n")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error decoding JWT: {e}")

    ttk.Button(frame, text="Decode JWT", command=decode_jwt).grid(row=1, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Close", command=jwt_window.window.destroy).grid(row=3, column=1, padx=5, pady=5, sticky="e")

def open_ssl_cert_reader(theme):
    ssl_cert_window = CustomWindow("SSL Certificate Reader", 1000, 600, theme)
    frame = ssl_cert_window.frame
    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    # Create sidebar frame
    sidebar_frame = ttk.Frame(frame, width=200)
    sidebar_frame.grid(row=0, column=0, rowspan=6, sticky="nsw", padx=10, pady=10)
    sidebar_frame.grid_propagate(False)

    # Add instruction label to sidebar
    instruction_label = ttk.Label(sidebar_frame, text="Enter path to the certificate or paste the certificate into the box then click Read Certificate", wraplength=180)
    instruction_label.pack(padx=5, pady=5)

    # Create main content frame
    content_frame = ttk.Frame(frame)
    content_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
    frame.columnconfigure(1, weight=1)
    frame.rowconfigure(0, weight=1)

    cert_file_entry = create_labeled_entry(content_frame, "Certificate File Path:", 0, 0)
    cert_text_entry = create_scrollable_text(content_frame, 10, 60, theme, 2, 0, 2)

    result_text = create_scrollable_text(content_frame, 10, 60, theme, 4, 0, 2)

    def read_ssl_certificate():
        cert_file_path = cert_file_entry.get().strip()
        cert_text = cert_text_entry.get("1.0", tk.END).strip()
        
        if not cert_file_path and not cert_text:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a certificate file path or paste the certificate text.")
            return

        try:
            if cert_text:
                cert_data = cert_text.encode()
            else:
                with open(cert_file_path, "rb") as cert_file:
                    cert_data = cert_file.read()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Certificate Details:\n\n")
            result_text.insert(tk.END, cert.public_bytes(serialization.Encoding.PEM).decode())

            # Display certificate details
            result_text.insert(tk.END, f"\nIssuer: {cert.issuer.rfc4514_string()}")
            result_text.insert(tk.END, f"\nSubject: {cert.subject.rfc4514_string()}")
            result_text.insert(tk.END, f"\nSerial Number: {cert.serial_number}")
            result_text.insert(tk.END, f"\nNot Valid Before: {cert.not_valid_before}")
            result_text.insert(tk.END, f"\nNot Valid After: {cert.not_valid_after}")
            result_text.insert(tk.END, f"\nPublic Key:\n{cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")
        except Exception as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Error reading certificate: {e}")

    ttk.Button(content_frame, text="Read Certificate", command=read_ssl_certificate).grid(row=3, column=1, padx=5, pady=5)
    ttk.Button(content_frame, text="Close", command=ssl_cert_window.window.destroy).grid(row=5, column=1, padx=5, pady=5, sticky="e")

def generate_self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"localhost")
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    
    key_file = "key_file.pem"
    cert_file = "cert_file.pem"
    
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def load_certificates():
    key_file = "key_file.pem"
    cert_file = "cert_file.pem"

    if os.path.exists(key_file) and os.path.exists(cert_file):
        return {"private_key": key_file, "certificate": cert_file}
    generate_self_signed_cert()
    return {"private_key": key_file, "certificate": cert_file}


def show_certificate():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("600x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget.insert(tk.END, "Certificate:\n")
    text_widget.insert(tk.END, cert_data["certificate"])
    text_widget.insert(tk.END, "\n\nPrivate Key:\n")
    text_widget.insert(tk.END, cert_data["private_key"])

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)

def create_labeled_entry(frame, text, row, col, width=50):
    ttk.Label(frame, text=text).grid(row=row, column=col, padx=5, pady=5)
    entry = ttk.Entry(frame, width=width)
    entry.grid(row=row + 1, column=col, padx=5, pady=5, sticky="ew")
    return entry

def create_scrollable_text(frame, height, width, theme, row, col, colspan=1):
    text_widget = tk.Text(frame, wrap=tk.WORD, height=height, width=width, bg=NORD_STYLES[theme]["background"], fg=NORD_STYLES[theme]["foreground"])
    text_widget.grid(row=row, column=col, columnspan=colspan, padx=5, pady=5, sticky="nsew")
    scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)
    scrollbar.grid(row=row, column=col + colspan, sticky="ns")
    return text_widget

def fetch_well_known(endpoint, result_text):
    cert_path = certifi.where()
    ssl_context = create_combined_ssl_context(CA_path, cert_path) #if cert_path else None

    try:
        try:
            response = requests.get(endpoint, verify=ssl_context)
        except Exception as ssl_error:
            response = requests.get(endpoint, verify=False)

        response.raise_for_status()
        well_known_data = response.json()
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, json.dumps(well_known_data, indent=4))
    except Exception as e:
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Error fetching well-known endpoint: {e}")

def open_oauth_window(theme):
    oauth_window = CustomWindow("OAuth Debugger", 1200, 600, theme)
    frame = oauth_window.frame
    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)
    ssl_context = create_combined_ssl_context(CA_path, cert_path) if cert_path else None

    well_known_entry = create_labeled_entry(frame, "OAuth Well-Known Endpoint:", 1, 0)
    well_known_entry.insert(0,"https://sso.fed.dev.aws.swacorp.com/.well-known/openid-configuration")
    token_endpoint_entry = create_labeled_entry(frame, "Token Endpoint:", 3, 0)
    client_id_entry = create_labeled_entry(frame, "Client ID:", 5, 0)
    client_secret_entry = create_labeled_entry(frame, "Client Secret:", 7, 0)
    scopes_entry = create_labeled_entry(frame, "Scopes (space-separated):", 9, 0)

    result_text = create_scrollable_text(frame, 15, 60, theme, 11, 0, 2)

    well_known_table_frame = ttk.Frame(frame)
    well_known_table_frame.grid(row=0, column=3, rowspan=12, padx=10, pady=10, sticky="nsew")

    well_known_table = CustomTable(well_known_table_frame, ("Key", "Value"), 0, 0)

    def fetch_well_known_oauth():
        well_known_url = well_known_entry.get().strip()
        
        if not well_known_url:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a Well-Known Endpoint URL.")
            return
        

        try:
            try:
                well_known_response = requests.get(well_known_url, verify=ssl_context)
            except Exception as ssl_error:
                well_known_response = requests.get(well_known_url, verify=False)

            #well_known_response = requests.get(well_known_url, verify=False)
            well_known_response.raise_for_status()
            well_known_data = well_known_response.json()
            token_endpoint = well_known_data.get("token_endpoint", "")
            token_endpoint_entry.delete(0, tk.END)
            token_endpoint_entry.insert(0, token_endpoint)
            result_text.insert(tk.END, "Well-Known Endpoint fetched successfully.\n")
            
            well_known_table.clear_table()
            for key, value in well_known_data.items():
                well_known_table.insert_row((key, value))
        except Exception as e:
            result_text.insert(tk.END, f"Error fetching Well-Known Endpoint: {e}")
            log_error("Error fetching Well-Known Endpoint in OAuth",e)

    def decode_jwt(token):
        try:
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            decoded = {
                "header": json.loads(header_decoded),
                "payload": json.loads(payload_decoded),
                "signature": signature
            }
            return json.dumps(decoded, indent=4)
        except Exception as e:
            log_error("Error decoding JWT",e)
            return f"Error decoding JWT: {e}"


    def get_oauth_tokens():
        token_endpoint = token_endpoint_entry.get().strip()
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()
        scopes = scopes_entry.get().strip()


        if not all([token_endpoint, client_id, client_secret, scopes]):
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please fill in all fields to get tokens.")
            return

        result_text.delete(1.0, tk.END)
        try:
            data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'client_credentials',
                'scope': scopes
            }
            try:
                ssl_context = create_combined_ssl_context(CA_path, cert_path) if cert_path else None
                response = requests.post(token_endpoint, data=data, verify=ssl_context)
            except Exception as ssl_error:
                response = requests.post(token_endpoint, data=data, verify=False)

            #response = requests.post(token_endpoint, data=data, verify=False)
            response.raise_for_status()
            token_data = response.json()
            access_token = token_data.get('access_token')
            result_text.insert(tk.END, f"Access Token:\n{access_token}\n\n")
            result_text.insert(tk.END, f"Token Type:\n{token_data.get('token_type')}\n\n")
            result_text.insert(tk.END, f"Expires In:\n{token_data.get('expires_in')}\n\n")

            if access_token:
                decoded_token = decode_jwt(access_token)
                result_text.insert(tk.END, f"Decoded Access Token:\n{decoded_token}\n\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error retrieving OAuth tokens: {e}")
            log_error("Error retrieving OAuth token",e)

    def show_cert_details():
        show_certificate_details()

    ttk.Button(frame, text="Fetch Well-Known OAuth", command=fetch_well_known_oauth).grid(row=2, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Get Tokens", command=get_oauth_tokens).grid(row=10, column=1, padx=5, pady=5)
    ttk.Button(frame, text="Show Certificate Details", command=show_cert_details).grid(row=0, column=0, padx=5, pady=5, sticky="e")
    ttk.Button(frame, text="Close", command=oauth_window.window.destroy).grid(row=12, column=1, padx=5, pady=5, sticky="e")

def show_certificate_details():
    cert_data = load_certificates()
    cert_window = tk.Toplevel()
    cert_window.title("Certificate Details")
    cert_window.geometry("600x400")

    frame = ttk.Frame(cert_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    text_widget = tk.Text(frame, wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True)

    scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=text_widget.xview)
    text_widget.configure(xscrollcommand=scrollbar_x.set)
    scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

    scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget.insert(tk.END, "Certificate:\n")
    with open(cert_data["certificate"], "r") as cert_file:
        cert_content = cert_file.read()
        text_widget.insert(tk.END, cert_content)
    text_widget.insert(tk.END, "\n\nPublic Key:\n")
    cert = x509.load_pem_x509_certificate(cert_content.encode(), default_backend())
    public_key = cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    text_widget.insert(tk.END, public_key)

    ttk.Button(cert_window, text="Close", command=cert_window.destroy).pack(padx=5, pady=5)

class OIDCDebugger:
    def __init__(self, master, theme):
        self.master = master
        self.theme = theme
        self.window = tk.Toplevel()
        self.window.title("OIDC Debugger")
        self.window.geometry("1400x600")
        self.server_port = 4443
        ssl_context = create_combined_ssl_context(CA_path, cert_path) if cert_path else None
        self.setup_ui()

    def apply_theme(self):
        style = ttk.Style(self.window)
        style.theme_use(self.theme)
        theme_colors = NORD_STYLES.get(self.theme, NORD_STYLES["standard"])
        self.window.configure(background=theme_colors["background"])
    
    def setup_ui(self):
        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

        self.endpoint_label = ttk.Label(self.frame, text="Select or enter well-known endpoint URL:")
        self.endpoint_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.well_known_var = tk.StringVar()
        self.well_known_dropdown = ttk.Combobox(self.frame, textvariable=self.well_known_var)

        self.well_known_dropdown['values'] = [
            'https://sso.cfi.prod.aws.southwest.com/.well-known/openid-configuration'
            'https://sso.fed.dev.aws.swacorp.com/.well-known/openid-configuration',
            'https://sso.fed.dev.aws.swalife.com/.well-known/openid-configuration',
            'https://sso.fed.prod.aws.swacorp.com/.well-known/openid-configuration',
            'https://sso.fed.prod.aws.swalife.com/.well-known/openid-configuration',
            'https://sso.fed.qa.aws.swacorp.com/.well-known/openid-configuration',
            'https://sso.fed.qa.aws.swalife.com/.well-known/openid-configuration'
        ]
        self.well_known_dropdown.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        # Bind the selection event to a function
        self.well_known_dropdown.bind("<<ComboboxSelected>>", self.update_endpoint_entry)

        self.endpoint_entry = ttk.Entry(self.frame, width=50)
        self.endpoint_entry.grid(row=2, column=0, padx=5, pady=5)
        self.endpoint_entry.insert(0, "Enter well-known endpoint URL")

        self.server_name_label = ttk.Label(self.frame, text="Enter server name for redirect URL(optional):")
        self.server_name_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.server_name_entry = ttk.Entry(self.frame, width=50)
        self.server_name_entry.grid(row=4, column=0, padx=5, pady=5)
        self.server_name_entry.insert(0, "localhost")

        self.client_id_entry = ttk.Entry(self.frame, width=50)
        self.client_id_entry.grid(row=5, column=0, padx=5, pady=5)
        self.client_id_entry.insert(0, "Enter Client ID")

        self.client_secret_entry = ttk.Entry(self.frame, width=50, show="*")
        self.client_secret_entry.grid(row=6, column=0, padx=5, pady=5)
        self.client_secret_entry.insert(0, "Enter Client Secret")

        self.scope_entry = ttk.Entry(self.frame, width=50)
        self.scope_entry.grid(row=7, column=0, padx=5, pady=5)
        self.scope_entry.insert(0, "Enter Scopes (e.g., openid profile email)")

        self.use_pkce = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Use PKCE", variable=self.use_pkce).grid(row=8, column=0, padx=5, pady=5)

        self.auth_method = tk.StringVar(value="client_secret_post")
        ttk.Radiobutton(self.frame, text="Client Secret Post", variable=self.auth_method, value="client_secret_post").grid(row=0, column=1, padx=1, pady=1, sticky="w")
        ttk.Radiobutton(self.frame, text="Client Secret Basic", variable=self.auth_method, value="client_secret_basic").grid(row=1, column=1, padx=1, pady=1, sticky="w")

        self.generate_request_btn = ttk.Button(self.frame, text="Generate Auth Request", command=self.generate_auth_request)
        self.generate_request_btn.grid(row=9, column=0, padx=5, pady=5)

        self.auth_url_text = tk.Text(self.frame, height=5, width=80)
        self.auth_url_text.grid(row=10, column=0, padx=5, pady=5, sticky="ew")
        auth_url_scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.auth_url_text.yview)
        self.auth_url_text.configure(yscrollcommand=auth_url_scrollbar.set)
        auth_url_scrollbar.grid(row=10, column=1, sticky="ns")

        self.submit_btn = ttk.Button(self.frame, text="Submit Auth Request", command=self.submit_auth_request)
        self.submit_btn.grid(row=11, column=0, padx=5, pady=5)

        self.clear_text_checkbox = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Clear response text\n before next request", variable=self.clear_text_checkbox).grid(row=12, column=0, padx=5, pady=5, sticky="w")
        self.log_oidc_process = tk.BooleanVar()
        ttk.Checkbutton(self.frame, text="Log OIDC process\n in separate window", variable=self.log_oidc_process).grid(row=12, column=1, padx=5, pady=5, sticky="w")
        
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
        self.response_text.grid(row=13, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        response_text_scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.response_text.yview)
        self.response_text.configure(yscrollcommand=response_text_scrollbar.set)
        response_text_scrollbar.grid(row=13, column=2, sticky="ns")

        self.certificate_btn = ttk.Button(self.frame, text="Show Certificate", command=self.show_certificate)
        self.certificate_btn.grid(row=14, column=0, padx=5, pady=5)

        self.replace_certificate_btn = ttk.Button(self.frame, text="Replace Certificate", command=self.replace_certificate)
        self.replace_certificate_btn.grid(row=15, column=0, padx=5, pady=5)

        self.oidc_log_window = None
        #Draw the screen and start network operations after UI is fully rendered 
        self.window.update_idletasks() 
        #self.window.after(100, self.after_ui_setup)
        
   # def after_ui_setup(self):
        # Start any initial network operations here, like nslookup or HTTP requests
   #     self.generate_self_signed_cert()
   #     self.start_https_server()

    def open_oidc_log_window(self):
        if self.oidc_log_window is None or not self.oidc_log_window.winfo_exists():
            self.oidc_log_window = tk.Toplevel(self.window)
            self.oidc_log_window.title("OIDC Process Log")
            self.oidc_log_window.geometry("600x400")

            # Create a frame to hold the text widget and scrollbars
            frame = ttk.Frame(self.oidc_log_window)
            frame.pack(fill=tk.BOTH, expand=True)

            # Create vertical and horizontal scrollbars
            v_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL)
            h_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)

            # Create the text widget
            self.oidc_log_text = tk.Text(frame, wrap=tk.NONE, yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            self.oidc_log_text.grid(row=0, column=0, sticky="nsew")

            # Configure the scrollbars
            v_scrollbar.config(command=self.oidc_log_text.yview)
            h_scrollbar.config(command=self.oidc_log_text.xview)

            # Pack the scrollbars
            v_scrollbar.grid(row=0, column=1, sticky="ns")
            h_scrollbar.grid(row=1, column=0, sticky="ew")

            # Configure the frame to expand with the window
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)            


    def update_endpoint_entry(self, event):
        selected_value = self.well_known_var.get()
        if selected_value:
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, selected_value)
        else:
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, "Enter well-known endpoint URL")


    def copy_item_to_clipboard(self, event):
        selected_item = self.response_table.selection()
        if selected_item:
            item = selected_item[0]
            column = self.response_table.identify_column(event.x)
            value = self.response_table.item(item, "values")[int(column[1:]) - 1]
            self.window.clipboard_clear()
            self.window.clipboard_append(value)
            self.window.update()  # Keep the clipboard updated
            messagebox.showinfo("Copied", f"Copied to clipboard:\n{value}")

    def generate_auth_request(self):
        if self.log_oidc_process.get():
            self.open_oidc_log_window()

        well_known_url = self.well_known_var.get()
        if not well_known_url:
            well_known_url = self.endpoint_entry.get().strip()

        client_id = self.client_id_entry.get().strip()
        client_secret = self.client_secret_entry.get().strip()
        scopes = self.scope_entry.get().strip()
        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"

        if not well_known_url or not client_id:
            self.response_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Please enter the well-known endpoint and client credentials.\n")
            return

        try:
            try:
                response = requests.get(well_known_url, verify=ssl_context)
            except Exception as ssl_error:
                response = requests.get(well_known_url, verify=False)

            #response = requests.get(well_known_url, verify=False)
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error fetching well-known configuration: {response.status_code}\n")
                log_error("Unable to query Well-known Endpoint",f"{response.status_code}")
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
                log_error("Missing data in OIDC Well-Known Endpoint", "Error in configuration")
                return

            state = self.generate_state()
            nonce = self.generate_nonce()
            params = {
                "client_id": client_id,
                "redirect_uri": f"https://{server_name}:{self.server_port}/callback",
                "response_type": "code",
                "scope": scopes,
                "state": state,
                "nonce": nonce
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
            log_error("Error create OIDC Auth Request",e)

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
        global https_server, https_server_thread

        server_name = self.server_name_entry.get().strip()
        if not server_name:
            server_name = "localhost"
        # Check if the server name resolves
        try:
            socket.gethostbyname(server_name)
        except socket.error:
            self.response_text.insert(tk.END, f"Server name '{server_name}' does not resolve. Using 127.0.0.1 instead.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Server name '{server_name}' does not resolve. Using 127.0.0.1 instead.\n")
            server_name = "localhost"
            
        if https_server is not None: 
            self.response_text.insert(tk.END, "HTTPS server is already running.\n")
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
            self.response_text.insert(tk.END, f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
            self.response_text.insert(tk.END, f"Please confirm {self.client_id} has the redirect uri:  https://{server_name}:{self.server_port}/callback\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
                self.oidc_log_text.insert(tk.END, f"Please confirm {self.client_id} has the redirect uri:  https://{server_name}:{self.server_port}/callback\n")
                self.add_horizontal_rule()

        except Exception as e:
            self.response_text.insert(tk.END, f"HTTPS server https://{server_name}:{self.server_port} Failed.\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"HTTPS server https://{server_name}:{self.server_port} Failed.: {e}\n")
                self.add_horizontal_rule()
            log_error("HTTPS server Failed.", e)
    
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

            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Token Exchange Request Data: {json.dumps(data, indent=4)}\n")
                self.add_horizontal_rule()

            try:
                response = requests.post(self.token_endpoint, data=data, headers=headers, verify=ssl_context)
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

            log_error("Error exchanging code for tokens", e)

    def stop_https_server(self): 
        shutdown_https_server() 
        self.response_text.insert(tk.END, "HTTPS server stopped.\n")

    def display_tokens(self, tokens):
        try:
        # Clear the response text if the checkbox is checked 
            if self.clear_text_checkbox.get(): 
                self.response_text.delete(1.0, tk.END)
            #self.response_text.delete(1.0, tk.END)
            
            self.response_text.insert(tk.END, f"Display Tokens:\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, "Display Tokens:\n")
                self.add_horizontal_rule()

            for key, value in tokens.items():
                self.response_text.insert(tk.END, f"{key}: {value}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"{key}: {value}\n")
                    self.add_horizontal_rule()


            if "id_token" in tokens:
                self.decode_jwt(tokens["id_token"])
            if "access_token" in tokens:
                self.userinfo_query(tokens["access_token"], "access")
            if "access_token" in tokens:
                self.introspect_token(tokens["access_token"], "access")
            if "refresh_token" in tokens:
                self.introspect_token(tokens["refresh_token"], "refresh")
        except Exception as e:
            self.response_text.insert(tk.END, f"Error displaying tokens: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error displaying tokens: {e}\n")
                self.add_horizontal_rule()
            log_error("Error displaying tokens", e)


    def decode_jwt(self, token):
        try:
            header, payload, signature = token.split('.')
            header_decoded = base64.urlsafe_b64decode(header + '==').decode('utf-8')
            payload_decoded = base64.urlsafe_b64decode(payload + '==').decode('utf-8')
            decoded = {
                "header": json.loads(header_decoded),
                "payload": json.loads(payload_decoded),
                "signature": signature
            }
            self.response_text.insert(tk.END, f"Decoded ID Token: {json.dumps(decoded, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Decoded ID Token: {json.dumps(decoded, indent=4)}\n")
                self.add_horizontal_rule()

        except Exception as e:
            self.response_text.insert(tk.END, f"Error decoding JWT: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error decoding JWT: {e}\n")
                self.add_horizontal_rule()


    def userinfo_query(self, token, token_type):
        try:
            headers = {
                'Authorization': f'Bearer {token}'
            }

            try:
                response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=ssl_context)
            except Exception as ssl_error:
                response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=False)
            #response = requests.get(f"{self.userinfo_endpoint}", headers=headers, verify=False)
           
            if response.status_code != 200:
                self.response_text.insert(tk.END, f"Error userinfo {token_type} token: {response.status_code}\n")
                if self.log_oidc_process.get():
                    self.oidc_log_text.insert(tk.END, f"Error userinfo {token_type} token: {response.status_code}\n")
                    self.add_horizontal_rule()

                return

            userinfo = response.json()
            self.response_text.insert(tk.END, f"UserInfo {token_type.capitalize()} Token: {json.dumps(userinfo, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"UserInfo {token_type.capitalize()} Token: {json.dumps(userinfo, indent=4)}\n")
                self.add_horizontal_rule()
        except Exception as e:
            self.response_text.insert(tk.END, f"Error calling UserInfo: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error calling UserInfo: {e}\n")
                self.add_horizontal_rule()


    def introspect_token(self, token, token_type):
        try:
            data = {
                "token": token,
                "token_type_hint": token_type,
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
                response = requests.post(self.introspect_endpoint, data=data, headers=headers, verify=ssl_context)
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
            self.response_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Introspected {token_type.capitalize()} Token: {json.dumps(introspection, indent=4)}\n")
                self.add_horizontal_rule()
        except Exception as e:
            self.response_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")
            if self.log_oidc_process.get():
                self.oidc_log_text.insert(tk.END, f"Error introspecting {token_type} token: {e}\n")
                self.add_horizontal_rule()
            log_error("Error introspecting token", e)

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

    def on_item_double_click(self, event):
        item = event.widget.selection()[0]
        column = event.widget.identify_column(event.x)
        value = event.widget.item(item, "values")[int(column[1:]) - 1]
        self.master.clipboard_clear()
        self.master.clipboard_append(value)
        self.master.update()  # Keep the clipboard updated
        tk.messagebox.showinfo("Copied", f"Copied to clipboard:\n{value}")


class CustomWindow:
    def __init__(self, title, width, height, theme):
        self.window = tk.Toplevel()
        self.window.title(title)
        self.window.geometry(f"{width}x{height}")
        self.theme = theme
        self.apply_theme()

        self.frame = ttk.Frame(self.window, padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True)

#Apply theme
    def apply_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        colors = NORD_STYLES[self.theme]
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

    def add_scrollbar(self, widget):
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=widget.yview)
        widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

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

def show_help():
    help_window = tk.Toplevel()
    help_window.title("Help")
    help_window.geometry("400x300")


    frame = ttk.Frame(help_window, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)

    help_text = (
        "Welcome to the Network Tools Application!\n\n"
        "Features:\n"
        "All details are available on the GitHub page.\n\n"
        "Version: 1.3.1\n"
    )
    link = ttk.Label(frame, text="Cyber Ops Tool Help Page", foreground="blue", cursor="hand2")
    link.pack(padx=5, pady=5)
    link.bind("<Button-1>", lambda e: webbrowser.open_new("https://southwest.atlassian.net/wiki/spaces/CYSEC/pages/446727546/Tools+Info+-+OpsTool+Python+Tool"))

    ttk.Label(frame, text=help_text).pack(padx=5, pady=5)

    # Load and display the image
    image = Image.open("img/EdJeep.png")
    image = image.resize((100, 50), Image.Resampling.LANCZOS)

    photo = ImageTk.PhotoImage(image)
    image_label = ttk.Label(frame, image=photo)
    image_label.image = photo  # Keep a reference to avoid garbage collection
    image_label.pack(padx=5, pady=5)

    # Bind double-click event to play audio
    image_label.bind("<Double-1>", lambda e: play_audio())
    

    ttk.Button(frame, text="Close", command=help_window.destroy).pack(padx=5, pady=5)


def play_audio():
    pygame.mixer.init()
    fun = "aHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL3NvdW5kYm9hcmRzL0NhcnRvb25zL1RIRSBTSU1QU09OUy9NUiBCVVJOUy9NUDMvRVhDRUxMRU5UIC0gQVVESU8gRlJPTSBKQVlVWlVNSS5DT00ubXAz"
    url = base64.b64decode(fun)
    try:
        response = requests.get(url, verify=False)
        audio_data = BytesIO(response.content)
        pygame.mixer.music.load(audio_data)
        pygame.mixer.music.play()
    except Exception as e:
        log_error("Play audio failed",e)

class NSLookup:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.theme = style
        self.is_collapsed = False
        self.setup_ui()
        self.domains = {
            "production": self.load_domains("production_domains.json", "production"),
            "qa": self.load_domains("qa_domains.json", "qa"),
            "development": self.load_domains("development_domains.json", "development")
        }
        self.dns_history = self.load_dns_history()
        self.populate_table_from_history("production")
        self.populate_table_from_history("qa")
        self.populate_table_from_history("development")
        self.update_nslookup_table("production")
        self.update_nslookup_table("qa")
        self.update_nslookup_table("development")

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.grid(row=1, column=0, sticky="nsew")

        self.frames = {}
        for env in ["production", "qa", "development"]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=env.capitalize())
            self.frames[env] = frame

            self.setup_table_ui(frame, env)

        self.master.rowconfigure(1, weight=1)
        self.master.columnconfigure(0, weight=1)

    def setup_table_ui(self, frame, env):
        style = ttk.Style()

        colors = NORD_STYLES[self.theme]
        table_title_frame = ttk.Frame(frame)
        table_title_frame.grid(row=0, column=0, columnspan=5, sticky="ew")
        ttk.Label(table_title_frame, text=f"{env.capitalize()} NSLookup").pack(side=tk.LEFT)

        ttk.Label(table_title_frame, text="Refresh Time (s):").pack(side=tk.RIGHT, padx=5)
        refresh_time_entry = ttk.Entry(table_title_frame, width=10)
        refresh_time_entry.pack(side=tk.RIGHT, padx=5)
        refresh_time_entry.insert(0, "600")  # Default to 10 minutes

        domain_entry = ttk.Entry(frame, width=50)
        domain_entry.grid(row=1, column=0, padx=5, pady=5)

        add_domain_btn = ttk.Button(frame, text="Add Domain", command=lambda: self.add_domain(env, domain_entry))
        add_domain_btn.grid(row=1, column=1, padx=5, pady=5)

        refresh_btn = ttk.Button(frame, text="Refresh", command=lambda: self.update_nslookup_table(env))
        refresh_btn.grid(row=1, column=2, padx=5, pady=5)

        reset_btn = ttk.Button(frame, text="Reset Domains", command=lambda: self.reset_domains(env))
        reset_btn.grid(row=1, column=3, padx=5, pady=5)

        table = ttk.Treeview(frame, columns=("Domain", "Name", "IP Address", "Last IP Change", "Hanger", "Timestamp"), show="headings")
        for col in ("Domain", "Name", "IP Address", "Last IP Change", "Hanger", "Timestamp"):
            table.heading(col, text=col)
            table.column(col, anchor=tk.W, width=150)
        table.grid(row=2, column=0, columnspan=6, padx=5, pady=5, sticky="nsew")

        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=table.yview)
        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=table.xview)
        table.configure(yscroll=scrollbar_y.set, xscroll=scrollbar_x.set)
        scrollbar_y.grid(row=2, column=6, sticky="ns")
        scrollbar_x.grid(row=3, column=0, columnspan=6, sticky="ew")

        table.bind("<Double-1>", lambda event: self.delete_row(event, env))

        frame.rowconfigure(2, weight=1)
        frame.columnconfigure(0, weight=1)

        setattr(self, f"{env}_table", table)
        setattr(self, f"{env}_refresh_time_entry", refresh_time_entry)
        setattr(self, f"{env}_domain_entry", domain_entry)

    def load_domains(self, filename, env):
        if not os.path.exists(filename):
            if env == "production":
                initial_data = ["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com"]
            elif env == "qa":
                initial_data = ["sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com"]
            elif env == "development":
                initial_data = ["sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com"]
            with open(filename, "w") as file:
                json.dump(initial_data, file)
        with open(filename, "r") as file:
            return json.load(file)

    def save_domains(self, env):
        filename = f"{env}_domains.json"
        with open(filename, "w") as file:
            json.dump(self.domains[env], file)

    def add_domain(self, env, domain_entry):
        domain = domain_entry.get().strip()
        if domain:
            self.domains[env].append(domain)
            self.save_domains(env)
            self.update_nslookup_table(env)

    def delete_row(self, event, env):
        selected_item = getattr(self, f"{env}_table").selection()
        if selected_item:
            for item in selected_item:
                values = getattr(self, f"{env}_table").item(item, "values")
                domain = values[0]
                getattr(self, f"{env}_table").delete(item)
                self.delete_domain(env, domain)

    def delete_domain(self, env, domain):
        self.domains[env] = [d for d in self.domains[env] if d != domain]
        self.save_domains(env)

    def reset_domains(self, env):
        if env == "production":
            self.domains[env] = ["sso.fed.prod.aws.swalife.com", "sso.fed.prod.aws.swacorp.com", "sso.cfi.prod.aws.southwest.com"]
        elif env == "qa":
            self.domains[env] = ["sso.fed.qa.aws.swalife.com", "sso.fed.qa.aws.swacorp.com"]
        elif env == "development":
            self.domains[env] = ["sso.fed.dev.aws.swalife.com", "sso.fed.dev.aws.swacorp.com"]
        self.save_domains(env)
        self.update_nslookup_table(env)

    def load_dns_history(self):
        if os.path.exists("dns_history.json"):
            with open("dns_history.json", "r") as file:
                return json.load(file)
        return {}

    def save_dns_history(self, history):
        with open("dns_history.json", "w") as file:
            json.dump(history, file)

    def populate_table_from_history(self, env):
        table = getattr(self, f"{env}_table")
        dns_history = self.dns_history
        for domain in self.domains[env]:
            if domain in dns_history:
                history = dns_history[domain]["history"]
                last_entry = history[-1]
                last_ip_change = dns_history[domain].get("last_ip_change", "N/A")
                table.insert("", "end", values=(domain, last_entry["name"], last_entry["ip_address"], last_ip_change, last_entry["hanger"], last_entry["timestamp"]))

    def resolve_domain(self, domain):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        resolver = aiodns.DNSResolver(timeout=4)
        start_time = datetime.now()
        try:
            answers = loop.run_until_complete(resolver.query(domain, 'A'))
            cname = loop.run_until_complete(resolver.query(domain, 'CNAME'))
            name = cname.cname if cname else "No CNAME"
            ip_address = answers[0].host if answers else "No A record"
            hanger = self.get_hanger(name) 
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            resolve_time = (datetime.now() - start_time).total_seconds()
            return (domain, name, ip_address, hanger, timestamp, resolve_time)
        except (aiodns.error.DNSError, Exception) as e:
            log_error("Async DNS resolution failed", e)
             # Fallback to synchronous nds.resolver
            try:
                answers = dns.resolver.resolve(domain, 'A')
                name = domain
                ip_address = answers[0].to_text() if len(answers) > 0 else "No A record"
                hanger = self.get_hanger(name)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                resolve_time = (datetime.now() - start_time).total_seconds()
                return (domain, name, ip_address, hanger, timestamp, resolve_time)
            except dns.resolver.NXDOMAIN as e:
                resolve_time = (datetime.now() - start_time).total_seconds()
                log_error("Synchronous DNS resolution failed", e)
                return (domain, "DNS Failed", "", "Unknown", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), resolve_time)
            except dns.resolver.LifetimeTimeout as e:
                resolve_time = (datetime.now() - start_time).total_seconds()
                log_error("Synchronous DNS resolution timeout", e)
                return (domain, "DNS TimeOut", "", "Unknown", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), resolve_time)
            except Exception as e:
                resolve_time = (datetime.now() - start_time).total_seconds()
                log_error("Synchronous DNS failed", e)
                return (domain, "DNS Error", "", "Unknown", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), resolve_time)

    def update_nslookup_table(self, env):
        table = getattr(self, f"{env}_table")
        table.delete(*table.get_children())  # Clear the table

        def resolve_domain_thread(domain):
            return self.resolve_domain(domain)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(resolve_domain_thread, domain) for domain in self.domains[env]]
            dns_history = self.load_dns_history()
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                domain, name, ip_address, hanger, timestamp, resolve_time = result
                last_ip_change = dns_history.get(domain, {}).get("last_ip_change", "N/A")
                if domain not in dns_history:
                    dns_history[domain] = {"history": []}
                dns_history[domain]["history"].append({
                    "name": name,
                    "ip_address": ip_address,
                    "resolve_time": resolve_time,
                    "timestamp": timestamp,
                    "hanger": hanger
                })
                if len(dns_history[domain]["history"]) > 2:
                    dns_history[domain]["history"].pop(0)
                if len(dns_history[domain]["history"]) > 1 and dns_history[domain]["history"][-1]["ip_address"] != dns_history[domain]["history"][-2]["ip_address"]:
                    last_ip_change = timestamp
                    dns_history[domain]["last_ip_change"] = last_ip_change
                table.insert("", "end", values=(domain, name, ip_address, last_ip_change, hanger, timestamp))
            self.save_dns_history(dns_history)

        refresh_time = int(getattr(self, f"{env}_refresh_time_entry").get()) * 1000  # Convert seconds to milliseconds
        self.master.after(refresh_time, lambda: self.update_nslookup_table(env))  # Auto-refresh based on user input

    def get_hanger(self, name):
        for key, value in hanger_mappings.items():
            if key in name:
                return value
        return 'Unknown'

class HTTPRequest:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.is_collapsed = False
        self.ignore_ssl_verification = False
        self.production_ignore_ssl = False
        self.qa_ignore_ssl = False
        self.development_ignore_ssl = False
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Geko) Chrome/91.0.4472.124 Safari/537.36'
        }

        self.urls = {
            "production": self.load_urls("production_urls.json", "production"),
            "qa": self.load_urls("qa_urls.json", "qa"),
            "development": self.load_urls("development_urls.json", "development")
        }

        self.history = self.load_history()

        self.setup_ui()
        self.load_history_to_table("production")
        self.load_history_to_table("qa")
        self.load_history_to_table("development")
        self.update_http_table("production")
        self.update_http_table("qa")
        self.update_http_table("development")

    def apply_theme(self, theme, env):
        style = ttk.Style()
        style.theme_use("clam")
        colors = NORD_STYLES[theme]

        background_color = colors["background"]
        style.configure("TFrame", background=background_color)
        style.configure("TLabelFrame", background=background_color, foreground=colors["foreground"])
        style.configure("Treeview", background=background_color, foreground=colors["foreground"], fieldbackground=background_color)
        style.configure("Treeview.Heading", background=colors["header"], foreground=colors["foreground"])
        style.configure("TButton", background=colors["button"], foreground=colors["foreground"])
        style.map("TButton", background=[("active", colors["highlight"])])
        style.configure("TEntry", background=background_color, foreground=colors["foreground"], fieldbackground=background_color)
        style.configure("TText", background=background_color, foreground=colors["foreground"])
        style.configure("Invert.TButton", background=colors["invert_button"], foreground=colors["foreground"])
        style.map("Invert.TButton", background=[("active", colors["highlight"])])
        style.configure("TButton", background=colors["button_background"], foreground=colors["foreground"])
        style.configure("TLabel", background=colors["button_background"], foreground=colors["foreground"])
        style.configure("TEntry", fieldbackground=colors["button_background"], foreground=colors["foreground"])

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.grid(row=2, column=0, sticky="nsew")

        self.frames = {}
        for env in ["production", "qa", "development"]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=env.capitalize())
            self.frames[env] = frame

            self.setup_table_ui(frame, env)
            self.apply_theme(self.style, env)

        self.master.rowconfigure(2, weight=1)
        self.master.columnconfigure(0, weight=1)

    def setup_table_ui(self, frame, env):
        table_title_frame = ttk.Frame(frame)
        table_title_frame.grid(row=0, column=0, columnspan=7, sticky="ew")
        ttk.Label(table_title_frame, text=f"{env.capitalize()} HTTPRequest").pack(side=tk.LEFT)

        ttk.Label(table_title_frame, text="Refresh Time (s):").pack(side=tk.RIGHT, padx=5)
        refresh_time_entry = ttk.Entry(table_title_frame, width=10)
        refresh_time_entry.pack(side=tk.RIGHT, padx=5)
        refresh_time_entry.insert(0, "600")  # Default to 10 minutes

        url_entry = ttk.Entry(frame, width=50)
        url_entry.grid(row=1, column=0, padx=2, pady=2, sticky="ew")
        url_entry.insert(0, "Enter URL")

        regex_entry = ttk.Entry(frame, width=15)
        regex_entry.grid(row=1, column=1, padx=2, pady=2, sticky="ew")
        regex_entry.insert(0, "Enter regex")

        port_entry = ttk.Entry(frame, width=5)
        port_entry.grid(row=1, column=2, padx=2, pady=2, sticky="ew")
        port_entry.insert(0, "443")  # Default to port 443

        ssl_var = tk.BooleanVar(value=True)
        ssl_checkbox = ttk.Checkbutton(frame, text="Use\n SSL", variable=ssl_var)
        ssl_checkbox.grid(row=1, column=3, padx=2, pady=2, sticky="ew")

        add_url_btn = ttk.Button(frame, text="Add\n URL", command=lambda: self.add_url(env, url_entry, regex_entry, port_entry, ssl_var), style="TButton", width=5)
        add_url_btn.grid(row=1, column=4, padx=2, pady=2, sticky="ew")

        refresh_btn = ttk.Button(frame, text="Refresh", command=lambda: self.update_http_table(env), style="TButton", width=8)
        refresh_btn.grid(row=1, column=5, padx=2, pady=2, sticky="ew")

        reset_btn = ttk.Button(frame, text="Reset\n URLs", command=lambda: self.reset_urls(env), style="TButton", width=8)
        reset_btn.grid(row=1, column=6, padx=2, pady=2, sticky="ew")

        ignore_ssl_btn = ttk.Button(frame, text="Ignore\n SSL", command=lambda: self.toggle_ssl_verification(env), style="TButton", width=9)
        ignore_ssl_btn.grid(row=1, column=7, padx=2, pady=2, sticky="ew")

        table = ttk.Treeview(frame, columns=("URL", "Regex Pattern", "Port", "Use SSL", "Status Code", "Status Text", "SSL Match", "Response Time", "Timestamp"), show="headings")
        for col in ("URL", "Regex Pattern", "Port", "Use SSL", "Status Code", "Status Text", "SSL Match", "Response Time", "Timestamp"):
            table.heading(col, text=col)
            table.column(col, anchor=tk.W, width=150)
        table.grid(row=2, column=0, columnspan=8, padx=5, pady=5, sticky="nsew")

        scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=table.yview)
        scrollbar_x = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=table.xview)
        table.configure(yscroll=scrollbar_y.set, xscroll=scrollbar_x.set)
        scrollbar_y.grid(row=2, column=8, sticky="ns")
        scrollbar_x.grid(row=3, column=0, columnspan=8, sticky="ew")

        table.bind("<Double-1>", lambda event: self.delete_row(event, env))

        frame.rowconfigure(2, weight=1)
        frame.columnconfigure(0, weight=1)

        setattr(self, f"{env}_table", table)
        setattr(self, f"{env}_refresh_time_entry", refresh_time_entry)
        setattr(self, f"{env}_url_entry", url_entry)
        setattr(self, f"{env}_regex_entry", regex_entry)
        setattr(self, f"{env}_port_entry", port_entry)
        setattr(self, f"{env}_ssl_var", ssl_var)
        setattr(self, f"{env}_ignore_ssl_btn", ignore_ssl_btn)

    def toggle_ssl_verification(self, env):
        if env == "production":
            self.production_ignore_ssl = not self.production_ignore_ssl
            btn_text = "Verify SSL" if self.production_ignore_ssl else "Ignore SSL"
        elif env == "qa":
            self.qa_ignore_ssl = not self.qa_ignore_ssl
            btn_text = "Verify SSL" if self.qa_ignore_ssl else "Ignore SSL"
        elif env == "development":
            self.development_ignore_ssl = not self.development_ignore_ssl
            btn_text = "Verify SSL" if self.development_ignore_ssl else "Ignore SSL"

        ignore_ssl_btn = getattr(self, f"{env}_ignore_ssl_btn")
        ignore_ssl_btn.config(text=btn_text)

    def load_urls(self, filename, env):
        if not os.path.exists(filename):
            if env == "production":
                initial_data = [
                    {"url": "sso.fed.prod.aws.swalife.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.cfi.prod.aws.southwest.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.fed.prod.aws.swacorp.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True}
                ]
            elif env == "qa":
                initial_data = [
                    {"url": "sso.fed.qa.aws.swalife.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.fed.qa.aws.swacorp.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True}
                ]
            elif env == "development":
                initial_data = [
                    {"url": "sso.fed.dev.aws.swalife.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.fed.dev.aws.swacorp.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True}
                ]
            with open(filename, "w") as file:
                json.dump(initial_data, file)
        with open(filename, "r") as file:
            return json.load(file)

    def save_urls(self, env):
        filename = f"{env}_urls.json"
        with open(filename, "w") as file:
            json.dump(self.urls[env], file)

    def load_history(self):
        if os.path.exists("urls_history.json"):
            with open("urls_history.json", "r") as file:
                return json.load(file)
        return {"production": [], "qa": [], "development": []}

    def save_history(self):
        with open("urls_history.json", "w") as file:
            json.dump(self.history, file)

    def load_history_to_table(self, env):
        table = getattr(self, f"{env}_table")
        for entry in self.history[env]:
            table.insert("", "end", values=entry)

    def add_url(self, env, url_entry, regex_entry, port_entry, ssl_var):
        url = url_entry.get().strip()
        regex = regex_entry.get().strip()
        port = int(port_entry.get().strip())
        use_ssl = ssl_var.get()
        if url:
            if validate_url_and_check_sql_injection(url):
                self.urls[env].append({"url": url, "regex": regex, "port": port, "use_ssl": use_ssl})
                self.save_urls(env)
                self.update_http_table(env)
            else:
                messagebox.showerror("Invalid URL", "The URL is invalid or contains potential SQL injection patterns.")
                url_entry.focus_set()

    def delete_row(self, event, env):
        selected_item = getattr(self, f"{env}_table").selection()
        if selected_item:
            for item in selected_item:
                values = getattr(self, f"{env}_table").item(item, "values")
                url = values[0]
                getattr(self, f"{env}_table").delete(item)
                self.delete_url(env, url)

    def delete_url(self, env, url):
        self.urls[url] = [d for d in self.urls[env] if d != url]
        self.save_urls(env)

    def reset_urls(self, env):
        if env == "production":
            self.urls[env] = [
                    {"url": "sso.fed.prod.aws.swalife.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.cfi.prod.aws.southwest.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.fed.prod.aws.swacorp.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True}
                ]
        elif env == "qa":
            initial_data = [
                    {"url": "sso.fed.qa.aws.swalife.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.fed.qa.aws.swacorp.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True}
                ]
        elif env == "development":
            initial_data = [
                    {"url": "sso.fed.dev.aws.swalife.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True},
                    {"url": "sso.fed.dev.aws.swacorp.com/pf/heartbeat.ping", "regex": "OK", "port": 443, "use_ssl": True}
                ]
        self.save_urls(env)
        self.update_http_table(env)

    async def fetch_url(self, url, regex, port, use_ssl, cert_path, env):
        if SetAsyncDebug:
            enable_aiohttp_debugging()

        start_time = datetime.now()
        cert_path = certifi.where()
        ssl_context = ssl.create_default_context()
        if getattr(self, f"{env}_ignore_ssl"):
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context.load_verify_locations(cert_path)
        timeout = aiohttp.ClientTimeout(total=60)
        connector = aiohttp.TCPConnector(ssl=ssl_context)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Geko) Chrome/91.0.4472.124 Safari/537.36'
        }

        pattern = re.compile(r'^(?:http[s]?://)?([^:/\s]+)(?::(\d+))?')
        match = pattern.match(url)
        if match:
            hostname = match.group(1)
            port = int(match.group(2)) if match.group(2) else port
        else:
            print(f"Invalid URL: {url}")
            return (url, regex, port, use_ssl, "Error", "Invalid URL", "✘", "N/A", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        try:
            if SetAsyncDebug:
                enable_aiohttp_debugging()
            default_ssl_context = ssl.create_default_context()
            default_ssl_context.check_hostname = False
            default_ssl_context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(hostname, port, ssl=default_ssl_context, headers=headers, server_hostname=hostname)
            ssl_object = writer.get_extra_info('ssl_object')
            cert_binary = ssl_object.getpeercert(binary_form=True)
            writer.close()
            await writer.wait_closed()

            x509_cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            for attribute in x509_cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value

            try:
                ext = x509_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                san = []

            def match_hostname(hostname, pattern):
                if pattern.startswith('*.'):
                    return hostname.endswith(pattern[1:])
                return hostname == pattern

            ssl_match = match_hostname(hostname, common_name) or any(match_hostname(hostname, name) for name in san)

        except Exception as e:
           # print(e)
            ssl_match = False

        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as session:
            encoded_url = yarl.URL(url, encoded=True)

            if SetAsyncDebug:
                enable_aiohttp_debugging()
            try:
                #async with session.get(f"{'https' if use_ssl else 'http'}://{hostname}:{port}") as response:
                async with session.get(f"{'https' if use_ssl else 'http'}://{url}") as response:
                    status_code = response.status
                    logging.debug(f"Request url: {url}")
                    logging.debug(f"Headers: {headers}")

                    status_text = await response.text()
                    if regex and not re.search(regex, status_text):
                        status_text = "Pattern Failed"
                    elif regex and re.search(regex, status_text):
                        status_text = "OK"
                    response_time = (datetime.now() - start_time).total_seconds()
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    return (url, regex, port, use_ssl, status_code, status_text, "✔" if ssl_match else "✘", response_time, timestamp)
            except ClientConnectorCertificateError as e:
                response_time = (datetime.now() - start_time).total_seconds()
                return (url, regex, port, use_ssl, "Error", f"SSL Certificate Error: {str(e)}", "✘", response_time, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            except Exception as e:
                response_time = (datetime.now() - start_time).total_seconds()
                return (url, regex, port, use_ssl, "Error", str(e), "✘", response_time, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    async def fetch_url_nossl(self, url, regex, port):
        start_time = datetime.now()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Geko) Chrome/91.0.4472.124 Safari/537.36',
            'Content-Type': 'application/json'
        }
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(f"http://{url}:{port}") as response:
                    status_code = response.status
                    status_text = await response.text()
                    if regex and not re.search(regex, status_text):
                        status_text = "Pattern Failed"
                    elif regex and re.search(regex, status_text):
                        status_text = "OK"
                    response_time = (datetime.now() - start_time).total_seconds()
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    return (url, regex, port, False, status_code, status_text, "✘", response_time, timestamp)
            except Exception as e:
                response_time = (datetime.now() - start_time).total_seconds()
                return (url, regex, port, False, "Error", str(e), "✘", response_time, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    def update_http_table(self, env):
        table = getattr(self, f"{env}_table")
        table.delete(*table.get_children())  # Clear the table

        def fetch_url_thread(url, regex, port, use_ssl, cert_path, env):
            return asyncio.run(self.fetch_url(url, regex, port, use_ssl, cert_path, env))

        def fetch_url_nossl_thread(url, regex, port):
            return asyncio.run(self.fetch_url_nossl(url, regex, port))

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for entry in self.urls[env]:
                if entry["use_ssl"]:
                    futures.append(executor.submit(fetch_url_thread, entry["url"], entry["regex"], entry["port"], entry["use_ssl"], cert_path, env))
                else:
                    futures.append(executor.submit(fetch_url_nossl_thread, entry["url"], entry["regex"], entry["port"]))

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                table.insert("", "end", values=result)
                self.history[env].append(result)

        self.save_history()

        refresh_time = int(getattr(self, f"{env}_refresh_time_entry").get()) * 1000  # Convert seconds to milliseconds
        self.master.after(refresh_time, lambda: self.update_http_table(env))  # Auto-refresh based on user input

class JWKSCheck:
    def __init__(self, master, style):
        self.master = master
        self.style = style
        self.is_collapsed = False
        self.default_url = "https://auth.pingone.com/0a7af83d-4ed9-4510-93cd-506fe835f69a/as/jwks"
        self.url = self.default_url
        ssl_context = create_combined_ssl_context(CA_path, cert_path) if cert_path else None
        self.setup_ui()
        self.update_jwks_table()


    def validate_url(self, event):
        url = self.url_entry.get()
        regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not re.match(regex, url):
            messagebox.showerror("Invalid URL", "Please enter a valid URL starting with http:// or https://")
            self.url_entry.focus_set()

    def setup_ui(self):
    # Apply custom theme if it exists, otherwise apply default theme
        initial_theme = load_custom_theme()
        apply_theme(initial_theme)
        self.frame = ttk.LabelFrame(self.master, padding="10")
        self.frame.grid(row=3, column=0, sticky="nsew")

        self.table_title_frame = ttk.Frame(self.frame)
        self.table_title_frame.grid(row=0, column=0, columnspan=4, sticky="ew")
        ttk.Label(self.table_title_frame, text="JWKSCheck").pack(side=tk.LEFT)

        self.url_entry = ttk.Entry(self.frame, width=50)
        self.url_entry.insert(0, "https://auth.pingone.com/0a7af83d-4ed9-4510-93cd-506fe835f69a/as/jwks")
        self.url_entry.grid(row=1, column=0, padx=5, pady=5)
        self.url_entry.bind("<FocusOut>", self.validate_url)

        self.add_url_btn = ttk.Button(self.frame, text="Set URL", command=self.set_url)
        self.add_url_btn.grid(row=1, column=1, padx=5, pady=5)

        self.refresh_btn = ttk.Button(self.frame, text="Refresh", command=self.update_jwks_table)
        self.refresh_btn.grid(row=1, column=2, padx=5, pady=5)

        self.cert_table = self.setup_table(self.frame, ("Key ID", "Name", "Not Valid Before", "Not Valid After"))
        self.cert_table.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.cert_scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.cert_table.yview)
        self.cert_table.configure(yscroll=self.cert_scrollbar_y.set)
        self.cert_scrollbar_y.grid(row=2, column=4, sticky='ns')

        self.cert_scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.cert_table.xview)
        self.cert_table.configure(xscroll=self.cert_scrollbar_x.set)
        self.cert_scrollbar_x.grid(row=3, column=0, columnspan=4, sticky='ew')

        self.ec_table = self.setup_table(self.frame, ("Key Type", "Key ID", "Use", "X", "Y", "Curve"))
        self.ec_table.grid(row=4, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        self.ec_scrollbar_y = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.ec_table.yview)
        self.ec_table.configure(yscroll=self.ec_scrollbar_y.set)
        self.ec_scrollbar_y.grid(row=4, column=4, sticky='ns')

        self.ec_scrollbar_x = ttk.Scrollbar(self.frame, orient=tk.HORIZONTAL, command=self.ec_table.xview)
        self.ec_table.configure(xscroll=self.ec_scrollbar_x.set)
        self.ec_scrollbar_x.grid(row=5, column=0, columnspan=4, sticky='ew')

        self.frame.rowconfigure(2, weight=1)
        self.frame.rowconfigure(4, weight=1)
        self.frame.columnconfigure(0, weight=1)
        self.cert_table.bind("<Double-1>", self.delete_row)
        self.ec_table.bind("<Double-1>", self.delete_row)

    def delete_row(self, event):
        selected_item = self.table.selection()[0]
        self.table.delete(selected_item)

    def set_url(self):
        self.url = self.url_entry.get().strip()
        if not self.url:
            self.url = self.default_url
        self.update_jwks_table()

    def update_jwks_table(self):
        self.clear_table(self.cert_table)
        self.clear_table(self.ec_table)
        try:
            response = requests.get(self.url, verify=False)
            response.raise_for_status()
            jwks = response.json()
            for key in jwks.get('keys', []):
                if 'x5c' in key:
                    for cert in key['x5c']:
                        cert_bytes = base64.b64decode(cert)
                        x509_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                        key_id = key['kid']
                        name = x509_cert.subject
                        not_valid_before = x509_cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
                        not_valid_after = x509_cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
                        self.cert_table.insert("", "end", values=(key_id, name, not_valid_before, not_valid_after))
                if key['kty'] == 'EC':
                    key_type = key['kty']
                    key_id = key['kid']
                    use = key['use']
                    x = key.get('x', '')
                    y = key.get('y', '')
                    curve = key.get('crv', '')
                    self.ec_table.insert("", "end", values=(key_type, key_id, use, x, y, curve))
        except Exception as e:
            #print(f"Error fetching JWKS: {e}")
            log_error("Error fetching JWKS", e)
        self.master.after(600000, self.update_jwks_table)  # Auto-refresh every 10 minutes

    def setup_table(self, master, columns):
        table = ttk.Treeview(master, columns=columns, show="headings")
        for col in columns:
            table.heading(col, text=col)
            table.column(col, anchor=tk.W, width=150, stretch=True)
        return table

    def clear_table(self, table):
        for item in table.get_children():
            table.delete(item)

def backup_data(NSLookup, HTTPRequest):
    try:
        data = {}
        environments = ["production", "qa", "development"]

        for env in environments:
            # Get Lookup Table
            try:
                with open(f"{env}_domains.json", "r") as file:
                    nslookup_data = json.load(file)
            except FileNotFoundError:
                nslookup_data = ["server1"]

            # Get HTTP Table
            try:
                with open(f"{env}_urls.json", "r") as file:
                    http_data = json.load(file)
            except FileNotFoundError:
                http_data = [{"url": "server1", "regex": "ok"}]

            # Store data for the environment
            data[env] = {
                "nslookup": nslookup_data,
                "httprequest": http_data
            }

        # Add theme information
        if os.path.exists("customtheme.json"):
            with open("customtheme.json", "r") as file:
                custom_theme = json.load(file)
        else:
            custom_theme = False

        data["theme"] = ttk.Style().theme_use()
        if custom_theme: data["custom_theme"] = custom_theme.copy()

        # Create backup file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{timestamp}.json"
        with open(filename, "w") as file:
            json.dump(data, file)

        messagebox.showinfo("Backup Completed", f"The Backup File {filename} was created.")
        print(f"Backup created: {filename}")
    except Exception as e:
        print(f"Error creating backup: {e}")
        log_error("Error creating backup file", e)

def restore_data():
    filename = filedialog.askopenfilename(title="Select Backup File", filetypes=[("JSON files", "*.json")])
    if filename:
        try:
            with open(filename, "r") as file:
                data = json.load(file)

            environments = ["production", "qa", "development"]

            for env in environments:
                with open(f"{env}_domains.json", "w") as ns_file:
                    json.dump(data.get(env, {}).get("nslookup", []), ns_file)
                with open(f"{env}_urls.json", "w") as http_file:
                    json.dump(data.get(env, {}).get("httprequest", []), http_file)

            ttk.Style().theme_use(data.get("theme", "clam"))
            try:
                custom_theme = data.get("custom_theme", {})
                if custom_theme:
                    with open(f"customtheme.json", "w") as customtheme_file:
                        json.dump(custom_theme, customtheme_file)
                    # Apply custom theme if it exists, otherwise apply default theme
                    initial_theme = load_custom_theme()
                    apply_theme(initial_theme)
                   # apply_theme("custom")
                    print(f"Data restored from {filename}")
            except Exception as e:
                #print(f"Error restoring data: {e}")
                log_error("Restore Custom failed", e)
        except Exception as e:
            print(f"Error restoring data: {e}")
            log_error("Restore failed", e)

def main():
    global first_run
    
    root = tk.Tk()
    root.title("Southwest Airlines CyberOps Eng OpsTools")
    root.geometry("1200x800")

    # Apply custom theme if it exists, otherwise apply default theme
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    # Add a menu bar with a Custom Theme option
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    options_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Options", menu=options_menu)
    options_menu.add_command(label="Custom Theme", command=open_custom_theme_window)

    # Add a frame at the top for navigation
    top_frame = ttk.Frame(root, padding="5")
    top_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
    ttk.Button(top_frame, text="Help", command=show_help).pack(side=tk.RIGHT, padx=5, pady=5)
    ttk.Button(top_frame, text="Custom Theme", command=open_custom_theme_window).pack(side=tk.RIGHT, padx=5, pady=5)
    ttk.Button(top_frame, text="Backup Settings", command=lambda: backup_data(NSLookup, HTTPRequest)).pack(side=tk.RIGHT, padx=5, pady=5)
    ttk.Button(top_frame, text="Restore Settings", command=restore_data).pack(side=tk.RIGHT, padx=5, pady=5)


# Add VPN indicator
    def update_vpn_status():
        vpn_connected, vpn_ip, local_ip = is_connected_to_vpn()
        bulb_color = "green" if vpn_connected else "blue"
        bulb_image = Image.open(f"img/{bulb_color}_bulb.png")  # Ensure you have green_bulb.png and blue_bulb.png images
        bulb_image = bulb_image.resize((20, 20), Image.Resampling.LANCZOS)
        bulb_img = ImageTk.PhotoImage(bulb_image)
        bulb_label.config(image=bulb_img)
        bulb_label.image = bulb_img  # Keep a reference to avoid garbage collection
        vpn_label.config(text=f"VPN IP: {vpn_ip}\nLocal IP: {local_ip}")
        root.after(600000, update_vpn_status)  # Schedule to run every 10 minutes recursively
    
    root.after(600000, update_vpn_status)  # Initial call to update_vpn_status

    vpn_connected, vpn_ip, local_ip = is_connected_to_vpn()
    bulb_color = "green" if vpn_connected else "blue"
    bulb_image = Image.open(f"img/{bulb_color}_bulb.png")  # Ensure you have green_bulb.png and blue_bulb.png images
    bulb_image = bulb_image.resize((20, 20), Image.Resampling.LANCZOS)
    bulb_img = ImageTk.PhotoImage(bulb_image)
    bulb_label = ttk.Label(top_frame, image=bulb_img)
    bulb_label.image = bulb_img  # Keep a reference to avoid garbage collection
    bulb_label.pack(side=tk.LEFT, padx=5, pady=5)

    vpn_label = ttk.Label(top_frame, text=f"VPN IP: {vpn_ip}\nLocal IP: {local_ip}")
    vpn_label.pack(side=tk.LEFT, padx=5, pady=5)
    ttk.Button(top_frame, text="Show IP Addresses", command=show_ip_addresses).pack(side=tk.LEFT, padx=5, pady=5)

    main_frame = ttk.Frame(root, padding="5")
    main_frame.grid(row=1, column=0, columnspan=3, sticky="nsew")

    scrollbar = ttk.Scrollbar(main_frame, orient="vertical")
    scrollbar_x = ttk.Scrollbar(main_frame, orient="horizontal")

    scrollable_frame = ttk.Frame(main_frame)
    scrollable_frame.grid(row=0, column=0, sticky="nsew")

    scrollbar.grid(row=0, column=1, sticky="ns")
    scrollbar_x.grid(row=1, column=0, sticky="ew")

    main_frame.grid_rowconfigure(0, weight=1)
    main_frame.grid_columnconfigure(0, weight=1)

    for i in range(3):
        root.rowconfigure(i + 1, weight=1)
    root.columnconfigure(0, weight=1)

    theme_var = tk.StringVar(value=initial_theme)

    sidebar = ttk.Frame(scrollable_frame, padding="5")
    sidebar.grid(row=0, column=1, rowspan=10, sticky="ns")

    logo = Image.open("img/sw.png")
    logo = logo.resize((100, 50), Image.Resampling.LANCZOS)
    logo_img = ImageTk.PhotoImage(logo)
    logo_label = ttk.Label(sidebar, image=logo_img)
    logo_label.image = logo_img
    logo_label.grid(row=0, column=0, padx=5, pady=5)

    ttk.Label(sidebar, text="Choose Theme:").grid(row=1, column=0, padx=5, pady=5)
    ttk.Radiobutton(sidebar, text="Default", variable=theme_var, value="standard", command=lambda: apply_theme(theme_var.get())).grid(row=2, column=0, padx=5, pady=2)
    ttk.Radiobutton(sidebar, text="Frost", variable=theme_var, value="frost", command=lambda: apply_theme(theme_var.get())).grid(row=3, column=0, padx=5, pady=2)
    ttk.Radiobutton(sidebar, text="Aurora", variable=theme_var, value="aurora", command=lambda: apply_theme(theme_var.get())).grid(row=4, column=0, padx=5, pady=2)
    ttk.Label(sidebar, text="Diagnostic Tools:").grid(row=5, column=0, padx=5, pady=5)
    ttk.Button(sidebar, text="TCP Tools", command=lambda: open_tcp_tools_window(theme_var.get()), style="TButton").grid(row=6, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="JWT Decoder", command=lambda: open_jwt_window(theme_var.get())).grid(row=7, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="SAML Decoder", command=lambda: open_saml_window(theme_var.get())).grid(row=8, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="OIDC Debugger", command=lambda: OIDCDebugger(scrollable_frame, theme_var.get())).grid(row=9, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="OAuth Debugger", command=lambda: open_oauth_window(theme_var.get())).grid(row=10, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="SSL Certificate Reader", command=lambda: open_ssl_cert_reader(theme_var.get())).grid(row=11, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="JWKS Check", command=lambda: open_jwks_check_window(theme_var.get())).grid(row=12, column=0, padx=5, pady=2)
    ttk.Button(sidebar, text="PingFederate OAuth Client Tool", command=lambda: open_pingfederate_client_app(theme_var.get())).grid(row=13, column=0, padx=5, pady=2)

   # ttk.Button(sidebar, text="Create Custom Hosts File", command=lambda: open_hosts_file_window(theme_var.get())).grid(row=13, column=0, padx=5, pady=2)

    #ttk.Label(sidebar, text="CA Path:", style="TLabel").grid(row=14, column=0, padx=5, pady=5)
    #ca_path_var = tk.StringVar(value=CA_path)
    #ca_path_entry = ttk.Entry(sidebar, textvariable=ca_path_var, width=30, style="TEntry")
    #ca_path_entry.grid(row=15, column=0, padx=5, pady=5)
    #ttk.Button(sidebar, text="Update CA Path", command=lambda: update_ca_path(ca_path_var.get()), style="TButton").grid(row=16, column=0, padx=5, pady=5)

    for widget in scrollable_frame.winfo_children():
        widget.grid_configure(sticky="nsew")

    scrollable_frame.columnconfigure(0, weight=1)
    scrollable_frame.rowconfigure(1, weight=1)
    scrollable_frame.rowconfigure(2, weight=1)
    scrollable_frame.rowconfigure(3, weight=1)
    scrollable_frame.rowconfigure(4, weight=1)
    scrollable_frame.rowconfigure(5, weight=1)

    apply_theme(theme_var.get())

    def display_message():
        try:
            motd = "4oCcV2UgaGF2ZSBhIHN0cmF0ZWdpYyBwbGFuIOKAlCBpdOKAmXMgY2FsbGVkIGRvaW5nIHRoaW5ncy7igJ0K4oCcWW91ciBwZW9wbGUgY29tZSBmaXJzdCwgYW5kIGlmIHlvdSB0cmVhdCB0aGVtIHJpZ2h0LCB0aGV54oCZbGwgdHJlYXQgdGhlIGN1c3RvbWVycyByaWdodC7igJ0K4oCcVGhlIGVzc2VudGlhbCBkaWZmZXJlbmNlIGluIHNlcnZpY2UgaXMgbm90IG1hY2hpbmVzIG9yIOKAmHRoaW5ncy7igJkgVGhlIGVzc2VudGlhbCBkaWZmZXJlbmNlIGlzIG1pbmRzLCBoZWFydHMsIHNwaXJpdHMsIGFuZCBzb3Vscy7igJ0K4oCcWW91IGhhdmUgdG8gdHJlYXQgeW91ciBlbXBsb3llZXMgbGlrZSBjdXN0b21lcnMu4oCdCuKAnFlvdSBkb27igJl0IGhpcmUgZm9yIHNraWxscywgeW91IGhpcmUgZm9yIGF0dGl0dWRlLiBZb3UgY2FuIGFsd2F5cyB0ZWFjaCBza2lsbHMu4oCdCuKAnEEgY29tcGFueSBpcyBzdHJvbmdlciBpZiBpdCBpcyBib3VuZCBieSBsb3ZlIHJhdGhlciB0aGFuIGJ5IGZlYXIu4oCdCuKAnFRoaW5rIHNtYWxsIGFuZCBhY3Qgc21hbGwsIGFuZCB3ZeKAmWxsIGdldCBiaWdnZXIuIFRoaW5rIGJpZyBhbmQgYWN0IGJpZywgYW5kIHdl4oCZbGwgZ2V0IHNtYWxsZXIu4oCdCuKAnElmIHlvdeKAmXJlIGNyYXp5IGVub3VnaCB0byBkbyB3aGF0IHlvdSBsb3ZlIGZvciBhIGxpdmluZywgdGhlbiB5b3XigJlyZSBib3VuZCB0byBjcmVhdGUgYSBsaWZlIHRoYXQgbWF0dGVycy7igJ0K4oCcSSB0ZWxsIG15IGVtcGxveWVlcyB0aGF0IHdl4oCZcmUgaW4gdGhlIHNlcnZpY2UgYnVzaW5lc3MsIGFuZCBpdOKAmXMgaW5jaWRlbnRhbCB0aGF0IHdlIGZseSBhaXJwbGFuZXMu4oCdCuKAnEp1c3QgYmVjYXVzZSB5b3UgZG9u4oCZdCBhbm5vdW5jZSB5b3VyIHBsYW4gZG9lc27igJl0IG1lYW4geW91IGRvbuKAmXQgaGF2ZSBvbmUu4oCdCuKAnEkgZm9yZ2l2ZSBhbGwgcGVyc29uYWwgd2Vha25lc3NlcyBleGNlcHQgZWdvbWFuaWEgYW5kIHByZXRlbnNpb24u4oCdCuKAnElmIHlvdSBkb27igJl0IHRyZWF0IHlvdXIgb3duIHBlb3BsZSB3ZWxsLCB0aGV5IHdvbuKAmXQgdHJlYXQgb3RoZXIgcGVvcGxlIHdlbGwu4oCdCuKAnFRoZSBidXNpbmVzcyBvZiBidXNpbmVzcyBpcyBwZW9wbGUu4oCdCuKAnElmIHlvdSBjcmVhdGUgYW4gZW52aXJvbm1lbnQgd2hlcmUgdGhlIHBlb3BsZSB0cnVseSBwYXJ0aWNpcGF0ZSwgeW91IGRvbuKAmXQgbmVlZCBjb250cm9sLiBUaGV5IGtub3cgd2hhdCBuZWVkcyB0byBiZSBkb25lIGFuZCB0aGV5IGRvIGl0LuKAnQrigJxMZWFkaW5nIGFuIG9yZ2FuaXphdGlvbiBpcyBhcyBtdWNoIGFib3V0IHNvdWwgYXMgaXQgaXMgYWJvdXQgc3lzdGVtcy4gRWZmZWN0aXZlIGxlYWRlcnNoaXAgZmluZHMgaXRzIHNvdXJjZSBpbiB1bmRlcnN0YW5kaW5nLuKAnQrigJxJIGxlYXJuZWQgaXQgYnkgZG9pbmcgaXQsIGFuZCBJIHdhcyBzY2FyZWQgdG8gZGVhdGgu4oCdCuKAnEkgdGhpbmsgbXkgZ3JlYXRlc3QgbW9tZW50IGluIGJ1c2luZXNzIHdhcyB3aGVuIHRoZSBmaXJzdCBTb3V0aHdlc3QgYWlycGxhbmUgYXJyaXZlZCBhZnRlciBmb3VyIHllYXJzIG9mIGxpdGlnYXRpb24gYW5kIEkgd2Fsa2VkIHVwIHRvIGl0IGFuZCBJIGtpc3NlZCB0aGF0IGJhYnkgb24gdGhlIGxpcHMgYW5kIEkgY3JpZWQu4oCdCiJXaGVuIGl0IGNvbWVzIHRvIGdldHRpbmcgdGhpbmdzIGRvbmUsIHdlIG5lZWQgZmV3ZXIgYXJjaGl0ZWN0cyBhbmQgbW9yZSBicmlja2xheWVycy4iCg=="
            decoded_motd = base64.b64decode(motd).decode('utf-8')
            sayings = decoded_motd.split("\n")
            message = random.choice(sayings).strip()
        except Exception as e:
                message = "Please wait for first update, thanks for your patience."

        # Create a Toplevel window
        message_window = Toplevel(root)
        message_window.title("Message of the Day")
        message_window.geometry("400x200")
        message_window.attributes("-topmost", True)
        Label(message_window, text=message, wraplength=350, padx=10, pady=10).pack(expand=True)
        return message_window

    message_window = display_message()

    def initialize_tools():
        global first_run
        check_version()
        if first_run:
            first_run = False
            nslookup = NSLookup(scrollable_frame, theme_var.get())
            http_request = HTTPRequest(scrollable_frame, theme_var.get())
        else:
            try:
                nslookup = NSLookup(scrollable_frame, theme_var.get())
                http_request = HTTPRequest(scrollable_frame, theme_var.get())
            except Exception as e:
                print(f"Startup failed: {e}")
                log_error("Startup failed", e)
        # Close the message window after initialization is complete
        message_window.after(10000, message_window.destroy)

    root.after(10, initialize_tools)
    root.mainloop()

def update_ca_path(new_path):
    global CA_path
    CA_path = new_path
    print(f"CA Path updated to: {CA_path}")

if __name__ == "__main__":
    if os.name == 'nt':
        Is_Windows = True
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    custom_theme = load_custom_theme()
    main()
