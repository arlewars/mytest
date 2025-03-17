import threading
import ssl
import http.server
import tkinter as tk

class MyApp:
    def __init__(self):
        # Initialize your Tkinter app and components here
        pass

    def write_to_response_text(self, output):
        self.response_text.insert(tk.END, f"{output}\n")

    def add_horizontal_rule(self):
        self.write_to_response_text("---------------------------------------------------\n\n")
        if self.log_oidc_process.get():
            self.oidc_log_text.insert(tk.END, "---------------------------------------------------\n\n")

    def start_https_server(self):
        global https_server, https_server_thread

        server_name = self.server_name_entry.get().strip()
        aud = self.aud_entry.get().strip()

        if not self.resolve_server_name(server_name):
            server_name = "localhost"

        if https_server is not None:
            self.write_to_response_text("HTTPS server is already running.\n")
            return

        https_server = http.server.HTTPServer((server_name, self.server_port), self.create_https_handler(aud))
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        https_server.socket = context.wrap_socket(https_server.socket, server_side=True)

        https_server_thread = threading.Thread(target=https_server.serve_forever)
        https_server_thread.daemon = True
        try:
            https_server_thread.start()
            self.schedule_ui_update(f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n")
            self.schedule_ui_update(f"Please confirm {self.client_id} has the redirect uri: https://{server_name}:{self.server_port}/callback\n")
            if self.log_oidc_process.get():
                self.schedule_ui_update(f"HTTPS server started on https://{server_name}:{self.server_port}/callback\n\n", log=True)
                self.schedule_ui_update(f"Please confirm {self.client_id} has the redirect uri: https://{server_name}:{self.server_port}/callback\n", log=True)
                self.add_horizontal_rule()
        except Exception as e:
            self.schedule_ui_update(f"HTTPS server https://{server_name}:{self.server_port} Failed.\n")
            if self.log_oidc_process.get():
                self.schedule_ui_update(f"HTTPS server https://{server_name}:{self.server_port} Failed.: {e}\n", log=True)
                self.add_horizontal_rule()
            self.log_error("HTTPS server Failed.", e)

    def schedule_ui_update(self, message, log=False):
        # Schedule UI updates on the main thread
        self.master.after(0, self.write_to_response_text, message)
        if log:
            self.master.after(0, self.oidc_log_text.insert, tk.END, message)

    def create_https_handler(self, aud):
        parent = self

        class HTTPSHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/callback'):
                    query = self.path.split('?')[-1]
                    params = {k: v for k, v in (item.split('=') for item in query.split('&'))}
                    code = params.get('code')
                    # Safely update UI using schedule_ui_update
                    parent.schedule_ui_update(f"Received code: {code}\n")
                    if parent.log_oidc_process.get():
                        parent.schedule_ui_update(f"Received authorization code: {code}\n", log=True)
                    parent.exchange_code_for_tokens(code, aud)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Authorization code received. You can close this window.")
                else:
                    self.send_error(404, "Not Found")

            def do_POST(self):
                if self.path == '/kill_server':
                    # Shutdown server in a separate thread to avoid blocking the main thread
                    threading.Thread(target=shutdown_https_server).start()
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"Server shutdown initiated.")
                    if parent.log_oidc_process.get():
                        parent.schedule_ui_update("Server shutdown initiated.\n", log=True)

        return HTTPSHandler

def shutdown_https_server():
    global https_server
    https_server.shutdown()

Key Changes:
Thread-Safe UI Updates: schedule_ui_update() is used to ensure all updates to the UI (response_text and oidc_log_text) are done in the main thread. This resolves potential threading issues.
Avoid Direct UI Updates in Background Threads: Updates in HTTPSHandler (such as logging the authorization code) now use parent.schedule_ui_update() to ensure they occur on the main thread.
Shutdown HTTPS Server Properly: The shutdown_https_server() function is called from a separate thread when /kill_server is POSTed to avoid blocking the main thread.