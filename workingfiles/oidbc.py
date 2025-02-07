import tkinter as tk
from tkinter import ttk
import requests
import json
from requests.auth import HTTPBasicAuth
from oauthlib.oauth2 import WebApplicationClient
import os
import base64

# Allow insecure transport for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Function to conduct OIDC auth code flow
def start_oidc_flow():
    issuer = issuer_var.get()
    client_id = client_id_entry.get()
    client_secret = client_secret_entry.get()
    audience = audience_entry.get()
    scope = scopes_entry.get()
    use_pkce = pkce_var.get()

    # Get well-known endpoint
    response = requests.get(f"{issuer}/.well-known/openid-configuration", verify=False)
    config = response.json()
    print("OIDC Configuration:", json.dumps(config, indent=4))
    authorization_endpoint = config["authorization_endpoint"]
    token_endpoint = config["token_endpoint"]
    userinfo_endpoint = config["userinfo_endpoint"]
    introspection_endpoint = config["introspection_endpoint"]
    
    # Initialize OAuth2 client
    client = WebApplicationClient(client_id)

    # Create authorization URL
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri="http://localhost:8080/callback",
        scope=scope.split(),
        state=os.urandom(24).hex()
    )

    print("Open the following URL in your browser and authorize the application:")
    print(request_uri)

    # Handle the authorization response
    auth_code = input("Enter the authorization code:")
    
    # Exchange authorization code for tokens
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=f"http://localhost:8080/callback?code={auth_code}",
        redirect_url="http://localhost:8080/callback",
        code=auth_code,
        client_secret=client_secret
    )

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=HTTPBasicAuth(client_id, client_secret), verify=False
    )
    
    tokens = token_response.json()

    print("Tokens:", json.dumps(tokens, indent=4))

    # Introspect tokens
    introspect_token(token_endpoint, introspection_endpoint, tokens['access_token'], client_id, client_secret)

    # Get user info
    userinfo = requests.get(userinfo_endpoint, headers={'Authorization': f"Bearer {tokens['access_token']}"})
    print("Userinfo:", json.dumps(userinfo.json(), indent=4))

# Function to introspect tokens
def introspect_token(token_endpoint, introspection_endpoint, access_token, client_id, client_secret):
    introspect_response = requests.post(
        introspection_endpoint,
        data={'token': access_token},
        auth=HTTPBasicAuth(client_id, client_secret, verify=False)
    )
    print("Introspected token:", json.dumps(introspect_response.json(), indent=4))

# Tkinter UI
root = tk.Tk()
root.title("OIDC Auth Code Flow")

# Drop-down list for issuer
issuer_label = tk.Label(root, text="Issuer:")
issuer_label.grid(row=0, column=0)
issuer_var = tk.StringVar()
issuer_entry = ttk.Combobox(root, textvariable=issuer_var)
issuer_entry.grid(row=0, column=1)

# Input fields
client_id_label = tk.Label(root, text="Client ID:")
client_id_label.grid(row=1, column=0)
client_id_entry = tk.Entry(root)
client_id_entry.grid(row=1, column=1)

client_secret_label = tk.Label(root, text="Client Secret:")
client_secret_label.grid(row=2, column=0)
client_secret_entry = tk.Entry(root, show='*')
client_secret_entry.grid(row=2, column=1)

audience_label = tk.Label(root, text="Audience:")
audience_label.grid(row=3, column=0)
audience_entry = tk.Entry(root)
audience_entry.grid(row=3, column=1)

scopes_label = tk.Label(root, text="Scopes:")
scopes_label.grid(row=4, column=0)
scopes_entry = tk.Entry(root)
scopes_entry.grid(row=4, column=1)

pkce_var = tk.BooleanVar()
pkce_checkbutton = tk.Checkbutton(root, text="Use PKCE", variable=pkce_var)
pkce_checkbutton.grid(row=5, columnspan=2)

# Start OIDC Flow button
start_button = tk.Button(root, text="Start OIDC Flow", command=start_oidc_flow)
start_button.grid(row=6, columnspan=2)

root.mainloop()
