import tkinter as tk
from tkinter import ttk
import requests

def open_oauth_window(theme):
    oauth_window = CustomWindow("OAuth Debugger", 1200, 600, theme)
    frame = oauth_window.frame
    initial_theme = load_custom_theme()
    apply_theme(initial_theme)

    # SSL Context for Requests
    ssl_context = create_combined_ssl_context(CA_path, cert_path) if cert_path else None

    # Label for Well-Known URL
    endpoint_label = ttk.Label(frame, text="Select or enter well-known endpoint URL:")
    endpoint_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

    well_known_var = tk.StringVar()
    well_known_dropdown = ttk.Combobox(frame, textvariable=well_known_var)
    well_known_values = [
        'https://sso.cfi.prod.aws.southwest.com/.well-known/openid-configuration',
        'https://sso.fed.dev.aws.swacorp.com/.well-known/openid-configuration',
        'https://sso.fed.dev.aws.swalife.com/.well-known/openid-configuration',
        'https://sso.fed.prod.aws.swacorp.com/.well-known/openid-configuration',
        'https://sso.fed.prod.aws.swalife.com/.well-known/openid-configuration',
        'https://sso.fed.qa.aws.swacorp.com/.well-known/openid-configuration',
        'https://sso.fed.qa.aws.swalife.com/.well-known/openid-configuration'
    ]
    well_known_dropdown['values'] = well_known_values
    well_known_dropdown.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

    # Function to update the entry field when a combobox item is selected
    def update_endpoint_entry(event):
        selected_value = well_known_var.get()
        endpoint_entry.delete(0, tk.END)
        endpoint_entry.insert(0, selected_value if selected_value else "Enter well-known endpoint URL")

    well_known_dropdown.bind("<<ComboboxSelected>>", update_endpoint_entry)

    # Entry for the Well-Known URL
    endpoint_entry = ttk.Entry(frame, width=50)
    endpoint_entry.grid(row=2, column=0, padx=5, pady=5)
    endpoint_entry.insert(0, "Enter well-known endpoint URL")

    # Other fields (Token Endpoint, Client ID, Client Secret, Scopes)
    well_known_entry = create_labeled_entry(frame, "OAuth Well-Known Endpoint:", 1, 0)
    well_known_entry.insert(0, "https://sso.fed.dev.aws.swacorp.com/.well-known/openid-configuration")
    
    token_endpoint_entry = create_labeled_entry(frame, "Token Endpoint:", 3, 0)
    client_id_entry = create_labeled_entry(frame, "Client ID:", 5, 0)
    client_secret_entry = create_labeled_entry(frame, "Client Secret:", 7, 0)
    scopes_entry = create_labeled_entry(frame, "Scopes (space-separated):", 9, 0)

    # Scrollable Text Widget for Result
    result_text = create_scrollable_text(frame, 15, 60, theme, 11, 0, 2)

    # Table Frame for Well-Known Data
    well_known_table_frame = ttk.Frame(frame)
    well_known_table_frame.grid(row=0, column=3, rowspan=12, padx=10, pady=10, sticky="nsew")

    # Custom Table for displaying key-value pairs from Well-Known Endpoint
    well_known_table = CustomTable(well_known_table_frame, ("Key", "Value"), 0, 0)
    scrollbar_x = ttk.Scrollbar(well_known_table_frame, orient="horizontal", command=well_known_table.xview)
    well_known_table.configure(xscrollcommand=scrollbar_x.set)
    scrollbar_x.grid(row=1, column=0, sticky="ew")

    scrollbar_y = ttk.Scrollbar(well_known_table_frame, orient="vertical", command=well_known_table.yview)
    well_known_table.configure(yscrollcommand=scrollbar_y.set)
    scrollbar_y.grid(row=0, column=1, sticky="ns")

    # Function to update well-known dropdown values dynamically
    def update_well_known_values(new_values):
        well_known_dropdown['values'] = new_values

    # Example: Update the well-known dropdown list
    new_well_known_values = [
        'https://example.com/.well-known/openid-configuration'
    ]
    update_well_known_values(new_well_known_values)

    # Function to fetch Well-Known OAuth information
    def fetch_well_known_oauth():
        well_known_url = well_known_entry.get().strip()
        
        if not well_known_url:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "Please enter a Well-Known Endpoint URL.\n")
            return

        try:
            # Attempt request with SSL context if provided
            try:
                well_known_response = requests.get(well_known_url, verify=ssl_context)
            except Exception as ssl_error:
                well_known_response = requests.get(well_known_url, verify=False)

            well_known_response.raise_for_status()
            well_known_data = well_known_response.json()

            # Populate Token Endpoint field
            token_endpoint = well_known_data.get("token_endpoint", "")
            token_endpoint_entry.delete(0, tk.END)
            token_endpoint_entry.insert(0, token_endpoint)

            result_text.insert(tk.END, "Well-Known Endpoint fetched successfully.\n")
            
            # Clear previous table data and insert new rows
            well_known_table.clear_table()
            for key, value in well_known_data.items():
                well_known_table.insert_row((key, value))
        except requests.exceptions.RequestException as e:
            result_text.insert(tk.END, f"Error fetching Well-Known Endpoint: {e}\n")
            log_error("Error fetching Well-Known Endpoint in OAuth", e)
        except Exception as e:
            result_text.insert(tk.END, f"Unexpected error: {e}\n")
            log_error("Unexpected error in OAuth fetching", e)
