import csv
import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from azure.identity import InteractiveBrowserCredential
from azure.keyvault.secrets import SecretClient
import requests
import threading
import logging
import re

class KeyVaultUploader:
    def __init__(self, master):
        self.master = master
        master.title("Azure Key Vault CSV Uploader")
        master.geometry("600x500")
        master.configure(bg='#f3f3f3')

        # Initialize logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        # Load configuration
        self.config = self.load_config()

        # Prompt for Azure login with additional allowed tenants from config
        allowed_tenants = self.config.get('allowed_tenants', ['*'])
        print(f"Using additionally allowed tenants: {allowed_tenants}")
        self.credential = InteractiveBrowserCredential(additionally_allowed_tenants=allowed_tenants)
        self.user_info = self.get_user_info()

        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Segoe UI', 12), padding=10)
        self.style.configure('TLabel', font=('Segoe UI', 12), padding=10, background='#f3f3f3')
        self.style.configure('TEntry', font=('Segoe UI', 12), padding=10)
        self.style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), padding=10, background='#f3f3f3')

        # Frame for title
        self.title_frame = tk.Frame(master, bg='#f3f3f3')
        self.title_frame.pack(pady=20)

        # Title label
        self.title_label = ttk.Label(self.title_frame, text="Azure Key Vault CSV Uploader", style='Header.TLabel')
        self.title_label.pack()

        # User info label
        self.user_label = ttk.Label(self.title_frame, text=f"Logged in as: {self.user_info.get('unique_name', 'Unknown')}", style='TLabel')
        self.user_label.pack(pady=5)

        # Frame for instructions
        self.instruction_frame = tk.Frame(master, bg='#f3f3f3')
        self.instruction_frame.pack(pady=5)

        # Instruction label
        self.label = ttk.Label(self.instruction_frame, text="Select a CSV file to upload secrets to Azure Key Vault:")
        self.label.pack()

        # Frame for file selection
        self.file_frame = tk.Frame(master, bg='#f3f3f3')
        self.file_frame.pack(pady=10, fill=tk.X, padx=20)

        # Browse button to select CSV file
        self.browse_button = ttk.Button(self.file_frame, text="Browse", command=self.browse_file, width=20)
        self.browse_button.pack(pady=5, padx=5, anchor='center')

        # CSV file path display
        self.csv_file_path_var = tk.StringVar()
        self.csv_file_path_label = ttk.Label(self.file_frame, textvariable=self.csv_file_path_var, style='TLabel', width=50, anchor="w")
        self.csv_file_path_label.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Frame for key vault name entry
        self.keyvault_frame = tk.Frame(master, bg='#f3f3f3')
        self.keyvault_frame.pack(pady=5, fill=tk.X, padx=20)

        # Key Vault name label
        self.keyvault_name_label = ttk.Label(self.keyvault_frame, text="Key Vault Name:")
        self.keyvault_name_label.pack(side=tk.LEFT, padx=5)
        
        # Key Vault name entry field
        self.keyvault_name_entry = ttk.Entry(self.keyvault_frame, width=30)
        self.keyvault_name_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Set default Key Vault name from config
        self.keyvault_name_entry.insert(0, self.config.get('keyvault_name', ''))

        # Frame for action buttons
        self.action_frame = tk.Frame(master, bg='#f3f3f3')
        self.action_frame.pack(pady=10)

        # Ping button to check Key Vault connectivity
        self.ping_button = ttk.Button(self.action_frame, text="Ping Key Vault", command=self.ping_keyvault, width=20)
        self.ping_button.pack(side=tk.LEFT, padx=5)

        # Upload button to upload secrets
        self.upload_button = ttk.Button(self.action_frame, text="Upload", command=self.upload_secrets, width=20)
        self.upload_button.pack(side=tk.LEFT, padx=5)

    def get_user_info(self):
        """
        Get the user info from the Azure credential.
        """
        try:
            access_token = self.credential.get_token("https://management.azure.com/.default")
            token_parts = access_token.token.split('.')
            if len(token_parts) < 2:
                return {"unique_name": "Unknown"}
            user_info = json.loads(base64.urlsafe_b64decode(token_parts[1] + "==").decode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to get user info: {e}")
            user_info = {"unique_name": "Unknown"}
        return user_info

    def load_config(self):
        """
        Load configuration from a JSON file.
        """
        config_path = 'config.json'
        if os.path.exists(config_path):
            with open(config_path, 'r') as config_file:
                return json.load(config_file)
        else:
            messagebox.showerror("Error", "Configuration file not found.")
            return {}

    def browse_file(self):
        """
        Open a file dialog to select a CSV file.
        """
        self.csv_file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if self.csv_file_path:
            self.csv_file_path_var.set(self.csv_file_path)
            self.show_message("Info", "CSV file selected successfully.")

    def ping_keyvault(self):
        """
        Ping the Azure Key Vault to check connectivity.
        """
        self.disable_buttons()
        threading.Thread(target=self.ping_keyvault_thread).start()

    def ping_keyvault_thread(self):
        keyvault_name = self.keyvault_name_entry.get()

        if not keyvault_name:
            self.status_message = "Error: Please enter the Key Vault name."
            self.master.after(0, self.show_message, "Error", self.status_message)
            self.master.after(0, self.enable_buttons)
            return

        keyvault_uri = f"https://{keyvault_name}.vault.azure.net"
        try:
            self.response = requests.get(keyvault_uri, timeout=5)
            self.status_message = "Ping Ok"
        except requests.RequestException as e:
            self.status_message = f"An error occurred: {e}"
            logging.error(self.status_message)
        finally:
            self.master.after(0, self.show_message, "Info", self.status_message)
            self.master.after(0, self.enable_buttons)

    def show_message(self, title, message):
        """
        Show a message box with the given title and message.
        """
        messagebox.showinfo(title, message)

    def sanitize_secret_name(self, name):
        """
        Sanitize the secret name to ensure it conforms to Azure Key Vault naming rules.
        """
        sanitized_name = re.sub(r'[^a-zA-Z0-9-]', '-', name)  # Replace invalid characters with dashes
        sanitized_name = re.sub(r'^-+|-+$', '', sanitized_name)  # Trim leading and trailing dashes
        if not sanitized_name:
            raise ValueError("Secret name cannot be empty after sanitization.")
        if not re.match(r'^[a-zA-Z]', sanitized_name):
            sanitized_name = '' + sanitized_name  # Ensure the name starts with a letter
        if len(sanitized_name) > 127:
            sanitized_name = sanitized_name[:127]  # Ensure the name is within the valid length
        return sanitized_name

    def upload_secrets(self):
        """
        Read the CSV file and store each row as a secret in Azure Key Vault.
        """
        self.disable_buttons()
        threading.Thread(target=self.upload_secrets_thread).start()

    def upload_secrets_thread(self):
        keyvault_name = self.keyvault_name_entry.get()
        if not keyvault_name:
            self.status_message = "Error: Please enter the Key Vault name."
            self.master.after(0, self.show_message, "Error", self.status_message)
            self.master.after(0, self.enable_buttons)
            return

        if not self.csv_file_path:
            self.status_message = "Error: Please select a CSV file."
            self.master.after(0, self.show_message, "Error", self.status_message)
            self.master.after(0, self.enable_buttons)
            return

        try:
            # Initialize Key Vault Client
            keyvault_uri = f"https://{keyvault_name}.vault.azure.net"
            secret_client = SecretClient(vault_url=keyvault_uri, credential=self.credential)

            # Read the CSV file and store secrets
            with open(self.csv_file_path, newline='') as csvfile:
                csv_reader = csv.reader(csvfile)
                for row in csv_reader:
                    if len(row) >= 2:  # Ensure there are at least 2 columns
                        secret_name = self.sanitize_secret_name(row[0])
                        secret_value = row[1]
                        secret_client.set_secret(secret_name, secret_value)

            self.status_message = "All secrets stored successfully."
        except Exception as e:
            self.status_message = f"An error occurred: {e}"
            logging.error(self.status_message)
        finally:
            self.master.after(0, self.show_message, "Info", self.status_message)
            self.master.after(0, self.enable_buttons)

    def disable_buttons(self):
        self.browse_button.config(state=tk.DISABLED)
        self.upload_button.config(state=tk.DISABLED)
        self.ping_button.config(state=tk.DISABLED)

    def enable_buttons(self):
        self.browse_button.config(state=tk.NORMAL)
        self.upload_button.config(state=tk.NORMAL)
        self.ping_button.config(state=tk.NORMAL)

def main():
    """
    Main function to run the tkinter GUI application.
    """
    root = tk.Tk()
    app = KeyVaultUploader(root)
    root.mainloop()

if __name__ == "__main__":
    main()
