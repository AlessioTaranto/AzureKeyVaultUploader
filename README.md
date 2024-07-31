# Azure Key Vault CSV Uploader

Azure Key Vault CSV Uploader is a GUI application that allows users to upload secrets from a CSV file to an Azure Key Vault. This application leverages the Azure SDK for Python and the `InteractiveBrowserCredential` for user authentication.

## Features

- **User Authentication**: Utilizes Azure's `InteractiveBrowserCredential` for secure user login.
- **CSV File Upload**: Easily select and upload secrets from a CSV file.
- **Key Vault Connectivity**: Check connectivity to your Azure Key Vault.
- **Firewall Handling**: Provides guidance on managing Azure Key Vault firewall settings.

## Requirements

- Python 3.6 or higher
- Azure account with access to Azure Key Vault
- The following Python packages:
  - `azure-identity`
  - `azure-keyvault-secrets`
  - `requests` (usually included with Python)
  - `tkinter` (usually included with Python)
  - `logging` (usually included with Python)
  - `json` (usually included with Python)
  - `base64` (usually included with Python)
  - `re` (usually included with Python)
  - `threading` (usually included with Python)

## Installation

1. **Install required packages**:

   ```sh
   pip install azure-identity azure-keyvault-secrets
   ```

2. **Prepare `config.json` file**:
   Create a `config.json` file in the project root directory with the following content:
   ```json
   {
     "keyvault_name": "your-keyvault-name",
     "allowed_tenants": ["*"] // or specify your allowed tenants
   }
   ```

## Usage

1. **Run the application**:

   ```sh
   python keyvault_uploader.py
   ```

2. **Log in to your Azure account**:

   - The application will open a browser window for Azure authentication.

3. **Upload Secrets**:

   - Select a CSV file containing your secrets.
   - Ensure your CSV file follows this format:
     ```csv
     secret_name_1,secret_value_1
     secret_name_2,secret_value_2
     ```

4. **Ping Key Vault**:

   - Enter the name of your Key Vault.
   - Click "Ping Key Vault" to check connectivity.

5. **Upload Secrets**:
   - After selecting the CSV file and entering the Key Vault name, click "Upload" to upload the secrets to Azure Key Vault.

## Troubleshooting

### Common Issues

- **403 Forbidden Error**:

  - Ensure your client IP address is allowed in the Key Vault firewall settings.
  - Enable "Allow trusted Microsoft services to bypass this firewall" in the Azure portal under your Key Vault's networking settings.

- **Invalid Secret Names**:
  - Secret names must conform to Azure Key Vault naming rules (alphanumeric characters and dashes only, starting with a letter, etc.). The application sanitizes secret names to comply with these rules.

### Logging

- The application logs errors and important events. Check the logs if you encounter any issues.

## Detailed Explanation of Code

### Configuration

The application loads its configuration from a `config.json` file. This file should contain the default Key Vault name and optionally a list of allowed tenants.

```json
{
  "keyvault_name": "your-keyvault-name",
  "allowed_tenants": ["*"]
}
```

### Secret Name Sanitization

Secret names are sanitized to ensure they comply with Azure Key Vault naming rules:

- Only alphanumeric characters and dashes are allowed.
- Names must start with a letter.
- Names cannot exceed 127 characters.

The `sanitize_secret_name` function handles this by replacing invalid characters with dashes and trimming any leading or trailing dashes.

```py
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
```

### CSV File Format

The CSV file should contain two columns: the secret name and the secret value. Each row represents a secret to be stored in the Azure Key Vault.

Example:

```csv
secret_name_1,secret_value_1
secret_name_2,secret_value_2
```

### Application Workflow

1. **Initialization**: The application initializes the GUI and loads the configuration.
2. **Azure Authentication**: The user logs in via Azure's `InteractiveBrowserCredential`.
3. **File Selection**: The user selects a CSV file containing the secrets.
4. **Key Vault Connectivity**: The user can check connectivity to their Azure Key Vault by clicking "Ping Key Vault".
5. **Upload Secrets**: The user uploads the secrets to the Azure Key Vault by clicking "Upload".

### GUI Components

The application uses `tkinter` for its GUI. Key components include:

- **Title and User Info**: Displays the application title and the logged-in user's information.
- **File Selection**: Allows the user to browse and select a CSV file.
- **Key Vault Name**: Input field for the user to enter the Key Vault name.
- **Ping and Upload Buttons**: Buttons to check Key Vault connectivity and upload secrets, respectively.

### Error Handling

The application includes error handling for common issues such as missing configuration files, invalid secret names, and connectivity problems. Errors are logged, and relevant messages are displayed to the user.

## Conclusion

The Azure Key Vault CSV Uploader simplifies the process of uploading secrets to Azure Key Vault from a CSV file. By following the instructions in this README, users can easily configure and use the application to manage their secrets securely.
