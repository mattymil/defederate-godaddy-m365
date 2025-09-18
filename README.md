# defederate-godaddy-m365

Defederate a Microsoft 365 custom domain (e.g., one previously federated via GoDaddy) by converting it from Federated to Managed authentication using Microsoft Graph.

## Features
- Checks/installs Microsoft.Graph.Identity.DirectoryManagement (CurrentUser scope) if missing
- Connects to Microsoft Graph with the required scopes
- Shows current domain authenticationType
- Converts domain to Managed (defederates)
- Verifies the result and performs a delayed final verification

## Prerequisites
- PowerShell 7+ (pwsh)
- Permissions to grant Graph scopes: Directory.Read.All, Domain.Read.All, Domain.ReadWrite.All, Directory.AccessAsUser.All
- An admin account (e.g., Global Admin) to sign in during the script run

## Usage
From the project root:

```bash
pwsh ./scripts/ps/Defederate-Domain.ps1 -Domain "contoso.com"
```

Skip confirmation prompt:

```bash
pwsh ./scripts/ps/Defederate-Domain.ps1 -Domain "contoso.com" -Force
```

If you prefer not to auto-install the required module:

```bash
pwsh ./scripts/ps/Defederate-Domain.ps1 -Domain "contoso.com" -SkipModuleInstall
```

## Notes
- The script will prompt you to sign in to Microsoft Graph and request the necessary scopes.
- After the update, the script verifies the authenticationType immediately and again after a short delay.
- If verification fails, manually confirm the status in the Entra admin portal.
