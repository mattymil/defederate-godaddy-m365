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

## Tenant admin: create a Global Administrator for defederation

Before running the script, have the tenant admin create a cloud-only Global Administrator account you can use to authenticate and defederate. Using a cloud-only account on the tenant’s onmicrosoft.com domain avoids sign-in issues while the custom domain is being converted.

1) Sign in to the Azure portal: https://portal.azure.com using a tenant admin account for the GoDaddy Microsoft 365 tenant.
2) Open "Microsoft Entra ID" (formerly Azure Active Directory).
3) Go to Users > New user > Create new user.
4) Create the user:
   - User principal name (UPN): choose the tenant’s onmicrosoft.com domain (e.g., admin-helper@tenant.onmicrosoft.com).
   - Name: something descriptive (e.g., Defederation Admin).
   - Let the portal generate an initial password; copy it for first sign-in.
5) Assign the Global Administrator role:
   - In the user creation flow, expand Roles and click Assign roles (or after creation, open the user > Assigned roles > Add assignments).
   - Search for and assign Global Administrator.
6) Complete user creation.
7) First-time sign-in and password change:
   - Open a private browser window and sign in at https://portal.azure.com with the new account.
   - Change the temporary password when prompted. If Conditional Access/MFA is enforced, complete the setup.
8) Verify access:
   - Ensure the account can open Microsoft Entra ID and manage directory settings.
9) Use this account when prompted by the script to sign in to Microsoft Graph.

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
