# Defederate M365 From GoDaddy

Defederate a Microsoft 365 tenant (e.g., one previously federated via GoDaddy) by converting federated domains to Managed authentication using Microsoft Graph.

## Features
- Checks/installs Microsoft.Graph.Identity.DirectoryManagement (CurrentUser scope) if missing
- Connects to Microsoft Graph with the required scopes
- Shows current domain authenticationType
- Converts a specified domain to Managed (as part of tenant defederation)
- Verifies the result and performs a delayed final verification

## Prerequisites
- PowerShell 7+ (pwsh)
- Permissions to grant Graph scopes: Directory.Read.All, Domain.Read.All, Domain.ReadWrite.All, Directory.AccessAsUser.All
- An admin account (e.g., Global Admin) to sign in during the script run

## High-level defederation steps (overview)
- Prepare your end users with the planned date/time and password reset expectations.
- Become a tenant admin (create or regain access to a Global Administrator on the tenant’s onmicrosoft.com domain).
- Defederate the tenant by converting all federated custom domains to Managed.
- Reset users’ passwords (bulk via CSV supported below), and distribute new credentials.
- Add a CSP provider or move Direct to Microsoft and provision licensing as needed.
- Remove GoDaddy as Delegated Admin.
- Cancel the GoDaddy subscription after access has been removed.

Important: All custom domains in the tenant must be in a Managed state for defederation to fully take effect.

## Prepare end users
- Notify users of the exact window when defederation and password resets will occur (preferably off-hours).
- Share simple re-sign-in steps for Office apps: e.g., Office apps File > Account > Sign out > Sign in; Outlook will prompt for the new password.

## Tenant admin: create a Global Administrator for defederation

Before running the script, have the tenant admin create a cloud-only Global Administrator account you can use to authenticate and defederate. Using a cloud-only account on the tenant’s onmicrosoft.com domain avoids sign-in issues while the tenant is being defederated.

1) Sign in to the Azure portal: https://portal.azure.com using a tenant admin account for the GoDaddy Microsoft 365 tenant. This is normally the GoDaddy user that owns the GoDaddy account but you can use any global admin account.
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

## Orchestrated run (one command)
Use the orchestrator to run preflight (read-only), defederate the tenant (by converting the specified federated domain to Managed; repeat for additional domains if present), and optionally bulk reset passwords. Artifacts are saved under ./logs.

Examples:
- Full run with preflight, install missing modules, defederate, and reset passwords:
```bash
pwsh ./scripts/ps/Run-Defederation.ps1 -Domain "contoso.com" -AdminUpn "admin-helper@tenant.onmicrosoft.com" -CsvPath "./passwords.csv" -InstallModules -Force
```
- Run preflight + defederate only (no password reset):
```bash
pwsh ./scripts/ps/Run-Defederation.ps1 -Domain "contoso.com" -AdminUpn "admin-helper@tenant.onmicrosoft.com" -InstallModules -Force
```

## Preflight checks (read-only)
Use the automated preflight script to validate readiness. It performs only read operations and reports PASS/WARN/FAIL, exiting non-zero on FAIL. You’ll get a concise table in the terminal and can optionally export JSON for auditing.

What it validates
- Modules availability (no changes unless -InstallModules)
- Graph read scopes
- Tenant snapshot (name/id and onmicrosoft.com domain)
- All domains are Managed; verified status
- Optional: Admin account exists and is Global Administrator
- Optional: CSV user list validity
- Optional: Licensing snapshot
- Optional: Write-scope readiness (fail with -RequireWriteScopes)

Basic run:
```bash
pwsh ./scripts/ps/Preflight-Defederation.ps1
```
With admin and CSV checks, plus JSON export:
```bash
pwsh ./scripts/ps/Preflight-Defederation.ps1 -AdminUpn "admin-helper@tenant.onmicrosoft.com" -CsvPath "./passwords.csv" -OutJson "./preflight.json"
```
Attempt to install missing modules for CurrentUser:
```bash
pwsh ./scripts/ps/Preflight-Defederation.ps1 -InstallModules
```
Require write scopes to already be granted (otherwise FAIL):
```bash
pwsh ./scripts/ps/Preflight-Defederation.ps1 -RequireWriteScopes
```

## Defederate the Tenant
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

## Bulk reset user passwords (CSV)
After defederation, reset passwords in bulk and distribute credentials.

1) Prepare a CSV file with the columns UserPrincipalName and Password. Example:

```csv
UserPrincipalName,Password
user1@contoso.com,TempP@ssw0rd!
user2@contoso.com,AnotherP@ss1!
```

2) Run the bulk reset script:

```bash
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv"
```

- Dry run (validate CSV and user existence, no changes):

```bash
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv" -DryRun
```

- By default, users will be required to change the password at next sign-in. To disable that behavior:

```bash
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv" -ForceChangePasswordNextSignIn:$false
```

- Export results to CSV:

```bash
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv" -OutCsv "./reset-results.csv"
```

Notes:
- The script checks that all tenant domains are Managed before proceeding.
- Ensure your password values meet the tenant’s password policy.
- If Conditional Access or MFA is enforced, first sign-in may require additional steps.

## CSP vs. Direct licensing (post-defederation)
- CSP: Accept the partner relationship, provision the required licenses, and (if changing SKUs) bulk-assign the new licenses and remove old ones.
- Direct to Microsoft: Purchase licenses in the Microsoft 365 admin center and assign as needed.

## Remove GoDaddy delegated admin and cancel subscription (warning)
- Remove GoDaddy as a delegated admin before canceling their subscription to avoid unintended automated actions (like user deletions or domain removal).
- After removing access, cancel the GoDaddy subscription from their portal.

## Optional: SharePoint URL rename
- You can update SharePoint site addresses post-defederation to reflect the tenant domain (see Microsoft docs for changing site addresses).

## Notes
- The script will prompt you to sign in to Microsoft Graph and request the necessary scopes.
- After the update, the script verifies the authenticationType immediately and again after a short delay.
- If verification fails, manually confirm the status in the Entra admin portal.
