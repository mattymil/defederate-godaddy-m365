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

## High-level defederation steps (overview)
- Prepare your end users with the planned date/time and password reset expectations.
- Become a tenant admin (create or regain access to a Global Administrator on the tenant’s onmicrosoft.com domain).
- Remove federation with GoDaddy (convert the custom domain(s) to Managed).
- Reset users’ passwords (bulk via CSV supported below), and distribute new credentials.
- Add a CSP provider or move Direct to Microsoft and provision licensing as needed.
- Remove GoDaddy as Delegated Admin.
- Cancel the GoDaddy subscription after access has been removed.

Important: All custom domains in the tenant must be in a Managed state for defederation to fully take effect.

## Prepare end users
- Notify users of the exact window when defederation and password resets will occur (preferably off-hours).
- Share simple re-sign-in steps for Office apps: e.g., Office apps File > Account > Sign out > Sign in; Outlook will prompt for the new password.

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

## Preflight checks (read-only)
Use this checklist to validate your environment and tenant state before defederation and bulk password resets. These steps are read-only and safe to run.

What this validates
- Local environment: PowerShell version available
- Graph connection with read scopes
- Tenant snapshot (name/id)
- All domains are Managed and verified
- Optional: Admin account existence and role
- Optional: CSV user list validity

1) Confirm PowerShell and connect to Graph (read scopes)
```powershell path=null start=null
pwsh --version
# Connect with minimal read scopes for preflight
Connect-MgGraph -Scopes 'Directory.Read.All','Domain.Read.All','User.Read.All'
```

2) Tenant snapshot
```powershell path=null start=null
Get-MgOrganization | Select-Object Id, DisplayName, VerifiedDomains
```

3) Domain state (must be Managed)
```powershell path=null start=null
Get-MgDomain | Select-Object Id, AuthenticationType, IsVerified | Format-Table -AutoSize
# If any AuthenticationType is not 'Managed', address that before proceeding
```

4) Optional: Verify admin account and role
```powershell path=null start=null
$adminUpn = 'admin-helper@tenant.onmicrosoft.com'
$admin    = Get-MgUser -UserId $adminUpn
$gaRole   = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
if ($gaRole) {
  $members = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All
  $isGA    = $members | Where-Object { $_.Id -eq $admin.Id }
  if ($isGA) { Write-Host "[PASS] $adminUpn is Global Administrator" } else { Write-Host "[FAIL] $adminUpn is not Global Administrator" }
} else {
  Write-Host "[WARN] Global Administrator directory role not activated in this tenant"
}
```

5) Optional: Validate your CSV before bulk password reset
```powershell path=null start=null
$csvPath = './passwords.csv'
$rows    = Import-Csv -LiteralPath $csvPath
# Check headers
$required = 'UserPrincipalName','Password'
$missingHeaders = $required | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name }
if ($missingHeaders) { Write-Host "[FAIL] Missing headers: $($missingHeaders -join ', ')" }
# Check each user exists
$notFound = 0
foreach ($r in $rows) {
  if ([string]::IsNullOrWhiteSpace($r.UserPrincipalName) -or [string]::IsNullOrWhiteSpace($r.Password)) { continue }
  try { $null = Get-MgUser -UserId $r.UserPrincipalName } catch { $notFound++ }
}
Write-Host ("Users not found: {0}" -f $notFound)
```

Tip: You can also run the built-in dry-run mode of the bulk reset script to validate users with a summary:
```bash path=null start=null
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv" -DryRun
```

### Automated preflight script
Prefer a one-command, read-only preflight? Use the script below. It reports PASS/WARN/FAIL and exits non-zero on FAIL.

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

## Usage (defederate the domain)
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
