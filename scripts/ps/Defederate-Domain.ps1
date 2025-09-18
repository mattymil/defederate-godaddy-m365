#!/usr/bin/env pwsh
<#
.SYNOPSIS
Defederate a Microsoft 365 custom domain (e.g., from GoDaddy federation) by converting it to Managed authentication.

.DESCRIPTION
This script:
- Ensures the Microsoft.Graph.Identity.DirectoryManagement module is available (installs for current user if missing).
- Connects to Microsoft Graph with the required scopes.
- Shows the current authenticationType for the specified domain.
- Updates the domain to Managed (defederates) with optional confirmation bypass.
- Verifies the result and reports success/failure.

.PARAMETER Domain
The custom domain to convert (e.g., contoso.com).

.PARAMETER Force
Skip the interactive confirmation prompt.

.PARAMETER SkipModuleInstall
Do not attempt to install missing modules; fail instead if the module is not found.

.EXAMPLE
pwsh ./Defederate-Domain.ps1 -Domain "contoso.com"

.EXAMPLE
pwsh ./Defederate-Domain.ps1 -Domain "contoso.com" -Force

.NOTES
Requires PowerShell 7+ and Microsoft Graph permissions:
Directory.Read.All, Domain.Read.All, Domain.ReadWrite.All, Directory.AccessAsUser.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter()] [switch]$Force,

    [Parameter()] [switch]$SkipModuleInstall
)

$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Warning $Message
}

function Write-ErrMsg {
    param([string]$Message)
    Write-Error $Message
}

# Ensure required module is present
Write-Info "Checking for Microsoft.Graph.Identity.DirectoryManagement module..."
$module = Get-Module -Name Microsoft.Graph.Identity.DirectoryManagement -ListAvailable | Select-Object -First 1
if (-not $module) {
    if ($SkipModuleInstall) {
        Write-ErrMsg "Required module 'Microsoft.Graph.Identity.DirectoryManagement' not found and -SkipModuleInstall specified."
        exit 1
    }
    Write-Info "Module not found. Installing for current user..."
    try {
        Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        Write-ErrMsg ("Failed to install Microsoft.Graph.Identity.DirectoryManagement: {0}" -f $_.Exception.Message)
        exit 1
    }
}

# Import the module explicitly (no-op if already loaded)
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

# Connect to Microsoft Graph with required scopes
$requiredScopes = @(
    'Directory.Read.All',
    'Domain.Read.All',
    'Domain.ReadWrite.All',
    'Directory.AccessAsUser.All'
)

try {
    $context = Get-MgContext -ErrorAction SilentlyContinue
    $hasScopes = $false
    if ($context -and $context.Scopes) {
        $missing = $requiredScopes | Where-Object { $_ -notin $context.Scopes }
        if ($missing.Count -eq 0) { $hasScopes = $true }
    }
    if (-not $context -or -not $hasScopes) {
        Write-Info "Connecting to Microsoft Graph and requesting scopes: $($requiredScopes -join ', ')"
        Connect-MgGraph -Scopes $requiredScopes
    }
}
catch {
    Write-ErrMsg ("Failed to connect to Microsoft Graph: {0}" -f $_.Exception.Message)
    exit 1
}

# Fetch domains and locate target
Write-Info "Retrieving domains..."
$domains = Get-MgDomain
$target = $domains | Where-Object { $_.Id -ieq $Domain -or $_.DomainName -ieq $Domain }

if (-not $target) {
    Write-ErrMsg "Domain '$Domain' not found in tenant."
    exit 1
}

Write-Info ("Current authenticationType for '{0}': {1}" -f $target.Id, $target.AuthenticationType)

if ($target.AuthenticationType -ieq 'Managed') {
    Write-Info "Domain is already Managed. No action required."
    exit 0
}

if ($target.AuthenticationType -and $target.AuthenticationType -ine 'Federated') {
    Write-WarnMsg ("Domain authenticationType is '{0}', not 'Federated'. Proceeding to set to 'Managed'." -f $target.AuthenticationType)
}

if (-not $Force) {
    $answer = Read-Host "Convert '$($target.Id)' from '$($target.AuthenticationType)' to 'Managed'? Type 'yes' to continue"
    if ($answer -ne 'yes') {
        Write-Info "Aborted by user."
        exit 0
    }
}

Write-Info ("Converting '{0}' to Managed..." -f $target.Id)
try {
    # Microsoft Graph PATCH /domains/{id} with authenticationType='Managed'
    Update-MgDomain -DomainId $target.Id -AuthenticationType Managed
}
catch {
    Write-ErrMsg ("Failed to update domain to Managed: {0}" -f $_.Exception.Message)
    exit 1
}

# Verify
Start-Sleep -Seconds 2
$verify = Get-MgDomain -DomainId $target.Id
Write-Info ("Post-update authenticationType: {0}" -f $verify.AuthenticationType)

if ($verify.AuthenticationType -ine 'Managed') {
    Write-ErrMsg "Defederation did not complete as expected. Please verify in the Entra admin portal."
    exit 1
}

Write-Host "SUCCESS: Domain '$($verify.Id)' is now set to 'Managed'."

# Final verification after delay
Start-Sleep -Seconds 10
$final = Get-MgDomain -DomainId $target.Id
if ($final.AuthenticationType -ieq 'Managed') {
    Write-Info ("Final verification after delay: domain '{0}' remains 'Managed'." -f $final.Id)
} else {
    Write-WarnMsg ("Final verification after delay indicates authenticationType is '{0}'. Please manually confirm in the Entra admin portal." -f $final.AuthenticationType)
}
