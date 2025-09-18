#!/usr/bin/env pwsh
<#
.SYNOPSIS
Bulk reset user passwords in Microsoft 365 from a CSV using Microsoft Graph.

.DESCRIPTION
Reads a CSV with columns UserPrincipalName and Password, connects to Microsoft Graph, and sets each
user's password. By default, users must change the password at next sign-in.

.PARAMETER CsvPath
Path to the CSV file with UserPrincipalName,Password columns.

.PARAMETER ForceChangePasswordNextSignIn
If $true (default), require users to change password at next sign-in. Set $false to skip.

.EXAMPLE
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv"

.EXAMPLE
pwsh ./scripts/ps/Reset-User-Passwords.ps1 -CsvPath "./passwords.csv" -ForceChangePasswordNextSignIn:$false

.NOTES
Requires Microsoft.Graph.Users and Microsoft.Graph.Users.Actions modules.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath,

    [Parameter()]
    [bool]$ForceChangePasswordNextSignIn = $true
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" }
function Write-WarnMsg { param([string]$Message) Write-Warning $Message }
function Write-ErrMsg { param([string]$Message) Write-Error $Message }

# Ensure required modules are present
$requiredModules = @('Microsoft.Graph.Users','Microsoft.Graph.Users.Actions')
foreach ($m in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $m | Select-Object -First 1)) {
        Write-Info "Installing module $m for current user..."
        Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module $m -ErrorAction Stop
}

# Connect to Graph - Users.ReadWrite.All is required to reset passwords
$scopes = @('User.ReadWrite.All')
try {
    $context = Get-MgContext -ErrorAction SilentlyContinue
    $needsConnect = $true
    if ($context -and $context.Scopes) {
        $missing = $scopes | Where-Object { $_ -notin $context.Scopes }
        if ($missing.Count -eq 0) { $needsConnect = $false }
    }
    if ($needsConnect) {
        Write-Info "Connecting to Microsoft Graph with scopes: $($scopes -join ', ')"
        Connect-MgGraph -Scopes $scopes
    }
}
catch {
    Write-ErrMsg ("Failed to connect to Microsoft Graph: {0}" -f $_.Exception.Message)
    exit 1
}

# Validate CSV
if (-not (Test-Path -LiteralPath $CsvPath)) {
    Write-ErrMsg "CSV file not found: $CsvPath"
    exit 1
}

try { $rows = Import-Csv -LiteralPath $CsvPath } catch { Write-ErrMsg "Failed to read CSV: $($_.Exception.Message)"; exit 1 }
if (-not $rows -or $rows.Count -eq 0) { Write-ErrMsg "CSV is empty: $CsvPath"; exit 1 }

$requiredHeaders = @('UserPrincipalName','Password')
$headers = $rows[0].PSObject.Properties.Name
foreach ($h in $requiredHeaders) { if ($h -notin $headers) { Write-ErrMsg "CSV missing required column: $h"; exit 1 } }

# Process
$success = 0; $fail = 0
$results = @()
foreach ($row in $rows) {
    $upn = $row.UserPrincipalName
    $pwd = $row.Password
    if ([string]::IsNullOrWhiteSpace($upn) -or [string]::IsNullOrWhiteSpace($pwd)) {
        $results += [pscustomobject]@{ UserPrincipalName=$upn; Status='Skipped'; Message='Missing UPN or Password' }
        $fail++
        continue
    }
    try {
        # Update-MgUserPassword is part of Microsoft.Graph.Users.Actions in earlier examples,
        # currently Set-MgUserPassword or Update-MgUser -PasswordProfile is supported.
        $passwordProfile = @{ forceChangePasswordNextSignIn = $ForceChangePasswordNextSignIn; password = $pwd }
        Update-MgUser -UserId $upn -PasswordProfile $passwordProfile -ErrorAction Stop
        $results += [pscustomobject]@{ UserPrincipalName=$upn; Status='Success'; Message='Password updated' }
        $success++
    }
    catch {
        $results += [pscustomobject]@{ UserPrincipalName=$upn; Status='Failed'; Message=$_.Exception.Message }
        $fail++
    }
}

# Summary
Write-Host "Completed password reset: $success succeeded, $fail failed"
$results | Sort-Object Status, UserPrincipalName | Format-Table -AutoSize
