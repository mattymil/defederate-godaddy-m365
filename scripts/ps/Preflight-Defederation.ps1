#!/usr/bin/env pwsh
<#
.SYNOPSIS
Read-only preflight checks for defederating a GoDaddy Microsoft 365 tenant.

.DESCRIPTION
Validates local and tenant readiness before defederation and bulk password resets. Performs only read operations
and reports PASS/WARN/FAIL. Exits non-zero if any FAIL conditions are detected (e.g., domains not Managed).

Checks include:
- Local modules presence (no install unless -InstallModules specified)
- Microsoft Graph connection with read scopes
- Tenant snapshot (name/id)
- Domain state (Managed/Verified)
- Optional: Admin account existence and Global Administrator role
- Optional: CSV validation for bulk password reset
- Optional: Licensing snapshot (best effort)
- Optional: Write-scope readiness (Domain.ReadWrite.All/User.ReadWrite.All)

.PARAMETER AdminUpn
Optional admin UPN to validate and check Global Administrator role membership.

.PARAMETER CsvPath
Optional path to a CSV (UserPrincipalName,Password) to validate before bulk reset.

.PARAMETER OutJson
Optional path to write the preflight results as JSON.

.PARAMETER InstallModules
If specified, attempt to install missing Microsoft Graph modules for the CurrentUser scope.

.PARAMETER RequireWriteScopes
If specified, require write scopes to be present (Domain.ReadWrite.All, User.ReadWrite.All); otherwise only WARN.

.EXAMPLE
pwsh ./scripts/ps/Preflight-Defederation.ps1 -AdminUpn "admin-helper@tenant.onmicrosoft.com"

.EXAMPLE
pwsh ./scripts/ps/Preflight-Defederation.ps1 -CsvPath "./passwords.csv" -OutJson "./preflight.json"
#>

[CmdletBinding()]
param(
    [Parameter()] [string]$AdminUpn,
    [Parameter()] [string]$CsvPath,
    [Parameter()] [string]$OutJson,
    [Parameter()] [switch]$InstallModules,
    [Parameter()] [switch]$RequireWriteScopes
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" }
function Write-WarnMsg { param([string]$Message) Write-Warning $Message }
function Write-ErrMsg { param([string]$Message) Write-Error $Message }

# Report accumulator
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result {
    param([string]$Area,[string]$Item,[string]$Status,[string]$Detail)
    $results.Add([pscustomobject]@{ Area=$Area; Item=$Item; Status=$Status; Detail=$Detail })
}

# 1) Module checks (read-only unless -InstallModules)
$requiredModules = @(
    'Microsoft.Graph.Identity.DirectoryManagement', # domains, org, subscribedSkus
    'Microsoft.Graph.Users'                         # user lookups
)
foreach ($m in $requiredModules) {
    $found = Get-Module -ListAvailable -Name $m | Select-Object -First 1
    if (-not $found) {
        if ($InstallModules) {
            try {
                Write-Info "Installing module $m for CurrentUser..."
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Add-Result 'Module' $m 'PASS' 'Installed for CurrentUser'
            } catch {
                Add-Result 'Module' $m 'FAIL' ("Install failed: {0}" -f $_.Exception.Message)
            }
        } else {
            Add-Result 'Module' $m 'WARN' 'Module missing; run preflight with -InstallModules or install manually'
        }
    } else {
        Add-Result 'Module' $m 'PASS' 'Available'
    }
}

# 2) Connect to Microsoft Graph with read scopes
$readScopes = @('Directory.Read.All','Domain.Read.All','User.Read.All')
$writeScopes = @('Domain.ReadWrite.All','User.ReadWrite.All')
try {
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
    $needsConnect = $true
    if ($ctx -and $ctx.Scopes) {
        $missing = $readScopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($missing.Count -eq 0) { $needsConnect = $false }
    }
    if ($needsConnect) {
        Write-Info "Connecting to Microsoft Graph with read scopes: $($readScopes -join ', ')"
        Connect-MgGraph -Scopes $readScopes
        $ctx = Get-MgContext
    }
    Add-Result 'Graph' 'Read scopes' 'PASS' ("Granted: " + ($ctx.Scopes -join ', '))
} catch {
    Add-Result 'Graph' 'Connect' 'FAIL' ("Failed to connect: {0}" -f $_.Exception.Message)
}

# Check write scopes presence (do not request; just report)
try {
    $ctx = Get-MgContext -ErrorAction Stop
    $missingWrite = $writeScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($missingWrite.Count -gt 0) {
        if ($RequireWriteScopes) {
            Add-Result 'Graph' 'Write scopes' 'FAIL' ("Missing: " + ($missingWrite -join ', '))
        } else {
            Add-Result 'Graph' 'Write scopes' 'WARN' ("Missing: " + ($missingWrite -join ', '))
        }
    } else {
        Add-Result 'Graph' 'Write scopes' 'PASS' 'All present'
    }
} catch {
    Add-Result 'Graph' 'Write scopes' 'WARN' 'Unable to evaluate write scopes'
}

# 3) Tenant snapshot
try {
    $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    if ($org) {
        Add-Result 'Tenant' 'DisplayName' 'INFO' $org.DisplayName
        Add-Result 'Tenant' 'Id' 'INFO' $org.Id
        $onm = ($org.VerifiedDomains | Where-Object { $_.Name -like '*.onmicrosoft.com' } | Select-Object -First 1).Name
        if ($onm) { Add-Result 'Tenant' 'OnMicrosoftDomain' 'INFO' $onm }
    } else {
        Add-Result 'Tenant' 'Organization' 'WARN' 'No organization returned'
    }
} catch {
    Add-Result 'Tenant' 'Organization' 'FAIL' ("Failed to query organization: {0}" -f $_.Exception.Message)
}

# 4) Domains (critical: must be Managed)
try {
    $domains = Get-MgDomain -ErrorAction Stop
    if (-not $domains) { Add-Result 'Domain' 'List' 'WARN' 'No domains returned' }
    $nonManaged = @()
    foreach ($d in $domains) {
        $status = if ($d.AuthenticationType -eq 'Managed') { 'PASS' } else { 'FAIL' }
        Add-Result 'Domain' $d.Id $status ("AuthType=$($d.AuthenticationType); Verified=$($d.IsVerified)")
        if ($d.AuthenticationType -ne 'Managed') { $nonManaged += $d }
        if (-not $d.IsVerified) { Add-Result 'Domain' ("Verify:" + $d.Id) 'WARN' 'Domain is not verified' }
    }
    if ($nonManaged.Count -gt 0) {
        Add-Result 'Domain' 'Overall' 'FAIL' ("Non-managed domains: " + (($nonManaged | Select-Object -ExpandProperty Id) -join ', '))
    }
} catch {
    Add-Result 'Domain' 'List' 'FAIL' ("Failed to query domains: {0}" -f $_.Exception.Message)
}

# 5) Admin role check (optional)
if ($AdminUpn) {
    try {
        $admin = Get-MgUser -UserId $AdminUpn -ErrorAction Stop
        Add-Result 'Admin' 'Exists' 'PASS' $AdminUpn
        try {
            $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" -ErrorAction Stop | Select-Object -First 1
            if ($gaRole) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop
                $isGA = $false
                foreach ($m in $members) { if ($m.Id -eq $admin.Id) { $isGA = $true; break } }
                if ($isGA) { Add-Result 'Admin' 'Global Administrator' 'PASS' 'User is in Global Administrator role' }
                else { Add-Result 'Admin' 'Global Administrator' 'FAIL' 'User is not in Global Administrator role' }
            } else {
                Add-Result 'Admin' 'Global Administrator' 'WARN' 'Directory role not activated in this tenant'
            }
        } catch {
            Add-Result 'Admin' 'Global Administrator' 'WARN' 'Unable to evaluate role membership'
        }
    } catch {
        Add-Result 'Admin' 'Exists' 'FAIL' ("User not found: {0}" -f $AdminUpn)
    }
}

# 6) CSV validation (optional)
if ($CsvPath) {
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        Add-Result 'CSV' 'Path' 'FAIL' ("Not found: {0}" -f $CsvPath)
    } else {
        try { $rows = Import-Csv -LiteralPath $CsvPath -ErrorAction Stop } catch { $rows = $null; Add-Result 'CSV' 'Read' 'FAIL' ("Failed to load: {0}" -f $_.Exception.Message) }
        if ($rows) {
            $required = @('UserPrincipalName','Password')
            $headers = $rows[0].PSObject.Properties.Name
            $missingHeaders = $required | Where-Object { $_ -notin $headers }
            if ($missingHeaders.Count -gt 0) { Add-Result 'CSV' 'Headers' 'FAIL' ("Missing: " + ($missingHeaders -join ', ')) } else { Add-Result 'CSV' 'Headers' 'PASS' 'Present' }
            $missing = 0; $notFound = 0
            foreach ($r in $rows) {
                if ([string]::IsNullOrWhiteSpace($r.UserPrincipalName) -or [string]::IsNullOrWhiteSpace($r.Password)) { $missing++; continue }
                try { $null = Get-MgUser -UserId $r.UserPrincipalName -ErrorAction Stop } catch { $notFound++ }
            }
            Add-Result 'CSV' 'Row completeness' ($(if ($missing -eq 0){'PASS'}else{'WARN'})) ("Rows missing data: $missing")
            Add-Result 'CSV' 'Users exist' ($(if ($notFound -eq 0){'PASS'}else{'WARN'})) ("Users not found: $notFound")
        }
    }
}

# 7) Licensing snapshot (best effort)
try {
    $skus = Get-MgSubscribedSku -ErrorAction Stop
    if ($skus) {
        $summary = ($skus | ForEach-Object { "{0} ({1}/{2})" -f $_.SkuPartNumber, $_.ConsumedUnits, ($_.PrepaidUnits.Enabled) } ) -join '; '
        Add-Result 'Licensing' 'SubscribedSkus' 'INFO' $summary
    } else {
        Add-Result 'Licensing' 'SubscribedSkus' 'WARN' 'No subscribed SKUs returned'
    }
} catch {
    Add-Result 'Licensing' 'SubscribedSkus' 'WARN' 'Unable to query subscribed SKUs (insufficient scope or permission)'
}

# 8) Summarize and exit
$fail = $results | Where-Object { $_.Status -eq 'FAIL' }
$warn = $results | Where-Object { $_.Status -eq 'WARN' }

$results | Sort-Object Area, Item | Format-Table -AutoSize
if ($OutJson) {
    try { $results | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path $OutJson } catch { Write-Warning "Failed to write JSON output: $($_.Exception.Message)" }
}

if ($fail.Count -gt 0) { exit 1 } else { exit 0 }
