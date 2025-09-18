#!/usr/bin/env pwsh
<#
.SYNOPSIS
Orchestrate preflight checks, domain defederation, and optional bulk password resets.

.DESCRIPTION
This script:
- Runs the read-only preflight to validate readiness (with optional module install and write-scope checks).
- Defederates the specified domain by converting it to Managed.
- Optionally performs bulk password resets from a CSV and writes a results CSV.
- Writes JSON/CSV artifacts under ./logs by default.

.PARAMETER Domain
The custom domain to defederate (e.g., contoso.com).

.PARAMETER AdminUpn
Optional admin account to validate during preflight.

.PARAMETER CsvPath
Optional CSV for bulk password reset (UserPrincipalName,Password). If omitted, password reset is skipped.

.PARAMETER InstallModules
Attempt to install missing Microsoft Graph modules during preflight (-Scope CurrentUser).

.PARAMETER RequireWriteScopes
Require write scopes to be already granted during preflight; treat as FAIL if missing.

.PARAMETER Force
Skip the interactive confirmation when converting the domain to Managed.

.PARAMETER OutDir
Output directory for logs/artifacts. Default: ./logs

.EXAMPLE
pwsh ./scripts/ps/Run-Defederation.ps1 -Domain "contoso.com" -AdminUpn "admin-helper@tenant.onmicrosoft.com" -CsvPath "./passwords.csv" -InstallModules -Force
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Domain,
  [Parameter()][string]$AdminUpn,
  [Parameter()][string]$CsvPath,
  [Parameter()][switch]$InstallModules,
  [Parameter()][switch]$RequireWriteScopes,
  [Parameter()][switch]$Force,
  [Parameter()][string]$OutDir = './logs'
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" }
function Write-WarnMsg { param([string]$Message) Write-Warning $Message }
function Write-ErrMsg { param([string]$Message) Write-Error $Message }

$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutDir = Resolve-Path -LiteralPath (New-Item -ItemType Directory -Path $OutDir -Force) | Select-Object -ExpandProperty Path

$scriptRoot = $PSScriptRoot
# Fallback if invoked from different working dir
if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

$preflight = Join-Path $scriptRoot 'Preflight-Defederation.ps1'
$defed     = Join-Path $scriptRoot 'Defederate-Domain.ps1'
$reset     = Join-Path $scriptRoot 'Reset-User-Passwords.ps1'

if (-not (Test-Path -LiteralPath $preflight)) { Write-ErrMsg "Preflight script not found: $preflight"; exit 1 }
if (-not (Test-Path -LiteralPath $defed)) { Write-ErrMsg "Defederate script not found: $defed"; exit 1 }
if ($CsvPath -and -not (Test-Path -LiteralPath $reset)) { Write-ErrMsg "Password reset script not found: $reset"; exit 1 }

# 1) Preflight (read-only)
$preflightJson = Join-Path $OutDir ("preflight-$ts.json")
$pfArgs = @('-NoLogo','-NoProfile','-File', $preflight, '-OutJson', $preflightJson)
if ($AdminUpn) { $pfArgs += @('-AdminUpn', $AdminUpn) }
if ($CsvPath) { $pfArgs += @('-CsvPath', (Resolve-Path -LiteralPath $CsvPath).Path) }
if ($InstallModules) { $pfArgs += @('-InstallModules') }
if ($RequireWriteScopes) { $pfArgs += @('-RequireWriteScopes') }

Write-Info "Running preflight checks (artifacts: $preflightJson)"
& pwsh @pfArgs
$pfExit = $LASTEXITCODE
if ($pfExit -ne 0) {
  Write-ErrMsg "Preflight reported FAIL conditions (exit code $pfExit). Aborting. See $preflightJson"
  exit $pfExit
}

# 2) Defederate domain (set to Managed)
Write-Info "Defederating domain '$Domain' (converting to Managed)"
$defArgs = @('-NoLogo','-NoProfile','-File', $defed, '-Domain', $Domain)
if ($Force) { $defArgs += @('-Force') }
& pwsh @defArgs
$defExit = $LASTEXITCODE
if ($defExit -ne 0) {
  Write-ErrMsg "Domain defederation failed (exit code $defExit)."
  exit $defExit
}

# 3) Optional: bulk password reset
if ($CsvPath) {
  $CsvPathResolved = (Resolve-Path -LiteralPath $CsvPath).Path
  $resetCsv = Join-Path $OutDir ("password-reset-$ts.csv")
  Write-Info "Resetting passwords from '$CsvPathResolved' (results: $resetCsv)"
  $rsArgs = @('-NoLogo','-NoProfile','-File', $reset, '-CsvPath', $CsvPathResolved, '-OutCsv', $resetCsv)
  & pwsh @rsArgs
  $rsExit = $LASTEXITCODE
  if ($rsExit -ne 0) {
    Write-WarnMsg "Bulk password reset returned non-zero exit code ($rsExit). See results: $resetCsv"
  }
}

Write-Host "SUCCESS: Workflow complete. Artifacts in: $OutDir"
