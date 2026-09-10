# S2: live wevtutil on a second physical Windows host.
# Run elevated. Refuses host-1 (cyborg_1). Does not invent live_second_host.json.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$ident = [System.Net.Dns]::GetHostName()
$blocked = @("cyborg_1", "CYBORG_1", "cyborg-1")
if ($blocked -contains $ident) {
    throw "Refusing S2 on hostname $ident - this is Phase 0 host-1. Run this script on the second physical Windows PC."
}

$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($wid)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Elevate this PowerShell (Run as administrator). wevtutil Security needs elevation."
}

python -m corvex stage-b-lab-unlock --reason "s2 second physical Windows host live wevtutil"
if ($LASTEXITCODE -ne 0) { throw "stage-b-lab-unlock failed" }

$run = Join-Path $Root "runs\live-host-2"
New-Item -ItemType Directory -Force -Path $run | Out-Null

python -m corvex sensor-windows --require-live --once `
    --run-dir $run `
    --channels security,sysmon,firewall,powershell `
    --host-id host-pc-2 --producer prod-pc-2
if ($LASTEXITCODE -ne 0) { throw "sensor-windows --require-live --once failed" }

python scripts/record_live_host_evidence.py --run-dir $run --host-id host-pc-2
if ($LASTEXITCODE -ne 0) { throw "record_live_host_evidence failed - need source=wevtutil and events>0" }

Write-Host "Wrote reports/live_second_host.json. Copy it to the author checkout if this is a separate clone, then: python -m corvex claim-gates"
