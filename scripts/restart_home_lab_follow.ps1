# Restart Phase 0 home-lab follow on host-win (elevated). Do not peek or curate.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($wid)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Elevate this PowerShell. Unelevated wevtutil degrades Security/Sysmon (access_denied)."
}

python -m corvex stage-b-lab-unlock --reason "resume phase0 home-lab capture window"
python -m corvex sensor-windows --follow --require-live `
    --run-dir runs/home-lab-capture `
    --channels security,sysmon,firewall,powershell `
    --host-id host-win --producer prod-win `
    --host-map fixtures/os_wide/host_map_phase0.json `
    --poll-seconds 30
