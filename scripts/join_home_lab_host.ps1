# Join an extra host to the open home-lab capture window (same run-dir).
# Do not peek or curate events. Do not start a new corpus folder.
param(
    [Parameter(Mandatory = $true)][string]$HostId,
    [Parameter(Mandatory = $true)][string]$Producer,
    [string]$RunDir = "runs/home-lab-capture"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if ($HostId -eq "host-win") {
    throw "host-win is already Phase 0 on cyborg_1. Use host-pc-2 or host-mac."
}

$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
$prin = New-Object Security.Principal.WindowsPrincipal($wid)
if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Elevate this PowerShell."
}

python -m corvex stage-b-lab-unlock --reason "phase1 join extra host to open capture window"
python -m corvex sensor-windows --follow --require-live `
    --run-dir $RunDir `
    --channels security,sysmon,firewall,powershell `
    --host-id $HostId --producer $Producer `
    --host-map fixtures/os_wide/host_map_phase0.json `
    --poll-seconds 30
