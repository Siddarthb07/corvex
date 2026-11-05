# Bootstrap S2 on PC-2 over Win OpenSSH (elevated session).
# Usage (from author machine):
#   ssh -t USER@PC2 "powershell -ExecutionPolicy Bypass -File C:\path\to\corvex\scripts\bootstrap_s2_remote.ps1"
# Or clone fresh on PC-2 then run this script elevated.
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
    $prin = New-Object Security.Principal.WindowsPrincipal($wid)
    if (-not $prin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Need elevated PowerShell (Administrator) for wevtutil Security."
    }
}

Assert-Admin

$Repo = if ($env:CORVEX_ROOT) { $env:CORVEX_ROOT } else {
    # Prefer existing clone next to this script; else clone to %USERPROFILE%\corvex
    $here = Split-Path -Parent $PSScriptRoot
    if (Test-Path (Join-Path $here "pyproject.toml")) { $here } else { Join-Path $env:USERPROFILE "corvex" }
}

if (-not (Test-Path (Join-Path $Repo "pyproject.toml"))) {
    Write-Host "Cloning Siddarthb07/corvex into $Repo"
    git clone https://github.com/Siddarthb07/corvex.git $Repo
}

Set-Location $Repo
$ident = [System.Net.Dns]::GetHostName()
Write-Host "hostname=$ident"
if (@("cyborg_1", "CYBORG_1", "cyborg-1") -contains $ident) {
    throw "This is host-1 ($ident). S2 must run on a different physical Windows PC."
}

python -m pip install -e ".[dev]"
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

powershell -ExecutionPolicy Bypass -File (Join-Path $Repo "scripts\run_s2_second_host.ps1")
if ($LASTEXITCODE -ne 0) { throw "run_s2_second_host.ps1 failed" }

$out = Join-Path $Repo "reports\live_second_host.json"
Write-Host "S2 artifact: $out"
Get-Content $out
Write-Host "Copy this JSON to the author checkout reports\live_second_host.json then: python -m corvex claim-gates"
