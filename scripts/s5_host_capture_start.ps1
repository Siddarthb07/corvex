#Requires -Version 5.1
# Observe-only: start wevtutil / Sysmon export loop for S5. No Atomic/ART.
param(
  [Parameter(Mandatory = $true)][string]$CorpusName,
  [Parameter(Mandatory = $true)][string]$HostId,
  [string]$OutRoot = "C:\corvex-capture"
)

$ErrorActionPreference = "Stop"
$dir = Join-Path $OutRoot $CorpusName
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$meta = @{
  host_id = $HostId
  hostname = $env:COMPUTERNAME
  capture_start_utc = $stamp
  corpus = $CorpusName
  honesty = "pure-benign S5 — no red-team; do not curate mid-window"
}
($meta | ConvertTo-Json) | Set-Content (Join-Path $dir "capture_meta.json") -Encoding UTF8

# Prefer Sysmon Operational if present; always pull Security.
$channels = @(
  @{ Name = "Security"; File = "security.json" },
  @{ Name = "Microsoft-Windows-Sysmon/Operational"; File = "sysmon.json" },
  @{ Name = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; File = "firewall.json" }
)

foreach ($ch in $channels) {
  $out = Join-Path $dir $ch.File
  try {
    wevtutil qe $ch.Name /f:json /rd:true /c:5000 2>$null | Set-Content -Path $out -Encoding UTF8
    Write-Host "snapshot $($ch.Name) -> $out"
  } catch {
    Write-Host "skip $($ch.Name): $_"
  }
}

Write-Host "Started S5 capture for host_id=$HostId at $stamp"
Write-Host "Leave this host routine-only. Export with s5_host_capture_export.ps1 when window closes."
