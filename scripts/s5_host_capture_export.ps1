#Requires -Version 5.1
param(
  [Parameter(Mandatory = $true)][string]$CorpusName,
  [Parameter(Mandatory = $true)][string]$HostId,
  [string]$OutRoot = "C:\corvex-capture",
  [string]$DestRaw = ""
)

$ErrorActionPreference = "Stop"
$dir = Join-Path $OutRoot $CorpusName
if (-not (Test-Path $dir)) { throw "missing $dir — run s5_host_capture_start.ps1 first" }

$end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$metaPath = Join-Path $dir "capture_meta.json"
$meta = Get-Content $metaPath -Raw | ConvertFrom-Json
$meta | Add-Member -NotePropertyName capture_end_utc -NotePropertyValue $end -Force
($meta | ConvertTo-Json) | Set-Content $metaPath -Encoding UTF8

$channels = @(
  @{ Name = "Security"; File = "security.jsonl" },
  @{ Name = "Microsoft-Windows-Sysmon/Operational"; File = "sysmon.jsonl" },
  @{ Name = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; File = "firewall.jsonl" }
)

foreach ($ch in $channels) {
  $out = Join-Path $dir $ch.File
  try {
    wevtutil qe $ch.Name /f:json /rd:true /c:200000 2>$null | Set-Content -Path $out -Encoding UTF8
  } catch {
    Write-Host "skip $($ch.Name)"
  }
}

if ($DestRaw) {
  $dest = Join-Path $DestRaw $HostId
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item (Join-Path $dir "*") $dest -Force
  Write-Host "Copied exports to $dest"
} else {
  Write-Host "Exports in $dir — copy to fuse host labs/benign/$CorpusName/raw/$HostId/"
}
