#Requires -Version 5.1
<#
.SYNOPSIS
  Lab helper: sensor-windows --follow around corvex atomic-run for one host role.

.DESCRIPTION
  Requires CORVEX_ATOMIC=1 and Stage B lab unlock. Does not flip claim_allowed.
  Does not vendor Atomic scripts — Invoke-AtomicRedTeam must already be installed.

.PARAMETER Playbook
  Path to *.atomic.json playbook.

.PARAMETER Role
  Host role to execute (e.g. host-a).

.PARAMETER RunDir
  Output run directory.

.PARAMETER DryRun
  Pass --dry-run to atomic-run (no Invoke-AtomicTest).
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Playbook,

    [Parameter(Mandatory = $true)]
    [string]$Role,

    [string]$RunDir = "runs/atomic/lab",

    [string]$HostMap = "fixtures/windows_host_map.json",

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if ($env:CORVEX_ATOMIC -ne "1") {
    Write-Error "Set CORVEX_ATOMIC=1 before running this script (lab purple-team only)."
}

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$sensorArgs = @(
    "sensor-windows",
    "--run-dir", $RunDir,
    "--follow",
    "--host-map", $HostMap
)

Write-Host "Starting sensor-windows --follow in background → $RunDir"
$sensor = Start-Process -FilePath "corvex" -ArgumentList $sensorArgs `
    -PassThru -NoNewWindow -RedirectStandardOutput "$RunDir/sensor_stdout.log" `
    -RedirectStandardError "$RunDir/sensor_stderr.log"

Start-Sleep -Seconds 3

try {
    $runArgs = @(
        "atomic-run",
        $Playbook,
        "--role", $Role,
        "--run-dir", $RunDir,
        "--i-authorize-lab-ttp"
    )
    if ($DryRun) {
        $runArgs += "--dry-run"
    }
    Write-Host "Running: corvex $($runArgs -join ' ')"
    & corvex @runArgs
    if ($LASTEXITCODE -ne 0) {
        throw "atomic-run exited $LASTEXITCODE"
    }
}
finally {
    if ($sensor -and -not $sensor.HasExited) {
        Write-Host "Stopping sensor (PID $($sensor.Id))"
        Stop-Process -Id $sensor.Id -Force -ErrorAction SilentlyContinue
    }
}

# Best-effort reconstruct if timeline exists
if (Test-Path (Join-Path $RunDir "timeline.json")) {
    Write-Host "Reconstructing $RunDir"
    & corvex reconstruct $RunDir
}

Write-Host "Done. See $RunDir/atomic_summary.json and reports/atomic_run_*.json"
Write-Host "Honesty: does not flip claim_allowed."
