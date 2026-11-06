#Requires -Version 5.1
param(
  [Parameter(Mandatory = $true)][string]$CorpusName,
  [string]$Region = "us-east-1"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Inv = Join-Path $Root "labs\benign\$CorpusName\aws_inventory.json"
if (-not (Test-Path $Inv)) { throw "missing $Inv" }
$obj = Get-Content $Inv -Raw | ConvertFrom-Json
$Ids = @($obj.instances | ForEach-Object { $_.Id })
if (-not $Ids) { throw "no instance ids in inventory" }
Write-Host "Terminating $($Ids -join ', ')"
aws ec2 terminate-instances --region $Region --instance-ids $Ids | Out-Null
aws ec2 wait instance-terminated --region $Region --instance-ids $Ids
Write-Host "Terminated. Keep hashed raw/ + benign_baseline report."
