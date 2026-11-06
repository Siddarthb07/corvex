#Requires -Version 5.1
<#
.SYNOPSIS
  Launch Windows EC2 instance(s) for S5 pure-benign capture.
.NOTES
  S5 needs >=3 distinct Windows hosts total. Typical: Cyborg + author PC + 1 EC2 (-Count 1).
  Use t3.medium (x86) for Windows — not t4g (ARM; no Windows Server AMI).
  See docs/s5-aws-three-host.md.
#>
param(
  [Parameter(Mandatory = $true)][string]$KeyName,
  [Parameter(Mandatory = $true)][string]$AllowCidr,
  [string]$Region = "us-east-1",
  [string]$InstanceType = "t3.medium",
  [ValidateRange(1, 3)][int]$Count = 1,
  [string]$CorpusName = "",
  [switch]$AllowSsh
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $CorpusName) {
  $CorpusName = "aws-s5-" + (Get-Date -Format "yyyy-MM-dd")
}
$Corpus = Join-Path $Root "labs\benign\$CorpusName"
New-Item -ItemType Directory -Force -Path (Join-Path $Corpus "raw") | Out-Null

aws sts get-caller-identity --region $Region | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw "AWS credentials missing. Run: aws configure   (two EC2 alone still need a 3rd host for S5)"
}

Write-Host "S5 note: launching $Count Windows EC2 ($InstanceType). Need >=3 Windows hosts total in the capture." -ForegroundColor Yellow
if ($InstanceType -like "t4g*") {
  throw "t4g is ARM — Windows Server AMIs need x86 (use t3.medium / t3.large)."
}

# Latest Windows Server 2022 AMI (Amazon-owned)
$Ami = aws ssm get-parameters `
  --names /aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base `
  --region $Region `
  --query "Parameters[0].Value" --output text
if (-not $Ami -or $Ami -eq "None") { throw "Could not resolve Windows AMI" }

$SgName = "corvex-s5-$CorpusName"
$SgId = aws ec2 describe-security-groups --region $Region --group-names $SgName `
  --query "SecurityGroups[0].GroupId" --output text 2>$null
if (-not $SgId -or $SgId -eq "None") {
  $SgId = aws ec2 create-security-group --region $Region `
    --group-name $SgName --description "Corvex S5 RDP/SSH" `
    --query "GroupId" --output text
  aws ec2 authorize-security-group-ingress --region $Region --group-id $SgId `
    --protocol tcp --port 3389 --cidr $AllowCidr | Out-Null
  if ($AllowSsh) {
    aws ec2 authorize-security-group-ingress --region $Region --group-id $SgId `
      --protocol tcp --port 22 --cidr $AllowCidr | Out-Null
  }
}

$UserData = @"
<powershell>
Install-WindowsFeature -Name RSAT-AD-Tools -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path C:\corvex-capture | Out-Null
</powershell>
"@
$UdPath = Join-Path $env:TEMP "corvex-s5-userdata.txt"
Set-Content -Path $UdPath -Value $UserData -Encoding ASCII

$Run = aws ec2 run-instances --region $Region `
  --image-id $Ami --count $Count --instance-type $InstanceType `
  --key-name $KeyName --security-group-ids $SgId `
  --user-data "file://$UdPath" `
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=corvex-s5},{Key=corvex-corpus,Value=$CorpusName}]" `
  --query "Instances[].InstanceId" --output text

$Ids = @($Run -split "\s+" | Where-Object { $_ })
Write-Host "Waiting for instances: $($Ids -join ', ')"
aws ec2 wait instance-running --region $Region --instance-ids $Ids

$Desc = aws ec2 describe-instances --region $Region --instance-ids $Ids `
  --query "Reservations[].Instances[].{Id:InstanceId,Dns:PublicDnsName,Ip:PublicIpAddress,Az:Placement.AvailabilityZone}" `
  --output json

$Inventory = @{
  corpus = $CorpusName
  region = $Region
  launched_utc = (Get-Date).ToUniversalTime().ToString("o")
  note = "Only 2 EC2 hosts. Add Cyborg or a third EC2 before starting S5 clock. Bars locked 2026-07-25."
  instances = ($Desc | ConvertFrom-Json)
}
$InvPath = Join-Path $Corpus "aws_inventory.json"
($Inventory | ConvertTo-Json -Depth 6) | Set-Content -Path $InvPath -Encoding UTF8

$Manifest = @{
  name = $CorpusName
  corpus_kind = "home_lab_capture"
  source = @{
    project = "aws-ec2-plus-lab"
    capture_start_utc = $null
    capture_end_utc = $null
    note = "Passive Sysmon; not inspected until window closed. 2x AWS + 1 lab host required."
  }
  raw_glob = "raw/**/*.jsonl"
  host_map = @{}
  attack_windows = @()
  roles = @{}
  bars_locked = "2026-07-25"
}
($Manifest | ConvertTo-Json -Depth 6) | Set-Content -Path (Join-Path $Corpus "manifest.json") -Encoding UTF8

Write-Host "Wrote $InvPath"
Write-Host "Next: RDP (Administrator password via aws ec2 get-password-data), install OpenSSH optional, then:"
Write-Host "  join_home_lab_host.ps1 -HostId host-aws-1 -Producer prod-aws-1 -RunDir runs/home-lab-s5-..."
Write-Host "Pair with Cyborg + one other Windows host for >=3. See docs\s5-aws-three-host.md"
