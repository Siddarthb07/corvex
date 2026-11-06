# One-shot: install/start OpenSSH Server + authorize author (cyborg_1) key.
# On the NEW Windows lab PC (Admin PowerShell):
#   irm https://raw.githubusercontent.com/Siddarthb07/corvex/master/scripts/enable_s2_ssh.ps1 | iex
# Or from a local clone:
#   powershell -ExecutionPolicy Bypass -File scripts\enable_s2_ssh.ps1
$ErrorActionPreference = "Continue"
$pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8BSq2MukTIAWN79BAjcsVxjzJk/zNrYZ1CpLjf/1ll cyborg_1-to-cyborg-s2"

# Install OpenSSH Server if missing (Windows 10/11)
$sshd = Get-Service sshd -ErrorAction SilentlyContinue
if (-not $sshd) {
    Write-Host "Installing OpenSSH Server..."
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    } catch {
        Write-Host "Add-WindowsCapability failed; trying optional feature..."
        DISM /Online /Add-Capability /CapabilityName:OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }
}

cmd /c "net start sshd"
cmd /c "sc config sshd start= auto"
cmd /c "netsh advfirewall firewall delete rule name=OpenSSH Server"
cmd /c "netsh advfirewall firewall add rule name=OpenSSH Server dir=in action=allow protocol=TCP localport=22 profile=any"

New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\ProgramData\ssh" | Out-Null
$auth = "$env:USERPROFILE\.ssh\authorized_keys"
$adminAuth = "C:\ProgramData\ssh\administrators_authorized_keys"
if (-not (Test-Path $auth) -or -not (Select-String -Path $auth -Pattern "cyborg_1-to-cyborg-s2" -Quiet -ErrorAction SilentlyContinue)) {
    Add-Content -Path $auth -Value $pub
}
if (-not (Test-Path $adminAuth) -or -not (Select-String -Path $adminAuth -Pattern "cyborg_1-to-cyborg-s2" -Quiet -ErrorAction SilentlyContinue)) {
    Add-Content -Path $adminAuth -Value $pub
}
cmd /c "icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant Administrators:F /grant SYSTEM:F"

$cfg = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $cfg) {
    $t = Get-Content $cfg -Raw
    if ($t -notmatch "(?m)^PubkeyAuthentication\s+yes") {
        $t = $t -replace "(?m)^\s*#?\s*PubkeyAuthentication\s+.*", "PubkeyAuthentication yes"
        if ($t -notmatch "(?m)^PubkeyAuthentication\s+") { $t += "`r`nPubkeyAuthentication yes`r`n" }
    }
    if ($t -notmatch "(?m)^PasswordAuthentication\s+yes") {
        $t = $t -replace "(?m)^\s*#?\s*PasswordAuthentication\s+.*", "PasswordAuthentication yes"
        if ($t -notmatch "(?m)^PasswordAuthentication\s+") { $t += "`r`nPasswordAuthentication yes`r`n" }
    }
    Set-Content -Path $cfg -Value $t -NoNewline
}
cmd /c "net stop sshd & net start sshd"

$ip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -ExpandProperty IPAddress -First 3) -join ", "
Write-Host "SSH ready. hostname=$(hostname) user=$env:USERNAME ip=$ip"
Write-Host "From author PC:  ssh -i ~/.ssh/corvex_s2 $env:USERNAME@<ip>"
