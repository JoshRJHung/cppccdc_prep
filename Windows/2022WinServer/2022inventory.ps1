# Windows inventory (read-only) - run from an ELEVATED PowerShell
# Usage:  powershell -ExecutionPolicy Bypass -File .\inventory.ps1
# Save:   powershell -ExecutionPolicy Bypass -File .\inventory.ps1 > inventory.txt

$ErrorActionPreference = 'SilentlyContinue'
$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4   # 4/5 = Domain Controller

function Header($title) {
    Write-Output ""
    Write-Output "=== $title ==="
}

# List Internal IPs
Header "IP Address"
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength |
    Format-Table -AutoSize | Out-String -Width 200

# List Open Ports (like ss -tulpn)
Header "Open Ports"
$procs = @{}
Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$tcp = Get-NetTCPConnection -State Listen | ForEach-Object {
    [pscustomobject]@{ Proto = 'tcp'; Address = $_.LocalAddress; Port = $_.LocalPort; PID = $_.OwningProcess; Process = $procs[[int]$_.OwningProcess] }
}
$udp = Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 } | ForEach-Object {
    [pscustomobject]@{ Proto = 'udp'; Address = $_.LocalAddress; Port = $_.LocalPort; PID = $_.OwningProcess; Process = $procs[[int]$_.OwningProcess] }
}
@($tcp) + @($udp) | Sort-Object Proto, Port | Format-Table -AutoSize | Out-String -Width 200

# List All Users
Header "All Users"
if ($isDC) {
    Get-ADUser -Filter * -Properties PasswordLastSet, LastLogonDate |
        Select-Object SamAccountName, Enabled, PasswordLastSet, LastLogonDate |
        Format-Table -AutoSize | Out-String -Width 200
} else {
    Get-LocalUser |
        Select-Object Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon |
        Format-Table -AutoSize | Out-String -Width 200
}

# List Admin Users (like sudo/wheel)
Header "Admin Users"
if ($isDC) {
    foreach ($g in 'Domain Admins', 'Enterprise Admins', 'Administrators') {
        Write-Output "-- $g"
        Get-ADGroupMember -Identity $g -Recursive |
            Select-Object SamAccountName, objectClass |
            Format-Table -AutoSize | Out-String -Width 200
    }
} else {
    Get-LocalGroupMember -SID S-1-5-32-544 |
        Select-Object Name, ObjectClass, PrincipalSource |
        Format-Table -AutoSize | Out-String -Width 200
}

# Users That Don't Require a Password (blank password allowed)
Header "Users with No Password Required"
if ($isDC) {
    Get-ADUser -Filter 'PasswordNotRequired -eq $true' |
        Select-Object SamAccountName, Enabled |
        Format-Table -AutoSize | Out-String -Width 200
} else {
    Get-LocalUser | Where-Object { -not $_.PasswordRequired } |
        Select-Object Name, Enabled |
        Format-Table -AutoSize | Out-String -Width 200
}

# RDP Config
Header "RDP Config (Enabled / NLA / Port)"
$ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdp = "$ts\WinStations\RDP-Tcp"
"RDP enabled : " + ((Get-ItemProperty $ts).fDenyTSConnections -eq 0)
"NLA required: " + ((Get-ItemProperty $rdp).UserAuthentication -eq 1)
"Port        : " + (Get-ItemProperty $rdp).PortNumber

# SSH Config (only if OpenSSH server is installed)
Header "SSH Config (Root Login / Password Auth)"
$sshd = "$env:ProgramData\ssh\sshd_config"
if (Test-Path $sshd) {
    Select-String -Path $sshd -Pattern 'PermitRootLogin|PasswordAuthentication|^Port|AllowUsers' | ForEach-Object { $_.Line }
} else {
    "OpenSSH server config not found"
}

# SMB Shares
Header "SMB Shares"
Get-SmbShare | Select-Object Name, Path, Description |
    Format-Table -AutoSize | Out-String -Width 200

# Installed Software
Header "Installed Software"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object DisplayName |
    Sort-Object DisplayName |
    Select-Object DisplayName, DisplayVersion |
    Format-Table -AutoSize | Out-String -Width 200

# Running Services
Header "Running Services"
Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } |
    Sort-Object Name |
    Select-Object Name, StartName, PathName |
    Format-Table -AutoSize -Wrap | Out-String -Width 250

# Firewall Status
Header "Firewall Status"
Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    Format-Table -AutoSize | Out-String -Width 200

# Scheduled Tasks (like cron) - skips the built-in Microsoft ones
Header "Scheduled Tasks (non-Microsoft)"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Select-Object TaskPath, TaskName, State,
        @{ n = 'RunAs';  e = { $_.Principal.UserId } },
        @{ n = 'Action'; e = { ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ' } } |
    Format-Table -AutoSize -Wrap | Out-String -Width 250

# Autoruns (persistence check, closest thing to the SUID/cron review)
Header "Autorun Registry Keys"
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
               'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
    Write-Output "-- $k"
    (Get-ItemProperty $k).PSObject.Properties |
        Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object { "$($_.Name) = $($_.Value)" }
}
