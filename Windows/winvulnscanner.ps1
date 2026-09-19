# Windows Server 2019 / 2022 vulnerability & misconfiguration scanner (read-only)
# Checks for known legacy-protocol exposures, weak auth settings, missing patches,
# and common privilege-escalation misconfigs. Makes NO changes to the system.
#
# Usage (run ELEVATED):
#   powershell -ExecutionPolicy Bypass -File .\vulnscan.ps1
#   powershell -ExecutionPolicy Bypass -File .\vulnscan.ps1 > vulnscan_report.txt
#
# CCDC note: fixing a finding here can BREAK a scored service if that service is
# what depends on the "vulnerable" setting (e.g. disabling SMBv1 when a legacy
# app needs it, or disabling PasswordAuthentication-equivalent for RDP/SSH).
# Cross-check against the scored-services list before changing anything, and
# file a PCR before touching any scored credential.

$ErrorActionPreference = 'SilentlyContinue'
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$Severity,
        [string]$Check,
        [string]$Detail,
        [string]$Fix
    )
    $findings.Add([pscustomobject]@{
        Severity = $Severity
        Check    = $Check
        Detail   = $Detail
        Fix      = $Fix
    })
}

function Header($title) {
    Write-Output ""
    Write-Output "=== $title ==="
}

$isDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4

Header "Target"
$os = Get-CimInstance Win32_OperatingSystem
"$env:COMPUTERNAME - $($os.Caption) (build $($os.BuildNumber))"

# ---------------------------------------------------------------------------
Header "Patch Level"
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
$hotfixes | Select-Object -First 10 HotFixID, Description, InstalledOn | Format-Table -AutoSize | Out-String -Width 200
$newest = $hotfixes | Select-Object -First 1 -ExpandProperty InstalledOn
if ($newest -and ((Get-Date) - $newest).Days -gt 60) {
    Add-Finding -Severity HIGH -Check "Patch level" `
        -Detail "Most recent hotfix installed $newest (>60 days ago)" `
        -Fix "Run Windows Update / apply latest cumulative update"
} elseif (-not $newest) {
    Add-Finding -Severity MEDIUM -Check "Patch level" `
        -Detail "Could not determine last hotfix date" `
        -Fix "Check manually: Get-HotFix, or Settings > Windows Update"
}

# ---------------------------------------------------------------------------
Header "SMBv1 (EternalBlue / WannaCry class)"
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
"SMBv1 enabled: $smb1"
if ($smb1) {
    Add-Finding -Severity CRITICAL -Check "SMBv1 enabled" `
        -Detail "SMBv1 protocol is enabled on the SMB server" `
        -Fix "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol (verify no scored service depends on it first)"
}

Header "SMB Signing"
$smbCfg = Get-SmbServerConfiguration
"RequireSecuritySignature: $($smbCfg.RequireSecuritySignature)"
"EncryptData: $($smbCfg.EncryptData)"
if (-not $smbCfg.RequireSecuritySignature) {
    Add-Finding -Severity MEDIUM -Check "SMB signing not required" `
        -Detail "SMB server does not require security signatures (relay attack risk)" `
        -Fix "Set-SmbServerConfiguration -RequireSecuritySignature `$true"
}

# ---------------------------------------------------------------------------
Header "Null Session / Anonymous Enumeration"
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
"RestrictAnonymous: $($lsa.RestrictAnonymous)"
"RestrictAnonymousSAM: $($lsa.RestrictAnonymousSAM)"
"EveryoneIncludesAnonymous: $($lsa.EveryoneIncludesAnonymous)"
if ($lsa.RestrictAnonymous -ne 1 -and $lsa.RestrictAnonymous -ne 2) {
    Add-Finding -Severity MEDIUM -Check "Anonymous enumeration allowed" `
        -Detail "RestrictAnonymous is not set to restrict SAM/share enumeration" `
        -Fix "Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa RestrictAnonymous to 1"
}
if ($lsa.EveryoneIncludesAnonymous -eq 1) {
    Add-Finding -Severity MEDIUM -Check "Anonymous = Everyone" `
        -Detail "EveryoneIncludesAnonymous is enabled, granting anonymous users Everyone-group rights" `
        -Fix "Set EveryoneIncludesAnonymous to 0"
}

# ---------------------------------------------------------------------------
Header "LLMNR / NBT-NS (poisoning / relay risk)"
$llmnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 2>$null
$llmnrEnabled = if ($null -eq $llmnr.EnableMulticast) { "Enabled (default)" } else { "Disabled" }
"LLMNR: $llmnrEnabled"
if ($null -eq $llmnr.EnableMulticast -or $llmnr.EnableMulticast -ne 0) {
    Add-Finding -Severity LOW -Check "LLMNR enabled" `
        -Detail "LLMNR is enabled (default), allowing name-resolution poisoning/relay attacks on the local segment" `
        -Fix "Set HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient EnableMulticast to 0 (via GPO: Turn off Multicast Name Resolution)"
}

# ---------------------------------------------------------------------------
Header "RDP / NLA"
$ts  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdp = "$ts\WinStations\RDP-Tcp"
$rdpEnabled = ((Get-ItemProperty $ts).fDenyTSConnections -eq 0)
$nla = ((Get-ItemProperty $rdp).UserAuthentication -eq 1)
"RDP enabled: $rdpEnabled"
"NLA required: $nla"
if ($rdpEnabled -and -not $nla) {
    Add-Finding -Severity HIGH -Check "RDP without NLA" `
        -Detail "RDP is enabled but Network Level Authentication is not required (BlueKeep-class exposure, pre-auth attack surface)" `
        -Fix "Set-ItemProperty -Path '$rdp' -Name UserAuthentication -Value 1 (NOTE: verify the scoring checker supports NLA before enabling for a scored RDP service)"
}

# ---------------------------------------------------------------------------
Header "Print Spooler (PrintNightmare)"
$spooler = Get-Service -Name Spooler
"Spooler status: $($spooler.Status), StartType: $($spooler.StartType)"
if ($spooler.Status -eq 'Running') {
    $pointAndPrint = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 2>$null
    Add-Finding -Severity MEDIUM -Check "Print Spooler running" `
        -Detail "Spooler service is running. Confirm PointAndPrint restrictions (NoWarningNoElevationOnInstall) are not set to 1, which enables PrintNightmare RCE" `
        -Fix "Disable spooler if not needed (Stop-Service Spooler; Set-Service Spooler -StartupType Disabled) or ensure May 2021+ patches and PointAndPrint restrictions are applied"
}

# ---------------------------------------------------------------------------
Header "PowerShell v2 (no logging, downgrade attack surface)"
$psv2 = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root 2>$null
if ($psv2) {
    "PowerShell v2 feature state: $($psv2.State)"
    if ($psv2.State -eq 'Enabled') {
        Add-Finding -Severity MEDIUM -Check "PowerShell v2 enabled" `
            -Detail "Legacy PowerShell v2 engine is installed - lacks AMSI/ScriptBlock logging, usable for downgrade attacks" `
            -Fix "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"
    }
}

# ---------------------------------------------------------------------------
Header "WinRM"
$winrm = Get-Service WinRM
"WinRM status: $($winrm.Status)"
if ($winrm.Status -eq 'Running') {
    $listeners = winrm enumerate winrm/config/listener 2>&1
    $listeners | Out-String
    if ($listeners -match 'Transport = HTTP\b' -and $listeners -notmatch 'HTTPS') {
        Add-Finding -Severity MEDIUM -Check "WinRM over HTTP only" `
            -Detail "WinRM listener uses unencrypted HTTP transport" `
            -Fix "Configure an HTTPS WinRM listener with a valid cert; disable the HTTP listener if not required"
    }
}

# ---------------------------------------------------------------------------
Header "UAC"
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
"EnableLUA: $($uac.EnableLUA)"
"ConsentPromptBehaviorAdmin: $($uac.ConsentPromptBehaviorAdmin)"
if ($uac.EnableLUA -eq 0) {
    Add-Finding -Severity HIGH -Check "UAC disabled" `
        -Detail "User Account Control is disabled (EnableLUA=0)" `
        -Fix "Set EnableLUA to 1 (requires reboot)"
}

# ---------------------------------------------------------------------------
Header "AlwaysInstallElevated (MSI privilege escalation)"
$aieHklm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer').AlwaysInstallElevated
$aieHkcu = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer').AlwaysInstallElevated
"HKLM AlwaysInstallElevated: $aieHklm"
"HKCU AlwaysInstallElevated: $aieHkcu"
if ($aieHklm -eq 1 -and $aieHkcu -eq 1) {
    Add-Finding -Severity HIGH -Check "AlwaysInstallElevated set" `
        -Detail "Both HKLM and HKCU AlwaysInstallElevated are 1 - any user can run an MSI as SYSTEM" `
        -Fix "Set both registry values to 0 or delete them"
}

# ---------------------------------------------------------------------------
Header "Unquoted Service Paths (privilege escalation)"
$unquoted = Get-CimInstance Win32_Service |
    Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match '\.exe' -and
        ($_.PathName -split '\.exe')[0] -match ' ' -and
        $_.PathName -notmatch '^[a-zA-Z]:\\[^ ]+\.exe$'
    } |
    Select-Object Name, StartName, PathName
$unquoted | Format-Table -AutoSize -Wrap | Out-String -Width 250
foreach ($svc in $unquoted) {
    Add-Finding -Severity HIGH -Check "Unquoted service path" `
        -Detail "Service '$($svc.Name)' path '$($svc.PathName)' is unquoted and contains spaces - classic local privesc via planted binary in an intermediate folder" `
        -Fix "Quote the binary path in the service's ImagePath registry value"
}

# ---------------------------------------------------------------------------
Header "Weak Service Permissions (world-writable binaries)"
$svcPaths = Get-CimInstance Win32_Service | Where-Object PathName |
    ForEach-Object {
        $exe = ($_.PathName -replace '^"([^"]+)".*$', '$1') -replace '^([^ ]+).*$', '$1'
        if (Test-Path $exe -PathType Leaf) { [pscustomobject]@{ Service = $_.Name; Path = $exe } }
    }
foreach ($s in $svcPaths) {
    $acl = Get-Acl $s.Path
    $writable = $acl.Access | Where-Object {
        $_.FileSystemRights -match 'Write|FullControl|Modify' -and
        $_.IdentityReference -match 'Everyone|Authenticated Users|Users\b|BUILTIN\\Users'
    }
    if ($writable) {
        Add-Finding -Severity CRITICAL -Check "Writable service binary" `
            -Detail "Service '$($s.Service)' binary at $($s.Path) is writable by a low-privilege group ($($writable.IdentityReference -join ', '))" `
            -Fix "Restrict NTFS permissions on the binary/folder to Administrators/SYSTEM only"
    }
}
"Checked $($svcPaths.Count) service binaries for weak ACLs (findings, if any, listed above)"

# ---------------------------------------------------------------------------
Header "Guest Account"
$guest = Get-LocalUser -Name 'Guest'
"Guest enabled: $($guest.Enabled)"
if ($guest.Enabled) {
    Add-Finding -Severity HIGH -Check "Guest account enabled" `
        -Detail "The built-in Guest account is enabled" `
        -Fix "Disable-LocalUser -Name Guest"
}

Header "Accounts with No Password Required"
$noPwd = Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired }
$noPwd | Select-Object Name | Format-Table -AutoSize | Out-String -Width 200
foreach ($u in $noPwd) {
    Add-Finding -Severity CRITICAL -Check "Blank password allowed" `
        -Detail "Enabled local account '$($u.Name)' does not require a password" `
        -Fix "Set-LocalUser -Name $($u.Name) -PasswordNeverExpires `$false; enforce a strong password (file a PCR first if this is a scored credential)"
}

Header "Accounts with Password Never Expires"
$neverExp = Get-LocalUser | Where-Object { $_.Enabled -and $_.PasswordExpires -eq $null -and $_.Name -ne 'Administrator' -and $_.Name -ne 'Guest' -and $_.Name -ne 'DefaultAccount' -and $_.Name -ne 'WDAGUtilityAccount' }
$neverExp | Select-Object Name | Format-Table -AutoSize | Out-String -Width 200
foreach ($u in $neverExp) {
    Add-Finding -Severity LOW -Check "Password never expires" `
        -Detail "Account '$($u.Name)' has no password expiration set" `
        -Fix "Review whether this is intentional (service accounts) or should be rotated"
}

# ---------------------------------------------------------------------------
Header "Windows Defender / AV Status"
$mp = Get-MpComputerStatus
if ($mp) {
    "AntivirusEnabled: $($mp.AntivirusEnabled)"
    "RealTimeProtectionEnabled: $($mp.RealTimeProtectionEnabled)"
    "AntivirusSignatureAge (days): $($mp.AntivirusSignatureAge)"
    if (-not $mp.RealTimeProtectionEnabled) {
        Add-Finding -Severity HIGH -Check "Real-time protection disabled" `
            -Detail "Microsoft Defender real-time protection is OFF" `
            -Fix "Set-MpPreference -DisableRealtimeMonitoring `$false"
    }
    if ($mp.AntivirusSignatureAge -gt 7) {
        Add-Finding -Severity MEDIUM -Check "Stale AV signatures" `
            -Detail "Defender signatures are $($mp.AntivirusSignatureAge) days old" `
            -Fix "Update-MpSignature"
    }
} else {
    "Defender status unavailable (disabled, uninstalled, or third-party AV present)"
    Add-Finding -Severity MEDIUM -Check "AV status unknown" `
        -Detail "Could not query Defender status" `
        -Fix "Confirm an AV/EDR product is installed and active"
}

# ---------------------------------------------------------------------------
Header "Windows Firewall"
$fw = Get-NetFirewallProfile
$fw | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize | Out-String -Width 200
foreach ($p in $fw | Where-Object { -not $_.Enabled }) {
    Add-Finding -Severity HIGH -Check "Firewall profile disabled" `
        -Detail "Windows Firewall profile '$($p.Name)' is disabled" `
        -Fix "Set-NetFirewallProfile -Name $($p.Name) -Enabled True"
}

# ---------------------------------------------------------------------------
Header "SMB Shares - Everyone / Full Control"
$shares = Get-SmbShare | Where-Object { -not $_.Special }
foreach ($s in $shares) {
    $acl = Get-SmbShareAccess -Name $s.Name
    foreach ($a in $acl | Where-Object { $_.AccountName -eq 'Everyone' -and "$($_.AccessRight)" -in 'Full','Change' -and "$($_.AccessControlType)" -eq 'Allow' }) {
        Add-Finding -Severity HIGH -Check "Over-permissive share" `
            -Detail "Share '$($s.Name)' ($($s.Path)) grants Everyone $($a.AccessRight) access" `
            -Fix "Restrict share permissions to specific users/groups that need access"
    }
}
$shares | Select-Object Name, Path | Format-Table -AutoSize | Out-String -Width 200

# ---------------------------------------------------------------------------
Header "Deprecated TLS/SSL and Weak Ciphers"
$protoBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($proto in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1') {
    $srv = Get-ItemProperty "$protoBase\$proto\Server" 2>$null
    $disabled = ($srv.Enabled -eq 0) -or ($srv.DisabledByDefault -eq 1)
    $state = if ($null -eq $srv) { "not explicitly configured (OS default)" } elseif ($disabled) { "disabled" } else { "ENABLED" }
    "$proto (server): $state"
    if ($state -eq 'ENABLED') {
        Add-Finding -Severity MEDIUM -Check "Deprecated protocol enabled: $proto" `
            -Detail "$proto is explicitly enabled for inbound SChannel connections" `
            -Fix "Disable via registry ($protoBase\$proto\Server -> Enabled=0, DisabledByDefault=1) if no legacy client depends on it"
    }
}

# ---------------------------------------------------------------------------
Header "SUMMARY"
$order = @{CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFO=4}
$sorted = $findings | Sort-Object { $order[$_.Severity] }
if ($sorted.Count -eq 0) {
    "No findings raised by this scan (still review the sections above manually)."
} else {
    "$($sorted.Count) finding(s):"
    Write-Output ""
    $sorted | ForEach-Object {
        Write-Output "[$($_.Severity)] $($_.Check)"
        Write-Output "    Detail: $($_.Detail)"
        Write-Output "    Fix:    $($_.Fix)"
        Write-Output ""
    }
    Write-Output ("By severity: " + (($sorted | Group-Object Severity | Sort-Object { $order[$_.Name] } | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '))
}
