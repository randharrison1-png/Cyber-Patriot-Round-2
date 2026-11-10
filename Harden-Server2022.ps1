<#
.SYNOPSIS
    Audits and hardens the Windows Server 2022 machine described in the
    "Arc Foundry & Aerospace" CyberPatriot training README (intranet web
    server plus the Handbook file share).

.DESCRIPTION
    Each check reads the current state first, logs OK if it is already
    compliant, and fixes it if it is not. Everything is written to a log in
    C:\HardeningLogs. Items a script cannot safely decide are listed at the
    end as MANUAL / REVIEW.

    Critical services it keeps working (README):
      - IIS (Web Server): stays running, directory browsing is turned off
      - SMB File Share: C:\Shares\Handbook stays shared as "Handbook",
        readable by everyone, changeable only by administrators

    What it will NOT touch (README guidelines):
      - the CCS Client service/process and C:\CyberPatriot
      - the password of the account running the script / the auto-login account
      - authorized users or their home directories
      - time zone, date, time
      - Windows feature updates, Insider builds, Reset/Go-back recovery
      - the content of the web site and the Handbook folder (media found there
        is reported, not removed)

.PARAMETER AuditOnly
    Report what would change. Makes no changes.

.PARAMETER PasswordScope
    All       (default) new password for every authorized account except the
              account running the script and the auto-login account
    UsersOnly new password for standard users plus accounts in $KnownWeakAccounts
    None      do not change any passwords

.PARAMETER NewPassword
    SecureString to use as the new password. Prompted for if omitted.

.PARAMETER DeleteProhibited
    Delete prohibited files instead of moving them to C:\HardeningQuarantine.

.PARAMETER SkipSoftwareUpdates
    Do not try to update the authorized applications with winget.

.PARAMETER SkipFileScan
    Skip the prohibited media / hacking tool file scan.

.PARAMETER Force
    Skip the "have you answered the Forensics Questions" confirmation.

.EXAMPLE
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Harden-Server2022.ps1 -AuditOnly   # look first
    .\Harden-Server2022.ps1              # then fix
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$AuditOnly,
    [ValidateSet('All', 'UsersOnly', 'None')]
    [string]$PasswordScope = 'All',
    [securestring]$NewPassword,
    [switch]$DeleteProhibited,
    [switch]$SkipSoftwareUpdates,
    [switch]$SkipFileScan,
    [switch]$Force
)

# =============================================================================
#  CONFIGURATION  -  taken from the README. Edit here for a different scenario.
# =============================================================================

$AuthorizedAdmins = @('pparker', 'tstark', 'ppotts', 'hhogan', 'nfury', 'mhill', 'pcoulson')

$AuthorizedUsers = @('bbanner', 'swilson', 'sstrange', 'slang', 'cdanvers', 'okoye', 'kbishop',
                     'ybelova', 'jfoster', 'nleeds', 'mjwatson', 'jtorres', 'pcarter')

# Admins whose README password does not meet the secure-password policy.
# ("security1" has no upper case or symbol and is only 9 characters.)
$KnownWeakAccounts = @('hhogan')

# Password / lockout policy
$MinPasswordLength = 14
$MaxPasswordAge    = 90     # days
$MinPasswordAge    = 1      # days
$PasswordHistory   = 24
$LockoutThreshold  = 5      # bad attempts
$LockoutMinutes    = 30

# Required file share (README): everyone may read, only administrators may change
$HandbookShareName = 'Handbook'
$HandbookSharePath = 'C:\Shares\Handbook'
$AuthorizedShares  = @($HandbookShareName)

# The README lists IIS and the SMB share as the only critical services and
# says nothing about remote access, so Remote Desktop is turned OFF.
# Set this to $true if you administer the server over RDP.
$KeepRemoteDesktop = $false

# Folders that hold the content of the critical services. Media files found
# here are reported for review instead of being removed. IIS site folders are
# added automatically.
$ProtectedContentRoots = @('C:\inetpub', 'C:\Shares')

# Business software that must stay installed (README) -> winget package IDs
$AuthorizedSoftware = [ordered]@{
    'Google Chrome' = 'Google.Chrome'
    'Notepad++'     = 'Notepad++.Notepad++'
    'WinSCP'        = 'WinSCP.WinSCP'
    '7-Zip'         = '7zip.7zip'
}

# Installed programs matching these are never flagged
$SoftwareAllowPattern = 'Google Chrome|Notepad\+\+|WinSCP|7-Zip|^Microsoft|^Windows|^IIS|VMware|' +
                        'CyberPatriot|CCS Client|Intel|Realtek'

# Installed programs matching these are prohibited (hacking tools, remote
# access, P2P, games, media players). The script tries a silent uninstall.
$ProhibitedSoftwarePattern = @(
    'Wireshark', 'Npcap', 'WinPcap', '\bNmap\b', 'Zenmap', 'Cain & Abel', '^Cain\b', 'John the Ripper',
    'Ophcrack', 'Hashcat', 'Metasploit', 'Netcat', 'Angry IP', 'Advanced IP Scanner', 'Burp Suite',
    'Aircrack', 'L0phtCrack', 'Nessus', 'THC.?Hydra', 'Nikto', 'sqlmap', 'Mimikatz', 'Keylogger',
    'Spyrix', 'Revealer', 'Ardamax', 'TeamViewer', 'AnyDesk', 'VNC', 'LogMeIn', 'Radmin', 'Ammyy',
    'uTorrent', 'BitTorrent', 'qBittorrent', 'Vuze', 'Deluge', 'FrostWire', 'eMule', 'Tor Browser',
    '^Steam\b', 'Epic Games', 'Minecraft', 'Roblox', 'League of Legends', 'Battle\.net', 'GOG Galaxy',
    'Spotify', 'iTunes', '\bKodi\b', '\bPlex\b', 'VLC media', 'Winamp', 'Discord', 'CCleaner',
    'Driver Booster', 'IObit', 'FileZilla Server', 'XAMPP', 'WampServer'
) -join '|'

# Non-work media (auto-removed outside program folders and AppData)
$MediaExtensions = @('.mp3', '.mp4', '.m4a', '.m4v', '.wav', '.wma', '.wmv', '.avi', '.mkv', '.mov',
                     '.flac', '.ogg', '.aac', '.mpg', '.mpeg', '.flv', '.webm')

# File types that are only listed for you to review (never auto-removed)
$ReviewExtensions = @('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.zip', '.rar', '.7z', '.tar', '.gz',
                      '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.py', '.jar')

# Stand-alone hacking tool file names (auto-removed outside program folders)
$HackToolFileNames = @('nc.exe', 'nc64.exe', 'ncat.exe', 'netcat.exe', 'mimikatz.exe', 'pwdump.exe',
                       'pwdump7.exe', 'fgdump.exe', 'john.exe', 'hashcat.exe', 'cain.exe', 'abel.exe',
                       'ophcrack.exe', 'hydra.exe', 'nmap.exe', 'zenmap.exe', 'wireshark.exe',
                       'lazagne.exe', 'wce.exe', 'gsecdump.exe', 'keylogger.exe', 'sqlmap.py',
                       'nikto.pl', 'aircrack-ng.exe', 'ettercap.exe', 'medusa.exe', 'brutus.exe')

# Services that have no business purpose in this scenario. The web server
# (W3SVC, WAS) and file server (LanmanServer) are critical and never listed.
# FTP is listed because the README only authorizes the IIS *web* server.
# Print Spooler is listed because nothing in the README needs printing and it
# is a well-known attack surface on servers.
# WinRM is NOT listed: Server Manager uses it locally. It is reported instead.
$ServicesToDisable = @('RemoteRegistry', 'TlntSvr', 'SNMP', 'SNMPTRAP', 'simptcp', 'FTPSVC', 'MSFTPSVC',
                       'sshd', 'RemoteAccess', 'SharedAccess', 'upnphost', 'SSDPSRV', 'Fax', 'Spooler',
                       'NetTcpPortSharing', 'WMPNetworkSvc', 'tftpd*', 'uvnc_service', 'tvnserver',
                       'vncserver*', 'TeamViewer*', 'AnyDesk*', 'FileZilla Server*')

$WindowsFeaturesToDisable = @('TelnetClient', 'TFTP', 'SMB1Protocol', 'SimpleTCP',
                              'MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')

$LogDir        = 'C:\HardeningLogs'
$QuarantineDir = 'C:\HardeningQuarantine'

# =============================================================================
#  PLUMBING
# =============================================================================

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$Stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$LogFile = Join-Path $LogDir "harden-$Stamp.log"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$script:Counts = @{ OK = 0; FIXED = 0; WOULD = 0; FAIL = 0; WARN = 0 }
$script:Manual = New-Object System.Collections.Generic.List[string]
$script:Review = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param([string]$Level, [string]$Message)
    $colors = @{ OK = 'DarkGray'; FIXED = 'Green'; WOULD = 'Cyan'; FAIL = 'Red'; WARN = 'Yellow';
                 INFO = 'White'; HEAD = 'Magenta' }
    if ($script:Counts.ContainsKey($Level)) { $script:Counts[$Level]++ }
    $line = '[{0}] {1}' -f $Level.PadRight(5), $Message
    $color = 'White'
    if ($colors.ContainsKey($Level)) { $color = $colors[$Level] }
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Add-Content -Path $LogFile -Value '' -Encoding UTF8
    Write-Log 'HEAD' "===== $Title ====="
}

function Add-Manual {
    param([string]$Text)
    $script:Manual.Add($Text)
    Write-Log 'WARN' "MANUAL: $Text"
}

function Add-Review {
    param([string]$Text)
    $script:Review.Add($Text)
}

# Runs a fix unless -AuditOnly. Blocks may read the caller's variables.
function Invoke-Change {
    param([string]$What, [scriptblock]$Do)
    if ($AuditOnly) { Write-Log 'WOULD' $What; return }
    try {
        $ErrorActionPreference = 'Stop'
        & $Do
        Write-Log 'FIXED' $What
    }
    catch {
        Write-Log 'FAIL' "$What  ->  $($_.Exception.Message)"
    }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Why)
    $current = $null
    try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { }
    if ($null -ne $current -and "$current" -eq "$Value") { Write-Log 'OK' $Why; return }
    $was = 'not set'
    if ($null -ne $current) { $was = "$current" }
    Invoke-Change "$Why  [$Name = $Value, was $was]" {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    }
}

# Removes a policy value that is switching a protection off.
function Remove-Reg {
    param([string]$Path, [string]$Name, [string]$Why)
    $current = $null
    try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { }
    if ($null -eq $current) { return }
    Invoke-Change "$Why  [removed $Name = $current]" {
        Remove-ItemProperty -Path $Path -Name $Name -Force
    }
}

function Test-IsCcs {
    param([string]$Text)
    return ($Text -match 'CCS ?Client|CyberPatriot')
}

function Disable-Svc {
    param([string]$Name)
    $found = Get-Service -Name $Name -ErrorAction SilentlyContinue
    foreach ($svc in $found) {
        if (Test-IsCcs "$($svc.Name) $($svc.DisplayName)") { continue }
        if ("$($svc.StartType)" -eq 'Disabled' -and "$($svc.Status)" -eq 'Stopped') {
            Write-Log 'OK' "Service '$($svc.DisplayName)' is disabled"
            continue
        }
        Invoke-Change "Stop and disable service '$($svc.DisplayName)' ($($svc.Name))" {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled
        }
    }
}

function Enable-Svc {
    param([string]$Name, [string]$StartType = 'Automatic', [switch]$Start)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { Write-Log 'WARN' "Service '$Name' not found"; return }
    $startOk = ("$($svc.StartType)" -eq $StartType) -or ("$($svc.StartType)" -eq 'Automatic')
    $runOk   = (-not $Start) -or ("$($svc.Status)" -eq 'Running')
    if ($startOk -and $runOk) { Write-Log 'OK' "Service '$($svc.DisplayName)' is enabled"; return }
    Invoke-Change "Enable service '$($svc.DisplayName)' ($Name)" {
        if (-not $startOk) {
            try { Set-Service -Name $Name -StartupType $StartType }
            catch {
                # protected services (wscsvc, WinDefend) refuse Set-Service
                $map = @{ Automatic = 2; Manual = 3 }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name Start -Value $map[$StartType]
            }
        }
        if ($Start) { Start-Service -Name $Name }
    }
}

# Makes sure an enabled inbound allow rule covers a TCP port on the active network profile.
function Enable-InboundPort {
    param([int]$Port, [string]$Label)
    $cats = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue |
              ForEach-Object { "$($_.NetworkCategory)" -replace 'DomainAuthenticated', 'Domain' } |
              Select-Object -Unique)
    if ($cats.Count -eq 0) { $cats = @('Public') }
    $activePattern = $cats -join '|'
    $open = $false
    try {
        $filters = @(Get-NetFirewallPortFilter -ErrorAction Stop |
                     Where-Object { "$($_.Protocol)" -eq 'TCP' -and (@($_.LocalPort) -contains "$Port") })
        foreach ($filter in $filters) {
            $rule = $filter | Get-NetFirewallRule -ErrorAction SilentlyContinue
            foreach ($r in $rule) {
                $profileOk = ("$($r.Profile)" -eq 'Any') -or ("$($r.Profile)" -match $activePattern)
                if ("$($r.Enabled)" -eq 'True' -and "$($r.Direction)" -eq 'Inbound' -and "$($r.Action)" -eq 'Allow' -and $profileOk) {
                    $open = $true
                }
            }
        }
    }
    catch { }
    if ($open) { Write-Log 'OK' "Firewall allows inbound TCP $Port ($Label)"; return }
    Invoke-Change "Firewall: allow inbound TCP $Port ($Label)" {
        New-NetFirewallRule -DisplayName "Hardening - $Label (TCP $Port)" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Any | Out-Null
    }
}

# Lists every identity other than Administrators / SYSTEM / TrustedInstaller that can change a folder.
function Get-NonAdminWriters {
    param([string]$Path)
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeBits = [int][Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $genericWriteOrAll = 0x50000000
    $found = New-Object System.Collections.Generic.List[string]
    $items = @(Get-Item -LiteralPath $Path -Force)
    $items += @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue)
    $first = $true
    foreach ($item in $items) {
        try {
            $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            # top folder: every rule counts; below it: only rules set directly on the item
            $rules = $acl.GetAccessRules($true, $first, [Security.Principal.SecurityIdentifier])
            foreach ($rule in $rules) {
                if ("$($rule.AccessControlType)" -ne 'Allow') { continue }
                $sid = $rule.IdentityReference.Value
                if ($trusted -contains $sid) { continue }
                $rights = [int]$rule.FileSystemRights
                if (($rights -band $writeBits) -ne 0 -or ($rights -band $genericWriteOrAll) -ne 0) {
                    $who = $sid
                    try { $who = $rule.IdentityReference.Translate([Security.Principal.NTAccount]).Value } catch { }
                    $found.Add("$who on $($item.FullName)")
                }
            }
        }
        catch { }
        $first = $false
    }
    return $found
}

function ConvertTo-PlainText {
    param([securestring]$Secure)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Test-PasswordStrength {
    param([string]$Plain)
    $classes = 0
    if ($Plain -cmatch '[a-z]') { $classes++ }
    if ($Plain -cmatch '[A-Z]') { $classes++ }
    if ($Plain -match '\d') { $classes++ }
    if ($Plain -match '[^a-zA-Z0-9]') { $classes++ }
    return ($Plain.Length -ge $MinPasswordLength -and $classes -ge 3)
}

function Get-GroupMembers {
    param([string]$Group)
    try {
        Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name    = ($_.Name -split '\\')[-1]
                Full    = $_.Name
                IsLocalUser = ("$($_.ObjectClass)" -eq 'User' -and "$($_.PrincipalSource)" -eq 'Local')
            }
        }
    }
    catch {
        # Get-LocalGroupMember fails when the group holds an orphaned SID
        $lines = & net.exe localgroup $Group
        $start = [array]::IndexOf($lines, ($lines | Where-Object { $_ -match '^-{5,}' } | Select-Object -First 1))
        if ($start -lt 0) { return }
        foreach ($line in $lines[($start + 1)..($lines.Count - 1)]) {
            $entry = $line.Trim()
            if (-not $entry -or $entry -match '^The command completed') { continue }
            [pscustomobject]@{
                Name        = ($entry -split '\\')[-1]
                Full        = $entry
                IsLocalUser = ($entry -notmatch '\\')
            }
        }
    }
}

function Remove-Prohibited {
    param([System.IO.FileInfo]$File, [string]$Reason)
    if ($DeleteProhibited) {
        Invoke-Change "Delete $Reason '$($File.FullName)'" { Remove-Item -LiteralPath $File.FullName -Force }
    }
    else {
        Invoke-Change "Quarantine $Reason '$($File.FullName)'" {
            if (-not (Test-Path $QuarantineDir)) { New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null }
            $flat = ($File.FullName -replace '^[A-Za-z]:\\', '') -replace '\\', '__'
            Move-Item -LiteralPath $File.FullName -Destination (Join-Path $QuarantineDir $flat) -Force
        }
    }
}

# =============================================================================
#  0. PRE-FLIGHT
# =============================================================================

Write-Section 'Pre-flight'
$mode = 'FIX'
if ($AuditOnly) { $mode = 'AUDIT ONLY (no changes)' }
Write-Log 'INFO' "Mode: $mode   Log: $LogFile"

$domainRole = 0
try { $domainRole = [int](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole } catch { }
if ($domainRole -ge 4) {
    Write-Log 'FAIL' 'This server is a domain controller. This script manages LOCAL accounts and local policy, which do not exist on a domain controller. Stopping; nothing was changed.'
    return
}

$CurrentUser = $env:USERNAME
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
$AutoLogonUser = $null
if ("$($winlogon.AutoAdminLogon)" -eq '1') { $AutoLogonUser = "$($winlogon.DefaultUserName)" }
$ProtectedAccounts = @(@($CurrentUser, $AutoLogonUser) | Where-Object { $_ } | Select-Object -Unique)
$AllAuthorized = @($AuthorizedAdmins + $AuthorizedUsers)
Write-Log 'INFO' "Running as '$CurrentUser'. Auto-login account: '$AutoLogonUser'. Their passwords are never changed."

if ($AuthorizedAdmins -notcontains $CurrentUser -and -not $Force) {
    Write-Log 'FAIL' "'$CurrentUser' is not in `$AuthorizedAdmins. Stopping so the script cannot lock you out. Fix the list or use -Force."
    return
}

if (-not $AuditOnly -and -not $Force) {
    Write-Host ''
    Write-Host 'STOP. Before this script changes anything:' -ForegroundColor Yellow
    Write-Host '  1. Read the whole README.' -ForegroundColor Yellow
    Write-Host '  2. Answer every Forensics Question on the Desktop. This script removes users' -ForegroundColor Yellow
    Write-Host '     and files that those questions may ask about.' -ForegroundColor Yellow
    Write-Host '  3. Take a VM snapshot.' -ForegroundColor Yellow
    $answer = Read-Host 'Type YES to continue'
    if ($answer -cne 'YES') { Write-Log 'INFO' 'Cancelled by operator.'; return }
}

# Password to hand out
$PasswordTargets = @()
switch ($PasswordScope) {
    'All'       { $PasswordTargets = @($AllAuthorized | Where-Object { $ProtectedAccounts -notcontains $_ }) }
    'UsersOnly' { $PasswordTargets = @(@($AuthorizedUsers + $KnownWeakAccounts) | Where-Object { $ProtectedAccounts -notcontains $_ }) }
    'None'      { $PasswordTargets = @() }
}
if (-not $AuditOnly -and $PasswordTargets.Count -gt 0) {
    while ($true) {
        if (-not $NewPassword) {
            $NewPassword = Read-Host "New password for $($PasswordTargets.Count) accounts ($MinPasswordLength+ chars, 3 of: upper/lower/digit/symbol)" -AsSecureString
            $confirm = Read-Host 'Confirm password' -AsSecureString
            if ((ConvertTo-PlainText $NewPassword) -cne (ConvertTo-PlainText $confirm)) {
                Write-Host 'Passwords do not match.' -ForegroundColor Red
                $NewPassword = $null
                continue
            }
        }
        if (Test-PasswordStrength (ConvertTo-PlainText $NewPassword)) { break }
        Write-Host 'That password does not meet the policy this script is about to enforce.' -ForegroundColor Red
        $NewPassword = $null
    }
    Write-Log 'INFO' 'New password accepted. Write it down somewhere safe: it is not stored in the log.'
}

# Backups of what is about to change
if (-not $AuditOnly) {
    & secedit.exe /export /cfg (Join-Path $LogDir "secpol-before-$Stamp.inf") /quiet
    Get-LocalUser | Select-Object Name, Enabled, SID, PasswordLastSet, PasswordRequired |
        Export-Csv (Join-Path $LogDir "users-before-$Stamp.csv") -NoTypeInformation
    Write-Log 'INFO' "Saved the current security policy and user list to $LogDir"
}

# =============================================================================
#  1. USER ACCOUNTS
# =============================================================================

Write-Section 'User accounts'
$BuiltInRids = @('500', '501', '503', '504')   # Administrator, Guest, DefaultAccount, WDAGUtilityAccount

foreach ($u in Get-LocalUser) {
    $rid = ($u.SID.Value -split '-')[-1]
    if ($BuiltInRids -contains $rid) {
        if (($rid -eq '500' -or $rid -eq '501') -and $u.Enabled) {
            if ($ProtectedAccounts -contains $u.Name) {
                Write-Log 'WARN' "Built-in account '$($u.Name)' is the account in use; left enabled"
            }
            else {
                Invoke-Change "Disable built-in account '$($u.Name)'" { Disable-LocalUser -Name $u.Name }
            }
        }
        continue
    }
    if ($AllAuthorized -contains $u.Name) { continue }
    if ($ProtectedAccounts -contains $u.Name) {
        Write-Log 'WARN' "'$($u.Name)' is not authorized but is the account in use; not removed"
        continue
    }
    Invoke-Change "Remove unauthorized user '$($u.Name)' (profile folder is left on disk)" {
        Remove-LocalUser -Name $u.Name
    }
}

foreach ($name in $AllAuthorized) {
    $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if (-not $u) {
        Add-Manual "Authorized account '$name' does not exist. Create it if the README or a Forensics Question asks for it."
        continue
    }
    if (-not $u.Enabled) {
        Invoke-Change "Enable authorized account '$name'" { Enable-LocalUser -Name $name }
    }
    if ($PasswordTargets -contains $name) {
        Invoke-Change "Set a new strong password for '$name'" { Set-LocalUser -Name $name -Password $NewPassword }
    }
    if (-not $u.PasswordRequired) {
        Invoke-Change "Require a password for '$name'" {
            & net.exe user $name /passwordreq:yes | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "net user exited $LASTEXITCODE" }
        }
    }
    $flags = 0
    try { $flags = [int]([ADSI]"WinNT://./$name,user").UserFlags.Value } catch { }
    if ($flags -band 0x10000) {
        Invoke-Change "Clear 'password never expires' on '$name'" { Set-LocalUser -Name $name -PasswordNeverExpires $false }
    }
    if (-not $u.UserMayChangePassword) {
        Invoke-Change "Allow '$name' to change their own password" { Set-LocalUser -Name $name -UserMayChangePassword $true }
    }
}

# =============================================================================
#  2. GROUP MEMBERSHIP
# =============================================================================

Write-Section 'Group membership'
$AdminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name
$UsersGroup = (Get-LocalGroup -SID 'S-1-5-32-545').Name
$GuestGroup = (Get-LocalGroup -SID 'S-1-5-32-546').Name
$RdpGroup   = (Get-LocalGroup -SID 'S-1-5-32-555').Name

$adminMembers = @(Get-GroupMembers $AdminGroup)
foreach ($m in $adminMembers) {
    if (-not $m.IsLocalUser) { Add-Review "Non-local member of $AdminGroup : $($m.Full)"; continue }
    $lu = Get-LocalUser -Name $m.Name -ErrorAction SilentlyContinue
    if ($lu -and $lu.SID.Value.EndsWith('-500')) { continue }
    if ($AuthorizedAdmins -contains $m.Name) { Write-Log 'OK' "'$($m.Name)' is an authorized administrator"; continue }
    if ($ProtectedAccounts -contains $m.Name) { Write-Log 'WARN' "'$($m.Name)' is the account in use; left in $AdminGroup"; continue }
    Invoke-Change "Remove '$($m.Name)' from $AdminGroup (not an authorized administrator)" {
        Remove-LocalGroupMember -Group $AdminGroup -Member $m.Name
    }
}
foreach ($name in $AuthorizedAdmins) {
    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { continue }
    if (($adminMembers | ForEach-Object { $_.Name }) -notcontains $name) {
        Invoke-Change "Add authorized administrator '$name' to $AdminGroup" {
            Add-LocalGroupMember -Group $AdminGroup -Member $name
        }
    }
}

$userMembers = @(Get-GroupMembers $UsersGroup | ForEach-Object { $_.Name })
foreach ($name in $AllAuthorized) {
    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { continue }
    if ($userMembers -notcontains $name) {
        Invoke-Change "Add '$name' to $UsersGroup" { Add-LocalGroupMember -Group $UsersGroup -Member $name }
    }
}

foreach ($m in @(Get-GroupMembers $GuestGroup)) {
    if ($AllAuthorized -contains $m.Name) {
        Invoke-Change "Remove authorized user '$($m.Name)' from $GuestGroup" {
            Remove-LocalGroupMember -Group $GuestGroup -Member $m.Name
        }
    }
}

foreach ($m in @(Get-GroupMembers $RdpGroup)) {
    if ($m.IsLocalUser -and $AllAuthorized -notcontains $m.Name) {
        Invoke-Change "Remove unauthorized '$($m.Name)' from $RdpGroup" {
            Remove-LocalGroupMember -Group $RdpGroup -Member $m.Name
        }
    }
    else { Add-Review "$RdpGroup member: $($m.Full)" }
}

foreach ($g in Get-LocalGroup) {
    if ($g.SID.Value -notmatch '^S-1-5-32-') {
        $names = (@(Get-GroupMembers $g.Name) | ForEach-Object { $_.Name }) -join ', '
        Add-Review "Non-default local group '$($g.Name)' (members: $names)"
    }
}

# =============================================================================
#  3. PASSWORD, LOCKOUT AND USER RIGHTS POLICY
# =============================================================================

Write-Section 'Password, lockout and user-rights policy'

# Guard: a max password age shorter than the age of the auto-login password
# would force a password change at the next sign-in.
$applyMaxAge = $true
foreach ($name in $ProtectedAccounts) {
    $pu = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($pu -and $pu.PasswordLastSet) {
        $age = ((Get-Date) - $pu.PasswordLastSet).Days
        if ($age -ge ($MaxPasswordAge - 2)) {
            $applyMaxAge = $false
            Add-Manual "Password for '$name' is $age days old. Maximum password age was NOT set, to avoid locking that account out. Set it in secpol.msc (Account Policies > Password Policy) after dealing with that password."
        }
    }
}

$builtinAdminInUse = $false
foreach ($name in $ProtectedAccounts) {
    $pu = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    if ($pu -and $pu.SID.Value.EndsWith('-500')) { $builtinAdminInUse = $true }
}

$inf = New-Object System.Collections.Generic.List[string]
$inf.Add('[Unicode]')
$inf.Add('Unicode=yes')
$inf.Add('[Version]')
$inf.Add('signature="$CHICAGO$"')
$inf.Add('Revision=1')
$inf.Add('[System Access]')
$inf.Add("MinimumPasswordAge = $MinPasswordAge")
if ($applyMaxAge) { $inf.Add("MaximumPasswordAge = $MaxPasswordAge") }
$inf.Add("MinimumPasswordLength = $MinPasswordLength")
$inf.Add('PasswordComplexity = 1')
$inf.Add("PasswordHistorySize = $PasswordHistory")
$inf.Add('ClearTextPassword = 0')
$inf.Add("LockoutBadCount = $LockoutThreshold")
$inf.Add("ResetLockoutCount = $LockoutMinutes")
$inf.Add("LockoutDuration = $LockoutMinutes")
$inf.Add('LSAAnonymousNameLookup = 0')
$inf.Add('EnableGuestAccount = 0')
if (-not $builtinAdminInUse) { $inf.Add('EnableAdminAccount = 0') }
$inf.Add('[Privilege Rights]')
# 544 Administrators, 546 Guests, 555 Remote Desktop Users, S-1-5-11 Authenticated Users
# Authenticated Users keep network logon: without it nobody could open the Handbook share.
$inf.Add('SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11')
$inf.Add('SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555')
$inf.Add('SeDenyNetworkLogonRight = *S-1-5-32-546')
$inf.Add('SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546')
$inf.Add('SeDenyInteractiveLogonRight = *S-1-5-32-546')
$inf.Add('SeDebugPrivilege = *S-1-5-32-544')
$inf.Add('SeTakeOwnershipPrivilege = *S-1-5-32-544')
$inf.Add('SeRemoteShutdownPrivilege = *S-1-5-32-544')
$inf.Add('SeTcbPrivilege =')
$inf.Add('SeCreateTokenPrivilege =')

Invoke-Change "Apply password policy (length $MinPasswordLength, complexity, history $PasswordHistory, age $MinPasswordAge-$MaxPasswordAge days), lockout ($LockoutThreshold attempts / $LockoutMinutes min) and user rights" {
    $infPath = Join-Path $LogDir "secpol-applied-$Stamp.inf"
    $dbPath  = Join-Path $LogDir "secpol-$Stamp.sdb"
    $inf | Out-File -FilePath $infPath -Encoding Unicode
    & secedit.exe /configure /db $dbPath /cfg $infPath /areas SECURITYPOLICY USER_RIGHTS /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit exited $LASTEXITCODE (see %windir%\security\logs\scesrv.log)" }
}

Invoke-Change 'Enable success and failure auditing for every audit category' {
    & auditpol.exe /set /category:* /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol exited $LASTEXITCODE" }
}

# =============================================================================
#  4. LOCAL SECURITY OPTIONS
# =============================================================================

Write-Section 'Security options'
$polSys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lanSrv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$lanWks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

Set-Reg $polSys 'EnableLUA' 1                    -Why 'UAC is enabled'
Set-Reg $polSys 'ConsentPromptBehaviorAdmin' 2   -Why 'UAC prompts administrators for consent on the secure desktop'
Set-Reg $polSys 'PromptOnSecureDesktop' 1        -Why 'UAC prompts appear on the secure desktop'
Set-Reg $polSys 'EnableInstallerDetection' 1     -Why 'UAC detects application installs'
Set-Reg $polSys 'FilterAdministratorToken' 1     -Why 'Built-in Administrator runs in Admin Approval Mode'
Set-Reg $polSys 'DontDisplayLastUserName' 1      -Why 'Last signed-in user name is not shown'
Set-Reg $polSys 'DisableCAD' 0                   -Why 'Ctrl+Alt+Del is required to sign in'
Set-Reg $polSys 'InactivityTimeoutSecs' 900      -Why 'Machine locks after 15 minutes of inactivity'

Set-Reg $lsa 'LimitBlankPasswordUse' 1           -Why 'Blank passwords are limited to console logon'
Set-Reg $lsa 'RestrictAnonymous' 1               -Why 'Anonymous enumeration of shares is blocked'
Set-Reg $lsa 'RestrictAnonymousSAM' 1            -Why 'Anonymous enumeration of SAM accounts is blocked'
Set-Reg $lsa 'EveryoneIncludesAnonymous' 0       -Why 'Everyone permissions do not apply to anonymous users'
Set-Reg $lsa 'NoLMHash' 1                        -Why 'LAN Manager password hashes are not stored'
Set-Reg $lsa 'LmCompatibilityLevel' 5            -Why 'Only NTLMv2 is accepted (LM and NTLM refused)'
Set-Reg $lsa 'RunAsPPL' 1                        -Why 'LSA runs as a protected process'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 -Why 'WDigest does not keep plaintext credentials in memory'

Set-Reg $lanSrv 'RequireSecuritySignature' 1     -Why 'SMB server requires signing'
Set-Reg $lanSrv 'EnableSecuritySignature' 1      -Why 'SMB server signing is enabled'
Set-Reg $lanSrv 'RestrictNullSessAccess' 1       -Why 'Null-session access to shares and pipes is restricted'
$nullShares = @()
try { $nullShares = @((Get-ItemProperty -Path $lanSrv -Name NullSessionShares -ErrorAction Stop).NullSessionShares | Where-Object { $_ }) } catch { }
if ($nullShares.Count -gt 0) {
    Invoke-Change "Clear the list of shares that allow anonymous (null-session) access: $($nullShares -join ', ')" {
        Set-ItemProperty -Path $lanSrv -Name NullSessionShares -Value ([string[]]@()) -Type MultiString
    }
}
else { Write-Log 'OK' 'No shares allow anonymous (null-session) access' }
Set-Reg $lanWks 'RequireSecuritySignature' 1     -Why 'SMB client requires signing'
Set-Reg $lanWks 'EnableSecuritySignature' 1      -Why 'SMB client signing is enabled'
Set-Reg $lanWks 'EnablePlainTextPassword' 0      -Why 'SMB client never sends unencrypted passwords'

Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 -Why 'AutoPlay is off for all drives'
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 1           -Why 'AutoRun is off'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0                -Why 'LLMNR is off'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1                    -Why 'Windows SmartScreen is on'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Warn' -Type String -Why 'SmartScreen warns before running unrecognized apps'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 -Why 'PowerShell script block logging is on'

try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    if ($smb.EnableSMB1Protocol) {
        Invoke-Change 'Disable the SMBv1 server protocol' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
    }
    else { Write-Log 'OK' 'SMBv1 server protocol is off' }
}
catch { Write-Log 'WARN' "Could not read SMB server configuration: $($_.Exception.Message)" }

# =============================================================================
#  5. REMOTE DESKTOP (not a required service here: off unless $KeepRemoteDesktop)
# =============================================================================

Write-Section 'Remote Desktop'
$ts    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdp   = "$ts\WinStations\RDP-Tcp"
$tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

if ($KeepRemoteDesktop) {
    Set-Reg $ts 'fDenyTSConnections' 0     -Why 'Remote Desktop connections are allowed ($KeepRemoteDesktop is set)'
    Remove-Reg $tsPol 'fDenyTSConnections' -Why 'Policy value that could block Remote Desktop'
    Enable-Svc 'TermService' -StartType Manual -Start
}
else {
    Set-Reg $ts 'fDenyTSConnections' 1     -Why 'Remote Desktop is off (the README does not list it as a required service)'
}
# These apply whenever RDP is ever switched on
Set-Reg $rdp 'UserAuthentication' 1    -Why 'RDP requires Network Level Authentication'
Set-Reg $rdp 'SecurityLayer' 2         -Why 'RDP uses TLS'
Set-Reg $rdp 'MinEncryptionLevel' 3    -Why 'RDP uses high encryption'
Set-Reg $tsPol 'fPromptForPassword' 1  -Why 'RDP always prompts for a password'
Set-Reg $tsPol 'DisablePasswordSaving' 1 -Why 'RDP client may not save passwords'
Set-Reg $tsPol 'fEncryptRPCTraffic' 1  -Why 'RDP requires secure RPC'
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' 0 -Why 'Remote Assistance is off (policy)'
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0 -Why 'Remote Assistance is off'

# =============================================================================
#  6. FIREWALL
# =============================================================================

Write-Section 'Windows Firewall'
foreach ($p in 'DomainProfile', 'StandardProfile', 'PublicProfile', 'PrivateProfile') {
    Remove-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" 'EnableFirewall' -Why "Firewall policy override ($p)"
}
Enable-Svc 'mpssvc' -Start
foreach ($fwProfile in Get-NetFirewallProfile) {
    if ("$($fwProfile.Enabled)" -eq 'True' -and "$($fwProfile.DefaultInboundAction)" -ne 'Allow') {
        Write-Log 'OK' "Firewall is on for the $($fwProfile.Name) profile"
    }
    else {
        Invoke-Change "Turn on the firewall for the $($fwProfile.Name) profile (block inbound, allow outbound)" {
            Set-NetFirewallProfile -Name $fwProfile.Name -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        }
    }
}
Invoke-Change 'Log dropped packets on all firewall profiles' {
    Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384
}
if ($KeepRemoteDesktop) {
    Invoke-Change 'Allow Remote Desktop through the firewall' { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' }
}
else {
    Invoke-Change 'Block Remote Desktop in the firewall' { Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' }
}
Invoke-Change 'Block Remote Assistance in the firewall' { Disable-NetFirewallRule -DisplayGroup 'Remote Assistance' -ErrorAction SilentlyContinue }
# Ports for the two critical services are opened in the IIS and file share sections.

# =============================================================================
#  7. MICROSOFT DEFENDER AND ACTION CENTER
# =============================================================================

Write-Section 'Defender and Action Center'
$defPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
Remove-Reg $defPol 'DisableAntiSpyware' -Why 'Policy value that disables Defender'
Remove-Reg $defPol 'DisableAntiVirus'   -Why 'Policy value that disables Defender'
foreach ($v in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection',
               'DisableScanOnRealtimeEnable', 'DisableIOAVProtection') {
    Remove-Reg "$defPol\Real-Time Protection" $v -Why 'Policy value that disables real-time protection'
}
if (-not (Get-Service -Name WinDefend -ErrorAction SilentlyContinue)) {
    # On Windows Server, Defender is a removable feature
    try {
        $defFeature = Get-WindowsFeature -Name Windows-Defender -ErrorAction Stop
        if ($defFeature -and -not $defFeature.Installed) {
            Invoke-Change 'Install the Microsoft Defender Antivirus feature (needs a restart)' {
                Install-WindowsFeature -Name Windows-Defender | Out-Null
            }
        }
    }
    catch { Add-Manual 'Microsoft Defender Antivirus is not installed and could not be checked. Add it in Server Manager > Add Roles and Features > Features.' }
}
Enable-Svc 'WinDefend' -Start

try {
    $mp = Get-MpPreference -ErrorAction Stop
    if ($mp.DisableRealtimeMonitoring -or $mp.DisableBehaviorMonitoring -or $mp.DisableIOAVProtection -or $mp.DisableScriptScanning) {
        Invoke-Change 'Turn Defender real-time, behavior, download and script protection back on' {
            Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false
        }
    }
    else { Write-Log 'OK' 'Defender real-time protection is on' }

    Invoke-Change 'Enable Defender cloud protection, PUA blocking and archive/removable-drive scanning' {
        Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled -DisableArchiveScanning $false -DisableRemovableDriveScanning $false -DisableBlockAtFirstSeen $false
    }

    foreach ($x in @($mp.ExclusionPath)) {
        if ($x -and -not (Test-IsCcs $x)) { Invoke-Change "Remove Defender path exclusion '$x'" { Remove-MpPreference -ExclusionPath $x } }
    }
    foreach ($x in @($mp.ExclusionExtension)) {
        if ($x) { Invoke-Change "Remove Defender extension exclusion '$x'" { Remove-MpPreference -ExclusionExtension $x } }
    }
    foreach ($x in @($mp.ExclusionProcess)) {
        if ($x -and -not (Test-IsCcs $x)) { Invoke-Change "Remove Defender process exclusion '$x'" { Remove-MpPreference -ExclusionProcess $x } }
    }

    Invoke-Change 'Update Defender signatures' { Update-MpSignature }
    Invoke-Change 'Start a Defender quick scan in the background' { Start-MpScan -ScanType QuickScan -AsJob | Out-Null }
}
catch {
    Add-Manual "Defender could not be configured ($($_.Exception.Message)). Open Windows Security and turn on real-time protection by hand."
}

# README: Action Center must be enabled and monitoring security status.
# Windows Server has no Security Center service (wscsvc); where it exists it is enabled.
if (Get-Service -Name wscsvc -ErrorAction SilentlyContinue) { Enable-Svc 'wscsvc' -Start }
if (Get-Service -Name SecurityHealthService -ErrorAction SilentlyContinue) { Enable-Svc 'SecurityHealthService' -StartType Manual }
Remove-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableNotificationCenter' -Why 'Policy value that hides Action Center'
Remove-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableNotificationCenter' -Why 'Policy value that hides Action Center (current user)'
Remove-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAHealth' -Why 'Policy value that hides security status notifications'
Remove-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' 'DisableNotifications' -Why 'Policy value that mutes Windows Security notifications'

# =============================================================================
#  8. WINDOWS UPDATE (quality updates on, preview builds blocked)
# =============================================================================

Write-Section 'Windows Update'
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
Set-Reg "$wu\AU" 'NoAutoUpdate' 0 -Why 'Automatic updates are enabled'
Set-Reg "$wu\AU" 'AUOptions' 4    -Why 'Updates download and install automatically'
Remove-Reg $wu 'DisableWindowsUpdateAccess' -Why 'Policy value that blocks Windows Update'
Enable-Svc 'wuauserv' -StartType Manual
Enable-Svc 'UsoSvc'
Enable-Svc 'BITS' -StartType Manual

# README forbids feature updates and Insider builds.
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' 'AllowBuildPreview' 0 -Why 'Insider Preview builds are blocked'
Add-Manual 'Settings > Windows Update > Check for updates. Install security/quality (cumulative) updates only. Do NOT accept a feature update or an upgrade to a newer Windows Server.'

# =============================================================================
#  9. SERVICES AND WINDOWS FEATURES
# =============================================================================

Write-Section 'Services and Windows features'
foreach ($s in $ServicesToDisable) { Disable-Svc $s }
Enable-Svc 'EventLog' -Start

foreach ($f in $WindowsFeaturesToDisable) {
    $feature = $null
    try { $feature = Get-WindowsOptionalFeature -Online -FeatureName $f -ErrorAction Stop } catch { continue }
    if ($feature -and "$($feature.State)" -eq 'Enabled') {
        Invoke-Change "Turn off Windows feature '$f'" {
            Disable-WindowsOptionalFeature -Online -FeatureName $f -NoRestart -WarningAction SilentlyContinue | Out-Null
        }
    }
}

$winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrm -and "$($winrm.Status)" -eq 'Running') {
    Add-Review 'WinRM (remote management) is running. Left alone because Server Manager uses it; the README says no centralized management tools are used, so disable it if you do not need Server Manager: Stop-Service WinRM; Set-Service WinRM -StartupType Disabled'
}

try {
    $expectedRoles = @('Web-Server', 'FileAndStorage-Services')
    Get-WindowsFeature -ErrorAction Stop |
        Where-Object { $_.Installed -and "$($_.FeatureType)" -eq 'Role' -and $expectedRoles -notcontains $_.Name } |
        ForEach-Object { Add-Review "Installed server role the README does not mention: $($_.DisplayName) [$($_.Name)]" }
    Get-WindowsFeature -ErrorAction Stop |
        Where-Object { $_.Installed -and $_.Name -match '^(Web-Ftp-Server|Web-Ftp-Service|Web-Ftp-Ext|Web-DAV-Publishing|SNMP-Service|SMTP-Server|WINS|Simple-TCPIP|Telnet-Client|TFTP-Client|FS-SMB1)$' } |
        ForEach-Object { Add-Review "Installed feature that is rarely needed and often abused: $($_.DisplayName) [$($_.Name)]. Remove with: Uninstall-WindowsFeature $($_.Name)" }
}
catch { }

# =============================================================================
# 10. SMB FILE SHARE (critical service) AND HOSTS FILE
# =============================================================================

Write-Section 'SMB file share (critical service)'
Enable-Svc 'LanmanServer' -Start
Enable-InboundPort 445 'SMB file sharing'

$sidEveryone = 'S-1-1-0'
$sidAdmins   = 'S-1-5-32-544'
$sidSystem   = 'S-1-5-18'
$nameEveryone = ([Security.Principal.SecurityIdentifier]$sidEveryone).Translate([Security.Principal.NTAccount]).Value
$nameAdmins   = ([Security.Principal.SecurityIdentifier]$sidAdmins).Translate([Security.Principal.NTAccount]).Value

try {
    $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Name -ne 'print$' })
    foreach ($sh in $shares) {
        if ($AuthorizedShares -contains $sh.Name) { continue }
        Invoke-Change "Remove unauthorized file share '$($sh.Name)' -> $($sh.Path) (files stay on disk)" {
            Remove-SmbShare -Name $sh.Name -Force
        }
    }
}
catch { Write-Log 'WARN' "Could not list shares: $($_.Exception.Message)" }

if (-not (Test-Path -LiteralPath $HandbookSharePath)) {
    Add-Manual "The folder $HandbookSharePath does not exist, so the required '$HandbookShareName' share cannot be checked. Find where the handbook went, restore the folder, and re-run this script."
}
else {
    $hb = Get-SmbShare -Name $HandbookShareName -ErrorAction SilentlyContinue
    if (-not $hb) {
        Invoke-Change "Create the required share '$HandbookShareName' -> $HandbookSharePath" {
            New-SmbShare -Name $HandbookShareName -Path $HandbookSharePath -ReadAccess $nameEveryone -FullAccess $nameAdmins | Out-Null
        }
    }
    elseif ($hb.Path.TrimEnd('\') -ne $HandbookSharePath.TrimEnd('\')) {
        Invoke-Change "Re-point share '$HandbookShareName' from $($hb.Path) to $HandbookSharePath" {
            Remove-SmbShare -Name $HandbookShareName -Force
            New-SmbShare -Name $HandbookShareName -Path $HandbookSharePath -ReadAccess $nameEveryone -FullAccess $nameAdmins | Out-Null
        }
    }
    else { Write-Log 'OK' "Share '$HandbookShareName' points to $HandbookSharePath" }

    # Share permissions: Everyone = Read, Administrators = Full, nobody else can change
    if (Get-SmbShare -Name $HandbookShareName -ErrorAction SilentlyContinue) {
        $everyoneRead = $false
        $adminsFull   = $false
        foreach ($entry in @(Get-SmbShareAccess -Name $HandbookShareName -ErrorAction SilentlyContinue)) {
            $acct  = "$($entry.AccountName)"
            $right = "$($entry.AccessRight)"
            if ("$($entry.AccessControlType)" -eq 'Deny') {
                Invoke-Change "Share '$HandbookShareName': remove the Deny entry for '$acct' (the share must stay available to everyone)" {
                    Unblock-SmbShareAccess -Name $HandbookShareName -AccountName $acct -Force | Out-Null
                }
                continue
            }
            if ($acct -eq $nameAdmins) { if ($right -eq 'Full') { $adminsFull = $true }; continue }
            if ($acct -eq $nameEveryone -and $right -eq 'Read') { $everyoneRead = $true; continue }
            if ($acct -eq $nameEveryone) { continue }
            if ($right -ne 'Read') {
                Invoke-Change "Share '$HandbookShareName': reduce '$acct' from $right to Read (only administrators may change the share)" {
                    Revoke-SmbShareAccess -Name $HandbookShareName -AccountName $acct -Force | Out-Null
                    Grant-SmbShareAccess -Name $HandbookShareName -AccountName $acct -AccessRight Read -Force | Out-Null
                }
            }
        }
        if ($everyoneRead) { Write-Log 'OK' "Share '$HandbookShareName': Everyone has Read" }
        else {
            Invoke-Change "Share '$HandbookShareName': set Everyone to Read (no more, no less)" {
                Revoke-SmbShareAccess -Name $HandbookShareName -AccountName $nameEveryone -Force -ErrorAction SilentlyContinue | Out-Null
                Grant-SmbShareAccess -Name $HandbookShareName -AccountName $nameEveryone -AccessRight Read -Force | Out-Null
            }
        }
        if ($adminsFull) { Write-Log 'OK' "Share '$HandbookShareName': Administrators have Full control" }
        else {
            Invoke-Change "Share '$HandbookShareName': give Administrators Full control" {
                Grant-SmbShareAccess -Name $HandbookShareName -AccountName $nameAdmins -AccessRight Full -Force | Out-Null
            }
        }
    }

    # NTFS permissions: the share permission alone does not stop local or RDP users
    $writers = @(Get-NonAdminWriters -Path $HandbookSharePath)
    $canRead = $false
    try {
        $topRules = (Get-Acl -LiteralPath $HandbookSharePath).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
        foreach ($rule in $topRules) {
            if ("$($rule.AccessControlType)" -eq 'Allow' -and @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') -contains $rule.IdentityReference.Value -and
                (([int]$rule.FileSystemRights -band [int][Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [int][Security.AccessControl.FileSystemRights]::ReadAndExecute)) {
                $canRead = $true
            }
        }
    }
    catch { }
    if ($writers.Count -eq 0 -and $canRead) {
        Write-Log 'OK' "NTFS permissions on $HandbookSharePath: users can read, only administrators can change"
    }
    else {
        foreach ($w in ($writers | Select-Object -First 15)) { Write-Log 'WARN' "Can change Handbook content: $w" }
        if (-not $canRead) { Write-Log 'WARN' "Ordinary users cannot read $HandbookSharePath" }
        Invoke-Change "Reset NTFS permissions on $HandbookSharePath (Administrators and SYSTEM: full control; Everyone: read only)" {
            & icacls.exe $HandbookSharePath /setowner "*$sidAdmins" /T /C /Q | Out-Null
            & icacls.exe $HandbookSharePath /reset /T /C /Q | Out-Null
            & icacls.exe $HandbookSharePath /inheritance:r /grant:r "*${sidAdmins}:(OI)(CI)F" "*${sidSystem}:(OI)(CI)F" "*${sidEveryone}:(OI)(CI)RX" /C /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "icacls exited $LASTEXITCODE" }
        }
    }
}

# =============================================================================
# 10b. IIS WEB SERVER (critical service)
# =============================================================================

Write-Section 'IIS web server (critical service)'
Enable-Svc 'WAS' -StartType Manual
Enable-Svc 'W3SVC' -Start

$iisReady = $false
try { Import-Module WebAdministration -ErrorAction Stop; $iisReady = $true } catch { }

if (-not $iisReady) {
    # Fallback when the IIS PowerShell module is not installed: appcmd ships with IIS itself
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (Test-Path -LiteralPath $appcmd) {
        Invoke-Change 'IIS: turn directory browsing off for the whole server (appcmd)' {
            & $appcmd set config /section:directoryBrowse /enabled:false | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "appcmd exited $LASTEXITCODE" }
        }
        foreach ($siteName in @(& $appcmd list site /text:name)) {
            if (-not $siteName) { continue }
            Invoke-Change "IIS: turn directory browsing off for site '$siteName' (appcmd)" {
                & $appcmd set config "$siteName" /section:directoryBrowse /enabled:false | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "appcmd exited $LASTEXITCODE" }
            }
        }
        Enable-InboundPort 80 'IIS web server'
        Add-Manual 'The IIS PowerShell module is missing, so only the server and site level were set with appcmd. In IIS Manager, check Directory Browsing on each application and sub-folder, and check the site bindings.'
    }
    else {
        Add-Manual 'IIS management tools were not found. Confirm the Web Server (IIS) role is installed, then turn directory browsing off: IIS Manager > server node > Directory Browsing > Disable, and repeat for each site.'
    }
}

if ($iisReady) {
    $dbFilter = '/system.webServer/directoryBrowse'
    $iisPaths = New-Object System.Collections.Generic.List[string]
    $iisPaths.Add('IIS:\')
    $sitePhysicalPaths = New-Object System.Collections.Generic.List[string]
    $webPorts = New-Object System.Collections.Generic.List[int]

    foreach ($site in @(Get-Website)) {
        $siteName = $site.Name
        $iisPaths.Add("IIS:\Sites\$siteName")
        $phys = [Environment]::ExpandEnvironmentVariables("$($site.physicalPath)")
        if ($phys) { $sitePhysicalPaths.Add($phys) }
        foreach ($app in @(Get-WebApplication -Site $siteName -ErrorAction SilentlyContinue)) {
            $iisPaths.Add("IIS:\Sites\$siteName" + ("$($app.path)" -replace '/', '\'))
            $appPhys = [Environment]::ExpandEnvironmentVariables("$($app.PhysicalPath)")
            if ($appPhys) { $sitePhysicalPaths.Add($appPhys) }
        }
        foreach ($vdir in @(Get-WebVirtualDirectory -Site $siteName -ErrorAction SilentlyContinue)) {
            $iisPaths.Add("IIS:\Sites\$siteName" + ("$($vdir.path)" -replace '/', '\'))
            $vdirPhys = [Environment]::ExpandEnvironmentVariables("$($vdir.physicalPath)")
            if ($vdirPhys) { $sitePhysicalPaths.Add($vdirPhys) }
        }
        $bindingText = (@($site.bindings.Collection) | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join '; '
        Add-Review "IIS site '$siteName' [$($site.State)] serves $phys on: $bindingText"
        if ("$($site.State)" -ne 'Started') {
            Invoke-Change "Start IIS site '$siteName' (the web server must stay available)" { Start-Website -Name $siteName }
        }
        foreach ($b in @($site.bindings.Collection)) {
            if ("$($b.protocol)" -match '^https?$') {
                $portText = ("$($b.bindingInformation)" -split ':')[1]
                $portNumber = 0
                if ([int]::TryParse($portText, [ref]$portNumber) -and -not $webPorts.Contains($portNumber)) { $webPorts.Add($portNumber) }
            }
            elseif ("$($b.protocol)" -eq 'ftp') {
                Add-Review "IIS site '$siteName' has an FTP binding ($($b.bindingInformation)). The README authorizes a web server only; remove the FTP site or binding."
            }
        }
    }

    # SOC request: directory browsing off at the server, every site, application and virtual directory
    foreach ($p in $iisPaths) {
        $enabled = $null
        try { $enabled = (Get-WebConfigurationProperty -PSPath $p -Filter $dbFilter -Name enabled -ErrorAction Stop).Value } catch { continue }
        if ($enabled -eq $true) {
            Invoke-Change "IIS: turn directory browsing off at $p" {
                Set-WebConfigurationProperty -PSPath $p -Filter $dbFilter -Name enabled -Value $false
            }
        }
        else { Write-Log 'OK' "IIS: directory browsing is off at $p" }
    }

    # ...and in any web.config further down that switches it back on
    foreach ($root in ($sitePhysicalPaths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root)) { Add-Review "IIS content folder does not exist: $root"; continue }
        if ($ProtectedContentRoots -notcontains $root) { $ProtectedContentRoots += $root }
        foreach ($cfg in @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -Filter web.config -ErrorAction SilentlyContinue)) {
            $text = [IO.File]::ReadAllText($cfg.FullName)
            if ($text -match '(?i)<directoryBrowse[^>]*\benabled\s*=\s*"true"') {
                Invoke-Change "IIS: turn directory browsing off in $($cfg.FullName) (original copied to $LogDir)" {
                    Copy-Item -LiteralPath $cfg.FullName -Destination (Join-Path $LogDir ("web.config-" + ($cfg.DirectoryName -replace '[:\\]', '_') + "-$Stamp.bak")) -Force
                    $fixed = [regex]::Replace($text, '(?i)(<directoryBrowse[^>]*\benabled\s*=\s*")true(")', '${1}false${2}')
                    [IO.File]::WriteAllText($cfg.FullName, $fixed)
                }
            }
        }
        $scripts = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                     Where-Object { @('.php', '.asp', '.aspx', '.ashx', '.jsp', '.cgi', '.exe', '.bat', '.cmd', '.ps1') -contains $_.Extension.ToLower() })
        if ($scripts.Count -gt 0) {
            $sample = ($scripts | Select-Object -First 8 | ForEach-Object { $_.FullName }) -join ', '
            Add-Review "$($scripts.Count) script/executable files in web content under $root. Check for web shells: $sample"
        }
    }

    foreach ($pool in @(Get-ChildItem 'IIS:\AppPools' -ErrorAction SilentlyContinue)) {
        if ("$($pool.processModel.identityType)" -eq 'LocalSystem') {
            Add-Review "IIS application pool '$($pool.Name)' runs as LocalSystem. Change it to ApplicationPoolIdentity in IIS Manager unless the site needs it."
        }
    }

    if ($webPorts.Count -eq 0) { $webPorts.Add(80) }
    foreach ($port in $webPorts) { Enable-InboundPort $port 'IIS web server' }
}

Write-Section 'Hosts file'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hosts) {
    $entries = @(Get-Content $hosts | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^#' })
    if ($entries.Count -eq 0) { Write-Log 'OK' 'hosts file has no custom entries' }
    else {
        Invoke-Change "Reset hosts file ($($entries.Count) custom entries; original saved to $LogDir)" {
            Copy-Item $hosts (Join-Path $LogDir "hosts-before-$Stamp.txt") -Force
            $default = @('# Copyright (c) 1993-2009 Microsoft Corp.', '#',
                         '# localhost name resolution is handled within DNS itself.',
                         '#	127.0.0.1       localhost', '#	::1             localhost')
            Set-Content -Path $hosts -Value $default -Encoding ASCII
        }
    }
}

# =============================================================================
# 11. INSTALLED SOFTWARE
# =============================================================================

Write-Section 'Installed software'
$uninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
$installed = @(Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
               Sort-Object DisplayName -Unique)

foreach ($app in $installed) {
    $n = "$($app.DisplayName)"
    if (Test-IsCcs $n) { continue }
    if ($n -match $ProhibitedSoftwarePattern) {
        $quiet = "$($app.QuietUninstallString)"
        $un    = "$($app.UninstallString)"
        if ($quiet) {
            Invoke-Change "Uninstall prohibited software '$n'" {
                $proc = Start-Process cmd.exe -ArgumentList ('/c "' + $quiet + '"') -Wait -PassThru -WindowStyle Hidden
                if ($proc.ExitCode -ne 0) { throw "uninstaller exited $($proc.ExitCode)" }
            }
        }
        elseif ($un -match 'MsiExec' -and $un -match '\{[0-9A-Fa-f\-]{36}\}') {
            $guid = $Matches[0]
            Invoke-Change "Uninstall prohibited software '$n'" {
                $proc = Start-Process msiexec.exe -ArgumentList "/x $guid /qn /norestart" -Wait -PassThru
                if ($proc.ExitCode -notin 0, 1605, 3010) { throw "msiexec exited $($proc.ExitCode)" }
            }
        }
        else {
            Add-Manual "Uninstall prohibited software '$n' from Settings > Apps (no silent uninstaller available)."
        }
    }
    elseif ($n -notmatch $SoftwareAllowPattern) {
        Add-Review "Installed program not on the authorized list: $n $($app.DisplayVersion)"
    }
}

foreach ($label in $AuthorizedSoftware.Keys) {
    $escaped = [regex]::Escape($label)
    if (-not ($installed | Where-Object { $_.DisplayName -match $escaped })) {
        Add-Manual "Required business software '$label' was not found installed. Install the 64-bit version."
    }
}

try {
    $badApps = @(Get-AppxPackage -AllUsers -ErrorAction Stop |
                 Where-Object { $_.Name -match 'CandyCrush|Solitaire|Xbox|Spotify|Netflix|TikTok|Disney|Minecraft|Roblox|BubbleWitch|MarchofEmpires' })
    foreach ($a in $badApps) { Add-Review "Store app that may be non-work software: $($a.Name)" }
}
catch { }

if ($SkipSoftwareUpdates) {
    Add-Manual 'Update Chrome, Notepad++, WinSCP and 7-Zip to their latest 64-bit versions.'
}
elseif (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
    Add-Manual 'winget is not available (normal on Windows Server 2022). Update Chrome, Notepad++, WinSCP and 7-Zip by hand from their official sites (64-bit installers, no ad links).'
}
else {
    foreach ($label in $AuthorizedSoftware.Keys) {
        $id = $AuthorizedSoftware[$label]
        Invoke-Change "Update $label with winget" {
            & winget.exe upgrade --id $id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Null
            # -1978335189 = no newer version available, -1978335212 = package not found by winget
            if ($LASTEXITCODE -eq -1978335189) { return }
            if ($LASTEXITCODE -ne 0) { throw "winget exited $LASTEXITCODE; update $label by hand" }
        }
    }
    Add-Manual 'Open each business app once (Help > About) and confirm it reports the latest version.'
}
Add-Manual 'Make Google Chrome the default browser for all users: Settings > Apps > Default apps > Web browser > Google Chrome. Windows blocks scripts from doing this.'

# =============================================================================
# 12. PROHIBITED FILES
# =============================================================================

if (-not $SkipFileScan) {
    Write-Section 'Prohibited files (this scan can take a few minutes)'
    $skipTop  = @('Windows', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'CyberPatriot',
                  (Split-Path $LogDir -Leaf), (Split-Path $QuarantineDir -Leaf))
    $progTop  = @('Program Files', 'Program Files (x86)', 'ProgramData')
    $topDirs  = @(Get-ChildItem -Path 'C:\' -Directory -Force -ErrorAction SilentlyContinue |
                  Where-Object { $skipTop -notcontains $_.Name -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })

    foreach ($top in $topDirs) {
        $isProgramArea = $progTop -contains $top.Name
        $files = Get-ChildItem -LiteralPath $top.FullName -Recurse -File -Force -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            if (Test-IsCcs $file.FullName) { continue }
            if ($file.FullName -match '\\Users\\(All Users|Default User)\\') { continue }
            $ext  = $file.Extension.ToLower()
            $name = $file.Name.ToLower()
            $inAppData = $file.FullName -match '\\(AppData|Application Data|Local Settings)\\'
            $inServedContent = $false
            foreach ($contentRoot in $ProtectedContentRoots) {
                if ($file.FullName -like ($contentRoot.TrimEnd('\') + '\*')) { $inServedContent = $true }
            }

            if ($HackToolFileNames -contains $name) {
                if ($isProgramArea) { Add-Review "Hacking tool file inside a program folder (uninstall its parent program): $($file.FullName)" }
                else { Remove-Prohibited $file 'hacking tool' }
                continue
            }
            if ($isProgramArea -or $inAppData) { continue }

            if ($MediaExtensions -contains $ext) {
                if ($inServedContent) { Add-Review "Media file inside web/share content. Remove it unless it is real handbook or intranet material: $($file.FullName)" }
                else { Remove-Prohibited $file 'non-work media file' }
                continue
            }
            if ($name -match 'password|passwd|credential') { Add-Review "File name suggests stored credentials: $($file.FullName)"; continue }
            if ($ReviewExtensions -contains $ext) { Add-Review "Check this file: $($file.FullName)" }
        }
    }
}

# =============================================================================
# 13. PERSISTENCE AND EXPOSURE (report only)
# =============================================================================

Write-Section 'Startup items, scheduled tasks and listening ports (report only)'
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
             'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
             'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
foreach ($key in $runKeys) {
    $item = Get-Item -Path $key -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    foreach ($valueName in $item.GetValueNames()) {
        $data = "$($item.GetValue($valueName))"
        if (Test-IsCcs "$valueName $data") { continue }
        if ($data -match 'SecurityHealth|Windows Defender|VMware|vmtoolsd|OneDrive|msedge') { continue }
        Add-Review "Startup entry ($key): $valueName = $data"
    }
}

$startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
$startupDirs += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
foreach ($dir in $startupDirs) {
    Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'desktop.ini' -and -not (Test-IsCcs $_.Name) } |
        ForEach-Object { Add-Review "Startup folder item: $($_.FullName)" }
}

try {
    Get-ScheduledTask -ErrorAction Stop |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and -not (Test-IsCcs "$($_.TaskName) $($_.TaskPath)") } |
        ForEach-Object {
            $what = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
            Add-Review "Scheduled task $($_.TaskPath)$($_.TaskName) [$($_.State)] runs: $what"
        }
}
catch { }

try {
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
        Sort-Object LocalPort -Unique |
        ForEach-Object {
            $procName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            Add-Review "Listening TCP port $($_.LocalPort) (process: $procName). 80/443 (IIS) and 445 (SMB) must stay."
        }
}
catch { }

try {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
        Where-Object { -not $_.DisplayGroup } |
        ForEach-Object { Add-Review "Custom inbound firewall allow rule: $($_.DisplayName)" }
}
catch { }

# =============================================================================
#  SUMMARY
# =============================================================================

Write-Section 'Summary'
$summary = 'Already compliant: {0}   Fixed: {1}   Would fix (audit): {2}   Failed: {3}' -f $script:Counts.OK, $script:Counts.FIXED, $script:Counts.WOULD, $script:Counts.FAIL
Write-Log 'INFO' $summary

Add-Content -Path $LogFile -Value '' -Encoding UTF8
Write-Host ''
Write-Host "REVIEW ($($script:Review.Count) items the script reports but does not decide):" -ForegroundColor Cyan
Add-Content -Path $LogFile -Value "REVIEW ($($script:Review.Count) items):" -Encoding UTF8
foreach ($r in $script:Review) {
    Write-Host "  - $r"
    Add-Content -Path $LogFile -Value "  - $r" -Encoding UTF8
}

Write-Host ''
Write-Host "MANUAL STEPS ($($script:Manual.Count)):" -ForegroundColor Yellow
Add-Content -Path $LogFile -Value "MANUAL STEPS ($($script:Manual.Count)):" -Encoding UTF8
$i = 0
foreach ($m in $script:Manual) {
    $i++
    Write-Host "  $i. $m" -ForegroundColor Yellow
    Add-Content -Path $LogFile -Value "  $i. $m" -Encoding UTF8
}

Write-Host ''
if ($script:Counts.FAIL -gt 0) {
    Write-Host "$($script:Counts.FAIL) fixes FAILED. Search the log for [FAIL]." -ForegroundColor Red
}
if (-not $AuditOnly) {
    if ((Test-Path $QuarantineDir) -and -not $DeleteProhibited) {
        Write-Host "Removed files are in $QuarantineDir. Check them, then delete that folder: prohibited media must not stay on the machine." -ForegroundColor Yellow
    }
    Write-Host 'Restart the computer to finish (LSA protection, feature removal and some policies need it).' -ForegroundColor Yellow
    Write-Host 'After the restart, open http://localhost and \\localhost\Handbook, then the CyberPatriot Scoring Report, and confirm IIS and the file share still work.' -ForegroundColor Yellow
}
Write-Host "Full log: $LogFile"
