<#
.SYNOPSIS
    Lead finder for the Windows images of a CyberPatriot scenario. Run it AFTER
    the hardening script, when points are still missing. It works on both
    Windows 11 (workstation) and Windows Server 2022 and picks the right
    profile by itself. The Debian image uses the companion script leads.sh.

.DESCRIPTION
    It collects evidence, ranks what is most likely to be an unscored check,
    makes a few safe configuration repairs, and writes one report:

      A. Already repaired  - check the scoring report two minutes later
      B. Open leads        - most likely first, each with the reason and the fix
      C. Full inventory    - the raw evidence

    Every finding gets a score from 0 to 100: an estimate that it is one of the
    missing checks. The score is higher when the README names the item, when
    the same kind of item was scored on another image of the scenario, or when
    it is a classic scored setting.

    Profiles
      Workstation (Windows 11): Remote Desktop is the critical service; no file
        share or web server is expected; README software is Chrome, Notepad++,
        LibreOffice, Thunderbird, OpenRocket and 7-Zip.
      Server (Server 2022): IIS and the Handbook share are the critical
        services; README software is Chrome, Notepad++, WinSCP and 7-Zip. The
        web site and the share are inspected (directory browsing, web shells,
        upload folders, share permissions, password files).
    For a different scenario, edit the CONFIGURATION section.

    Safe repairs made automatically (skip them with -ReportOnly):
      - local group policy values that switch protection off (inside Registry.pol)
      - Microsoft Defender exclusions and disabled Defender features
        (an exclusion for the CyberPatriot client is always kept)
      - paused or disabled Windows Update
      - hidden Action Center, and disabled protection or critical services
      - debugger hijacks on the sign-in screen accessibility tools
    Nothing is deleted, no account is changed, no service is disabled.

    Output: C:\HardeningLogs\leads-<computer>-<timestamp>.txt  (opens in Notepad)

.PARAMETER ReportOnly
    Change nothing; only write the report.

.PARAMETER Offline
    Skip the online lookup of the latest software versions.

.PARAMETER Role
    Auto (default), Workstation or Server. Auto reads the Windows edition.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Leads.ps1
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param([switch]$ReportOnly, [switch]$Offline, [ValidateSet('Auto', 'Workstation', 'Server')][string]$Role = 'Auto')

# =============================================================================
#  CONFIGURATION (from the README)
# =============================================================================
$AuthorizedAdmins = @('pparker', 'tstark', 'ppotts', 'hhogan', 'nfury', 'mhill', 'pcoulson')
$AuthorizedUsers  = @('bbanner', 'swilson', 'sstrange', 'slang', 'cdanvers', 'okoye', 'kbishop',
                      'ybelova', 'jfoster', 'nleeds', 'mjwatson', 'jtorres', 'pcarter')
$AllAuthorized    = @($AuthorizedAdmins + $AuthorizedUsers)
$BuiltInUsers     = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')

# Which image is this? ProductType 1 = workstation, 2 = domain controller, 3 = server
$Os = Get-CimInstance Win32_OperatingSystem
if ($Role -eq 'Auto') {
    $Role = 'Workstation'
    if ($Os.ProductType -ne 1) { $Role = 'Server' }
}
$IsServer           = ($Role -eq 'Server')
$IsDomainController = ($Os.ProductType -eq 2)

# Per-image facts from the READMEs
if ($IsServer) {
    $BusinessSoftware = @('Google Chrome', 'Notepad++', 'WinSCP', '7-Zip')
    $ExpectedShares   = @('Handbook')          # every other share is a lead
    $RdpIsCritical    = $false
    $IisIsCritical    = $true
    $RoleAllow        = 'WinSCP|IIS'
}
else {
    $BusinessSoftware = @('Google Chrome', 'Notepad++', 'LibreOffice', 'Mozilla Thunderbird', 'OpenRocket', '7-Zip')
    $ExpectedShares   = @()
    $RdpIsCritical    = $true
    $IisIsCritical    = $false
    $RoleAllow        = 'LibreOffice|Document Foundation|Thunderbird|Mozilla|OpenRocket'
}
if ($IsDomainController) { $ExpectedShares += @('NETLOGON', 'SYSVOL') }

$CcsPattern   = 'CCS ?Client|CCSClient|CyberPatriot'
$AllowPattern = 'Google|Chrome|Notepad\+\+|7-Zip|Microsoft|Windows|VMware|vmtoolsd|Intel|Realtek|OneDrive|SecurityHealth|' +
                'Edge|WebView|Visual C\+\+|\.NET|Java|OpenJDK|' + $RoleAllow + '|' + $CcsPattern
$ToolPattern  = 'netcat|\bnc(64)?\.exe|\bncat\b|mimikatz|hashcat|\bjohn\b|ophcrack|\bcain\b|pwdump|lazagne|' +
                '\bhydra\b|medusa|\bnmap\b|zenmap|wireshark|npcap|winpcap|ipscan|angry ?ip|anydesk|teamviewer|' +
                'vnc|radmin|ammyy|logmein|keylog|metasploit|burp ?suite|sqlmap|nikto|aircrack|ettercap|' +
                'sharphound|bloodhound|rubeus|\bhfs\b|backdoor|trojan|rockyou|wordlist|utorrent|bittorrent|' +
                'qbittorrent|tor ?browser|pinball|minesweeper|\bsteam\b|ccleaner|driver ?booster'

$MediaExt   = @('.mp3', '.mp4', '.m4a', '.m4v', '.wav', '.wma', '.wmv', '.avi', '.mkv', '.mov', '.flac',
                '.ogg', '.aac', '.mpg', '.mpeg', '.flv', '.webm', '.mid', '.midi')
$ImageExt   = @('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')
$ArchiveExt = @('.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.iso', '.cab')
$ProgramExt = @('.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.py', '.jar', '.scr', '.com', '.torrent', '.pcap', '.pcapng')
$TextExt    = @('.txt', '.csv', '.log', '.ini', '.xml', '.json', '.cfg', '.conf', '.rtf', '.md', '.htm', '.html')
# Inside a web site these are ordinary content, not leads
$WebSkipExt = @('.htm', '.html', '.js', '.css', '.config', '.aspx', '.asp', '.ashx', '.asmx', '.cshtml', '.master', '.xml',
                '.json', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.woff', '.woff2', '.ttf', '.map', '.dll', '.pdb')
$WebScriptExt  = @('.aspx', '.asp', '.ashx', '.asmx', '.cshtml', '.php', '.jsp', '.cer', '.asa')
$ShellPattern  = 'cmd\.exe|/bin/sh|Process\.Start|ProcessStartInfo|WScript\.Shell|Shell\.Application|eval\s*\(\s*Request|' +
                 'Execute\s*\(\s*Request|xp_cmdshell|powershell|shell_exec|passthru|base64_decode\s*\('
$SkipFileName = 'Forensics|README|CyberPatriot|Scoring|^desktop\.ini$|^ntuser|^Harden-|^Finish-|-Leads\.ps1$|^Thumbs\.db$|^secedit\.log$'

# =============================================================================
#  PLUMBING
# =============================================================================
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$LogDir = 'C:\HardeningLogs'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Out   = Join-Path $LogDir "leads-$($env:COMPUTERNAME)-$Stamp.txt"

$Leads = New-Object System.Collections.Generic.List[object]
$Inv   = New-Object System.Collections.Generic.List[string]
$Done  = New-Object System.Collections.Generic.List[string]

function Note {
    param([string]$Text = '')
    $Inv.Add($Text)
}
function Head {
    param([string]$Title)
    $Inv.Add('')
    $Inv.Add("===== $Title =====")
    Write-Host "Checking: $Title" -ForegroundColor Cyan
}
function Add-Lead {
    param([int]$Score, [string]$Title, [string]$Why = '', [string]$Fix = '', [switch]$Repaired)
    $Leads.Add([pscustomobject]@{ Score = $Score; Title = $Title; Why = $Why; Fix = $Fix; Repaired = [bool]$Repaired })
    $Inv.Add("  >> LEAD ($Score): $Title")
}
function Invoke-Fix {
    # Runs one repair. Returns $true when it was made.
    param([string]$What, [scriptblock]$Action)
    if ($ReportOnly) { return $false }
    try {
        $ErrorActionPreference = 'Stop'
        & $Action | Out-Null
        $Done.Add($What)
        $Inv.Add("  FIXED: $What")
        Write-Host "  FIXED: $What" -ForegroundColor Green
        return $true
    }
    catch {
        $Inv.Add("  could not fix ($What): $($_.Exception.Message)")
        return $false
    }
}
function Get-Reg {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}
function Get-ExePath {
    param([string]$Command)
    if (-not $Command) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { return $c.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($c, '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|com|scr))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}
$SigCache = @{}
function Get-Signer {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'file not found' }
    if ($SigCache.ContainsKey($Path)) { return $SigCache[$Path] }
    $result = 'UNSIGNED'
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ("$($sig.Status)" -eq 'Valid') {
            $subject = "$($sig.SignerCertificate.Subject)"
            if ($subject.Length -gt 60) { $subject = $subject.Substring(0, 60) }
            $result = "signed [$subject]"
        }
        elseif ("$($sig.Status)" -ne 'NotSigned') { $result = "SIGNATURE $($sig.Status)" }
    }
    catch { $result = 'unreadable' }
    $SigCache[$Path] = $result
    return $result
}
function Test-OddPath {
    # True for locations where installed software does not normally live.
    param([string]$Path)
    return ($Path -match '\\Users\\|\\ProgramData\\|\\Temp\\|\\Windows\\Tasks\\|\\Recycle|^[A-Za-z]:\\[^\\]+$')
}
function Get-Members {
    param([string]$Group)
    try { return @(Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch { }
    $lines = @(& net.exe localgroup $Group 2>$null)
    $start = -1
    for ($k = 0; $k -lt $lines.Count; $k++) { if ($lines[$k] -match '^-{5,}') { $start = $k + 1 } }
    if ($start -lt 0 -or $start -ge $lines.Count) { return @() }
    return @($lines[$start..($lines.Count - 1)] | Where-Object { $_ -and $_ -notmatch 'command completed' } |
             ForEach-Object { ($_.Trim() -split '\\')[-1] })
}
function Get-FileVer {
    # Numeric file version (a.b.c.d); empty when the file has none.
    param($File)
    $v = $File.VersionInfo
    if (-not $v -or ($v.FileMajorPart + $v.FileMinorPart + $v.FileBuildPart + $v.FilePrivatePart) -eq 0) { return '' }
    return "$($v.FileMajorPart).$($v.FileMinorPart).$($v.FileBuildPart).$($v.FilePrivatePart)"
}
function Get-VersionParts {
    param([string]$Text)
    $m = [regex]::Match("$Text", '\d+(\.\d+)*')
    if (-not $m.Success) { return @() }
    return @($m.Value -split '\.' | ForEach-Object { [long]$_ })
}
function Test-Older {
    # True when $Have is an older version than $Latest (compared over the parts $Latest has).
    param([string]$Have, [string]$Latest)
    $a = @(Get-VersionParts $Have)
    $b = @(Get-VersionParts $Latest)
    if ($a.Count -eq 0 -or $b.Count -eq 0) { return $false }
    for ($k = 0; $k -lt $b.Count; $k++) {
        $x = 0
        if ($k -lt $a.Count) { $x = $a[$k] }
        if ($x -lt $b[$k]) { return $true }
        if ($x -gt $b[$k]) { return $false }
    }
    return $false
}

Write-Host ''
Write-Host "Lead finder: $($Os.Caption) detected, using the $Role profile." -ForegroundColor White
Write-Host 'This takes a few minutes. Do not close the window.' -ForegroundColor White
if ($ReportOnly) { Write-Host 'Report-only mode: nothing will be changed.' -ForegroundColor Yellow }

# =============================================================================
#  1. LOCAL GROUP POLICY FILES (they override the registry on every refresh)
# =============================================================================
function Read-Pol {
    param([byte[]]$Bytes)
    $entries = New-Object System.Collections.Generic.List[object]
    $n = $Bytes.Length
    $i = 8                                              # skip the "PReg" signature and version
    while ($i -lt $n - 1) {
        if ([BitConverter]::ToUInt16($Bytes, $i) -ne 0x5B) { $i += 2; continue }     # '['
        $entryStart = $i
        $i += 2
        $s = $i
        while ($i -lt $n - 1 -and [BitConverter]::ToUInt16($Bytes, $i) -ne 0) { $i += 2 }
        $key = [Text.Encoding]::Unicode.GetString($Bytes, $s, $i - $s)
        $i += 4                                         # null + ';'
        $s = $i
        while ($i -lt $n - 1 -and [BitConverter]::ToUInt16($Bytes, $i) -ne 0) { $i += 2 }
        if ($i -ge $n - 1) { break }
        $name = [Text.Encoding]::Unicode.GetString($Bytes, $s, $i - $s)
        $i += 4                                         # null + ';'
        if ($i + 12 -gt $n) { break }
        $type = [BitConverter]::ToUInt32($Bytes, $i)
        $i += 6                                         # type + ';'
        $size = [int][BitConverter]::ToUInt32($Bytes, $i)
        $i += 6                                         # size + ';'
        $dataOffset = $i
        if ($dataOffset + $size + 2 -gt $n) { break }
        $number = $null
        $shown  = "($size bytes)"
        if ($type -eq 4 -and $size -eq 4) { $number = [long][BitConverter]::ToUInt32($Bytes, $dataOffset); $shown = "$number" }
        elseif ($type -eq 1 -or $type -eq 2) { $shown = [Text.Encoding]::Unicode.GetString($Bytes, $dataOffset, $size).TrimEnd([char]0) }
        $i += $size + 2                                 # data + ']'
        $entries.Add([pscustomobject]@{ Key = $key; Name = $name; Type = $type; Size = $size; DataOffset = $dataOffset
                                        Start = $entryStart; End = $i; Number = $number; Shown = $shown })
    }
    return $entries.ToArray()
}

# Policy values that switch protection off. Bad: nonzero | zero | any.  Set: a number, or 'delete'.
$PolRules = @(
    @{ Key = 'WindowsUpdate\\AU$';  Name = '^NoAutoUpdate$'; Bad = 'nonzero'; Set = 0; Score = 90
       Text = 'automatic updates are turned off by policy (this exact override was on the Server image)' }
    @{ Key = 'WindowsUpdate$';      Name = '^(DisableWindowsUpdateAccess|SetDisableUXWUAccess)$'; Bad = 'nonzero'; Set = 0; Score = 80
       Text = 'access to Windows Update is blocked by policy' }
    @{ Key = 'Windows Defender$';   Name = '^(DisableAntiSpyware|DisableAntiVirus)$'; Bad = 'nonzero'; Set = 0; Score = 90
       Text = 'Microsoft Defender is turned off by policy' }
    @{ Key = 'Windows Defender\\Real-Time Protection$'; Name = '^Disable'; Bad = 'nonzero'; Set = 0; Score = 90
       Text = 'a Defender real-time protection feature is turned off by policy' }
    @{ Key = 'Windows Defender\\Exclusions'; Name = '.'; Bad = 'any'; Set = 'delete'; Score = 88
       Text = 'a Defender exclusion is set by policy (Defender exclusions were scored on the Server image)' }
    @{ Key = 'WindowsFirewall\\\w+Profile$'; Name = '^EnableFirewall$'; Bad = 'zero'; Set = 1; Score = 75
       Text = 'a firewall profile is turned off by policy' }
    @{ Key = 'Terminal Services$';  Name = '^fDenyTSConnections$'; Bad = 'nonzero'; Set = 0; Score = 85; Role = 'Workstation'
       Text = 'Remote Desktop, the critical service, is blocked by policy' }
    @{ Key = 'Terminal Services$';  Name = '^UserAuthentication$'; Bad = 'zero'; Set = 1; Score = 40
       Text = 'RDP network level authentication is turned off by policy' }
    @{ Key = 'Windows\\System$';    Name = '^EnableSmartScreen$'; Bad = 'zero'; Set = 1; Score = 60
       Text = 'SmartScreen is turned off by policy' }
    @{ Key = 'Explorer$';           Name = '^(HideSCAHealth|DisableNotificationCenter)$'; Bad = 'nonzero'; Set = 0; Score = 88
       Text = 'Action Center is hidden by policy (the Windows 11 README requires Action Center to be enabled)' }
    @{ Key = 'Windows Defender Security Center\\Notifications$'; Name = '^Disable'; Bad = 'nonzero'; Set = 0; Score = 80
       Text = 'security notifications are turned off by policy (the Windows 11 README requires Action Center monitoring)' }
    @{ Key = 'Policies\\System$';   Name = '^EnableLUA$'; Bad = 'zero'; Set = 1; Score = 80
       Text = 'User Account Control is turned off by policy' }
)

function Repair-Pol {
    param([string]$File, [string]$Hive, [string]$Label)
    if (-not (Test-Path -LiteralPath $File)) { Note "No $Label Registry.pol file: no local group policy of that kind is set."; return }
    try {
        $bytes   = [IO.File]::ReadAllBytes($File)
        $entries = @(Read-Pol $bytes)
        $changed = $false
        $remove  = @()
        foreach ($e in $entries) {
            Note "  $($e.Key) \ $($e.Name) = $($e.Shown)"
            if ($e.Name.StartsWith('**') -or "$($e.Name) $($e.Shown)" -match $CcsPattern) { continue }
            foreach ($rule in $PolRules) {
                if ($rule.Role -and $rule.Role -ne $Role) { continue }
                if ($e.Key -notmatch $rule.Key -or $e.Name -notmatch $rule.Name) { continue }
                $bad = $false
                if ($rule.Bad -eq 'any') { $bad = $true }
                elseif ($null -ne $e.Number) {
                    if ($rule.Bad -eq 'nonzero' -and $e.Number -ne 0) { $bad = $true }
                    if ($rule.Bad -eq 'zero' -and $e.Number -eq 0) { $bad = $true }
                }
                if (-not $bad) { continue }
                $title   = "$Label group policy: $($e.Key) \ $($e.Name) = $($e.Shown)"
                $regPath = "$Hive\$($e.Key)"
                $fixed   = $false
                if ("$($rule.Set)" -eq 'delete') {
                    if (-not $ReportOnly) {
                        $remove += $e
                        Remove-ItemProperty -Path $regPath -Name $e.Name -ErrorAction SilentlyContinue
                        $fixed = $true
                    }
                }
                elseif (-not $ReportOnly) {
                    $target = [BitConverter]::GetBytes([uint32]$rule.Set)
                    foreach ($k in 0..3) { $bytes[$e.DataOffset + $k] = $target[$k] }
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    New-ItemProperty -Path $regPath -Name $e.Name -Value ([int]$rule.Set) -PropertyType DWord -Force | Out-Null
                    $fixed = $true
                }
                if ($fixed) { $changed = $true; $Done.Add("$title -> corrected inside Registry.pol") }
                Add-Lead -Score $rule.Score -Title $title -Why $rule.Text -Repaired:$fixed `
                         -Fix 'gpedit.msc > find the setting under Administrative Templates and set it to Not Configured, then run: gpupdate /force'
                break
            }
        }
        if ($changed) {
            Copy-Item -LiteralPath $File -Destination (Join-Path $LogDir "Registry.pol-$Label-before-$Stamp.bak") -Force
            if ($remove.Count -gt 0) {
                $stream = New-Object IO.MemoryStream
                $pos = 0
                foreach ($r in @($remove | Sort-Object Start)) {
                    $stream.Write($bytes, $pos, $r.Start - $pos)
                    $pos = $r.End
                }
                $stream.Write($bytes, $pos, $bytes.Length - $pos)
                $bytes = $stream.ToArray()
            }
            [IO.File]::WriteAllBytes($File, $bytes)
            Note "  FIXED: $Label Registry.pol rewritten (original saved in $LogDir)"
            $script:PolChanged = $true
        }
    }
    catch { Note "Could not read $File : $($_.Exception.Message)" }
}

Head 'Local group policy values'
$script:PolChanged = $false
Repair-Pol -File (Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Registry.pol') -Hive 'HKLM:' -Label 'machine'
Repair-Pol -File (Join-Path $env:SystemRoot 'System32\GroupPolicy\User\Registry.pol')    -Hive 'HKCU:' -Label 'user'
if ($script:PolChanged) {
    Write-Host '  running gpupdate /force ...'
    & gpupdate.exe /force | Out-Null
}

# =============================================================================
#  2. MICROSOFT DEFENDER
# =============================================================================
Head 'Microsoft Defender'
$pref = $null
try { $pref = Get-MpPreference -ErrorAction Stop } catch { Note "Get-MpPreference failed: $($_.Exception.Message)"; Add-Lead 85 'Microsoft Defender cannot be queried' 'the antivirus may be disabled or removed' 'Windows Security > Virus & threat protection: turn everything on' }
if ($pref) {
    $kinds = @{ ExclusionPath = 'folder/file'; ExclusionExtension = 'extension'; ExclusionProcess = 'process'; ExclusionIpAddress = 'IP address' }
    foreach ($kind in $kinds.Keys) {
        foreach ($item in @($pref.$kind)) {
            if (-not $item) { continue }
            if ("$item" -match $CcsPattern) { Note "Defender exclusion for the CyberPatriot client kept: $item  (the README asks for it)"; continue }
            $what  = "Defender exclusion ($($kinds[$kind])): $item"
            $fixed = Invoke-Fix "removed $what" {
                $arguments = @{ $kind = $item }
                Remove-MpPreference @arguments
            }
            Add-Lead -Score 90 -Title $what -Repaired:$fixed -Why 'Defender exclusions were a scored check on the Server image of this scenario; an excluded folder is also where prohibited tools hide' `
                     -Fix 'Windows Security > Virus & threat protection > Manage settings > Exclusions > remove it. Then look inside that folder.'
            if ($kind -eq 'ExclusionPath' -and (Test-Path -LiteralPath $item -PathType Container)) {
                foreach ($f in @(Get-ChildItem -LiteralPath $item -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 40)) { Note "      inside excluded folder: $($f.FullName)" }
            }
        }
    }
    $switches = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning',
                  'DisableBlockAtFirstSeen', 'DisableArchiveScanning', 'DisableRemovableDriveScanning', 'DisableEmailScanning')
    foreach ($name in $switches) {
        if ($pref.$name -eq $true) {
            $fixed = Invoke-Fix "Defender: $name set back to off" {
                $arguments = @{ $name = $false }
                Set-MpPreference @arguments
            }
            $score = 60
            if ($name -match 'Realtime|Behavior|IOAV') { $score = 88 }
            Add-Lead -Score $score -Title "Defender protection feature is switched off: $name" -Repaired:$fixed -Why 'antivirus protection is a standard scored item' `
                     -Fix 'Windows Security > Virus & threat protection > Manage settings: turn every switch on'
        }
    }
    Note "MAPSReporting=$($pref.MAPSReporting)  SubmitSamplesConsent=$($pref.SubmitSamplesConsent)  PUAProtection=$($pref.PUAProtection)  EnableNetworkProtection=$($pref.EnableNetworkProtection)"
    if ("$($pref.MAPSReporting)" -eq '0') {
        $fixed = Invoke-Fix 'Defender cloud-delivered protection turned on' { Set-MpPreference -MAPSReporting Advanced }
        Add-Lead -Score 45 -Title 'Defender cloud-delivered protection is off' -Repaired:$fixed -Fix 'Windows Security > Virus & threat protection > Manage settings > Cloud-delivered protection: On'
    }
    foreach ($default in 'LowThreatDefaultAction', 'ModerateThreatDefaultAction', 'HighThreatDefaultAction', 'SevereThreatDefaultAction') {
        if ("$($pref.$default)" -match '^(6|9|Allow|NoAction)$') {
            Add-Lead 70 "Defender is set to ignore threats: $default = $($pref.$default)" 'threats of that level are allowed to run' "Set-MpPreference -$default Quarantine"
        }
    }
}
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    Note "AntivirusEnabled=$($status.AntivirusEnabled)  RealTimeProtectionEnabled=$($status.RealTimeProtectionEnabled)  TamperProtected=$($status.IsTamperProtected)  signature age (days)=$($status.AntivirusSignatureAge)"
    if (-not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled) {
        Add-Lead 88 'Microsoft Defender real-time protection is not running' 'antivirus protection is a standard scored item' 'Windows Security > Virus & threat protection > Manage settings > Real-time protection: On'
    }
    if ($status.AntivirusSignatureAge -gt 7) { Add-Lead 45 "Defender definitions are $($status.AntivirusSignatureAge) days old" '' 'Update-MpSignature' }
}
catch { Note "Get-MpComputerStatus failed: $($_.Exception.Message)" }
try {
    foreach ($threat in @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 30)) {
        foreach ($res in @($threat.Resources)) {
            $path = "$res" -replace '^[a-z]+:_?', ''
            $exists = Test-Path -LiteralPath $path -ErrorAction SilentlyContinue
            Note "Detection history: $res  (still on disk: $exists)"
            if ($exists) { Add-Lead 80 "File flagged by Defender is still on disk: $path" 'Defender detected it but it was not removed' "Remove-Item -LiteralPath '$path' -Force" }
        }
    }
}
catch { }

# =============================================================================
#  3. WINDOWS UPDATE
# =============================================================================
Head 'Windows Update'
$auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$noAuto = Get-Reg $auKey 'NoAutoUpdate'
$auOpt  = Get-Reg $auKey 'AUOptions'
Note "Policy registry: NoAutoUpdate=$noAuto  AUOptions=$auOpt   (blank or 0, and blank/3/4 = automatic updates on)"
if (($null -ne $noAuto -and $noAuto -ne 0) -or $auOpt -eq 2) {
    $fixed = Invoke-Fix 'Automatic updates policy set to on (NoAutoUpdate=0, AUOptions=4)' {
        if (-not (Test-Path $auKey)) { New-Item -Path $auKey -Force | Out-Null }
        New-ItemProperty -Path $auKey -Name NoAutoUpdate -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $auKey -Name AUOptions -Value 4 -PropertyType DWord -Force | Out-Null
    }
    Add-Lead -Score 88 -Title "Automatic updates are disabled in the registry (NoAutoUpdate=$noAuto AUOptions=$auOpt)" -Repaired:$fixed `
             -Why 'automatic updates is a standard scored item and was switched off this way on both Windows practice images' `
             -Fix 'gpedit.msc > Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates: Enabled, option 4. Then: gpupdate /force'
}
$uxKey = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$ux = Get-ItemProperty -Path $uxKey -ErrorAction SilentlyContinue
if ($ux) {
    $pauseNames = @($ux.PSObject.Properties | Where-Object { $_.Name -match '^Pause' -and "$($_.Value)" } | ForEach-Object { $_.Name })
    foreach ($name in $pauseNames) { Note "Pause value: $name = $($ux.$name)" }
    if ($pauseNames.Count -gt 0) {
        $fixed = Invoke-Fix 'Windows Update pause removed' { foreach ($name in $pauseNames) { Remove-ItemProperty -Path $uxKey -Name $name -Force } }
        Add-Lead -Score 75 -Title 'Windows Update is paused' -Repaired:$fixed -Why 'updates cannot install while paused' -Fix 'Settings > Windows Update > Resume updates'
    }
}
try {
    $latestFix = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn | Select-Object -Last 1
    if ($latestFix) { Note "Most recent installed update: $($latestFix.HotFixID) on $($latestFix.InstalledOn)" }
}
catch { }

# Services that protection depends on must not be disabled
$needed = @{ wuauserv = 'Manual'; UsoSvc = 'Automatic'; BITS = 'Manual'; WinDefend = 'Automatic'; mpssvc = 'Automatic'
             EventLog = 'Automatic'; wscsvc = 'Automatic'; SecurityHealthService = 'Manual'; TermService = 'Manual'
             Schedule = 'Automatic'; CryptSvc = 'Automatic' }
$needText = @{ wuauserv = 'Windows Update'; UsoSvc = 'Update Orchestrator'; BITS = 'Background Intelligent Transfer (update downloads)'
               WinDefend = 'Microsoft Defender Antivirus'; mpssvc = 'Windows Defender Firewall'; EventLog = 'Windows Event Log'
               wscsvc = 'Security Center (Action Center monitoring, required by the README)'; SecurityHealthService = 'Windows Security'
               TermService = 'Remote Desktop Services (the critical service)'; Schedule = 'Task Scheduler'; CryptSvc = 'Cryptographic Services' }
if (-not $RdpIsCritical) { $needed.Remove('TermService') }
if ($IisIsCritical) {
    $needed['W3SVC'] = 'Automatic';        $needText['W3SVC'] = 'IIS web server (critical service)'
    $needed['LanmanServer'] = 'Automatic'; $needText['LanmanServer'] = 'Server service that publishes the file share (critical service)'
}
foreach ($name in @($needed.Keys)) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
    if (-not $svc) { Note "Service $name : not present"; continue }
    Note "Service $name : $($svc.State), start mode $($svc.StartMode)"
    if ("$($svc.StartMode)" -eq 'Disabled') {
        $startType = $needed[$name]
        $fixed = Invoke-Fix "Service $name re-enabled ($startType)" {
            Set-Service -Name $name -StartupType $startType
            if ($startType -eq 'Automatic' -or $name -eq 'TermService') { Start-Service -Name $name }
        }
        $score = 80
        if ($name -match 'wuauserv|wscsvc|TermService|WinDefend|W3SVC|LanmanServer') { $score = 88 }
        Add-Lead -Score $score -Title "Service '$name' ($($needText[$name])) is DISABLED" -Repaired:$fixed -Why 'a disabled protection service is a classic scored item' `
                 -Fix "Set-Service -Name $name -StartupType $startType ; Start-Service -Name $name"
    }
}

# =============================================================================
#  4. ACTION CENTER (the README requires it)
# =============================================================================
Head 'Action Center / Security Center'
$acValues = @(
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'HideSCAHealth' }
    @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'HideSCAHealth' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'DisableNotificationCenter' }
    @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = 'DisableNotificationCenter' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'; Name = 'DisableNotifications' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications'; Name = 'DisableEnhancedNotifications' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications'; Name = 'DisableNotifications' }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications'; Name = 'DisableEnhancedNotifications' }
    @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name = 'NoToastApplicationNotification' }
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name = 'NoToastApplicationNotification' }
)
foreach ($v in $acValues) {
    $value = Get-Reg $v.Path $v.Name
    if ($null -eq $value) { continue }
    Note "$($v.Path) \ $($v.Name) = $value"
    if ($value -ne 0) {
        $path = $v.Path
        $name = $v.Name
        $fixed = Invoke-Fix "Action Center: $name cleared ($path)" { Set-ItemProperty -Path $path -Name $name -Value 0 -Type DWord }
        Add-Lead -Score 86 -Title "Action Center / security notifications are switched off: $name" -Repaired:$fixed `
                 -Why 'the Windows 11 README says Action Center must be enabled and monitoring' `
                 -Fix 'Settings > System > Notifications: On. Windows Security > Settings > Manage notifications: all on.'
    }
}
$toastKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'
$toast = Get-Reg $toastKey 'ToastEnabled'
Note "ToastEnabled = $toast   (blank or 1 = notifications on)"
if ($null -ne $toast -and $toast -eq 0) {
    $fixed = Invoke-Fix 'Notifications turned back on (ToastEnabled=1)' { Set-ItemProperty -Path $toastKey -Name ToastEnabled -Value 1 -Type DWord }
    Add-Lead -Score 78 -Title 'Notifications are switched off for this user (Action Center shows nothing)' -Repaired:$fixed `
             -Why 'the Windows 11 README says Action Center must be enabled and monitoring' -Fix 'Settings > System > Notifications: On'
}
foreach ($feature in 'AntiVirusDisableNotify', 'FirewallDisableNotify', 'UpdatesDisableNotify', 'AntiSpywareDisableNotify', 'UacDisableNotify') {
    $value = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Security Center' $feature
    if ($null -ne $value -and $value -ne 0) {
        $fixed = Invoke-Fix "Security Center: $feature cleared" { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Security Center' -Name $feature -Value 0 -Type DWord }
        Add-Lead -Score 80 -Title "Security Center monitoring is switched off: $feature = $value" -Repaired:$fixed -Why 'the Windows 11 README requires Action Center monitoring' -Fix 'Control Panel > Security and Maintenance > Change Security and Maintenance settings: tick every box'
    }
}

# =============================================================================
#  5. BUSINESS SOFTWARE (README: latest stable Chrome; the rest kept up to date)
# =============================================================================
Head 'Business software versions'
$uninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
$Installed = @(Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })

$Apps = @(
    @{ Label = 'Google Chrome'; Match = '^Google Chrome'; Exe = 'chrome.exe'; Page = 'https://www.google.com/chrome/'
       Latest = { (Invoke-RestMethod 'https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions?page_size=1' -TimeoutSec 20).versions[0].version } }
    @{ Label = 'Notepad++'; Match = '^Notepad\+\+'; Exe = 'notepad++.exe'; Page = 'https://notepad-plus-plus.org/downloads/'
       Latest = { (Invoke-RestMethod 'https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest' -TimeoutSec 20).tag_name } }
    @{ Label = 'LibreOffice'; Match = '^LibreOffice'; Exe = 'soffice.bin'; Page = 'https://www.libreoffice.org/download/'
       Latest = {
           $html = (Invoke-WebRequest 'https://download.documentfoundation.org/libreoffice/stable/' -UseBasicParsing -TimeoutSec 20).Content
           $all = @([regex]::Matches($html, 'href="(\d+\.\d+\.\d+)/"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object { [version]$_ } -Unique)
           $all[-1]
       } }
    @{ Label = 'Mozilla Thunderbird'; Match = 'Thunderbird'; Exe = 'thunderbird.exe'; Page = 'https://www.thunderbird.net/'
       Latest = { (Invoke-RestMethod 'https://product-details.mozilla.org/1.0/thunderbird_versions.json' -TimeoutSec 20).LATEST_THUNDERBIRD_VERSION } }
    @{ Label = 'OpenRocket'; Match = '^OpenRocket'; Exe = 'OpenRocket.exe'; NoFileVersion = $true; Page = 'https://openrocket.info/downloads.html'
       Latest = { (Invoke-RestMethod 'https://api.github.com/repos/openrocket/openrocket/releases/latest' -TimeoutSec 20).tag_name } }
    @{ Label = 'WinSCP'; Match = '^WinSCP'; Exe = 'WinSCP.exe'; Page = 'https://winscp.net/eng/download.php'
       Latest = {
           $html = (Invoke-WebRequest 'https://winscp.net/eng/downloads.php' -UseBasicParsing -TimeoutSec 20).Content
           $all = @([regex]::Matches($html, 'WinSCP-(\d+\.\d+(\.\d+)?)-Setup\.exe') | ForEach-Object { $_.Groups[1].Value } | Sort-Object { [version]$_ } -Unique)
           if ($all.Count -gt 0) { $all[-1] }
       } }
    @{ Label = '7-Zip'; Match = '^7-Zip'; Exe = '7zFM.exe'; Page = 'https://www.7-zip.org/download.html'
       Latest = {
           $html = (Invoke-WebRequest 'https://www.7-zip.org/download.html' -UseBasicParsing -TimeoutSec 20).Content
           $all = @([regex]::Matches($html, '7z(\d{2})(\d{2})-x64\.exe') | ForEach-Object { "$($_.Groups[1].Value).$($_.Groups[2].Value)" } | Sort-Object { [version]$_ } -Unique)
           if ($all.Count -gt 0) { $all[-1] }
       } }
)

$Apps = @($Apps | Where-Object { $BusinessSoftware -contains $_.Label })

# One pass over the program folders to find every copy of each program
$exeNames = @($Apps | ForEach-Object { $_.Exe })
$copies = @()
$searchRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) + @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local' })
foreach ($root in $searchRoots) {
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
    $copies += @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $exeNames -contains $_.Name })
}

foreach ($app in $Apps) {
    $entries = @($Installed | Where-Object { $_.DisplayName -match $app.Match })
    $files   = @($copies | Where-Object { $_.Name -eq $app.Exe })
    $latest  = ''
    if (-not $Offline) {
        try { $latest = "$(& $app.Latest)" } catch { Note "$($app.Label): could not look up the latest version ($($_.Exception.Message))" }
    }
    Note "$($app.Label)   latest published: $latest"
    foreach ($entry in $entries) { Note "    installed entry: $($entry.DisplayName)  version $($entry.DisplayVersion)" }
    foreach ($file in $files)    { Note "    file: $($file.FullName)  version $(Get-FileVer $file)  (product version text: $($file.VersionInfo.ProductVersion))" }

    if ($entries.Count -eq 0 -and $files.Count -eq 0) {
        Add-Lead 82 "$($app.Label) is NOT installed" 'the README says it must remain installed and up to date' "Install the x86_64 version from $($app.Page)"
        continue
    }
    $versions = @($entries | ForEach-Object { "$($_.DisplayVersion)" } | Where-Object { $_ })
    if (-not $app.NoFileVersion) { $versions += @($files | ForEach-Object { Get-FileVer $_ } | Where-Object { $_ }) }
    if ($versions.Count -eq 0) {
        Add-Lead 55 "$($app.Label): could not read the installed version (latest is '$latest')" 'software updates are scored on these images (two were scored on the Server image)' "Open the program > Help > About, and compare with $($app.Page)"
        continue
    }
    if ($latest) {
        $old = @($versions | Where-Object { Test-Older $_ $latest } | Select-Object -Unique)
        if ($old.Count -gt 0) {
            Add-Lead 90 "$($app.Label) is out of date: found version(s) $($old -join ', '), latest is $latest" `
                     'the README requires it up to date; software updates are scored on these images (two were scored on the Server image)' `
                     "Download the x86_64 installer from $($app.Page) and run it. Remove any old copy listed in the inventory section."
        }
    }
    else {
        Add-Lead 55 "$($app.Label): installed version(s) $(@($versions | Select-Object -Unique) -join ', ') - latest version unknown (no internet lookup)" `
                 'software updates are scored on these images (two were scored on the Server image)' "Compare with $($app.Page)"
    }
    $entryVersions = @($entries | ForEach-Object { "$($_.DisplayName) [$($_.DisplayVersion)]" } | Select-Object -Unique)
    if ($entryVersions.Count -gt 1) {
        Add-Lead 86 "$($app.Label) is registered twice: $($entryVersions -join '  and  ')" `
                 'the old version is still listed as installed, so a version check can keep failing even though the new one is there' `
                 'Settings > Apps > Installed apps: uninstall the OLDER entry, then run the new installer again if the program stops opening'
    }
    $folders = @($files | ForEach-Object { $_.DirectoryName } | Select-Object -Unique)
    if ($folders.Count -gt 1) {
        Add-Lead 78 "$($app.Label) exists in more than one place: $($folders -join ' | ')" `
                 'the scoring engine reads the version of one specific file; an old leftover copy (often the 32-bit one) keeps the check failing' `
                 'Uninstall the old copy from Settings > Apps > Installed apps, keep the 64-bit one in C:\Program Files'
    }
    if (@($files | Where-Object { $_.FullName -match '\\Program Files \(x86\)\\|\\AppData\\' }).Count -gt 0 -and
        @($files | Where-Object { $_.FullName -match '\\Program Files\\' }).Count -eq 0) {
        Add-Lead 60 "$($app.Label) is only installed as a 32-bit or per-user copy" 'the README recommends the x86_64 version' "Install the 64-bit version from $($app.Page)"
    }
}

$progId = Get-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' 'ProgId'
Note "Default browser for $($env:USERNAME): $progId"
if ("$progId" -notmatch 'Chrome') {
    Add-Lead 62 "Default web browser is not Google Chrome (currently '$progId')" 'the README says the default browser for all users should be Chrome' `
             'Settings > Apps > Default apps > Google Chrome > Set default'
}
$chromePolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue
if ($chromePolicy) {
    foreach ($p in @($chromePolicy.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) { Note "Chrome policy: $($p.Name) = $($p.Value)" }
}

# =============================================================================
#  6. ACCOUNTS AND GROUPS
# =============================================================================
Head 'Accounts'
$localUsers = @()
try { $localUsers = @(Get-LocalUser -ErrorAction Stop) }
catch { Note "Local accounts cannot be listed on this machine ($($_.Exception.Message)). On a domain controller use: Get-ADUser -Filter *" }
foreach ($u in $localUsers) {
    $name = $u.Name
    $required = $true
    try { $required = [bool]$u.PasswordRequired } catch { }
    Note "$name  enabled=$($u.Enabled)  pwdRequired=$required  pwdLastSet=$($u.PasswordLastSet)  pwdExpires=$($u.PasswordExpires)  mayChangePwd=$($u.UserMayChangePassword)  description='$($u.Description)'"
    if ($BuiltInUsers -contains $name) {
        if ($u.Enabled -and $name -eq 'Guest') { Add-Lead 82 'The Guest account is enabled' 'classic scored item' 'net user Guest /active:no' }
        if ($u.Enabled -and $name -eq 'Administrator') { Add-Lead 62 'The built-in Administrator account is enabled' 'classic scored item' 'net user Administrator /active:no' }
        continue
    }
    if ($AllAuthorized -notcontains $name) {
        Add-Lead 90 "Account '$name' is not on the README list" 'unauthorized users are scored on every image' "net user $name /delete"
        continue
    }
    if (-not $u.Enabled) { Add-Lead 55 "Authorized account '$name' is disabled" 'authorized users must be able to sign in' "net user $name /active:yes" }
    if ($name -eq $env:USERNAME) { continue }
    if (-not $required) {
        Add-Lead 82 "Account '$name' does not require a password" 'the README says all accounts must be password protected' "net user $name /passwordreq:yes"
    }
    $mustChange = $false
    try { $mustChange = ([int]([ADSI]"WinNT://./$name,user").PasswordExpired.Value -eq 1) } catch { }
    if ($mustChange) { Note "    '$name' must change password at next sign-in (that is why no password date is shown; not a lead)"; continue }
    if ($u.Enabled -and -not $u.PasswordLastSet) {
        Add-Lead 78 "Account '$name' has never had a password set (probably blank)" 'the README says all accounts must be password protected' "net user $name *"
    }
    if ($u.Enabled -and $u.PasswordLastSet -and -not $u.PasswordExpires) {
        Add-Lead 55 "Account '$name' has a password that never expires" 'classic scored item' "Set-LocalUser -Name $name -PasswordNeverExpires 0"
    }
    if (-not $u.UserMayChangePassword) {
        Add-Lead 40 "Account '$name' is not allowed to change its password" '' "net user $name /passwordchg:yes"
    }
    if ("$($u.Description)" -match 'pass|pw|login|cred') {
        Add-Lead 70 "Account '$name' has a suspicious description: '$($u.Description)'" 'a password stored in the description field' "Set-LocalUser -Name $name -Description ''"
    }
}
foreach ($name in $AllAuthorized) {
    if ($localUsers.Count -gt 0 -and @($localUsers | Where-Object { $_.Name -eq $name }).Count -eq 0) {
        Add-Lead 68 "Authorized account '$name' does not exist" 'the README lists it; a missing authorized user can be a scored item' "net user $name * /add"
    }
}

Note ''
foreach ($g in @(Get-LocalGroup -ErrorAction SilentlyContinue)) {
    $members = @(Get-Members $g.Name)
    if ($members.Count -eq 0) { continue }
    Note "Group '$($g.Name)': $($members -join ', ')"
    $sid = "$($g.SID)"
    if ($sid -eq 'S-1-5-32-544') {
        foreach ($m in $members) {
            if ($m -ne 'Administrator' -and $AuthorizedAdmins -notcontains $m) {
                Add-Lead 90 "'$m' is in the Administrators group but is not an authorized administrator" 'extra administrators are scored on every image' "net localgroup Administrators $m /delete"
            }
        }
        foreach ($a in $AuthorizedAdmins) {
            if ($members -notcontains $a) { Add-Lead 68 "Authorized administrator '$a' is not in the Administrators group" '' "net localgroup Administrators $a /add" }
        }
    }
    elseif ($sid -eq 'S-1-5-32-555') {
        foreach ($m in $members) {
            if ($AllAuthorized -notcontains $m) { Add-Lead 80 "'$m' may sign in through Remote Desktop but is not an authorized user" 'only authorized users should be able to sign in remotely' "net localgroup `"Remote Desktop Users`" $m /delete" }
        }
    }
    elseif (@('S-1-5-32-547', 'S-1-5-32-551', 'S-1-5-32-552', 'S-1-5-32-556', 'S-1-5-32-562', 'S-1-5-32-569', 'S-1-5-32-573',
              'S-1-5-32-578', 'S-1-5-32-579', 'S-1-5-32-580', 'S-1-5-32-558', 'S-1-5-32-559') -contains $sid) {
        Add-Lead 62 "Privileged group '$($g.Name)' has members: $($members -join ', ')" 'these groups are normally empty on a workstation' "net localgroup `"$($g.Name)`" NAME /delete"
    }
    elseif ($sid -notmatch '^S-1-5-32-') {
        Note "    (custom group)"
    }
}

# =============================================================================
#  7. SECURITY POLICY, USER RIGHTS, AUDITING, SECURITY OPTIONS
# =============================================================================
Head 'Security policy'
$cfg = Join-Path $env:TEMP "leads-secpol-$Stamp.inf"
& secedit.exe /export /cfg $cfg /areas SECURITYPOLICY USER_RIGHTS | Out-Null
$policy = @{}
if (Test-Path $cfg) {
    foreach ($line in Get-Content -LiteralPath $cfg) {
        if ($line -match '^\s*([^=\[]+?)\s*=\s*(.*)$') { $policy[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    Remove-Item -LiteralPath $cfg -Force -ErrorAction SilentlyContinue
}
function Get-PolicyNumber {
    param([string]$Name)
    if ($policy.ContainsKey($Name) -and "$($policy[$Name])" -match '^-?\d+$') { return [int]$policy[$Name] }
    return $null
}
foreach ($name in 'MinimumPasswordLength', 'PasswordComplexity', 'MaximumPasswordAge', 'MinimumPasswordAge', 'PasswordHistorySize',
                  'LockoutBadCount', 'LockoutDuration', 'ResetLockoutCount', 'ClearTextPassword', 'EnableGuestAccount', 'LSAAnonymousNameLookup') {
    Note "$name = $($policy[$name])"
}
$n = Get-PolicyNumber 'MinimumPasswordLength'
if ($null -ne $n -and $n -lt 10) { Add-Lead 72 "Minimum password length is $n" 'scored on the Server image' 'net accounts /minpwlen:14' }
$n = Get-PolicyNumber 'MaximumPasswordAge'
if ($null -ne $n -and ($n -le 0 -or $n -gt 90)) { Add-Lead 66 "Maximum password age is $n days" 'classic scored item' 'net accounts /maxpwage:90' }
$n = Get-PolicyNumber 'MinimumPasswordAge'
if ($null -ne $n -and $n -lt 1) { Add-Lead 60 'Minimum password age is 0 days' 'classic scored item' 'net accounts /minpwage:1' }
$n = Get-PolicyNumber 'PasswordHistorySize'
if ($null -ne $n -and $n -lt 5) { Add-Lead 62 "Password history remembers only $n passwords" 'classic scored item' 'net accounts /uniquepw:24' }
$n = Get-PolicyNumber 'LockoutBadCount'
if ($null -ne $n -and ($n -eq 0 -or $n -gt 10)) { Add-Lead 72 "Account lockout threshold is $n (0 = never lock)" 'classic scored item' 'net accounts /lockoutthreshold:5' }
$n = Get-PolicyNumber 'LockoutDuration'
if ($null -ne $n -and $n -ge 0 -and $n -lt 15 -and (Get-PolicyNumber 'LockoutBadCount') -gt 0) { Add-Lead 50 "Account lockout duration is only $n minutes" '' 'net accounts /lockoutduration:30 /lockoutwindow:30' }
if ((Get-PolicyNumber 'ClearTextPassword') -eq 1) { Add-Lead 72 'Passwords are stored with reversible encryption' 'classic scored item' 'secpol.msc > Account Policies > Password Policy > Store passwords using reversible encryption: Disabled' }
if ((Get-PolicyNumber 'LSAAnonymousNameLookup') -eq 1) { Add-Lead 50 'Anonymous SID/name translation is allowed' '' 'secpol.msc > Local Policies > Security Options > Network access: Allow anonymous SID/Name translation: Disabled' }

Note ''
$looseSids = @{ '*S-1-1-0' = 'Everyone'; '*S-1-5-32-546' = 'Guests'; '*S-1-5-32-545' = 'Users'; '*S-1-5-7' = 'Anonymous'; '*S-1-5-11' = 'Authenticated Users' }
$sensitive = 'SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeLoadDriverPrivilege',
             'SeRemoteShutdownPrivilege', 'SeSecurityPrivilege', 'SeCreateTokenPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeEnableDelegationPrivilege',
             'SeSystemEnvironmentPrivilege', 'SeManageVolumePrivilege', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege'
foreach ($right in @($policy.Keys | Where-Object { $_ -like 'Se*' } | Sort-Object)) {
    $holders = @($policy[$right] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Note "$right = $($holders -join ', ')"
    $loose = @($holders | Where-Object { $looseSids.ContainsKey($_) } | ForEach-Object { $looseSids[$_] })
    $named = @($holders | Where-Object { -not $_.StartsWith('*') })
    if ($right -eq 'SeNetworkLogonRight' -and $loose -contains 'Everyone') {
        Add-Lead 72 "User right 'Access this computer from the network' still includes Everyone" 'this exact item was scored on the Server image' 'secpol.msc > Local Policies > User Rights Assignment > Access this computer from the network: remove Everyone'
    }
    elseif ($right -eq 'SeRemoteInteractiveLogonRight' -and ($loose.Count -gt 0 -or $named.Count -gt 0)) {
        Add-Lead 66 "User right 'Allow log on through Remote Desktop Services' includes: $(@($loose + $named) -join ', ')" 'should be only Administrators and Remote Desktop Users' 'secpol.msc > Local Policies > User Rights Assignment > Allow log on through Remote Desktop Services'
    }
    elseif ($sensitive -contains $right) {
        $bad = @($loose | Where-Object { $_ -ne 'Authenticated Users' -or $right -notmatch 'Impersonate|CreateGlobal' }) + $named
        if ($bad.Count -gt 0) { Add-Lead 70 "Powerful user right $right is granted to: $($bad -join ', ')" 'should be Administrators or service accounts only' "secpol.msc > Local Policies > User Rights Assignment > remove them from $right" }
    }
}
foreach ($deny in 'SeDenyNetworkLogonRight', 'SeDenyRemoteInteractiveLogonRight') {
    if ("$($policy[$deny])" -notmatch 'S-1-5-32-546|Guest') { Add-Lead 42 "Guests are not denied in $deny" '' "secpol.msc > Local Policies > User Rights Assignment > add Guests to the matching 'Deny' right" }
}

Note ''
try {
    $rows = @(& auditpol.exe /get /category:* /r 2>$null | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv)
    $none = @($rows | Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' })
    Note "Audit policy: $($rows.Count) subcategories, $($none.Count) with no auditing"
    foreach ($row in $rows) { Note "    $($row.Subcategory) = $($row.'Inclusion Setting')" }
    if ($rows.Count -gt 0 -and $none.Count -gt ($rows.Count / 2)) {
        Add-Lead 66 "Auditing is off for $($none.Count) of $($rows.Count) audit subcategories" 'audit policy is a classic scored item' 'auditpol /set /category:* /success:enable /failure:enable'
    }
}
catch { Note "auditpol failed: $($_.Exception.Message)" }

Note ''
# Good: wanted value. Mode: eq | min | ne.  AbsentOk: a missing value counts as fine.
$options = @(
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'LimitBlankPasswordUse'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 74; T = 'Accounts: blank passwords may be used over the network' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'RestrictAnonymousSAM'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 56; T = 'Anonymous enumeration of SAM accounts is allowed' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'RestrictAnonymous'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 52; T = 'Anonymous enumeration of SAM accounts and shares is allowed' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'EveryoneIncludesAnonymous'; Good = 0; Mode = 'eq'; AbsentOk = $true; S = 56; T = 'Everyone permissions apply to anonymous users' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'NoLMHash'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 46; T = 'LAN Manager password hashes are stored' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'LmCompatibilityLevel'; Good = 3; Mode = 'min'; AbsentOk = $true; S = 46; T = 'Weak LAN Manager authentication level' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'EnableLUA'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 82; T = 'User Account Control is turned off' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'ConsentPromptBehaviorAdmin'; Good = 0; Mode = 'ne'; AbsentOk = $true; S = 64; T = 'UAC never prompts administrators' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'PromptOnSecureDesktop'; Good = 1; Mode = 'eq'; AbsentOk = $true; S = 46; T = 'UAC prompt does not use the secure desktop' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'DontDisplayLastUserName'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 38; T = 'The last signed-in user name is shown on the sign-in screen' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; N = 'RequireSecuritySignature'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 58; T = 'SMB server does not require signing (SMB signing was scored on the Server image)' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; N = 'RequireSecuritySignature'; Good = 1; Mode = 'eq'; AbsentOk = $false; S = 52; T = 'SMB client does not require signing' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; N = 'EnablePlainTextPassword'; Good = 0; Mode = 'eq'; AbsentOk = $true; S = 56; T = 'SMB client may send unencrypted passwords' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; N = 'SMB1'; Good = 0; Mode = 'eq'; AbsentOk = $true; S = 66; T = 'SMB version 1 server is enabled (SMB1 was scored on the Server image)' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; N = 'SecurityLayer'; Good = 2; Mode = 'min'; AbsentOk = $true; S = 46; T = 'RDP does not require TLS (security layer)' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; N = 'MinEncryptionLevel'; Good = 3; Mode = 'min'; AbsentOk = $true; S = 46; T = 'RDP encryption level is below High' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; N = 'NoDriveTypeAutoRun'; Good = 255; Mode = 'eq'; AbsentOk = $false; S = 40; T = 'AutoPlay is not disabled for all drives' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; N = 'EnableSmartScreen'; Good = 0; Mode = 'ne'; AbsentOk = $true; S = 58; T = 'SmartScreen is turned off' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; N = 'UseLogonCredential'; Good = 0; Mode = 'eq'; AbsentOk = $true; S = 48; T = 'WDigest keeps plaintext passwords in memory' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; N = 'fAllowFullControl'; Good = 0; Mode = 'eq'; AbsentOk = $true; S = 36; T = 'Remote Assistance full control is allowed' }
)
foreach ($o in $options) {
    $value = Get-Reg $o.P $o.N
    Note "$($o.N) = $value   ($($o.P))"
    $ok = $true
    if ($null -eq $value) { $ok = $o.AbsentOk }
    elseif ($o.Mode -eq 'eq')  { $ok = ($value -eq $o.Good) }
    elseif ($o.Mode -eq 'min') { $ok = ($value -ge $o.Good) }
    elseif ($o.Mode -eq 'ne')  { $ok = ($value -ne $o.Good) }
    if (-not $ok) {
        $want = "$($o.Good)"
        if ($o.Mode -eq 'ne') { $want = '1' }
        if ($o.N -eq 'ConsentPromptBehaviorAdmin') { $want = '5' }
        $regPath = $o.P -replace '^HKLM:\\', 'HKLM\'
        Add-Lead $o.S "$($o.T)  [$($o.N) = $value]" 'security option that is commonly scored' "reg add `"$regPath`" /v $($o.N) /t REG_DWORD /d $want /f"
    }
}
$autoLogon = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
Note "AutoAdminLogon = $autoLogon  (left alone: the README says not to touch the auto-login account)"
$deny = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
Note "fDenyTSConnections = $deny   (0 = Remote Desktop is on)"
if ($RdpIsCritical -and $deny -ne 0) {
    Add-Lead 85 'Remote Desktop is turned OFF but the README lists it as a critical service' 'a critical service that is down costs points' `
             'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
}
if (-not $RdpIsCritical -and $deny -eq 0) {
    Add-Lead 50 'Remote Desktop is turned on, and the README does not list it as a needed service' 'remote access that nobody asked for' `
             'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f   (skip this if you manage the machine over RDP)'
}
$term = Get-Service -Name TermService -ErrorAction SilentlyContinue
if ($RdpIsCritical -and $term -and "$($term.Status)" -ne 'Running') {
    $fixed = Invoke-Fix 'Remote Desktop Services started' { Start-Service -Name TermService }
    Add-Lead -Score 70 -Title 'Remote Desktop Services is not running' -Repaired:$fixed -Why 'RDP is the critical service' -Fix 'Start-Service TermService'
}

# =============================================================================
#  8. SERVICES
# =============================================================================
Head 'Services'
$risky = @{
    RemoteRegistry = @(76, 'Remote Registry lets other machines edit the registry'); TlntSvr = @(88, 'Telnet server')
    ftpsvc = @(88, 'FTP server'); MSFTPSVC = @(88, 'FTP server'); W3SVC = @(82, 'IIS web server on a workstation')
    IISADMIN = @(72, 'IIS admin service'); WAS = @(55, 'IIS process activation'); SNMP = @(78, 'SNMP polling service (README: no polling tools are used)')
    SNMPTRAP = @(52, 'SNMP trap service'); sshd = @(78, 'OpenSSH server (the README does not list SSH as a needed service)')
    WinRM = @(64, 'Windows Remote Management (README: no centralized maintenance tools)'); Wecsvc = @(40, 'Windows Event Collector (README: no centralized polling; it was running on both practice images and was not needed for 100 on the Server)')
    RemoteAccess = @(66, 'Routing and Remote Access'); SharedAccess = @(48, 'Internet Connection Sharing'); SSDPSRV = @(44, 'SSDP discovery')
    upnphost = @(48, 'UPnP device host'); simptcp = @(78, 'Simple TCP/IP services'); LPDSVC = @(62, 'LPD print server')
    Fax = @(36, 'Fax'); NetTcpPortSharing = @(42, 'Net.Tcp port sharing'); WMSvc = @(62, 'Web management service')
    WebClient = @(40, 'WebDAV client'); RpcLocator = @(36, 'RPC locator'); Spooler = @(26, 'Print spooler'); TapiSrv = @(30, 'Telephony')
    'PeerDistSvc' = @(40, 'BranchCache'); 'p2psvc' = @(40, 'Peer networking'); 'PNRPsvc' = @(40, 'Peer name resolution')
}
if ($IsServer) {
    foreach ($name in 'W3SVC', 'IISADMIN', 'WAS') { $risky.Remove($name) }
    $risky['WinRM']   = @(30, 'Windows Remote Management (on by default on a server; Server Manager stops working without it)')
    $risky['Spooler'] = @(55, 'Print Spooler on a server that is not a print server')
}
foreach ($svc in @(Get-CimInstance Win32_Service | Sort-Object Name)) {
    if ("$($svc.StartMode)" -eq 'Disabled') { continue }
    $exe  = Get-ExePath "$($svc.PathName)"
    $text = "$($svc.Name) | $($svc.DisplayName) | $($svc.PathName)"
    if ($text -match $CcsPattern) { Note "$($svc.Name) | $($svc.DisplayName) | $($svc.State) | $($svc.StartMode)   <- CyberPatriot client: leave alone"; continue }
    if ($risky.ContainsKey($svc.Name)) {
        $info  = $risky[$svc.Name]
        $score = $info[0]
        if ("$($svc.State)" -ne 'Running' -and "$($svc.StartMode)" -eq 'Manual') { $score = [int]($score * 0.6) }
        Add-Lead $score "Service '$($svc.Name)' ($($svc.DisplayName)) is $($svc.State), start mode $($svc.StartMode)" $info[1] "Stop-Service $($svc.Name) -Force ; Set-Service $($svc.Name) -StartupType Disabled"
    }
    $thirdParty = ($exe -and $exe -notmatch '^[A-Za-z]:\\Windows\\')
    $signer = ''
    if ($thirdParty) {
        $signer = Get-Signer $exe
        if ($text -match $ToolPattern) {
            Add-Lead 90 "Service '$($svc.Name)' looks like a prohibited tool: $($svc.PathName)" 'the README prohibits hacking tools' "Stop-Service $($svc.Name) -Force ; sc.exe delete $($svc.Name)   (then uninstall the program)"
        }
        elseif ($signer -notmatch '^signed') {
            Add-Lead 84 "Service '$($svc.Name)' runs a program that is not signed: $exe  [$signer]" 'possible backdoor installed as a service' "Stop-Service $($svc.Name) -Force ; Set-Service $($svc.Name) -StartupType Disabled"
        }
        elseif ((Test-OddPath $exe) -and $signer -notmatch 'Microsoft') {
            Add-Lead 80 "Service '$($svc.Name)' runs from a user/temp/data folder: $exe  [$signer]" 'installed services do not normally run from there' "Stop-Service $($svc.Name) -Force ; Set-Service $($svc.Name) -StartupType Disabled"
        }
        elseif ($text -notmatch $AllowPattern) {
            Add-Lead 58 "Service '$($svc.Name)' ($($svc.DisplayName)) is not Windows or README software: $exe" 'software that is not on the README list' "Stop-Service $($svc.Name) -Force ; Set-Service $($svc.Name) -StartupType Disabled"
        }
    }
    Note "$($svc.Name) | $($svc.DisplayName) | $($svc.State) | $($svc.StartMode) | $($svc.PathName) $signer"
}

# =============================================================================
#  9. WINDOWS FEATURES
# =============================================================================
Head 'Windows optional features that are enabled'
$featureRules = @(
    @{ M = '^SMB1Protocol'; S = 72; T = 'SMB version 1 (scored on the Server image)' }
    @{ M = '^TelnetClient$'; S = 66; T = 'Telnet client' }
    @{ M = '^TFTP$'; S = 62; T = 'TFTP client' }
    @{ M = '^IIS-'; S = 74; T = 'IIS web/FTP server component on a workstation'; Role = 'Workstation' }
    @{ M = '^SimpleTCP$'; S = 70; T = 'Simple TCP/IP services' }
    @{ M = 'LPD|LPR'; S = 50; T = 'legacy print services' }
    @{ M = '^MicrosoftWindowsPowerShellV2'; S = 44; T = 'PowerShell 2.0 (bypasses modern logging)' }
    @{ M = '^MSMQ-'; S = 44; T = 'Message Queuing' }
    @{ M = '^WorkFolders-Client$'; S = 22; T = 'Work Folders client' }
)
try {
    $seen = @{}
    foreach ($f in @(Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object { "$($_.State)" -eq 'Enabled' } | Sort-Object FeatureName)) {
        Note "$($f.FeatureName)"
        foreach ($rule in $featureRules) {
            if ($rule.Role -and $rule.Role -ne $Role) { continue }
            if ($f.FeatureName -match $rule.M -and -not $seen.ContainsKey($rule.M)) {
                $seen[$rule.M] = $true
                Add-Lead $rule.S "Windows feature enabled: $($f.FeatureName)  ($($rule.T))" 'unneeded Windows features are a classic scored item' "Disable-WindowsOptionalFeature -Online -FeatureName $($f.FeatureName) -NoRestart"
                break
            }
        }
    }
}
catch { Note "Could not list features: $($_.Exception.Message)" }
try {
    foreach ($cap in @(Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop)) {
        Note "Capability $($cap.Name): $($cap.State)"
        if ("$($cap.State)" -eq 'Installed') { Add-Lead 74 'OpenSSH Server is installed' 'the README does not list SSH as a needed service' "Remove-WindowsCapability -Online -Name $($cap.Name)" }
    }
}
catch { }

if ($IsServer) {
    $serverRules = @(
        @{ M = '^Web-Ftp'; S = 80; T = 'FTP server' }
        @{ M = '^FS-SMB1'; S = 72; T = 'SMB version 1 (scored on the Server image)' }
        @{ M = '^SNMP-'; S = 70; T = 'SNMP polling (README: no polling tools are used)' }
        @{ M = '^Simple-TCPIP$'; S = 70; T = 'Simple TCP/IP services' }
        @{ M = '^Telnet-Client$'; S = 66; T = 'Telnet client' }
        @{ M = '^TFTP-Client$'; S = 62; T = 'TFTP client' }
        @{ M = '^Web-DAV-Publishing$'; S = 58; T = 'WebDAV publishing (lets clients write to the web site)' }
        @{ M = '^(RemoteAccess|Routing|DirectAccess-VPN)$'; S = 55; T = 'routing / remote access role' }
        @{ M = '^(DNS|DHCP|WINS|Fax|Print-Server|Print-Services)$'; S = 48; T = 'a server role the README does not ask for' }
        @{ M = '^Web-Mgmt-Service$'; S = 48; T = 'remote IIS management service' }
        @{ M = '^PowerShell-V2$'; S = 44; T = 'PowerShell 2.0 (bypasses modern logging)' }
    )
    try {
        Import-Module ServerManager -ErrorAction Stop
        Note ''
        foreach ($f in @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed } | Sort-Object Name)) {
            Note "Role/feature: $($f.Name)"
            foreach ($rule in $serverRules) {
                if ($f.Name -match $rule.M) {
                    Add-Lead $rule.S "Server role or feature installed: $($f.Name)  ($($rule.T))" 'unneeded roles and features are a classic scored item' "Uninstall-WindowsFeature -Name $($f.Name)"                    break
                }
            }
        }
    }
    catch { Note "Could not list server roles: $($_.Exception.Message)" }
}

# =============================================================================
#  10. THINGS THAT START BY THEMSELVES
# =============================================================================
Head 'Startup entries, scheduled tasks and sign-in screen tools'
function Test-StartupItem {
    param([string]$Where, [string]$Name, [string]$Command, [string]$Remove)
    $exe = Get-ExePath $Command
    Note "$Where | $Name | $Command"
    if ("$Name $Command" -match $CcsPattern) { return }
    if ("$Name $Command" -match $ToolPattern) {
        Add-Lead 90 "Startup entry runs a prohibited tool: $Name -> $Command  ($Where)" 'the README prohibits hacking tools' $Remove
    }
    elseif ((Test-OddPath $exe) -or $Command -match 'powershell|cmd(\.exe)? /c|wscript|cscript|mshta|rundll32|regsvr32|-enc|\.bat|\.vbs|\.ps1') {
        if ("$Name $Command" -notmatch 'OneDrive|SecurityHealth|MicrosoftEdge|Teams|GoogleUpdate|GoogleDrive') {
            Add-Lead 80 "Suspicious startup entry: $Name -> $Command  ($Where)" 'starts a script or a program from a user/temp folder at every sign-in' $Remove
        }
    }
    elseif ("$Name $Command" -notmatch $AllowPattern) {
        Add-Lead 60 "Startup entry that is not Windows or README software: $Name -> $Command  ($Where)" '' $Remove
    }
}
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
foreach ($hive in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
    $runKeys += "Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $runKeys += "Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
}
foreach ($key in $runKeys) {
    $item = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    foreach ($p in @($item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
        $regKey = ($key -replace '^Registry::', '') -replace '^HKLM:\\', 'HKLM\'
        Test-StartupItem -Where $key -Name $p.Name -Command "$($p.Value)" -Remove "reg delete `"$regKey`" /v `"$($p.Name)`" /f"
    }
}
$startupDirs = @('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp') +
               @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
foreach ($dir in $startupDirs) {
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
        Test-StartupItem -Where 'Startup folder' -Name $f.Name -Command $f.FullName -Remove "Remove-Item -LiteralPath '$($f.FullName)' -Force"
    }
}

Note ''
foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    $actions = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
    $full    = "$($task.TaskPath)$($task.TaskName)"
    $inMicrosoft = ($task.TaskPath -like '\Microsoft\*')
    if (-not $inMicrosoft) { Note "$full [$($task.State)] runs: $actions" }
    if ("$full $actions" -match $CcsPattern) { continue }
    $remove = "Unregister-ScheduledTask -TaskName '$($task.TaskName)' -Confirm:0"
    if ("$full $actions" -match $ToolPattern) {
        Add-Lead 90 "Scheduled task runs a prohibited tool: $full -> $actions" 'the README prohibits hacking tools' $remove
    }
    elseif ($inMicrosoft) {
        if ($actions -match '\\Users\\|\\Temp\\|\\ProgramData\\(?!Microsoft)') { Add-Lead 82 "Task inside \Microsoft\ runs a program from a user/temp folder: $full -> $actions" 'a backdoor hidden among the Windows tasks' $remove }
    }
    elseif ("$full" -match 'GoogleUpdate|GoogleSystem|MicrosoftEdgeUpdate|OneDrive|Mozilla|Thunderbird|LibreOffice|Opera|Adobe') { }
    elseif ($actions -match '\\Users\\|\\Temp\\|powershell|cmd(\.exe)?\s|wscript|cscript|mshta|\.bat|\.vbs|\.ps1|net(\.exe)? user|-enc') {
        Add-Lead 84 "Suspicious scheduled task: $full -> $actions" 'runs a script or command on a schedule; a classic planted backdoor' $remove
    }
    else {
        Add-Lead 62 "Scheduled task outside \Microsoft\: $full -> $actions" 'not part of Windows' $remove
    }
}

Note ''
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($sub in @(Get-ChildItem -Path $ifeo -ErrorAction SilentlyContinue)) {
    $debugger = Get-Reg $sub.PSPath 'Debugger'
    if (-not $debugger) { continue }
    Note "Debugger hijack: $($sub.PSChildName) -> $debugger"
    $fixed = $false
    if ($sub.PSChildName -match '^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$') {
        $target = $sub.PSPath
        $fixed = Invoke-Fix "Debugger hijack removed from $($sub.PSChildName)" { Remove-ItemProperty -Path $target -Name Debugger -Force }
    }
    Add-Lead -Score 88 -Title "Program '$($sub.PSChildName)' is hijacked to start '$debugger' instead" -Repaired:$fixed `
             -Why 'the classic sticky-keys backdoor: a command prompt from the sign-in screen' -Fix "reg delete `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($sub.PSChildName)`" /v Debugger /f"
}
$shells = @{}
foreach ($name in 'cmd.exe', 'powershell.exe', 'explorer.exe', 'taskmgr.exe') {
    $path = Join-Path $env:SystemRoot "System32\$name"
    if ($name -eq 'powershell.exe') { $path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
    if ($name -eq 'explorer.exe') { $path = Join-Path $env:SystemRoot 'explorer.exe' }
    try { $shells[(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash] = $name } catch { }
}
foreach ($name in 'sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe') {
    $path = Join-Path $env:SystemRoot "System32\$name"
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $hash = ''
    try { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
    $signer = Get-Signer $path
    Note "$name : $signer"
    if ($hash -and $shells.ContainsKey($hash)) {
        Add-Lead 90 "$path is really a copy of $($shells[$hash])" 'sticky-keys backdoor: the accessibility tool was replaced' 'sfc /scannow'
    }
    elseif ($signer -notmatch '^signed') {
        Add-Lead 84 "$path is not a signed Windows file ($signer)" 'the accessibility tool may have been replaced' 'sfc /scannow'
    }
}
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$shell = "$(Get-Reg $winlogon 'Shell')"
$userinit = "$(Get-Reg $winlogon 'Userinit')"
Note "Winlogon Shell = $shell   Userinit = $userinit"
if ($shell -and $shell.Trim() -ne 'explorer.exe') { Add-Lead 86 "Winlogon Shell is '$shell' instead of explorer.exe" 'something extra starts at every sign-in' "reg add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v Shell /t REG_SZ /d explorer.exe /f" }
if ($userinit -and $userinit.Trim().TrimEnd(',') -notmatch '^(C:\\Windows\\system32\\)?userinit\.exe$') { Add-Lead 86 "Winlogon Userinit is '$userinit'" 'something extra starts at every sign-in' "reg add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /v Userinit /t REG_SZ /d C:\Windows\system32\userinit.exe, /f" }
$appInit = "$(Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' 'AppInit_DLLs')"
if ($appInit.Trim()) { Add-Lead 68 "AppInit_DLLs is set: $appInit" 'a library loaded into every program' "reg add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`" /v AppInit_DLLs /t REG_SZ /d `"`" /f" }
foreach ($class in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
    foreach ($consumer in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction SilentlyContinue)) {
        $what = "$($consumer.CommandLineTemplate)$($consumer.ScriptText)"
        Note "WMI consumer $class '$($consumer.Name)': $what"
        if ($consumer.Name -ne 'BVTConsumer') { Add-Lead 72 "WMI event consumer '$($consumer.Name)' runs: $what" 'a hidden way to run a command automatically' "Get-CimInstance -Namespace root\subscription -ClassName $class | Remove-CimInstance" }
    }
}

# =============================================================================
#  11. NETWORK: PORTS, SHARES, HOSTS, PROXY, FIREWALL
# =============================================================================
Head 'Listening ports, shares, hosts file, firewall'
$watchPorts = @(21, 23, 25, 69, 80, 110, 143, 443, 1433, 3306, 5900, 8080)
if ($IisIsCritical) { $watchPorts = @($watchPorts | Where-Object { $_ -ne 80 -and $_ -ne 443 }) }
foreach ($conn in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique)) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    $path = "$($proc.Path)"
    Note "TCP $($conn.LocalPort) | $($conn.LocalAddress) | $($proc.ProcessName) | $path"
    if ("$($proc.ProcessName) $path" -match $CcsPattern) { continue }
    if ("$($proc.ProcessName) $path" -match $ToolPattern) {
        Add-Lead 92 "Prohibited tool is listening on TCP port $($conn.LocalPort): $($proc.ProcessName) ($path)" 'a running backdoor or remote-access tool' "Stop-Process -Id $($conn.OwningProcess) -Force   (then remove the program and whatever starts it)"
    }
    elseif ($path -and $path -notmatch '^[A-Za-z]:\\Windows\\' -and $path -notmatch $AllowPattern) {
        Add-Lead 82 "Non-Windows program is listening on TCP port $($conn.LocalPort): $($proc.ProcessName) ($path)" 'a possible backdoor listener' "Stop-Process -Id $($conn.OwningProcess) -Force   (then remove the program and whatever starts it)"
    }
    elseif ($watchPorts -contains [int]$conn.LocalPort) {
        Add-Lead 66 "A server is listening on TCP port $($conn.LocalPort): $($proc.ProcessName)" 'the README does not list this service' 'Find and disable the service that owns the port (see the services list)'
    }
}
foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Sort-Object Path -Unique)) {
    if ("$($proc.Path)" -match $CcsPattern) { continue }
    if ("$($proc.ProcessName) $($proc.Path)" -match $ToolPattern) {
        Add-Lead 90 "Prohibited tool is running: $($proc.Path)" 'the README prohibits hacking tools' "Stop-Process -Name $($proc.ProcessName) -Force   (then remove the program)"
    }
    elseif ((Test-OddPath $proc.Path) -and $proc.Path -notmatch $AllowPattern) {
        $signer = Get-Signer $proc.Path
        $score = 58
        if ($signer -notmatch '^signed') { $score = 78 }
        Add-Lead $score "Program running from a user/temp folder: $($proc.Path)  [$signer]" 'installed software does not run from there' "Stop-Process -Name $($proc.ProcessName) -Force"
    }
}

Note ''
foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue)) {
    Note "Share '$($share.Name)' -> $($share.Path)  special=$($share.Special)"
    if ($share.Special -or $share.Name -eq 'print$') { continue }
    $access = @(Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue)
    foreach ($entry in $access) { Note "    $($entry.AccountName): $($entry.AccessControlType) $($entry.AccessRight)" }
    if ($ExpectedShares -notcontains $share.Name) {
        $kind = 'Shared folder'
        if ($share.Name.EndsWith('$')) { $kind = 'HIDDEN shared folder' }
        Add-Lead 85 "$kind '$($share.Name)' -> $($share.Path) is not a share the README asks for" 'an extra hidden share was a scored item on the Server image' "Remove-SmbShare -Name '$($share.Name)' -Force"
        continue
    }
    foreach ($entry in $access) {
        if ("$($entry.AccessControlType)" -ne 'Allow') { continue }
        $account = "$($entry.AccountName)"
        if ($account -match 'Guest|ANONYMOUS') {
            Add-Lead 74 "Required share '$($share.Name)' is open to $account" 'guests and anonymous users should have no access' "Revoke-SmbShareAccess -Name '$($share.Name)' -AccountName '$account' -Force"
        }
        elseif ($account -match 'Everyone|Authenticated Users|\\Users$' -and "$($entry.AccessRight)" -ne 'Read') {
            Add-Lead 80 "Required share '$($share.Name)' gives $account $($entry.AccessRight) access" 'permissions on this share were a scored item on the Server image; ordinary users should only read' `
                     "Grant-SmbShareAccess -Name '$($share.Name)' -AccountName '$account' -AccessRight Read -Force"
        }
    }
    try {
        foreach ($ace in @((Get-Acl -LiteralPath $share.Path -ErrorAction Stop).Access)) {
            Note "    NTFS: $($ace.IdentityReference) $($ace.AccessControlType) $($ace.FileSystemRights)"
            if ("$($ace.AccessControlType)" -eq 'Allow' -and "$($ace.IdentityReference)" -match 'Everyone|Authenticated Users|\\Users$' -and "$($ace.FileSystemRights)" -match 'FullControl|Modify|Write') {
                Add-Lead 62 "Folder behind share '$($share.Name)' lets $($ace.IdentityReference) change files ($($ace.FileSystemRights))" 'ordinary users should only read the required share' `
                         "Folder > Properties > Security > Edit: leave $($ace.IdentityReference) with Read & execute only"
            }
        }
    }
    catch { }
}
try {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    Note "SMB server: SMB1=$($smb.EnableSMB1Protocol)  RequireSigning=$($smb.RequireSecuritySignature)  EncryptData=$($smb.EncryptData)"
    if ($smb.EnableSMB1Protocol) { Add-Lead 72 'SMB version 1 is enabled on the file server' 'scored on the Server image' 'Set-SmbServerConfiguration -EnableSMB1Protocol 0 -Force' }
    if ($IsServer -and -not $smb.RequireSecuritySignature) { Add-Lead 66 'The file server does not require SMB signing' 'scored on the Server image' 'Set-SmbServerConfiguration -RequireSecuritySignature 1 -Force' }
}
catch { }

Note ''
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
foreach ($line in @(Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })) {
    Note "hosts: $line"
    if ($line -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*$') { Add-Lead 68 "hosts file redirects a name: $($line.Trim())" 'redirected update or security sites are a classic scored item' 'notepad C:\Windows\System32\drivers\etc\hosts   (delete the line, save)' }
}
$proxyOn = Get-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyEnable'
$proxy   = Get-Reg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer'
Note "Proxy: enabled=$proxyOn server=$proxy"
if ($proxyOn -eq 1) { Add-Lead 58 "A proxy server is configured: $proxy" 'traffic is being sent through another machine' 'Settings > Network & internet > Proxy > turn off "Use a proxy server"' }
foreach ($adapter in @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })) { Note "DNS $($adapter.InterfaceAlias): $($adapter.ServerAddresses -join ', ')" }

Note ''
foreach ($fw in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    Note "Firewall $($fw.Name): enabled=$($fw.Enabled) inbound=$($fw.DefaultInboundAction) outbound=$($fw.DefaultOutboundAction) notify=$($fw.NotifyOnListen)"
    if ("$($fw.Enabled)" -ne 'True') { Add-Lead 70 "Firewall profile $($fw.Name) is off" 'all three profiles should be on' 'Set-NetFirewallProfile -All -Enabled True' }
    if ("$($fw.DefaultInboundAction)" -eq 'Allow') { Add-Lead 64 "Firewall profile $($fw.Name) allows all inbound connections by default" '' 'Set-NetFirewallProfile -All -DefaultInboundAction Block' }
}
foreach ($rule in @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue | Where-Object { -not $_.DisplayGroup })) {
    $pf = $rule | Get-NetFirewallPortFilter
    $af = $rule | Get-NetFirewallApplicationFilter
    $program = "$($af.Program)"
    Note "Inbound allow rule: $($rule.DisplayName) | $($pf.Protocol) $(@($pf.LocalPort) -join ',') | $program"
    if ("$($rule.DisplayName) $program" -match $CcsPattern) { continue }
    if ("$($rule.DisplayName) $program" -match $ToolPattern) {
        Add-Lead 80 "Firewall lets a prohibited tool in: $($rule.DisplayName) ($program)" '' "Remove-NetFirewallRule -DisplayName '$($rule.DisplayName)'"
    }
    elseif ("$($rule.DisplayName) $program" -notmatch $AllowPattern) {
        Add-Lead 56 "Custom inbound firewall rule: $($rule.DisplayName) | $($pf.Protocol) $(@($pf.LocalPort) -join ',') | $program" 'not a built-in rule' "Remove-NetFirewallRule -DisplayName '$($rule.DisplayName)'"
    }
}

# =============================================================================
#  12. INSTALLED PROGRAMS AND APPS
# =============================================================================
Head 'Installed programs'
foreach ($app in @($Installed | Sort-Object DisplayName -Unique)) {
    Note "$($app.DisplayName) | $($app.DisplayVersion) | $($app.Publisher) | $($app.InstallLocation)"
    $text = "$($app.DisplayName) $($app.Publisher)"
    if ($text -match $CcsPattern) { continue }
    if ($text -match $ToolPattern) {
        Add-Lead 92 "Prohibited program is installed: $($app.DisplayName) $($app.DisplayVersion)" 'the README prohibits hacking tools and games; each removal is usually its own check' 'Settings > Apps > Installed apps > uninstall it'
    }
    elseif ($text -notmatch $AllowPattern -and -not $app.SystemComponent) {
        Add-Lead 58 "Program that is not on the README list: $($app.DisplayName) ($($app.Publisher))" 'only the README software is business related' 'Settings > Apps > Installed apps > uninstall it if it is not needed'
    }
}
Note ''
foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, 'C:\')) {
    foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
        Note "Folder: $($dir.FullName)"
        if ($dir.Name -match $CcsPattern) { continue }
        if ($dir.Name -match $ToolPattern) {
            Add-Lead 88 "Folder of a prohibited tool: $($dir.FullName)" 'a portable copy does not show up under installed apps' "Remove-Item -LiteralPath '$($dir.FullName)' -Recurse -Force"
        }
        elseif ($root -eq 'C:\' -and $dir.Name -notmatch '^(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|PerfLogs|Recovery|HardeningLogs|HardeningQuarantine|\$.*|System Volume Information|Documents and Settings|OneDriveTemp|Config\.Msi|inetpub)$' -and -not ($IsServer -and $dir.Name -eq 'Shares')) {
            Add-Lead 55 "Unusual folder in the root of C: $($dir.FullName)" 'worth a look inside' "explorer `"$($dir.FullName)`""
        }
        elseif ($root -eq 'C:\' -and $dir.Name -eq 'inetpub' -and -not $IisIsCritical) {
            Add-Lead 70 'C:\inetpub exists: a web server is or was installed' 'the README does not list a web site for this machine' 'Turn Windows features on or off > untick Internet Information Services'
        }
    }
}
Note ''
try {
    foreach ($pkg in @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { -not $_.IsFramework -and "$($_.SignatureKind)" -eq 'Store' } | Sort-Object Name)) {
        Note "Store app: $($pkg.Name) | $($pkg.Publisher)"
        if ($pkg.Name -match 'CandyCrush|Solitaire|Spotify|Netflix|TikTok|Disney|Minecraft|Roblox|BubbleWitch|Facebook|Instagram|Twitter|PrimeVideo|Hulu|ZuneMusic|ZuneVideo|GamingApp|XboxApp|king\.com') {
            Add-Lead 46 "Game or entertainment Store app: $($pkg.Name)" 'the README prohibits non-work media and games' "Get-AppxPackage -AllUsers -Name $($pkg.Name) | Remove-AppxPackage -AllUsers"
        }
        elseif ($pkg.Name -match $ToolPattern) {
            Add-Lead 88 "Prohibited Store app: $($pkg.Name)" 'the README prohibits hacking tools' "Get-AppxPackage -AllUsers -Name $($pkg.Name) | Remove-AppxPackage -AllUsers"
        }
    }
}
catch { Note "Could not list Store apps: $($_.Exception.Message)" }

# =============================================================================
#  13. IIS WEB SERVER
# =============================================================================
Head 'IIS web server'
$SiteRoots = @()
$iisReady  = $false
if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
    try { Import-Module WebAdministration -ErrorAction Stop; $iisReady = $true }
    catch { Note "IIS is installed but its PowerShell module is not available: $($_.Exception.Message)" }
}
else {
    Note 'IIS is not installed.'
    if ($IisIsCritical) {
        Add-Lead 85 'IIS is not installed but the README lists it as a critical service' 'a critical service that is down costs points' 'Install-WindowsFeature Web-Server -IncludeManagementTools'
    }
}
if ($iisReady) {
    $appcmd = '& "C:\Windows\System32\inetsrv\appcmd.exe"'
    foreach ($site in @(Get-Website)) {
        $siteName = $site.Name
        $root = [Environment]::ExpandEnvironmentVariables("$($site.physicalPath)")
        $SiteRoots += $root
        $bindings = (@($site.bindings.Collection) | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join '; '
        Note "Site '$siteName' [$($site.State)]  path: $root  bindings: $bindings  pool: $($site.applicationPool)"
        if ($bindings -match '(^|; )ftp ') {
            Add-Lead 80 "Site '$siteName' is an FTP site ($bindings)" 'FTP is not a service the README asks for' "Remove-Website -Name '$siteName'"
        }
        elseif ($IisIsCritical -and "$($site.State)" -ne 'Started') {
            Add-Lead 85 "Web site '$siteName' is $($site.State)" 'IIS is a critical service; a site that is down costs points' "Start-Website -Name '$siteName'"
        }
        foreach ($kind in 'anonymousAuthentication', 'basicAuthentication', 'windowsAuthentication') {
            try {
                $enabled = (Get-WebConfigurationProperty -PSPath 'IIS:\' -Location $siteName -Filter "system.webServer/security/authentication/$kind" -Name enabled -ErrorAction Stop).Value
                Note "    $kind enabled = $enabled"
                if ($kind -eq 'basicAuthentication' -and $enabled) {
                    Add-Lead 50 "Basic authentication is on for site '$siteName'" 'it sends passwords without encryption' "$appcmd set config `"$siteName`" /section:basicAuthentication /enabled:false /commit:apphost"
                }
            }
            catch { }
        }

        # Directory browsing: the site itself and every application / virtual directory
        $places = @($siteName)
        foreach ($child in (@(Get-WebApplication -Site $siteName -ErrorAction SilentlyContinue) + @(Get-WebVirtualDirectory -Site $siteName -ErrorAction SilentlyContinue))) {
            Note "    child '$($child.path)' -> $($child.physicalPath)"
            $places += ($siteName + "$($child.path)")
        }
        foreach ($place in $places) {
            $browse = $false
            try { $browse = [bool](Get-WebConfigurationProperty -PSPath ('IIS:\Sites\' + ($place -replace '/', '\')) -Filter 'system.webServer/directoryBrowse' -Name enabled -ErrorAction Stop).Value } catch { }
            Note "    directory browsing at '$place' = $browse"
            if ($browse) {
                Add-Lead 84 "Directory browsing is ON for '$place'" 'this exact item was scored on the Server image' "$appcmd set config `"$place`" /section:directoryBrowse /enabled:false"
            }
        }

        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $ext = $f.Extension.ToLower()
            if ($f.Name -ieq 'web.config') {
                $text = ''
                try { $text = [IO.File]::ReadAllText($f.FullName) } catch { }
                Note ''
                Note "--- $($f.FullName) ---"
                foreach ($line in @($text -split "`r?`n" | Select-Object -First 80)) { Note "    $line" }
                if ($text -match '<directoryBrowse[^>]*enabled\s*=\s*"true"') {
                    Add-Lead 84 "Directory browsing is switched on inside $($f.FullName)" 'this exact item was scored on the Server image' 'Open the file in Notepad and change enabled="true" to enabled="false" on the directoryBrowse line'
                }
                if ($text -match '<compilation[^>]*debug\s*=\s*"true"') {
                    Add-Lead 50 "ASP.NET debug mode is on in $($f.FullName)" 'debug builds expose details to visitors' 'Open the file in Notepad and change debug="true" to debug="false"'
                }
                if ($text -match '<customErrors[^>]*mode\s*=\s*"Off"') {
                    Add-Lead 46 "Detailed error pages are shown to visitors ($($f.FullName))" 'error details help an attacker' 'Open the file in Notepad and change customErrors mode="Off" to mode="RemoteOnly"'
                }
                continue
            }
            if ($WebScriptExt -notcontains $ext) { continue }
            $text = ''
            if ($f.Length -lt 1MB) { try { $text = [IO.File]::ReadAllText($f.FullName) } catch { } }
            Note "    script: $($f.FullName)  ($($f.Length) bytes)"
            $hit = [regex]::Match($text, $ShellPattern, 'IgnoreCase')
            $remove = "Remove-Item -LiteralPath '$($f.FullName)' -Force   (open it in Notepad first, to be sure it is not part of the real site)"
            if ($hit.Success) {
                Add-Lead 90 "Possible web shell: $($f.FullName)  (it contains '$($hit.Value)')" 'an ASPX web shell was a scored item on the Server image' $remove
            }
            elseif ($f.Name -match 'shell|cmd|c99|r57|backdoor|b374k|wso|webadmin') {
                Add-Lead 72 "Web script with a suspicious name: $($f.FullName)" 'an ASPX web shell was a scored item on the Server image' $remove
            }
            elseif ($f.DirectoryName -match 'upload') {
                Add-Lead 70 "Script file inside an upload folder: $($f.FullName)" 'uploaded files should never be runnable pages' $remove
            }
        }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'upload' })) {
            $relative = $dir.FullName.Substring($root.TrimEnd('\').Length).TrimStart('\') -replace '\\', '/'
            $location = "$siteName/$relative"
            $policy = ''
            try { $policy = "$(Get-WebConfigurationProperty -PSPath 'IIS:\' -Location $location -Filter 'system.webServer/handlers' -Name accessPolicy -ErrorAction Stop)" } catch { }
            Note "    upload folder '$location' handler permissions: $policy"
            if ($policy -and $policy -ne 'Read') {
                Add-Lead 56 "Scripts can run inside upload folder '$location' (handler permissions: $policy)" 'an uploaded file could run as code' "$appcmd set config `"$location`" /section:handlers /accessPolicy:Read /commit:apphost"
            }
        }
    }
    foreach ($pool in @(Get-ChildItem 'IIS:\AppPools' -ErrorAction SilentlyContinue)) {
        Note "App pool '$($pool.Name)' [$($pool.State)] identity: $($pool.processModel.identityType) $($pool.processModel.userName)  .NET: $($pool.managedRuntimeVersion)"
        if ("$($pool.processModel.identityType)" -eq 'LocalSystem') {
            Add-Lead 60 "App pool '$($pool.Name)' runs as LocalSystem" 'a compromised site would control the whole server' "$appcmd set apppool `"$($pool.Name)`" /processModel.identityType:ApplicationPoolIdentity"
        }
    }
    $status = 0
    try { $status = [int](Invoke-WebRequest -Uri 'http://localhost/' -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop).StatusCode }
    catch { if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } }
    Note "Web site check: http://localhost/ -> HTTP $status"
    if ($IisIsCritical -and ($status -eq 0 -or $status -ge 500)) {
        Add-Lead 82 "The web site does not answer correctly (HTTP $status)" 'IIS is a critical service; a site that is down costs points' 'iisreset   (then open http://localhost/ in a browser)'
    }
}

# =============================================================================
#  14. FILES IN USER FOLDERS, SHARES AND WEB SITES
# =============================================================================
Head 'Files in user folders (outside AppData), shares and web sites'
try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
$found = @{ Media = @(); Image = @(); Archive = @(); Program = @() }
$credCount = 0
$toolCount = 0
$script:InWebRoot = $false
function Test-UserFile {
    param($File)
    if ($File.Name -match $SkipFileName) { return }
    $ext = $File.Extension.ToLower()
    if ($script:InWebRoot -and (($WebSkipExt -contains $ext) -or ($WebScriptExt -contains $ext))) { return }
    Note "$($File.FullName)  ($($File.Length) bytes)"
    if ($File.FullName -match $ToolPattern -and $script:toolCount -lt 20) {
        $script:toolCount++
        Add-Lead 88 "File with the name of a prohibited tool: $($File.FullName)" 'the README prohibits hacking tools; a prohibited archive was scored on the Server image' "Remove-Item -LiteralPath '$($File.FullName)' -Force"
        return
    }
    if ($MediaExt -contains $ext)   { $script:found.Media   += $File; return }
    if ($ImageExt -contains $ext)   { $script:found.Image   += $File; return }
    if ($ProgramExt -contains $ext) { $script:found.Program += $File; return }
    if ($ArchiveExt -contains $ext) {
        $names = ''
        if ($ext -eq '.zip') {
            try {
                $zip = [IO.Compression.ZipFile]::OpenRead($File.FullName)
                $names = (@($zip.Entries | Select-Object -First 200 | ForEach-Object { $_.FullName }) -join ' ; ')
                $zip.Dispose()
                Note "      contains: $names"
            }
            catch { }
        }
        if ($names -match $ToolPattern -and $script:toolCount -lt 20) {
            $script:toolCount++
            Add-Lead 88 "Archive that contains a prohibited tool: $($File.FullName)" 'a prohibited archive was the last 3-point item pattern on the Server image' "Remove-Item -LiteralPath '$($File.FullName)' -Force"
        }
        else { $script:found.Archive += $File }
        return
    }
    if ($TextExt -contains $ext -and $File.Length -gt 0 -and $File.Length -lt 512KB) {
        $text = ''
        try { $text = [IO.File]::ReadAllText($File.FullName) } catch { }
        $strong = [regex]::Match($text, '(?im)^.*\b(pass(word|wd|phrase|code)?|pwd)s?\b[ \t]*([:=,;|]|\r?$).*$')
        $weak   = [regex]::Match($text, '(?im)^.*\b(pass(word|wd|phrase|code)?|pwd|credentials?)\b.*$')
        if (($strong.Success -or $weak.Success) -and $script:credCount -lt 15) {
            $script:credCount++
            $score = 62
            $hit = $weak
            if ($strong.Success) { $score = 88; $hit = $strong }
            $sample = $hit.Value.Trim()
            if ($sample.Length -gt 70) { $sample = $sample.Substring(0, 70) }
            foreach ($line in @($text -split "`r?`n" | Select-Object -First 5)) { Note "      | $line" }
            Add-Lead $score "File that appears to hold passwords: $($File.FullName)   (line: $sample)" `
                     'exactly this - a plaintext password list - was the final missing check on the Server image' "Remove-Item -LiteralPath '$($File.FullName)' -Force   (read it first)"
            return
        }
    }
    if ($File.Name -match 'passw|credential|secret|logins?\b' -and $script:credCount -lt 15) {
        $script:credCount++
        Add-Lead 80 "File whose name suggests stored passwords: $($File.FullName)" 'a plaintext password list was the final missing check on the Server image' "Open it; if it holds passwords: Remove-Item -LiteralPath '$($File.FullName)' -Force"
    }
}
function Search-Folder {
    param([string]$Path)
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue)) {
        if ($item.PSIsContainer) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            Search-Folder $item.FullName
        }
        else { Test-UserFile $item }
    }
}
foreach ($profileDir in @(Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
    if ($profileDir.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    if ($profileDir.Name -match '^(Default|Default User|All Users)$') { continue }
    foreach ($item in @(Get-ChildItem -LiteralPath $profileDir.FullName -Force -ErrorAction SilentlyContinue)) {
        if ($item.PSIsContainer) {
            if ($item.Name -match '^(AppData|Application Data|Local Settings)$') { continue }
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            Search-Folder $item.FullName
        }
        else { Test-UserFile $item }
    }
}
foreach ($item in @(Get-ChildItem -LiteralPath 'C:\' -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(pagefile|hiberfil|swapfile|DumpStack|bootmgr|BOOTNXT)' })) { Test-UserFile $item }
foreach ($share in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.Path -and $_.Path -notmatch '^C:\\Users\\' })) { Search-Folder $share.Path }
$script:InWebRoot = $true
foreach ($root in @($SiteRoots | Select-Object -Unique)) {
    if ($root -and (Test-Path -LiteralPath $root)) { Search-Folder $root }
}
$script:InWebRoot = $false

function Add-FileGroupLead {
    param([int]$Score, [string]$Kind, $Files, [string]$Why)
    $list = @($Files)
    if ($list.Count -eq 0) { return }
    $byExt = @($list | Group-Object { $_.Extension.ToLower() } | Sort-Object Count -Descending | ForEach-Object { "$($_.Count) x $($_.Name)" }) -join ', '
    $sample = @($list | Select-Object -First 6 | ForEach-Object { $_.FullName }) -join ' | '
    Add-Lead $Score "$($list.Count) $Kind in user, share or web folders ($byExt). Examples: $sample" $Why 'The full list is in the last inventory section. Delete the ones that are not work related.'
}
Add-FileGroupLead 80 'audio/video file(s)' $found.Media 'the README prohibits non-work media; each file type can be its own check'
Add-FileGroupLead 58 'program/script file(s)' $found.Program 'planted tools often sit here as installers or scripts (ignore installers you downloaded yourself)'
Add-FileGroupLead 52 'archive file(s)' $found.Archive 'a prohibited archive was scored on the Server image; open these and look'
Add-FileGroupLead 34 'picture file(s)' $found.Image 'possibly non-work media; lower odds'

# =============================================================================
#  REPORT
# =============================================================================
$open    = @($Leads | Where-Object { -not $_.Repaired } | Sort-Object Score -Descending)
$repaired = @($Leads | Where-Object { $_.Repaired } | Sort-Object Score -Descending)

$report = New-Object System.Collections.Generic.List[string]
$report.Add("LEADS REPORT   $(Get-Date)   computer: $($env:COMPUTERNAME)   run as: $($env:USERNAME)")
$report.Add("System: $($Os.Caption)   profile: $Role")
$mode = 'report + safe repairs'
if ($ReportOnly) { $mode = 'report only (nothing changed)' }
$report.Add("Mode: $mode")
$report.Add('Score = estimated chance (0-100) that the item is one of the missing scored checks.')
$report.Add('')
$report.Add("##### A. ALREADY REPAIRED BY THIS SCRIPT ($($repaired.Count)) - check the scoring report in 2 minutes #####")
if ($repaired.Count -eq 0) { $report.Add('  (nothing needed repair)') }
foreach ($lead in $repaired) {
    $report.Add("  [$($lead.Score)] $($lead.Title)")
    if ($lead.Why) { $report.Add("        why: $($lead.Why)") }
}
if ($Done.Count -gt 0) { $report.Add('  Exact changes made:') }
foreach ($line in $Done) { $report.Add("    - $line") }
$report.Add('')
$report.Add("##### B. OPEN LEADS, MOST LIKELY FIRST ($($open.Count)) - do one, check the score, then the next #####")
if ($open.Count -eq 0) { $report.Add('  (none found - send this file anyway, the inventory below may still show something)') }
$rank = 0
foreach ($lead in $open) {
    $rank++
    $report.Add("  $rank. [$($lead.Score)] $($lead.Title)")
    if ($lead.Why) { $report.Add("        why: $($lead.Why)") }
    if ($lead.Fix) { $report.Add("        fix: $($lead.Fix)") }
}
$report.Add('')
$report.Add('##### C. FULL INVENTORY (evidence) #####')
foreach ($line in $Inv) { $report.Add($line) }
[IO.File]::WriteAllLines($Out, $report)

Write-Host ''
Write-Host "Repaired automatically: $($repaired.Count)     Open leads: $($open.Count)" -ForegroundColor White
foreach ($lead in $repaired) { Write-Host "  FIXED [$($lead.Score)] $($lead.Title)" -ForegroundColor Green }
Write-Host ''
Write-Host 'Top open leads:' -ForegroundColor Yellow
$rank = 0
foreach ($lead in @($open | Select-Object -First 12)) {
    $rank++
    Write-Host "  $rank. [$($lead.Score)] $($lead.Title)" -ForegroundColor Yellow
    if ($lead.Fix) { Write-Host "       fix: $($lead.Fix)" -ForegroundColor Gray }
}
Write-Host ''
Write-Host "Full report: $Out" -ForegroundColor Cyan
Start-Process notepad.exe $Out