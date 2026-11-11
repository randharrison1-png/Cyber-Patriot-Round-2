# CyberPatriot Round 2 — Command Reference

Quick reference for Windows 11, Windows Server 2022, Debian 12, and Cisco Packet Tracer.

**Repository scripts:** [Harden-Win11.ps1](Harden-Win11.ps1) | [Harden-Server2022.ps1](Harden-Server2022.ps1) | [harden-debian12.sh](harden-debian12.sh)

> **Before making changes:** Read the README **inside the competition image**, answer Forensics Questions, identify required users and services, and take a VM snapshot if permitted. The three scripts in this repository are tailored to the **Arc Foundry & Aerospace** training scenario, with hardcoded authorized users, passwords policies, and protected services. Do **not** blindly use them on another image. The audit options are intended to be non-remediating, but still review the scripts and environment first. Never disable the CyberPatriot scoring client. Only run software allowed by your competition rules.
>
> **Legend:** **READ** = inspection/verification; **CHANGE** = modifies the system. Commands with placeholders such as USERNAME, IP, IFACE, or PORT must be adapted.

## 1. Launch the repository scripts

Run Windows examples in **Windows PowerShell 5.1 as Administrator**, from the directory containing the downloaded script.

### Windows 11

~~~powershell
# READ — script audit (no hardening changes)
.\Harden-Win11.ps1 -AuditOnly

# CHANGE — only after reviewing image README, forensics, and script settings
.\Harden-Win11.ps1

# CHANGE — apply fixes without rotating account passwords
.\Harden-Win11.ps1 -PasswordScope None

# Other supported options: -SkipSoftwareUpdates -SkipFileScan
# -DeleteProhibited deletes instead of quarantining; avoid unless justified.
# -Force skips the forensics confirmation; use with caution.
~~~

If script execution is blocked, a **process-scoped** policy override (not machine-wide) is:

~~~powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
~~~

### Windows Server 2022

~~~powershell
# READ
.\Harden-Server2022.ps1 -AuditOnly

# CHANGE — after reviewing this image's README and script configuration
.\Harden-Server2022.ps1

# CHANGE — leave passwords untouched
.\Harden-Server2022.ps1 -PasswordScope None
~~~

The Server 2022 script is designed for an IIS web server and a share named **Handbook**. It is **not** intended for domain controllers. It may disable RDP by default. Confirm whether remote access is required before using remediation mode.

### Debian 12

Run these from the directory containing the file:

~~~bash
# READ — audit mode
sudo bash harden-debian12.sh --audit

# Show script help
bash harden-debian12.sh --help

# CHANGE — after README, forensics, account-list review, and snapshot
sudo bash harden-debian12.sh

# CHANGE — do not rotate passwords
sudo bash harden-debian12.sh --password-scope none

# Supported optional switches:
# --skip-upgrade --skip-file-scan --delete-prohibited --force
~~~

The Debian script retains SSH and LightDM and uses scenario-specific account lists. Do not purge packages, change PAM, or alter SSH settings without confirming required services and authorized users.

**Script logs:** Windows scripts write to C:\HardeningLogs; Debian script logs to /var/log/hardening and stores backups in /var/backups/hardening-*.

---

## 2. Windows 11 — PowerShell / CMD reference

Run PowerShell as Administrator when a command requires elevated access.

### Identity, users, groups, and passwords

| Purpose | Command | Mode |
|---|---|---|
| List local users | Get-LocalUser | READ |
| Show user details | Get-LocalUser -Name USERNAME | READ |
| Local administrators | Get-LocalGroupMember -Group Administrators | READ |
| Remote Desktop Users | Get-LocalGroupMember -Group "Remote Desktop Users" | READ |
| Password and lockout policy | net accounts | READ |
| Current account | whoami | READ |
| Group memberships / privileges | whoami /all | READ |
| Local groups | net localgroup | READ |

### Security settings

| Purpose | Command | Mode |
|---|---|---|
| Microsoft Defender status | Get-MpComputerStatus | READ |
| Defender preferences/exclusions | Get-MpPreference | READ |
| Firewall profiles | Get-NetFirewallProfile | READ |
| Enabled inbound firewall rules | Get-NetFirewallRule -Enabled True -Direction Inbound | READ |
| Windows update service | Get-Service wuauserv | READ |
| Security-relevant services | Get-Service WinDefend,mpssvc,TermService,EventLog | READ |
| User Account Control | Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | READ |
| RDP setting | Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | READ |
| SMBv1 feature | Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | READ |
| Local security policy console | secpol.msc | READ / GUI |
| Services console | services.msc | READ / GUI |
| Local users & groups console | lusrmgr.msc | READ / GUI (if available) |

### Software, startup, networking, and logs

| Purpose | Command | Mode |
|---|---|---|
| Available package updates | winget upgrade | READ |
| Installed software packages | winget list | READ |
| Windows system information | systeminfo | READ |
| IP address and DNS | ipconfig /all | READ |
| Established/listening connections | netstat -ano | READ |
| Listening TCP connections | Get-NetTCPConnection -State Listen | READ |
| Scheduled tasks | Get-ScheduledTask | READ |
| Process list | Get-Process | READ |
| Service list | Get-Service | READ |
| Recent system events | Get-WinEvent -LogName System -MaxEvents 20 | READ |
| Recent security events (admin may be required) | Get-WinEvent -LogName Security -MaxEvents 20 | READ |

Read the script's MANUAL / REVIEW summary and log before acting on findings. Avoid changing scoring-client services or deleting files before answering Forensics Questions.

---

## 3. Windows Server 2022 — PowerShell / CMD reference

All Windows 11 inspection commands above remain useful, plus:

| Purpose | Command | Mode |
|---|---|---|
| Windows Server roles and features | Get-WindowsFeature | READ |
| IIS web server role | Get-WindowsFeature Web-Server | READ |
| Web server service | Get-Service W3SVC | READ |
| SMB shares | Get-SmbShare | READ |
| Handbook share permissions | Get-SmbShareAccess -Name Handbook | READ |
| Handbook NTFS permissions | Get-Acl 'C:\Shares\Handbook' | READ |
| Test local HTTP port | Test-NetConnection -ComputerName localhost -Port 80 | READ |
| IIS browsing check (if WebAdministration installed) | Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/directoryBrowse' -Name enabled | READ |
| Listening ports | Get-NetTCPConnection -State Listen | READ |
| Local firewall profile | Get-NetFirewallProfile | READ |
| Windows share browsing | net share | READ |

**Required services in the repository scenario:** IIS HTTP service and the Handbook SMB share. Verify the actual README before changing firewall rules, IIS bindings, share access, or services. The server script specifically protects site content and C:\Shares\Handbook.

---

## 4. Debian 12 — Terminal reference

### Users, groups, and passwords

| Purpose | Command | Mode |
|---|---|---|
| Current user and groups | id | READ |
| Local account list | getent passwd | READ |
| Check a specific user | id USERNAME | READ |
| Sudo group members | getent group sudo | READ |
| Account password status | sudo passwd -S USERNAME | READ |
| Password aging | sudo chage -l USERNAME | READ |
| Failed-login account lockouts (if available) | sudo faillock --user USERNAME | READ |
| Sudoers syntax validation | sudo visudo -c | READ |
| Root equivalent UID 0 accounts | awk -F: '$3 == 0 {print $1}' /etc/passwd | READ |

### Services, SSH, and network security

| Purpose | Command | Mode |
|---|---|---|
| Running services | systemctl --type=service --state=running | READ |
| Service status | systemctl status SERVICE | READ |
| Enabled services | systemctl list-unit-files --type=service --state=enabled | READ |
| SSH daemon config validation | sudo /usr/sbin/sshd -t | READ |
| Effective SSH server configuration | sudo /usr/sbin/sshd -T | READ |
| SSH service | systemctl status ssh | READ |
| Firewall configuration | sudo ufw status verbose | READ |
| Firewall numbered rules | sudo ufw status numbered | READ |
| Listening TCP/UDP sockets | sudo ss -tulpen | READ |
| IP address | ip addr | READ |
| Routing table and default route | ip route | READ |
| DNS resolver | cat /etc/resolv.conf | READ |
| Kernel security settings | sysctl -a | READ |
| AppArmor status (if available) | sudo aa-status | READ |

### Packages, updates, logs, and files

| Purpose | Command | Mode |
|---|---|---|
| Debian release | cat /etc/os-release | READ |
| Kernel | uname -r | READ |
| Installed packages | dpkg -l | READ |
| Package status | dpkg -s PACKAGE | READ |
| Pending upgrades (based on cached package lists) | apt list --upgradable | READ |
| APT sources | cat /etc/apt/sources.list | READ |
| Recent system logs | journalctl -b -n 100 --no-pager | READ |
| SSH service journal | sudo journalctl -u ssh -n 50 --no-pager | READ |
| File permissions | ls -la PATH | READ |
| Path permissions across parent directories | namei -l PATH | READ |
| Scheduled system cron jobs | ls -la /etc/cron* | READ |
| Root cron entries | sudo crontab -l | READ |
| Check current APT package sources metadata | sudo apt update | CHANGE (package index) |
| Install available updates | sudo apt upgrade | CHANGE (packages) |

When changing Debian accounts, SSH, UFW, PAM, packages or file permissions, retain console access and verify that authorized users can still sign in. The repository hardening script uses backups; check its /var/backups/hardening-* directory when troubleshooting.

---

## 5. Cisco Packet Tracer — Router and switch reference

These commands are a **general IOS reference** drawn from the Packet Tracer questions, not from the Windows/Debian hardening scripts.

### From a Packet Tracer PC Command Prompt

| Purpose | Command |
|---|---|
| Show IP, gateway and DNS | ipconfig /all |
| Test IP reachability | ping IP |
| Trace network hops | tracert IP |
| SSH into managed network device | ssh -l USERNAME IP |
| Telnet into device, if authorized/configured | telnet IP |

### From router or switch privileged EXEC mode

Connect remotely, authenticate, then enter enable if necessary.

| Purpose | Cisco IOS command |
|---|---|
| Full running configuration | show running-config |
| IOS version and system image name | show version |
| IOS files and sizes | dir flash: |
| Interface IPs and status | show ip interface brief |
| Interface speed, MAC/BIA, queue, ARP timeout | show interfaces IFACE |
| Assigned VLAN access ports | show vlan brief |
| Trunk/native VLAN information | show interfaces trunk |
| Direct Cisco neighbors | show cdp neighbors |
| Neighbors and management IPs | show cdp neighbors detail |
| IP routing table/default route | show ip route |
| ARP IP-to-MAC bindings | show ip arp |
| Learned MACs by switchport | show mac address-table interface IFACE |
| ACL contents | show access-lists |
| ACL direction applied on an interface | show ip interface IFACE |
| Interface-specific configuration | show running-config |
| Inter-VLAN routing setting | show running-config \| include ip routing |
| Find router static routes | show running-config \| include ip route |
| Password encryption setting | show running-config \| include password-encryption |
| Enable secret hash type | show running-config \| include enable secret |

**Interpretation guide:**
- Routing table **C** = directly connected; **L** = local interface IP; **S** = static; **S*** = candidate default static route; **O** = OSPF; **R** = RIP.
- The default route destination is **0.0.0.0/0**; the address after **via** is the next-hop IP when a next-hop route is used.
- Interface **administratively down** = disabled by configuration. **up/up** = operating.
- **ip access-group 102 in** filters packets entering that interface; **out** filters packets leaving it.
- **encapsulation dot1Q 1 native** designates the native VLAN on a router subinterface; **dot1Q 1** without native is not the same statement.
- **Input queue 0/75/0/0** = current depth / maximum depth / drops / flushes.
- **show vlan brief** lists VLAN access ports; trunk ports generally do not appear in that access-port list.
- For exact default gateway values, check the clients' IP config and the routing device's VLAN interface or subinterface.

---

## 6. Suggested Round 2 workflow

1. Open the image README; record permitted users, required services, network settings, and prohibited software.
2. Answer Forensics Questions **before** removing users, files, or software.
3. Take a snapshot if permitted; record current score and connectivity.
4. Run read-only inspection commands and the appropriate script's audit mode.
5. Review each proposed change against the current image README. The repo scripts contain scenario-specific assumptions.
6. Make one controlled group of changes; check the score and confirm required services still work.
7. Read the script's **MANUAL / REVIEW / FAIL** report and inspect remaining items individually.
8. Recheck authorized logins, network access, firewall, antivirus, service availability, and scoring-client health.

**Rule of thumb:** A command being present in a hardening script does not make it safe for every image. The current image README and competition rules take priority.
