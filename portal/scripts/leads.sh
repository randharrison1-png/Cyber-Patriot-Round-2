#!/usr/bin/env bash
#
# leads.sh  -  lead finder for the Debian image of a CyberPatriot scenario.
#
# Run it AFTER the hardening script, when points are still missing. It is the
# Linux half of the pair: Leads.ps1 does the same job on Windows 11 and
# Windows Server 2022, and both write the same kind of report.
#
#   A. Already repaired  - check the scoring report two minutes later
#   B. Open leads        - most likely first, each with the reason and the fix
#   C. Full inventory    - the raw evidence
#
# Every finding gets a score from 0 to 100: an estimate that it is one of the
# missing scored checks.
#
# Safe repairs made automatically (skip them with --report-only):
#   - the SSH service (critical service) is started if it is stopped
#   - UFW is switched on if it is installed but inactive (SSH is allowed first)
#   - automatic updates are switched on if they are off
#   - wrong permissions on /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow
# Nothing is deleted, no account is changed, no service is disabled.
#
# Usage:
#   sudo bash leads.sh                 # report + safe repairs
#   sudo bash leads.sh --report-only   # change nothing (also skips "apt-get update")
#   sudo bash leads.sh --offline       # skip "apt-get update"
#
# Output: /var/log/hardening/leads-<host>-<timestamp>.txt
#         (a copy is placed in the home folder of the user who ran sudo)

set -u
set -o pipefail
export LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# =============================================================================
#  CONFIGURATION  -  from the README. Edit here for a different scenario.
# =============================================================================
AUTH_ADMINS=(pparker tstark ppotts hhogan nfury mhill pcoulson)
AUTH_USERS=(bbanner swilson sstrange slang cdanvers okoye kbishop ybelova
            jfoster nleeds mjwatson jtorres pcarter)

CRITICAL_UNITS=(ssh)              # services the README says must keep working
DISPLAY_MANAGER=lightdm           # README: the display manager stays LightDM
DEFAULT_BROWSER=chromium          # README: default browser
CCS_REGEX='[Cc]yber[Pp]atriot|CCS|ccsclient'

# unit name -> "score|why". Checked as NAME.service and NAME.socket.
declare -A RISKY_UNITS=(
    [apache2]="78|web server" [nginx]="78|web server" [lighttpd]="78|web server"
    [vsftpd]="86|FTP server" [proftpd]="86|FTP server" [pure-ftpd]="86|FTP server"
    [smbd]="76|Samba file sharing" [nmbd]="70|Samba name service" [samba-ad-dc]="70|Samba domain controller"
    [nfs-server]="74|NFS file sharing" [nfs-kernel-server]="74|NFS file sharing" [rpcbind]="62|RPC port mapper"
    [named]="72|DNS server" [bind9]="72|DNS server" [inetd]="80|inetd super-server" [xinetd]="80|xinetd super-server"
    [openbsd-inetd]="80|inetd super-server" [telnet]="88|Telnet server" [snmpd]="78|SNMP polling (README: no polling tools)"
    [mariadb]="72|database server" [mysql]="72|database server" [postgresql]="72|database server"
    [dovecot]="72|mail server" [postfix]="60|mail server" [exim4]="50|mail server" [squid]="72|proxy server"
    [tftpd-hpa]="80|TFTP server" [atftpd]="80|TFTP server" [rsync]="62|rsync daemon" [nis]="70|NIS" [ypbind]="70|NIS"
    [minidlna]="74|media server" [transmission-daemon]="80|BitTorrent daemon" [x11vnc]="84|VNC remote access"
    [xrdp]="78|remote desktop server" [vncserver]="84|VNC remote access" [tightvncserver]="84|VNC remote access"
    [avahi-daemon]="46|zero-configuration networking" [cups]="34|printing" [cups-browsed]="40|printer discovery"
    [inspircd]="80|IRC server" [ngircd]="80|IRC server" [znc]="78|IRC bouncer" [tor]="84|Tor" [pptpd]="74|VPN server"
    [openvpn]="56|VPN" [cockpit]="70|web admin console (README: no centralized maintenance tools)"
    [webmin]="76|web admin console" [salt-minion]="70|central management agent" [puppet]="70|central management agent"
    [nagios-nrpe-server]="72|polling agent (README: no polling tools)" [zabbix-agent]="72|polling agent (README: no polling tools)"
    [docker]="56|container engine" [bluetooth]="30|Bluetooth" [minetest-server]="80|game server"
)

TOOL_PKG_REGEX='^(john|john-data|hydra|hydra-gtk|nmap|zenmap|ncat|ndiff|netcat|netcat-traditional|nikto|sqlmap|aircrack-ng|wireshark.*|tshark|ophcrack.*|hashcat.*|medusa|ettercap.*|dsniff|kismet.*|fcrackzip|crack|pdfcrack|rarcrack|cmospwd|yersinia|hping3|masscan|zmap|metasploit.*|beef.*|burpsuite|proxychains.*|tor|torbrowser-launcher|hunt|sucrack|chntpw|macchanger|reaver|bully|wifite|bettercap|responder|mimikatz|crunch|cewl|dirb|gobuster|wfuzz|recon-ng|sslstrip|driftnet|tcpflow|ngrep|p0f|arp-scan|nbtscan|enum4linux|socat|weevely|backdoor-factory|logkeys|keylogger.*)$'
REMOTE_PKG_REGEX='^(telnetd|inetutils-telnetd|rsh-server|rsh-client|rsh-redone-.*|talk|talkd|ntalk|nis|x11vnc|tightvncserver|tigervnc-.*server|vnc4server|vino|xrdp|anydesk|teamviewer.*|rustdesk|remmina.*|transmission.*|deluge.*|qbittorrent.*|rtorrent|ktorrent|amule.*|vuze|frostwire|nicotine|ircd-.*|inspircd|ngircd|znc.*)$'
SERVER_PKG_REGEX='^(apache2|nginx|nginx-.*|lighttpd|vsftpd|proftpd.*|pure-ftpd.*|samba|nfs-kernel-server|bind9|snmpd|mariadb-server.*|mysql-server.*|postgresql|postgresql-[0-9].*|dovecot-.*|squid|tftpd-hpa|atftpd|openbsd-inetd|xinetd|minidlna|cockpit|webmin)$'
GAME_PKG_REGEX='^(aisleriot|gnome-mines|gnome-sudoku|gnome-mahjongg|gnome-chess|gnome-nibbles|gnome-robots|gnome-tetravex|gnome-klotski|gnome-taquin|gnome-2048|five-or-more|four-in-a-row|hitori|iagno|lightsoff|quadrapassel|swell-foop|tali|gnome-games|kpat|kmines|ksudoku|freeciv.*|wesnoth.*|minetest.*|supertux.*|0ad.*|nethack.*|bsdgames.*|openarena.*|xonotic.*|steam.*|lutris|frozen-bubble|pingus|hedgewars.*|teeworlds.*|nexuiz.*|sauerbraten.*|warzone2100.*|dopewars|endless-sky.*|manaplus.*|pinball.*|xbill|gnuchess|chromium-bsu.*|neverball.*|extremetuxracer.*|armagetronad.*|widelands.*|openttd.*|scummvm.*|mame.*|dosbox|kodi.*)$'
TOOL_NAME_REGEX='netcat|ncat|mimikatz|hashcat|john|ophcrack|pwdump|lazagne|hydra|medusa|nmap|zenmap|wireshark|ipscan|angryip|anydesk|teamviewer|vnc|keylog|metasploit|msfvenom|meterpreter|burpsuite|sqlmap|nikto|aircrack|ettercap|sharphound|bloodhound|rubeus|backdoor|trojan|rootkit|rockyou|wordlist|exploit|reverse.?shell|linpeas|pspy|chisel'

MEDIA_EXT='mp3|mp4|m4a|m4v|wav|wma|wmv|avi|mkv|mov|flac|ogg|oga|opus|aac|mpg|mpeg|flv|webm|mid|midi'
IMAGE_EXT='jpg|jpeg|png|gif|bmp|webp'
ARCHIVE_EXT='zip|rar|7z|tar|gz|tgz|bz2|xz|iso'
PROGRAM_EXT='sh|py|pl|rb|php|exe|msi|bat|deb|rpm|elf|bin|jar|run|appimage|pcap|pcapng|torrent'
TEXT_EXT='txt|csv|log|ini|cfg|conf|xml|json|md|rtf|lst|list|bak|old|sql'
SCAN_ROOTS=(/home /root /srv /var/www /opt /tmp /var/tmp /media /mnt)
SKIP_NAME_REGEX='Forensics|README|CyberPatriot|Scoring|^harden-|^leads'

SUID_NEVER='^(bash|dash|sh|zsh|ksh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|find|vim.*|vi|nano|less|more|awk|gawk|mawk|cp|mv|env|nmap|tar|sed|cat|tee|dd|nc|ncat|socat|php[0-9.]*|node|lua[0-9.]*|gdb|strace|tcpdump|wget|curl|chmod|chown)$'
SUSPICIOUS='(^|[^[:alnum:]_./-])(nc|ncat|netcat|socat)([[:space:]]|$)|/dev/(tcp|udp)/|bash[[:space:]]+-i|mkfifo|base64[[:space:]]+(-d|--decode)|(curl|wget)[^|;]*[|][[:space:]]*(ba)?sh|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|/tmp/|/dev/shm/|chmod[[:space:]]+[0-7]*[ug]?[+]s|useradd|adduser|chpasswd|authorized_keys'

# key=wanted value|score
SYSCTL_WANT=(
    "net.ipv4.ip_forward=0|62" "net.ipv4.tcp_syncookies=1|62" "kernel.randomize_va_space=2|60"
    "net.ipv4.conf.all.accept_redirects=0|46" "net.ipv4.conf.default.accept_redirects=0|40"
    "net.ipv4.conf.all.send_redirects=0|44" "net.ipv4.conf.all.accept_source_route=0|46"
    "net.ipv4.conf.all.rp_filter=1|42" "net.ipv4.conf.all.log_martians=1|40"
    "net.ipv4.icmp_echo_ignore_broadcasts=1|44" "net.ipv6.conf.all.accept_redirects=0|40"
    "kernel.dmesg_restrict=1|36" "fs.suid_dumpable=0|40" "fs.protected_hardlinks=1|36" "fs.protected_symlinks=1|36"
)

# =============================================================================
#  PLUMBING
# =============================================================================
REPORT_ONLY=0
OFFLINE=0
for arg in "$@"; do
    case "$arg" in
        --report-only|--audit) REPORT_ONLY=1 ;;
        --offline)             OFFLINE=1 ;;
        -h|--help)             sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $arg  (try --help)"; exit 2 ;;
    esac
done
if [[ $(id -u) -ne 0 ]]; then
    echo "Run this with sudo:  sudo bash $0"
    exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
HOST=$(hostname 2>/dev/null || echo host)
LOG_DIR=/var/log/hardening
mkdir -p "$LOG_DIR"
OUT="$LOG_DIR/leads-$HOST-$STAMP.txt"
INV=$(mktemp)
trap 'rm -f "$INV"' EXIT

L_SCORE=(); L_TITLE=(); L_WHY=(); L_FIX=(); L_REPAIRED=()
DONE=()

note() { printf '%s\n' "${1:-}" >>"$INV"; }
head_() {
    note ""
    note "===== $1 ====="
    printf '\033[36mChecking: %s\033[0m\n' "$1"
}
# lead SCORE TITLE [WHY] [FIX] [REPAIRED]
lead() {
    L_SCORE+=("$1"); L_TITLE+=("$2"); L_WHY+=("${3:-}"); L_FIX+=("${4:-}"); L_REPAIRED+=("${5:-0}")
    note "  >> LEAD ($1): $2"
}
# try_fix "description" command...   -> returns 0 when the repair was made
try_fix() {
    local what=$1
    shift
    [[ $REPORT_ONLY -eq 1 ]] && return 1
    if "$@" >/dev/null 2>&1; then
        DONE+=("$what")
        note "  FIXED: $what"
        printf '\033[32m  FIXED: %s\033[0m\n' "$what"
        return 0
    fi
    note "  could not fix: $what"
    return 1
}
have()       { command -v "$1" >/dev/null 2>&1; }
in_list()    { local x=$1 y; shift; for y in "$@"; do [[ $x == "$y" ]] && return 0; done; return 1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
# True when the file belongs to an installed package (handles merged /usr).
owned_by_pkg() {
    local p=$1 real
    dpkg -S "$p" >/dev/null 2>&1 && return 0
    real=$(readlink -f "$p" 2>/dev/null || echo "$p")
    dpkg -S "$real" >/dev/null 2>&1 && return 0
    dpkg -S "${real#/usr}" >/dev/null 2>&1 && return 0
    dpkg -S "/usr$real" >/dev/null 2>&1 && return 0
    return 1
}
unit_exists() { systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"; }
unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
unit_enabled() { [[ $(systemctl is-enabled "$1" 2>/dev/null) == enabled ]]; }
active_lines() { grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null; }

ALL_AUTH=("${AUTH_ADMINS[@]}" "${AUTH_USERS[@]}")
RUN_USER=${SUDO_USER:-root}

echo
echo "Lead finder for $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}") - this takes a few minutes."
[[ $REPORT_ONLY -eq 1 ]] && echo "Report-only mode: nothing will be changed."

# =============================================================================
#  1. ACCOUNTS, GROUPS, SUDO
# =============================================================================
head_ "Accounts"
no_expiry=()
while IFS=: read -r name _ uid gid _ home shell; do
    hash=$(awk -F: -v u="$name" '$1==u {print $2}' /etc/shadow 2>/dev/null)
    maxdays=$(awk -F: -v u="$name" '$1==u {print $5}' /etc/shadow 2>/dev/null)
    state=password
    case "$hash" in
        "")      state="NO PASSWORD" ;;
        '!'*|'*'*) state=locked ;;
    esac
    is_login_shell=0
    [[ $shell =~ /(bash|sh|zsh|dash|ksh|fish)$ ]] && is_login_shell=1

    if [[ $uid -eq 0 && $name != root ]]; then
        note "$name  uid=$uid  shell=$shell  [$state]"
        lead 92 "Account '$name' has user ID 0 (it is a second root)" "a hidden administrator account" "sudo userdel -f $name   (or change its UID in /etc/passwd)"
        continue
    fi
    if [[ $uid -ge 1000 && $uid -lt 60000 ]]; then
        note "$name  uid=$uid  home=$home  shell=$shell  [$state]  max password age=${maxdays:-none}"
        if ! in_list "$name" "${ALL_AUTH[@]}"; then
            lead 90 "Account '$name' is not on the README list" "unauthorized users are scored on every image" "sudo userdel -r $name"
            continue
        fi
        [[ $state == "NO PASSWORD" ]] && lead 85 "Account '$name' has no password at all" "the README says all accounts must be password protected" "sudo passwd $name"
        [[ $state == locked && $name != "$RUN_USER" ]] && lead 50 "Authorized account '$name' is locked" "authorized users must be able to log in" "sudo passwd $name   (sets a password and unlocks it)"
        [[ $hash == '$1$'* ]] && lead 55 "Account '$name' has a weak MD5 password hash" "old hashing scheme" "sudo passwd $name"
        [[ $is_login_shell -eq 0 ]] && lead 55 "Authorized account '$name' has no login shell ($shell)" "the README says authorized users must be able to log in over SSH" "sudo usermod -s /bin/bash $name"
        if [[ -z $maxdays || $maxdays -gt 90 ]]; then no_expiry+=("$name"); fi
        continue
    fi
    # system accounts
    [[ $name == root || $name == sync ]] && continue
    [[ $name =~ $CCS_REGEX ]] && continue
    if [[ $is_login_shell -eq 1 ]]; then
        note "$name  uid=$uid  shell=$shell  [$state]   (system account)"
        lead 62 "System account '$name' (uid $uid) has a login shell: $shell" "service accounts should not be able to log in" "sudo usermod -s /usr/sbin/nologin $name"
    fi
    if [[ $state != locked ]]; then
        lead 64 "System account '$name' (uid $uid) has a usable password" "service accounts should be locked" "sudo passwd -l $name"
    fi
done </etc/passwd
missing=()
for name in "${ALL_AUTH[@]}"; do
    getent passwd "$name" >/dev/null 2>&1 || missing+=("$name")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    lead 68 "${#missing[@]} authorized account(s) do not exist: ${missing[*]}" "the README lists them; a missing authorized user can be a scored item" "sudo adduser NAME   (once per missing account)"
fi
if [[ ${#no_expiry[@]} -gt 0 ]]; then
    lead 52 "${#no_expiry[@]} account(s) have no password expiry within 90 days: ${no_expiry[*]}" "password aging is a classic scored item" "sudo chage -M 90 -m 1 -W 7 NAME   (once per account)"
fi
root_hash=$(awk -F: '$1=="root" {print $2}' /etc/shadow 2>/dev/null)
note "root password state: $([[ $root_hash == '!'* || $root_hash == '*'* ]] && echo locked || echo SET)"
if [[ -n $root_hash && $root_hash != '!'* && $root_hash != '*'* ]]; then
    lead 48 "The root account has a password (direct root login is possible)" "administrators should use sudo" "sudo passwd -l root   (only after you confirm sudo works for your account)"
fi

note ""
admin_group=sudo
getent group sudo >/dev/null 2>&1 || admin_group=wheel
members=$(getent group "$admin_group" | cut -d: -f4 | tr ',' ' ')
admin_gid=$(getent group "$admin_group" | cut -d: -f3)
primary=$(awk -F: -v g="$admin_gid" '$4==g {print $1}' /etc/passwd | tr '\n' ' ')
note "Group '$admin_group': $members $primary"
for m in $members $primary; do
    in_list "$m" "${AUTH_ADMINS[@]}" || lead 90 "'$m' is in the $admin_group group but is not an authorized administrator" "extra administrators are scored on every image" "sudo gpasswd -d $m $admin_group"
done
for a in "${AUTH_ADMINS[@]}"; do
    getent passwd "$a" >/dev/null 2>&1 || continue
    in_list "$a" $members $primary || lead 68 "Authorized administrator '$a' is not in the $admin_group group" "" "sudo usermod -aG $admin_group $a"
done
for g in root adm shadow disk docker lxd admin wheel staff; do
    [[ $g == "$admin_group" ]] && continue
    gm=$(getent group "$g" 2>/dev/null | cut -d: -f4 | tr ',' ' ')
    [[ -z $gm ]] && continue
    note "Group '$g': $gm"
    for m in $gm; do
        [[ $m =~ $CCS_REGEX ]] && continue
        if [[ $g == adm ]] && in_list "$m" "${AUTH_ADMINS[@]}"; then continue; fi
        score=66
        [[ $g == adm || $g == staff ]] && score=42
        lead "$score" "'$m' is a member of the privileged group '$g'" "these groups give root-level or log access" "sudo gpasswd -d $m $g"
    done
done

note ""
for f in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f $f ]] || continue
    while IFS= read -r line; do
        note "$f: $line"
        [[ $line =~ $CCS_REGEX ]] && continue
        if [[ $line =~ NOPASSWD|\!authenticate ]]; then
            lead 82 "sudo without a password: '$line'  ($f)" "a classic scored item" "sudo visudo -f $f   (delete NOPASSWD: or the whole line)"
        elif [[ $line =~ ^[[:space:]]*Defaults.*(\!env_reset|visiblepw|\!use_pty) ]]; then
            lead 50 "Weak sudo default: '$line'  ($f)" "" "sudo visudo -f $f"
        elif [[ $line =~ ^[[:space:]]*(%?[A-Za-z0-9_.-]+)[[:space:]].*ALL ]]; then
            who=${BASH_REMATCH[1]}
            case "$who" in
                root|%sudo|%admin|%wheel|Defaults) ;;
                *) in_list "$who" "${AUTH_ADMINS[@]}" || lead 82 "sudo rights for '$who': '$line'  ($f)" "only authorized administrators should have sudo" "sudo visudo -f $f   (delete the line)" ;;
            esac
        fi
    done < <(active_lines "$f")
done

# =============================================================================
#  2. PASSWORD POLICY AND LOCKOUT
# =============================================================================
head_ "Password policy"
defs() { awk -v k="$1" '$1==k {print $2}' /etc/login.defs 2>/dev/null | tail -n1; }
max=$(defs PASS_MAX_DAYS); min=$(defs PASS_MIN_DAYS); warn=$(defs PASS_WARN_AGE)
note "login.defs: PASS_MAX_DAYS=$max PASS_MIN_DAYS=$min PASS_WARN_AGE=$warn ENCRYPT_METHOD=$(defs ENCRYPT_METHOD)"
[[ -z $max || $max -gt 90 ]] && lead 68 "PASS_MAX_DAYS is '${max:-unset}' in /etc/login.defs" "maximum password age is a classic scored item" "sudo nano /etc/login.defs   (set PASS_MAX_DAYS 90)"
[[ -z $min || $min -lt 1 ]] && lead 58 "PASS_MIN_DAYS is '${min:-unset}' in /etc/login.defs" "minimum password age is a classic scored item" "sudo nano /etc/login.defs   (set PASS_MIN_DAYS 1)"
[[ -z $warn || $warn -lt 7 ]] && lead 44 "PASS_WARN_AGE is '${warn:-unset}' in /etc/login.defs" "" "sudo nano /etc/login.defs   (set PASS_WARN_AGE 7)"

cp_file=/etc/pam.d/common-password
ca_file=/etc/pam.d/common-auth
while IFS= read -r line; do note "common-password: $line"; done < <(active_lines "$cp_file")
while IFS= read -r line; do note "common-auth: $line"; done < <(active_lines "$ca_file")
if ! active_lines "$cp_file" | grep -qE 'pam_pwquality|pam_cracklib'; then
    lead 72 "No password complexity module in $cp_file" "password complexity is scored on these images" "sudo apt install libpam-pwquality   (then run: sudo pam-auth-update)"
else
    minlen=$( { active_lines /etc/security/pwquality.conf; cat /etc/security/pwquality.conf.d/*.conf 2>/dev/null; } | sed -nE 's/^[[:space:]]*minlen[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' | tail -n1)
    [[ -z $minlen ]] && minlen=$(active_lines "$cp_file" | grep -oE 'minlen=[0-9]+' | tail -n1 | cut -d= -f2)
    note "pwquality minlen=${minlen:-default(8)}"
    [[ -z $minlen || $minlen -lt 10 ]] && lead 68 "Minimum password length is ${minlen:-8 (default)}" "minimum length was scored on the Server image" "sudo nano /etc/security/pwquality.conf   (set minlen = 14)"
fi
active_lines "$cp_file" | grep -qE 'remember=|pam_pwhistory' || lead 50 "No password history is kept" "password history is a classic scored item" "add 'remember=5' to the pam_unix.so line in $cp_file"
if grep -hE '^[^#]*pam_unix\.so.*nullok' "$ca_file" "$cp_file" >/dev/null 2>&1; then
    lead 72 "Empty passwords are accepted (nullok in PAM)" "a classic scored item" "sudo nano $ca_file   (remove the word nullok)"
fi
active_lines "$ca_file" | grep -qE 'pam_faillock|pam_tally2' || lead 68 "No account lockout after failed logins" "account lockout is a classic scored item" "sudo pam-auth-update   (enable faillock), or add pam_faillock lines to $ca_file"

# =============================================================================
#  3. SSH (critical service)
# =============================================================================
head_ "SSH"
ssh_port=22
if ! have sshd; then
    lead 86 "The SSH server is not installed, but it is the critical service" "a critical service that is down costs points" "sudo apt install openssh-server"
else
    if ! unit_active ssh && ! unit_active sshd && ! unit_active ssh.socket; then
        fixed=0
        try_fix "SSH service started and enabled" sh -c 'systemctl unmask ssh; systemctl enable --now ssh' && fixed=1
        lead 88 "The SSH service is not running, but it is the critical service" "a critical service that is down costs points" "sudo systemctl enable --now ssh" "$fixed"
    fi
    mkdir -p /run/sshd 2>/dev/null
    eff=$(sshd -T 2>/dev/null)
    if [[ -z $eff ]]; then
        lead 80 "sshd configuration does not load: $(sshd -t 2>&1 | head -n1)" "SSH will not start with a broken configuration" "sudo sshd -t   (shows the bad line in /etc/ssh/sshd_config)"
    else
        sv() { printf '%s\n' "$eff" | awk -v k="$1" '$1==k {print $2; exit}'; }
        ssh_port=$(sv port); ssh_port=${ssh_port:-22}
        for k in port permitrootlogin permitemptypasswords passwordauthentication pubkeyauthentication x11forwarding maxauthtries \
                 hostbasedauthentication ignorerhosts permituserenvironment allowtcpforwarding logingracetime usepam; do
            note "$k $(sv "$k")"
        done
        printf '%s\n' "$eff" | grep -E '^(allowusers|allowgroups|denyusers|denygroups) ' | while IFS= read -r l; do note "$l"; done
        edit="sudo nano /etc/ssh/sshd_config   (set the line, save, then: sudo systemctl restart ssh)"
        [[ $(sv permitrootlogin) != no ]] && lead 82 "SSH allows root login (PermitRootLogin $(sv permitrootlogin))" "a classic scored item" "PermitRootLogin no  ->  $edit"
        [[ $(sv permitemptypasswords) == yes ]] && lead 82 "SSH allows empty passwords" "a classic scored item" "PermitEmptyPasswords no  ->  $edit"
        [[ $(sv hostbasedauthentication) == yes ]] && lead 60 "SSH host-based authentication is on" "" "HostbasedAuthentication no  ->  $edit"
        [[ $(sv ignorerhosts) == no ]] && lead 56 "SSH honours .rhosts files" "" "IgnoreRhosts yes  ->  $edit"
        [[ $(sv permituserenvironment) == yes ]] && lead 52 "SSH lets users set their environment" "" "PermitUserEnvironment no  ->  $edit"
        [[ $(sv x11forwarding) == yes ]] && lead 46 "SSH X11 forwarding is on" "" "X11Forwarding no  ->  $edit"
        [[ $(sv usepam) == no ]] && lead 50 "SSH does not use PAM (lockout and password rules are skipped)" "" "UsePAM yes  ->  $edit"
        mat=$(sv maxauthtries)
        [[ -n $mat && $mat -gt 4 ]] && lead 42 "SSH MaxAuthTries is $mat" "" "MaxAuthTries 4  ->  $edit"
        denied=$(printf '%s\n' "$eff" | awk '$1=="denyusers" {$1=""; print}')
        for u in $denied; do
            in_list "$u" "${ALL_AUTH[@]}" && lead 70 "SSH refuses the authorized user '$u' (DenyUsers)" "the README says authorized users must be able to log in over SSH" "$edit"
        done
    fi
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -f $f ]] || continue
        mode=$(stat -c '%a %U' "$f")
        note "$f  ($mode)"
        [[ $(stat -c '%a' "$f") =~ [2367]$ || $(stat -c '%U' "$f") != root ]] && lead 52 "$f can be changed by non-root users ($mode)" "" "sudo chown root:root $f && sudo chmod 600 $f"
    done
    while IFS= read -r f; do
        note "authorized_keys: $f  ($(wc -l <"$f") key line(s))"
        lead 60 "SSH key login is set up in $f" "a planted key is a backdoor that survives password changes" "sudo cat $f   (if you do not recognise the key: sudo rm $f)"
    done < <(find /root /home -maxdepth 3 -name 'authorized_keys*' -type f -size +0 2>/dev/null | head -n 20)
fi

# =============================================================================
#  4. FIREWALL
# =============================================================================
head_ "Firewall"
if ! have ufw; then
    lead 80 "UFW (the firewall) is not installed" "the firewall is scored on these images" "sudo apt install ufw && sudo ufw allow $ssh_port/tcp && sudo ufw enable"
else
    status=$(ufw status verbose 2>/dev/null)
    while IFS= read -r l; do note "$l"; done <<<"$status"
    if ! grep -q '^Status: active' <<<"$status"; then
        fixed=0
        try_fix "UFW switched on (SSH port $ssh_port allowed first)" sh -c "ufw allow $ssh_port/tcp && ufw --force enable" && fixed=1
        lead 84 "The firewall (UFW) is switched off" "the firewall is scored on these images" "sudo ufw allow $ssh_port/tcp && sudo ufw enable" "$fixed"
        status=$(ufw status verbose 2>/dev/null)
    fi
    if grep -q '^Status: active' <<<"$status"; then
        grep -qE '^Default: allow \(incoming\)' <<<"$status" && lead 66 "The firewall allows all incoming connections by default" "" "sudo ufw default deny incoming"
        grep -qE '^Logging: off' <<<"$status" && lead 40 "Firewall logging is off" "" "sudo ufw logging on"
        if ! grep -qiE "^($ssh_port(/tcp)?|OpenSSH|SSH|22(/tcp)?)[[:space:]].*ALLOW" <<<"$status"; then
            lead 76 "The firewall does not allow SSH (port $ssh_port), the critical service" "a critical service that cannot be reached costs points" "sudo ufw allow $ssh_port/tcp"
        fi
        while IFS= read -r l; do
            [[ $l =~ ^($ssh_port|22|OpenSSH|SSH) ]] && continue
            lead 48 "Firewall rule lets other traffic in: $(echo "$l" | tr -s ' ')" "only SSH is a listed service" "sudo ufw status numbered   (then: sudo ufw delete NUMBER)"
        done < <(grep -E 'ALLOW IN|ALLOW[[:space:]]+Anywhere' <<<"$status" | grep -v '(v6)')
    fi
fi

# =============================================================================
#  5. UPDATES AND SOFTWARE SOURCES
# =============================================================================
head_ "Updates"
p_lists=$(apt-config dump 2>/dev/null | sed -nE 's/^APT::Periodic::Update-Package-Lists "([^"]*)";/\1/p')
p_upg=$(apt-config dump 2>/dev/null | sed -nE 's/^APT::Periodic::Unattended-Upgrade "([^"]*)";/\1/p')
note "APT::Periodic::Update-Package-Lists=${p_lists:-unset}  Unattended-Upgrade=${p_upg:-unset}"
if ! pkg_installed unattended-upgrades; then
    lead 74 "Automatic updates are not installed (package unattended-upgrades)" "automatic updates were switched off on both Windows images of this scenario too" "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
elif [[ ${p_lists:-0} == 0 || ${p_upg:-0} == 0 ]]; then
    fixed=0
    write_auto() {
        [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] && cp -p /etc/apt/apt.conf.d/20auto-upgrades "$LOG_DIR/20auto-upgrades-before-$STAMP"
        printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >/etc/apt/apt.conf.d/20auto-upgrades
        # another file may still set the value to 0
        grep -lE 'APT::Periodic::(Update-Package-Lists|Unattended-Upgrade) "0"' /etc/apt/apt.conf.d/* 2>/dev/null | while IFS= read -r other; do
            cp -p "$other" "$LOG_DIR/$(basename "$other")-before-$STAMP"
            sed -i -E 's/(APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)) "0"/\1 "1"/' "$other"
        done
    }
    try_fix "Automatic updates switched on (/etc/apt/apt.conf.d/20auto-upgrades)" write_auto && fixed=1
    lead 80 "Automatic updates are switched off (lists=${p_lists:-unset}, upgrade=${p_upg:-unset})" "automatic updates were switched off on both Windows images of this scenario too" "sudo dpkg-reconfigure -plow unattended-upgrades   (answer Yes)" "$fixed"
fi
for t in apt-daily.timer apt-daily-upgrade.timer; do
    if unit_exists "$t" && ! unit_enabled "$t"; then
        lead 62 "The update timer $t is disabled" "daily update checks do not run" "sudo systemctl enable --now $t"
    fi
done

sources=$(cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | grep -E '^[[:space:]]*deb ' ; grep -hE '^URIs:' /etc/apt/sources.list.d/*.sources 2>/dev/null)
while IFS= read -r l; do [[ -n $l ]] && note "source: $l"; done <<<"$sources"
[[ -z $sources ]] && lead 66 "No package sources are configured" "the system cannot receive updates" "sudo nano /etc/apt/sources.list   (add the Debian bookworm, bookworm-updates and bookworm-security lines)"
if [[ -n $sources ]] && ! grep -qE 'security' <<<"$sources"; then
    lead 64 "The Debian security repository is missing from the package sources" "security updates cannot be installed" "add: deb http://security.debian.org/debian-security bookworm-security main"
fi
while IFS= read -r l; do
    [[ -z $l ]] && continue
    grep -qE 'debian\.org|ubuntu\.com|cdrom:|file:' <<<"$l" || lead 52 "Third-party package source: $l" "software from outside Debian" "check the files in /etc/apt/sources.list.d/"
done <<<"$sources"
held=$(apt-mark showhold 2>/dev/null | tr '\n' ' ')
[[ -n ${held// /} ]] && lead 62 "Packages are held back from updating: $held" "a held package never updates" "sudo apt-mark unhold $held"

if [[ $OFFLINE -eq 0 && $REPORT_ONLY -eq 0 ]]; then
    echo "  refreshing package lists (apt-get update) ..."
    timeout 180 apt-get update -qq >/dev/null 2>&1 || note "apt-get update failed or timed out (no internet?)"
fi
pending=$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null | awk '$1=="Inst" {print $2}')
count=$(grep -c . <<<"$pending")
note "Packages with an update waiting: $count"
while IFS= read -r l; do [[ -n $l ]] && note "    $l"; done <<<"$pending"
if [[ $count -gt 0 ]]; then
    key=$(grep -E "^($DEFAULT_BROWSER|firefox.*|openssh-.*|sudo|linux-image.*|libreoffice-core|thunderbird|bash|openssl|libssl.*|systemd|apt)$" <<<"$pending" | head -n 8 | tr '\n' ' ')
    lead 74 "$count package(s) have an update waiting${key:+ (including: $key)}" "software updates are scored on these images" "sudo apt update && sudo apt full-upgrade"
fi

if ! pkg_installed "$DEFAULT_BROWSER"; then
    lead 70 "The README browser ($DEFAULT_BROWSER) is not installed" "the README names it as the default browser" "sudo apt install $DEFAULT_BROWSER"
else
    cur=$(update-alternatives --query x-www-browser 2>/dev/null | awk '$1=="Value:" {print $2}')
    note "Default browser (x-www-browser): ${cur:-unset}"
    [[ -n $cur && $cur != *"$DEFAULT_BROWSER"* ]] && lead 55 "The default browser is $cur, not $DEFAULT_BROWSER" "the README names the default browser" "sudo update-alternatives --set x-www-browser /usr/bin/$DEFAULT_BROWSER"
fi

# =============================================================================
#  6. SERVICES
# =============================================================================
head_ "Services"
systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print "running: " $1}' >>"$INV"
systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print "enabled: " $1}' >>"$INV"
for name in "${!RISKY_UNITS[@]}"; do
    in_list "$name" "${CRITICAL_UNITS[@]}" && continue
    for unit in "$name.service" "$name.socket"; do
        state=""
        unit_active "$unit" && state="running"
        unit_enabled "$unit" && state="${state:+$state, }enabled at boot"
        [[ -z $state ]] && continue
        score=${RISKY_UNITS[$name]%%|*}
        why=${RISKY_UNITS[$name]#*|}
        lead "$score" "Service $unit is $state  ($why)" "the README lists only SSH as a needed service" "sudo systemctl disable --now $unit"
    done
done
for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /usr/local/lib/systemd/system/*.service; do
    [[ -f $f && ! -L $f ]] || continue
    [[ $f =~ $CCS_REGEX ]] && continue
    execs=$(grep -hE '^(ExecStart|ExecStartPre|ExecStartPost)=' "$f" 2>/dev/null | tr '\n' ' ')
    grep -qE "$CCS_REGEX" <<<"$execs" && continue
    note "local unit: $f  $execs"
    owned_by_pkg "$f" && continue
    unit=$(basename "$f")
    if grep -qE "$SUSPICIOUS" <<<"$execs"; then
        lead 90 "Hand-made service $unit runs a suspicious command: $execs" "a classic planted backdoor" "sudo systemctl disable --now $unit && sudo rm $f"
    else
        lead 72 "Hand-made service that belongs to no package: $unit  ($execs)" "not part of Debian; check what it runs" "sudo systemctl disable --now $unit   (then: sudo rm $f)"
    fi
done

# =============================================================================
#  7. PACKAGES AND LOOSE PROGRAMS
# =============================================================================
head_ "Installed software"
all_pkgs=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 ~ /^ii/ {print $2}')
note "Installed packages: $(grep -c . <<<"$all_pkgs")"
games=()
while IFS= read -r p; do
    [[ -z $p ]] && continue
    if [[ $p =~ $TOOL_PKG_REGEX ]]; then
        lead 88 "Hacking tool installed: $p" "the README prohibits hacking tools; each removal is usually its own check" "sudo apt purge $p"
    elif [[ $p =~ $REMOTE_PKG_REGEX ]]; then
        lead 80 "Remote-access, legacy or file-sharing package installed: $p" "not business software; only SSH is a listed service" "sudo apt purge $p"
    elif [[ $p =~ $SERVER_PKG_REGEX ]]; then
        lead 70 "Server software installed: $p" "the README lists only SSH as a needed service" "sudo apt purge $p"
    elif [[ $p =~ $GAME_PKG_REGEX ]]; then
        games+=("$p")
    fi
done <<<"$all_pkgs"
if [[ ${#games[@]} -gt 0 ]]; then
    lead 70 "${#games[@]} game package(s) installed: ${games[*]}" "the README prohibits non-work software; a removed game was scored on the Server image" "sudo apt purge ${games[*]}"
fi
if have snap; then
    while IFS= read -r l; do
        note "snap: $l"
        n=${l%% *}
        if grep -qiE "$TOOL_NAME_REGEX" <<<"$n"; then lead 86 "Prohibited snap package: $n" "the README prohibits hacking tools" "sudo snap remove $n"; fi
    done < <(snap list 2>/dev/null | tail -n +2)
fi
if have flatpak; then
    flatpak list --app --columns=application 2>/dev/null | while IFS= read -r l; do note "flatpak: $l"; done
fi
loose=0
for d in /opt/* /usr/local/bin/* /usr/local/sbin/* /usr/local/games/* /usr/games/*; do
    [[ -e $d ]] || continue
    [[ $d =~ $CCS_REGEX ]] && continue
    note "loose program: $d"
    base=$(basename "$d")
    if grep -qiE "$TOOL_NAME_REGEX" <<<"$base"; then
        lead 88 "Prohibited program outside the package system: $d" "a copy installed by hand does not show up in apt" "sudo rm -r $d"
    elif [[ $d == /usr/games/* ]]; then
        owned_by_pkg "$d" || lead 66 "Game installed by hand: $d" "the README prohibits non-work software" "sudo rm $d"
    elif ! owned_by_pkg "$d"; then
        loose=$((loose + 1))
        [[ $loose -le 20 ]] && lead 56 "Program installed by hand: $d" "not part of Debian; check what it is" "ls -l $d   (remove it if it is not business software)"
    fi
done
[[ $loose -gt 20 ]] && note "($((loose - 20)) more hand-installed programs are listed above without a lead)"

# =============================================================================
#  8. LISTENING PORTS
# =============================================================================
head_ "Listening ports"
if have ss; then
    while IFS= read -r l; do
        proto=$(awk '{print $1}' <<<"$l")
        addr=$(awk '{print $5}' <<<"$l")
        port=${addr##*:}
        prog=$(grep -oE 'users:\(\("[^"]+"' <<<"$l" | cut -d'"' -f2)
        pid=$(grep -oE 'pid=[0-9]+' <<<"$l" | head -n1 | cut -d= -f2)
        exe=""
        [[ -n $pid ]] && exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
        note "$proto $addr  $prog  $exe"
        [[ $addr == 127.* || $addr == "[::1]"* ]] && local_only=1 || local_only=0
        [[ "$prog $exe" =~ $CCS_REGEX ]] && continue
        if [[ $prog =~ ^(nc|ncat|netcat|nc\.traditional|nc\.openbsd|socat|bash|sh|dash|python[0-9.]*|perl|ruby|php[0-9.]*)$ ]]; then
            lead 92 "A shell or scripting tool is listening on $proto port $port: $prog (pid $pid)" "a running backdoor" "sudo kill $pid   (then find what starts it: cron, systemd, rc.local)"
        elif [[ -n $exe && $exe != *" (deleted)" ]] && ! owned_by_pkg "$exe"; then
            lead 84 "A program that belongs to no package is listening on $proto port $port: $exe" "a possible backdoor listener" "sudo kill $pid   (then remove $exe and whatever starts it)"
        elif [[ $local_only -eq 0 && $prog != sshd && $port =~ ^(21|23|25|53|69|80|110|111|139|143|443|445|631|2049|3306|3389|5432|5900|6667|8080)$ ]]; then
            lead 66 "A server is listening on $proto port $port: $prog" "the README lists only SSH as a needed service" "find its service in the Services section and disable it"
        fi
    done < <(ss -H -tulpn 2>/dev/null | sort -u -k1,1 -k5,5)
fi

# =============================================================================
#  9. THINGS THAT START BY THEMSELVES
# =============================================================================
head_ "Cron jobs, startup scripts, shell profiles"
check_cron_file() {
    local f=$1 kind=$2 line
    while IFS= read -r line; do
        note "$f: $line"
        [[ $line =~ ^[A-Za-z_]+= ]] && continue
        [[ $line =~ $CCS_REGEX ]] && continue
        if grep -qE "$SUSPICIOUS" <<<"$line"; then
            lead 88 "Suspicious scheduled command in $f: $line" "runs a shell, a download or a temp-folder program on a schedule" "sudo nano $f   (delete the line)"
        elif [[ $kind == user ]]; then
            lead 62 "Personal cron job in $f: $line" "users rarely need scheduled jobs on a workstation" "sudo crontab -u $(basename "$f") -e"
        elif [[ $kind == system && ! $line =~ run-parts|anacron ]]; then
            lead 66 "Extra line in /etc/crontab: $line" "not one of the standard run-parts lines" "sudo nano /etc/crontab"
        fi
    done < <(active_lines "$f")
}
check_cron_file /etc/crontab system
for f in /var/spool/cron/crontabs/*; do [[ -f $f ]] && check_cron_file "$f" user; done
for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [[ -f $f ]] || continue
    [[ $(basename "$f") == .placeholder ]] && continue
    [[ $f =~ $CCS_REGEX ]] && continue
    if owned_by_pkg "$f"; then note "$f (from a package)"; continue; fi
    lead 72 "Scheduled job file that belongs to no package: $f" "check what it runs" "sudo cat $f   (then: sudo rm $f)"
    [[ $f == /etc/cron.d/* ]] && check_cron_file "$f" crond
done
if have atq; then
    jobs=$(atq 2>/dev/null | grep -c .)
    [[ $jobs -gt 0 ]] && lead 58 "$jobs one-time job(s) are queued with 'at'" "a delayed command" "sudo atq   (then: sudo atrm NUMBER)"
fi
if [[ -f /etc/rc.local ]] && active_lines /etc/rc.local | grep -vqE '^[[:space:]]*exit 0'; then
    while IFS= read -r line; do note "/etc/rc.local: $line"; done < <(active_lines /etc/rc.local)
    lead 68 "/etc/rc.local runs commands at every boot" "a classic place for a backdoor" "sudo nano /etc/rc.local"
fi
if [[ -s /etc/ld.so.preload ]]; then
    lead 86 "/etc/ld.so.preload loads a library into every program: $(tr '\n' ' ' </etc/ld.so.preload)" "a rootkit technique" "sudo rm /etc/ld.so.preload"
fi
grep -qs 'LD_PRELOAD' /etc/environment && lead 82 "LD_PRELOAD is set in /etc/environment" "a library is injected into every program" "sudo nano /etc/environment"
for f in /etc/bash.bashrc /etc/profile /etc/profile.d/* /etc/environment /root/.bashrc /root/.profile /root/.bash_aliases \
         /home/*/.bashrc /home/*/.profile /home/*/.bash_aliases /home/*/.bash_login /home/*/.bash_logout; do
    [[ -f $f ]] || continue
    bad=$(active_lines "$f" | grep -E "/dev/(tcp|udp)/|bash[[:space:]]+-i|(^|[^[:alnum:]_.-])(nc|ncat|netcat|socat)[[:space:]]|base64[[:space:]]+(-d|--decode)|(curl|wget)[^|;]*[|][[:space:]]*(ba)?sh|alias[[:space:]]+(sudo|su|passwd|ssh|apt|apt-get|visudo)=|LD_PRELOAD" | head -n 3)
    [[ -z $bad ]] && continue
    note "$f: $bad"
    lead 80 "Suspicious line in the shell start-up file $f: $(head -n1 <<<"$bad")" "runs for a user at every login" "sudo nano $f   (delete the line)"
done
for f in /etc/xdg/autostart/*.desktop /home/*/.config/autostart/*.desktop; do
    [[ -f $f ]] || continue
    owned_by_pkg "$f" && continue
    cmd=$(sed -nE 's/^Exec=//p' "$f" | head -n1)
    [[ "$f $cmd" =~ $CCS_REGEX ]] && continue
    note "autostart: $f -> $cmd"
    lead 62 "Desktop autostart entry that belongs to no package: $f -> $cmd" "starts at every desktop login" "sudo rm $f"
done

# =============================================================================
#  10. PRIVILEGED FILES AND PERMISSIONS
# =============================================================================
head_ "Set-uid programs and file permissions"
while IFS= read -r f; do
    note "setuid: $f"
    base=$(basename "$f")
    if [[ $base =~ $SUID_NEVER ]]; then
        lead 90 "$f is set-uid root" "anyone who runs it becomes root; a classic planted backdoor" "sudo chmod u-s $f"
    elif ! owned_by_pkg "$f"; then
        lead 82 "Set-uid program that belongs to no package: $f" "a possible root backdoor" "sudo chmod u-s $f   (or remove it)"
    fi
done < <(find / -xdev \( -path /proc -o -path /sys -o -path /snap -o -path /var/lib/docker \) -prune -o -type f -perm -4000 -print 2>/dev/null)
if have getcap; then
    while IFS= read -r l; do
        note "capability: $l"
        grep -qE 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin)' <<<"$l" || continue
        f=${l%% *}
        [[ $(basename "$f") =~ $SUID_NEVER ]] || ! owned_by_pkg "$f" || continue
        lead 84 "Dangerous file capability: $l" "gives the program root powers without set-uid" "sudo setcap -r $f"
    done < <(getcap -r /usr/bin /usr/sbin /usr/local /opt /home 2>/dev/null)
fi

check_perm() {   # file  maximum-mode  owner:group  score
    local f=$1 want=$2 own=$3 score=$4 mode fixed=0
    [[ -e $f ]] || return 0
    mode=$(stat -c '%a' "$f")
    note "$f  mode $mode  $(stat -c '%U:%G' "$f")"
    # any permission bit beyond the wanted mode, or a different owner, is wrong
    if (( (8#$mode & ~8#$want) != 0 )) || [[ $(stat -c '%U' "$f") != root ]]; then
        try_fix "$f set to $own mode $want" sh -c "chown $own '$f' && chmod $want '$f'" && fixed=1
        lead "$score" "$f has loose permissions (mode $mode, owner $(stat -c '%U:%G' "$f"))" "a classic scored item" "sudo chown $own $f && sudo chmod $want $f" "$fixed"
    fi
}
shadow_group=root
getent group shadow >/dev/null 2>&1 && shadow_group=shadow
check_perm /etc/shadow  640 "root:$shadow_group" 80
check_perm /etc/gshadow 640 "root:$shadow_group" 70
check_perm /etc/passwd  644 root:root 80
check_perm /etc/group   644 root:root 70
if [[ -e /etc/sudoers ]] && (( (8#$(stat -c '%a' /etc/sudoers) & ~8#440) != 0 )); then
    lead 66 "/etc/sudoers has loose permissions (mode $(stat -c '%a' /etc/sudoers))" "" "sudo chmod 440 /etc/sudoers"
fi
while IFS= read -r f; do
    lead 70 "World-writable file in /etc: $f" "any user can change system configuration" "sudo chmod o-w $f"
done < <(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 10)
open_homes=()
for d in /home/*; do
    [[ -d $d ]] || continue
    (( (8#$(stat -c '%a' "$d") & 8#007) != 0 )) && open_homes+=("$d")
done
[[ ${#open_homes[@]} -gt 0 ]] && lead 36 "${#open_homes[@]} home folder(s) can be read by every user: ${open_homes[*]}" "" "sudo chmod 750 /home/NAME"

# =============================================================================
#  11. KERNEL AND NETWORK SETTINGS
# =============================================================================
head_ "Kernel and network settings"
for item in "${SYSCTL_WANT[@]}"; do
    pair=${item%%|*}; score=${item##*|}
    key=${pair%%=*}; want=${pair##*=}
    cur=$(sysctl -n "$key" 2>/dev/null)
    note "$key = ${cur:-unavailable}"
    [[ -z $cur || $cur == "$want" ]] && continue
    lead "$score" "Kernel setting $key is $cur (should be $want)" "network and kernel hardening values are classic scored items" "echo '$key = $want' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system"
done

# =============================================================================
#  12. LOGIN SCREEN AND MISCELLANEOUS
# =============================================================================
head_ "Login screen, hosts file, protection services"
dm=$(basename "$(cat /etc/X11/default-display-manager 2>/dev/null)" 2>/dev/null)
note "Display manager: ${dm:-none}"
[[ -n $dm && $dm != "$DISPLAY_MANAGER" ]] && lead 58 "The display manager is $dm, but the README says it must be $DISPLAY_MANAGER" "" "sudo dpkg-reconfigure $DISPLAY_MANAGER"
ldm=$(cat /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
while IFS= read -r l; do [[ -n $l ]] && note "lightdm: $l"; done <<<"$ldm"
grep -qiE '^[[:space:]]*allow-guest[[:space:]]*=[[:space:]]*true' <<<"$ldm" && lead 68 "The login screen allows a guest session (allow-guest=true)" "the guest account is a classic scored item" "sudo nano /etc/lightdm/lightdm.conf   (set allow-guest=false under [Seat:*])"
grep -qiE '^[[:space:]]*greeter-show-manual-login[[:space:]]*=[[:space:]]*false' <<<"$ldm" && note "(manual login is hidden on the greeter)"
grep -qiE '^[[:space:]]*autologin-user[[:space:]]*=' <<<"$ldm" && note "(auto-login is configured; left alone, the README says not to change the auto-login account)"

while IFS= read -r l; do
    note "hosts: $l"
    grep -qE "^(127\.0\.0\.1|127\.0\.1\.1|::1|f[ef]0[0-9]::[0-9a-f]*)[[:space:]]" <<<"$l" && continue
    lead 68 "The hosts file redirects a name: $l" "redirected update or security sites are a classic scored item" "sudo nano /etc/hosts   (delete the line)"
done < <(active_lines /etc/hosts)

if have aa-status; then
    aa-status --enabled 2>/dev/null || lead 44 "AppArmor is not enabled" "" "sudo systemctl enable --now apparmor"
fi
pkg_installed auditd || lead 40 "The audit daemon (auditd) is not installed" "auditing was scored on Windows; the Linux counterpart is auditd" "sudo apt install auditd"
if pkg_installed auditd && ! unit_active auditd; then lead 44 "auditd is installed but not running" "" "sudo systemctl enable --now auditd"; fi
for u in rsyslog systemd-journald; do
    unit_exists "$u.service" && ! unit_active "$u.service" && lead 50 "The logging service $u is not running" "" "sudo systemctl enable --now $u"
done

# =============================================================================
#  13. FILES
# =============================================================================
head_ "Files in home folders and other user-writable places"
media=(); images=(); archives=(); programs=()
cred_count=0; tool_count=0; listed=0
while IFS= read -r -d '' f; do
    base=${f##*/}
    [[ $base =~ $SKIP_NAME_REGEX ]] && continue
    ext=""
    if [[ $base == *.* ]]; then ext=${base##*.}; ext=${ext,,}; fi
    listed=$((listed + 1))
    if [[ $listed -le 4000 ]]; then printf '%s\n' "$f" >>"$INV"; fi
    if [[ $listed -eq 100000 ]]; then note "(more than 100000 files; the scan stops here)"; break; fi
    if [[ ${base,,} =~ $TOOL_NAME_REGEX && $tool_count -lt 20 ]]; then
        tool_count=$((tool_count + 1))
        lead 88 "File with the name of a prohibited tool: $f" "the README prohibits hacking tools; a prohibited archive was scored on the Server image" "sudo rm '$f'"
        continue
    fi
    if   [[ $ext =~ ^($MEDIA_EXT)$ ]];   then media+=("$f")
    elif [[ $ext =~ ^($IMAGE_EXT)$ ]];   then images+=("$f")
    elif [[ $ext =~ ^($ARCHIVE_EXT)$ ]]; then archives+=("$f")
    elif [[ $ext =~ ^($PROGRAM_EXT)$ ]]; then programs+=("$f")
    elif [[ $ext =~ ^($TEXT_EXT)$ || ( -z $ext && $f == /home/* ) ]]; then
        size=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
        [[ $size -gt 0 && $size -lt 524288 && $cred_count -lt 15 ]] || continue
        grep -Iq . "$f" 2>/dev/null || continue
        hit=$(grep -m1 -iE '(^|[^[:alnum:]])(pass(word|wd|phrase|code)?|pwd)s?[[:space:]]*([:=,;|]|$)' "$f" 2>/dev/null | cut -c1-70)
        if [[ -n $hit ]]; then
            cred_count=$((cred_count + 1))
            head -n 5 "$f" | cut -c1-120 | while IFS= read -r l; do note "      | $l"; done
            lead 88 "File that appears to hold passwords: $f   (line: $hit)" "exactly this - a plaintext password list - was the final missing check on the Server image" "sudo cat '$f'   (then: sudo rm '$f')"
        elif [[ ${base,,} =~ passw|credential|secret ]]; then
            cred_count=$((cred_count + 1))
            lead 78 "File whose name suggests stored passwords: $f" "a plaintext password list was the final missing check on the Server image" "sudo cat '$f'   (remove it if it holds passwords)"
        fi
    fi
done < <(find "${SCAN_ROOTS[@]}" -xdev \
            \( -path /opt/CyberPatriot -o -name .cache -o -name .config -o -name .local -o -name .mozilla -o -name snap \
               -o -name .thunderbird -o -name node_modules -o -name .git -o -path '/tmp/.*' -o -path '/tmp/systemd-*' -o -path '/tmp/snap*' \) -prune \
            -o -type f -print0 2>/dev/null)
group_lead() {   # score  kind  why  files...
    local score=$1 kind=$2 why=$3
    shift 3
    [[ $# -eq 0 ]] && return 0
    local sample
    sample=$(printf '%s | ' "${@:1:6}")
    lead "$score" "$# $kind found. Examples: ${sample% | }" "$why" "the full list is in the last inventory section; delete the ones that are not work related (sudo rm 'FILE')"
}
group_lead 80 "audio/video file(s)" "the README prohibits non-work media; removed media files were scored on Windows 11" "${media[@]}"
group_lead 58 "program/script file(s)" "planted tools often sit here as scripts or installers (ignore files you put there yourself)" "${programs[@]}"
group_lead 52 "archive file(s)" "a prohibited archive was scored on the Server image; open these and look" "${archives[@]}"
group_lead 34 "picture file(s)" "possibly non-work media; lower odds" "${images[@]}"

# =============================================================================
#  REPORT
# =============================================================================
mapfile -t order < <(for i in "${!L_SCORE[@]}"; do printf '%s %s\n' "${L_SCORE[$i]}" "$i"; done | sort -k1,1nr -k2,2n | awk '{print $2}')
repaired=0; open=0
for i in "${order[@]}"; do
    if [[ ${L_REPAIRED[$i]} -eq 1 ]]; then repaired=$((repaired + 1)); else open=$((open + 1)); fi
done
{
    echo "LEADS REPORT   $(date)   computer: $HOST   run as: $RUN_USER (sudo)"
    echo "System: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}")   profile: Debian workstation"
    if [[ $REPORT_ONLY -eq 1 ]]; then echo "Mode: report only (nothing changed)"; else echo "Mode: report + safe repairs"; fi
    echo "Score = estimated chance (0-100) that the item is one of the missing scored checks."
    echo
    echo "##### A. ALREADY REPAIRED BY THIS SCRIPT ($repaired) - check the scoring report in 2 minutes #####"
    [[ $repaired -eq 0 ]] && echo "  (nothing needed repair)"
    for i in "${order[@]}"; do
        [[ ${L_REPAIRED[$i]} -eq 1 ]] || continue
        echo "  [${L_SCORE[$i]}] ${L_TITLE[$i]}"
        [[ -n ${L_WHY[$i]} ]] && echo "        why: ${L_WHY[$i]}"
    done
    if [[ ${#DONE[@]} -gt 0 ]]; then
        echo "  Exact changes made:"
        for d in "${DONE[@]}"; do echo "    - $d"; done
    fi
    echo
    echo "##### B. OPEN LEADS, MOST LIKELY FIRST ($open) - do one, check the score, then the next #####"
    [[ $open -eq 0 ]] && echo "  (none found - send this file anyway, the inventory below may still show something)"
    rank=0
    for i in "${order[@]}"; do
        [[ ${L_REPAIRED[$i]} -eq 1 ]] && continue
        rank=$((rank + 1))
        echo "  $rank. [${L_SCORE[$i]}] ${L_TITLE[$i]}"
        [[ -n ${L_WHY[$i]} ]] && echo "        why: ${L_WHY[$i]}"
        [[ -n ${L_FIX[$i]} ]] && echo "        fix: ${L_FIX[$i]}"
    done
    echo
    echo "##### C. FULL INVENTORY (evidence) #####"
    cat "$INV"
} >"$OUT"
chmod 600 "$OUT"

copy=""
if [[ $RUN_USER != root ]]; then
    user_home=$(getent passwd "$RUN_USER" | cut -d: -f6)
    if [[ -d $user_home ]]; then
        copy="$user_home/$(basename "$OUT")"
        cp "$OUT" "$copy" && chown "$RUN_USER": "$copy" && chmod 600 "$copy"
    fi
fi

echo
echo "Repaired automatically: $repaired     Open leads: $open"
for i in "${order[@]}"; do
    [[ ${L_REPAIRED[$i]} -eq 1 ]] && printf '\033[32m  FIXED [%s] %s\033[0m\n' "${L_SCORE[$i]}" "${L_TITLE[$i]}"
done
echo
echo "Top open leads:"
rank=0
for i in "${order[@]}"; do
    [[ ${L_REPAIRED[$i]} -eq 1 ]] && continue
    rank=$((rank + 1))
    [[ $rank -gt 12 ]] && break
    printf '\033[33m  %s. [%s] %s\033[0m\n' "$rank" "${L_SCORE[$i]}" "${L_TITLE[$i]}"
    [[ -n ${L_FIX[$i]} ]] && echo "       fix: ${L_FIX[$i]}"
done
echo
echo "Full report: $OUT"
[[ -n $copy ]] && echo "Copy for you: $copy"
exit 0