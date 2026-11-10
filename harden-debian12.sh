#!/usr/bin/env bash
#
# harden-debian12.sh
#
# Audits and hardens the Debian 12 workstation described in the
# "Arc Foundry & Aerospace" CyberPatriot training README.
#
# Each check reads the current state first, logs OK if it is already
# compliant, and fixes it if it is not. Everything is logged to
# /var/log/hardening. Originals of every file it edits are copied to
# /var/backups/hardening-<timestamp>. Items a script cannot safely decide are
# listed at the end as MANUAL / REVIEW.
#
# What it will NOT touch (README guidelines):
#   - the CCS Client service/process and /opt/CyberPatriot
#   - the password of the account that ran sudo / the LightDM auto-login account
#   - authorized users or their home directories
#   - time zone, date, time
#   - sshd stays enabled (critical service) and is hardened
#   - LightDM stays the display manager
#
# Usage:
#   sudo bash harden-debian12.sh --audit     # look first, change nothing
#   sudo bash harden-debian12.sh             # then fix
#
# Options:
#   --audit                 report what would change; make no changes
#   --password-scope SCOPE  all   (default) new password for every authorized
#                                 account except yours and the auto-login one
#                           users new password for standard users plus the
#                                 accounts in KNOWN_WEAK_ACCOUNTS
#                           none  do not change any passwords
#   --delete-prohibited     delete prohibited files instead of quarantining
#   --skip-upgrade          do not run apt upgrade
#   --skip-file-scan        skip the prohibited media / file scan
#   --force                 skip the Forensics Questions confirmation
#   -h, --help              show this help

set -u
set -o pipefail
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# =============================================================================
#  CONFIGURATION  -  taken from the README. Edit here for a different scenario.
# =============================================================================

AUTH_ADMINS=(pparker tstark ppotts hhogan nfury mhill pcoulson)

AUTH_USERS=(bbanner swilson sstrange slang cdanvers okoye kbishop ybelova
            jfoster nleeds mjwatson jtorres pcarter)

# Admins whose README password does not meet the secure-password policy.
KNOWN_WEAK_ACCOUNTS=(hhogan)

# Password policy
MIN_PASS_LEN=14
PASS_MAX_DAYS=90
PASS_MIN_DAYS=1
PASS_WARN_AGE=7
PASS_REMEMBER=5
LOCKOUT_DENY=5
LOCKOUT_SECONDS=1800

# README: every authorized user must be able to log in over SSH. With this set
# to 1, sshd also refuses everyone who is NOT on the authorized lists.
SSH_RESTRICT_TO_AUTHORIZED=1

# Services with no business purpose here. ssh and lightdm are deliberately
# absent. Management/polling agents are listed because the README says the
# company uses no centralized maintenance tools.
SERVICES_TO_DISABLE=(apache2 nginx lighttpd vsftpd proftpd pure-ftpd smbd nmbd samba-ad-dc
    nfs-server nfs-kernel-server rpcbind named bind9 inetd xinetd openbsd-inetd telnet snmpd
    mariadb mysql postgresql dovecot squid tftpd-hpa atftpd rsync nis ypbind minidlna
    transmission-daemon x11vnc xrdp xrdp-sesman avahi-daemon inspircd ngircd znc tor pptpd
    cockpit webmin salt-minion puppet nagios-nrpe-server zabbix-agent)

# Installed packages matching this are purged: hacking tools, remote-access
# and legacy servers, P2P clients, games.
PROHIBITED_PKG_REGEX='^(john|john-data|hydra|hydra-gtk|nmap|nmap-common|zenmap|ncat|ndiff|netcat|netcat-traditional|netcat-openbsd|nikto|sqlmap|aircrack-ng|wireshark.*|tshark|ophcrack.*|hashcat.*|medusa|ettercap.*|kismet.*|dsniff|fcrackzip|pdfcrack|rarcrack|sucrack|crack|crack-common|cewl|crunch|wifite|reaver|bully|pixiewps|hping3|masscan|yersinia|weevely|metasploit-framework|armitage|wapiti|skipfish|dirb|gobuster|wfuzz|nbtscan|enum4linux|smbmap|responder|bettercap.*|driftnet|logkeys|telnetd|inetutils-telnetd|rsh-server|rsh-redone-server|rsh-client|tftpd.*|atftpd|x11vnc|tightvncserver|tigervnc-standalone-server|xrdp|vino|transmission.*|deluge.*|qbittorrent.*|ktorrent.*|amule.*|rtorrent|freeciv.*|wesnoth.*|minetest.*|supertux.*|0ad.*|nethack.*|aisleriot|gnome-games|gnome-mines|gnome-sudoku|gnome-mahjongg|quadrapassel|kmines|ksudoku|steam.*|lutris|dosbox|openarena.*|xonotic.*|frozen-bubble|pingus|tor|torbrowser-launcher|proxychains.*)$'

# Non-work media (auto-removed from the scan roots below)
MEDIA_EXT_REGEX='^(mp3|mp4|m4a|m4v|wav|wma|wmv|avi|mkv|mov|flac|ogg|oga|opus|aac|mpg|mpeg|flv|webm)$'
# Only listed for you to review, never auto-removed
REVIEW_EXT_REGEX='^(jpg|jpeg|png|gif|bmp|zip|rar|7z|tar|gz|tgz|deb|exe|sh|py|pl|rb|elf|bin|pcap|pcapng)$'
SCAN_ROOTS=(/home /root /srv /var/www /tmp /var/tmp /media /mnt)
# Media found here is only reported (it may belong to installed software)
REVIEW_ROOTS=(/opt /usr/local /var /etc)

# Programs that must never be set-uid root
SUID_NEVER='^(bash|dash|sh|zsh|ksh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|find|vim.*|vi|nano|less|more|awk|gawk|mawk|cp|mv|env|nmap|tar|sed|cat|tee|dd)$'

SYSCTL_SETTINGS=(
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.ip_forward=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "net.ipv4.tcp_rfc1337=1"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"
    "kernel.randomize_va_space=2"
    "kernel.dmesg_restrict=1"
    "kernel.kptr_restrict=2"
    "kernel.sysrq=0"
    "kernel.yama.ptrace_scope=1"
    "fs.suid_dumpable=0"
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
)

SSHD_SETTINGS=(
    "PermitRootLogin no"
    "PermitEmptyPasswords no"
    "PasswordAuthentication yes"
    "PubkeyAuthentication yes"
    "HostbasedAuthentication no"
    "IgnoreRhosts yes"
    "PermitUserEnvironment no"
    "UsePAM yes"
    "StrictModes yes"
    "X11Forwarding no"
    "AllowTcpForwarding no"
    "AllowAgentForwarding no"
    "MaxAuthTries 4"
    "LoginGraceTime 60"
    "ClientAliveInterval 300"
    "ClientAliveCountMax 3"
    "LogLevel VERBOSE"
)
# Directives that could lock authorized users out; always commented out.
SSHD_ALSO_DISABLE=(AllowUsers DenyUsers AllowGroups DenyGroups)
SSHD_BEGIN="# --- BEGIN hardening script settings (first value wins; keep at top) ---"
SSHD_END="# --- END hardening script settings ---"

LOG_DIR=/var/log/hardening
QUARANTINE_DIR=/var/hardening-quarantine

# =============================================================================
#  PLUMBING
# =============================================================================

AUDIT=0
FORCE=0
PASSWORD_SCOPE=all
DELETE_PROHIBITED=0
SKIP_UPGRADE=0
SKIP_FILE_SCAN=0

STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$LOG_DIR/harden-$STAMP.log"
BACKUP_DIR="/var/backups/hardening-$STAMP"

N_OK=0; N_FIXED=0; N_WOULD=0; N_FAIL=0
MANUAL=()
REVIEW=()
NEW_PASS=""
APT_READY=0
PROTECTED=()
PASSWORD_TARGETS=()

log() {
    local level=$1; shift
    local msg=$* color=""
    case $level in
        OK)    color=$'\e[90m'; N_OK=$((N_OK + 1)) ;;
        FIXED) color=$'\e[32m'; N_FIXED=$((N_FIXED + 1)) ;;
        WOULD) color=$'\e[36m'; N_WOULD=$((N_WOULD + 1)) ;;
        FAIL)  color=$'\e[31m'; N_FAIL=$((N_FAIL + 1)) ;;
        WARN)  color=$'\e[33m' ;;
        HEAD)  color=$'\e[35m' ;;
    esac
    if [[ -t 1 ]]; then
        printf '%s[%-5s] %s\e[0m\n' "$color" "$level" "$msg"
    else
        printf '[%-5s] %s\n' "$level" "$msg"
    fi
    printf '[%-5s] %s\n' "$level" "$msg" >>"$LOG"
}

section() { echo; echo >>"$LOG"; log HEAD "===== $* ====="; }
manual()  { MANUAL+=("$*"); log WARN "MANUAL: $*"; }
review()  { REVIEW+=("$*"); }

# change "description" command [args...]   -> runs the command unless --audit
change() {
    local what=$1; shift
    if (( AUDIT )); then log WOULD "$what"; return 0; fi
    if "$@" >>"$LOG" 2>&1; then
        log FIXED "$what"
        return 0
    else
        log FAIL "$what (exit $?; details in $LOG)"
        return 1
    fi
}

in_list() {
    local needle=$1 item; shift
    for item in "$@"; do [[ $item == "$needle" ]] && return 0; done
    return 1
}

is_ccs()       { [[ $1 =~ [Cc][Cc][Ss][Cc]lient|[Cc]yber[Pp]atriot ]]; }
is_admin()     { in_list "$1" "${AUTH_ADMINS[@]}"; }
is_authorized(){ in_list "$1" "${AUTH_ADMINS[@]}" "${AUTH_USERS[@]}"; }
is_protected() { (( ${#PROTECTED[@]} )) && in_list "$1" "${PROTECTED[@]}"; }
user_exists()  { getent passwd "$1" >/dev/null 2>&1; }
pkg_installed(){ dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
pkg_owns()     { dpkg -S "$1" >/dev/null 2>&1 || dpkg -S "${1#/usr}" >/dev/null 2>&1; }

backup() {
    local f
    (( AUDIT )) && return 0
    for f in "$@"; do
        [[ -e $f ]] || continue
        mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
        mkdir -p "$BACKUP_DIR$(dirname "$f")"
        [[ -e $BACKUP_DIR$f ]] || cp -a "$f" "$BACKUP_DIR$f"
    done
}

# --- "key = value" files (pwquality.conf, faillock.conf, sysctl.conf) --------
get_kv() {  # file key
    awk -F= -v k="$2" '
        /^[[:space:]]*#/ { next }
        { n=$1; gsub(/[[:space:]]/, "", n)
          if (n == k) { v=$0; sub(/^[^=]*=/, "", v); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); out=v } }
        END { print out }' "$1" 2>/dev/null
}
_set_kv() {  # file key value
    local key_re=${2//./\\.}
    touch "$1"
    sed -i -E "/^[[:space:]]*${key_re}[[:space:]]*=/d" "$1"
    printf '%s = %s\n' "$2" "$3" >>"$1"
}
set_kv() {  # file key value
    local cur; cur=$(get_kv "$1" "$2")
    if [[ $cur == "$3" ]]; then log OK "$1: $2 = $3"; return 0; fi
    backup "$1"
    change "$1: set $2 = $3 (was ${cur:-not set})" _set_kv "$1" "$2" "$3"
}

# --- "KEY value" files (login.defs) -----------------------------------------
get_def() { awk -v k="$2" '$1 == k { v=$2 } END { print v }' "$1" 2>/dev/null; }
_set_def() {
    sed -i -E "/^[[:space:]]*$2[[:space:]]/d" "$1"
    printf '%s\t%s\n' "$2" "$3" >>"$1"
}
set_def() {  # file KEY value
    local cur; cur=$(get_def "$1" "$2")
    if [[ $cur == "$3" ]]; then log OK "$1: $2 $3"; return 0; fi
    backup "$1"
    change "$1: set $2 $3 (was ${cur:-not set})" _set_def "$1" "$2" "$3"
}

# --- ini files (lightdm.conf) -----------------------------------------------
get_ini() {  # file section key
    awk -v sec="[$2]" -v k="$3" '
        /^[[:space:]]*\[/ { t=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", t); insec=(t == sec); next }
        insec && !/^[[:space:]]*#/ {
            n=$0; sub(/=.*/, "", n); gsub(/[[:space:]]/, "", n)
            if (n == k) { v=$0; sub(/^[^=]*=/, "", v); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); out=v } }
        END { print out }' "$1" 2>/dev/null
}
_set_ini() {  # file section key value
    local tmp; tmp=$(mktemp)
    touch "$1"
    awk -v sec="[$2]" -v k="$3" -v v="$4" '
        /^[[:space:]]*\[/ {
            t=$0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", t); insec=(t == sec)
            print
            if (insec) { print k "=" v; seen=1 }
            next
        }
        insec && !/^[[:space:]]*#/ {
            n=$0; sub(/=.*/, "", n); gsub(/[[:space:]]/, "", n)
            if (n == k) next
        }
        { print }
        END { if (!seen) { print ""; print sec; print k "=" v } }' "$1" >"$tmp" \
        && cat "$tmp" >"$1"
    local rc=$?
    rm -f "$tmp"
    return $rc
}
set_ini() {  # file section key value
    local cur; cur=$(get_ini "$1" "$2" "$3")
    if [[ $cur == "$4" ]]; then log OK "$1 [$2]: $3=$4"; return 0; fi
    backup "$1"
    change "$1 [$2]: set $3=$4 (was ${cur:-not set})" _set_ini "$1" "$2" "$3" "$4"
}

apt_ready() {
    (( APT_READY == 1 )) && return 0
    (( APT_READY == 2 )) && return 1
    if apt-get update >>"$LOG" 2>&1; then APT_READY=1; return 0; fi
    APT_READY=2
    manual "apt-get update failed (no network, or a broken source). Fix /etc/apt/sources.list, then re-run this script."
    return 1
}
apt_do() { apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"; }
_apt_install() { apt_ready && apt_do install "$@"; }
ensure_pkg() {  # package [why]
    if pkg_installed "$1"; then log OK "Package $1 is installed"; return 0; fi
    change "Install package $1${2:+ ($2)}" _apt_install "$1"
}

disable_unit() {  # unit name without suffix
    local base=$1 suffix unit en act
    for suffix in service socket; do
        unit="$base.$suffix"
        is_ccs "$unit" && continue
        systemctl cat "$unit" >/dev/null 2>&1 || continue
        en=$(systemctl is-enabled "$unit" 2>/dev/null)
        act=$(systemctl is-active "$unit" 2>/dev/null)
        if [[ $act == active || $en == enabled || $en == enabled-runtime ]]; then
            change "Stop and disable $unit" systemctl disable --now "$unit"
        else
            log OK "$unit is not running or enabled"
        fi
    done
}

enable_unit() {  # unit
    local unit=$1
    systemctl cat "$unit" >/dev/null 2>&1 || { log WARN "$unit is not installed"; return 1; }
    if [[ $(systemctl is-active "$unit" 2>/dev/null) == active && $(systemctl is-enabled "$unit" 2>/dev/null) == enabled ]]; then
        log OK "$unit is enabled and running"
    else
        change "Enable and start $unit" systemctl enable --now "$unit"
    fi
}

password_is_strong() {
    local p=$1
    (( ${#p} >= MIN_PASS_LEN )) && [[ $p =~ [a-z] && $p =~ [A-Z] && $p =~ [0-9] && $p =~ [^a-zA-Z0-9] ]]
}

shadow_field() { awk -F: -v u="$1" -v f="$2" '$1 == u { print $f }' /etc/shadow; }

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

# =============================================================================
#  0. PRE-FLIGHT
# =============================================================================

preflight() {
    section "Pre-flight"
    log INFO "Mode: $( (( AUDIT )) && echo 'AUDIT ONLY (no changes)' || echo FIX )   Log: $LOG"

    local invoker=${SUDO_USER:-}
    [[ -z $invoker ]] && invoker=$(logname 2>/dev/null || true)
    [[ -z $invoker ]] && invoker=root
    local autologin
    autologin=$(grep -rhE '^[[:space:]]*autologin-user[[:space:]]*=' /etc/lightdm 2>/dev/null |
                tail -n1 | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]+$//')
    PROTECTED=("$invoker")
    [[ -n $autologin && $autologin != "$invoker" ]] && PROTECTED+=("$autologin")
    INVOKER=$invoker
    log INFO "Run by '$invoker'. Auto-login account: '${autologin:-none}'. Their passwords are never changed."

    if ! is_admin "$invoker" && (( ! FORCE )); then
        log FAIL "'$invoker' is not in AUTH_ADMINS. Stopping so the script cannot lock you out. Run it with sudo from your own account, fix the list, or use --force."
        exit 1
    fi

    if (( ! AUDIT && ! FORCE )); then
        echo
        echo "STOP. Before this script changes anything:"
        echo "  1. Read the whole README."
        echo "  2. Answer every Forensics Question on the Desktop. This script removes"
        echo "     users, packages and files that those questions may ask about."
        echo "  3. Take a VM snapshot."
        echo "  4. Keep this terminal open until you have tested sudo and SSH at the end."
        local answer
        read -r -p "Type YES to continue: " answer
        [[ $answer == YES ]] || { log INFO "Cancelled by operator."; exit 0; }
    fi

    local u
    case $PASSWORD_SCOPE in
        all)   for u in "${AUTH_ADMINS[@]}" "${AUTH_USERS[@]}"; do is_protected "$u" || PASSWORD_TARGETS+=("$u"); done ;;
        users) for u in "${AUTH_USERS[@]}" "${KNOWN_WEAK_ACCOUNTS[@]}"; do is_protected "$u" || PASSWORD_TARGETS+=("$u"); done ;;
        none)  ;;
    esac

    if (( ! AUDIT && ${#PASSWORD_TARGETS[@]} > 0 )); then
        local p1 p2
        while true; do
            read -r -s -p "New password for ${#PASSWORD_TARGETS[@]} accounts ($MIN_PASS_LEN+ chars with upper, lower, digit and symbol): " p1; echo
            read -r -s -p "Confirm password: " p2; echo
            if [[ $p1 != "$p2" ]]; then echo "Passwords do not match."; continue; fi
            if ! password_is_strong "$p1"; then echo "That password does not meet the policy this script is about to enforce."; continue; fi
            NEW_PASS=$p1
            break
        done
        log INFO "New password accepted. Write it down somewhere safe: it is not stored in the log."
    fi

    backup /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d \
           /etc/login.defs /etc/pam.d /etc/security /etc/ssh/sshd_config /etc/ssh/sshd_config.d \
           /etc/lightdm /etc/sysctl.conf /etc/sysctl.d /etc/apt/sources.list /etc/apt/apt.conf.d
    (( AUDIT )) || log INFO "Originals of edited files are saved under $BACKUP_DIR"
}

# =============================================================================
#  1. USER ACCOUNTS
# =============================================================================

_remove_user() {
    pkill -KILL -u "$1" 2>/dev/null
    sleep 1
    userdel "$1"
}
_remove_uid0_imposter() {
    sed -i -E "/^$1:/d" /etc/passwd /etc/shadow
}
_set_password() { printf '%s:%s\n' "$1" "$NEW_PASS" | chpasswd; }

users() {
    section "User accounts"
    local name uid shell home hash

    # Accounts with UID 0 that are not root
    while IFS=: read -r name _ uid _; do
        [[ $uid == 0 && $name != root ]] || continue
        if is_authorized "$name" || is_protected "$name"; then
            manual "Account '$name' has UID 0 (full root). It is an authorized account, so give it a normal UID by hand: usermod -u <new uid> $name"
        else
            change "Remove unauthorized UID 0 account '$name'" _remove_uid0_imposter "$name"
        fi
    done </etc/passwd

    # Unauthorized human accounts
    while IFS=: read -r name _ uid _ _ home shell; do
        (( uid >= 1000 && uid < 65534 )) || continue
        is_authorized "$name" && continue
        is_ccs "$name" && continue
        if is_protected "$name"; then
            log WARN "'$name' is not authorized but is the account in use; not removed"
            continue
        fi
        change "Remove unauthorized user '$name' (home $home is left on disk)" _remove_user "$name"
    done </etc/passwd

    # System accounts must not have a usable password
    while IFS=: read -r name _ uid _ _ home shell; do
        (( uid > 0 && uid < 1000 )) || continue
        is_authorized "$name" && continue
        hash=$(shadow_field "$name" 2)
        if [[ $hash != '!'* && $hash != '*'* ]]; then
            change "Lock system account '$name' (it has a usable or empty password)" passwd -l "$name"
        fi
        if [[ $shell != */nologin && $shell != */false && $shell != /bin/sync ]]; then
            review "System account '$name' (UID $uid) has login shell $shell"
        fi
    done </etc/passwd

    # Authorized accounts
    local today=$(( $(date +%s) / 86400 )) lastchg age cur_max cur_min cur_warn skip_max
    for name in "${AUTH_ADMINS[@]}" "${AUTH_USERS[@]}"; do
        if ! user_exists "$name"; then
            manual "Authorized account '$name' does not exist. Create it if the README or a Forensics Question asks for it."
            continue
        fi
        shell=$(getent passwd "$name" | cut -d: -f7)
        if [[ $shell == */nologin || $shell == */false ]]; then
            change "Give '$name' a login shell (was $shell; README requires SSH login for authorized users)" usermod -s /bin/bash "$name"
        fi

        hash=$(shadow_field "$name" 2)
        if in_list "$name" "${PASSWORD_TARGETS[@]+"${PASSWORD_TARGETS[@]}"}"; then
            change "Set a new strong password for '$name'" _set_password "$name"
        elif [[ -z $hash ]]; then
            manual "'$name' has NO password and was excluded from password changes. Set one: sudo passwd $name"
        elif [[ $hash == '!'* ]]; then
            review "Authorized account '$name' is locked (password hash starts with !)"
        elif [[ $hash == '$1$'* || $hash != '$'* ]]; then
            review "Authorized account '$name' has a weakly hashed password (MD5/DES); reset it"
        fi

        # password ageing
        cur_min=$(shadow_field "$name" 4); cur_max=$(shadow_field "$name" 5); cur_warn=$(shadow_field "$name" 6)
        skip_max=0
        if is_protected "$name"; then
            lastchg=$(shadow_field "$name" 3)
            if [[ $lastchg =~ ^[0-9]+$ ]] && (( lastchg > 0 )); then
                age=$(( today - lastchg ))
                if (( age >= PASS_MAX_DAYS - 2 )); then
                    skip_max=1
                    manual "Password for '$name' is $age days old. Its maximum age was NOT set, to avoid locking that account out. After changing that password run: sudo chage -M $PASS_MAX_DAYS $name"
                fi
            fi
        fi
        if [[ $cur_min == "$PASS_MIN_DAYS" && $cur_warn == "$PASS_WARN_AGE" && ( $cur_max == "$PASS_MAX_DAYS" || $skip_max == 1 ) ]]; then
            log OK "Password ageing for '$name' is set"
        elif (( skip_max )); then
            change "Set password ageing for '$name' (min $PASS_MIN_DAYS, warn $PASS_WARN_AGE)" chage -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$name"
        else
            change "Set password ageing for '$name' (min $PASS_MIN_DAYS, max $PASS_MAX_DAYS, warn $PASS_WARN_AGE)" \
                chage -m "$PASS_MIN_DAYS" -M "$PASS_MAX_DAYS" -W "$PASS_WARN_AGE" "$name"
        fi

        # home directory
        home=$(getent passwd "$name" | cut -d: -f6)
        if [[ -d $home ]]; then
            local mode owner
            mode=$(stat -c %a "$home"); owner=$(stat -c %U "$home")
            if (( (8#$mode & 8#027) != 0 )); then
                change "Tighten permissions on $home (was $mode)" chmod g-w,o-rwx "$home"
            fi
            [[ $owner == "$name" ]] || review "Home directory $home is owned by '$owner', not '$name'"
            [[ -s $home/.ssh/authorized_keys ]] && review "SSH authorized_keys present for '$name': $home/.ssh/authorized_keys"
            [[ -e $home/.rhosts ]] && change "Remove $home/.rhosts" rm -f "$home/.rhosts"
        fi
    done

    [[ -s /root/.ssh/authorized_keys ]] && review "root has SSH authorized_keys: /root/.ssh/authorized_keys (root must not log in)"
    [[ -e /etc/hosts.equiv ]] && { backup /etc/hosts.equiv; change "Remove /etc/hosts.equiv" rm -f /etc/hosts.equiv; }

    if awk -F: '$2 == "" { found=1 } END { exit !found }' /etc/passwd; then
        manual "/etc/passwd has an account with an empty password field (no 'x'). Run 'sudo pwconv' and set a password for it."
    fi
}

# =============================================================================
#  2. GROUPS AND SUDO
# =============================================================================

group_members() { getent group "$1" | cut -d: -f4 | tr ',' '\n' | sed '/^$/d'; }

_clean_sudoers_file() {  # file
    local f=$1 tmp admins
    admins=$(printf '%s\n' "${AUTH_ADMINS[@]}" | paste -sd'|')
    tmp=$(mktemp)
    awk -v admins="$admins" '
        BEGIN { n=split(admins, a, "|"); for (i=1; i<=n; i++) ok[a[i]]=1 }
        /^[[:space:]]*(#|$)/ || /[Cc]yber[Pp]atriot|CCS/ { print; next }
        /!authenticate/ { print "# removed by hardening script: " $0; next }
        {
            gsub(/NOPASSWD:[[:space:]]*/, "")
            first=$1
            if (first !~ /^(Defaults|root|%|@|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)/ && !(first in ok)) {
                print "# removed by hardening script: " $0; next
            }
            print
        }' "$f" >"$tmp" && cat "$tmp" >"$f"
    rm -f "$tmp"
}

_fix_sudoers() {
    local f
    for f in "$@"; do _clean_sudoers_file "$f"; done
    if ! visudo -c >/dev/null 2>&1; then
        echo "visudo -c failed after edit; restoring originals"
        for f in "$@"; do cp -a "$BACKUP_DIR$f" "$f"; done
        return 1
    fi
}

groups_and_sudo() {
    section "Groups and sudo"
    local m g name admins_re
    ensure_pkg sudo

    # sudo group = exactly the authorized administrators
    for m in $(group_members sudo); do
        if is_admin "$m"; then log OK "'$m' is an authorized administrator"; continue; fi
        if is_protected "$m"; then log WARN "'$m' is the account in use; left in sudo"; continue; fi
        change "Remove '$m' from the sudo group (not an authorized administrator)" gpasswd -d "$m" sudo
    done
    for name in "${AUTH_ADMINS[@]}"; do
        user_exists "$name" || continue
        group_members sudo | grep -qx "$name" || change "Add authorized administrator '$name' to the sudo group" gpasswd -a "$name" sudo
    done

    # other groups that grant root-equivalent access
    for g in admin wheel adm root shadow disk docker lxd; do
        getent group "$g" >/dev/null || continue
        for m in $(group_members "$g"); do
            is_protected "$m" && continue
            if ! is_admin "$m"; then
                change "Remove '$m' from privileged group '$g'" gpasswd -d "$m" "$g"
            elif [[ $g == root || $g == shadow || $g == disk ]]; then
                review "Administrator '$m' is a member of group '$g', which no person normally needs"
            fi
        done
    done

    while IFS=: read -r name _ uid gid _; do
        [[ $gid == 0 && $name != root ]] && manual "Account '$name' has primary group root (GID 0). Fix with: usermod -g <own group> $name"
    done </etc/passwd

    # sudoers
    local files=() f bad=0
    for f in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f $f ]] || continue
        [[ $(basename "$f") == README || $f == *~ || $(basename "$f") == *.* ]] && continue
        files+=("$f")
    done
    admins_re=$(printf '%s\n' "${AUTH_ADMINS[@]}" | paste -sd'|')
    for f in "${files[@]}"; do
        if grep -vE '^[[:space:]]*(#|$)|[Cc]yber[Pp]atriot|CCS' "$f" | grep -qE 'NOPASSWD|!authenticate'; then
            log WARN "$f lets sudo run without a password"; bad=1
        fi
        if grep -vE '^[[:space:]]*(#|$)|[Cc]yber[Pp]atriot|CCS' "$f" |
           awk -v re="^(Defaults.*|root|%.*|@.*|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|${admins_re})$" '$1 !~ re { found=1 } END { exit !found }'; then
            log WARN "$f grants sudo to an account that is not an authorized administrator"; bad=1
        fi
        while read -r line; do review "sudoers ($f): $line"; done < <(
            grep -vE '^[[:space:]]*(#|$)' "$f" | grep -E '^[[:space:]]*%' | grep -vE '^[[:space:]]*%sudo[[:space:]]' )
        while read -r line; do review "sudoers ($f): $line"; done < <(
            grep -vE '^[[:space:]]*(#|$)' "$f" | grep -E '!env_reset|visiblepw|timestamp_timeout|!requiretty|env_keep.*LD_' )
    done
    if (( bad )); then
        change "Clean sudoers: require a password, drop entries for non-administrators" _fix_sudoers "${files[@]}"
    else
        log OK "sudoers requires a password and only names authorized administrators"
    fi
    if ! grep -rqsE '^[[:space:]]*%sudo[[:space:]]+ALL' /etc/sudoers /etc/sudoers.d; then
        manual "/etc/sudoers has no '%sudo ALL=(ALL:ALL) ALL' line. Add it with visudo or administrators cannot use sudo."
    fi

    # README: nobody logs in as root. Lock root only when sudo is known to work.
    local root_state; root_state=$(passwd -S root 2>/dev/null | awk '{print $2}')
    if [[ $root_state == L ]]; then
        log OK "root password is locked"
    elif [[ -z ${SUDO_USER:-} ]]; then
        manual "root password is not locked, and this script was not started with sudo, so it was left alone. From your own account run: sudo passwd -l root"
    elif ! visudo -c >/dev/null 2>&1; then
        manual "sudoers does not validate (visudo -c), so the root password was NOT locked. Fix sudoers, then: sudo passwd -l root"
    else
        change "Lock the root password (administrators use sudo)" passwd -l root
    fi
}

# =============================================================================
#  3. PASSWORD POLICY AND ACCOUNT LOCKOUT
# =============================================================================

_strip_nullok() { sed -i -E '/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?//g' "$@"; }
_add_remember() { sed -i -E "/^password.*pam_unix\.so/ { /remember=/! s/\$/ remember=$PASS_REMEMBER/ }" /etc/pam.d/common-password
                  touch /etc/security/opasswd; chmod 600 /etc/security/opasswd; }

_pam_update() {
    cat >/usr/share/pam-configs/faillock <<'EOF'
Name: Lock accounts after repeated failed logins (pam_faillock)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
EOF
    cat >/usr/share/pam-configs/faillock_notify <<'EOF'
Name: Check and reset the failed-login counter (pam_faillock)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
    pam-auth-update --enable faillock faillock_notify
    if ! grep -q pam_faillock /etc/pam.d/common-auth || ! grep -q pam_pwquality /etc/pam.d/common-password; then
        echo "PAM files have local modifications; regenerating them with pam-auth-update --force"
        pam-auth-update --force --enable faillock faillock_notify
    fi
    # sanity: never leave a PAM stack that cannot authenticate
    if ! grep -q 'pam_unix\.so' /etc/pam.d/common-auth || ! grep -q pam_faillock /etc/pam.d/common-auth; then
        echo "common-auth looks wrong after pam-auth-update; restoring original PAM files"
        cp -a "$BACKUP_DIR/etc/pam.d/." /etc/pam.d/
        rm -f /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_notify
        return 1
    fi
}

password_policy() {
    section "Password policy and account lockout"
    set_def /etc/login.defs PASS_MAX_DAYS "$PASS_MAX_DAYS"
    set_def /etc/login.defs PASS_MIN_DAYS "$PASS_MIN_DAYS"
    set_def /etc/login.defs PASS_WARN_AGE "$PASS_WARN_AGE"
    set_def /etc/login.defs ENCRYPT_METHOD YESCRYPT
    set_def /etc/login.defs UMASK 027
    set_def /etc/login.defs LOGIN_RETRIES 5

    ensure_pkg libpam-pwquality "password complexity"
    local q=/etc/security/pwquality.conf
    if [[ -e $q ]] || (( ! AUDIT )); then
        set_kv $q minlen "$MIN_PASS_LEN"
        set_kv $q dcredit -1
        set_kv $q ucredit -1
        set_kv $q lcredit -1
        set_kv $q ocredit -1
        set_kv $q difok 3
        set_kv $q maxrepeat 3
        set_kv $q dictcheck 1
        set_kv $q usercheck 1
    else
        log WOULD "Configure $q (minimum length $MIN_PASS_LEN, all four character classes)"
    fi

    # Module set first (pam-auth-update), then the hand edits it would refuse to keep.
    local regen=0
    grep -q pam_faillock /etc/pam.d/common-auth 2>/dev/null || regen=1
    grep -q pam_pwquality /etc/pam.d/common-password 2>/dev/null || regen=1
    if (( regen )); then
        change "PAM: enable password complexity (pam_pwquality) and account lockout (pam_faillock)" _pam_update
    else
        log OK "PAM password complexity and account lockout modules are enabled"
    fi

    if grep -qE 'pam_unix\.so.*nullok' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null; then
        change "PAM: stop accepting empty passwords (remove nullok)" _strip_nullok /etc/pam.d/common-auth /etc/pam.d/common-password
    else
        log OK "PAM does not accept empty passwords"
    fi

    if grep -E '^password.*pam_unix\.so' /etc/pam.d/common-password 2>/dev/null | grep -q 'remember='; then
        log OK "PAM remembers previous passwords"
    else
        change "PAM: remember the last $PASS_REMEMBER passwords" _add_remember
    fi

    local fl=/etc/security/faillock.conf
    set_kv $fl deny "$LOCKOUT_DENY"
    set_kv $fl unlock_time "$LOCKOUT_SECONDS"
    set_kv $fl fail_interval 900

    if grep -qE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf 2>/dev/null; then
        log OK "Core dumps are disabled"
    else
        backup /etc/security/limits.conf
        change "Disable core dumps in /etc/security/limits.conf" sh -c "printf '*\thard\tcore\t0\n' >>/etc/security/limits.conf"
    fi
}

# =============================================================================
#  4. SSH (critical service: keep it, harden it)
# =============================================================================

_sshd_comment_keys() {  # file extra-keys...  -> stdout; comments out managed directives
    local src=$1; shift
    local keys
    keys=$( { printf '%s\n' "${SSHD_SETTINGS[@]}" | awk '{print $1}'; printf '%s\n' "$@"; } | tr 'A-Z' 'a-z' | paste -sd'|')
    awk -v keys="$keys" -v b="$SSHD_BEGIN" -v e="$SSHD_END" '
        BEGIN { n=split(keys, a, "|"); for (i=1; i<=n; i++) want[a[i]]=1 }
        $0 == b { skip=1; next }
        $0 == e { skip=0; eat=1; next }
        skip { next }
        eat { eat=0; if ($0 == "") next }
        { k=tolower($1); sub(/=.*/, "", k)
          if (k in want) print "#" $0 "   # disabled by hardening script"; else print }' "$src"
}

_sshd_build() {  # src -> stdout: managed block first, then the cleaned original
    printf '%s\n' "$SSHD_BEGIN"
    printf '%s\n' "${SSHD_SETTINGS[@]}"
    if (( SSH_RESTRICT_TO_AUTHORIZED )); then
        printf 'AllowUsers %s\n' "${AUTH_ADMINS[*]} ${AUTH_USERS[*]}"
    fi
    printf '%s\n\n' "$SSHD_END"
    _sshd_comment_keys "$1" "${SSHD_ALSO_DISABLE[@]}"
}

_apply_sshd() {
    local cfg=/etc/ssh/sshd_config tmp f
    tmp=$(mktemp)
    _sshd_build "$cfg" >"$tmp"
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f $f ]] || continue
        _sshd_comment_keys "$f" "${SSHD_ALSO_DISABLE[@]}" >"$f.new" && cat "$f.new" >"$f"
        rm -f "$f.new"
    done
    if ! sshd -t -f "$tmp"; then
        echo "new sshd_config failed validation; restoring originals"
        rm -f "$tmp"
        [[ -d $BACKUP_DIR/etc/ssh/sshd_config.d ]] && cp -a "$BACKUP_DIR/etc/ssh/sshd_config.d/." /etc/ssh/sshd_config.d/
        return 1
    fi
    cat "$tmp" >"$cfg"
    rm -f "$tmp"
    chown root:root "$cfg"; chmod 600 "$cfg"
    systemctl reload ssh 2>/dev/null || systemctl restart ssh
}

ssh_service() {
    section "SSH (critical service)"
    ensure_pkg openssh-server "critical service"
    if ! command -v sshd >/dev/null 2>&1; then
        log WARN "sshd is not installed yet; SSH settings will be applied once it is"
        return
    fi
    (( AUDIT )) || mkdir -p /run/sshd

    local need=0 line key want have effective
    effective=$(sshd -T 2>/dev/null)
    for line in "${SSHD_SETTINGS[@]}"; do
        key=${line%% *}; want=${line#* }
        have=$(awk -v k="${key,,}" '$1 == k { print $2; exit }' <<<"$effective")
        if [[ ${have,,} == "${want,,}" ]]; then
            log OK "sshd: $key $want"
        else
            log WARN "sshd: $key is '${have:-unknown}', should be '$want'"; need=1
        fi
    done
    grep -qxF "$SSHD_BEGIN" /etc/ssh/sshd_config 2>/dev/null || need=1
    if grep -qiE '^[[:space:]]*(DenyUsers|DenyGroups|AllowGroups)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null; then
        log WARN "sshd has Deny/Allow group or user rules that may block authorized users"; need=1
    fi
    if (( need )); then
        change "Write hardened SSH settings to /etc/ssh/sshd_config (validated with sshd -t)" _apply_sshd
    fi

    enable_unit ssh.service
    local f mode
    for f in /etc/ssh/ssh_host_*_key; do
        [[ -f $f ]] || continue
        mode=$(stat -c %a "$f")
        [[ $mode == 600 ]] || change "Restrict SSH host key $f (was $mode)" chmod 600 "$f"
    done
}

# =============================================================================
#  5. FIREWALL (UFW only)
# =============================================================================

firewall() {
    section "Firewall (UFW)"
    ensure_pkg ufw "the only approved firewall"
    local other
    for other in firewalld nftables-persistent iptables-persistent; do
        pkg_installed "$other" && review "Another firewall package is installed: $other (README approves UFW only)"
    done
    disable_unit firewalld
    if ! command -v ufw >/dev/null 2>&1; then
        log WARN "ufw is not installed yet; firewall rules will be applied once it is"
        return
    fi

    local port status
    port=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }'); port=${port:-22}
    status=$(ufw status verbose 2>/dev/null)

    if ! grep -qE "^${port}/tcp[[:space:]]+ALLOW|^${port}[[:space:]]+ALLOW|OpenSSH[[:space:]]+ALLOW" <<<"$status"; then
        change "UFW: allow SSH on ${port}/tcp" ufw allow "${port}/tcp"
    else
        log OK "UFW allows SSH (port $port)"
    fi
    if grep -q 'deny (incoming), allow (outgoing)' <<<"$status"; then
        log OK "UFW default policy is deny incoming / allow outgoing"
    else
        change "UFW: default deny incoming" ufw default deny incoming
        change "UFW: default allow outgoing" ufw default allow outgoing
    fi
    if grep -qE '^Logging: on' <<<"$status"; then log OK "UFW logging is on"; else change "UFW: turn logging on" ufw logging on; fi
    if grep -q '^Status: active' <<<"$status"; then
        log OK "UFW is active"
    else
        change "UFW: enable the firewall" ufw --force enable
    fi
    while read -r line; do
        [[ -n $line ]] && review "UFW rule: $line"
    done < <(ufw status 2>/dev/null | awk 'NR > 4' | grep -vE "^${port}(/tcp)?[[:space:]]|^${port}(/tcp)? \(v6\)|OpenSSH")
}

# =============================================================================
#  6. KERNEL / NETWORK PARAMETERS
# =============================================================================

_apply_sysctl() {
    local kv dropin=/etc/sysctl.d/99-zz-hardening.conf
    : >"$dropin"
    for kv in "${SYSCTL_SETTINGS[@]}"; do
        sysctl -n "${kv%%=*}" >/dev/null 2>&1 || continue
        printf '%s = %s\n' "${kv%%=*}" "${kv#*=}" >>"$dropin"
        _set_kv /etc/sysctl.conf "${kv%%=*}" "${kv#*=}"
    done
    sysctl --system >/dev/null 2>&1
    sysctl -p "$dropin"
}

kernel_params() {
    section "Kernel and network parameters"
    local kv key want have need=0 unsaved=0
    for kv in "${SYSCTL_SETTINGS[@]}"; do
        key=${kv%%=*}; want=${kv#*=}
        have=$(sysctl -n "$key" 2>/dev/null)
        if [[ -z $have ]]; then continue; fi
        if [[ $have != "$want" ]]; then
            log WARN "sysctl $key is $have, should be $want"; need=1
        elif [[ $(get_kv /etc/sysctl.conf "$key") != "$want" ]]; then
            unsaved=$((unsaved + 1)); need=1
        else
            log OK "sysctl $key = $want"
        fi
    done
    (( unsaved )) && log WARN "$unsaved sysctl settings are correct right now but not saved in /etc/sysctl.conf"
    if (( need )); then
        backup /etc/sysctl.conf
        change "Write and load hardened sysctl settings (/etc/sysctl.conf and /etc/sysctl.d/99-zz-hardening.conf)" _apply_sysctl
    fi
    if [[ $(systemctl is-enabled ctrl-alt-del.target 2>/dev/null) == masked ]]; then
        log OK "Ctrl+Alt+Del reboot is disabled"
    else
        change "Disable Ctrl+Alt+Del reboot" systemctl mask ctrl-alt-del.target
    fi
}

# =============================================================================
#  7. SERVICES
# =============================================================================

services() {
    section "Services"
    local s
    for s in "${SERVICES_TO_DISABLE[@]}"; do disable_unit "$s"; done
    if [[ $(systemctl is-active cups.service 2>/dev/null) == active ]]; then
        review "CUPS (printing) is running. Left alone in case this workstation prints; disable it if not: systemctl disable --now cups cups-browsed"
    fi
    ensure_pkg auditd "system auditing"
    systemctl cat auditd.service >/dev/null 2>&1 && enable_unit auditd.service
    if systemctl cat apparmor.service >/dev/null 2>&1; then
        if [[ $(systemctl is-enabled apparmor.service 2>/dev/null) == enabled ]]; then
            log OK "AppArmor is enabled"
        else
            change "Enable AppArmor" systemctl enable --now apparmor.service
        fi
    fi

    local unit exec_line
    for unit in /etc/systemd/system/*.service; do
        [[ -f $unit && ! -L $unit ]] || continue
        is_ccs "$unit" && continue
        pkg_owns "$unit" && continue
        exec_line=$(grep -m1 -E '^ExecStart=' "$unit")
        is_ccs "$exec_line" && continue
        review "Service not from any Debian package: $unit ($exec_line) [$(systemctl is-enabled "$(basename "$unit")" 2>/dev/null)]"
    done
}

# =============================================================================
#  8. SOFTWARE: sources, prohibited packages, updates, Chromium
# =============================================================================

_add_sources() { printf '%s\n' "$@" >>/etc/apt/sources.list; }

_purge_pkg() { apt_do purge "$1"; }

_auto_updates() {
    cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
    local f
    for f in /etc/apt/apt.conf.d/*; do
        [[ -f $f && $f != */20auto-upgrades ]] || continue
        sed -i -E 's/^([[:space:]]*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade|Download-Upgradeable-Packages)[[:space:]]+)"0"/\1"1"/' "$f"
    done
}

_default_browser() {
    local desktop=chromium.desktop f
    update-alternatives --set x-www-browser /usr/bin/chromium
    update-alternatives --set gnome-www-browser /usr/bin/chromium 2>/dev/null || true
    mkdir -p /etc/xdg
    f=/etc/xdg/mimeapps.list
    touch "$f"
    local key
    for key in x-scheme-handler/http x-scheme-handler/https text/html x-scheme-handler/about x-scheme-handler/unknown; do
        _set_ini "$f" "Default Applications" "$key" "$desktop"
    done
    if [[ -d /etc/xdg/xfce4 ]]; then
        touch /etc/xdg/xfce4/helpers.rc
        sed -i -E '/^WebBrowser=/d' /etc/xdg/xfce4/helpers.rc
        echo 'WebBrowser=chromium' >>/etc/xdg/xfce4/helpers.rc
    fi
    # per-user overrides that point somewhere else
    local home
    while IFS=: read -r _ _ uid _ _ home _; do
        (( uid >= 1000 && uid < 65534 )) || continue
        f=$home/.config/mimeapps.list
        [[ -f $f ]] && sed -i -E "s#^(x-scheme-handler/https?|text/html)=.*#\1=$desktop#" "$f"
        f=$home/.config/xfce4/helpers.rc
        [[ -f $f ]] && sed -i -E 's/^WebBrowser=.*/WebBrowser=chromium/' "$f"
    done </etc/passwd
    return 0
}

apt_sources() {
    section "Software sources"
    local active missing=()
    active=$(cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    grep -qE '(^deb[[:space:]].*[[:space:]]bookworm[[:space:]])|(^Suites:.*\bbookworm\b([[:space:]]|$))' <<<"$active" ||
        missing+=("deb http://deb.debian.org/debian bookworm main non-free-firmware")
    grep -q 'bookworm-security' <<<"$active" ||
        missing+=("deb http://security.debian.org/debian-security bookworm-security main non-free-firmware")
    grep -q 'bookworm-updates' <<<"$active" ||
        missing+=("deb http://deb.debian.org/debian bookworm-updates main non-free-firmware")
    if (( ${#missing[@]} )); then
        change "Add missing official Debian 12 sources (${#missing[@]}: main / security / updates)" _add_sources "${missing[@]}"
    else
        log OK "Official Debian 12 main, security and updates sources are present"
    fi
    while read -r line; do
        [[ -n $line ]] && review "Non-standard APT source: $line"
    done < <(grep -E '^(deb|deb-src|URIs:|Suites:)' <<<"$active" | grep -vE 'debian\.org.*bookworm|^URIs:.*debian\.org|^Suites:[[:space:]]*bookworm' )
}

software() {
    section "Prohibited packages"
    local pkg sim extra r found=0
    while read -r pkg; do
        [[ $pkg =~ $PROHIBITED_PKG_REGEX ]] || continue
        is_ccs "$pkg" && continue
        found=1
        sim=$(apt-get -s purge "$pkg" 2>/dev/null | awk '/^(Purg|Remv) / { print $2 }')
        extra=""
        for r in $sim; do
            [[ $r == "$pkg" || $r =~ $PROHIBITED_PKG_REGEX ]] || extra+="$r "
        done
        if [[ -n $extra ]]; then
            manual "Prohibited package '$pkg' was NOT removed automatically because that would also remove: $extra. Check, then: sudo apt purge $pkg"
        else
            change "Purge prohibited package '$pkg'" _purge_pkg "$pkg"
        fi
    done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 == "ii" { print $2 }')
    (( found )) || log OK "No known prohibited packages are installed"

    local locals=()
    mapfile -t locals < <(apt list --installed 2>/dev/null | awk -F/ '/\[.*local.*\]/ { print $1 }')
    if (( ${#locals[@]} > 25 )); then
        review "${#locals[@]} installed packages match no configured repository. The package lists are probably stale; after 'apt update' check: apt list --installed | grep local"
    else
        for pkg in "${locals[@]+"${locals[@]}"}"; do
            is_ccs "$pkg" || review "Package not from a configured repository (installed by hand?): $pkg"
        done
    fi

    section "Updates and Chromium"
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]] &&
       ! grep -rhsE '^[[:space:]]*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)[[:space:]]+"0"' /etc/apt/apt.conf.d >/dev/null &&
       grep -qsE 'Unattended-Upgrade[[:space:]]+"1"' /etc/apt/apt.conf.d/20auto-upgrades; then
        log OK "Automatic updates are enabled"
    else
        change "Enable daily automatic updates" _auto_updates
    fi
    ensure_pkg unattended-upgrades "automatic security updates"
    ensure_pkg chromium "required default browser"

    if (( SKIP_UPGRADE )); then
        manual "Updates were skipped. Run: sudo apt update && sudo apt upgrade"
    elif (( AUDIT )); then
        local n; n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ')
        if (( n > 0 )); then log WOULD "Upgrade $n packages to the latest Debian 12 versions (count is from the last 'apt update')"; else log OK "No pending package upgrades (as of the last 'apt update')"; fi
    elif apt_ready; then
        log INFO "Upgrading packages; this can take several minutes..."
        change "Upgrade all packages to the latest Debian 12 versions" apt_do upgrade
    fi

    if command -v chromium >/dev/null 2>&1; then
        local cur; cur=$(update-alternatives --query x-www-browser 2>/dev/null | awk '/^Value:/ { print $2 }')
        if [[ $cur == /usr/bin/chromium && $(get_ini /etc/xdg/mimeapps.list "Default Applications" x-scheme-handler/https) == chromium.desktop ]]; then
            log OK "Chromium is the system default browser"
        else
            backup /etc/xdg/mimeapps.list
            change "Make Chromium the default browser system-wide and in existing user settings" _default_browser
        fi
    fi
    manual "Log in to the desktop and confirm Chromium opens for web links (Settings > Default Applications). A desktop session can override the system default."
}

# =============================================================================
#  9. DISPLAY MANAGER (LightDM stays)
# =============================================================================

_set_default_dm() {
    echo /usr/sbin/lightdm >/etc/X11/default-display-manager
    ln -sf /lib/systemd/system/lightdm.service /etc/systemd/system/display-manager.service
    systemctl daemon-reload
}

display_manager() {
    section "Display manager (LightDM)"
    if ! pkg_installed lightdm; then
        manual "LightDM is not installed, but the README says the display manager must be LightDM. Install it: sudo apt install lightdm"
        return
    fi
    if [[ $(cat /etc/X11/default-display-manager 2>/dev/null) == /usr/sbin/lightdm ]]; then
        log OK "LightDM is the default display manager"
    else
        backup /etc/X11/default-display-manager
        change "Set LightDM as the default display manager (takes effect after reboot)" _set_default_dm
    fi
    local conf=/etc/lightdm/lightdm.conf
    set_ini $conf "Seat:*" allow-guest false
    set_ini $conf "Seat:*" greeter-hide-users true
    set_ini $conf "Seat:*" greeter-show-manual-login true
    set_ini $conf "Seat:*" greeter-allow-guest false
    local f
    for f in /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf; do
        [[ -f $f ]] || continue
        grep -qE '^[[:space:]]*(allow-guest|autologin-guest)[[:space:]]*=[[:space:]]*true' "$f" && review "LightDM drop-in enables guest access: $f"
    done
}

# =============================================================================
# 10. FILE PERMISSIONS
# =============================================================================

fix_perm() {  # path mode owner:group
    [[ -e $1 ]] || return 0
    local cur; cur="$(stat -c '%a %U:%G' "$1")"
    if [[ $cur == "$2 $3" ]]; then log OK "$1 is $2 $3"; return 0; fi
    change "Set $1 to $2 $3 (was $cur)" sh -c "chown $3 '$1' && chmod $2 '$1'"
}

permissions() {
    section "File permissions"
    fix_perm /etc/passwd   644 root:root
    fix_perm /etc/passwd-  644 root:root
    fix_perm /etc/group    644 root:root
    fix_perm /etc/group-   644 root:root
    fix_perm /etc/shadow   640 root:shadow
    fix_perm /etc/shadow-  640 root:shadow
    fix_perm /etc/gshadow  640 root:shadow
    fix_perm /etc/gshadow- 640 root:shadow
    fix_perm /etc/sudoers  440 root:root
    fix_perm /etc/crontab  600 root:root
    fix_perm /etc/ssh/sshd_config 600 root:root

    local f base
    while IFS= read -r -d '' f; do
        change "Remove world-write permission from $f" chmod o-w "$f"
    done < <(find /etc -xdev -type f -perm -0002 -print0 2>/dev/null)

    while IFS= read -r -d '' f; do
        is_ccs "$f" && continue
        base=$(basename "$f")
        if [[ $base =~ $SUID_NEVER ]]; then
            change "Remove set-uid/set-gid bit from $f (a shell, interpreter or editor must never have it)" chmod ug-s "$f"
        elif ! pkg_owns "$f"; then
            review "Set-uid/set-gid file not from any Debian package: $f"
        fi
    done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print0 2>/dev/null)

    [[ -s /etc/ld.so.preload ]] && review "/etc/ld.so.preload is not empty (libraries forced into every program): $(tr '\n' ' ' </etc/ld.so.preload)"
}

# =============================================================================
# 11. PROHIBITED FILES
# =============================================================================

_quarantine() {
    mkdir -p "$QUARANTINE_DIR" && chmod 700 "$QUARANTINE_DIR" || return 1
    local flat=${1//\//__}
    mv -f -- "$1" "$QUARANTINE_DIR/$flat"
}

remove_prohibited() {  # file reason
    if (( DELETE_PROHIBITED )); then
        change "Delete $2: $1" rm -f -- "$1"
    else
        change "Quarantine $2: $1" _quarantine "$1"
    fi
}

file_scan() {
    section "Prohibited files (this scan can take a minute)"
    local roots=() r f name ext
    for r in "${SCAN_ROOTS[@]}"; do [[ -d $r ]] && roots+=("$r"); done
    (( ${#roots[@]} )) || return 0
    while IFS= read -r -d '' f; do
        is_ccs "$f" && continue
        name=${f##*/}
        ext=""; [[ $name == *.* ]] && ext=${name##*.}; ext=${ext,,}
        if [[ $ext =~ $MEDIA_EXT_REGEX ]]; then
            remove_prohibited "$f" "non-work media file"
        elif [[ ${name,,} =~ passw|credential|shadow|hash ]]; then
            review "File name suggests stored credentials: $f"
        elif [[ $ext =~ $REVIEW_EXT_REGEX ]]; then
            review "Check this file: $f"
        fi
    done < <(find "${roots[@]}" \
                \( -path /opt/CyberPatriot -o -path "$QUARANTINE_DIR" -o -name .cache -o -name .config \
                   -o -name .mozilla -o -path '*/.local/lib' -o -path '*/.local/share/icons' \
                   -o -name snap -o -name .git \) -prune \
                -o -type f -print0 2>/dev/null)

    roots=()
    for r in "${REVIEW_ROOTS[@]}"; do [[ -d $r ]] && roots+=("$r"); done
    (( ${#roots[@]} )) || return 0
    while IFS= read -r -d '' f; do
        name=${f##*/}
        ext=""; [[ $name == *.* ]] && ext=${name##*.}; ext=${ext,,}
        [[ $ext =~ $MEDIA_EXT_REGEX ]] && review "Media file outside the home directories (remove it if it is not part of installed software): $f"
    done < <(find "${roots[@]}" -xdev \
                \( -path /opt/CyberPatriot -o -path "$QUARANTINE_DIR" -o -path /var/lib -o -path /var/cache \
                   -o -path /var/tmp -o -path /var/www -o -path /var/backups -o -path /var/log \) -prune \
                -o -type f -print0 2>/dev/null)
}

# =============================================================================
# 12. PERSISTENCE AND EXPOSURE (report only)
# =============================================================================

report_only() {
    section "Scheduled jobs, startup items and listening ports (report only)"
    local f line
    for f in /var/spool/cron/crontabs/*; do
        [[ -f $f ]] || continue
        while read -r line; do review "crontab of $(basename "$f"): $line"; done < <(grep -vE '^[[:space:]]*(#|$)' "$f")
    done
    while read -r line; do review "/etc/crontab: $line"; done < <(
        grep -vE '^[[:space:]]*(#|$)|^(SHELL|PATH|MAILTO)=|run-parts|anacron' /etc/crontab 2>/dev/null)
    for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f $f && $(basename "$f") != .placeholder ]] || continue
        is_ccs "$f" && continue
        pkg_owns "$f" || review "Cron file not from any Debian package: $f"
    done
    if [[ -f /etc/rc.local ]] && grep -vE '^[[:space:]]*(#|$)|^exit 0' /etc/rc.local | grep -q .; then
        review "/etc/rc.local runs commands at boot: $(grep -vE '^[[:space:]]*(#|$)|^exit 0' /etc/rc.local | tr '\n' ';')"
    fi
    while read -r line; do
        is_ccs "$line" && continue
        review "Listening: $line"
    done < <(ss -H -tulpn 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\])/ { print $1, $5, $7 }' | sort -u)
    while read -r line; do review "/etc/hosts entry: $line"; done < <(
        grep -vE '^[[:space:]]*(#|$)|localhost|ip6-|^127\.0\.1\.1' /etc/hosts 2>/dev/null)
}

# =============================================================================
#  SUMMARY
# =============================================================================

summary() {
    section "Summary"
    log INFO "Already compliant: $N_OK   Fixed: $N_FIXED   Would fix (audit): $N_WOULD   Failed: $N_FAIL"
    local i item shown=60
    { echo; echo "REVIEW (${#REVIEW[@]} items the script reports but does not decide):"
      for item in "${REVIEW[@]+"${REVIEW[@]}"}"; do echo "  - $item"; done
    } >>"$LOG"
    echo; echo "REVIEW (${#REVIEW[@]} items the script reports but does not decide):"
    i=0
    for item in "${REVIEW[@]+"${REVIEW[@]}"}"; do
        i=$((i + 1))
        if (( i > shown )); then echo "  ... and $(( ${#REVIEW[@]} - shown )) more in $LOG"; break; fi
        echo "  - $item"
    done
    { echo; echo "MANUAL STEPS (${#MANUAL[@]}):"
      i=0
      for item in "${MANUAL[@]+"${MANUAL[@]}"}"; do i=$((i + 1)); echo "  $i. $item"; done
      echo
    } | tee -a "$LOG"

    (( N_FAIL > 0 )) && echo "$N_FAIL fixes FAILED. Search the log for [FAIL]."
    if (( ! AUDIT )); then
        echo "BEFORE you close this terminal or reboot, open a second terminal and check:"
        echo "    sudo -k; sudo true             # sudo still works with your password"
        echo "    ssh ${INVOKER}@localhost true   # SSH still accepts you"
        echo "If either fails, restore from $BACKUP_DIR using this terminal."
        echo "A locked-out account can be cleared with: sudo faillock --user <name> --reset"
        [[ -d $QUARANTINE_DIR ]] && (( ! DELETE_PROHIBITED )) &&
            echo "Removed files are in $QUARANTINE_DIR. Check them, then delete that folder: prohibited media must not stay on the machine."
        echo "Then reboot and open the CyberPatriot Scoring Report."
    fi
    echo "Full log: $LOG"
}

# =============================================================================
#  MAIN
# =============================================================================

main() {
    while (( $# )); do
        case $1 in
            --audit)             AUDIT=1 ;;
            --force)             FORCE=1 ;;
            --delete-prohibited) DELETE_PROHIBITED=1 ;;
            --skip-upgrade)      SKIP_UPGRADE=1 ;;
            --skip-file-scan)    SKIP_FILE_SCAN=1 ;;
            --password-scope)    shift; PASSWORD_SCOPE=${1:-} ;;
            --password-scope=*)  PASSWORD_SCOPE=${1#*=} ;;
            -h|--help)           usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        esac
        shift
    done
    case $PASSWORD_SCOPE in all|users|none) ;; *) echo "--password-scope must be all, users or none" >&2; exit 2 ;; esac
    if (( EUID != 0 )); then echo "Run this with sudo: sudo bash $0 $*" >&2; exit 1; fi

    mkdir -p "$LOG_DIR" && chmod 750 "$LOG_DIR"
    : >"$LOG"

    preflight
    apt_sources
    users
    groups_and_sudo
    password_policy
    ssh_service
    firewall
    kernel_params
    services
    software
    display_manager
    permissions
    (( SKIP_FILE_SCAN )) || file_scan
    report_only
    summary
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
