#!/bin/bash
# Linux Hardening Script


set -euo pipefail 

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# -u: makes the script error out if there is an unreferenced variable 
# -o pipfail: if any command in a pipe fails, the whole line fails
# -e: if there is a non-zero exit code(error), the whole script exits immediately 

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Run as root: sudo $0" >&2
        exit 1
    fi
}

#Step 1:Change user/root default creds

# Prompt twice (hidden), retry until they match and are non-empty.
# Result is stored in the global NEW_PASS.
prompt_password() {
    local user="$1" p1 p2
    while true; do
        read -rsp "New password for $user: " p1; echo
        read -rsp "Confirm password for $user: " p2; echo
        if [[ -z "$p1" ]]; then
            echo "No empty passwords"
        elif [[ "$p1" != "$p2" ]]; then
            echo "Passwords do not match."
        else
            NEW_PASS="$p1"
            return 0
        fi
    done
}

change_password() {
    local user="$1"
    prompt_password "$user"
    # chpasswd reads from stdin, so the password never shows up in `ps`
    if printf '%s:%s\n' "$user" "$NEW_PASS" | chpasswd; then
        echo "[+] Password changed for $user"
    else
        echo "[!] Failed to change password for $user" >&2
    fi
    NEW_PASS=""
}

#Step 2: List Open Ports
list_open_ports() {
     ss -tulpn
}


#Step 3: Audit accounts & sudo
audit_accounts(){
   awk -F: '$3 == 0 {print $1}' /etc/passwd
   cut -d: -f3 /etc/passwd | sort | uniq -d
   awk -F: '$2 == "" {print $1}' /etc/shadow
   awk -F: '$7 !~ /(nologin|false)$/ {print $1 " (uid " $3 ") " $7}' /etc/passwd
   getent group sudo || true
   grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ || echo "none found"
   visudo -c
}

# ---Main---
require_root
change_password root

login_user="$(getent passwd 1000 | cut -d: -f1 || true)"
if [[ -n "$login_user" ]]; then
      change_password "$login_user"
else
      echo "No default user found" >&2
fi

list_open_ports
audit_accounts
