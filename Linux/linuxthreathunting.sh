#!/bin/bash

echo "===================== ACCOUNTS ====================="

#Check for Sus Accounts
echo "--- Check for Sus Accounts ---"
cat /etc/passwd

#Check UID 0 Accounts (should only be root)
echo "--- Check UID 0 Accounts (should only be root) ---"
awk -F: '$3 == 0 {print $1}' /etc/passwd

#Check for Duplicate UIDs
echo "--- Check for Duplicate UIDs ---"
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

#Check Accounts With a Real Login Shell
echo "--- Check Accounts With a Real Login Shell ---"
grep -Ev '(nologin|false)$' /etc/passwd

#Check System Accounts (uid < 1000) That Have a Login Shell
echo "--- Check System Accounts (uid < 1000) That Have a Login Shell ---"
awk -F: '$3 < 1000 && $7 !~ /(nologin|false)$/' /etc/passwd

#Check for Accounts Missing From Shadow (or vice versa)
echo "--- Check for Accounts Missing From Shadow (or vice versa) ---"
diff <(cut -d: -f1 /etc/passwd | sort) <(cut -d: -f1 /etc/shadow | sort)

echo "===================== SUDOERS ====================="

#Check Sudoers File
echo "--- Check Sudoers File ---"
grep -vE '^\s*(#|$)' /etc/sudoers

#Check Sudoers.d Directory
echo "--- Check Sudoers.d Directory ---"
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/* 2>/dev/null

#Check for NOPASSWD Entries
echo "--- Check for NOPASSWD Entries ---"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

#Check for Full ALL=(ALL) ALL Grants
echo "--- Check for Full ALL=(ALL) ALL Grants ---"
grep -r "ALL=(ALL)" /etc/sudoers /etc/sudoers.d/

#Check Sudoers Files Last Modified Time
echo "--- Check Sudoers Files Last Modified Time ---"
ls -la --time-style=full-iso /etc/sudoers /etc/sudoers.d/

echo "===================== GROUPS ====================="

#Check Admin Group Members (sudo/wheel)
echo "--- Check Admin Group Members (sudo/wheel) ---"
grep -E "^(sudo|wheel):" /etc/group

#Check Root Group Members
echo "--- Check Root Group Members ---"
grep "^root:" /etc/group

#Check High-Risk Groups (disk, shadow, adm)
echo "--- Check High-Risk Groups (disk, shadow, adm) ---"
grep -E "^(disk|shadow|adm):" /etc/group

#Check Container Groups (docker/lxd - root-equivalent)
echo "--- Check Container Groups (docker/lxd - root-equivalent) ---"
grep -E "^(docker|lxd):" /etc/group

#Check for Duplicate GIDs
echo "--- Check for Duplicate GIDs ---"
awk -F: '{print $3}' /etc/group | sort | uniq -d

#List All Groups
echo "--- List All Groups ---"
cat /etc/group

echo "===================== CRON JOBS ====================="

#Check System-Wide Crontab
echo "--- Check System-Wide Crontab ---"
grep -vE '^\s*(#|$)' /etc/crontab

#Check Cron.d Directory
echo "--- Check Cron.d Directory ---"
ls -la /etc/cron.d/
cat /etc/cron.d/* 2>/dev/null

#Check Cron.hourly/daily/weekly/monthly
echo "--- Check Cron.hourly/daily/weekly/monthly ---"
ls -la /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/

#Check Per-User Crontabs
echo "--- Check Per-User Crontabs ---"
for user in $(cut -d: -f1 /etc/passwd); do crontab -u $user -l 2>/dev/null; done

#Check At Jobs (one-time scheduled tasks)
echo "--- Check At Jobs (one-time scheduled tasks) ---"
if command -v atq >/dev/null 2>&1; then
  atq
else
  echo "at is NOT installed on this machine"
fi

#Check Cron Spool Directory Directly
echo "--- Check Cron Spool Directory Directly ---"
ls -la /var/spool/cron/crontabs/ 2>/dev/null
ls -la /var/spool/cron/ 2>/dev/null

echo "===================== BASHRC / SHELL STARTUP ====================="

#Check System-Wide Bashrc
echo "--- Check System-Wide Bashrc ---"
cat /etc/bash.bashrc 2>/dev/null
cat /etc/bashrc 2>/dev/null

#Check Profile.d Scripts
echo "--- Check Profile.d Scripts ---"
ls -la /etc/profile.d/
cat /etc/profile.d/* 2>/dev/null

#Check System-Wide Profile
echo "--- Check System-Wide Profile ---"
cat /etc/profile

#Check Per-User Bashrc/Profile Files
echo "--- Check Per-User Bashrc/Profile Files ---"
ls -la /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /root/.bashrc /root/.bash_profile /root/.profile 2>/dev/null

#Check Recently Modified Shell Startup Files
echo "--- Check Recently Modified Shell Startup Files ---"
find /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /home /root -maxdepth 2 \( -name ".bash*" -o -name ".profile" -o -name "profile" -o -name "*.sh" -o -name "*bashrc" \) -newermt "3 days ago" 2>/dev/null

#---Main---
