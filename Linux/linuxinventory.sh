#!/bin/bash


#List Internal IPs
echo "IP Address"
ip a

#List Open Ports
echo
echo "Open Ports"
ss -tulpn

#List All Users
echo
echo "All Users"
cat /etc/passwd

#List Sudo/Wheel Users
echo
echo "Sudo Users"
grep sudo /etc/group
grep wheel /etc/group

#List Users With No Password Set
echo
echo "Users with No Password"
awk -F: '($2 == "") {print $1}' /etc/shadow

#SSH Config
echo
echo "SSH Config (Root Login / Password Auth)"
grep -Ei "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
echo "Effective values (sshd -T):"
sshd -T 2>/dev/null | grep -Ei "permitrootlogin|passwordauthentication"

#Installed Packages
echo
echo "Installed Packages"
dpkg -l 2>/dev/null
rpm -qa 2>/dev/null

#---Main---
echo
echo "Running Services"
systemctl list-units --type=service --state=running

#Firewall Status
echo
echo "Firewall Status"
if command -v iptables >/dev/null 2>&1; then
  echo "--- iptables ---"
  iptables -L -v -n
else
  echo "iptables is NOT installed on this machine"
fi

if command -v firewall-cmd >/dev/null 2>&1; then
  echo "--- firewalld ---"
  firewall-cmd --state
  firewall-cmd --list-all
else
  echo "firewalld is NOT installed on this machine"
fi

if command -v nft >/dev/null 2>&1; then
  echo "--- nftables ---"
  nft list ruleset
else
  echo "nftables is NOT installed on this machine"
fi

if command -v ufw >/dev/null 2>&1; then
  echo "--- ufw ---"
  ufw status verbose
else
  echo "ufw is NOT installed on this machine"
fi

#Cron Jobs
echo
echo "List of Cronjobs"
for user in $(cut -d: -f1 /etc/passwd); do crontab -u $user -l 2>/dev/null; done
ls -la /etc/cron.d

#SUID Files
echo
echo "SUID Binaries"
find / -perm -4000 -type f 2>/dev/null
