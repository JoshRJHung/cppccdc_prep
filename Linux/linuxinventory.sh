#!/bin/bash


#List Internal IPs
ip a

#List Open Ports
ss -tulpn

#List All Users
cat /etc/passwd

#List Sudo/Wheel Users
grep sudo /etc/group
grep wheel /etc/group

#List Users With No Password Set
awk -F: '($2 == "") {print $1}' /etc/shadow

#---Main---
systemctl list-units --type=service --state=running

#Firewall Status
if command -v iptables >/dev/null 2>&1; then
  iptables -L -v -n
else
  echo "ERROR: iptables is NOT installed on this machine"
fi 

#Cron Jobs
crontab -l
ls -la /etc/cron.d

#SUID Files
find / -perm -4000 -type f 2>/dev/null


