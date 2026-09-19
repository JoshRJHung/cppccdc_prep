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

#---Main---
echo
echo "Running Services"
systemctl list-units --type=service --state=running

#Firewall Status
echo
echo "Firewall Status"
if command -v iptables >/dev/null 2>&1; then
  iptables -L -v -n
else
  echo "ERROR: iptables is NOT installed on this machine"
fi 

#Cron Jobs
echo
echo "List of Cronjobs"
crontab -l
ls -la /etc/cron.d

#SUID Files
echo
echo "SUID Binaries" 
find / -perm -4000 -type f 2>/dev/null


