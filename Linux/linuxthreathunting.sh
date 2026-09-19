#!/bin/bash

#Open Ports
echo
echo "Open Ports O_O"
ss -tulpn


#Other Root Users?
echo "Other Root Users"
awk -F: '$3 == 0 {print $1}' /etc/passwd

#Duplicate UIDs?
echo "Duplicate UIDs?"
awk -F: '{print $3}' /etc/passwd | sort | uniq -d

#Accounts with a real login shell
echo "Who has a login shell?"
grep -Ev '(nologin|false)$' /etc/passwd

# System accounts that shouldn't have a shell
echo "System accounts that should not have a shell"
awk -F: '$3 < 1000 && $7 !~ /(nologin|false)$/' /etc/passwd

#Password entries missing from shadow
cut -d: -f1 /etc/passwd | sort against cut -d: -f1 /etc/shadow | sort


#Who is a Sudo User

echo "Users with Sudo Perms"
grep sudo /etc/group
grep wheel /etc/group

#High Risk Groups
echo "Who is in disk,shadow,adm?"
grep -E "^(disk|shadow|adm):" /etc/group

#Check Container Groups
echo "Who is in container groups?"
grep -E "^(docker|lxd):" /etc/group

#Check for Duplicate GIDs
echo "Any Duplicate GIDs?"
awk -F: '{print $3}' /etc/group | sort | uniq -d

#Check Sudoers
grep -vE '^\s*(#|$)' /etc/sudoers

#Check for NOPASSWD Entries
echo "Who has NOPASSWD(Sudoers)"
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

#Check for ALL=(ALL)
echo "Who has ALL=(ALL)(Sudoers)"
grep -r "ALL=(ALL)" /etc/sudoers /etc/sudoers.d/



#Cronjobs
echo "Check system-wide crontab"
grep -vE '^\s*(#|$)' /etc/crontab

#Bashrc
echo "Check bashrc"
cat /etc/bash.bashrc 2>/dev/null
cat /etc/bashrc 2>/dev/null

