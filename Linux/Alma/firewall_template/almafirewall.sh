#!/bin/bash

# Alma Linux uses firewalld by default. Stop it so it doesn't fight with iptables rules.
systemctl stop firewalld &> /dev/null
systemctl disable firewalld &> /dev/null
systemctl mask firewalld &> /dev/null

#if iptables is not installed
which iptables &> /dev/null || dnf install -y iptables-nft
# iptables-services provides the iptables systemd service, which restores saved rules on boot
rpm -q iptables-services &> /dev/null || dnf install -y iptables-services

# Wait for the briefing packet to release which services will be scored so that I can create exception rules

iptables -F # Flushes all rules from chains
iptables -X # Delete all empty user-defined chains. Leaves the default chains alone.

# Default Policies
iptables -P INPUT DROP # DROP all packets from Incoming traffic unless explicitly allowed. 
iptables -P FORWARD DROP # DROP all packets from Forwarded traffic unless explicitly allowed.
iptables -P OUTPUT ACCEPT # ACCEPT all packets from Outgoing traffic unless explicitly denied.

# Allow Loopback Interface 
iptables -A INPUT -i lo -j ACCEPT # Appends a Rule to the INPUT chain, rule is applied to the loopback interface, and the action is to ACCEPT the packet.


# Allow Established & Related Connections
# Appends a Rule to the INPUT Chain
# ACCEPT packets that are part of an established connection or related to an established connnection
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 


# Service exceptions go here once the briefing packet is released, e.g.:
# iptables -A INPUT -p tcp --dport 22 -j ACCEPT


# Save rules so they persist across reboots (writes /etc/sysconfig/iptables)
iptables-save > /etc/sysconfig/iptables
systemctl enable iptables &> /dev/null
