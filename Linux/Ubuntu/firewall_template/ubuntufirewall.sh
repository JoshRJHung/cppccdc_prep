#!/bin/bash

#if iptables is not installed
which iptables &> /dev/null || apt-get update
which iptables &> /dev/null || apt-get install -y iptables

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


