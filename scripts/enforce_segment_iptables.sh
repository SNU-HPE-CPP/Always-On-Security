#!/usr/bin/env bash
set -euo pipefail

# Host-side helper for segment boundaries in the Docker-simulated HPC.
# Run as root on the Docker host after inspecting the bridge interfaces.

COMPUTE_CIDR="${COMPUTE_CIDR:-10.10.1.0/24}"
STORAGE_CIDR="${STORAGE_CIDR:-10.10.2.0/24}"
MGMT_CIDR="${MGMT_CIDR:-10.10.3.0/24}"

COMPUTE_BRIDGE="${COMPUTE_BRIDGE:-br-compute}"
STORAGE_BRIDGE="${STORAGE_BRIDGE:-br-storage}"
MGMT_BRIDGE="${MGMT_BRIDGE:-br-mgmt}"

# Default policy: accept established traffic, then allow only the intended flows.
iptables -P FORWARD DROP
iptables -F FORWARD
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Compute nodes may talk to compute peers and mgmt services only.
iptables -A FORWARD -i "${COMPUTE_BRIDGE}" -o "${COMPUTE_BRIDGE}" -j ACCEPT
iptables -A FORWARD -s "${COMPUTE_CIDR}" -d "${MGMT_CIDR}" -p tcp -m multiport --dports 22,514,5555,5556 -j ACCEPT
iptables -A FORWARD -s "${COMPUTE_CIDR}" -d "${STORAGE_CIDR}" -p tcp -m multiport --dports 22,2049 -j ACCEPT

# Storage network only accepts access from active compute jobs and management.
iptables -A FORWARD -s "${MGMT_CIDR}" -d "${STORAGE_CIDR}" -p tcp -m multiport --dports 22,2049 -j ACCEPT
iptables -A FORWARD -s "${STORAGE_CIDR}" -d "${MGMT_CIDR}" -p tcp -m multiport --dports 22,514,5555,5556 -j ACCEPT

# Block direct compute -> mgmt lateral movement beyond allowed monitoring ports.
iptables -A FORWARD -s "${COMPUTE_CIDR}" -d "${MGMT_CIDR}" -j DROP

# Log drops for review by Zeek/Wazuh correlation if LOG targets are enabled.
iptables -A FORWARD -j LOG --log-prefix "HPC-FORWARD-DROP " --log-level 4
