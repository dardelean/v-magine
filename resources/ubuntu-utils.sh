#!/bin/bash
set -e

function check_new_kernel() {
    local LAST_KERNEL=$(apt-cache policy linux-generic | grep Candidate | awk '{print $2}')
    local CURR_KERNEL=$(apt-cache policy linux-generic | grep Installed | awk '{print $2}')
    if [ "$LAST_KERNEL" != "$CURR_KERNEL" ]; then
        return 1
    fi
}

function check_nova_service_up() {
    local host_name=$1
    local service_name=${2-"nova-compute"}
    nova service-list | awk '{if ($4 == host_name && $2 == service_name && $10 == "up" && $8 == "enabled") {f=1}} END {exit !f}' host_name=$host_name service_name=$service_name
}

function check_neutron_agent_up() {
    local host_name=$1
    local agent_type=${2:-"HyperV agent"}
    neutron agent-list |  awk 'BEGIN { FS = "[ ]*\\|[ ]+" }; {if (NR > 3 && $4 == host_name && $3 == agent_type && $5 == ":-)"){f=1}} END {exit !f}' host_name=$host_name agent_type="$agent_type"
}