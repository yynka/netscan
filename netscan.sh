#!/bin/bash
# netscan.sh
# this script performs a basic network scan to find active devices on the local network.

# function to get the local network range
get_network_range() {
    local_ip=$(hostname -I | awk '{print $1}')
    subnet_mask=$(ip -o -f inet addr show | grep "$local_ip" | awk '{print $4}')
    echo "$subnet_mask"
}

# function to scan the network range for active devices
scan_network() {
    local network_range=$1
    echo "scanning network range: $network_range"
    
    # extract the base IP address
    ip_base=$(echo "$network_range" | sed 's/[0-9]*\/[0-9]*$//')
    
    # loop through addresses 1-254 to find active devices
    for i in {1..254}; do
        ip="${ip_base}${i}"
        if ping -c 1 -W 1 "$ip" &> /dev/null; then
            echo "$ip is active"
        fi
    done
}

# main script execution
network_range=$(get_network_range)
if [ -z "$network_range" ]; then
    echo "could not determine network range. please check your connection."
    exit 1
fi

scan_network "$network_range"
