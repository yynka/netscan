#!/bin/bash

# run.sh
# this script scans the local network for active devices and retrieves their MAC addresses.

# function to get the local IP address and subnet mask to figure out the network range
get_network_range() {
    local interface=$(route -n get default | grep interface | awk '{print $2}')
    if [ -z "$interface" ]; then
        echo "No valid network interface found" >&2
        exit 1
    fi

    local ip_info=$(ifconfig "$interface" | grep "inet " | awk '{print $2, $4}')
    local ip_address=$(echo "$ip_info" | awk '{print $1}')
    local subnet_mask=$(echo "$ip_info" | awk '{print $2}')
    local cidr=$(ipcalc -c "$ip_address" "$subnet_mask" | grep -oE "CIDR: [^/]+" | awk '{print $2}')

    echo "$ip_address/$cidr"
}

# function to scan the network range and find active devices
scan_network() {
    local network_range=$1
    echo "scanning network range: $network_range"

    local active_devices=()

    # ping sweep to find active devices
    for ip in $(nmap -sn "$network_range" | grep "Nmap scan report" | awk '{print $NF}' | tr -d '()'); do
        echo "$ip is active"
        active_devices+=("$ip")
    done

    echo "${active_devices[@]}"
}

# function to retrieve the MAC address of each active device
get_mac_address() {
    local active_devices=("$@")

    echo -e "\nretrieving MAC addresses for active devices..."
    for ip in "${active_devices[@]}"; do
        local mac=$(arp -n "$ip" | grep "$ip" | awk '{print $3}')
        if [ -n "$mac" ]; then
            echo "$ip - MAC Address: $mac"
        else
            echo "$ip - MAC Address: Not found"
        fi
    done
}

# main script execution
network_range=$(get_network_range)
active_devices=$(scan_network "$network_range")
get_mac_address "${active_devices[@]}"