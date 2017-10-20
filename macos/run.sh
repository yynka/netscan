#!/bin/bash
# run.sh
# macOS network scanner for discovering active devices on the local network.

# function to get the local network range
get_network_range() {
    local interface=$(route get default | grep 'interface:' | awk '{print $2}')
    local ip_info=$(ifconfig "$interface" | grep 'inet ' | awk '{print $2, $4}')
    local ip_address=$(echo "$ip_info" | awk '{print $1}')
    local subnet_mask=$(echo "$ip_info" | awk '{print $2}')
    
    # convert subnet mask to CIDR prefix
    local cidr_prefix=$(echo "$subnet_mask" | awk -F. '{print $1, $2, $3, $4}' | \
        awk '{print ($1 * 16777216 + $2 * 65536 + $3 * 256 + $4)}' | \
        awk '{for (i = 31; i >= 0; i--) { if (and($1, lshift(1, i))) { print 32 - i; exit } }}')
    
    echo "$ip_address/$cidr_prefix"
}

# function to scan the network for active devices
scan_network() {
    local network_range="$1"
    local ip_base=$(echo "$network_range" | cut -d '/' -f 1 | sed 's/\.[0-9]*$//')
    echo "scanning network range: $network_range"

    for i in {1..254}; do
        local ip="$ip_base.$i"
        if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
            echo "$ip is active"
        fi
    done
}

# main execution
network_range=$(get_network_range)
if [ -z "$network_range" ]; then
    echo "error: could not determine network range."
    exit 1
fi

scan_network "$network_range"
