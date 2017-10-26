#!/bin/bash

# run.sh
# This script scans the local network for active devices, retrieves MAC addresses, checks for open ports, and provides a summary.

# Get the local IP address and subnet mask to figure out the network range
get_network_range() {
    local interface=$(ipconfig getifaddr en0)
    if [ -z "$interface" ]; then
        echo "No valid network interface found"
        exit 1
    fi

    local subnet_mask=$(ifconfig en0 | grep 'netmask' | awk '{ print $4 }')
    local prefix=$(echo "$subnet_mask" | awk -F '.' '{print ($1*16777216 + $2*65536 + $3*256 + $4)*1}')
    echo "$interface/$prefix"
}

# Perform a network scan by pinging each IP in the range and checking which ones respond
scan_network() {
    local network_range=$1
    echo "Scanning network range: $network_range"

    local ip_base=$(echo $network_range | awk -F '.' '{OFS="."; print $1, $2, $3, ""}')
    local active_devices=()

    for i in {1..254}; do
        local ip="$ip_base$i"
        if ping -c 1 -W 1 $ip >/dev/null 2>&1; then
            active_devices+=("$ip")
            echo "$ip is active"
        fi
    done
    echo "${active_devices[@]}"
}

# Retrieve MAC addresses for each active device using arp
get_mac_addresses() {
    local active_devices=($@)
    echo -e "\nRetrieving MAC addresses for active devices..."

    for ip in "${active_devices[@]}"; do
        local mac=$(arp -n $ip | awk '/ether/ {print $3}')
        if [ -n "$mac" ]; then
            echo "$ip - MAC Address: $mac"
        else
            echo "$ip - MAC Address: Not found"
        fi
    done
}

# Check for open common ports on each active device
check_open_ports() {
    local active_devices=($@)
    declare -A common_ports=(
        [21]="FTP"
        [22]="SSH"
        [23]="Telnet"
        [25]="SMTP"
        [53]="DNS"
        [80]="HTTP"
        [110]="POP3"
        [143]="IMAP"
        [443]="HTTPS"
        [3389]="RDP"
    )

    echo -e "\nChecking for open ports on active devices..."

    for ip in "${active_devices[@]}"; do
        echo -e "\n$ip"
        for port in "${!common_ports[@]}"; do
            if nc -z -w 1 $ip $port 2>/dev/null; then
                echo "Port $port is open - ${common_ports[$port]}"
            fi
        done
    done
}

# Display a summary of all active devices
display_summary() {
    local active_devices=($@)
    echo -e "\nSummary of active devices:"

    for ip in "${active_devices[@]}"; do
        local mac=$(arp -n $ip | awk '/ether/ {print $3}')
        [ -z "$mac" ] && mac="Not found"

        echo "IP: $ip, MAC: $mac"
    done
}

# Main script execution
network_range=$(get_network_range)
active_devices=($(scan_network $network_range))
get_mac_addresses "${active_devices[@]}"
check_open_ports "${active_devices[@]}"
display_summary "${active_devices[@]}"
