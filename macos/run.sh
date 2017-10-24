#!/bin/bash

# run.sh
# this script scans the local network for active devices, retrieves MAC addresses, and checks for open ports.

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

# function to retrieve MAC addresses for active devices
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

# function to check for open common ports
check_open_ports() {
    local active_devices=("$@")

    declare -A common_ports=(
        [21]="FTP" [22]="SSH" [23]="Telnet"
        [25]="SMTP" [53]="DNS" [80]="HTTP"
        [110]="POP3" [143]="IMAP" [443]="HTTPS"
        [3389]="RDP"
    )

    echo -e "\nchecking for open ports on active devices..."
    for ip in "${active_devices[@]}"; do
        echo -e "\n$ip"
        for port in "${!common_ports[@]}"; do
            if nc -z -w1 "$ip" "$port" &>/dev/null; then
                echo "Port $port is open - ${common_ports[$port]}"
            fi
        done
    done
}

# main script execution: get the network range, scan for devices, retrieve MAC addresses, and check open ports
network_range=$(get_network_range)
active_devices=$(scan_network "$network_range")
get_mac_address "${active_devices[@]}"
check_open_ports "${active_devices[@]}"
