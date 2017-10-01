#!/bin/bash
# netscan.sh
# this script scans the local network for active devices, retrieves mac addresses, and checks for open ports.

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
    active_devices=()

    # loop through addresses 1-254 to find active devices
    for i in {1..254}; do
        ip="${ip_base}${i}"
        if ping -c 1 -W 1 "$ip" &> /dev/null; then
            echo "$ip is active"
            active_devices+=("$ip")
        fi
    done

    echo "${active_devices[@]}"
}

# function to retrieve MAC addresses for active devices
get_mac_addresses() {
    local active_devices=("$@")
    echo -e "\nretrieving mac addresses for active devices..."
    
    # retrieve the ARP table
    arp_table=$(arp -n)

    for ip in "${active_devices[@]}"; do
        mac=$(echo "$arp_table" | grep -w "$ip" | awk '{print $3}')
        if [ -n "$mac" ]; then
            echo "$ip - MAC Address: $mac"
        else
            echo "$ip - MAC Address: Not found"
        fi
    done
}

# function to check for open common ports on active devices
check_open_ports() {
    local active_devices=("$@")
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

    echo -e "\nchecking for open ports on active devices..."
    for ip in "${active_devices[@]}"; do
        echo -e "\n$ip"
        for port in "${!common_ports[@]}"; do
            (echo > /dev/tcp/"$ip"/"$port") &> /dev/null && \
                echo "Port $port is open - ${common_ports[$port]}"
        done
    done
}

# main script execution
network_range=$(get_network_range)
if [ -z "$network_range" ]; then
    echo "could not determine network range. please check your connection."
    exit 1
fi

# scan the network, retrieve MAC addresses, and check open ports
active_devices=($(scan_network "$network_range"))
get_mac_addresses "${active_devices[@]}"
check_open_ports "${active_devices[@]}"
