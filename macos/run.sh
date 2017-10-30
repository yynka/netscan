#!/bin/bash

# run.sh
# Enhanced network scanner for macOS. Scans the local network for active devices, retrieves MAC addresses, checks for open ports, monitors services, and provides a GUI for viewing device details.

# Ensure required tools are installed
if ! command -v ipconfig >/dev/null || ! command -v ifconfig >/dev/null || ! command -v arp >/dev/null || ! command -v nc >/dev/null || ! command -v osascript >/dev/null; then
    echo "This script requires ipconfig, ifconfig, arp, nc, and osascript. Ensure they are installed."
    exit 1
fi

# Get the local IP address and subnet mask to figure out the network range
get_network_range() {
    local interface=$(ipconfig getifaddr en0)
    if [ -z "$interface" ]; then
        echo "No valid network interface found"
        exit 1
    fi

    local subnet_mask=$(ifconfig en0 | grep 'netmask' | awk '{ print $4 }')
    local cidr_prefix=$(echo "$subnet_mask" | awk -F '.' '{print (log(2^32 - ($1*16777216 + $2*65536 + $3*256 + $4))/log(2))}')
    echo "$interface/$cidr_prefix"
}

# Perform a network scan by pinging each IP in the range and checking which ones respond
scan_network() {
    local network_range=$1
    echo "Scanning network range: $network_range"

    local ip_base=$(echo $network_range | awk -F '/' '{print $1}' | awk -F '.' '{OFS="."; print $1, $2, $3, ""}')
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

# Retrieve MAC addresses and vendor details for each active device using arp
get_mac_addresses() {
    local active_devices=($@)
    echo -e "\nRetrieving MAC addresses and vendor details for active devices..."

    for ip in "${active_devices[@]}"; do
        local mac=$(arp -n $ip | awk '/ether/ {print $3}')
        local vendor="Unknown"

        if [ -n "$mac" ]; then
            # Retrieve vendor information using a hypothetical local database or online API
            vendor=$(curl -s "https://api.macvendors.com/$mac" || echo "Unknown")
            echo "$ip - MAC Address: $mac, Vendor: $vendor"
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
summarize_devices() {
    local active_devices=($@)
    echo -e "\nSummary of active devices:"

    for ip in "${active_devices[@]}"; do
        local mac=$(arp -n $ip | awk '/ether/ {print $3}')
        [ -z "$mac" ] && mac="Not found"

        echo "IP: $ip, MAC: $mac"
    done
}

# Show device details in a macOS GUI
show_device_monitor() {
    local active_devices=($@)
    echo -e "\nLaunching macOS device monitor..."

    # Prepare AppleScript content
    local details=""
    for ip in "${active_devices[@]}"; do
        local mac=$(arp -n $ip | awk '/ether/ {print $3}')
        details+="IP: $ip\nMAC: ${mac:-Not found}\n\n"
    done

    osascript <<EOF
    tell application "System Events"
        activate
        display dialog "Device Monitor:\n\n$details" buttons {"OK"} default button "OK"
    end tell
EOF
}

# Main script execution
network_range=$(get_network_range)
active_devices=($(scan_network $network_range))
get_mac_addresses "${active_devices[@]}"
check_open_ports "${active_devices[@]}"
summarize_devices "${active_devices[@]}"
show_device_monitor "${active_devices[@]}"