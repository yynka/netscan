#!/bin/bash

# netscan.sh
# Advanced network scanner for device discovery and service enumeration
# Requires: ipcalc, curl, jq

# Common ports with service names
declare -A COMMON_PORTS=(
    [20]="FTP-Data" [21]="FTP" [22]="SSH" [23]="Telnet"
    [25]="SMTP" [53]="DNS" [80]="HTTP" [110]="POP3"
    [123]="NTP" [143]="IMAP" [161]="SNMP" [443]="HTTPS"
    [445]="SMB" [3389]="RDP" [8080]="HTTP-Alt"
)

# Default values
SKIP_PORT_SCAN=false
TIMEOUT=1
OUTPUT_FILE=""
MAC_VENDOR_API="https://api.macvendors.com"
VERBOSE=true

# Usage function
usage() {
    echo "Usage: $0 [-s] [-t timeout] [-o output_file] [-q]"
    echo "  -s: Skip port scan"
    echo "  -t: Timeout in milliseconds (default: 1000)"
    echo "  -o: Output file (CSV format)"
    echo "  -q: Quiet mode"
    exit 1
}

# Parse arguments
while getopts "st:o:qh" opt; do
    case $opt in
        s) SKIP_PORT_SCAN=true ;;
        t) TIMEOUT=$((OPTARG/1000)) ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        q) VERBOSE=false ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Logging function
log() {
    local level=$1
    local message=$2
    local color=$3
    
    if [ "$VERBOSE" = true ]; then
        echo -e "\e[${color}m[${level}] ${message}\e[0m"
    fi
}

# Get network interface and range
get_network_range() {
    if ! command -v ipcalc >/dev/null 2>&1; then
        log "*" "ipcalc is required but not installed. Please install it first." "31"
        exit 1
    }

    local interface=$(ip -o -4 route show to default | awk '{print $5}')
    if [ -z "$interface" ]; then
        log "*" "No valid network interface found" "31"
        exit 1
    }

    local ip_info=$(ip -o -4 addr show "$interface" | awk '{print $4}')
    local ip_addr=${ip_info%/*}
    local prefix=${ip_info#*/}
    local network=$(ipcalc -n "$ip_info" | grep "Network:" | awk '{print $2}')
    
    echo "$network|$prefix|$ip_addr|$interface"
}

# MAC vendor lookup function
get_mac_vendor() {
    local mac=$1
    local oui=${mac//:/}
    oui=${oui:0:6}
    oui=${oui^^}
    
    if [ -n "$oui" ]; then
        local vendor
        vendor=$(curl -s "$MAC_VENDOR_API/$oui" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$vendor" ] && [[ ! "$vendor" =~ "error" ]]; then
            echo "$vendor"
        else
            echo "Unknown"
        fi
    else
        echo "Unknown"
    fi
}

# Function to scan network for active hosts
scan_network() {
    local network_info=$1
    local network=${network_info%|*|*|*}
    local prefix=${network_info#*|};prefix=${prefix%|*|*}
    
    log "*" "Starting network scan on network $network/$prefix" "36"
    
    # Calculate host range
    local hosts=$((2**(32-prefix) - 2))
    local base_ip=${network%.*}
    local start_ip=${network##*.}
    
    # Create temporary directory for scan results
    local tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT
    
    # Parallel ping sweep
    for i in $(seq 1 $hosts); do
        local ip="$base_ip.$((start_ip + i))"
        (ping -c 1 -W 1 "$ip" >/dev/null 2>&1 && echo "$ip" > "$tmp_dir/$i") &
        
        # Limit parallel processes
        [ $((i % 50)) -eq 0 ] && wait
    done
    wait
    
    # Collect results
    find "$tmp_dir" -type f -exec cat {} \;
}

# Function to get device information
get_device_info() {
    local ip=$1
    local hostname=$(getent hosts "$ip" | awk '{print $2}')
    [ -z "$hostname" ] && hostname="N/A"
    
    local mac=$(ip neigh show "$ip" | awk '{print $5}')
    local vendor="Unknown"
    
    if [ -n "$mac" ] && [[ "$mac" =~ ^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$ ]]; then
        vendor=$(get_mac_vendor "$mac")
    else
        mac="N/A"
    fi
    
    echo "$hostname|$mac|$vendor"
}

# Function to scan ports
scan_ports() {
    local ip=$1
    local open_ports=()
    local tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT
    
    log "*" "Scanning ports on $ip (timeout: ${TIMEOUT}s)" "36"
    
    # Parallel port scanning
    for port in "${!COMMON_PORTS[@]}"; do
        (timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null && \
            echo "$port (${COMMON_PORTS[$port]})" > "$tmp_dir/$port") &
    done
    wait
    
    # Collect results
    while read -r port_file; do
        if [ -f "$port_file" ]; then
            local port_info=$(cat "$port_file")
            open_ports+=("$port_info")
            log "+" "$ip - Port $port_info open" "32"
        fi
    done < <(find "$tmp_dir" -type f)
    
    # Join results with commas
    (IFS=,; echo "${open_ports[*]}")
}

# Main execution
network_info=$(get_network_range)
log "*" "Network Information: ${network_info//|/, }" "36"

# Create CSV header if output file specified
if [ -n "$OUTPUT_FILE" ]; then
    echo "IP Address,Hostname,MAC Address,Vendor,Open Ports" > "$OUTPUT_FILE"
fi

# Scan for active hosts
mapfile -t active_hosts < <(scan_network "$network_info")

# Process each active host
for ip in "${active_hosts[@]}"; do
    if [ -n "$ip" ]; then
        log "+" "Found active host: $ip" "32"
        
        # Get device information
        IFS='|' read -r hostname mac vendor <<< "$(get_device_info "$ip")"
        
        # Scan ports if not skipped
        if [ "$SKIP_PORT_SCAN" = false ]; then
            open_ports=$(scan_ports "$ip")
        else
            open_ports="N/A"
        fi
        
        # Output results
        if [ "$VERBOSE" = true ]; then
            echo -e "\e[32m[+] $ip ($hostname):\e[0m"
            echo "    MAC: $mac"
            echo "    Vendor: $vendor"
            echo "    Open Ports: $open_ports"
        fi
        
        # Save to CSV if output file specified
        if [ -n "$OUTPUT_FILE" ]; then
            echo "$ip,$hostname,$mac,$vendor,\"$open_ports\"" >> "$OUTPUT_FILE"
        fi
    fi
done

if [ -n "$OUTPUT_FILE" ]; then
    log "*" "Results exported to $OUTPUT_FILE" "36"
fi