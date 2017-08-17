# netscan.ps1
# this script does a basic network scan to find active devices on the local network.

# get the local IP address and subnet mask to figure out the network range
function Get-NetworkRange {
    $ipconfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }
    $ipAddress = $ipconfig.IPAddress
    $subnetMask = $ipconfig.PrefixLength
    $networkRange = "$ipAddress/$subnetMask"
    return $networkRange
}

# perform a network scan by pinging each IP in the range and checking which ones respond
function Scan-Network {
    param (
        [string]$networkRange
    )

    Write-Host "scanning network range: $networkRange"
    
    # split out the IP base to loop through addresses 1-254
    $ipBase = $networkRange -replace '\d+$', ''
    for ($i = 1; $i -le 254; $i++) {
        $ip = "$ipBase$i"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
            Write-Host "$ip is active"
        }
    }
}

# main script execution: get the network range and start scanning
$networkRange = Get-NetworkRange
Scan-Network -networkRange $networkRange