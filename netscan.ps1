# netscan.ps1
# this script scans the local network for active devices, retrieves MAC addresses, and checks for open ports.

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
    $activeDevices = @()

    for ($i = 1; $i -le 254; $i++) {
        $ip = "$ipBase$i"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
            $activeDevices += [PSCustomObject]@{
                IPAddress = $ip
            }
            Write-Host "$ip is active"
        }
    }
    return $activeDevices
}

# retrieve MAC addresses for each active device using arp
function Get-MACAddress {
    param (
        [array]$activeDevices
    )

    Write-Host "`nretrieving MAC addresses for active devices..."
    $arpTable = arp -a

    foreach ($device in $activeDevices) {
        $ip = $device.IPAddress
        $mac = ($arpTable | Select-String $ip).ToString().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)[1]
        if ($mac) {
            $device | Add-Member -MemberType NoteProperty -Name MACAddress -Value $mac
            Write-Host "$ip - MAC Address: $mac"
        } else {
            Write-Host "$ip - MAC Address: Not found"
        }
    }
}

# check for open common ports on each active device
function Check-OpenPorts {
    param (
        [array]$activeDevices
    )

    $commonPorts = @{
        21  = "FTP"
        22  = "SSH"
        23  = "Telnet"
        25  = "SMTP"
        53  = "DNS"
        80  = "HTTP"
        110 = "POP3"
        143 = "IMAP"
        443 = "HTTPS"
        3389 = "RDP"
    }

    Write-Host "`nchecking for open ports on active devices..."
    foreach ($device in $activeDevices) {
        Write-Host "`n$($device.IPAddress)"
        foreach ($port in $commonPorts.Keys) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($device.IPAddress, $port)
                $tcpClient.Close()
                Write-Host "Port $port is open - $($commonPorts[$port])"
                $device | Add-Member -MemberType NoteProperty -Name OpenPorts -Value "$port: $($commonPorts[$port])"
            } catch {
                # port is closed, no action needed
            }
        }
    }
}

# main script execution: get the network range, scan for devices, retrieve MAC addresses, and check open ports
$networkRange = Get-NetworkRange
$activeDevices = Scan-Network -networkRange $networkRange
Get-MACAddress -activeDevices $activeDevices
Check-OpenPorts -activeDevices $activeDevices
