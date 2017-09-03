# netscan.ps1
# Advanced network scanner for device discovery and service enumeration
[CmdletBinding()]
param(
    [switch]$SkipPortScan,
    [int]$Timeout = 1000,
    [string]$OutputFile
)

# Common ports with service names
$COMMON_PORTS = @{
    20  = "FTP-Data"
    21  = "FTP"
    22  = "SSH"
    23  = "Telnet"
    25  = "SMTP"
    53  = "DNS"
    80  = "HTTP"
    110 = "POP3"
    123 = "NTP"
    143 = "IMAP"
    161 = "SNMP"
    443 = "HTTPS"
    445 = "SMB"
    3389 = "RDP"
    8080 = "HTTP-Alt"
}

function Get-NetworkRange {
    try {
        $interface = Get-NetIPAddress -AddressFamily IPv4 | 
            Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixLength -lt 32 } |
            Select-Object -First 1

        if (-not $interface) {
            throw "No valid network interface found"
        }

        # Calculate network address range
        $ipBytes = [System.Net.IPAddress]::Parse($interface.IPAddress).GetAddressBytes()
        $maskBytes = [byte[]](1..4 | ForEach-Object { 
            if ($_ * 8 -le $interface.PrefixLength) { 255 }
            elseif (($_ - 1) * 8 -lt $interface.PrefixLength) { 
                [math]::Pow(2, 8 - ($interface.PrefixLength % 8)) - 1
            }
            else { 0 }
        })

        $networkAddress = [byte[]](0..3 | ForEach-Object { $ipBytes[$_] -band $maskBytes[$_] })
        $networkBase = [System.Net.IPAddress]::new($networkAddress).ToString()

        return @{
            Base = $networkBase
            Prefix = $interface.PrefixLength
            Interface = $interface.IPAddress
        }
    }
    catch {
        Write-Error "Failed to determine network range: $_"
        exit 1
    }
}

function Start-NetworkScan {
    param (
        [Parameter(Mandatory)]
        [hashtable]$NetworkInfo
    )

    Write-Host "[*] Starting network scan on $($NetworkInfo.Interface)/$($NetworkInfo.Prefix)" -ForegroundColor Cyan
    
    # Calculate scan range based on subnet
    $hosts = [math]::Pow(2, (32 - $NetworkInfo.Prefix)) - 2
    $scanRange = 1..$hosts
    
    # Parallel ping sweep
    $pingJobs = $scanRange | ForEach-Object {
        $ip = $NetworkInfo.Base -replace '\d+$', $_
        Start-Job -ScriptBlock {
            Test-Connection -ComputerName $args[0] -Count 1 -Quiet
        } -ArgumentList $ip
    }

    $activeDevices = @()
    foreach ($i in 0..($pingJobs.Count-1)) {
        $job = $pingJobs[$i]
        if ((Receive-Job -Job $job -Wait)) {
            $ip = $NetworkInfo.Base -replace '\d+$', ($i + 1)
            $activeDevices += [PSCustomObject]@{
                IPAddress = $ip
                Hostname = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { "N/A" }
            }
            Write-Host "[+] Found active host: $ip" -ForegroundColor Green
        }
        Remove-Job -Job $job
    }

    return $activeDevices
}

function Get-DeviceMACAddress {
    param (
        [array]$ActiveDevices
    )

    Write-Host "[*] Retrieving MAC addresses..." -ForegroundColor Cyan
    $arpTable = arp -a
    
    foreach ($device in $ActiveDevices) {
        $macMatch = $arpTable | Select-String $device.IPAddress
        if ($macMatch) {
            $mac = ($macMatch.ToString() -split '\s+')[2]
            $device | Add-Member -MemberType NoteProperty -Name MACAddress -Value $mac
            
            # Try to get vendor from MAC OUI
            $oui = $mac.Replace('-', '').Substring(0, 6)
            $device | Add-Member -MemberType NoteProperty -Name Vendor -Value (Get-MACVendor $oui)
        }
    }
}

function Get-MACVendor {
    param([string]$OUI)
    # Add your own MAC vendor lookup logic or API call here
    return "Unknown"
}

function Test-OpenPorts {
    param (
        [array]$ActiveDevices,
        [int]$Timeout
    )

    Write-Host "[*] Scanning for open ports (timeout: ${Timeout}ms)..." -ForegroundColor Cyan
    
    foreach ($device in $ActiveDevices) {
        $openPorts = @()
        
        # Parallel port scanning
        $portJobs = $COMMON_PORTS.Keys | ForEach-Object {
            $port = $_
            Start-Job -ScriptBlock {
                $tcp = New-Object System.Net.Sockets.TcpClient
                try {
                    $result = $tcp.BeginConnect($args[0], $args[1], $null, $null)
                    $success = $result.AsyncWaitHandle.WaitOne($args[2])
                    if ($success) { return $true }
                }
                catch {}
                finally {
                    $tcp.Close()
                }
                return $false
            } -ArgumentList $device.IPAddress, $port, $Timeout
        }

        foreach ($port in $COMMON_PORTS.Keys) {
            $job = $portJobs[$port - 1]
            if ((Receive-Job -Job $job -Wait)) {
                $openPorts += "$port ($($COMMON_PORTS[$port]))"
                Write-Host "[+] $($device.IPAddress) - Port $port open" -ForegroundColor Green
            }
            Remove-Job -Job $job
        }

        $device | Add-Member -MemberType NoteProperty -Name OpenPorts -Value ($openPorts -join ", ")
    }
}

# Main execution
$networkInfo = Get-NetworkRange
$activeDevices = Start-NetworkScan -NetworkInfo $networkInfo
Get-DeviceMACAddress -ActiveDevices $activeDevices

if (-not $SkipPortScan) {
    Test-OpenPorts -ActiveDevices $activeDevices -Timeout $Timeout
}

# Generate report
$report = $activeDevices | Format-Table -AutoSize -Property `
    IPAddress, Hostname, MACAddress, Vendor, OpenPorts | Out-String

Write-Host "`n[*] Scan Results:" -ForegroundColor Cyan
Write-Host $report

if ($OutputFile) {
    $activeDevices | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Host "[*] Results exported to $OutputFile" -ForegroundColor Cyan
}