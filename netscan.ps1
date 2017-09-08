# Enhanced netscan.ps1
[CmdletBinding()]
param(
    [switch]$Monitor,
    [int]$RefreshInterval = 300,
    [string]$LogPath = "$HOME\DeviceProfiles"
)

# Create log directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

class DeviceProfile {
    [string]$IPAddress
    [string]$Hostname
    [string]$MACAddress
    [string]$Vendor
    [string]$ComputerName
    [string]$OSVersion
    [string]$LastUser
    [datetime]$FirstSeen
    [datetime]$LastSeen
    [System.Collections.ArrayList]$Services
    [System.Collections.ArrayList]$SharedResources
    [System.Collections.ArrayList]$History
    
    DeviceProfile([string]$ip) {
        $this.IPAddress = $ip
        $this.FirstSeen = Get-Date
        $this.LastSeen = Get-Date
        $this.Services = New-Object System.Collections.ArrayList
        $this.SharedResources = New-Object System.Collections.ArrayList
        $this.History = New-Object System.Collections.ArrayList
    }
}

function Get-DeviceDetails {
    param (
        [Parameter(Mandatory)]
        [string]$IPAddress
    )
    
    $profile = [DeviceProfile]::new($IPAddress)
    
    try {
        # Basic system info
        $sysInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $IPAddress -ErrorAction Stop
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $IPAddress -ErrorAction Stop
        
        $profile.ComputerName = $sysInfo.Name
        $profile.OSVersion = $osInfo.Caption
        $profile.LastUser = $osInfo.RegisteredUser
        
        # Get running services
        Get-Service -ComputerName $IPAddress | Where-Object {$_.Status -eq 'Running'} | ForEach-Object {
            $profile.Services.Add(@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = $_.StartType
            }) | Out-Null
        }
        
        # Get shared resources
        Get-WmiObject -Class Win32_Share -ComputerName $IPAddress | ForEach-Object {
            $profile.SharedResources.Add(@{
                Name = $_.Name
                Path = $_.Path
                Description = $_.Description
            }) | Out-Null
        }
        
        # Network interfaces
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $IPAddress | 
            Where-Object {$_.IPEnabled} | ForEach-Object {
                $profile.History.Add(@{
                    Timestamp = Get-Date
                    Type = "NetworkAdapter"
                    Data = @{
                        Description = $_.Description
                        IPAddress = $_.IPAddress
                        DefaultGateway = $_.DefaultIPGateway
                        DHCPEnabled = $_.DHCPEnabled
                        DHCPServer = $_.DHCPServer
                    }
                }) | Out-Null
            }
    }
    catch {
        Write-Warning "Could not retrieve complete device details for $IPAddress : $_"
    }
    
    return $profile
}

function Show-DeviceMonitor {
    param (
        [array]$Devices
    )
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Network Device Monitor"
    $form.Size = New-Object System.Drawing.Size(800,600)
    
    $deviceList = New-Object System.Windows.Forms.ComboBox
    $deviceList.Location = New-Object System.Drawing.Point(10,10)
    $deviceList.Size = New-Object System.Drawing.Size(300,20)
    $deviceList.Items.AddRange($Devices | ForEach-Object { "$($_.ComputerName) ($($_.IPAddress))" })
    $form.Controls.Add($deviceList)
    
    $detailsPanel = New-Object System.Windows.Forms.Panel
    $detailsPanel.Location = New-Object System.Drawing.Point(10,40)
    $detailsPanel.Size = New-Object System.Drawing.Size(760,500)
    $detailsPanel.AutoScroll = $true
    $form.Controls.Add($detailsPanel)
    
    $deviceList.Add_SelectedIndexChanged({
        $detailsPanel.Controls.Clear()
        $selectedDevice = $Devices[$deviceList.SelectedIndex]
        
        $y = 10
        @(
            @{Label="Computer Name"; Value=$selectedDevice.ComputerName},
            @{Label="IP Address"; Value=$selectedDevice.IPAddress},
            @{Label="MAC Address"; Value=$selectedDevice.MACAddress},
            @{Label="OS Version"; Value=$selectedDevice.OSVersion},
            @{Label="Last User"; Value=$selectedDevice.LastUser},
            @{Label="First Seen"; Value=$selectedDevice.FirstSeen},
            @{Label="Last Seen"; Value=$selectedDevice.LastSeen}
        ) | ForEach-Object {
            $label = New-Object System.Windows.Forms.Label
            $label.Location = New-Object System.Drawing.Point(0,$y)
            $label.Size = New-Object System.Drawing.Size(760,20)
            $label.Text = "$($_.Label): $($_.Value)"
            $detailsPanel.Controls.Add($label)
            $y += 25
        }
        
        # Add services section
        $y += 10
        $servicesLabel = New-Object System.Windows.Forms.Label
        $servicesLabel.Location = New-Object System.Drawing.Point(0,$y)
        $servicesLabel.Size = New-Object System.Drawing.Size(760,20)
        $servicesLabel.Text = "Running Services:"
        $detailsPanel.Controls.Add($servicesLabel)
        $y += 25
        
        foreach ($service in $selectedDevice.Services) {
            $serviceLabel = New-Object System.Windows.Forms.Label
            $serviceLabel.Location = New-Object System.Drawing.Point(20,$y)
            $serviceLabel.Size = New-Object System.Drawing.Size(740,20)
            $serviceLabel.Text = "$($service.DisplayName) [$($service.Name)]"
            $detailsPanel.Controls.Add($serviceLabel)
            $y += 20
        }
        
        # Add history section
        $y += 20
        $historyLabel = New-Object System.Windows.Forms.Label
        $historyLabel.Location = New-Object System.Drawing.Point(0,$y)
        $historyLabel.Size = New-Object System.Drawing.Size(760,20)
        $historyLabel.Text = "History:"
        $detailsPanel.Controls.Add($historyLabel)
        $y += 25
        
        foreach ($entry in ($selectedDevice.History | Sort-Object Timestamp -Descending)) {
            $entryLabel = New-Object System.Windows.Forms.Label
            $entryLabel.Location = New-Object System.Drawing.Point(20,$y)
            $entryLabel.Size = New-Object System.Drawing.Size(740,40)
            $entryLabel.Text = "[$($entry.Timestamp)] $($entry.Type)`n$($entry.Data | ConvertTo-Json -Compress)"
            $detailsPanel.Controls.Add($entryLabel)
            $y += 45
        }
    })
    
    if ($Monitor) {
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $RefreshInterval * 1000
        $timer.Add_Tick({
            $deviceList.SelectedIndex = $deviceList.SelectedIndex
        })
        $timer.Start()
    }
    
    $form.ShowDialog()
}

# Main execution
Write-Host "[*] Starting enhanced network scan..."
$networkInfo = Get-NetworkRange
$activeDevices = Start-NetworkScan -NetworkInfo $networkInfo
$deviceProfiles = @()

foreach ($device in $activeDevices) {
    Write-Host "[*] Profiling device: $($device.IPAddress)..."
    $profile = Get-DeviceDetails -IPAddress $device.IPAddress
    $deviceProfiles += $profile
    
    # Save profile to log file
    $profile | ConvertTo-Json -Depth 10 | 
        Out-File -FilePath "$LogPath\$($device.IPAddress.Replace('.','_')).json"
}

Show-DeviceMonitor -Devices $deviceProfiles