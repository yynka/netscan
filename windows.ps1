# run.ps1
[CmdletBinding()]
param(
    [switch]$Monitor,
    [int]$RefreshInterval = 300,
    [string]$LogPath = "$PSScriptRoot\..\logs",
    [string]$Username,
    [string]$Password,
    [switch]$UseSSH,
    [int]$SSHPort = 22,
    [int]$WinRMPort = 5985
)

# Update log directory creation
$LogPath = (Resolve-Path $LogPath).Path
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

# Create log directory
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

# Load required assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Web

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
    [string]$Platform
    [bool]$IsAccessible
    
    DeviceProfile([string]$ip) {
        $this.IPAddress = $ip
        $this.FirstSeen = Get-Date
        $this.LastSeen = Get-Date
        $this.Services = New-Object System.Collections.ArrayList
        $this.SharedResources = New-Object System.Collections.ArrayList
        $this.History = New-Object System.Collections.ArrayList
        $this.IsAccessible = $false
    }
}

function Get-NetworkRange {
    try {
        $interface = Get-NetIPAddress -AddressFamily IPv4 | 
            Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixLength -lt 32 } |
            Select-Object -First 1

        if (-not $interface) {
            throw "No valid network interface found"
        }

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

function Test-WinRMAccess {
    param([string]$IPAddress)
    
    try {
        $result = Test-WSMan -ComputerName $IPAddress -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-SSHAccess {
    param([string]$IPAddress, [int]$Port = 22)
    
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect($IPAddress, $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne(1000)
        $tcp.Close()
        return $success
    }
    catch {
        return $false
    }
}

function Get-MACVendor {
    param([string]$MAC)
    
    try {
        $uri = "https://api.macvendors.com/$MAC"
        $response = Invoke-RestMethod -Uri $uri -Method Get
        return $response
    }
    catch {
        return "Unknown"
    }
}

function Get-WindowsDeviceDetails {
    param (
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [PSCredential]$Credential
    )
    
    $profile = [DeviceProfile]::new($IPAddress)
    
    try {
        # Use WinRM session
        $session = New-PSSession -ComputerName $IPAddress -Credential $Credential -ErrorAction Stop
        
        # Basic system info
        $sysInfo = Invoke-Command -Session $session -ScriptBlock {
            Get-WmiObject -Class Win32_ComputerSystem
        }
        $osInfo = Invoke-Command -Session $session -ScriptBlock {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        
        $profile.ComputerName = $sysInfo.Name
        $profile.OSVersion = $osInfo.Caption
        $profile.LastUser = $osInfo.RegisteredUser
        $profile.Platform = "Windows"
        $profile.IsAccessible = $true
        
        # Get running services
        Invoke-Command -Session $session -ScriptBlock {
            Get-Service | Where-Object {$_.Status -eq 'Running'}
        } | ForEach-Object {
            $profile.Services.Add(@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = $_.StartType
            }) | Out-Null
        }
        
        # Get shared resources
        Invoke-Command -Session $session -ScriptBlock {
            Get-WmiObject -Class Win32_Share
        } | ForEach-Object {
            $profile.SharedResources.Add(@{
                Name = $_.Name
                Path = $_.Path
                Description = $_.Description
            }) | Out-Null
        }
        
        # Network interfaces
        Invoke-Command -Session $session -ScriptBlock {
            Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
        } | ForEach-Object {
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
        
        Remove-PSSession $session
    }
    catch {
        Write-Warning "Could not retrieve complete Windows device details for $IPAddress : $_"
    }
    
    return $profile
}

function Get-LinuxDeviceDetails {
    param (
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [PSCredential]$Credential,
        [int]$Port = 22
    )
    
    $profile = [DeviceProfile]::new($IPAddress)
    
    try {
        # Use SSH.NET library for SSH access
        $ssh = New-Object Renci.SshNet.SshClient($IPAddress, $Port, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $ssh.Connect()
        
        # Basic system info
        $hostnameCmd = $ssh.CreateCommand("hostname")
        $profile.ComputerName = $hostnameCmd.Execute().Trim()
        
        $osCmd = $ssh.CreateCommand("cat /etc/os-release")
        $osInfo = $osCmd.Execute()
        $profile.OSVersion = ($osInfo -split "`n" | Select-String "PRETTY_NAME").ToString().Split("=")[1].Trim('"')
        
        $lastUserCmd = $ssh.CreateCommand("last -n 1")
        $profile.LastUser = ($lastUserCmd.Execute() -split " ")[0]
        
        $profile.Platform = "Linux"
        $profile.IsAccessible = $true
        
        # Get running services
        $servicesCmd = $ssh.CreateCommand("systemctl list-units --type=service --state=running --no-pager")
        $services = $servicesCmd.Execute() -split "`n" | Select-String "\.service"
        foreach ($service in $services) {
            $parts = $service -split "\s+"
            if ($parts.Count -ge 5) {
                $profile.Services.Add(@{
                    Name = $parts[0]
                    DisplayName = $parts[4]
                    Status = "Running"
                    StartType = "Enabled"
                }) | Out-Null
            }
        }
        
        # Get shared resources
        $sharesCmd = $ssh.CreateCommand("df -h --output=source,target,fstype | grep -E 'nfs|cifs|smb'")
        $shares = $sharesCmd.Execute() -split "`n"
        foreach ($share in $shares) {
            $parts = $share -split "\s+"
            if ($parts.Count -ge 3) {
                $profile.SharedResources.Add(@{
                    Name = $parts[1]
                    Path = $parts[0]
                    Description = $parts[2]
                }) | Out-Null
            }
        }
        
        # Network interfaces
        $ifconfigCmd = $ssh.CreateCommand("ip addr show")
        $interfaces = $ifconfigCmd.Execute()
        $profile.History.Add(@{
            Timestamp = Get-Date
            Type = "NetworkAdapter"
            Data = @{
                Description = "Network Interfaces"
                Interfaces = $interfaces
            }
        }) | Out-Null
        
        $ssh.Disconnect()
    }
    catch {
        Write-Warning "Could not retrieve complete Linux device details for $IPAddress : $_"
    }
    
    return $profile
}

function Get-DeviceDetails {
    param (
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [PSCredential]$Credential
    )
    
    # Test connectivity
    $winrm = Test-WinRMAccess -IPAddress $IPAddress
    $ssh = Test-SSHAccess -IPAddress $IPAddress -Port $SSHPort
    
    if ($winrm) {
        return Get-WindowsDeviceDetails -IPAddress $IPAddress -Credential $Credential
    }
    elseif ($ssh) {
        return Get-LinuxDeviceDetails -IPAddress $IPAddress -Credential $Credential -Port $SSHPort
    }
    else {
        $profile = [DeviceProfile]::new($IPAddress)
        $profile.Platform = "Unknown"
        return $profile
    }
}

function Start-NetworkScan {
    param (
        [Parameter(Mandatory)]
        [hashtable]$NetworkInfo
    )
    
    Write-Host "[*] Starting network scan on $($NetworkInfo.Interface)/$($NetworkInfo.Prefix)" -ForegroundColor Cyan
    
    $hosts = [math]::Pow(2, (32 - $NetworkInfo.Prefix)) - 2
    $scanRange = 1..$hosts
    
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
            try {
                $hostname = [System.Net.Dns]::GetHostEntry($ip).HostName
            }
            catch {
                $hostname = "N/A"
            }
            
            $activeDevices += [PSCustomObject]@{
                IPAddress = $ip
                Hostname = $hostname
            }
            Write-Host "[+] Found active host: $ip" -ForegroundColor Green
        }
        Remove-Job -Job $job
    }
    
    return $activeDevices
}

function Show-DeviceMonitor {
    param (
        [array]$Devices,
        [switch]$Monitor,
        [int]$RefreshInterval
    )
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Cross-Platform Network Device Monitor"
    $form.Size = New-Object System.Drawing.Size(1000,700)
    
    # Create layout
    $splitContainer = New-Object System.Windows.Forms.SplitContainer
    $splitContainer.Dock = [System.Windows.Forms.DockStyle]::Fill
    $splitContainer.SplitterDistance = 250
    $form.Controls.Add($splitContainer)
    
    # Device list (left panel)
    $deviceListView = New-Object System.Windows.Forms.ListView
    $deviceListView.View = [System.Windows.Forms.View]::Details
    $deviceListView.FullRowSelect = $true
    $deviceListView.Columns.Add("Device", 230)
    $deviceListView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $splitContainer.Panel1.Controls.Add($deviceListView)
    
    # Details tab control (right panel)
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
    $splitContainer.Panel2.Controls.Add($tabControl)
    
    # Create tabs
    $infoTab = New-Object System.Windows.Forms.TabPage
    $infoTab.Text = "Information"
    $servicesTab = New-Object System.Windows.Forms.TabPage
    $servicesTab.Text = "Services"
    $sharesTab = New-Object System.Windows.Forms.TabPage
    $sharesTab.Text = "Shared Resources"
    $historyTab = New-Object System.Windows.Forms.TabPage
    $historyTab.Text = "History"
    
    $tabControl.TabPages.AddRange(@($infoTab, $servicesTab, $sharesTab, $historyTab))
    
    # Info tab content
    $infoPanel = New-Object System.Windows.Forms.Panel
    $infoPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $infoPanel.AutoScroll = $true
    $infoTab.Controls.Add($infoPanel)
    
    # Services tab content
    $servicesListView = New-Object System.Windows.Forms.ListView
    $servicesListView.View = [System.Windows.Forms.View]::Details
    $servicesListView.FullRowSelect = $true
    $servicesListView.Columns.Add("Name", 150)
    $servicesListView.Columns.Add("Display Name", 250)
    $servicesListView.Columns.Add("Status", 100)
    $servicesListView.Columns.Add("Start Type", 100)
    $servicesListView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $servicesTab.Controls.Add($servicesListView)
    
    # Shares tab content
    $sharesListView = New-Object System.Windows.Forms.ListView
    $sharesListView.View = [System.Windows.Forms.View]::Details
    $sharesListView.FullRowSelect = $true
# Continuing from previous code...

$sharesListView.Columns.Add("Name", 150)
$sharesListView.Columns.Add("Path", 250)
$sharesListView.Columns.Add("Description", 200)
$sharesListView.Dock = [System.Windows.Forms.DockStyle]::Fill
$sharesTab.Controls.Add($sharesListView)

# History tab content
$historyListView = New-Object System.Windows.Forms.ListView
$historyListView.View = [System.Windows.Forms.View]::Details
$historyListView.FullRowSelect = $true
$historyListView.Columns.Add("Timestamp", 150)
$historyListView.Columns.Add("Type", 100)
$historyListView.Columns.Add("Details", 350)
$historyListView.Dock = [System.Windows.Forms.DockStyle]::Fill
$historyTab.Controls.Add($historyListView)

# Populate device list
foreach ($device in $Devices) {
    $item = New-Object System.Windows.Forms.ListViewItem(
        "$($device.ComputerName) ($($device.IPAddress)) [$($device.Platform)]"
    )
    $item.Tag = $device
    $deviceListView.Items.Add($item)
}

# Device selection handler
$deviceListView.Add_SelectedIndexChanged({
    if ($deviceListView.SelectedItems.Count -eq 0) { return }
    
    $device = $deviceListView.SelectedItems[0].Tag
    
    # Update info panel
    $infoPanel.Controls.Clear()
    $y = 10
    @(
        @{Label="Computer Name"; Value=$device.ComputerName},
        @{Label="IP Address"; Value=$device.IPAddress},
        @{Label="Platform"; Value=$device.Platform},
        @{Label="MAC Address"; Value=$device.MACAddress},
        @{Label="OS Version"; Value=$device.OSVersion},
        @{Label="Last User"; Value=$device.LastUser},
        @{Label="First Seen"; Value=$device.FirstSeen},
        @{Label="Last Seen"; Value=$device.LastSeen},
        @{Label="Status"; Value=if($device.IsAccessible){"Accessible"}else{"Inaccessible"}}
    ) | ForEach-Object {
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,$y)
        $label.Size = New-Object System.Drawing.Size(730,20)
        $label.Text = "$($_.Label): $($_.Value)"
        $infoPanel.Controls.Add($label)
        $y += 25
    }
    
    # Update services list
    $servicesListView.Items.Clear()
    foreach ($service in $device.Services) {
        $item = New-Object System.Windows.Forms.ListViewItem($service.Name)
        $item.SubItems.Add($service.DisplayName)
        $item.SubItems.Add($service.Status)
        $item.SubItems.Add($service.StartType)
        $servicesListView.Items.Add($item)
    }
    
    # Update shares list
    $sharesListView.Items.Clear()
    foreach ($share in $device.SharedResources) {
        $item = New-Object System.Windows.Forms.ListViewItem($share.Name)
        $item.SubItems.Add($share.Path)
        $item.SubItems.Add($share.Description)
        $sharesListView.Items.Add($item)
    }
    
    # Update history list
    $historyListView.Items.Clear()
    foreach ($entry in ($device.History | Sort-Object Timestamp -Descending)) {
        $item = New-Object System.Windows.Forms.ListViewItem($entry.Timestamp)
        $item.SubItems.Add($entry.Type)
        $item.SubItems.Add(($entry.Data | ConvertTo-Json -Compress))
        $historyListView.Items.Add($item)
    }
})

# Refresh timer for monitoring
if ($Monitor) {
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $RefreshInterval * 1000
    $timer.Add_Tick({
        $selectedIndex = $deviceListView.SelectedIndices[0]
        if ($selectedIndex -ge 0) {
            $device = $Devices[$selectedIndex]
            $updatedProfile = Get-DeviceDetails -IPAddress $device.IPAddress -Credential $Credential
            $Devices[$selectedIndex] = $updatedProfile
            $deviceListView.SelectedItems[0].Tag = $updatedProfile
            $deviceListView.SelectedItems[0].Selected = $true
        }
    })
    $timer.Start()
}

# Add refresh button
$refreshButton = New-Object System.Windows.Forms.Button
$refreshButton.Text = "Refresh"
$refreshButton.Location = New-Object System.Drawing.Point(10,10)
$refreshButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$refreshButton.Add_Click({
    if ($deviceListView.SelectedItems.Count -gt 0) {
        $device = $deviceListView.SelectedItems[0].Tag
        $updatedProfile = Get-DeviceDetails -IPAddress $device.IPAddress -Credential $Credential
        $deviceListView.SelectedItems[0].Tag = $updatedProfile
        $deviceListView.SelectedItems[0].Selected = $true
    }
})
$splitContainer.Panel1.Controls.Add($refreshButton)

$form.ShowDialog()
}

# Main execution
Write-Host "[*] Starting enhanced network scan..."

# Get credentials if not provided
if (-not $Username) {
$creds = Get-Credential -Message "Enter credentials for remote system access"
} else {
$securePass = ConvertTo-SecureString $Password -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($Username, $securePass)
}

$networkInfo = Get-NetworkRange
$activeDevices = Start-NetworkScan -NetworkInfo $networkInfo
$deviceProfiles = @()

foreach ($device in $activeDevices) {
Write-Host "[*] Profiling device: $($device.IPAddress)..."
$profile = Get-DeviceDetails -IPAddress $device.IPAddress -Credential $creds
$deviceProfiles += $profile

# Save profile to log file
$profile | ConvertTo-Json -Depth 10 | 
    Out-File -FilePath "$LogPath\$($device.IPAddress.Replace('.','_')).json"
}

Show-DeviceMonitor -Devices $deviceProfiles -Monitor:$Monitor -RefreshInterval $RefreshInterval