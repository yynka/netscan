# NetScan Advanced Network Monitor
# Auto-elevation and dependency check
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    Start-Process PowerShell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    exit
}

# Required assemblies
$assemblies = @(
    "System.Windows.Forms",
    "System.Drawing",
    "System.Management",
    "System.Net.Http",
    "System.Security"
)

foreach ($assembly in $assemblies) {
    Add-Type -AssemblyName $assembly
}

# Custom packet capture implementation
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WinDivert {
    [DllImport("WinDivert.dll")]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        byte layer,
        short priority,
        ulong flags
    );

    [DllImport("WinDivert.dll")]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        ref uint readLen
    );

    [DllImport("WinDivert.dll")]
    public static extern bool WinDivertSend(
        IntPtr handle,
        byte[] packet,
        uint packetLen,
        ref uint writeLen
    );
}
"@

# Enhanced device profile class
class NetworkDevice {
    [string]$IPAddress
    [string]$Hostname
    [string]$MACAddress
    [string]$Vendor
    [string]$ComputerName
    [string]$OSVersion
    [PSCustomObject]$SecurityProfile
    [System.Collections.ArrayList]$Services
    [System.Collections.ArrayList]$Connections
    [System.Collections.ArrayList]$TrafficHistory
    [hashtable]$Bandwidth
    [bool]$IsSuspicious
    [datetime]$FirstSeen
    [datetime]$LastSeen

    NetworkDevice([string]$ip) {
        $this.IPAddress = $ip
        $this.FirstSeen = Get-Date
        $this.LastSeen = Get-Date
        $this.Services = New-Object System.Collections.ArrayList
        $this.Connections = New-Object System.Collections.ArrayList
        $this.TrafficHistory = New-Object System.Collections.ArrayList
        $this.Bandwidth = @{
            Upload = 0
            Download = 0
            LastUpdate = Get-Date
        }
        $this.SecurityProfile = [PSCustomObject]@{
            OpenPorts = @()
            Certificates = @()
            Vulnerabilities = @()
            DetectedThreats = @()
        }
    }
}

# Main application form
class NetScanForm : System.Windows.Forms.Form {
    [System.Windows.Forms.TabControl]$MainTabs
    [System.Windows.Forms.SplitContainer]$MainSplitter
    [System.Windows.Forms.TreeView]$DeviceTree
    [System.Windows.Forms.DataGridView]$TrafficGrid
    [System.Windows.Forms.RichTextBox]$PacketDetails
    [System.Windows.Forms.Timer]$UpdateTimer
    [hashtable]$DeviceProfiles
    [IntPtr]$CaptureHandle
    [System.Collections.ArrayList]$PacketBuffer
    [bool]$IsCapturing

    NetScanForm() {
        $this.Text = "NetScan Advanced Monitor"
        $this.Size = New-Object System.Drawing.Size(1200, 800)
        $this.StartPosition = "CenterScreen"
        $this.DeviceProfiles = @{}
        $this.PacketBuffer = New-Object System.Collections.ArrayList
        $this.InitializeComponents()
        $this.InitializeMenus()
        $this.SetupEventHandlers()
    }

    [void]InitializeComponents() {
        # Main layout
        $this.MainTabs = New-Object System.Windows.Forms.TabControl
        $this.MainTabs.Dock = "Fill"

        # Overview tab
        $overviewTab = New-Object System.Windows.Forms.TabPage
        $overviewTab.Text = "Overview"
        $this.MainSplitter = New-Object System.Windows.Forms.SplitContainer
        $this.MainSplitter.Dock = "Fill"
        $this.MainSplitter.Orientation = "Vertical"

        # Device tree
        $this.DeviceTree = New-Object System.Windows.Forms.TreeView
        $this.DeviceTree.Dock = "Fill"
        $this.MainSplitter.Panel1.Controls.Add($this.DeviceTree)

        # Traffic grid
        $this.TrafficGrid = New-Object System.Windows.Forms.DataGridView
        $this.TrafficGrid.Dock = "Fill"
        $this.TrafficGrid.AllowUserToAddRows = $false
        $this.TrafficGrid.MultiSelect = $false
        $this.TrafficGrid.SelectionMode = "FullRowSelect"
        $this.ConfigureTrafficGrid()
        $this.MainSplitter.Panel2.Controls.Add($this.TrafficGrid)

        $overviewTab.Controls.Add($this.MainSplitter)
        $this.MainTabs.TabPages.Add($overviewTab)

        # Additional tabs
        $this.AddSecurityTab()
        $this.AddAnalysisTab()
        $this.AddReportingTab()

        $this.Controls.Add($this.MainTabs)
    }

    [void]ConfigureTrafficGrid() {
        $columns = @(
            @{Name="Time"; Width=100},
            @{Name="Source"; Width=150},
            @{Name="Destination"; Width=150},
            @{Name="Protocol"; Width=100},
            @{Name="Length"; Width=80},
            @{Name="Info"; Width=300}
        )

        foreach ($col in $columns) {
            $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
            $column.Name = $col.Name
            $column.HeaderText = $col.Name
            $column.Width = $col.Width
            $this.TrafficGrid.Columns.Add($column)
        }
    }

    [void]AddSecurityTab() {
        $securityTab = New-Object System.Windows.Forms.TabPage
        $securityTab.Text = "Security"
        
        $threatList = New-Object System.Windows.Forms.ListView
        $threatList.View = "Details"
        $threatList.Dock = "Fill"
        $threatList.Columns.Add("Time", 100)
        $threatList.Columns.Add("Device", 150)
        $threatList.Columns.Add("Type", 100)
        $threatList.Columns.Add("Severity", 80)
        $threatList.Columns.Add("Description", 400)
        
        $securityTab.Controls.Add($threatList)
        $this.MainTabs.TabPages.Add($securityTab)
    }

    [void]AddAnalysisTab() {
        $analysisTab = New-Object System.Windows.Forms.TabPage
        $analysisTab.Text = "Analysis"
        
        $analysisSplitter = New-Object System.Windows.Forms.SplitContainer
        $analysisSplitter.Dock = "Fill"
        $analysisSplitter.Orientation = "Horizontal"
        
        # Protocol distribution chart
        $protocolChart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
        $protocolChart.Dock = "Fill"
        $analysisSplitter.Panel1.Controls.Add($protocolChart)
        
        # Connection matrix
        $connectionGrid = New-Object System.Windows.Forms.DataGridView
        $connectionGrid.Dock = "Fill"
        $connectionGrid.AllowUserToAddRows = $false
        $analysisSplitter.Panel2.Controls.Add($connectionGrid)
        
        $analysisTab.Controls.Add($analysisSplitter)
        $this.MainTabs.TabPages.Add($analysisTab)
    }

    [void]AddReportingTab() {
        $reportingTab = New-Object System.Windows.Forms.TabPage
        $reportingTab.Text = "Reports"
        
        $reportPanel = New-Object System.Windows.Forms.TableLayoutPanel
        $reportPanel.Dock = "Fill"
        $reportPanel.ColumnCount = 2
        $reportPanel.RowCount = 3
        
        # Report options
        $reportTypes = @("Network Overview", "Security Audit", "Traffic Analysis")
        foreach ($type in $reportTypes) {
            $button = New-Object System.Windows.Forms.Button
            $button.Text = "Generate $type Report"
            $reportPanel.Controls.Add($button)
        }
        
        $reportingTab.Controls.Add($reportPanel)
        $this.MainTabs.TabPages.Add($reportingTab)
    }

    [void]InitializeMenus() {
        $menuStrip = New-Object System.Windows.Forms.MenuStrip
        $menuStrip.Dock = "Top"

        # File menu
        $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("File")
        $fileMenu.DropDownItems.Add("New Capture", $null, { $this.StartCapture() })
        $fileMenu.DropDownItems.Add("Stop Capture", $null, { $this.StopCapture() })
        $fileMenu.DropDownItems.Add("Save...", $null, { $this.SaveCapture() })
        $fileMenu.DropDownItems.Add("Export...", $null, { $this.ExportData() })
        $menuStrip.Items.Add($fileMenu)

        # View menu
        $viewMenu = New-Object System.Windows.Forms.ToolStripMenuItem("View")
        $viewMenu.DropDownItems.Add("Refresh", $null, { $this.RefreshView() })
        $viewMenu.DropDownItems.Add("Clear", $null, { $this.ClearDisplay() })
        $menuStrip.Items.Add($viewMenu)

        # Tools menu
        $toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Tools")
        $toolsMenu.DropDownItems.Add("Network Map", $null, { $this.ShowNetworkMap() })
        $toolsMenu.DropDownItems.Add("Port Scanner", $null, { $this.ScanPorts() })
        $toolsMenu.DropDownItems.Add("Certificate Checker", $null, { $this.CheckCertificates() })
        $menuStrip.Items.Add($toolsMenu)

        $this.MainMenuStrip = $menuStrip
        $this.Controls.Add($menuStrip)
    }

    [void]SetupEventHandlers() {
        $this.UpdateTimer = New-Object System.Windows.Forms.Timer
        $this.UpdateTimer.Interval = 1000
        $this.UpdateTimer.Add_Tick({ $this.UpdateDevices() })
        
        $this.DeviceTree.Add_AfterSelect({
            param($sender, $e)
            $this.ShowDeviceDetails($e.Node.Tag)
        })
        
        $this.TrafficGrid.Add_CellClick({
            param($sender, $e)
            if ($e.RowIndex -ge 0) {
                $this.ShowPacketDetails($this.PacketBuffer[$e.RowIndex])
            }
        })
    }

    [void]StartCapture() {
        if (-not $this.IsCapturing) {
            $filter = "true"  # Capture all packets
            $this.CaptureHandle = [WinDivert]::WinDivertOpen($filter, 0, 0, 0)
            
            if ($this.CaptureHandle -ne [IntPtr]::Zero) {
                $this.IsCapturing = $true
                Start-ThreadJob -ScriptBlock {
                    param($handle, $form)
                    
                    $packetBuffer = New-Object byte[] 65535
                    $readLen = 0
                    
                    while ($form.IsCapturing) {
                        if ([WinDivert]::WinDivertRecv($handle, $packetBuffer, [uint32]65535, [ref]$readLen)) {
                            $form.ProcessPacket($packetBuffer[0..$readLen])
                        }
                    }
                } -ArgumentList $this.CaptureHandle, $this
                
                $this.UpdateTimer.Start()
            }
        }
    }

    [void]StopCapture() {
        $this.IsCapturing = $false
        $this.UpdateTimer.Stop()
        # Close capture handle
    }

    [void]ProcessPacket([byte[]]$packetData) {
        $packet = $this.ParsePacket($packetData)
        if ($packet) {
            $this.PacketBuffer.Add($packet)
            $this.UpdateTrafficGrid($packet)
            $this.AnalyzeTraffic($packet)
            [void]UpdateTrafficGrid([PSCustomObject]$packet) {
                $this.TrafficGrid.Invoke([Action]{
                    $row = $this.TrafficGrid.Rows.Add()
                    $row.Cells["Time"].Value = $packet.Timestamp
                    $row.Cells["Source"].Value = $packet.Source
                    $row.Cells["Destination"].Value = $packet.Destination
                    $row.Cells["Protocol"].Value = $packet.Protocol
                    $row.Cells["Length"].Value = $packet.Length
                    $row.Cells["Info"].Value = $packet.Info
                })
            }
        
            [PSCustomObject]ParsePacket([byte[]]$data) {
                try {
                    $ipHeader = $data[0..19]
                    $protocol = $ipHeader[9]
                    $srcIP = [System.Net.IPAddress]::new($ipHeader[12..15])
                    $dstIP = [System.Net.IPAddress]::new($ipHeader[16..19])
                    
                    $srcPort = [BitConverter]::ToUInt16($data[20..21], 0)
                    $dstPort = [BitConverter]::ToUInt16($data[22..23], 0)
                    
                    return [PSCustomObject]@{
                        Timestamp = Get-Date
                        Source = "$srcIP`:$srcPort"
                        Destination = "$dstIP`:$dstPort"
                        Protocol = switch($protocol) {
                            6 {"TCP"}
                            17 {"UDP"}
                            default {"Other"}
                        }
                        Length = $data.Length
                        Info = $this.GetPacketInfo($data)
                        RawData = $data
                    }
                }
                catch {
                    Write-Warning "Error parsing packet: $_"
                    return $null
                }
            }
        
            [string]GetPacketInfo([byte[]]$data) {
                try {
                    $protocol = $data[9]
                    $payload = $data[20..$data.Length]
                    
                    switch($protocol) {
                        6 { # TCP
                            $flags = $payload[13]
                            $info = "TCP Flags: "
                            if ($flags -band 0x02) { $info += "SYN " }
                            if ($flags -band 0x10) { $info += "ACK " }
                            if ($flags -band 0x01) { $info += "FIN " }
                            if ($flags -band 0x04) { $info += "RST " }
                            return $info.Trim()
                        }
                        17 { # UDP
                            $length = [BitConverter]::ToUInt16($payload[4..5], 0)
                            return "UDP Length: $length"
                        }
                        default {
                            return "Protocol: $protocol"
                        }
                    }
                }
                catch {
                    return "Error parsing packet info"
                }
            }
        
            [void]AnalyzeTraffic([PSCustomObject]$packet) {
                # Update device statistics
                $srcDevice = $this.GetOrCreateDevice($packet.Source.Split(':')[0])
                $dstDevice = $this.GetOrCreateDevice($packet.Destination.Split(':')[0])
                
                $srcDevice.LastSeen = Get-Date
                $srcDevice.TrafficHistory.Add($packet)
                
                # Update bandwidth
                $srcDevice.Bandwidth.Upload += $packet.Length
                $dstDevice.Bandwidth.Download += $packet.Length
                
                # Security checks
                $this.DetectAnomalies($packet)
                $this.CheckPortScan($packet)
                $this.ValidateSSLCertificate($packet)
            }
        
            [void]DetectAnomalies([PSCustomObject]$packet) {
                # Port scan detection
                if ($this.IsPortScan($packet)) {
                    $this.RaiseSecurityAlert("Port Scan", "High", $packet.Source)
                }
                
                # Suspicious protocols
                if ($this.IsSuspiciousProtocol($packet)) {
                    $this.RaiseSecurityAlert("Suspicious Protocol", "Medium", $packet.Protocol)
                }
                
                # Traffic spikes
                if ($this.IsTrafficSpike($packet)) {
                    $this.RaiseSecurityAlert("Traffic Spike", "Low", "Unusual bandwidth usage")
                }
            }
        
            [bool]IsPortScan([PSCustomObject]$packet) {
                $source = $packet.Source.Split(':')[0]
                $timeWindow = (Get-Date).AddMinutes(-1)
                
                $recentConnections = $this.PacketBuffer | 
                    Where-Object { 
                        $_.Source.StartsWith($source) -and 
                        $_.Timestamp -gt $timeWindow 
                    }
                
                $uniquePorts = $recentConnections | 
                    ForEach-Object { $_.Destination.Split(':')[1] } | 
                    Select-Object -Unique
                
                return $uniquePorts.Count -gt 10
            }
        
            [bool]IsSuspiciousProtocol([PSCustomObject]$packet) {
                $suspiciousPorts = @(21, 23, 445, 1433, 3389)
                $port = [int]($packet.Destination.Split(':')[1])
                return $suspiciousPorts -contains $port
            }
        
            [bool]IsTrafficSpike([PSCustomObject]$packet) {
                $source = $packet.Source.Split(':')[0]
                $device = $this.DeviceProfiles[$source]
                
                if ($device) {
                    $timeWindow = (Get-Date).AddMinutes(-1)
                    $recentTraffic = $device.TrafficHistory | 
                        Where-Object { $_.Timestamp -gt $timeWindow } |
                        Measure-Object -Property Length -Sum
                    
                    return $recentTraffic.Sum -gt 1MB
                }
                return $false
            }
        
            [void]ValidateSSLCertificate([PSCustomObject]$packet) {
                if ($packet.Destination.EndsWith(':443')) {
                    try {
                        $ip = $packet.Destination.Split(':')[0]
                        $cert = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                        if (-not $cert) {
                            $this.RaiseSecurityAlert("Invalid SSL Certificate", "High", $ip)
                        }
                    }
                    catch {
                        Write-Warning "Error validating SSL certificate: $_"
                    }
                }
            }
        
            [void]RaiseSecurityAlert([string]$type, [string]$severity, [string]$details) {
                $alert = [PSCustomObject]@{
                    Timestamp = Get-Date
                    Type = $type
                    Severity = $severity
                    Details = $details
                }
                
                # Add to security log
                $securityTab = $this.MainTabs.TabPages | Where-Object { $_.Text -eq "Security" }
                if ($securityTab) {
                    $threatList = $securityTab.Controls[0]
                    $item = New-Object System.Windows.Forms.ListViewItem(
                        @(
                            $alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                            $alert.Type,
                            $alert.Severity,
                            $alert.Details
                        )
                    )
                    $threatList.Items.Add($item)
                }
            }
        
            [NetworkDevice]GetOrCreateDevice([string]$ip) {
                if (-not $this.DeviceProfiles.ContainsKey($ip)) {
                    $this.DeviceProfiles[$ip] = [NetworkDevice]::new($ip)
                    $this.UpdateDeviceTree()
                }
                return $this.DeviceProfiles[$ip]
            }
        
            [void]UpdateDeviceTree() {
                $this.DeviceTree.Invoke([Action]{
                    $this.DeviceTree.Nodes.Clear()
                    foreach ($device in $this.DeviceProfiles.Values) {
                        $node = New-Object System.Windows.Forms.TreeNode(
                            "$($device.ComputerName) ($($device.IPAddress))"
                        )
                        $node.Tag = $device
                        $this.DeviceTree.Nodes.Add($node)
                    }
                })
            }
        
            [void]ShowDeviceDetails([NetworkDevice]$device) {
                if ($device) {
                    $details = New-Object System.Windows.Forms.Form
                    $details.Text = "Device Details - $($device.IPAddress)"
                    $details.Size = New-Object System.Drawing.Size(600, 400)
                    
                    $tabs = New-Object System.Windows.Forms.TabControl
                    $tabs.Dock = "Fill"
                    
                    # Overview tab
                    $overviewTab = New-Object System.Windows.Forms.TabPage
                    $overviewTab.Text = "Overview"
                    $overview = New-Object System.Windows.Forms.PropertyGrid
                    $overview.SelectedObject = $device
                    $overview.Dock = "Fill"
                    $overviewTab.Controls.Add($overview)
                    
                    # Connections tab
                    $connectionsTab = New-Object System.Windows.Forms.TabPage
                    $connectionsTab.Text = "Connections"
                    $connections = New-Object System.Windows.Forms.ListView
                    $connections.Dock = "Fill"
                    $connections.View = "Details"
                    $connections.Columns.AddRange(@(
                        "Local Port",
                        "Remote Address",
                        "State",
                        "Process"
                    ))
                    foreach ($conn in $device.Connections) {
                        $item = New-Object System.Windows.Forms.ListViewItem(
                            @(
                                $conn.LocalPort,
                                $conn.RemoteAddress,
                                $conn.State,
                                $conn.Process
                            )
                        )
                        $connections.Items.Add($item)
                    }
                    $connectionsTab.Controls.Add($connections)
                    
                    # Traffic tab
                    $trafficTab = New-Object System.Windows.Forms.TabPage
                    $trafficTab.Text = "Traffic"
                    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
                    $chart.Dock = "Fill"
                    $area = $chart.ChartAreas.Add("Default")
                    $series = $chart.Series.Add("Traffic")
                    $series.ChartType = "Line"
                    
                    $trafficData = $device.TrafficHistory | 
                        Group-Object { $_.Timestamp.ToString("HH:mm") } |
                        ForEach-Object {
                            @{
                                Time = $_.Name
                                Bytes = ($_.Group | Measure-Object Length -Sum).Sum
                            }
                        }
                    
                    foreach ($point in $trafficData) {
                        $series.Points.AddXY($point.Time, $point.Bytes)
                    }
                    
                    $trafficTab.Controls.Add($chart)
                    
                    $tabs.TabPages.AddRange(@($overviewTab, $connectionsTab, $trafficTab))
                    $details.Controls.Add($tabs)
                    $details.ShowDialog()
                }
            }
        
            [void]ShowNetworkMap() {
                $map = New-Object System.Windows.Forms.Form
                $map.Text = "Network Topology Map"
                $map.Size = New-Object System.Drawing.Size(800, 600)
                
                $canvas = New-Object System.Windows.Forms.PictureBox
                $canvas.Dock = "Fill"
                $canvas.BackColor = [System.Drawing.Color]::White
                
                # Draw network map
                $bitmap = New-Object System.Drawing.Bitmap(800, 600)
                $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
                
                # Layout devices in a circle
                $centerX = 400
                $centerY = 300
                $radius = 200
                $devices = $this.DeviceProfiles.Values
                $angleStep = 360 / $devices.Count
                
                $devicePositions = @{}
                $i = 0
                foreach ($device in $devices) {
                    $angle = $i * $angleStep * [Math]::PI / 180
                    $x = $centerX + $radius * [Math]::Cos($angle)
                    $y = $centerY + $radius * [Math]::Sin($angle)
                    $devicePositions[$device.IPAddress] = @{
                        X = $x
                        Y = $y
                    }
                    $i++
                }
                
                # Draw connections
                $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::Gray, 1)
                foreach ($device in $devices) {
                    $sourcePos = $devicePositions[$device.IPAddress]
                    foreach ($conn in $device.Connections) {
                        $targetPos = $devicePositions[$conn.RemoteAddress]
                        if ($targetPos) {
                            $graphics.DrawLine($pen, 
                                $sourcePos.X, $sourcePos.Y,
                                $targetPos.X, $targetPos.Y)
                        }
                    }
                }
                
                # Draw devices
                $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::Blue)
                foreach ($device in $devices) {
                    $pos = $devicePositions[$device.IPAddress]
                    $graphics.FillEllipse($brush, 
                        $pos.X - 5, $pos.Y - 5, 10, 10)
                    $graphics.DrawString(
                        "$($device.ComputerName)`n$($device.IPAddress)",
                        [System.Drawing.Font]::new("Arial", 8),
                        $brush,
                        $pos.X + 10,
                        $pos.Y + 10
                    )
                }
                
                $canvas.Image = $bitmap
                $map.Controls.Add($canvas)
                $map.ShowDialog()
            }
        
            [void]SaveCapture() {
                $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
                $saveDialog.Filter = "PCAP Files (*.pcap)|*.pcap|All Files (*.*)|*.*"
                
                if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    # Write PCAP file format
                    $writer = [System.IO.File]::Create($saveDialog.FileName)
                    
                    # PCAP Global Header
                    $writer.Write([byte[]]@(
                        0xD4, 0xC3, 0xB2, 0xA1, # Magic number
                        0x02, 0x00, 0x04, 0x00, # Version
                        0x00, 0x00, 0x00, 0x00, # Timezone
                        0x00, 0x00, 0x00, 0x00, # Accuracy
                        0xFF, 0xFF, 0x00, 0x00, # Snap length
                        0x01, 0x00, 0x00, 0x00  # Link type (Ethernet)
                    ), 0, 24)
                    
                    foreach ($packet in $this.PacketBuffer) {
                        # Packet Header
                        $timestamp = [BitConverter]::GetBytes([uint32](
                            ($packet.Timestamp - (Get-Date "1970-01-01")).TotalSeconds))
                        $writer.Write($timestamp, 0, 4)
                        
                        $microseconds = [BitConverter]::GetBytes([uint32](
                            ($packet.Timestamp.Millisecond * 1000)))
                        $writer.Write($microseconds, 0, 4)
                        
                        $length = [BitConverter]::GetBytes([uint32]$packet.RawData.Length)
                        $writer.Write($length, 0, 4)
                        $writer.Write($length, 0, 4)