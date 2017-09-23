# Network Scanner with packet capture
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Import for packet capture
$code = @"
using System;
using System.Runtime.InteropServices;

public class PacketCapture {
    [DllImport("wpcap.dll")]
    public static extern IntPtr pcap_open_live(string dev, int snaplen, int promisc, int to_ms, StringBuilder errbuf);
    
    [DllImport("wpcap.dll")]
    public static extern int pcap_next_ex(IntPtr p, IntPtr pkt_header, ref IntPtr pkt_data);
    
    [DllImport("wpcap.dll")]
    public static extern void pcap_close(IntPtr p);
}
"@

Add-Type -TypeDefinition $code -Language CSharp

class ProtocolAnalyzer {
    static [hashtable]$KnownPorts = @{
        80 = "HTTP"
        443 = "HTTPS"
        53 = "DNS"
        21 = "FTP"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        110 = "POP3"
        143 = "IMAP"
        3389 = "RDP"
        445 = "SMB"
    }

    static [string]ParseTCPFlags([byte]$flags) {
        $flagStr = ""
        if ($flags -band 0x02) { $flagStr += "SYN " }
        if ($flags -band 0x10) { $flagStr += "ACK " }
        if ($flags -band 0x01) { $flagStr += "FIN " }
        if ($flags -band 0x04) { $flagStr += "RST " }
        return $flagStr.Trim()
    }

    static [string]DetectProtocol([int]$srcPort, [int]$dstPort) {
        foreach ($port in @($srcPort, $dstPort)) {
            if ([ProtocolAnalyzer]::KnownPorts.ContainsKey($port)) {
                return [ProtocolAnalyzer]::KnownPorts[$port]
            }
        }
        return "Other"
    }
}

class NetworkScanner {
    [System.Windows.Forms.Form]$MainForm
    [System.Windows.Forms.TabControl]$MainTabs
    [System.Windows.Forms.DataGridView]$DeviceGrid
    [System.Windows.Forms.DataGridView]$PacketGrid
    [System.Windows.Forms.RichTextBox]$Details
    [System.Windows.Forms.Button]$ScanButton
    [System.Windows.Forms.Button]$CaptureButton
    [bool]$IsScanning
    [bool]$IsCapturing
    [hashtable]$Devices
    [System.Collections.ArrayList]$Packets
    [IntPtr]$CaptureHandle

    NetworkScanner() {
        $this.Devices = @{}
        $this.Packets = New-Object System.Collections.ArrayList
        $this.InitializeUI()
    }

    [void]InitializeUI() {
        $this.MainForm = New-Object System.Windows.Forms.Form
        $this.MainForm.Text = "Network Scanner"
        $this.MainForm.Size = New-Object System.Drawing.Size(1000, 600)

        # Control panel
        $controlPanel = New-Object System.Windows.Forms.Panel
        $controlPanel.Dock = "Top"
        $controlPanel.Height = 40

        $this.ScanButton = New-Object System.Windows.Forms.Button
        $this.ScanButton.Text = "Scan Network"
        $this.ScanButton.Location = New-Object System.Drawing.Point(10, 10)
        $this.ScanButton.Add_Click({ $this.StartScan() })
        $controlPanel.Controls.Add($this.ScanButton)

        $this.CaptureButton = New-Object System.Windows.Forms.Button
        $this.CaptureButton.Text = "Start Capture"
        $this.CaptureButton.Location = New-Object System.Drawing.Point(120, 10)
        $this.CaptureButton.Add_Click({ $this.ToggleCapture() })
        $controlPanel.Controls.Add($this.CaptureButton)

        $this.MainForm.Controls.Add($controlPanel)

        # Tabs
        $this.MainTabs = New-Object System.Windows.Forms.TabControl
        $this.MainTabs.Dock = "Fill"

        # Devices tab
        $devicesTab = New-Object System.Windows.Forms.TabPage
        $devicesTab.Text = "Network Devices"

        $this.DeviceGrid = New-Object System.Windows.Forms.DataGridView
        $this.DeviceGrid.Dock = "Fill"
        $this.DeviceGrid.AllowUserToAddRows = $false
        $this.DeviceGrid.ReadOnly = $true
        $this.DeviceGrid.SelectionMode = "FullRowSelect"
        $this.ConfigureDeviceGrid()
        $devicesTab.Controls.Add($this.DeviceGrid)

        # Traffic tab
        $trafficTab = New-Object System.Windows.Forms.TabPage
        $trafficTab.Text = "Network Traffic"

        $trafficContainer = New-Object System.Windows.Forms.SplitContainer
        $trafficContainer.Dock = "Fill"
        $trafficContainer.Orientation = "Horizontal"

        $this.PacketGrid = New-Object System.Windows.Forms.DataGridView
        $this.PacketGrid.Dock = "Fill"
        $this.PacketGrid.AllowUserToAddRows = $false
        $this.PacketGrid.ReadOnly = $true
        $this.ConfigurePacketGrid()
        $trafficContainer.Panel1.Controls.Add($this.PacketGrid)

        $this.Details = New-Object System.Windows.Forms.RichTextBox
        $this.Details.Dock = "Fill"
        $this.Details.ReadOnly = $true
        $trafficContainer.Panel2.Controls.Add($this.Details)

        $trafficTab.Controls.Add($trafficContainer)

        $this.MainTabs.TabPages.Add($devicesTab)
        $this.MainTabs.TabPages.Add($trafficTab)
        $this.MainForm.Controls.Add($this.MainTabs)

        # Event handlers
        $this.DeviceGrid.Add_SelectionChanged({ $this.ShowDeviceDetails() })
        $this.PacketGrid.Add_SelectionChanged({ $this.ShowPacketDetails() })
    }

    [void]ConfigureDeviceGrid() {
        $columns = @(
            @{Name="IP"; Width=120},
            @{Name="Name"; Width=150},
            @{Name="MAC"; Width=120},
            @{Name="OS"; Width=150},
            @{Name="Open Ports"; Width=200}
        )

        foreach ($col in $columns) {
            $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
            $column.Name = $col.Name
            $column.HeaderText = $col.Name
            $column.Width = $col.Width
            $this.DeviceGrid.Columns.Add($column)
        }
    }

    [void]ConfigurePacketGrid() {
        $columns = @(
            @{Name="Time"; Width=100},
            @{Name="Source"; Width=150},
            @{Name="Destination"; Width=150},
            @{Name="Protocol"; Width=80},
            @{Name="Length"; Width=80},
            @{Name="Info"; Width=300}
        )

        foreach ($col in $columns) {
            $column = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
            $column.Name = $col.Name
            $column.HeaderText = $col.Name
            $column.Width = $col.Width
            $this.PacketGrid.Columns.Add($column)
        }
    }

    [void]StartScan() {
        $this.IsScanning = $true
        $this.DeviceGrid.Rows.Clear()
        $this.Devices.Clear()

        # Get local subnet
        $localIP = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -eq "Dhcp"}).IPAddress
        $subnet = $localIP -replace "\.\d+$", ".0/24"

        Start-ThreadJob -ScriptBlock {
            param($scanner, $subnet)
            
            1..254 | ForEach-Object {
                $ip = $subnet -replace "0/24", $_
                if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
                    $device = @{
                        IP = $ip
                        Name = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { "Unknown" }
                        MAC = (Get-NetNeighbor -IPAddress $ip).LinkLayerAddress
                        OS = "Detecting..."
                        OpenPorts = @()
                    }
                    
                    # Port scan
                    $ports = @(21,22,23,25,53,80,443,445,3389)
                    foreach ($port in $ports) {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        try {
                            if ($tcp.ConnectAsync($ip, $port).Wait(100)) {
                                $device.OpenPorts += $port
                            }
                        } catch {} finally {
                            $tcp.Close()
                        }
                    }

                    # OS detection
                    if ($device.OpenPorts -contains 445) {
                        try {
                            $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ip
                            $device.OS = $os.Caption
                        } catch {
                            $device.OS = "Unknown"
                        }
                    }

                    $scanner.AddDevice($device)
                }
            }
        } -ArgumentList $this, $subnet
    }

    [void]ToggleCapture() {
        if ($this.IsCapturing) {
            $this.StopCapture()
            $this.CaptureButton.Text = "Start Capture"
        } else {
            $this.StartCapture()
            $this.CaptureButton.Text = "Stop Capture"
        }
    }

    [void]StartCapture() {
        $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
        $device = "\Device\NPF_" + $adapter.InterfaceGuid

        $errbuf = New-Object System.Text.StringBuilder(256)
        $this.CaptureHandle = [PacketCapture]::pcap_open_live($device, 65536, 1, 1000, $errbuf)

        if ($this.CaptureHandle -ne [IntPtr]::Zero) {
            $this.IsCapturing = $true

            Start-ThreadJob -ScriptBlock {
                param($scanner)
                
                while ($scanner.IsCapturing) {
                    $header = [IntPtr]::Zero
                    $data = [IntPtr]::Zero
                    
                    $result = [PacketCapture]::pcap_next_ex(
                        $scanner.CaptureHandle, 
                        [ref]$header, 
                        [ref]$data
                    )
                    
                    if ($result -gt 0) {
                        $packet = $scanner.ParsePacket($data)
                        if ($packet) {
                            $scanner.AddPacket($packet)
                        }
                    }
                }
            } -ArgumentList $this
        }
    }

    [void]StopCapture() {
        $this.IsCapturing = $false
        if ($this.CaptureHandle -ne [IntPtr]::Zero) {
            [PacketCapture]::pcap_close($this.CaptureHandle)
            $this.CaptureHandle = [IntPtr]::Zero
        }
    }

    [PSCustomObject]ParsePacket($dataPtr) {
        try {
            $rawData = New-Object byte[] 65536
            [System.Runtime.InteropServices.Marshal]::Copy($dataPtr, $rawData, 0, 65536)

            $ethHeader = $rawData[0..13]
            $ipHeader = $rawData[14..33]
            $transportHeader = $rawData[34..53]

            $sourceIP = [System.Net.IPAddress]::new($ipHeader[12..15])
            $destIP = [System.Net.IPAddress]::new($ipHeader[16..19])
            $sourcePort = [BitConverter]::ToUInt16($transportHeader[0..1], 0)
            $destPort = [BitConverter]::ToUInt16($transportHeader[2..3], 0)

            return [PSCustomObject]@{
                Time = Get-Date
                Source = "$sourceIP`:$sourcePort"
                Destination = "$destIP`:$destPort"
                Protocol = [ProtocolAnalyzer]::DetectProtocol($sourcePort, $destPort)
                Length = $rawData.Length
                RawData = $rawData
            }
        }
        catch {
            Write-Warning "Error parsing packet: $_"
            return $null
        }
    }

    [void]AddDevice($device) {
        $this.MainForm.Invoke([Action]{
            $row = $this.DeviceGrid.Rows.Add()
            $row.Cells["IP"].Value = $device.IP
            $row.Cells["Name"].Value = $device.Name
            $row.Cells["MAC"].Value = $device.MAC
            $row.Cells["OS"].Value = $device.OS
            $row.Cells["Open Ports"].Value = ($device.OpenPorts -join ", ")
            
            $this.Devices[$device.IP] = $device
        })
    }

    [void]AddPacket($packet) {
        $this.Packets.Add($packet)
        $this.MainForm.Invoke([Action]{
            $row = $this.PacketGrid.Rows.Add()
            $row.Cells["Time"].Value = $packet.Time.ToString("HH:mm:ss.fff")
            $row.Cells["Source"].Value = $packet.Source
            $row.Cells["Destination"].Value = $packet.Destination
            $row.Cells["Protocol"].Value = $packet.Protocol
            $row.Cells["Length"].Value = $packet.Length
            $row.Cells["Info"].Value = $this.GetPacketInfo($packet)
        })
    }

    [string]GetPacketInfo($packet) {
        return "$($packet.Protocol) Connection"
    }

    [void]ShowDeviceDetails() {
        if ($this.DeviceGrid.SelectedRows.Count -gt 0) {
            $ip = $this.DeviceGrid.SelectedRows[0].Cells["IP"].Value
            $device = $this.Devices[$ip]
            
            $details = "Device Details`n"
            $details += "--------------`n"
            $details += "IP: $($device.IP)`n"
            $details += "Name: $($device.Name)`n"
            $details += "MAC: $($device.MAC)`n"
            $details += "Operating System: $($device.OS)`n"
            $details += "`nOpen Ports:`n"
            foreach ($port in $device.OpenPorts) {
                $service = [ProtocolAnalyzer]::KnownPorts[$port]
                $details += "  Port $port : $service`n"
            }
            
            $this.Details.Text = $details
        }
    }

    [void]Show() {
        $this.MainForm.ShowDialog()
    }

    [void]ShowPacketDetails() {
        if ($this.PacketGrid.SelectedRows.Count -gt 0) {
            $selectedIndex = $this.PacketGrid.SelectedRows[0].Index
            $packet = $this.Packets[$selectedIndex]
            
            $details = "Packet Details`n"
            $details += "--------------`n"
            $details += "Time: $($packet.Time)`n"
            $details += "Source: $($packet.Source)`n"
            $details += "Destination: $($packet.Destination)`n"
            $details += "Protocol: $($packet.Protocol)`n"
            $details += "Length: $($packet.Length) bytes`n"

            # Add raw data in hex format
            $details += "`nRaw Data (Hex):`n"
            $offset = 0
            $hexDump = ""
            $asciiDump = ""
            
            for ($i = 0; $i -lt [Math]::Min($packet.RawData.Length, 128); $i++) {
                if ($i % 16 -eq 0) {
                    if ($i -gt 0) {
                        $details += "$hexDump  $asciiDump`n"
                        $hexDump = ""
                        $asciiDump = ""
                    }
                    $hexDump = "{0:X4}: " -f $offset
                    $offset += 16
                }
                
                $hexDump += "{0:X2} " -f $packet.RawData[$i]
                if ([char]::IsControl([char]$packet.RawData[$i])) {
                    $asciiDump += "."
                } else {
                    $asciiDump += [char]$packet.RawData[$i]
                }
            }
            
            if ($hexDump) {
                $padding = "   " * (16 - ($packet.RawData.Length % 16))
                $details += "$hexDump$padding  $asciiDump"
            }
            
            $this.Details.Text = $details
        }
    }

    [void]SavePackets($filename) {
        $writer = [System.IO.File]::Create($filename)
        
        # PCAP global header
        $writer.Write([byte[]]@(
            0xD4, 0xC3, 0xB2, 0xA1,  # Magic number
            0x02, 0x00, 0x04, 0x00,  # Version
            0x00, 0x00, 0x00, 0x00,  # Timezone
            0x00, 0x00, 0x00, 0x00,  # Accuracy
            0xFF, 0xFF, 0x00, 0x00,  # Snap length
            0x01, 0x00, 0x00, 0x00   # Link type (Ethernet)
        ), 0, 24)
        
        foreach ($packet in $this.Packets) {
            $ts = [BitConverter]::GetBytes([uint32](($packet.Time - (Get-Date "1970-01-01")).TotalSeconds))
            $writer.Write($ts, 0, 4)
            
            $usec = [BitConverter]::GetBytes([uint32]($packet.Time.Millisecond * 1000))
            $writer.Write($usec, 0, 4)
            
            $len = [BitConverter]::GetBytes([uint32]$packet.RawData.Length)
            $writer.Write($len, 0, 4)
            $writer.Write($len, 0, 4)
            
            $writer.Write($packet.RawData, 0, $packet.RawData.Length)
        }
        
        $writer.Close()
    }
}

# Start the application
$scanner = [NetworkScanner]::new()
$scanner.Show()