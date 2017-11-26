<a id="top"></a>
```
     ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
     ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
     ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
     ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
     ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
     ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Enhanced Network Security Scanner - Complete Documentation**

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)
[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)

## Overview

This enhanced network security scanner is a comprehensive tool designed for network administrators and security professionals. It provides deep network discovery, vulnerability assessment, device fingerprinting, and security reporting capabilities across multiple platforms.

The scanner consists of three platform-specific scripts that each provide **full cross-platform device detection** - meaning you can run the Linux script to detect Windows and macOS devices, or run the Windows script to detect Linux and macOS devices, etc.

## Features

▸ **Advanced Device Discovery** - Cross-platform detection with ARP scanning and multi-threaded ping sweeps  
▸ **Security Assessment** - Vulnerability scanning with SSL/TLS certificate analysis  
▸ **Device Fingerprinting** - OS detection with service version detection and device classification  
▸ **Multi-Protocol Support** - SSH, WinRM, and SNMP enumeration across all platforms  
▸ **Network Topology** - Relationship mapping between devices with subnet analysis  
▸ **Comprehensive Reporting** - Detailed security reports with historical tracking  

---

## Installation

### Prerequisites
```bash
# macOS
brew install nmap python3

# Linux (Ubuntu/Debian)
sudo apt-get install nmap python3 python3-pip

# Windows
# Download and install nmap from https://nmap.org/download.html
# Install Python 3 from https://python.org

# Ensure you have admin privileges for network scanning
```

### Install Dependencies
```bash
# Create virtual environment
python3 -m venv ns
source ns/bin/activate  # On Windows: ns\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### Manual Installation
```bash
pip install netifaces python-nmap psutil paramiko pywinrm>=0.4.3
```

---

## Platform-Specific Scripts

### Linux Script (`linux.py`)
Run on Linux systems to scan for all device types:
```bash
sudo python3 linux.py [options]
```

### macOS Script (`macos.py`)
Run on macOS systems to scan for all device types:
```bash
sudo python3 macos.py [options]
```

### Windows Script (`windows.py`)
Run on Windows systems to scan for all device types:
```bash
# Run as Administrator
python windows.py [options]
```

---

## Usage

### Basic Scan
```bash
# Linux
sudo python3 linux.py

# macOS
sudo python3 macos.py

# Windows (as Administrator)
python windows.py

# Quick scan mode (skips nmap verification)
sudo python3 linux.py --fast

# Summary mode (condensed output)
sudo python3 linux.py --summary
```

### Advanced Options
```bash
# Custom SSH credentials for Linux/macOS device profiling
sudo python3 linux.py --username admin --password secret

# Custom WinRM port for Windows device profiling
sudo python3 linux.py --winrm-port 5986

# Custom SSH port for Linux/macOS device profiling
sudo python3 linux.py --ssh-port 2222

# Combine all options
sudo python3 linux.py --username admin --password secret --winrm-port 5986 --ssh-port 2222 --fast --summary
```

---

## Cross-Platform Device Detection

Each script can detect and profile devices from all three platforms:

### Windows Device Detection
▪ **WinRM Protocol** (port 5985/5986) for remote Windows management  
▪ **PowerShell Commands** for system information gathering  
▪ **Service Enumeration** using Get-Service  
▪ **Share Information** using Get-SmbShare  
▪ **System Information** using Get-ComputerInfo  

### macOS Device Detection
▪ **SSH Protocol** (port 22) for remote access  
▪ **Platform Detection** using `uname -s` (Darwin)  
▪ **Service Enumeration** using `launchctl list`  
▪ **System Information** using standard Unix commands  
▪ **Process Information** using `ps aux`  

### Linux Device Detection
▪ **SSH Protocol** (port 22) for remote access  
▪ **Platform Detection** using `uname -s` (Linux)  
▪ **Service Enumeration** using `systemctl list-units`  
▪ **System Information** using standard Unix commands  
▪ **Process Information** using `ps aux`  

---

## Sample Output

### Device Discovery
```
[*] Phase 1: Device Discovery
[*] Performing ARP scan on 192.168.1.0/24
[*] Performing ping sweep on 192.168.1.0/24
[+] Found 12 devices on 192.168.1.0/24

[*] Phase 2: Device Profiling
[*] Profiling device: 192.168.1.100
[+] Testing SSH access on 192.168.1.100:22
[+] Testing WinRM access on 192.168.1.100:5985
[+] SSH connection successful - detected Linux platform
[+] Profile completed for 192.168.1.100
    Device Type: Linux Server
    Platform: Linux
    Hostname: ubuntu-server
    Username: admin
    Open Ports: 5
    Services: 12
    Processes: 87
    Architecture: x86_64
```

### Cross-Platform Detection
```
[*] Device: 192.168.1.50
    Platform: Windows
    Method: WinRM
    Services: 45 Windows services detected
    Shares: 3 SMB shares found
    
[*] Device: 192.168.1.75
    Platform: macOS
    Method: SSH
    Services: 127 launchd services detected
    Processes: 234 processes running
    
[*] Device: 192.168.1.100
    Platform: Linux
    Method: SSH
    Services: 23 systemd services detected
    Processes: 87 processes running
```

### Security Report
```
================================================================================
ENHANCED NETWORK SECURITY REPORT
================================================================================
Generated: 2025-01-15 10:30:45
Total Devices: 12

SUMMARY STATISTICS
----------------------------------------
Device Types:
  Router: 1
  Switch: 1
  Apple Device: 3
  Windows Workstation: 2
  Linux Server: 1
  Printer: 1
  Unknown: 3

Platform Distribution:
  Windows: 4 devices
  macOS: 3 devices
  Linux: 2 devices
  Unknown: 3 devices

Protocol Support:
  SSH-enabled: 5 devices
  WinRM-enabled: 4 devices
  SNMP-enabled: 3 devices

Security Overview:
  Total Vulnerabilities: 8
  High Risk Devices: 2
  Average Security Score: 78.3/100

SECURITY RECOMMENDATIONS
----------------------------------------
1. 2 devices have security scores below 70. Review immediately.
2. 8 vulnerabilities detected. Apply patches and configuration changes.
3. Most common vulnerabilities:
   - SSH_OLD_VERSION: 3 devices affected
   - SNMP_DEFAULT_COMMUNITY: 2 devices affected
   - TELNET_OPEN: 1 device affected
```

---

## Data Collection

The enhanced scanner collects comprehensive information about each device:

### Basic Information
▪ IP Address  
▪ Hostname/Computer Name  
▪ MAC Address  
▪ Vendor Information  
▪ Device Type Classification  
▪ Operating System/Platform (Windows/macOS/Linux)  
▪ Architecture  

### Network Information
▪ Network Interfaces  
▪ Open Ports (including SSH:22, WinRM:5985)  
▪ Running Services  
▪ Service Versions  
▪ Service Banners  

### Platform-Specific Information

#### Windows Devices (via WinRM)
▪ Windows Services (Get-Service)  
▪ SMB Shares (Get-SmbShare)  
▪ Computer Information (Get-ComputerInfo)  
▪ System Architecture  
▪ Windows Version  

#### macOS Devices (via SSH)
▪ LaunchD Services (launchctl list)  
▪ Running Processes (ps aux)  
▪ System Information (uname -a)  
▪ Darwin Version  
▪ Hardware Platform  

#### Linux Devices (via SSH)
▪ SystemD Services (systemctl list-units)  
▪ Running Processes (ps aux)  
▪ System Information (uname -a)  
▪ Distribution Information  
▪ Kernel Version  

### Security Information
▪ Vulnerability Assessment  
▪ Security Score (0-100)  
▪ SSL/TLS Certificate Status  
▪ Default Credential Checks  
▪ Service Configuration Issues  

### SNMP Information (if available)
▪ System Description  
▪ System Name  
▪ System Location  
▪ System Contact  
▪ System Uptime  
▪ Interface Details  

### Historical Data
▪ First Seen Timestamp  
▪ Last Seen Timestamp  
▪ Change Tracking  
▪ Vulnerability Timeline  

---

## Output Files

The scanner generates several output files:

### Individual Device Profiles
▪ `192_168_1_1.json` - Detailed device information  
▪ `192_168_1_2.json` - JSON format for easy parsing  

### Comprehensive Reports
▪ `network_security_report_YYYYMMDD_HHMMSS.txt` - Human-readable report  
▪ `network_topology.json` - Network topology data  
▪ `netscan_enhanced.log` - Detailed scan logs  

### Database Storage
▪ `network_history.db` - SQLite database for historical tracking  
▪ Tracks device changes over time  
▪ Vulnerability timeline  
▪ Traffic statistics  

---

## Security Considerations

### Required Permissions
▪ **Root/Administrator** privileges required for:
  - Raw socket access (ARP scanning)
  - ICMP ping packets
  - Advanced port scanning
  - OS fingerprinting

### Network Impact
▪ Scans are designed to be **non-intrusive**  
▪ Configurable thread limits to prevent network overload  
▪ Timeout settings to avoid hanging connections  
▪ Respectful of network resources  
▪ **Fast mode** available to skip time-consuming nmap verification  

### Authentication Requirements
▪ **SSH Credentials** needed for Linux/macOS device profiling  
▪ **WinRM Credentials** needed for Windows device profiling  
▪ **SNMP Community Strings** for network device information  
▪ Credentials are used read-only and not stored permanently  

### Privacy and Compliance
▪ All scans are **passive** and **non-exploitative**  
▪ No data is modified on target systems  
▪ No passwords or sensitive data are collected  
▪ Compliant with network monitoring best practices  

---

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Linux/macOS: Run with sudo
sudo python3 linux.py

# Windows: Run as Administrator
python windows.py
```

**No Devices Found**
```bash
# Check network interface
ip route show default

# Verify network connectivity
ping 8.8.8.8
```

**WinRM Connection Issues**
```bash
# Test WinRM manually
winrm enumerate winrm/config/listener

# Check WinRM port
telnet 192.168.1.100 5985
```

**SSH Connection Issues**
```bash
# Test SSH manually
ssh admin@192.168.1.100

# Check SSH port
telnet 192.168.1.100 22
```

**Missing Dependencies**
```bash
# Install system dependencies
sudo apt-get install python3-dev libpcap-dev

# Reinstall Python packages
pip install --force-reinstall netifaces python-nmap psutil paramiko pywinrm
```

---

## Command Reference

### Universal Options
| Option | Description |
|--------|-------------|
| `--summary` | Display detailed device summary after scan |
| `--fast` | Fast scan mode (fewer checks, quicker results) |
| `--debug` | Enable debug logging for troubleshooting |
| `--log-path PATH` | Custom log directory path |
| `--username USER` | Authentication username for device access |
| `--password PASS` | Authentication password for device access |
| `--ssh-port N` | SSH port number (default: 22) |
| `--winrm-port N` | WinRM port number (default: 5985) |

### Platform Implementation
| Platform | Command Format | Authentication Methods |
|----------|----------------|----------------------|
| **Windows** | `python windows.py [options]` | SSH, WinRM |
| **macOS** | `python3 macos.py [options]` | SSH |
| **Linux** | `python3 linux.py [options]` | SSH |

---

## Integration with orca.us.org

This scanner is designed as the **first module** of the orca.us.org security suite:

▪ **Network Discovery** - This module provides comprehensive device inventory  
▪ **Vulnerability Assessment** - Feeds into advanced security analysis  
▪ **Asset Management** - Provides baseline for asset tracking  
▪ **Security Monitoring** - Historical data for change detection  
▪ **Incident Response** - Network context for security incidents  

---

## Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| **netifaces** | Network interface access | ≥0.11.0 |
| **python-nmap** | Network scanning capabilities | ≥0.7.1 |
| **psutil** | System monitoring utilities | ≥5.9.0 |
| **paramiko** | SSH connections | ≥3.0.0 |
| **pywinrm** | Windows Remote Management | ≥0.4.3 |

---

## Future Enhancements

▪ **Traffic Analysis** - Passive network monitoring  
▪ **Behavioral Analysis** - Device behavior patterns  
▪ **Threat Intelligence** - Integration with threat feeds  
▪ **Automated Remediation** - Suggested fixes for vulnerabilities  
▪ **Web Dashboard** - Real-time network visualization  
▪ **API Integration** - RESTful API for external tools  
▪ **Enhanced Authentication** - Certificate-based authentication for SSH/WinRM  
▪ **Privilege Escalation** - Automated privilege detection and escalation  

---

## License

This tool is part of the orca.us.org security suite and is intended for authorized network security assessment only.

## Support

For issues and questions:
▪ Check the log files in the output directory  
▪ Review the troubleshooting section  
▪ Ensure all dependencies are properly installed  
▪ Verify network permissions and connectivity  
▪ Test SSH/WinRM connectivity manually before running scans  

**※ Security Note:** This tool requires administrative privileges on all platforms. Use responsibly and in compliance with your organization's security policies. 