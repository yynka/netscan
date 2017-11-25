<a id="top"></a>
```
     ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
     ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
     ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
     ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
     ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
     ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Cross-Platform Network Discovery & Device Profiling Tool**

[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#windows)
[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#macos)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#linux)

## Features

▸ **Network Discovery** - Automatically detect and profile devices on your local network  
▸ **Service Enumeration** - Discover running services and monitor their status  
▸ **Resource Detection** - Identify shared files and network resources  
▸ **CLI Interface** - Clean command-line interface with summary and fast scan modes  
▸ **Cross-Platform** - Native Python support for Windows, macOS, and Linux  
▸ **Enhanced Security** - MAC vendor lookup with local OUI database fallback  
▸ **Device Profiling** - Detailed JSON profiles saved for each discovered device  
▸ **Authentication Support** - SSH/WinRM authentication for enhanced device access  

---

## ◆ Windows <a id="windows"></a>[![Windows](https://img.shields.io/badge/Windows-0078D4?style=flat&logo=windows&logoColor=white)](#top)

### Prerequisites
▪ Windows 10/11 or Windows Server 2016+  
▪ Python 3.8+ ([Download Python](https://www.python.org/downloads/windows/))  
▪ Administrator privileges (for nmap functionality)  

### Installation
```powershell
# Clone repository
git clone https://github.com/yynka/netscan.git
cd netscan

# Or download directly
curl https://raw.githubusercontent.com/yynka/netscan/main/windows.py -o windows.py
curl https://raw.githubusercontent.com/yynka/netscan/main/requirements.txt -o requirements.txt

# Setup virtual environment
python -m venv ns
.\ns\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Usage
```powershell
# Basic network scan
python windows.py

# Authenticated scan with detailed summary
python windows.py --username YOUR_USERNAME --password YOUR_PASSWORD --summary

# Fast scan mode
python windows.py --fast
```

※ **Note:** Requires Administrator privileges for comprehensive network scanning

---

## ◆ macOS <a id="macos"></a>[![macOS](https://img.shields.io/badge/macOS-000000?style=flat&logo=apple&logoColor=white)](#top)

### Prerequisites
▪ macOS 10.14+ (Mojave or later)  
▪ Homebrew package manager  
▪ Administrator privileges (`sudo` access)  

### Installation
```bash
# Install system dependencies
brew install nmap python3

# Clone repository
git clone https://github.com/yynka/netscan.git
cd netscan

# Or download directly
curl https://raw.githubusercontent.com/yynka/netscan/main/macos.py -o macos.py
curl https://raw.githubusercontent.com/yynka/netscan/main/requirements.txt -o requirements.txt

# Setup virtual environment
python3 -m venv ns
source ns/bin/activate

# Install dependencies
pip3 install -r requirements.txt
```

### Usage
```bash
# Basic network scan
sudo python3 macos.py

# Authenticated scan with detailed summary
sudo python3 macos.py --username YOUR_USERNAME --password YOUR_PASSWORD --summary

# Fast scan mode
sudo python3 macos.py --fast
```

※ **Note:** Requires running commands with `sudo` for network interface access

---

## ◆ Linux <a id="linux"></a>[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](#top)

### Prerequisites
▪ Linux distribution with Python 3.8+ support  
▪ `sudo` privileges  
▪ Package manager (apt/yum/dnf)  

### Installation
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap curl

# Clone repository
git clone https://github.com/yynka/netscan.git
cd netscan

# Or download directly
curl https://raw.githubusercontent.com/yynka/netscan/main/linux.py -o linux.py
curl https://raw.githubusercontent.com/yynka/netscan/main/requirements.txt -o requirements.txt

# Setup virtual environment
python3 -m venv ns
source ns/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Usage
```bash
# Basic network scan
sudo python3 linux.py

# Authenticated scan with detailed summary
sudo python3 linux.py --username YOUR_USERNAME --password YOUR_PASSWORD --summary

# Fast scan mode
sudo python3 linux.py --fast
```

※ **Note:** Requires running commands with `sudo` for network scanning privileges

---

## ※ Command Reference

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

## Usage Examples

### Basic Network Discovery
```bash
# Simple network scan
# Windows
python windows.py

# macOS
sudo python3 macos.py

# Linux
sudo python3 linux.py
```

### Advanced Authenticated Scanning
```bash
# Comprehensive scan with authentication
# Windows
python windows.py --username admin --password secret --summary --debug

# macOS
sudo python3 macos.py --username admin --password secret --summary --debug

# Linux
sudo python3 linux.py --username admin --password secret --summary --debug
```

### Performance Optimized Scanning
```bash
# Fast scan for quick results
# Windows
python windows.py --fast

# macOS
sudo python3 macos.py --fast

# Linux
sudo python3 linux.py --fast
```

## Technical Implementation

### Windows
▪ **Technology:** WinRM (Windows Remote Management) + SSH  
▪ **Method:** ARP table parsing, ping sweep, nmap verification  
▪ **Authentication:** Native WinRM on port 5985, SSH fallback  

### macOS
▪ **Technology:** SSH + nmap integration  
▪ **Method:** ARP table parsing, ping sweep, service enumeration  
▪ **Authentication:** SSH connections for detailed device profiling  

### Linux
▪ **Technology:** SSH + iptables integration  
▪ **Method:** IP neighbor table, ping sweep, systemctl service discovery  
▪ **Authentication:** SSH connections with service enumeration  

## Security Benefits

▪ **Network Visibility** - Comprehensive device discovery and profiling  
▪ **Service Monitoring** - Real-time service status tracking  
▪ **Security Assessment** - Identify unauthorized devices and services  
▪ **Compliance Reporting** - Generate detailed network inventory reports  
▪ **Authentication Support** - Secure device access with credential validation  

## Output Examples

### Basic Scan Results
```
[*] Network Scanner Starting...
[*] Checking network connectivity...
[+] Using interface en0 (192.168.1.100)
[*] Starting network scan on 192.168.1.100/24

[+] Found active host: 192.168.1.1 (hostname: router.local)
[+] Found active host: 192.168.1.152 (hostname: macbook.local)
[+] Found active host: 192.168.1.215 (hostname: iphone.local)

[*] Profiling discovered devices...
[*] Profiling device: 192.168.1.1
[+] Platform detected: Unknown
[+] Accessibility: No
[+] Vendor: Cisco Systems, Inc.

[+] Scan complete! Found 3 devices.
[+] Detailed profiles saved to: /Users/user/netscan/logs
```

### Device Summary Output
```
================================================================================
DEVICE DISCOVERY SUMMARY
================================================================================

[1] Device: 192.168.1.1
    Hostname: router.local
    Computer Name: N/A
    Platform: Unknown
    OS Version: N/A
    MAC Address: 00:10:18:XX:XX:XX
    Vendor: Cisco Systems, Inc.
    Accessible: No
    Last User: N/A
    Services: 0 found
    Shared Resources: 0 found
    First Seen: 2024-01-15T10:30:00.000000
    Last Seen: 2024-01-15T10:35:00.000000

[2] Device: 192.168.1.152
    Hostname: macbook.local
    Computer Name: MacBook-Pro
    Platform: macOS
    OS Version: macOS 14.2.1
    MAC Address: 3C:06:30:XX:XX:XX
    Vendor: Apple, Inc.
    Accessible: Yes
    Last User: admin
    Services: 15 found
    Shared Resources: 2 found
    First Seen: 2024-01-15T10:30:00.000000
    Last Seen: 2024-01-15T10:35:00.000000
    Top Services:
      - ssh (Running)
      - AppleFileServer (Running)
      - mDNSResponder (Running)
    Shared Resources:
      - Public (/Users/Shared)
      - AirDrop (/Users/admin/AirDrop)
```

## Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| **netifaces** | Network interface access | ≥0.11.0 |
| **python-nmap** | Network scanning capabilities | ≥0.7.1 |
| **psutil** | System monitoring utilities | ≥5.9.0 |
| **paramiko** | SSH connections | ≥3.0.0 |
| **pywinrm** | Windows Remote Management | ≥0.4.3 |

---

## License

[MIT License](LICENSE) - Feel free to use and modify as needed.

**※ Security Note:** This tool requires administrative privileges on all platforms. Use responsibly and in compliance with your organization's security policies.