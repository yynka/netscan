#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# setup logging first
script_dir = Path(__file__).parent
log_dir = script_dir / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(log_dir / 'network_scanner_debug.log'))
    ]
)

# import the rest

import json
import subprocess
import threading
import time
from datetime import datetime
import netifaces
import nmap
import psutil
import socket
import paramiko
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import traceback
import re
import urllib.request
import urllib.error

# tell user what's happening
print("\n=== Linux Network Scanner ===")
print("[*] Network Scanner Starting...")
print("[*] This script will scan your local network for devices")
print(f"[*] Results will be saved in: {log_dir}")
print("[*] Checking network connectivity...")

@dataclass
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str

@dataclass
class ShareInfo:
    name: str
    path: str
    description: str

@dataclass
class HistoryEntry:
    timestamp: str
    type: str
    data: Dict

@dataclass
class DeviceProfile:
    ip_address: str
    hostname: str = None
    mac_address: str = None
    vendor: str = None
    computer_name: str = None
    os_version: str = None
    last_user: str = None
    first_seen: str = None
    last_seen: str = None
    platform: str = None
    is_accessible: bool = False
    services: List[ServiceInfo] = None
    shared_resources: List[ShareInfo] = None
    history: List[HistoryEntry] = None

    def __post_init__(self):
        self.services = self.services or []
        self.shared_resources = self.shared_resources or []
        self.history = self.history or []
        if not self.first_seen:
            self.first_seen = datetime.now().isoformat()
        if not self.last_seen:
            self.last_seen = datetime.now().isoformat()

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)

class NetworkScanner:
    def __init__(self, log_path=str(Path(__file__).parent / "logs"), ssh_port=22, winrm_port=5985):
        self.log_path = log_path
        self.ssh_port = ssh_port
        self.winrm_port = winrm_port
        Path(log_path).mkdir(parents=True, exist_ok=True)
        self.nm = nmap.PortScanner()
        print(f"[*] Scanner initialized, logs will be saved to: {log_path}")
        logging.info(f"Initialized NetworkScanner with log_path={log_path}, ssh_port={ssh_port}, winrm_port={winrm_port}")

    def get_network_range(self):
        print("[*] Detecting network interfaces...")
        try:
            interfaces = netifaces.interfaces()
            logging.info(f"Available interfaces: {interfaces}")
            
            # try common Linux interfaces first
            primary_interface = None
            for iface in ['eth0', 'wlan0', 'eno1', 'wlp2s0', 'enp0s3']:
                if iface in interfaces and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    primary_interface = iface
                    break
            
            if not primary_interface:
                # fall back to first interface with IPv4 address
                for iface in interfaces:
                    if netifaces.AF_INET in netifaces.ifaddresses(iface):
                        primary_interface = iface
                        break

            if not primary_interface:
                raise Exception("No suitable network interface found")

            interface_info = netifaces.ifaddresses(primary_interface)[netifaces.AF_INET][0]
            ip = interface_info['addr']
            netmask = interface_info['netmask']
            
            print(f"[+] Using interface {primary_interface} ({ip})")
            logging.info(f"Selected interface {primary_interface}: IP={ip}, Netmask={netmask}")
            
            # convert to network base address
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            network = [ip_parts[i] & mask_parts[i] for i in range(4)]
            
            result = {
                'Base': '.'.join(map(str, network)),
                'Prefix': sum(bin(x).count('1') for x in mask_parts),
                'Interface': ip
            }
            logging.info(f"Network range result: {result}")
            return result
        except Exception as e:
            logging.error(f"Failed to determine network range: {str(e)}\n{traceback.format_exc()}")
            raise

    def get_mac_vendor(self, mac: str) -> str:
        """get mac vendor with fallback methods"""
        try:
            # clean up MAC address
            mac = mac.replace(':', '').replace('-', '').upper()
            if len(mac) < 6:
                return "Unknown"
            
            # try multiple lookup methods
            vendors = []
            
            # first try macvendors.com API
            try:
                import urllib.request
                import urllib.error
                url = f'https://api.macvendors.com/{mac[:6]}'
                with urllib.request.urlopen(url, timeout=3) as response:
                    vendor = response.read().decode().strip()
                    if vendor and not vendor.startswith('{"errors"'):
                        vendors.append(vendor)
                        logging.info(f"Vendor found via macvendors.com: {vendor}")
            except Exception as e:
                logging.debug(f"macvendors.com lookup failed: {e}")
            
            # fallback to local OUI database
            try:
                oui_prefix = mac[:6]
                vendor = self.get_vendor_from_oui(oui_prefix)
                if vendor:
                    vendors.append(vendor)
                    logging.info(f"Vendor found via OUI database: {vendor}")
            except Exception as e:
                logging.debug(f"OUI lookup failed: {e}")
            
            # return first successful vendor or fallback
            if vendors:
                return vendors[0]
            else:
                return "Unknown"
                
        except Exception as e:
            logging.warning(f"Failed to get MAC vendor for {mac}: {str(e)}")
            return "Unknown"

    def get_vendor_from_oui(self, oui_prefix: str) -> str:
        """lookup vendor from common OUI prefixes"""
        # common OUI prefixes (first 6 hex digits)
        oui_database = {
            '001560': 'Apple, Inc.',
            '001CF0': 'Apple, Inc.',
            '001B63': 'Apple, Inc.',
            '0017F2': 'Apple, Inc.',
            '000D93': 'Apple, Inc.',
            '000393': 'Apple, Inc.',
            '000A95': 'Apple, Inc.',
            '000A27': 'Apple, Inc.',
            '000502': 'Apple, Inc.',
            '3C0630': 'Apple, Inc.',
            '3C0754': 'Apple, Inc.',
            '3C15C2': 'Apple, Inc.',
            '3C2EFF': 'Apple, Inc.',
            '3C4142': 'Apple, Inc.',
            '3C7A8A': 'Apple, Inc.',
            '3CA82A': 'Apple, Inc.',
            '3CBDD8': 'Apple, Inc.',
            '3CE072': 'Apple, Inc.',
            '3CEC88': 'Apple, Inc.',
            '0014A5': 'Netgear Inc.',
            '0014A4': 'Netgear Inc.',
            '0050F2': 'Microsoft Corporation',
            '0003FF': 'Microsoft Corporation',
            '00A0C9': 'Intel Corporation',
            '00E018': 'Asustek Computer Inc.',
            '001124': 'Giga-Byte Technology Co., Ltd.',
            '000000': 'Xerox Corporation',
            '000001': 'Xerox Corporation',
            '000002': 'Xerox Corporation',
            '000003': 'Xerox Corporation',
            '001000': 'Cisco Systems, Inc.',
            '001001': 'Cisco Systems, Inc.',
            '001002': 'Cisco Systems, Inc.',
            '001003': 'Cisco Systems, Inc.',
            '001004': 'Cisco Systems, Inc.',
            '001005': 'Cisco Systems, Inc.',
            '001006': 'Cisco Systems, Inc.',
            '001007': 'Cisco Systems, Inc.',
            '001008': 'Cisco Systems, Inc.',
            '001009': 'Cisco Systems, Inc.',
            '00100A': 'Cisco Systems, Inc.',
            '00100B': 'Cisco Systems, Inc.',
            '00100C': 'Cisco Systems, Inc.',
            '00100D': 'Cisco Systems, Inc.',
            '00100E': 'Cisco Systems, Inc.',
            '00100F': 'Cisco Systems, Inc.',
            '001010': 'Cisco Systems, Inc.',
            '001011': 'Cisco Systems, Inc.',
            '001012': 'Cisco Systems, Inc.',
            '001013': 'Cisco Systems, Inc.',
            '001014': 'Cisco Systems, Inc.',
            '001015': 'Cisco Systems, Inc.',
            '001016': 'Cisco Systems, Inc.',
            '001017': 'Cisco Systems, Inc.',
            '001018': 'Cisco Systems, Inc.',
            '001019': 'Cisco Systems, Inc.',
            '00101A': 'Cisco Systems, Inc.',
            '00101B': 'Cisco Systems, Inc.',
            '00101C': 'Cisco Systems, Inc.',
            '00101D': 'Cisco Systems, Inc.',
            '00101E': 'Cisco Systems, Inc.',
            '00101F': 'Cisco Systems, Inc.',
        }
        
        return oui_database.get(oui_prefix.upper())
    
    def test_host_accessibility(self, ip):
        try:
            logging.info(f"Testing host accessibility for {ip}")
            ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
            subprocess.check_call(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info(f"Host {ip} is responding to ping")
            return True
        except subprocess.CalledProcessError:
            logging.warning(f"Host {ip} is not responding to ping")
            return False
        except Exception as e:
            logging.error(f"Error testing host accessibility: {str(e)}")
            return False

    def test_ssh_access(self, ip, port=22):
        try:
            logging.info(f"Testing SSH access to {ip}:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode()
                    logging.info(f"SSH banner: {banner}")
                    if 'SSH' in banner:
                        sock.close()
                        return True
                except:
                    pass
            sock.close()
            logging.info(f"SSH test result for {ip}:{port} = {result == 0}")
            return result == 0
        except Exception as e:
            logging.error(f"SSH test failed for {ip}:{port}: {str(e)}")
            return False

    def test_winrm_access(self, ip, port=5985):
        try:
            logging.info(f"Testing WinRM access to {ip}:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            logging.info(f"WinRM test result for {ip}:{port} = {result == 0}")
            return result == 0
        except Exception as e:
            logging.error(f"WinRM test failed for {ip}:{port}: {str(e)}")
            return False

    def get_linux_info(self, ip, username=None, password=None):
        """gather information about a Linux system via SSH"""
        logging.info(f"Attempting to gather Linux info for {ip}")
        if not username or not password:
            logging.warning("No credentials provided for Linux info gathering")
            return None

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logging.info(f"Attempting SSH connection to {ip} with username {username}")
            ssh.connect(ip, port=self.ssh_port, username=username, password=password, timeout=5)
            logging.info("SSH connection successful")

            # system info with error handling
            hostname = "Unknown"
            os_info = "Unknown"
            who = "Unknown"
            services = []
            shares = []
            interfaces = ""

            # gather hostname, OS info
            try:
                stdin, stdout, stderr = ssh.exec_command('hostname')
                hostname = stdout.readline().strip()
                
                # try multiple commands for OS info
                os_commands = [
                    'cat /etc/os-release',
                    'lsb_release -a',
                    'hostnamectl'
                ]
                for cmd in os_commands:
                    try:
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        os_info = stdout.read().decode()
                        if os_info.strip():
                            break
                    except Exception as cmd_error:
                        logging.debug(f"Command {cmd} failed: {cmd_error}")
                        continue
                
                stdin, stdout, stderr = ssh.exec_command('who')
                who_output = stdout.readline().strip()
                who = who_output if who_output else "Unknown"
                
                logging.info(f"System info gathered: hostname={hostname}, os_info={os_info}, who={who}")
            except Exception as e:
                logging.error(f"Error getting system info: {str(e)}")

            # services
            try:
                # try systemctl first
                stdin, stdout, stderr = ssh.exec_command('systemctl list-units --type=service --all')
                service_output = stdout.read().decode()
                
                if service_output:
                    for line in service_output.split('\n'):
                        if '.service' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                service_name = parts[0].replace('.service', '')
                                status = 'Running' if 'running' in line.lower() else 'Stopped'
                                service_info = ServiceInfo(
                                    name=service_name,
                                    display_name=service_name,
                                    status=status,
                                    start_type='Enabled' if 'enabled' in line.lower() else 'Disabled'
                                )
                                services.append(service_info)
                else:
                    # fallback to service command
                    stdin, stdout, stderr = ssh.exec_command('service --status-all')
                    for line in stdout:
                        if '[ + ]' in line or '[ - ]' in line:
                            service_name = line.split(']')[1].strip()
                            status = 'Running' if '[ + ]' in line else 'Stopped'
                            service_info = ServiceInfo(
                                name=service_name,
                                display_name=service_name,
                                status=status,
                                start_type='Unknown'
                            )
                            services.append(service_info)
                            
                logging.info(f"Found {len(services)} services")
            except Exception as e:
                logging.error(f"Error getting services: {str(e)}")

            # shares
            try:
                # check NFS shares
                stdin, stdout, stderr = ssh.exec_command('showmount -e localhost 2>/dev/null || true')
                for line in stdout:
                    if '*' in line:  # only show publicly accessible shares
                        path = line.split()[0]
                        share_info = ShareInfo(
                            name=os.path.basename(path),
                            path=path,
                            description='NFS Share'
                        )
                        shares.append(share_info)
                
                # check Samba shares
                stdin, stdout, stderr = ssh.exec_command('smbclient -L localhost -N 2>/dev/null || true')
                for line in stdout:
                    if 'Disk' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            share_info = ShareInfo(
                                name=parts[0],
                                path=f"//{hostname}/{parts[0]}",
                                description='Samba Share'
                            )
                            shares.append(share_info)
                            
                logging.info(f"Found {len(shares)} shares")
            except Exception as e:
                logging.error(f"Error getting shares: {str(e)}")

            # network interfaces
            try:
                stdin, stdout, stderr = ssh.exec_command('ip addr')
                interfaces = stdout.read().decode()
                logging.info("Network interface information gathered")
            except Exception as e:
                logging.error(f"Error getting network interfaces: {str(e)}")

            # clean up SSH connection
            try:
                ssh.close()
                logging.info("SSH connection closed successfully")
            except Exception as e:
                logging.error(f"Error closing SSH connection: {str(e)}")

            return {
                'hostname': hostname,
                'os_info': os_info,
                'last_user': who.split()[0] if who != "Unknown" else None,
                'services': services,
                'shares': shares,
                'interfaces': interfaces,
                'platform': 'Linux',
                'is_accessible': True
            }

        except Exception as e:
            logging.error(f"SSH connection or commands failed: {str(e)}")
            return None

    def get_windows_info(self, ip, username=None, password=None):
        """gather information about a Windows system via WinRM"""
        logging.info(f"Attempting to gather Windows info for {ip}")
        
        try:
            # Try to use WinRM if available
            try:
                import winrm
                
                if username and password:
                    session = winrm.Session(f'http://{ip}:5985/wsman', auth=(username, password))
                    
                    # Get basic system info
                    hostname = "Unknown"
                    os_info = "Unknown"
                    last_user = "Unknown"
                    services = []
                    shares = []
                    
                    try:
                        # Get hostname
                        result = session.run_cmd('hostname')
                        if result.status_code == 0:
                            hostname = result.std_out.decode().strip()
                        
                        # Get OS info
                        result = session.run_ps('Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion')
                        if result.status_code == 0:
                            os_info = result.std_out.decode().strip()
                        
                        # Get last logged user
                        result = session.run_ps('Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName')
                        if result.status_code == 0:
                            last_user = result.std_out.decode().strip()
                        
                        # Get services
                        result = session.run_ps('Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, Status, StartType -First 20')
                        if result.status_code == 0:
                            service_lines = result.std_out.decode().strip().split('\n')
                            for line in service_lines[3:]:  # Skip header lines
                                if line.strip():
                                    parts = line.split(None, 3)
                                    if len(parts) >= 3:
                                        service_info = ServiceInfo(
                                            name=parts[0],
                                            display_name=parts[1] if len(parts) > 1 else parts[0],
                                            status=parts[2] if len(parts) > 2 else 'Unknown',
                                            start_type=parts[3] if len(parts) > 3 else 'Unknown'
                                        )
                                        services.append(service_info)
                        
                        # Get shares
                        result = session.run_ps('Get-SmbShare | Select-Object Name, Path, Description')
                        if result.status_code == 0:
                            share_lines = result.std_out.decode().strip().split('\n')
                            for line in share_lines[3:]:  # Skip header lines
                                if line.strip():
                                    parts = line.split(None, 2)
                                    if len(parts) >= 2:
                                        share_info = ShareInfo(
                                            name=parts[0],
                                            path=parts[1] if len(parts) > 1 else 'Unknown',
                                            description=parts[2] if len(parts) > 2 else 'Windows Share'
                                        )
                                        shares.append(share_info)
                    
                    except Exception as cmd_error:
                        logging.error(f"WinRM command execution error: {cmd_error}")
                    
                    return {
                        'hostname': hostname,
                        'os_info': os_info,
                        'last_user': last_user.split('\\')[-1] if '\\' in last_user else last_user,
                        'services': services,
                        'shares': shares,
                        'interfaces': 'Windows Network Interfaces',
                        'platform': 'Windows',
                        'is_accessible': True
                    }
                
            except ImportError:
                logging.warning("pywinrm not available, using placeholder Windows info")
            except Exception as winrm_error:
                logging.error(f"WinRM connection failed: {winrm_error}")
            
            # Fallback to basic info if WinRM fails
            services = [ServiceInfo(
                name="Windows Services",
                display_name="Windows Services",
                status="Unknown",
                start_type="Unknown"
            )]
            
            shares = [ShareInfo(
                name="Windows Shares",
                path="C:\\",
                description="Windows Share"
            )]
            
            return {
                'hostname': ip,
                'os_info': 'Windows',
                'last_user': 'Unknown',
                'services': services,
                'shares': shares,
                'interfaces': 'Windows Network Interfaces',
                'platform': 'Windows',
                'is_accessible': True
            }
            
        except Exception as e:
            logging.error(f"Windows info error for {ip}: {str(e)}")
            return None

    def get_macos_info(self, ip, username=None, password=None):
        """gather information about a macOS system via SSH"""
        logging.info(f"Attempting to gather macOS info for {ip}")
        try:
            if not username or not password:
                logging.warning("No credentials provided for macOS info gathering")
                return None

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logging.info(f"Attempting SSH connection to {ip} with username {username}")
            ssh.connect(ip, port=self.ssh_port, username=username, password=password, timeout=10)
            logging.info("SSH connection successful")

            # get system info
            try:
                hostname = "Unknown"
                sw_vers = "Unknown"
                who = "Unknown"
                
                stdin, stdout, stderr = ssh.exec_command('hostname')
                hostname = stdout.readline().strip()
                
                stdin, stdout, stderr = ssh.exec_command('sw_vers')
                sw_vers = stdout.read().decode().strip()
                
                stdin, stdout, stderr = ssh.exec_command('who')
                who = stdout.readline().strip()
                
                logging.info(f"System info gathered: hostname={hostname}, sw_vers={sw_vers}, who={who}")
            except Exception as e:
                logging.error(f"Error getting system info: {str(e)}")

            # get services
            services = []
            try:
                stdin, stdout, stderr = ssh.exec_command('launchctl list | head -20')
                for line in stdout:
                    line = line.strip()
                    if line and not line.startswith('PID'):
                        parts = line.split()
                        if len(parts) >= 3:
                            pid = parts[0]
                            status = parts[1]
                            name = parts[2]
                            service_info = ServiceInfo(
                                name=name,
                                display_name=name,
                                status='Running' if pid != "-" else 'Stopped',
                                start_type='Enabled'
                            )
                            services.append(service_info)
                logging.info(f"Found {len(services)} services")
            except Exception as e:
                logging.error(f"Error getting services: {str(e)}")

            # get shares
            shares = []
            try:
                stdin, stdout, stderr = ssh.exec_command('sharing -l')
                for line in stdout:
                    line = line.strip()
                    if line.startswith('Name:'):
                        name = line.split(':', 1)[1].strip()
                        share_info = ShareInfo(
                            name=name,
                            path='/Volumes',
                            description='macOS Share'
                        )
                        shares.append(share_info)
                logging.info(f"Found {len(shares)} shares")
            except Exception as e:
                logging.error(f"Error getting shares: {str(e)}")

            # get network interfaces
            interfaces = ""
            try:
                stdin, stdout, stderr = ssh.exec_command('ifconfig -a')
                interfaces = stdout.read().decode()
                logging.info("Network interface information gathered")
            except Exception as e:
                logging.error(f"Error getting network interfaces: {str(e)}")

            ssh.close()
            logging.info("Successfully gathered all macOS info")

            return {
                'hostname': hostname,
                'os_info': sw_vers,
                'last_user': who.split()[0] if who and who != "Unknown" else None,
                'services': services,
                'shares': shares,
                'interfaces': interfaces,
                'platform': 'macOS',
                'is_accessible': True
            }
        except Exception as e:
            logging.error(f"macOS info error for {ip}: {str(e)}")
        return None

    def get_device_details(self, ip, username=None, password=None):
        """get detailed information about a network device"""
        logging.info(f"\n{'='*50}\nStarting device profiling for {ip}\n{'='*50}")
        profile = DeviceProfile(ip)
        
        try:
            # basic info
            logging.info(f"Getting basic info for {ip}")
            try:
                profile.hostname = socket.getfqdn(ip)
                logging.info(f"Hostname resolved: {profile.hostname}")
            except Exception as e:
                logging.error(f"Hostname resolution failed: {str(e)}")
                profile.hostname = ip

            # test basic accessibility
            is_accessible = self.test_host_accessibility(ip)
            if not is_accessible:
                logging.warning(f"Host {ip} is not responding to basic connectivity tests")

            # MAC address and vendor discovery
            try:
                logging.info(f"Getting MAC address for {ip}")
                mac = None

                # try ip neighbor first (Linux)
                try:
                    ip_neigh = subprocess.check_output(['ip', 'neighbor', 'show', ip]).decode()
                    logging.debug(f"ip neighbor output: {ip_neigh}")
                    if ip_neigh.strip():
                        parts = ip_neigh.split()
                        if len(parts) >= 5:
                            mac = parts[4]
                except Exception as e:
                    logging.debug(f"ip neighbor command failed: {e}")

                # fallback to arp
                if not mac:
                    try:
                        arp_output = subprocess.check_output(['arp', '-n', ip]).decode()
                        logging.debug(f"ARP output: {arp_output}")
                        if arp_output.strip():
                            lines = arp_output.split('\n')
                            for line in lines[1:]:  # skip header
                                if ip in line:
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        mac = parts[2]
                                        break
                    except Exception as e:
                        logging.debug(f"arp command failed: {e}")

                if mac and ':' in mac:  # basic MAC address validation
                    profile.mac_address = mac
                    logging.info(f"MAC address found: {mac}")
                    profile.vendor = self.get_mac_vendor(mac)
                    logging.info(f"Vendor found: {profile.vendor}")
            except Exception as e:
                logging.error(f"MAC address lookup failed: {str(e)}")

            # OS detection and port scanning
            try:
                logging.info(f"Running nmap OS detection for {ip}")
                self.nm.scan(ip, arguments='-sS -sV -O -A -T4 --version-intensity 5')
                logging.debug(f"Nmap scan result: {json.dumps(self.nm[ip], indent=2)}")
                
                if ip in self.nm and 'osmatch' in self.nm[ip]:
                    profile.os_version = self.nm[ip]['osmatch'][0]['name']
                    logging.info(f"OS detected: {profile.os_version}")
                
                # look for Linux/Unix signatures
                if ip in self.nm and 'tcp' in self.nm[ip]:
                    for port, port_info in self.nm[ip]['tcp'].items():
                        if 'product' in port_info:
                            if any(x in port_info['product'] for x in ['Linux', 'Unix', 'SSH']):
                                profile.platform = 'Linux'
                                logging.info(f"Linux detected through service fingerprint on port {port}")
                                break
            except Exception as e:
                logging.error(f"Nmap OS detection failed: {str(e)}")

            # platform detection and access testing
            try:
                logging.info(f"Starting platform detection for {ip}")
                
                # test different access methods
                winrm_accessible = self.test_winrm_access(ip, self.winrm_port)
                ssh_accessible = self.test_ssh_access(ip, self.ssh_port)
                
                if winrm_accessible:
                    logging.info(f"WinRM accessible on {ip}")
                    profile.platform = 'Windows'
                    
                    # get detailed Windows info
                    windows_info = self.get_windows_info(ip, username, password)
                    if windows_info:
                        profile.is_accessible = True
                        profile.computer_name = windows_info['hostname']
                        profile.os_version = windows_info['os_info']
                        profile.last_user = windows_info['last_user']
                        profile.services = windows_info['services']
                        profile.shared_resources = windows_info['shares']
                        
                        profile.history.append(HistoryEntry(
                            timestamp=datetime.now().isoformat(),
                            type='NetworkAdapter',
                            data={
                                'Description': "Network Interfaces",
                                'Interfaces': windows_info['interfaces']
                            }
                        ))
                        
                elif ssh_accessible:
                    logging.info(f"SSH accessible on {ip}")
                    
                    # try to determine specific platform via SSH
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        if username and password:
                            ssh.connect(ip, port=self.ssh_port, username=username, password=password, timeout=5)

                            # quick platform check
                            stdin, stdout, stderr = ssh.exec_command('uname -s')
                            uname = stdout.read().decode().strip()
                            
                            if uname == 'Linux':
                                profile.platform = 'Linux'
                                logging.info("Platform confirmed as Linux via SSH")
                                
                                # get detailed Linux info
                                linux_info = self.get_linux_info(ip, username, password)
                                if linux_info:
                                    profile.is_accessible = True
                                    profile.computer_name = linux_info['hostname']
                                    profile.os_version = linux_info['os_info']
                                    profile.last_user = linux_info['last_user']
                                    profile.services = linux_info['services']
                                    profile.shared_resources = linux_info['shares']
                                    
                                    profile.history.append(HistoryEntry(
                                        timestamp=datetime.now().isoformat(),
                                        type='NetworkAdapter',
                                        data={
                                            'Description': "Network Interfaces",
                                            'Interfaces': linux_info['interfaces'].split('\n')[:10]
                                        }
                                    ))
                                    
                            elif uname == 'Darwin':
                                profile.platform = 'macOS'
                                logging.info("Platform confirmed as macOS via SSH")
                                
                                # get detailed macOS info
                                macos_info = self.get_macos_info(ip, username, password)
                                if macos_info:
                                    profile.is_accessible = True
                                    profile.computer_name = macos_info['hostname']
                                    profile.os_version = macos_info['os_info']
                                    profile.last_user = macos_info['last_user']
                                    profile.services = macos_info['services']
                                    profile.shared_resources = macos_info['shares']
                                    
                                    profile.history.append(HistoryEntry(
                                        timestamp=datetime.now().isoformat(),
                                        type='NetworkAdapter',
                                        data={
                                            'Description': "Network Interfaces",
                                            'Interfaces': macos_info['interfaces'].split('\n')[:10]
                                        }
                                    ))
                                
                            ssh.close()
                        else:
                            logging.info("SSH accessible but no credentials provided")
                            
                    except Exception as ssh_e:
                        logging.debug(f"SSH detailed detection failed: {ssh_e}")
                        
                else:
                    logging.info("Device not accessible via WinRM or SSH")
                    profile.platform = 'Unknown'
                    profile.is_accessible = False
                    
            except Exception as e:
                logging.error(f"Platform detection failed: {str(e)}")

            # add service discovery history
            try:
                if ip in self.nm and 'tcp' in self.nm[ip]:
                    profile.history.append(HistoryEntry(
                        timestamp=datetime.now().isoformat(),
                        type='ServiceDiscovery',
                        data={'ports': self.nm[ip]['tcp']}
                    ))
                    logging.info("Added service discovery history")
            except Exception as e:
                logging.error(f"Failed to add service history: {str(e)}")
            
        except Exception as e:
            logging.error(f"Major error in device details: {str(e)}\n{traceback.format_exc()}")
        
        logging.info(f"Completed device profiling for {ip}")
        return profile

    def save_profile(self, profile):
        try:
            filename = os.path.join(self.log_path, f"{profile.ip_address.replace('.', '_')}.json")
            logging.info(f"Saving profile to {filename}")
            with open(filename, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)
            logging.info("Profile saved successfully")
        except Exception as e:
            logging.error(f"Failed to save profile: {str(e)}")

    def display_device_summary(self, profiles):
        """display a summary of all discovered devices"""
        print("\n" + "="*80)
        print("DEVICE DISCOVERY SUMMARY")
        print("="*80)
        
        if not profiles:
            print("No devices discovered.")
            return
        
        for i, profile in enumerate(profiles, 1):
            print(f"\n[{i}] Device: {profile.ip_address}")
            print(f"    Hostname: {profile.hostname or 'N/A'}")
            print(f"    Computer Name: {profile.computer_name or 'N/A'}")
            print(f"    Platform: {profile.platform or 'Unknown'}")
            print(f"    OS Version: {profile.os_version or 'N/A'}")
            print(f"    MAC Address: {profile.mac_address or 'N/A'}")
            print(f"    Vendor: {profile.vendor or 'N/A'}")
            print(f"    Accessible: {'Yes' if profile.is_accessible else 'No'}")
            print(f"    Last User: {profile.last_user or 'N/A'}")
            print(f"    Services: {len(profile.services)} found")
            print(f"    Shared Resources: {len(profile.shared_resources)} found")
            print(f"    First Seen: {profile.first_seen}")
            print(f"    Last Seen: {profile.last_seen}")
            
            # show top services if any
            if profile.services:
                print(f"    Top Services:")
                for service in profile.services[:3]:  # show first 3 services
                    print(f"      - {service.name} ({service.status})")
                if len(profile.services) > 3:
                    print(f"      ... and {len(profile.services) - 3} more")
            
            # show shared resources if any
            if profile.shared_resources:
                print(f"    Shared Resources:")
                for share in profile.shared_resources[:2]:  # show first 2 shares
                    print(f"      - {share.name} ({share.path})")
                if len(profile.shared_resources) > 2:
                    print(f"      ... and {len(profile.shared_resources) - 2} more")

def start_network_scan(network_info, fast_mode=False):
    logging.info(f"Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    print(f"\n[*] Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    print("[*] This may take a few moments...\n")
    
    active_devices = []

    try:
        # get the base network
        base_ip = network_info['Base']
        ip_parts = base_ip.split('.')
        base_prefix = '.'.join(ip_parts[:-1]) + '.'
        
        # first use ip neighbor to get initial list of devices
        logging.info("Running ip neighbor to find devices")
        ip_neigh_devices = set()
        try:
            ip_neigh_output = subprocess.check_output(['ip', 'neighbor', 'show']).decode()
            logging.info(f"ip neighbor output: {ip_neigh_output}")
            
            for line in ip_neigh_output.split('\n'):
                if line.strip():
                    try:
                        ip = line.split()[0]
                        if ip.startswith(base_prefix):
                            ip_neigh_devices.add(ip)
                            logging.info(f"Found device in ip neighbor: {ip}")
                    except Exception:
                        continue
        except Exception as e:
            logging.warning(f"ip neighbor command failed: {e}, using fallback methods")

        # fallback to arp cache
        try:
            arp_output = subprocess.check_output(['arp', '-n']).decode()
            logging.info(f"ARP output: {arp_output}")
            for line in arp_output.split('\n')[1:]:  # skip header
                if line.strip():
                    try:
                        parts = line.split()
                        ip = parts[0]
                        if ip.startswith(base_prefix):
                            ip_neigh_devices.add(ip)
                            logging.info(f"Found device in ARP cache: {ip}")
                    except Exception:
                        continue
        except Exception as e:
            logging.warning(f"arp command failed: {e}")

        # also try ping sweep (limited range for speed)
        logging.info("Starting ping sweep")
        print("[*] Performing ping sweep...")
        
        # use threading for faster ping sweep
        def ping_host(ip):
            try:
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
                result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return ip if result.returncode == 0 else None
            except Exception:
                return None

        # ping sweep with threading
        max_workers = 10 if fast_mode else 20
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{base_prefix}{i}"
                futures.append(executor.submit(ping_host, ip))
            
            for i, future in enumerate(futures):
                if (i + 1) % 50 == 0:
                    print(f"[*] Scanning... ({i + 1}/254)")
                
                result = future.result()
                if result:
                    try:
                        hostname = socket.getfqdn(result)
                    except:
                        hostname = "N/A"
                    
                    logging.info(f"Found active host: {result} (hostname: {hostname})")
                    print(f"[+] Found active host: {result} (hostname: {hostname})")
                    active_devices.append({
                        'IPAddress': result,
                        'Hostname': hostname
                    })

        # add ip neighbor devices that weren't found in ping sweep
        for ip_neigh_ip in ip_neigh_devices:
            if not any(device['IPAddress'] == ip_neigh_ip for device in active_devices):
                try:
                    hostname = socket.getfqdn(ip_neigh_ip)
                except:
                    hostname = "N/A"
                
                logging.info(f"Adding ip neighbor device: {ip_neigh_ip} (hostname: {hostname})")
                print(f"[+] Adding ip neighbor device: {ip_neigh_ip} (hostname: {hostname})")
                active_devices.append({
                    'IPAddress': ip_neigh_ip,
                    'Hostname': hostname
                })

        # now run nmap for additional verification (skip in fast mode)
        if active_devices and not fast_mode:
            print(f"\n[*] Verifying {len(active_devices)} discovered devices with nmap...")
            print("[*] Note: Some devices may not respond to nmap but are still active")
            nm = nmap.PortScanner()
            verified_devices = []
            
            for device in active_devices:
                ip = device['IPAddress']
                try:
                    logging.info(f"Running nmap verification scan on {ip}")
                    # try multiple nmap techniques for better detection
                    nm.scan(ip, arguments='-sn -PE -PP -PS21,22,23,25,53,80,111,199,443,993,995,5985 -T4')
                    if ip in nm.all_hosts():
                        verified_devices.append(device)
                        logging.info(f"Nmap confirmed {ip} is active")
                    else:
                        logging.debug(f"Nmap could not verify {ip} - keeping device anyway")
                        # keep device even if nmap verification fails
                        verified_devices.append(device)
                except Exception as e:
                    logging.error(f"Nmap scan error for {ip}: {str(e)}")
                    # keep device even if nmap fails
                    verified_devices.append(device)
            
            active_devices = verified_devices
        
        if not active_devices:
            print("\n[!] No active devices found on the network")
            print("[!] This could mean:")
            print("    - No other devices are connected")
            print("    - Devices are not responding to ping")
            print("    - Firewall is blocking scans")
            print("    - Network configuration issues")
            print("\n[*] Check the logs for more details")
        else:
            print(f"\n[+] Found {len(active_devices)} active devices")
        
        logging.info(f"Found {len(active_devices)} active devices")
        
    except Exception as e:
        logging.error(f"Network scan error: {str(e)}\n{traceback.format_exc()}")
        print(f"\n[!] Error during network scan: {str(e)}")
    
    return active_devices


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Linux Network Scanner')
    parser.add_argument('--log-path', type=str, 
                       default=str(Path(__file__).parent / "logs"),
                       help='Path to store device profiles')
    parser.add_argument('--username', type=str, help='Username for device authentication')
    parser.add_argument('--password', type=str, help='Password for device authentication')
    parser.add_argument('--ssh-port', type=int, default=22, help='SSH port for Linux/macOS systems')
    parser.add_argument('--winrm-port', type=int, default=5985, help='WinRM port for Windows systems')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--summary', action='store_true', help='Display detailed device summary')
    parser.add_argument('--fast', action='store_true', help='Fast scan mode (fewer checks)')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        print("\n=== Linux Network Scanner ===")
        print("[*] Initializing...")
        logging.info("Starting network scanner...")
        logging.info(f"Arguments: {args}")
        
        scanner = NetworkScanner(log_path=args.log_path, ssh_port=args.ssh_port, winrm_port=args.winrm_port)
        
        network_range = scanner.get_network_range()
        logging.info(f"Network range determined: {network_range}")
        
        active_devices = start_network_scan(network_range, args.fast)
        
        if active_devices:
            device_profiles = []
            print("\n[*] Profiling discovered devices...")
            for device in active_devices:
                ip = device['IPAddress']
                logging.info(f"\nProfiling device: {ip}")
                print(f"[*] Profiling device: {ip}")
                
                try:
                    profile = scanner.get_device_details(ip, args.username, args.password)
                    device_profiles.append(profile)
                    scanner.save_profile(profile)
                    logging.info(f"Profile saved for {ip}")
                    print(f"[+] Platform detected: {profile.platform}")
                    print(f"[+] Accessibility: {'Yes' if profile.is_accessible else 'No'}")
                    if profile.vendor and profile.vendor != 'Unknown':
                        print(f"[+] Vendor: {profile.vendor}")
                except Exception as e:
                    logging.error(f"Failed to profile device {ip}: {str(e)}")
                    print(f"[!] Failed to profile device {ip}: {str(e)}")

            # display summary
            if args.summary:
                scanner.display_device_summary(device_profiles)
            
            # show quick stats
            platforms = {}
            accessible_count = 0
            for profile in device_profiles:
                platform = profile.platform or 'Unknown'
                platforms[platform] = platforms.get(platform, 0) + 1
                if profile.is_accessible:
                    accessible_count += 1
            
            print(f"\n[+] Scan complete! Found {len(device_profiles)} devices.")
            print(f"[+] Detailed profiles saved to: {args.log_path}")
            print(f"[+] Use --summary flag to see detailed device information")
            print(f"\n[+] Platform breakdown:")
            for platform, count in platforms.items():
                print(f"    {platform}: {count} devices")
            print(f"[+] Accessible devices: {accessible_count}/{len(device_profiles)}")
        else:
            print("\n[*] No devices to profile")
            print("[*] Scan complete")
            
    except Exception as e:
        logging.error(f"Major error in main: {str(e)}\n{traceback.format_exc()}")
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()