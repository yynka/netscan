#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Set up logging first
script_dir = Path(__file__).parent
log_dir = script_dir / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(log_dir / 'network_scanner_debug.log'))
    ]
)

# Now import the rest
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gdk
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
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import traceback
import re

# Print clear messaging about script operation
print("\n=== Network Scanner ===")
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
        logging.info(f"Initialized NetworkScanner with log_path={log_path}, ssh_port={ssh_port}")

    def get_network_range(self):
        print("[*] Detecting network interfaces...")
        try:
            interfaces = netifaces.interfaces()
            logging.info(f"Available interfaces: {interfaces}")
            
            # Try en0 first (common for macOS), then fall back to other interfaces
            primary_interface = None
            for iface in ['en0', 'en1', 'eth0', 'wlan0']:
                if iface in interfaces and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    primary_interface = iface
                    break
            
            if not primary_interface:
                raise Exception("No suitable network interface found")

            interface_info = netifaces.ifaddresses(primary_interface)[netifaces.AF_INET][0]
            ip = interface_info['addr']
            netmask = interface_info['netmask']
            
            print(f"[+] Using interface {primary_interface} ({ip})")
            logging.info(f"Selected interface {primary_interface}: IP={ip}, Netmask={netmask}")
            
            # Convert to network base address
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

    def get_mac_vendor(self, mac):
        try:
            logging.info(f"Looking up vendor for MAC: {mac}")
            response = subprocess.check_output(['curl', '-s', f'https://api.macvendors.com/{mac}'])
            vendor = response.decode().strip()
            logging.info(f"Vendor found: {vendor}")
            return vendor
        except Exception as e:
            logging.warning(f"Failed to get MAC vendor: {str(e)}")
            return "Unknown"
    
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

    def test_ssh_access(self, ip, port=22):
        try:
            logging.info(f"Testing SSH access to {ip}:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Increased timeout
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Try banner grab
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

    def get_macos_info(self, ip, username=None, password=None):
        logging.info(f"Attempting to gather macOS info for {ip}")
        try:
            if not username or not password:
                logging.warning("No credentials provided for macOS info gathering")
                return None

            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logging.info(f"Attempting SSH connection to {ip} with username {username}")
            ssh.connect(ip, port=self.ssh_port, username=username, password=password, timeout=5)
            logging.info("SSH connection successful")

            # System info with error handling
            try:
                hostname = "Unknown"
                sw_vers = "Unknown"
                who = "Unknown"
                
                stdin, stdout, stderr = ssh.exec_command('hostname')
                hostname = stdout.readline().strip()
                
                stdin, stdout, stderr = ssh.exec_command('sw_vers')
                sw_vers = stdout.read().decode()
                
                stdin, stdout, stderr = ssh.exec_command('who')
                who = stdout.readline().strip()
                
                logging.info(f"System info gathered: hostname={hostname}, sw_vers={sw_vers}, who={who}")
            except Exception as e:
                logging.error(f"Error getting system info: {str(e)}")

            # Services with error handling
            services = []
            try:
                stdin, stdout, stderr = ssh.exec_command('launchctl list')
                for line in stdout:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0].isdigit():
                        service_info = ServiceInfo(
                            name=parts[2],
                            display_name=parts[2],
                            status='Running' if parts[0] != "-" else 'Stopped',
                            start_type='Enabled'
                        )
                        services.append(service_info)
                logging.info(f"Found {len(services)} services")
            except Exception as e:
                logging.error(f"Error getting services: {str(e)}")

            # Shares with error handling
            shares = []
            try:
                stdin, stdout, stderr = ssh.exec_command('sharing -l')
                for line in stdout:
                    if line.startswith('Name:'):
                        share_info = ShareInfo(
                            name=line.split(':')[1].strip(),
                            path='/Volumes',
                            description='macOS Share'
                        )
                        shares.append(share_info)
                logging.info(f"Found {len(shares)} shares")
            except Exception as e:
                logging.error(f"Error getting shares: {str(e)}")

            # Network interfaces
            interfaces = ""
            try:
                stdin, stdout, stderr = ssh.exec_command('ifconfig')
                interfaces = stdout.read().decode()
                logging.info("Network interface information gathered")
            except Exception as e:
                logging.error(f"Error getting network interfaces: {str(e)}")

            ssh.close()
            logging.info("Successfully gathered all macOS info")

            return {
                'hostname': hostname,
                'os_info': sw_vers,
                'last_user': who.split()[0] if who else None,
                'services': services,
                'shares': shares,
                'interfaces': interfaces,
                'platform': 'macOS',
                'is_accessible': True
            }
        except Exception as e:
            logging.error(f"macOS info error for {ip}: {str(e)}\n{traceback.format_exc()}")
        return None
    def get_device_details(self, ip, username=None, password=None):
        logging.info(f"\n{'='*50}\nStarting device profiling for {ip}\n{'='*50}")
        profile = DeviceProfile(ip)
        
        try:
            # Basic info
            logging.info(f"Getting basic info for {ip}")
            try:
                profile.hostname = socket.getfqdn(ip)
                logging.info(f"Hostname resolved: {profile.hostname}")
            except Exception as e:
                logging.error(f"Hostname resolution failed: {str(e)}")
                profile.hostname = ip

            # Test basic accessibility
            is_accessible = self.test_host_accessibility(ip)
            if not is_accessible:
                logging.warning(f"Host {ip} is not responding to basic connectivity tests")

            # MAC address and vendor
            try:
                logging.info(f"Getting MAC address for {ip}")
                arp_output = subprocess.check_output(['arp', '-n', ip]).decode()
                logging.debug(f"ARP output: {arp_output}")
                mac = next((line.split()[3] for line in arp_output.split('\n') if ip in line), None)
                if mac:
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
                
                # Check for specific macOS signatures in open ports
                if ip in self.nm and 'tcp' in self.nm[ip]:
                    for port, port_info in self.nm[ip]['tcp'].items():
                        if 'product' in port_info and ('Apple' in port_info['product'] or 'macOS' in port_info['product']):
                            profile.platform = 'macOS'
                            logging.info(f"macOS detected through service fingerprint on port {port}")
            except Exception as e:
                logging.error(f"Nmap OS detection failed: {str(e)}")

            # Platform detection
            try:
                logging.info(f"Testing SSH access for {ip}")
                is_macos = self.test_ssh_access(ip, self.ssh_port)
                logging.info(f"SSH accessible: {is_macos}")
                
                if is_macos:
                    logging.info("Attempting macOS info gathering...")
                    macos_info = self.get_macos_info(ip, username, password)
                    if macos_info:
                        logging.info("Successfully gathered macOS info")
                        profile.platform = macos_info['platform']
                        profile.is_accessible = macos_info['is_accessible']
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
                                'Interfaces': macos_info['interfaces'].split('\n')
                            }
                        ))
                else:
                    logging.info("Device not accessible via SSH")
                    profile.platform = 'Unknown'
                    profile.is_accessible = False
            except Exception as e:
                logging.error(f"Platform detection failed: {str(e)}")

            # Service discovery history
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

def start_network_scan(network_info):
    logging.info(f"Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    print(f"\n[*] Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    print("[*] This may take a few moments...\n")
    
    active_devices = []

    try:
        # Get the base network
        base_ip = network_info['Base']
        ip_parts = base_ip.split('.')
        base_prefix = '.'.join(ip_parts[:-1]) + '.'
        
        # First use arp -a to get initial list of devices
        logging.info("Running arp -a to find devices")
        arp_output = subprocess.check_output(['arp', '-a']).decode()
        logging.info(f"ARP output: {arp_output}")
        
        # Parse arp output
        arp_devices = set()
        for line in arp_output.split('\n'):
            if line.strip():
                try:
                    # Parse IP address from arp output
                    ip = line.split('(')[1].split(')')[0]
                    if ip.startswith(base_prefix):
                        arp_devices.add(ip)
                        logging.info(f"Found device in ARP: {ip}")
                except:
                    continue

        # Also try ping sweep
        logging.info("Starting ping sweep")
        print("[*] Performing ping sweep...")
        for i in range(1, 255):
            ip = f"{base_prefix}{i}"
            if i % 50 == 0:  # Progress indicator
                print(f"[*] Scanning... ({i}/254)")
            
            try:
                # Fast ping with short timeout
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
                result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if result.returncode == 0 or ip in arp_devices:
                    try:
                        hostname = socket.getfqdn(ip)
                    except:
                        hostname = "N/A"
                    
                    logging.info(f"Found active host: {ip} (hostname: {hostname})")
                    print(f"[+] Found active host: {ip} (hostname: {hostname})")
                    active_devices.append({
                        'IPAddress': ip,
                        'Hostname': hostname
                    })

            except Exception as e:
                logging.debug(f"Error pinging {ip}: {str(e)}")
                continue

            # Now run nmap for additional verification
        if active_devices:
            print("\n[*] Verifying discovered devices with nmap...")
            nm = nmap.PortScanner()
            for device in active_devices:
                ip = device['IPAddress']
                try:
                    logging.info(f"Running detailed nmap scan on {ip}")
                    nm.scan(ip, arguments='-sn -T4')
                    if ip in nm.all_hosts():
                        logging.info(f"Nmap confirmed {ip} is active")
                except Exception as e:
                    logging.error(f"Nmap scan error for {ip}: {str(e)}")
        
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

class DeviceMonitorWindow(Gtk.Window):
    def __init__(self, devices, refresh_interval=300):
        Gtk.Window.__init__(self, title="Network Device Monitor")
        self.set_default_size(1000, 700)
        self.devices = devices
        self.refresh_interval = refresh_interval
        logging.info("Initializing DeviceMonitorWindow")

        # Header bar with refresh button
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.props.title = "Network Device Monitor"
        self.set_titlebar(header)

        refresh_button = Gtk.Button()
        refresh_button.add(Gtk.Image.new_from_icon_name("view-refresh-symbolic", 
                                                       Gtk.IconSize.BUTTON))
        refresh_button.connect("clicked", self.on_refresh_clicked)
        header.pack_end(refresh_button)

        # Main container with split panes
        paned = Gtk.Paned()
        self.add(paned)

        # Device list (left pane)
        scrolled_list = Gtk.ScrolledWindow()
        scrolled_list.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled_list.set_size_request(250, -1)
        
        self.device_list = Gtk.ListBox()
        self.device_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.device_list.connect("row-selected", self.on_device_selected)
        scrolled_list.add(self.device_list)
        
        # Add devices to list with improved status indicators
        for device in devices:
            row = Gtk.ListBoxRow()
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            row.add(hbox)
            
            status_icon = Gtk.Image()
            if device.is_accessible:
                status_icon.set_from_icon_name("emblem-default", Gtk.IconSize.SMALL_TOOLBAR)
            else:
                status_icon.set_from_icon_name("emblem-important", Gtk.IconSize.SMALL_TOOLBAR)
            hbox.pack_start(status_icon, False, False, 0)
            
            label = Gtk.Label(
                label=f"{device.computer_name or device.hostname or device.ip_address} [{device.platform or 'Unknown'}]"
            )
            label.set_alignment(0, 0.5)
            hbox.pack_start(label, True, True, 0)
            
            self.device_list.add(row)

        paned.pack1(scrolled_list, False, False)

        # Details notebook (right pane)
        self.details_notebook = Gtk.Notebook()
        
        # Info page
        self.info_grid = Gtk.Grid()
        self.info_grid.set_column_spacing(12)
        self.info_grid.set_row_spacing(6)
        self.info_grid.set_margin_start(10)
        self.info_grid.set_margin_end(10)
        self.info_grid.set_margin_top(10)
        self.info_grid.set_margin_bottom(10)
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.info_grid)
        self.details_notebook.append_page(scroll, Gtk.Label(label="Information"))
        
        # Services page
        self.services_store = Gtk.ListStore(str, str, str, str)
        self.services_view = Gtk.TreeView(model=self.services_store)
        for i, title in enumerate(["Name", "Display Name", "Status", "Start Type"]):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            self.services_view.append_column(column)
        
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.services_view)
        self.details_notebook.append_page(scroll, Gtk.Label(label="Services"))
        
        # Shares page
        self.shares_store = Gtk.ListStore(str, str, str)
        self.shares_view = Gtk.TreeView(model=self.shares_store)
        for i, title in enumerate(["Name", "Path", "Description"]):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            self.shares_view.append_column(column)
        
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.shares_view)
        self.details_notebook.append_page(scroll, Gtk.Label(label="Shared Resources"))
        
        # History page
        self.history_store = Gtk.ListStore(str, str, str)
        self.history_view = Gtk.TreeView(model=self.history_store)
        for i, title in enumerate(["Timestamp", "Type", "Details"]):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            self.history_view.append_column(column)
        
        scroll = Gtk.ScrolledWindow()
        scroll.add(self.history_view)
        self.details_notebook.append_page(scroll, Gtk.Label(label="History"))

        paned.pack2(self.details_notebook, True, False)

        # Setup refresh timer
        GLib.timeout_add_seconds(refresh_interval, self.refresh_display)
        logging.info("DeviceMonitorWindow initialization complete")

    def on_device_selected(self, listbox, row):
        if row is not None:
            logging.info(f"Device selected: index={row.get_index()}")
            self.update_details(row.get_index())

    def on_refresh_clicked(self, button):
        logging.info("Manual refresh triggered")
        self.refresh_display()

    def update_details(self, index):
        if index < 0:
            return

        try:
            device = self.devices[index]
            logging.info(f"Updating details for device: {device.ip_address}")
            
            # Clear existing details
            for child in self.info_grid.get_children():
                self.info_grid.remove(child)
            
            self.services_store.clear()
            self.shares_store.clear()
            self.history_store.clear()

            # Update info page with improved formatting
            info_items = [
                ("Computer Name", device.computer_name),
                ("IP Address", device.ip_address),
                ("Platform", device.platform),
                ("MAC Address", device.mac_address),
                ("Vendor", device.vendor),
                ("OS Version", device.os_version),
                ("Last User", device.last_user),
                ("First Seen", device.first_seen),
                ("Last Seen", device.last_seen),
                ("Status", "Accessible" if device.is_accessible else "Inaccessible")
            ]

            for i, (label, value) in enumerate(info_items):
                label_widget = Gtk.Label(label=f"{label}:")
                label_widget.set_alignment(1, 0.5)
                value_widget = Gtk.Label(label=str(value if value is not None else "N/A"))
                value_widget.set_alignment(0, 0.5)
                value_widget.set_line_wrap(True)
                
                self.info_grid.attach(label_widget, 0, i, 1, 1)
                self.info_grid.attach(value_widget, 1, i, 1, 1)

            # Update services page
            if device.services:
                for service in device.services:
                    self.services_store.append([
                        service.name,
                        service.display_name,
                        service.status,
                        service.start_type
                    ])

            # Update shares page
            if device.shared_resources:
                for share in device.shared_resources:
                    self.shares_store.append([
                        share.name,
                        share.path,
                        share.description
                    ])

            # Update history page
            if device.history:
                for entry in sorted(device.history, key=lambda x: x.timestamp, reverse=True):
                    self.history_store.append([
                        entry.timestamp,
                        entry.type,
                        json.dumps(entry.data, indent=2)
                    ])
                
            logging.info("Details updated successfully")
        except Exception as e:
            logging.error(f"Error updating details: {str(e)}\n{traceback.format_exc()}")

    def refresh_display(self):
        try:
            logging.info("Refreshing display")
            selected_row = self.device_list.get_selected_row()
            if selected_row is not None:
                self.update_details(selected_row.get_index())
        except Exception as e:
            logging.error(f"Error refreshing display: {str(e)}")
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Network Scanner')
    parser.add_argument('--monitor', action='store_true', help='Enable monitoring mode')
    parser.add_argument('--refresh', type=int, default=300, help='Refresh interval in seconds')
    parser.add_argument('--log-path', type=str, 
                       default=str(Path(__file__).parent / "logs"),
                       help='Path to store device profiles')
    parser.add_argument('--username', type=str, help='Username for device authentication')
    parser.add_argument('--password', type=str, help='Password for device authentication')
    parser.add_argument('--ssh-port', type=int, default=22, help='SSH port for Linux/macOS systems')
    parser.add_argument('--winrm-port', type=int, default=5985, help='WinRM port for Windows systems')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        print("\n=== Network Scanner ===")
        print("[*] Initializing...")
        logging.info("Starting enhanced network scanner...")
        logging.info(f"Arguments: {args}")
        
        scanner = NetworkScanner(log_path=args.log_path, 
                               ssh_port=args.ssh_port, 
                               winrm_port=args.winrm_port)
        
        network_range = scanner.get_network_range()
        logging.info(f"Network range determined: {network_range}")
        
        active_devices = start_network_scan(network_range)
        
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
                except Exception as e:
                    logging.error(f"Failed to profile device {ip}: {str(e)}")
                    print(f"[!] Failed to profile device {ip}: {str(e)}")

            if args.monitor:
                logging.info("Starting monitoring mode...")
                print("\n[*] Starting monitoring mode...")
                win = DeviceMonitorWindow(device_profiles, args.refresh)
                win.connect("destroy", Gtk.main_quit)
                win.show_all()
                Gtk.main()
        else:
            print("\n[*] No devices to profile")
            print("[*] Scan complete")
            
    except Exception as e:
        logging.error(f"Major error in main: {str(e)}\n{traceback.format_exc()}")
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()