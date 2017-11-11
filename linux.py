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
try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, GLib, Gdk
    GTK_AVAILABLE = True
except ImportError:
    GTK_AVAILABLE = False
    logging.warning("GTK not available - GUI features will be disabled")

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
    def __init__(self, log_path=str(Path(__file__).parent / "logs"), ssh_port=22):
        self.log_path = log_path
        self.ssh_port = ssh_port
        Path(log_path).mkdir(parents=True, exist_ok=True)
        self.nm = nmap.PortScanner()
        print(f"[*] Scanner initialized, logs will be saved to: {log_path}")
        logging.info(f"Initialized NetworkScanner with log_path={log_path}, ssh_port={ssh_port}")

    def get_network_range(self):
        print("[*] Detecting network interfaces...")
        try:
            interfaces = netifaces.interfaces()
            logging.info(f"Available interfaces: {interfaces}")
            
            # Try common Linux interfaces first
            primary_interface = None
            for iface in ['eth0', 'wlan0', 'eno1', 'wlp2s0', 'enp0s3']:
                if iface in interfaces and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    primary_interface = iface
                    break
            
            if not primary_interface:
                # Fall back to first interface with IPv4 address
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

    def get_linux_info(self, ip, username=None, password=None):
        """Gather information about a Linux system via SSH."""
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

            # System info with error handling
            hostname = "Unknown"
            os_info = "Unknown"
            who = "Unknown"
            services = []
            shares = []
            interfaces = ""

            # Gather hostname, OS info
            try:
                stdin, stdout, stderr = ssh.exec_command('hostname')
                hostname = stdout.readline().strip()
                
                # Try multiple commands for OS info
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

            # Services
            try:
                # Try systemctl first
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
                    # Fallback to service command
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

            # Shares
            try:
                # Check NFS shares
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
                
                # Check Samba shares
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

            # Network interfaces
            try:
                stdin, stdout, stderr = ssh.exec_command('ip addr')
                interfaces = stdout.read().decode()
                logging.info("Network interface information gathered")
            except Exception as e:
                logging.error(f"Error getting network interfaces: {str(e)}")

            # Clean up SSH connection
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

    def get_device_details(self, ip, username=None, password=None):
        """Get detailed information about a network device."""
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

            # MAC address and vendor discovery
            try:
                logging.info(f"Getting MAC address for {ip}")
                mac = None

                # Try ip neighbor first (Linux)
                try:
                    ip_neigh = subprocess.check_output(['ip', 'neighbor', 'show', ip]).decode()
                    logging.debug(f"ip neighbor output: {ip_neigh}")
                    if ip_neigh.strip():
                        parts = ip_neigh.split()
                        if len(parts) >= 5:
                            mac = parts[4]
                except Exception as e:
                    logging.debug(f"ip neighbor command failed: {e}")

                # Fallback to arp
                if not mac:
                    try:
                        arp_output = subprocess.check_output(['arp', '-n', ip]).decode()
                        logging.debug(f"ARP output: {arp_output}")
                        if arp_output.strip():
                            lines = arp_output.split('\n')
                            for line in lines[1:]:  # Skip header
                                if ip in line:
                                    parts = line.split()
                                    if len(parts) >= 3:
                                        mac = parts[2]
                                        break
                    except Exception as e:
                        logging.debug(f"arp command failed: {e}")

                if mac and ':' in mac:  # Basic MAC address validation
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
                
                # Look for Linux/Unix signatures
                if ip in self.nm and 'tcp' in self.nm[ip]:
                    for port, port_info in self.nm[ip]['tcp'].items():
                        if 'product' in port_info:
                            if any(x in port_info['product'] for x in ['Linux', 'Unix', 'SSH']):
                                profile.platform = 'Linux'
                                logging.info(f"Linux detected through service fingerprint on port {port}")
                                break
            except Exception as e:
                logging.error(f"Nmap OS detection failed: {str(e)}")

            # Platform detection and access testing
            try:
                logging.info(f"Testing SSH access for {ip}")
                ssh_accessible = self.test_ssh_access(ip, self.ssh_port)
                logging.info(f"SSH accessible: {ssh_accessible}")
                
                if ssh_accessible:
                    logging.info("Attempting Linux info gathering...")
                    linux_info = self.get_linux_info(ip, username, password)
                    if linux_info:
                        logging.info("Successfully gathered Linux info")
                        profile.platform = linux_info['platform']
                        profile.is_accessible = linux_info['is_accessible']
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
                                'Interfaces': linux_info['interfaces'].split('\n')
                            }
                        ))
                else:
                    logging.info("Device not accessible via SSH")
                    profile.platform = 'Unknown'
                    profile.is_accessible = False
            except Exception as e:
                logging.error(f"Platform detection failed: {str(e)}")

            # Add service discovery history
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
        """Save device profile to JSON file."""
        try:
            filename = os.path.join(self.log_path, f"{profile.ip_address.replace('.', '_')}.json")
            logging.info(f"Saving profile to {filename}")
            with open(filename, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)
            logging.info("Profile saved successfully")
        except Exception as e:
            logging.error(f"Failed to save profile: {str(e)}")

def start_network_scan(network_info):
    """Perform network scan to discover active devices."""
    logging.info(f"Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    print(f"\n[*] Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    print("[*] This may take a few moments...\n")
    
    active_devices = []
    ip_neigh_devices = set()

    try:
        # Get the base network
        base_ip = network_info['Base']
        ip_parts = base_ip.split('.')
        base_prefix = '.'.join(ip_parts[:-1]) + '.'
        
        # First use ip neighbor to get initial list of devices
        logging.info("Running ip neighbor to find devices")
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

        # Also try using arp cache
        try:
            arp_output = subprocess.check_output(['arp', '-n']).decode()
            logging.info(f"ARP output: {arp_output}")
            for line in arp_output.split('\n')[1:]:  # Skip header
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

        def ping_host(ip):
            """Helper function to ping a single host."""
            try:
                ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
                result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return ip, result.returncode == 0
            except Exception:
                return ip, False

        # Use ThreadPoolExecutor for parallel ping sweep
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{base_prefix}{i}"
                if i % 50 == 0:  # Progress indicator
                    print(f"[*] Scanning... ({i}/254)")
                futures.append(executor.submit(ping_host, ip))

            for future in futures:
                try:
                    ip, is_alive = future.result()
                    if is_alive or ip in ip_neigh_devices:
                        try:
                            hostname = socket.getfqdn(ip)
                        except Exception:
                            hostname = "N/A"
                        
                        logging.info(f"Found active host: {ip} (hostname: {hostname})")
                        print(f"[+] Found active host: {ip} (hostname: {hostname})")
                        active_devices.append({
                            'IPAddress': ip,
                            'Hostname': hostname
                        })
                except Exception as e:
                    logging.error(f"Error processing ping result: {str(e)}")

        # Verify with nmap
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
    """Main window for monitoring network devices."""
    def __init__(self, devices, refresh_interval=300):
        Gtk.Window.__init__(self, title="Network Device Monitor")
        self.set_default_size(1000, 700)
        self.devices = devices
        self.refresh_interval = refresh_interval
        logging.info("Initializing DeviceMonitorWindow")

        try:
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
            
            # Add devices to list with status indicators
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

        except Exception as e:
            logging.error(f"Error initializing DeviceMonitorWindow: {str(e)}\n{traceback.format_exc()}")
            raise

    def on_device_selected(self, listbox, row):
        """Handle device selection in the list."""
        try:
            if row is not None:
                logging.info(f"Device selected: index={row.get_index()}")
                self.update_details(row.get_index())
        except Exception as e:
            logging.error(f"Error in device selection: {str(e)}")

    def on_refresh_clicked(self, button):
        """Handle manual refresh button click."""
        try:
            logging.info("Manual refresh triggered")
            self.refresh_display()
        except Exception as e:
            logging.error(f"Error during manual refresh: {str(e)}")

    def update_details(self, index):
        """Update the details pane with device information."""
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

            # Update info page
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
        """Refresh the display periodically."""
        try:
            logging.info("Refreshing display")
            selected_row = self.device_list.get_selected_row()
            if selected_row is not None:
                self.update_details(selected_row.get_index())
        except Exception as e:
            logging.error(f"Error refreshing display: {str(e)}")
        return True  # Continue the timer

def main():
    """Main program entry point."""
    import argparse
    parser = argparse.ArgumentParser(description='Linux Network Scanner')
    parser.add_argument('--monitor', action='store_true', help='Enable monitoring mode')
    parser.add_argument('--refresh', type=int, default=300, help='Refresh interval in seconds')
    parser.add_argument('--log-path', type=str, 
                       default=str(Path(__file__).parent / "logs"),
                       help='Path to store device profiles')
    parser.add_argument('--username', type=str, help='Username for device authentication')
    parser.add_argument('--password', type=str, help='Password for device authentication')
    parser.add_argument('--ssh-port', type=int, default=22, help='SSH port for Linux systems')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        print("\n=== Linux Network Scanner ===")
        print("[*] Initializing...")
        logging.info("Starting network scanner...")
        logging.info(f"Arguments: {args}")
        
        scanner = NetworkScanner(log_path=args.log_path, ssh_port=args.ssh_port)
        
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

            if args.monitor and GTK_AVAILABLE:
                try:
                    logging.info("Starting monitoring mode...")
                    print("\n[*] Starting monitoring mode...")
                    win = DeviceMonitorWindow(device_profiles, args.refresh)
                    win.connect("destroy", Gtk.main_quit)
                    win.show_all()
                    Gtk.main()
                except Exception as e:
                    logging.error(f"Error in monitoring mode: {str(e)}\n{traceback.format_exc()}")
                    print(f"[!] Error starting monitor: {str(e)}")
            elif args.monitor and not GTK_AVAILABLE:
                print("\n[!] GTK is not available - cannot start monitoring mode")
                print("[*] Scan complete")
                print(f"[*] Results saved in: {args.log_path}")
            else:
                print("\n[*] Scan complete")
                print(f"[*] Results saved in: {args.log_path}")
        else:
            print("\n[*] No devices to profile")
            print("[*] Scan complete")
            
    except Exception as e:
        logging.error(f"Major error in main: {str(e)}\n{traceback.format_exc()}")
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()