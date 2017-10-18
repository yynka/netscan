#!/usr/bin/env python3

import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

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
from pathlib import Path
import paramiko
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
from functools import partial

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
    def __init__(self, log_path=str(Path(__file__).parent.parent / "logs"), ssh_port=22, winrm_port=5985):
        self.log_path = log_path
        self.ssh_port = ssh_port
        self.winrm_port = winrm_port
        Path(log_path).mkdir(parents=True, exist_ok=True)
        self.nm = nmap.PortScanner()
        
        logging.basicConfig(
            filename=f"{log_path}/scanner.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def get_network_range(self):
        try:
            iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            netmask = addrs['netmask']
            ip = addrs['addr']
            
            # Convert to network base address
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            network = [ip_parts[i] & mask_parts[i] for i in range(4)]
            
            return {
                'Base': '.'.join(map(str, network)),
                'Prefix': sum(bin(x).count('1') for x in mask_parts),
                'Interface': ip
            }
        except Exception as e:
            logging.error(f"Failed to determine network range: {str(e)}")
            raise

    def get_mac_vendor(self, mac):
        try:
            response = subprocess.check_output(['curl', '-s', f'https://api.macvendors.com/{mac}'])
            return response.decode().strip()
        except:
            return "Unknown"

    def test_ssh_access(self, ip, port=22):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def get_linux_services(self, ssh):
        stdin, stdout, stderr = ssh.exec_command(
            'systemctl list-units --type=service --state=running --no-legend'
        )
        services = []
        for line in stdout:
            parts = line.strip().split()
            if len(parts) >= 4:
                service_info = ServiceInfo(
                    name=parts[0].replace('.service', ''),
                    display_name=' '.join(parts[3:]),
                    status='Running',
                    start_type='Enabled'
                )
                services.append(service_info)
        return services

    def get_linux_shares(self, ssh):
        stdin, stdout, stderr = ssh.exec_command(
            'df -h --output=source,target,fstype | grep -E "nfs|cifs|smb"'
        )
        shares = []
        for line in stdout:
            parts = line.strip().split()
            if len(parts) >= 3:
                share_info = ShareInfo(
                    name=parts[1].split('/')[-1] or parts[1],
                    path=parts[0],
                    description=f"{parts[2]} share"
                )
                shares.append(share_info)
        return shares

    def get_linux_info(self, ip, username=None, password=None):
        try:
            if username and password:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=self.ssh_port, username=username, password=password, timeout=5)

                # System info
                stdin, stdout, stderr = ssh.exec_command('hostname && uname -a && who')
                hostname = stdout.readline().strip()
                uname = stdout.readline().strip()
                who = stdout.readline().strip()

                # Get detailed system info
                stdin, stdout, stderr = ssh.exec_command('cat /etc/os-release')
                os_info = stdout.read().decode()
                os_name = None
                for line in os_info.split('\n'):
                    if line.startswith('PRETTY_NAME='):
                        os_name = line.split('=')[1].strip('"')
                        break

                services = self.get_linux_services(ssh)
                shares = self.get_linux_shares(ssh)

                # Network interfaces
                stdin, stdout, stderr = ssh.exec_command('ip addr show')
                interfaces = stdout.read().decode()

                ssh.close()

                return {
                    'hostname': hostname,
                    'os_info': os_name or uname,
                    'last_user': who.split()[0] if who else None,
                    'services': services,
                    'shares': shares,
                    'interfaces': interfaces,
                    'platform': 'Linux',
                    'is_accessible': True
                }
        except Exception as e:
            logging.error(f"Linux info error for {ip}: {str(e)}")
        return None

    def get_device_details(self, ip, username=None, password=None):
        profile = DeviceProfile(ip)
        
        try:
            # Basic info
            profile.hostname = socket.getfqdn(ip)
            
            # MAC address and vendor
            arp_output = subprocess.check_output(['arp', '-n', ip]).decode()
            mac = arp_output.split('\n')[1].split()[2]
            profile.mac_address = mac
            profile.vendor = self.get_mac_vendor(mac)
            
            # OS detection and port scanning
            self.nm.scan(ip, arguments='-O -sV')
            if 'osmatch' in self.nm[ip]:
                profile.os_version = self.nm[ip]['osmatch'][0]['name']

            # Platform detection
            is_linux = self.test_ssh_access(ip, self.ssh_port)
            if is_linux:
                linux_info = self.get_linux_info(ip, username, password)
                if linux_info:
                    profile.platform = linux_info['platform']
                    profile.is_accessible = linux_info['is_accessible']
                    profile.computer_name = linux_info['hostname']
                    profile.os_version = linux_info['os_info']
                    profile.last_user = linux_info['last_user']
                    profile.services = linux_info['services']
                    profile.shared_resources = linux_info['shares']
                    
                    # Add network interface history
                    profile.history.append(HistoryEntry(
                        timestamp=datetime.now().isoformat(),
                        type='NetworkAdapter',
                        data={
                            'Description': "Network Interfaces",
                            'Interfaces': linux_info['interfaces'].split('\n')
                        }
                    ))
            else:
                profile.platform = 'Unknown'
                profile.is_accessible = False

            # Add service discovery history
            if 'tcp' in self.nm[ip]:
                profile.history.append(HistoryEntry(
                    timestamp=datetime.now().isoformat(),
                    type='ServiceDiscovery',
                    data={'ports': self.nm[ip]['tcp']}
                ))
            
        except Exception as e:
            logging.error(f"Error getting details for {ip}: {str(e)}")
        
        return profile

    def save_profile(self, profile):
        filename = os.path.join(self.log_path, f"{profile.ip_address.replace('.', '_')}.json")
        with open(filename, 'w') as f:
            json.dump(profile.to_dict(), f, indent=2)

class DeviceMonitorWindow(Gtk.Window):
    def __init__(self, devices, refresh_interval=300):
        Gtk.Window.__init__(self, title="Network Device Monitor")
        self.set_default_size(1000, 700)
        self.devices = devices
        self.refresh_interval = refresh_interval

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
        
        # Add devices to list
        for device in devices:
            row = Gtk.ListBoxRow()
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            row.add(hbox)
            
            label = Gtk.Label(
                label=f"{device.computer_name or device.hostname} ({device.ip_address}) [{device.platform or 'Unknown'}]"
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

    def on_device_selected(self, listbox, row):
        if row is not None:
            self.update_details(row.get_index())

    def on_refresh_clicked(self, button):
        self.refresh_display()

    def update_details(self, index):
        if index < 0:
            return

        device = self.devices[index]
        
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
        for service in device.services:
            self.services_store.append([
                service.name,
                service.display_name,
                service.status,
                service.start_type
            ])

        # Update shares page
        for share in device.shared_resources:
            self.shares_store.append([
                share.name,
                share.path,
                share.description
            ])

        # Update history page
        for entry in sorted(device.history, key=lambda x: x.timestamp, reverse=True):
            self.history_store.append([
                entry.timestamp,
                entry.type,
                json.dumps(entry.data, indent=2)
            ])

    def refresh_display(self):
        selected_row = self.device_list.get_selected_row()
        if selected_row is not None:
            self.update_details(selected_row.get_index())
        return True

def start_network_scan(network_info):
    nm = nmap.PortScanner()
    print(f"[*] Starting network scan on {network_info['Interface']}/{network_info['Prefix']}")
    
    base_ip = network_info['Base']
    prefix = network_info['Prefix']
    scan_range = f"{base_ip}/{prefix}"
    
    active_devices = []
    try:
        nm.scan(hosts=scan_range, arguments='-sn')
        for ip in nm.all_hosts():
            try:
                hostname = socket.getfqdn(ip)
            except:
                hostname = "N/A"
            
            active_devices.append({
                'IPAddress': ip,
                'Hostname': hostname
            })
            print(f"[+] Found active host: {ip}")
    except Exception as e:
        logging.error(f"Network scan error: {str(e)}")
        
    return active_devices

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Network Scanner')
    parser.add_argument('--monitor', action='store_true', help='Enable monitoring mode')
    parser.add_argument('--refresh', type=int, default=300, help='Refresh interval in seconds')
    parser.add_argument('--log-path', type=str, 
                       default=str(Path(__file__).parent.parent / "logs"),
                       help='Path to store device profiles')
    parser.add_argument('--username', type=str, help='Username for device authentication')
    parser.add_argument('--password', type=str, help='Password for device authentication')
    parser.add_argument('--ssh-port', type=int, default=22, help='SSH port for Linux systems')
    parser.add_argument('--winrm-port', type=int, default=5985, help='WinRM port for Windows systems')
    args = parser.parse_args()

    scanner = NetworkScanner(log_path=args.log_path, 
                           ssh_port=args.ssh_port, 
                           winrm_port=args.winrm_port)
    print("[*] Starting enhanced network scan...")
    
    network_range = scanner.get_network_range()
    active_devices = start_network_scan(network_range)
    
    device_profiles = []
    for device in active_devices:
        print(f"[*] Profiling device: {device['IPAddress']}...")
        profile = scanner.get_device_details(device['IPAddress'], args.username, args.password)
        device_profiles.append(profile)
        scanner.save_profile(profile)
        print(f"[+] Platform detected: {profile.platform}")
        print(f"[+] Accessibility: {'Yes' if profile.is_accessible else 'No'}")

    if args.monitor:
        win = DeviceMonitorWindow(device_profiles, args.refresh)
        win.connect("destroy", Gtk.main_quit)
        win.show_all()
        Gtk.main()

if __name__ == "__main__":
    main()