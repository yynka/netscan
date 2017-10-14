#!/usr/bin/env python3

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gdk
import json
import subprocess
import threading
import os
import time
from datetime import datetime
import netifaces
import nmap
import psutil
import socket
from pathlib import Path
import paramiko
from pysnmp.hlapi import *
import winrm
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict
import smbclient

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
    def __init__(self, log_path=str(Path.home() / "DeviceProfiles")):
        self.log_path = log_path
        Path(log_path).mkdir(parents=True, exist_ok=True)
        self.nm = nmap.PortScanner()
        
        # Setup logging
        logging.basicConfig(
            filename=f"{log_path}/scanner.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def get_network_range(self):
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        default_interface = gateways['default'][netifaces.AF_INET][1]
        
        interface_info = netifaces.ifaddresses(default_interface)[netifaces.AF_INET][0]
        network = f"{interface_info['addr']}/{interface_info['netmask']}"
        return network

    def get_mac_vendor(self, mac):
        try:
            response = subprocess.check_output(['curl', '-s', f'https://api.macvendors.com/{mac}'])
            return response.decode().strip()
        except:
            return "Unknown"

    def get_snmp_info(self, ip):
        try:
            iterator = getNext(
                SnmpEngine(),
                CommunityData('public', mpModel=0),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication or errorStatus:
                return None
                
            return str(varBinds[0][1])
        except:
            return None

    def get_windows_info(self, ip, username=None, password=None):
        try:
            if username and password:
                # Try WinRM first
                session = winrm.Session(
                    f'http://{ip}:5985/wsman',
                    auth=(username, password)
                )
                result = session.run_ps('Get-WmiObject -Class Win32_OperatingSystem')
                if result.status_code == 0:
                    return json.loads(result.std_out)
            
            # Fallback to SMB
            smbclient.register_session(ip, username=username, password=password)
            shares = smbclient.scandir('\\\\' + ip)
            return {'shares': [share.name for share in shares]}
            
        except:
            return None

    def get_linux_info(self, ip, username=None, password=None):
        try:
            if username and password:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=5)
                
                # Get system info
                stdin, stdout, stderr = ssh.exec_command('uname -a; who; df -h')
                system_info = stdout.read().decode()
                
                # Get service info
                stdin, stdout, stderr = ssh.exec_command('systemctl list-units --type=service --state=running')
                services = stdout.read().decode()
                
                ssh.close()
                return {
                    'system_info': system_info,
                    'services': services
                }
        except:
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
            
            # OS detection using nmap
            self.nm.scan(ip, arguments='-O')
            if 'osmatch' in self.nm[ip]:
                profile.os_version = self.nm[ip]['osmatch'][0]['name']
            
            # Service detection
            self.nm.scan(ip, arguments='-sV')
            if 'tcp' in self.nm[ip]:
                for port, data in self.nm[ip]['tcp'].items():
                    if data['state'] == 'open':
                        service = ServiceInfo(
                            name=data['name'],
                            display_name=data['product'],
                            status='running',
                            start_type='automatic'
                        )
                        profile.services.append(service)
            
            # Try SNMP
            snmp_info = self.get_snmp_info(ip)
            if snmp_info:
                profile.computer_name = snmp_info.split()[0]
            
            # Try Windows/Linux specific info
            windows_info = self.get_windows_info(ip, username, password)
            if windows_info:
                if 'shares' in windows_info:
                    for share in windows_info['shares']:
                        share_info = ShareInfo(
                            name=share,
                            path=f"\\\\{ip}\\{share}",
                            description="Network Share"
                        )
                        profile.shared_resources.append(share_info)
            else:
                linux_info = self.get_linux_info(ip, username, password)
                if linux_info:
                    profile.os_version = linux_info['system_info'].split('\n')[0]
                    profile.last_user = linux_info['system_info'].split('\n')[1].split()[0]
            
            # Network interfaces
            profile.history.append(HistoryEntry(
                timestamp=datetime.now().isoformat(),
                type='NetworkAdapter',
                data={
                    'interfaces': self.nm[ip].get('interfaces', []),
                    'routes': netifaces.gateways()
                }
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
        self.set_default_size(800, 600)
        self.devices = devices
        self.refresh_interval = refresh_interval

        # Main layout with header bar
        header = Gtk.HeaderBar()
        header.set_show_close_button(True)
        header.props.title = "Network Device Monitor"
        self.set_titlebar(header)

        # Add refresh button
        refresh_button = Gtk.Button()
        refresh_button.add(Gtk.Image.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON))
        refresh_button.connect("clicked", self.on_refresh_clicked)
        header.pack_end(refresh_button)

        # Main container
        self.grid = Gtk.Grid()
        self.add(self.grid)

        # Device list (left pane)
        self.device_list = Gtk.ListBox()
        self.device_list.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.device_list.connect("row-selected", self.on_device_selected)
        
        scrolled_list = Gtk.ScrolledWindow()
        scrolled_list.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled_list.add(self.device_list)
        
        # Add devices to list
        for device in devices:
            row = Gtk.ListBoxRow()
            hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            row.add(hbox)
            
            label = Gtk.Label(label=f"{device.hostname} ({device.ip_address})")
            label.set_alignment(0, 0.5)
            hbox.pack_start(label, True, True, 0)
            
            self.device_list.add(row)

        # Details pane (right)
        self.details_notebook = Gtk.Notebook()
        
        # Info page
        self.info_grid = Gtk.Grid()
        self.info_grid.set_column_spacing(12)
        self.info_grid.set_row_spacing(6)
        self.details_notebook.append_page(
            self.info_grid, 
            Gtk.Label(label="Information")
        )
        
        # Services page
        self.services_store = Gtk.ListStore(str, str, str, str)
        self.services_view = Gtk.TreeView(model=self.services_store)
        for i, title in enumerate(["Name", "Display Name", "Status", "Start Type"]):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            self.services_view.append_column(column)
        
        services_scroll = Gtk.ScrolledWindow()
        services_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        services_scroll.add(self.services_view)
        self.details_notebook.append_page(services_scroll, Gtk.Label(label="Services"))
        
        # History page
        self.history_store = Gtk.ListStore(str, str, str)
        self.history_view = Gtk.TreeView(model=self.history_store)
        for i, title in enumerate(["Timestamp", "Type", "Data"]):
            column = Gtk.TreeViewColumn(title, Gtk.CellRendererText(), text=i)
            self.history_view.append_column(column)
        
        history_scroll = Gtk.ScrolledWindow()
        history_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        history_scroll.add(self.history_view)
        self.details_notebook.append_page(history_scroll, Gtk.Label(label="History"))

        # Add panes to grid
        self.grid.attach(scrolled_list, 0, 0, 1, 1)
        self.grid.attach(self.details_notebook, 1, 0, 2, 1)

        # Make details pane expand
        scrolled_list.set_size_request(250, -1)
        self.details_notebook.set_hexpand(True)
        self.details_notebook.set_vexpand(True)

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
        self.history_store.clear()

        # Update info page
        info_items = [
            ("Computer Name", device.computer_name),
            ("IP Address", device.ip_address),
            ("MAC Address", device.mac_address),
            ("Vendor", device.vendor),
            ("OS Version", device.os_version),
            ("Last User", device.last_user),
            ("First Seen", device.first_seen),
            ("Last Seen", device.last_seen)
        ]

        for i, (label, value) in enumerate(info_items):
            label_widget = Gtk.Label(label=f"{label}:")
            label_widget.set_alignment(1, 0.5)
            value_widget = Gtk.Label(label=str(value))
            value_widget.set_alignment(0, 0.5)
            
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

        # Update history page
        for entry in sorted(device.history, key=lambda x: x.timestamp, reverse=True):
            self.history_store.append([
                entry.timestamp,
                entry.type,
                json.dumps(entry.data)
            ])

    def refresh_display(self):
        selected_row = self.device_list.get_selected_row()
        if selected_row is not None:
            self.update_details(selected_row.get_index())
        return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Network Scanner')
    parser.add_argument('--monitor', action='store_true', help='Enable monitoring mode')
    parser.add_argument('--refresh', type=int, default=300, help='Refresh interval in seconds')
    parser.add_argument('--log-path', type=str, default=str(Path.home() / "DeviceProfiles"),
                      help='Path to store device profiles')
    parser.add_argument('--username', type=str, help='Username for device authentication')
    parser.add_argument('--password', type=str, help='Password for device authentication')
    args = parser.parse_args()

    scanner = NetworkScanner(log_path=args.log_path)
    print("[*] Starting enhanced network scan...")
    
    active_ips = scanner.nm.scan(hosts=scanner.get_network_range(), arguments='-sn')['scan'].keys()
    device_profiles = []

    for ip in active_ips:
        print(f"[*] Profiling device: {ip}...")
        profile = scanner.get_device_details(ip, args.username, args.password)
        device_profiles.append(profile)
        scanner.save_profile(profile)

    if args.monitor:
        win = DeviceMonitorWindow(device_profiles, args.refresh)
        win.connect("destroy", Gtk.main_quit)
        win.show_all()
        Gtk.main()

if __name__ == "__main__":
    main()