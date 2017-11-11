#!/usr/bin/env python3

import sys
print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")

try:
    import netifaces
    print("netifaces imported successfully")
except ImportError as e:
    print(f"Failed to import netifaces: {e}")

try:
    import nmap
    print("nmap imported successfully")
except ImportError as e:
    print(f"Failed to import nmap: {e}")

try:
    import psutil
    print("psutil imported successfully")
except ImportError as e:
    print(f"Failed to import psutil: {e}")

try:
    import paramiko
    print("paramiko imported successfully")
except ImportError as e:
    print(f"Failed to import paramiko: {e}")