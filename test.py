#!/usr/bin/env python3

import sys
import platform

print("=" * 50)
print("NETSCAN DEPENDENCY TEST")
print("=" * 50)
print(f"Python version: {sys.version}")
print(f"Platform: {platform.system()} {platform.release()}")
print(f"Architecture: {platform.machine()}")
print("=" * 50)

# Test all dependencies from requirements.txt
dependencies = [
    ('netifaces', 'Network interface detection'),
    ('nmap', 'Network scanning via python-nmap'),
    ('psutil', 'System and process information'),
    ('paramiko', 'SSH client for remote access'),
    ('winrm', 'Windows Remote Management (pywinrm)')
]

passed = 0
failed = 0

for module_name, description in dependencies:
    try:
        if module_name == 'nmap':
            import nmap
            # Test that nmap scanner can be instantiated
            nm = nmap.PortScanner()
            print(f"✓ {module_name:<12} - {description}")
        elif module_name == 'winrm':
            import winrm
            print(f"✓ {module_name:<12} - {description}")
        else:
            __import__(module_name)
            print(f"✓ {module_name:<12} - {description}")
        passed += 1
    except ImportError as e:
        print(f"✗ {module_name:<12} - {description} (FAILED: {e})")
        failed += 1
    except Exception as e:
        print(f"? {module_name:<12} - {description} (WARNING: {e})")
        passed += 1  # Still count as passed since import worked

print("=" * 50)
print(f"RESULTS: {passed} passed, {failed} failed")

if failed == 0:
    print("🎉 All dependencies are working correctly!")
    print("You can now run the network scanner scripts.")
else:
    print("❌ Some dependencies failed to import.")
    print("Please install missing dependencies with: pip install -r requirements.txt")
    
print("=" * 50)