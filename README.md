# <p><a href="#options"><img src="./assets/scan.png" alt="Network Scanner" width="120" style="vertical-align: middle; margin-right: 10px;"/></a> <span style="vertical-align: middle;">NETSCAN</span> <a href="#windows"><img src="./assets/windows.png" alt="Windows" width="120" style="vertical-align: middle; margin: 0 30px;"/></a> <a href="#macos"><img src="./assets/macos.png" alt="macOS" width="120" style="vertical-align: middle; margin: 0 30px;"/></a> <a href="#linux"><img src="./assets/linux.png" alt="Linux" width="120" style="vertical-align: middle;"/></a></p>

<span style="font-size: 1.2em; line-height: 1.6em;">

- 🔍 **Real-time device discovery and profiling:** Automatically detect and profile devices on the network in real-time.
- 📊 **Service monitoring and status tracking:** Monitor services running on each device and track their status.
- 🔗 **Network resource sharing detection:** Identify shared resources like files and printers on the network.
- 🖥️ **GTK-based monitoring interface:** Graphical user interface for monitoring built with the GTK toolkit.
- 📱 **Support for Windows, macOS, and Linux:** Run the scanner on the most popular desktop operating systems.
</span>

---

## Windows <a id="windows"></a> <img src="./assets/windows.png" alt="Windows" width="120" align="right"/>

### 1. Install system dependencies:
```bash
# Download and install Python 3 from python.org
https://www.python.org/ftp/python/3.13.1/python-3.13.1-amd64.exe
```
- Make sure to check the "Add Python to PATH" option during installation

### 2. Install netscan script:
```powershell
mkdir netscan && cd netscan
curl https://raw.githubusercontent.com/yynka/netscan/main/windows.ps1 -o windows.ps1
```

### 3. Set up virtual environment:
```powershell
python -m venv ns
.\ns\Scripts\Activate.ps1
```
- `venv`: isolates project-specific dependencies.

### 4. Install dependencies using pip:
```powershell
pip install netifaces python-nmap psutil paramiko dnspython pygobject
```
- `netifaces`: Provides access to network interfaces.
- `python-nmap`: Python bindings for Nmap.
- `psutil`: System monitoring and process utilities.
- `paramiko`: SSH connections and remote command execution.
- `dnspython`: Device name resolution.
- `pygobject`: Python bindings for GTK.

### 5. Run netscan/windows:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows.ps1 --username YOUR_USERNAME --password YOUR_PASSWORD
```
- Replace `YOUR_USERNAME` and `YOUR_PASSWORD` with valid authentication details.
- This script will create a `logs` directory in the `netscan` folder to save device profiles as JSON files.

## macOS <a id="macos"></a> <img src="./assets/macos.png" alt="macOS" width="120" align="right"/>

### 1. Install system dependencies:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install pygobject3 gtk+3 nmap python3
```
- `pygobject3`: Provides the 'gi' module for GTK bindings.
- `gtk+3`: Required for the GTK3 GUI.
- `nmap`: Command-line tool used by the python-nmap library.
- `python3`: Installs the latest Python version.

### 2. Install netscan script:
```bash
mkdir netscan && cd netscan
curl https://raw.githubusercontent.com/yynka/netscan/macos.py -o macos.py
```

### 3. Set up virtual environment:
```bash
python3 -m venv ns
source ns/bin/activate
```
- `venv`: isolates project-specific dependencies.

### 4. Install dependencies using pip:
```bash
pip3 install netifaces python-nmap psutil paramiko dnspython
```
- `netifaces`: Provides access to network interfaces.
- `python-nmap`: Python bindings for Nmap.
- `psutil`: System monitoring and process utilities.
- `paramiko`: SSH connections and remote command execution.
- `dnspython`: Device name resolution.

### 5. Verify GTK installation:
```bash
brew link pygobject3
```
- Ensures PyGObject is symlinked into system path so Python can find it.

### 6. Run netscan/macos:
```bash
sudo python3 macos.py --username YOUR_USERNAME --password YOUR_PASSWORD
```
- Replace `YOUR_USERNAME` and `YOUR_PASSWORD` with valid authentication details.
- `sudo`: Required for privileged network scanning.
- This script will create a `logs` directory in the `netscan` folder to save device profiles as JSON files.

## Linux <a id="linux"></a> <img src="./assets/linux.png" alt="Linux" width="120" align="right"/>

### 1. Install system dependencies:
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nmap gir1.2-gtk-3.0 libcanberra-gtk-module curl
```
- `python3, python3-venv, python3-pip`: Python environment and pip.
- `nmap`: Command-line tool for scanning.
- `gir1.2-gtk-3.0`: GTK bindings.
- `curl`: Used for vendor lookups via web API.

### 2. Install netscan script:
```bash
mkdir netscan && cd netscan
curl https://raw.githubusercontent.com/yynka/netscan/main/linux.py -o linux.py
```

### 3. Set up virtual environment:
```bash
python3 -m venv ns
source ns/bin/activate
```
- `venv`: isolates project-specific dependencies.

### 4. Install dependencies using pip:
```bash
pip install netifaces python-nmap psutil paramiko dnspython pygobject
```
- `netifaces`: Provides access to network interfaces.
- `python-nmap`: Python bindings for Nmap.
- `psutil`: System monitoring and process utilities.
- `paramiko`: SSH connections and remote command execution.
- `dnspython`: Device name resolution.
- `pygobject`: Python bindings for GTK3.

### 5. Run netscan/linux:
```bash
sudo python3 linux.py --username YOUR_USERNAME --password YOUR_PASSWORD
```
- Replace `YOUR_USERNAME` and `YOUR_PASSWORD` with valid authentication details.
- `sudo`: Required for privileged network scanning.
- This script will create a `logs` directory in the `netscan` folder to save device profiles as JSON files.

## Options <a href="#top"><img src="./assets/scan.png" alt="Options" width="120" align="right"/></a>
```bash
--monitor        GUI monitoring mode
--refresh N      Refresh interval (seconds): How often to rescan network
--log-path PATH  Custom log directory: Specify where to store logs 
--username USER  Authentication username: Login user for devices requiring auth
--password PASS  Authentication password: Login password for devices requiring auth
--ssh-port N     SSH port (default: 22): Port number for SSH connections
--winrm-port N   WinRM port (default: 5985): Port number for WinRM on Windows
```

[MIT License](LICENSE)