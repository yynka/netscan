# <p><a href="#options"><img src="./assets/scan.png" alt="Network Scanner" width="120" style="vertical-align: middle; margin-right: 10px;"/></a> <span style="vertical-align: middle;">Network Scanner</span> <a href="#windows"><img src="./assets/windows.png" alt="Windows" width="120" style="vertical-align: middle; margin: 0 30px;"/></a> <a href="#macos"><img src="./assets/macos.png" alt="macOS" width="120" style="vertical-align: middle; margin: 0 30px;"/></a> <a href="#linux"><img src="./assets/linux.png" alt="Linux" width="120" style="vertical-align: middle;"/></a></p>

<span style="font-size: 1.2em; line-height: 1.6em;">

- 🔍 **Real-time device discovery and profiling:** Automatically detect and profile devices on the network in real-time.
- 📊 **Service monitoring and status tracking:** Monitor services running on each device and track their status.
- 🔗 **Network resource sharing detection:** Identify shared resources like files and printers on the network.
- 🖥️ **GTK-based monitoring interface:** Graphical user interface for monitoring built with the GTK toolkit.
- 📱 **Support for Windows, macOS, and Linux:** Run the scanner on the most popular desktop operating systems.
</span>

## Windows <img src="./assets/windows.png" alt="Windows" width="120" align="right"/>
```powershell
# Download Windows files
mkdir netscan && cd netscan
curl https://raw.githubusercontent.com/yynka/netscan/main/windows/run.ps1 -o run.ps1
curl https://raw.githubusercontent.com/yynka/netscan/main/windows/requirements.ps1 -o requirements.ps1

# Setup and run
python -m venv ns
.\ns\Scripts\Activate.ps1
.\requirements.ps1
.\run.ps1 --monitor
```

## macOS <img src="./assets/macos.png" alt="macOS" width="120" align="right"/>
```bash
# Download macOS files
mkdir netscan && cd netscan
curl https://raw.githubusercontent.com/yynka/netscan/main/macos/run.py -o run.py
curl https://raw.githubusercontent.com/yynka/netscan/main/macos/requirements.txt -o requirements.txt

# Setup and run
python3 -m venv ns
source ns/bin/activate
brew install $(grep "^brew" requirements.txt | cut -d' ' -f2-)
pip3 install -r requirements.txt
python3 run.py --monitor
```

## Linux <img src="./assets/linux.png" alt="Linux" width="120" align="right"/>
```bash
# Download Linux files
mkdir netscan && cd netscan
curl https://raw.githubusercontent.com/yynka/netscan/main/linux/run.py -o run.py
curl https://raw.githubusercontent.com/yynka/netscan/main/linux/requirements.txt -o requirements.txt

# Setup and run
python3 -m venv ns
source ns/bin/activate
sudo apt-get update && sudo apt-get install -y $(grep "^python3-" requirements.txt | tr '\n' ' ')
pip3 install -r requirements.txt
python3 run.py --monitor
```

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