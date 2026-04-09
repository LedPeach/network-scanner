# Fast Network Service Scanner

A high-performance asynchronous network scanner that identifies open ports via Nmap and attempts to extract HTTP/HTTPS content using `httpx`.

## Features
- **Two-Stage Scanning**: Uses Nmap for rapid port discovery and Python Asyncio for high-speed HTTP probing.
- **Configurable**: Easily adjust concurrency, timeouts, and protocols in `src/fast_scan.py`.
- **Cross-Platform**: Automated setup for macOS and Linux (Ubuntu/Debian/RHEL).

## Installation

1. Clone the repository:
```
bash
git clone https://github.com/LedPeach/network-scanner.git
cd network-scanner
```

2. Run the setup script:
```
chmod +x setup.sh
./setup.sh
```
### Install python dependencies with python virtual environment
```
# If you wish to install a Python library with a virtual environment:  
python3 -m venv path/to/venv
source path/to/venv/bin/activate
python3 -m pip install xyz
```

## Usage
Run the scanner by providing a subnet:
```
python3 src/fast_scan.py 192.168.1.0/24
```

## Advanced Usage
You can override the default configuration via command line arguments:
```
# Increase concurrency to 500 and timeout to 5 seconds
python3 src/fast_scan.py 192.168.1.0/24 --concurrency 500 --timeout 5.0
```

## Output
Results are saved to scan_results.csv with the following columns:

- **address**: The IP of the device.
- **port**: The open port number.
- **curl_content**: A snippet of the HTTP response body.

## Disclaimer
**Use this tool only on networks you own or have explicit permission to scan. Unauthorized scanning is illegal.**
