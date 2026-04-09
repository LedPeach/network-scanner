# Fast Network Service Scanner

A high-performance asynchronous network scanner that identifies open ports via Nmap and attempts to extract HTTP/HTTPS content using `httpx`.

## Features
- **Two-Stage Scanning**: Uses Nmap for rapid port discovery and Python Asyncio for high-speed HTTP probing.
- **Configurable**: Easily adjust concurrency, timeouts, and protocols in `src/fast_scan.py`.
- **Cross-Platform**: Automated setup for macOS and Linux (Ubuntu/Debian/RHEL).

## Installation

1. Clone the repository:
   ```bash
   git clone 
   cd network-scanner
