#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}Checking system requirements...${NC}"

# Detect OS
OS_TYPE="$(uname -s)"
# Linux
if [ "$OS_TYPE" == "Linux" ]; then
    if [ -f /etc/debian_version ]; then
        echo -e "${GREEN}Detected Debian/Ubuntu system.${NC}"
        echo "[*] Installing Nmap..."
        sudo apt update && sudo apt install -y nmap python3-pip
    elif [ -f /etc/redhat-release ]; then
        echo -e "${GREEN}Detected RHEL/CentOS system.${NC}"
        echo "[*] Installing Nmap..."
        sudo yum install -y nmap python3-pip
    else
        echo -e "${RED}Unsupported Linux distribution.${NC}"
        exit 1
    fi
# macOS
elif [ "$OS_TYPE" == "Darwin" ]; then
    echo -e "${GREEN}Detected macOS.${NC}"
    if ! command -v brew &> /dev/null; then
        echo -e "${RED}Homebrew not found. Please install Homebrew first.${NC}"
        exit 1
    fi
    echo "[*] Installing Nmap..."
    brew install nmap
else
    echo -e "${RED}Unsupported OS: $OS_TYPE${NC}"
    exit 1
fi

# Install Python dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

echo -e "${GREEN}Setup complete!${NC}"
echo "To run the scanner: python3 src/fast_scan.py <subnet>"
