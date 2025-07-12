#!/bin/bash
set -e

# System dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-venv \
    aircrack-ng hostapd dnsmasq nmap reaver \
    git build-essential libffi-dev libssl-dev \
    net-tools iproute2 \
    libpcap-dev \
    metasploit-framework

# Optional: install impacket for advanced SMB/NTLM features
sudo apt-get install -y impacket-scripts || true

# Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "\nAll dependencies installed."
echo "To start the AI Network Guardian, run:"
echo "  source venv/bin/activate && python3 app/guardian_main.py"
echo "\nWould you like to start the Guardian now? (y/n)"
read -r answer
if [[ $answer == "y" || $answer == "Y" ]]; then
    python3 app/guardian_main.py
else
    echo "Exiting. You can start the Guardian later with:"
    echo "  source venv/bin/activate && python3 app/guardian_main.py"
fi 