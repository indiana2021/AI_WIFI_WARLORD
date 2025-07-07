Summary
To run wifi_warlord_main.py on the M5Stack LLM630 Compute Kit (Ubuntu 22.04), you’ll need to:

Add the StackFlow APT repository and install core LLM packages (lib-llm, llm-sys, llm-llm).

Ensure Python 3 (≥ 3.10), and install development tools (python3-pip, python3-venv, libzmq3-dev).

Create a virtual environment and install the Python libraries PyZMQ and Flask.

Install the Wi-Fi and network utilities (aircrack-ng, wireless-tools, network-manager, and nmap) needed for scanning, handshake capture, and post-exploitation tasks.

APT Repository & Core AI Packages
Configure the StackFlow Repository
First, add the M5Stack StackFlow repository and its GPG key, then update apt:


wget -qO /etc/apt/keyrings/StackFlow.gpg \
  https://repo.llm.m5stack.com/m5stack-apt-repo/key/StackFlow.gpg
echo 'deb [arch=arm64 signed-by=/etc/apt/keyrings/StackFlow.gpg] \
  https://repo.llm.m5stack.com/m5stack-apt-repo jammy ax630c' \
  > /etc/apt/sources.list.d/StackFlow.list
sudo apt update
docs.m5stack.com

Install Core StackFlow AI Packages
Install the runtime and LLM functional units:


sudo apt install -y lib-llm llm-sys llm-llm
These packages provide the on-device LLM inference engine (StackFlow core). 
docs.m5stack.com

Python Environment
System Packages for Python & ZMQ
Ensure Python 3 is present (Ubuntu 22.04 ships with Python 3.10; install if necessary) and install development tools:


sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y libzmq3-dev
Python 3 & pip: core interpreter and package manager 
digitalocean.com

python3-venv: virtual environment support 
digitalocean.com

libzmq3-dev: C headers for ZeroMQ required by PyZMQ 
askubuntu.com

Create Virtual Environment & Install Python Libraries
Create and activate a venv:


python3 -m venv ~/warlord-venv
source ~/warlord-venv/bin/activate
Upgrade pip and install the required Python modules:


pip install --upgrade pip
pip install pyzmq flask
PyZMQ: ZMQ bindings for Python 
pypi.org
askubuntu.com

Flask: lightweight web framework for the dashboard 
virtono.com

Network & Wi-Fi Pen-Test Tools
Install the command-line tools your script invokes for Wi-Fi scanning, handshake capture, and LAN reconnaissance:


sudo apt install -y aircrack-ng wireless-tools network-manager nmap
aircrack-ng: packet capture, deauth, and WPA cracking suite 
launchpad.net

wireless-tools: interface configuration utilities (e.g., iwconfig) 
launchpad.net

network-manager: manages switching between managed/monitor modes via nmcli 
help.ubuntu.com

nmap: network discovery and post-exploitation scanning 
phoenixnap.com

With these installed on your LLM630 device, you can place your wifi_warlord_main.py (and its assets/) on the file system, adjust WIFI_ATTACK_INTERFACE to the correct adapter (e.g., wlan1 for a USB dongle), then run under sudo within your venv:


source ~/warlord-venv/bin/activate
sudo python3 wifi_warlord_main.py