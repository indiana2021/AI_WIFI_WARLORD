# AI Network Guardian Installation

To run `network_guardian_main.py` on the M5Stack LLM630 Compute Kit (Ubuntu 22.04), you’ll need to:

1.  **Add the StackFlow APT repository** and install core LLM packages (`lib-llm`, `llm-sys`, `llm-llm`).
2.  **Ensure Python 3 (≥ 3.10) is installed**, along with development tools (`python3-pip`, `python3-venv`, `libzmq3-dev`).
3.  **Create a virtual environment** and install the required Python libraries (`PyZMQ`, `Flask`).
4.  **Install the Wi-Fi and network utilities** (`aircrack-ng`, `wireless-tools`, `network-manager`, `nmap`) needed for network scanning, security auditing, and internal network analysis.

---

## APT Repository & Core AI Packages

### Configure the StackFlow Repository
First, add the M5Stack StackFlow repository and its GPG key, then update `apt`:

```bash
wget -qO /etc/apt/keyrings/StackFlow.gpg \
  https://repo.llm.m5stack.com/m5stack-apt-repo/key/StackFlow.gpg
echo 'deb [arch=arm64 signed-by=/etc/apt/keyrings/StackFlow.gpg] \
  https://repo.llm.m5stack.com/m5stack-apt-repo jammy ax630c' \
  > /etc/apt/sources.list.d/StackFlow.list
sudo apt update
```
*(Source: docs.m5stack.com)*

### Install Core StackFlow AI Packages
Install the runtime and LLM functional units:

```bash
sudo apt install -y lib-llm llm-sys llm-llm
```
These packages provide the on-device LLM inference engine (StackFlow core).
*(Source: docs.m5stack.com)*

---

## Python Environment

### System Packages for Python & ZMQ
Ensure Python 3 is present (Ubuntu 22.04 ships with Python 3.10; install if necessary) and install development tools:

```bash
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y libzmq3-dev
```
*   **Python 3 & pip:** Core interpreter and package manager.
*   **python3-venv:** Virtual environment support.
*   **libzmq3-dev:** C headers for ZeroMQ required by PyZMQ.

### Create Virtual Environment & Install Python Libraries
Create and activate a virtual environment:

```bash
python3 -m venv ~/guardian-venv
source ~/guardian-venv/bin/activate
```

Upgrade pip and install the required Python modules:

```bash
pip install --upgrade pip
pip install pyzmq flask
```
*   **PyZMQ:** ZMQ bindings for Python.
*   **Flask:** Lightweight web framework for the dashboard.

---

## Network & Wi-Fi Analysis Tools

Install the command-line tools your script invokes for Wi-Fi scanning, security auditing, and LAN analysis:

```bash
sudo apt install -y aircrack-ng wireless-tools network-manager nmap
```
*   **aircrack-ng:** Packet capture and WPA security analysis suite.
*   **wireless-tools:** Interface configuration utilities (e.g., `iwconfig`).
*   **network-manager:** Manages switching between managed/monitor modes via `nmcli`.
*   **nmap:** Network discovery and internal network scanning.

---

## Running the Guardian

With these tools installed on your LLM630 device, you can place your `network_guardian_main.py` (and its `assets/`) on the file system, adjust `WIFI_AUDIT_INTERFACE` to the correct adapter (e.g., `wlan1` for a USB dongle), then run under `sudo` within your virtual environment:

```bash
source ~/guardian-venv/bin/activate
sudo python3 network_guardian_main.py
