"""
Configuration file for AI Network Guardian
Centralizes all constants, settings, and configuration values
"""

import os
from pathlib import Path

# ============================================================================
# PATHS & DIRECTORIES
# ============================================================================

# Base paths
BASE_DIR = Path(__file__).parent.parent
APP_DIR = BASE_DIR / "app"
ASSETS_DIR = BASE_DIR / "assets"
FIRMWARE_DIR = BASE_DIR / "firmware"

# Logging paths
SD_CARD_LOG_PATH = os.environ.get("SD_CARD_LOG_PATH", "/mnt/sdcard/logs")
STATE_FILE_PATH = os.path.join(SD_CARD_LOG_PATH, "guardian_state.json")

# ============================================================================
# NETWORK & INTERFACE SETTINGS
# ============================================================================

# Default network interface
DEFAULT_INTERFACE = os.environ.get("DEFAULT_INTERFACE", "wlan0")
WIFI_AUDIT_INTERFACE = os.environ.get("WIFI_AUDIT_INTERFACE", "wlan0")
LAN_INTERFACE = os.environ.get("LAN_INTERFACE", "eth0")

# Network discovery settings
NMAP_SCAN_TIMEOUT = int(os.environ.get("NMAP_SCAN_TIMEOUT", "300"))
NIKTO_SCAN_TIMEOUT = int(os.environ.get("NIKTO_SCAN_TIMEOUT", "120"))
HYDRA_TIMEOUT = int(os.environ.get("HYDRA_TIMEOUT", "300"))
WPS_AUDIT_TIMEOUT = int(os.environ.get("WPS_AUDIT_TIMEOUT", "600"))

# SSH settings
SSH_CONNECT_TIMEOUT = int(os.environ.get("SSH_CONNECT_TIMEOUT", "5"))
SSH_LOGIN_TIMEOUT = int(os.environ.get("SSH_LOGIN_TIMEOUT", "5"))

# Threshold constants
MAX_SSH_ATTEMPTS_PER_HOST = int(os.environ.get("MAX_SSH_ATTEMPTS_PER_HOST", "5"))
MAX_FAILED_ATTEMPTS_BEFORE_SKIP = int(os.environ.get("MAX_FAILED_ATTEMPTS_BEFORE_SKIP", "10"))

# AI model path
AI_MODEL_PATH = os.environ.get("AI_MODEL_PATH", "assets/")

# ============================================================================
# LLM & AI SETTINGS
# ============================================================================

# LLM configuration
LLM_ZMQ_ENDPOINT = os.environ.get("LLM_ZMQ_ENDPOINT", "tcp://localhost:5555")
DEFAULT_LLM_MODEL = os.environ.get("DEFAULT_LLM_MODEL", "qwen2.5-0.5B-int8-ax630c")
DEFAULT_LLM_PROMPT = os.environ.get("DEFAULT_LLM_PROMPT", 
    "You are GuardianGPT, a cybersecurity AI. Analyze network data and provide security recommendations. Respond ONLY with a single, valid JSON object.")

# ============================================================================
# WEB DASHBOARD SETTINGS
# ============================================================================

# Flask web server settings
WEB_HOST = os.environ.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("WEB_PORT", "8081"))
WEB_DEBUG = os.environ.get("WEB_DEBUG", "False").lower() == "true"

# Dashboard settings
DASHBOARD_UPDATE_INTERVAL = int(os.environ.get("DASHBOARD_UPDATE_INTERVAL", "2000"))  # milliseconds
LOG_RETENTION_COUNT = int(os.environ.get("LOG_RETENTION_COUNT", "100"))

# ============================================================================
# SECURITY & AUTHENTICATION
# ============================================================================

# Metasploit RPC settings
MSF_RPC_PASSWORD = os.environ.get("MSF_RPC_PASSWORD", "msfadmin")

# SSH audit settings
SSH_DEFAULT_TIMEOUT = float(os.environ.get("SSH_DEFAULT_TIMEOUT", "5.0"))
SSH_MAX_WORKERS = int(os.environ.get("SSH_MAX_WORKERS", "10"))

# ============================================================================
# TOOL CONFIGURATIONS
# ============================================================================

# Tool timeout configurations
TOOL_TIMEOUTS = {
    'bettercap': 120,
    'ettercap': 120,
    'dnsspoof': 60,
    'dnschef': 60,
    'tcpdump': 60,
    'tshark': 60,
    'arp-scan': 60,
    'arpwatch': 60,
    'netdiscover': 60,
    'wifite': 300,
    'hcxdumptool': 300,
    'hcxpcapngtool': 120,
    'evilginx2': 60,
    'setoolkit': 60,
    'suricata': 120,
    'nethogs': 60,
    'iftop': 60,
    'iptraf': 60,
    'whois': 30,
    'dig': 30,
    'nslookup': 30
}

# Package mapping for tool installation
PACKAGE_MAPPINGS = {
    # WiFi tools
    'reaver': 'reaver',
    'hostapd': 'hostapd',
    'dnsmasq': 'dnsmasq',
    
    # Network analysis tools
    'arpspoof': 'dsniff',
    'nikto': 'nikto',
    'hydra': 'hydra',
    'smbclient': 'smbclient',
    'dhcpd': 'isc-dhcp-server'
}

# ============================================================================
# LOGGING & MONITORING
# ============================================================================

# Log file settings
LOG_MAX_SIZE = int(os.environ.get("LOG_MAX_SIZE", "10*1024*1024"))  # 10MB
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))

# Status update settings
STATUS_UPDATE_INTERVAL = int(os.environ.get("STATUS_UPDATE_INTERVAL", "5"))  # seconds

# ============================================================================
# SIMULATION SETTINGS
# ============================================================================

# Rogue AP simulation
ROGUE_AP_IP_RANGE = os.environ.get("ROGUE_AP_IP_RANGE", "10.0.0.0/24")
ROGUE_AP_GATEWAY = os.environ.get("ROGUE_AP_GATEWAY", "10.0.0.1")

# ARP poisoning simulation
ARP_POISONING_DURATION = int(os.environ.get("ARP_POISONING_DURATION", "30"))  # seconds

# ============================================================================
# DEVELOPMENT & DEBUG SETTINGS
# ============================================================================

# Debug mode
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() == "true"

# Test settings
TEST_TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "30"))
TEST_RETRY_COUNT = int(os.environ.get("TEST_RETRY_COUNT", "3"))

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check required directories
    if not os.path.exists(SD_CARD_LOG_PATH):
        try:
            os.makedirs(SD_CARD_LOG_PATH, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create SD card log path: {e}")
    
    # Validate timeouts
    for tool, timeout in TOOL_TIMEOUTS.items():
        if timeout <= 0:
            errors.append(f"Invalid timeout for {tool}: {timeout}")
    
    # Validate web settings
    if not (1 <= WEB_PORT <= 65535):
        errors.append(f"Invalid web port: {WEB_PORT}")
    
    if errors:
        raise ValueError(f"Configuration validation failed:\n" + "\n".join(errors))
    
    return True

# ============================================================================
# ENVIRONMENT-SPECIFIC OVERRIDES
# ============================================================================

def load_environment_overrides():
    """Load environment-specific configuration overrides"""
    env = os.environ.get("GUARDIAN_ENV", "production")
    
    if env == "development":
        global DEBUG_MODE, WEB_DEBUG
        DEBUG_MODE = True
        WEB_DEBUG = True
    
    elif env == "testing":
        global SD_CARD_LOG_PATH, STATE_FILE_PATH
        SD_CARD_LOG_PATH = "/tmp/guardian_test_logs"
        STATE_FILE_PATH = "/tmp/guardian_test_state.json"

# Initialize configuration
load_environment_overrides() 