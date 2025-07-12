# AI Network Guardian

An advanced AI-powered network security auditing system that leverages on-device Large Language Models (LLMs) to autonomously identify and assess network vulnerabilities.

## 🚀 Recent Updates

**✅ All Critical Bugs Fixed (Latest Update)**
- Fixed class definition order issues
- Resolved Windows compatibility problems
- Fixed subprocess return type errors
- Eliminated null pointer dereferences
- Improved error handling and type safety
- Centralized configuration management
- Updated dependencies with version constraints

## 🎯 Features

### AI-Powered Security Analysis
- **Autonomous Decision Making**: Uses on-device LLM (StackFlow framework) for intelligent security decisions
- **WiFi Security Auditing**: Comprehensive WiFi network analysis including WPA2, WPS, and rogue AP detection
- **Network Vulnerability Scanning**: Automated discovery of hosts, services, and security weaknesses
- **Credential Strength Testing**: AI-driven password analysis and SSH credential auditing

### Advanced Network Tools
- **WiFi Tools**: aircrack-ng, reaver, hostapd, dnsmasq
- **Network Analysis**: nmap, masscan, arp-scan, netdiscover
- **MITM Simulation**: bettercap, ettercap, arpspoof
- **Vulnerability Scanning**: nikto, hydra, smbclient
- **Traffic Analysis**: tcpdump, tshark, suricata

### Web Dashboard
- **Real-time Monitoring**: Live status updates and log streaming
- **Interactive Controls**: Start/stop AI Guardian operations
- **Vulnerability Reports**: Detailed findings and remediation recommendations
- **Network Visualization**: Host discovery and service mapping

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Root/Administrator privileges (for network operations)
- Required system tools (see requirements below)

### Quick Start
```bash
# Clone the repository
git clone <repository-url>
cd AI_WIFI_WARLORD

# Install Python dependencies
pip install -r requirements.txt

# Install system tools (Linux)
sudo apt-get update
sudo apt-get install -y aircrack-ng reaver hostapd dnsmasq nmap masscan nikto hydra smbclient bettercap ettercap tcpdump tshark suricata

# Run the AI Network Guardian
sudo python app/guardian_main.py
```

### System Requirements
- **OS**: Linux (primary), Windows (limited support)
- **Network**: WiFi and Ethernet interfaces
- **Storage**: SD card or writable storage for logs
- **Memory**: 2GB+ RAM recommended
- **LLM**: StackFlow framework with AX630C or compatible model

## 📋 Configuration

### Environment Variables
```bash
export GUARDIAN_CONFIG="/path/to/config.json"
export GUARDIAN_LOG_PATH="/mnt/sdcard/logs"
export GUARDIAN_WIFI_IFACE="wlan0"
export GUARDIAN_LAN_IFACE="eth0"
export LLM_ZMQ_ENDPOINT="tcp://localhost:5555"
```

### Configuration File
Create `config.json` in the project root:
```json
{
  "log_path": "/mnt/sdcard/logs",
  "wifi_interface": "wlan0",
  "lan_interface": "eth0",
  "web_host": "0.0.0.0",
  "web_port": 8081
}
```

## 🔧 Usage

### Starting the System
```bash
# Run with default configuration
sudo python app/guardian_main.py

# Run with custom config
export GUARDIAN_CONFIG="/path/to/config.json"
sudo python app/guardian_main.py
```

### Web Dashboard
Access the dashboard at `http://localhost:8081`

- **Status**: Current system status and phase
- **Controls**: Start/stop AI Guardian operations
- **Logs**: Real-time log streaming
- **Results**: Vulnerability findings and network analysis

### AI Guardian Operations
1. **WiFi Scanning**: Automatically discovers nearby networks
2. **Security Assessment**: Analyzes network security posture
3. **Vulnerability Testing**: Identifies weak passwords and configurations
4. **Report Generation**: Provides actionable security recommendations

## 🏗️ Architecture

### Core Components
- **AIAnalysisOrchestrator**: Central AI decision-making engine
- **WiFiSecurityModule**: WiFi network analysis and auditing
- **LanAnalyzer**: Internal network vulnerability assessment
- **PasswordStrengthAnalyzer**: AI-driven credential analysis
- **StackFlowClient**: LLM communication interface

### AI Integration
- **StackFlow Framework**: On-device LLM inference
- **ZMQ Communication**: Robust LLM client-server communication
- **Decision Framework**: Strategic security analysis planning
- **Response Processing**: JSON-based AI response handling

## 🔒 Security Features

### Network Security Testing
- **WiFi Auditing**: WPA2/WPS vulnerability assessment
- **Rogue AP Detection**: Evil twin attack simulation
- **MITM Testing**: ARP poisoning and DNS spoofing simulation
- **Credential Harvesting**: Weak password identification

### Vulnerability Assessment
- **Port Scanning**: Service discovery and enumeration
- **Web Application Testing**: Nikto-based vulnerability scanning
- **SSH Auditing**: Default credential testing
- **SMB Analysis**: Share enumeration and access testing

## 📊 Monitoring & Logging

### Log Files
- `audit_history.json`: Complete audit history
- `audited_wifi.log`: WiFi network findings
- `rogue_ap_credentials.log`: Captured credentials (simulation)
- `nikto_*.log`: Web vulnerability scan results

### Dashboard Features
- **Real-time Status**: Live system status updates
- **Log Streaming**: Continuous log monitoring
- **Network Maps**: Discovered hosts and services
- **Vulnerability Reports**: Detailed security findings

## 🧪 Testing

### Unit Tests
```bash
# Run test suite
python -m pytest tests/

# Run specific tests
python -m pytest tests/test_guardian_main.py
```

### Integration Tests
```bash
# Test WiFi functionality
python tests/run_tests.py --wifi

# Test network scanning
python tests/run_tests.py --network

# Test AI integration
python tests/run_tests.py --ai
```

## 🐛 Bug Fixes & Improvements

### Recent Fixes
- ✅ Fixed class definition order issues
- ✅ Resolved Windows compatibility problems
- ✅ Fixed subprocess return type errors
- ✅ Eliminated null pointer dereferences
- ✅ Improved error handling and type safety
- ✅ Centralized configuration management
- ✅ Updated dependencies with version constraints

### Known Issues
- Async SSH functions defined but not used (non-critical)
- Some tools require root privileges
- Windows support limited to development/testing

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before testing any networks. The authors are not responsible for any misuse of this software.

## 🆘 Support

For issues and questions:
1. Check the [BUG_FIXES_SUMMARY.md](BUG_FIXES_SUMMARY.md) for known issues
2. Review the [REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md) for recent changes
3. Open an issue on GitHub with detailed information

---

**AI Network Guardian** - Autonomous Network Security Intelligence
