# 🧠 AI Network Guardian: Your Network's AI-Powered Sentry 🛡️

![Guardian Logo](assets/guardian_logo.png)

Welcome to the future of personal network management. The AI Network Guardian is a service device designed to give you unprecedented insight and control over your home network. Think of it as the ultimate security tool for your digital life—a powerful guardian that, when connected to your network, works tirelessly to identify vulnerabilities, monitor activity, and ensure your digital environment is safe.

Powered by the M5Stack LLM630 Compute Kit, this project provides a blueprint for an intelligent, AI-driven agent that helps you understand and manage your network's security posture. It's a tool for learning, for defense, and for taking control. When unplugged, it can audit nearby networks to understand the local wireless landscape. When plugged into your home network, it becomes your personal AI security analyst.

This project is a proof-of-concept for a new era of consumer-friendly, AI-powered cybersecurity tools. It aims to empower users to proactively manage their own network security, making advanced diagnostics accessible to everyone.

---

## 🚀 Project Status: Advanced Prototype

The AI Network Guardian is a mature prototype, featuring robust security analysis modules and sophisticated AI-driven decision-making. It's a truly autonomous agent for managing and securing your personal network.

**Current State (Implemented & AI-Driven):**

*   **Hardware Foundation:** Fully integrated with the M5Stack LLM630 Compute Kit (Axera AX630C SoC with NPU, ESP32-C6).
*   **Core Modules:** Functional classes for Wi-Fi Security Auditing, AI Password Strength Analysis, LAN Analysis, AI Decision-Making, and a Web Dashboard.
*   **AI Orchestration:** The `ai_main_loop` is driven by an on-device LLM, making real-time strategic decisions to identify and mitigate risks.
*   **Web Dashboard:** An enhanced Flask web server with an HTML template provides real-time status, live log streams, network audit results, and detailed connected host information.
*   **Automatic Tool Installation:** The script attempts to install necessary Linux tools (e.g., `dsniff`, `reaver`, `hostapd`, `dnsmasq`, `nikto`, `hydra`, `smbclient`, `metasploit-framework`) for comprehensive analysis.
*   **Security Simulation:** Integrates the Metasploit framework for automated, simulated penetration tests to safely identify and patch vulnerabilities.

---

## 🧠 Current AI Capabilities (ZMQ Integration & Autonomous Decision-Making)

The latest version of the script (`app/main.py`) fully integrates an on-device Large Language Model (LLM) using the `pyzmq` library. The AI serves as the central "brain" for the Guardian's operations, dynamically choosing and executing security analysis strategies.

Here is what the AI currently does:

1.  **Autonomous Wi-Fi Environment Analysis & Security Audit Selection:**
    *   The AI receives a real-time, detailed list of all nearby Wi-Fi networks, including SSID, BSSID, encryption type (OPEN, WPA2), signal strength, client count, and WPS status.
    *   It analyzes this data to identify potential security weaknesses in your network or surrounding networks.
    *   It makes a strategic decision on which security audit to perform next, prioritizing the most critical areas for review.
    *   It issues specific JSON commands to the Python script, choosing from:
        *   `{"action": "CONNECT_OPEN", "target_ssid": "..."}` to test the security of open networks.
        *   `{"action": "ATTACK_WPS", "target_ssid": "...", "target_bssid": "..."}` to audit WPS vulnerabilities.
        *   `{"action": "ATTACK_WPA2", "target_ssid": "...", "target_bssid": "..."}` to perform a security audit on your WPA2 network and analyze its password strength.
        *   `{"action": "ATTACK_EVIL_TWIN", "target_ssid": "...", "target_channel": "..."}` to simulate a "rogue access point" attack and test your network's resilience.

2.  **AI-Generated Password Strength Analysis:**
    *   When performing a WPA2 security audit, the script leverages the LLM to generate password candidates based on context (e.g., SSID) to test the strength of your password.
    *   These AI-generated passwords create a persistent, evolving wordlist to help you choose stronger credentials.

3.  **Automated Internal Network Health Analysis:**
    *   Once connected to your network, the AI automatically begins a comprehensive internal security scan.
    *   It receives its current IP, the network subnet, and a detailed list of all connected devices (including OS, open ports, services, and any discovered vulnerabilities or open shares).
    *   The AI then makes a strategic decision on the next analysis action, choosing from:
        *   `{"action": "SCAN_NETWORK"}`: Performs a deep `nmap` scan (`-sV`, `-sC`, `-O`) to map your network and identify all connected devices and services.
        *   `{"action": "VULNERABILITY_SCAN", "target_ip": "...", "port": "..."}`: Launches a `nikto` scan against a specific device to find known vulnerabilities.
        *   `{"action": "BRUTE_FORCE_SERVICE", "target_ip": "...", "port": "...", "service": "..."}`: Uses `hydra` to test the strength of service logins (e.g., SSH, FTP) on your devices.
        *   `{"action": "SCAN_SMB_SHARES", "target_ip": "..."}`: Enumerates open SMB (Windows file sharing) shares to prevent unauthorized data access.
        *   `{"action": "MITM_ATTACK", "target_ip": "...", "gateway_ip": "...", "phishing_domain": "..."}`: Simulates a Man-in-the-Middle attack to test your network's defenses against credential theft.

---

## ⚙️ Full Capabilities List: What the Guardian Can Do

The AI Network Guardian is a comprehensive, multi-stage security analysis agent. Here's a breakdown of its capabilities:

### 📡 Wi-Fi Security Assessment & Auditing

*   **Comprehensive Network Discovery:** Intelligently scans and enumerates nearby Wi-Fi networks.
*   **Automated Vulnerability Identification:** AI dynamically chooses the best security audit based on real-time network data.
*   **WPA/WPA2 Security Auditing:** Automated handshake capture to analyze the security of your encrypted network.
*   **AI-Accelerated Password Strength Analysis:**
    *   **Dictionary Analysis:** Rapidly tests your network's password against extensive common password dictionaries.
    *   **Generative Analysis:** Leverages the on-board NPU to run LLMs for intelligent, context-aware password generation to test credential strength.
*   **WPS Vulnerability Testing:** Audits WPS configurations to identify and help you disable this known vulnerability.
*   **Network Integrity Simulation:** Simulates "Evil Twin" scenarios to test resilience against credential harvesting attacks.

### 🌐 Internal Network Health & Security Analysis

Once connected to your network, the Guardian becomes your personal security analyst:

*   **Automated Device & Service Discovery:**
    *   **Deep Nmap Scanning:** Performs comprehensive Nmap scans to map all devices, open ports, services, and operating systems on your network.
    *   **Web Vulnerability Scanning:** Launches `nikto` scans against web-enabled devices to identify common vulnerabilities.
    *   **SMB Share Enumeration:** Scans for open Server Message Block (SMB) shares to prevent data leaks.
*   **Simulated Credential Exposure Testing:**
    *   **Service Login Strength Testing:** Uses `hydra` to test the strength of logins for services like SSH, FTP, and others.
    *   **Phishing Simulation:** Deploys simulated phishing websites via network integrity tests to educate and improve security awareness.
*   **MITM Vulnerability Simulation:** Initiates ARP spoofing simulations to test for vulnerabilities to traffic interception.
*   **DNS Spoofing Simulation:** Tests if devices on your network can be redirected to malicious pages.
*   **Automated Penetration Testing Simulation:** Safely selects and simulates Metasploit exploits against identified vulnerabilities to confirm their existence.

### 🧠 AI Orchestration: The Brain

*   **LLM-Driven Decision-Making:** The AI makes all strategic decisions for both Wi-Fi audits and internal network analysis.
*   **Adaptive Analysis Sequencing:** The AI decides on the optimal sequence of actions to achieve a full security overview.
*   **Continuous Learning & Feedback Loops:** Logs all analysis attempts and outcomes to continuously refine its intelligence.
*   **NPU Acceleration:** Leverages the M5Stack's Neural Processing Unit for high-speed AI inference.

### 💻 User Interface & Control

*   **Web Dashboard:** A Flask-based web interface provides real-time monitoring of AI status, live logs, audit results, and detailed information on all connected devices.

---

## 🗺️ Future Intentions & Roadmap

The journey to a fully featured AI Network Guardian is ongoing. Here's what's next:

### Phase 1: Advanced Security Auditing & Monitoring (Next Focus)

*   **Automated Patch Recommendation:** Integrate systems to suggest patches or configuration changes for discovered vulnerabilities.
*   **Establishing Persistence Monitoring:** Implement mechanisms to detect unauthorized persistent access on your devices.
*   **Data Exfiltration Simulation:** Develop safe methods to simulate data exfiltration to test your network's outbound security.

### Phase 2: Enhanced Privacy & Discretion

*   **MAC Address Spoofing:** Implement dynamic MAC address changes for privacy during external audits.
*   **Traffic Obfuscation:** Techniques to make the Guardian's analysis traffic less conspicuous.
*   **Forensic Trail Analysis:** Methods to understand the traces left by potential intruders.

### Phase 3: Next-Generation AI & Hardware Integration

*   **Bluetooth Low Energy (BLE) Interface:** Implement discreet, out-of-band control and status updates via BLE.
*   **5GHz/6GHz Wi-Fi Support:** Explore integration with external Wi-Fi modules to expand network analysis capabilities.
*   **Reinforcement Learning for Security Strategies:** Deeper integration of RL for truly adaptive, optimized security analysis in dynamic environments.
*   **On-Device LLM Fine-Tuning:** Research methods for fine-tuning small LLMs directly on the NPU for enhanced contextual intelligence.

---

## 🛡️ Ethical & Legal Disclaimer

This project is developed for educational, research, and personal network security purposes only. The techniques and capabilities described are powerful tools for understanding and managing your own digital environment. Users are solely responsible for ensuring that all activities conducted with this project are performed on networks they own or have explicit authorization to manage.

**Only use this project on your own network.**

---

## 🤝 Contribute to the Vision!

The AI Network Guardian is an ambitious open-source endeavor. We welcome contributions from cybersecurity researchers, AI enthusiasts, embedded systems developers, and anyone passionate about building the future of consumer network security.

Join us in creating powerful, accessible tools for a safer digital world.

---

**Keywords:** AI, Autonomous Agent, Wi-Fi Security, Network Management, Home Network Security, M5Stack, LLM630, NPU, ESP32-C6, Network Security, Cybersecurity Research, Ethical Hacking, Defensive Security, Network Analysis, MITM, Password Strength, Reinforcement Learning, IoT Security, Embedded Systems, Python, Flask, Linux, Nmap, Nikto, Hydra, SMB, DNS, Phishing Simulation
