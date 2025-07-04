# 🛡️SpoofSniff: Real-time DNS Spoofing Detection

[![Python 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---
```
 ____                     __ ____        _  __  __ 
/ ___| _ __   ___   ___  / _/ ___| _ __ (_)/ _|/ _|
\___ \| '_ \ / _ \ / _ \| |_\___ \| '_ \| | |_| |_ 
 ___) | |_) | (_) | (_) |  _|___) | | | | |  _|  _|
|____/| .__/ \___/ \___/|_| |____/|_| |_|_|_| |_|  
      |_|                                          
```
## 💡 Overview

**SpoofSniff** is a robust, Python-based network monitoring tool designed to detect various forms of DNS (Domain Name System) spoofing and cache poisoning attacks in real-time on a local network. It acts as an essential security layer, scrutinizing DNS traffic to ensure that domain resolutions are legitimate and untampered.

## ❓ Why SpoofSniff?

The Domain Name System (DNS) is a foundational service that translates human-readable domain names into numerical IP addresses, crucial for navigating the internet. However, DNS is highly vulnerable to "spoofing" or "cache poisoning" attacks. If compromised, an attacker can inject fraudulent DNS responses, redirecting users to malicious websites (e.g., phishing pages, malware downloads) or blocking access to legitimate services.

SpoofSniff addresses this critical vulnerability by providing an immediate alert system, helping users identify and mitigate such threats on their local network before significant damage occurs.

## ✨ Features

* **Real-time DNS Traffic Monitoring:** Continuously sniffs UDP traffic on port 53 to analyze DNS queries and responses.
* **Multi-layered Spoofing Detection:** Implements several sophisticated mechanisms to identify different attack vectors:
    * **Transaction ID (TXID) Matching:** Validates that incoming DNS responses correlate correctly with outgoing queries based on their unique Transaction IDs.
    * **Trusted DNS Server Source Validation:** Ensures responses originate only from a user-configured list of legitimate DNS servers.
    * **IP Mismatch Validation:** Compares received IP addresses against a "ground truth" obtained from trusted external DNS resolvers.
    * **NXDOMAIN Spoofing Detection:** Flags instances where an attacker provides an IP for a domain that should legitimately not exist.
* **Intuitive Graphical User Interface (GUI):** A user-friendly interface built with `tkinter` for easy control (start/stop monitoring) and real-time display of logs and alerts.
* **Persistent DNS Cache:** Maintains and reloads a local cache (`cache.json`) of resolved domains and NXDOMAIN statuses to improve performance and reduce redundant external lookups.
* **Configurable Trusted DNS Servers:** Allows users to easily specify their known-good local DNS servers within the application.
* **Comprehensive Alerting:** Provides clear, detailed alerts for detected anomalies, displayed in the GUI and logged to a file.

## ⚙️ Technical Stack

* **Python 3.x:** The core programming language.
* **Scapy:** A powerful packet manipulation program for sniffing and parsing network packets.
* **`dnspython` (`dns.resolver`):** Used for performing reliable, independent DNS lookups against external trusted servers.
* **`tkinter`:** Python's standard GUI library, used for the user interface.
* **`threading` & `queue`:** For concurrent operations, ensuring the GUI remains responsive while the sniffer runs in a separate thread.
* **`json`:** For persistent storage and loading of the DNS cache.

## 🚀 Getting Started

Follow these steps to get SpoofSniff up and running on your system.

### Prerequisites

* Python 3.x installed.
* `pip` (Python package installer).
* **Administrator/Root Privileges:** The sniffer part of this tool requires elevated privileges to capture raw network packets.
    * On **Windows**: Run Command Prompt or PowerShell as Administrator.
    * On **Linux/macOS**: Use `sudo` when running the main script.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Manan-78581/SpoofSniff.git](https://github.com/Manan-78581/SpoofSniff.git)
    cd SpoofSniff
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    * **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    * **Linux/macOS:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install the required dependencies:**
    ```bash
    pip install scapy dnspython
    ```

### Usage

1.  **Ensure you are in the `SpoofSniff` project directory** and your virtual environment is active.

2.  **Configure Trusted DNS Servers:**
    Open `sniffer.py` in a text editor. Locate the `TRUSTED_LOCAL_DNS_SERVERS` list and update it with the IP addresses of your actual local DNS servers (e.g., your router's IP, or your ISP's DNS IPs if you configure them directly).
    ```python
    # sniffer.py
    TRUSTED_LOCAL_DNS_SERVERS = [
        "192.168.1.1",  # Example: Your router's IP
        "8.8.8.8",      # Example: Google Public DNS
        "1.1.1.1"       # Example: Cloudflare DNS
    ]
    ```
    *Incorrect configuration here can lead to false positives.*

3.  **Run the application with elevated privileges:**

    * **Windows (in Administrator Command Prompt/PowerShell):**
        ```bash
        python main.py
        ```
    * **Linux/macOS (in terminal):**
        ```bash
        sudo python3 main.py
        ```
        (You might need to use `python` instead of `python3` depending on your system setup.)

The GUI window will appear. Click "Start Monitoring" to begin sniffing DNS traffic. Alerts will be displayed in the console and the GUI's log area.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/Manan-78581/SpoofSniff/issues) to contribute.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📧 Contact

Manan - https://github.com/Manan-78581

---
