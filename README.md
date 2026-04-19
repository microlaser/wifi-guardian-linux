# Wi-Fi Guardian (Linux/Debian Edition)

**Wi-Fi Guardian** is a lightweight, proactive wireless security scanner designed specifically for hardened **Debian** environments that do not use NetworkManager. It interacts directly with the Linux wireless stack via `iw` to detect physical-layer threats like Evil Twin attacks, rogue access points, and MAC spoofing in real-time.

## 🚀 Overview

In high-security environments, relying on standard OS notifications is often insufficient. **wifi-guardian2.py** provides a dedicated "Physical Layer IDS." By analyzing Beacon frames and BSSID fingerprints, it identifies attackers who are impersonating your trusted networks before you transmit sensitive data.

### Key Features
* **No NetworkManager Required**: Specifically built for users who manage connections via `wpa_supplicant` or `/etc/network/interfaces`.
* **Evil Twin Detection**: Identifies rogue APs using the same SSID as your trusted network but with differing BSSIDs.
* **Locally Administered Bit Analysis**: Flags MAC addresses that have the "locally administered" bit set—a high-confidence indicator of software-defined spoofing.
* **OUI Fingerprinting**: Detects OUIs associated with common pentest hardware like Alfa Networks and Ralink chipsets.
* **Zero-Connection Scanning**: Runs safely in public environments to verify network integrity before you connect.

## 🛠 Prerequisites

This tool requires the `iw` utility and root privileges to perform hardware-level scans.

```bash
# Install dependencies on Debian/Ubuntu
sudo apt update && sudo apt install iw python3
```

## 📥 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/microlaser/wifi-guardian-linux.git
   cd wifi-guardian-linux
   ```
2. Make the script executable:
   ```bash
   chmod +x wifi-guardian2.py
   ```

## 📖 Usage

### Basic Monitoring
Run the script and it will attempt to auto-detect your current interface and connected SSID:
```bash
sudo python3 wifi-guardian2.py
```

### Targeted Monitoring
Specify the SSID you want to protect:
```bash
sudo python3 wifi-guardian2.py --ssid "YourSSIDHere"
```

## 🔍 Understanding Alerts

When a threat is detected, the console will display a **CRITICAL** or **HIGH** alert:

* **CRITICAL: Locally Administered Bit**: This indicates the AP is likely a "Virtual AP" created by a tool like `hostapd-wpe` rather than a physical router.
* **HIGH: Unknown BSSID**: A device is claiming to be your network but the hardware address (BSSID) does not match your trusted router.

## 🛡 Security Context

This tool was developed as part of a hardened Linux ecosystem, complementing other security layers such as **Suricata** and custom **iptables** configurations. It is recommended for use by security professionals and privacy-conscious users who require transparent control over their wireless environment.

## ⚖️ License & Legality

This tool is for **defensive security auditing only**. Passive scanning of publicly broadcast Wi-Fi beacons is legal in most jurisdictions for self-protection. Unauthorized access to or disruption of networks you do not own is illegal.

---

### Author
**Michael Lazin** ([microlaser](https://github.com/microlaser))  
*Senior Security Professional & Linux Expert*
