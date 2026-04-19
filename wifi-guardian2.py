		#!/usr/bin/env python3
"""
wifi-guardian2.py — Wi-Fi Security Scanner for Debian (No-NetworkManager)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Uses 'iw' for low-level scanning to detect Evil Twins and Rogue APs.
"""

import subprocess, sys, os, re, time, signal, argparse
from datetime import datetime

# ─────────────────────────── ANSI Palette ────────────────────────────────────

class C:
    R   = '\033[0m'; BLD = '\033[1m'
    RED = '\033[91m'; YEL = '\033[93m'; GRN = '\033[92m'
    CYN = '\033[96m'; GRY = '\033[90m'; WHT = '\033[97m'
    RED_BG = '\033[41m'; WHT_BLD = '\033[97;1m'

# ─────────────────────────── Constants ───────────────────────────────────────

# OUIs commonly associated with pentest/attack hardware
ATTACK_OUIS = {
    '00:C0:CA': 'Alfa Networks',
    '00:0F:00': 'Ralink Technology',
    '74:DA:38': 'Edimax',
    '00:1F:1F': 'Qualcomm Atheros',
    'E8:4E:06': 'Alfa Networks AWUS'
}

LOG_FILE = os.path.expanduser("~/.wifi_guardian.log")

# ─────────────────────────── Helpers ─────────────────────────────────────────

def ts(): 
    return datetime.now().strftime('%H:%M:%S')

def normalize_mac(mac): 
    return ':'.join(re.split(r'[:\-]', mac)).upper()

def is_locally_administered(mac):
    """Checks the bit that indicates a software-generated/spoofed MAC."""
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except:
        return False

def rssi_bar(rssi):
    width = 10
    strength = max(0, min(width, int((rssi + 100) / 5)))
    color = C.GRN if rssi >= -60 else (C.YEL if rssi >= -75 else C.RED)
    return f"{color}{'█' * strength}{'░' * (width - strength)}{C.R}"

# ─────────────────────────── IW Backend ──────────────────────────────────────

def get_wifi_interface():
    """Finds the wireless interface using 'iw dev'."""
    try:
        r = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "Interface" in line:
                return line.split()[1]
    except:
        pass
    return 'wlan0'

def get_wifi_info():
    """Gets current connection status using 'iw link'."""
    info = {}
    iface = get_wifi_interface()
    try:
        r = subprocess.run(['iw', 'dev', iface, 'link'], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith('SSID:'):
                info['SSID'] = line.split(':', 1)[1].strip()
            elif line.startswith('Connected to'):
                info['BSSID'] = line.split()[2].upper()
    except:
        pass
    return info

def linux_scan():
    """Parses 'iw scan' output into a list of network dictionaries."""
    networks = []
    iface = get_wifi_interface()
    try:
        # Trigger hardware scan
        r = subprocess.run(['iw', 'dev', iface, 'scan'], capture_output=True, text=True)
        aps = r.stdout.split('BSS ')
        for ap in aps[1:]:
            lines = ap.splitlines()
            if not lines: continue
            
            # Extract BSSID
            bssid = lines[0].split('(')[0].strip().upper()
            
            ssid = "<hidden>"
            dbm = -100
            channel = "0"
            security = "Open"

            for line in lines:
                line = line.strip()
                if line.startswith('SSID:'):
                    ssid = line.split(':', 1)[1].strip()
                elif line.startswith('signal:'):
                    try:
                        dbm = int(float(line.split()[1]))
                    except:
                        pass
                elif line.startswith('* primary channel:'):
                    channel = line.split(':')[1].strip()
                elif 'RSN:' in line:
                    security = "WPA2/WPA3"
                elif 'capability: Privacy' in line and security == "Open":
                    security = "WEP/WPA"

            networks.append({
                'ssid': ssid,
                'bssid': normalize_mac(bssid),
                'rssi': dbm,
                'channel': channel,
                'security': security
            })
    except Exception as e:
        print(f"{C.RED}Scan Error: {e}{C.R}")
    return networks

# ─────────────────────────── Detection Engine ────────────────────────────────

def detect_threats(networks, home_ssid, known_bssids):
    alerts = []
    for n in networks:
        # Target: Same SSID name but unrecognized BSSID
        if n['ssid'] == home_ssid and n['bssid'] not in known_bssids:
            reasons = [f"Unknown BSSID {n['bssid']} advertising SSID '{home_ssid}'"]
            severity = 'HIGH'
            
            if is_locally_administered(n['bssid']):
                severity = 'CRITICAL'
                reasons.append("BSSID has Locally Administered bit set (indicates a spoofed MAC)")
            
            oui_hit = ATTACK_OUIS.get(n['bssid'][:8])
            if oui_hit:
                severity = 'CRITICAL'
                reasons.append(f"BSSID matches known attack hardware: {oui_hit}")

            alerts.append({
                'type': 'EVIL TWIN',
                'severity': severity,
                'msg': f"SSID: {n['ssid']} | BSSID: {n['bssid']}",
                'reasons': reasons
            })
    return alerts

# ─────────────────────────── Main Loop ───────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print(f"{C.RED}{C.BLD}[!] Error: Root privileges required for 'iw' scans.{C.R}")
        print("Please run with: sudo python3 wifi-guardian2.py")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Wi-Fi Guardian (Debian No-NM Edition)')
    parser.add_argument('--ssid', help='Manual trusted SSID override')
    args = parser.parse_args()

    iface = get_wifi_interface()
    info = get_wifi_info()
    
    # Identify home network
    home_ssid = args.ssid or info.get('SSID') or input("Enter trusted SSID to monitor: ").strip()
    known_bssids = {normalize_mac(info['BSSID'])} if 'BSSID' in info else set()

    print(f"\n{C.CYN}{C.BLD}Wi-Fi Guardian 2.0 (Debian Hardened Edition){C.R}")
    print(f"Interface: {C.WHT}{iface}{C.R}")
    print(f"Monitoring: {C.GRN}{home_ssid}{C.R}")
    if known_bssids:
        print(f"Known BSSID: {C.GRY}{list(known_bssids)[0]}{C.R}")
    else:
        print(f"{C.YEL}No current BSSID found. Will auto-learn from first scan.{C.R}")
    print(f"{C.GRY}Press Ctrl+C to stop scanning.{C.R}\n")

    count = 0
    while True:
        count += 1
        networks = linux_scan()
        
        if not networks:
            print(f"\r[{ts()}] {C.YEL}Interface busy or no results...{C.R}          ", end="")
            time.sleep(5)
            continue

        # Auto-learn the first instance of home_ssid if none is known
        if not known_bssids:
            for n in networks:
                if n['ssid'] == home_ssid:
                    known_bssids.add(n['bssid'])
                    print(f"\n{C.GRN}[LEARN]{C.R} Registered {n['bssid']} as trusted.")

        threats = detect_threats(networks, home_ssid, known_bssids)
        
        # UI Status Line
        status_color = C.RED if threats else C.GRN
        status_text = f"{len(threats)} THREATS" if threats else "SECURE"
        
        # Clear line and print status
        sys.stdout.write(f"\r\033[K[{ts()}] Scan #{count} | APs: {len(networks)} | Status: {status_color}{C.BLD}{status_text}{C.R}")
        sys.stdout.flush()

        # Display Detailed Alerts
        if threats:
            print("\n" + "━"*60)
            for t in threats:
                sev_c = C.RED_BG + C.WHT_BLD if t['severity'] == 'CRITICAL' else C.RED + C.BLD
                print(f"{sev_c} !! {t['severity']} ALERT !! {C.R} {t['type']}")
                print(f"  Target: {t['msg']}")
                for r in t['reasons']:
                    print(f"  {C.GRY}↳ {r}{C.R}")
            print("━"*60)

        time.sleep(10)

if __name__ == "__main__":
    # Handle clean exit
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
