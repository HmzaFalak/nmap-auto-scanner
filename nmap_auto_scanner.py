#!/usr/bin/env python3
"""
Automated Nmap Scanner - Open Ports, Firewall & Outdated Service Detection
=============================================================================
Ye script ek target IP leta hai aur khud:
  1. Open ports scan karta hai
  2. Har port ki service/version detect karta hai
  3. Firewall / packet filtering detect karta hai (SYN vs ACK scan compare)
  4. Outdated/vulnerable services ko nmap ke "vuln" NSE scripts se flag karta hai

Requirements:
  - nmap installed      -> sudo apt install nmap
  - Python 3.7+
  - Root/sudo privileges (SYN scan "-sS" aur OS detection "-O" ke liye zaroori hain)

Usage:
  sudo python3 nmap_auto_scanner.py <target_ip>
  sudo python3 nmap_auto_scanner.py <target_ip> --fast
  sudo python3 nmap_auto_scanner.py <target_ip> --ports 1-1000
  sudo python3 nmap_auto_scanner.py <target_ip> --ports 22,80,443

DISCLAIMER:
  Sirf un systems/IPs par scan chalayen jinke scan karne ki aap ko explicit
  ijazat ho (apna server, apna lab, ya written authorization). Bina ijazat
  kisi aur ke network ko scan karna illegal ho sakta hai.
"""

import subprocess
import sys
import shutil
import argparse
import xml.etree.ElementTree as ET
import os
from datetime import datetime


# ---------------------------------------------------------------------------
# UI Helpers
# ---------------------------------------------------------------------------

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def banner():
    print(Colors.BOLD + Colors.BLUE + "=" * 65 + Colors.END)
    print(Colors.BOLD + "   Automated Nmap Scanner - Ports / Firewall / Outdated Services" + Colors.END)
    print(Colors.BOLD + Colors.BLUE + "=" * 65 + Colors.END)
    print(Colors.YELLOW + "Disclaimer: Sirf authorized target par hi scan karein.\n" + Colors.END)


def check_requirements():
    if shutil.which("nmap") is None:
        print(Colors.RED + "[!] nmap installed nahi hai. Pehle install karein: sudo apt install nmap" + Colors.END)
        sys.exit(1)

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(Colors.YELLOW + "[!] Aap root/sudo nahi hain - SYN scan (-sS) aur OS detection (-O) "
              "shayed kaam na karein. Behtar results ke liye 'sudo' se chalayen.\n" + Colors.END)


# ---------------------------------------------------------------------------
# Nmap Execution
# ---------------------------------------------------------------------------

def run_main_scan(target, ports=None, fast=False):
    """Service version + OS detection + vulnerability scripts, XML output mein."""
    xml_out = "/tmp/_scan_result.xml"
    cmd = ["nmap", "-sS", "-sV", "-O", "--script=vuln,default", "-T4" if fast else "-T3"]

    if ports:
        cmd += ["-p", ports]
    elif fast:
        cmd += ["--top-ports", "1000"]
    else:
        cmd += ["-p-"]

    cmd += ["-oX", xml_out, target]

    print(Colors.BLUE + f"[*] Scan chal raha hai:\n    {' '.join(cmd)}\n" + Colors.END)
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(Colors.RED + f"[!] Scan fail ho gaya: {e.stderr.decode(errors='ignore')}" + Colors.END)
        sys.exit(1)
    except FileNotFoundError:
        print(Colors.RED + "[!] nmap command nahi mila." + Colors.END)
        sys.exit(1)

    return xml_out


def run_firewall_probe(target):
    """ACK scan se stateful firewall ya packet filtering detect karte hain."""
    xml_out = "/tmp/_ack_scan.xml"
    cmd = ["nmap", "-sA", "-T3", "-oX", xml_out, target]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        return None
    return xml_out


# ---------------------------------------------------------------------------
# XML Parsing
# ---------------------------------------------------------------------------

def parse_scan(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = {"os": [], "ports": [], "host_state": "unknown"}

    host = root.find("host")
    if host is None:
        return results

    status = host.find("status")
    results["host_state"] = status.get("state") if status is not None else "unknown"

    os_elem = host.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            results["os"].append({"name": match.get("name"), "accuracy": match.get("accuracy")})

    ports_elem = host.find("ports")
    if ports_elem is not None:
        for port in ports_elem.findall("port"):
            state_elem = port.find("state")
            service_elem = port.find("service")

            scripts = []
            for script in port.findall("script"):
                scripts.append({"id": script.get("id"), "output": script.get("output") or ""})

            results["ports"].append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state_elem.get("state") if state_elem is not None else "unknown",
                "service": service_elem.get("name") if service_elem is not None else "unknown",
                "product": service_elem.get("product") if service_elem is not None else "",
                "version": service_elem.get("version") if service_elem is not None else "",
                "extrainfo": service_elem.get("extrainfo") if service_elem is not None else "",
                "scripts": scripts,
            })

    return results


def parse_ack_scan(xml_path):
    """port -> state map, 'filtered' = firewall ka indication."""
    if not xml_path or not os.path.exists(xml_path):
        return {}
    tree = ET.parse(xml_path)
    root = tree.getroot()
    host = root.find("host")
    state_map = {}
    if host is not None:
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                state_map[port.get("portid")] = state_elem.get("state") if state_elem is not None else "unknown"
    return state_map


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(target, scan_data, ack_states):
    print(Colors.BOLD + f"\nTarget: {target}" + Colors.END)
    print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Host Status: {scan_data['host_state']}\n")

    if scan_data["os"]:
        print(Colors.BOLD + "[+] OS Detection (guess):" + Colors.END)
        for match in scan_data["os"][:3]:
            print(f"    - {match['name']}  (accuracy: {match['accuracy']}%)")
        print()

    filtered_ports = [p for p in scan_data["ports"] if p["state"] == "filtered"]
    ack_filtered = [pid for pid, st in ack_states.items() if st == "filtered"]

    print(Colors.BOLD + "[+] Firewall / Packet Filtering:" + Colors.END)
    if filtered_ports or ack_filtered:
        print(Colors.YELLOW + "    [!] Firewall ya packet filter ka indication mila hai." + Colors.END)
        if filtered_ports:
            print(f"        - SYN scan mein {len(filtered_ports)} port(s) 'filtered' state mein.")
        if ack_filtered:
            print(f"        - ACK scan mein {len(ack_filtered)} port(s) filtered (stateful firewall sign).")
    else:
        print(Colors.GREEN + "    [-] Koi clear filtering detect nahi hui." + Colors.END)
    print()

    open_ports = [p for p in scan_data["ports"] if p["state"] == "open"]
    print(Colors.BOLD + f"[+] Open Ports ({len(open_ports)}):" + Colors.END)
    if not open_ports:
        print("    Koi open port nahi mila.")
    for p in open_ports:
        svc = p["service"]
        if p["product"]:
            svc += f" ({p['product']} {p['version']} {p['extrainfo']})".replace("  ", " ")
        print(Colors.GREEN + f"    {p['port']:>6}/{p['protocol']:<4} OPEN   {svc}" + Colors.END)
    print()

    print(Colors.BOLD + "[+] Outdated / Vulnerable Services:" + Colors.END)
    found_any = False
    for p in open_ports:
        for script in p["scripts"]:
            output = script["output"]
            if any(k in output for k in ("VULNERABLE", "CVE-", "vulnerable")):
                found_any = True
                print(Colors.RED + f"    [!] Port {p['port']}/{p['protocol']}  "
                      f"({p['service']} {p['product']} {p['version']}) - script: {script['id']}" + Colors.END)
                for line in output.strip().splitlines():
                    print(f"        {line.strip()}")
                print()
    if not found_any:
        print(Colors.GREEN + "    Koi known vulnerability signature nahi mila "
              "(iska matlab 100% secure hona nahi - manually bhi check karein)." + Colors.END)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Automated Nmap Scanner")
    parser.add_argument("target", help="Target IP ya hostname")
    parser.add_argument("--fast", action="store_true", help="Sirf top 1000 ports scan karein (tez)")
    parser.add_argument("--ports", help="Specific range, e.g. 1-1000 ya 22,80,443")
    args = parser.parse_args()

    banner()
    check_requirements()

    xml_path = run_main_scan(args.target, ports=args.ports, fast=args.fast)
    scan_data = parse_scan(xml_path)

    print(Colors.BLUE + "[*] Firewall check ke liye ACK scan chal raha hai...\n" + Colors.END)
    ack_xml = run_firewall_probe(args.target)
    ack_states = parse_ack_scan(ack_xml)

    print_report(args.target, scan_data, ack_states)


if __name__ == "__main__":
    main()
