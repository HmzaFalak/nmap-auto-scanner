# 🛡️ Nmap Auto Scanner

Ek Python script jo [Nmap](https://nmap.org/) ke around build hui hai aur ek target IP/hostname par **khud-ba-khud** full reconnaissance kar deti hai — open ports, service versions, firewall presence, OS guess, aur outdated/vulnerable services, sab ek clean color-coded report mein.

Built as a side project to dig deeper into network scanning concepts and Nmap's XML/NSE scripting ecosystem.

---

## ✨ Features

- 🔍 **Open Port Detection** — SYN scan (`-sS`) + service/version detection (`-sV`)
- 🖥️ **OS Fingerprinting** — target ka OS guess karta hai, accuracy % ke saath
- 🔥 **Firewall Detection** — SYN scan aur ACK scan ke results compare kar ke stateful/stateless packet filtering detect karta hai
- ⚠️ **Outdated/Vulnerable Service Detection** — Nmap ke built-in `--script vuln` NSE scripts se known vulnerability signatures flag karta hai
- 🎨 **Clean Terminal Report** — color-coded output, koi manual XML parsing ki zaroorat nahi
- ⚡ **Fast mode** — sirf top 1000 ports scan karne ka option

---

## 📸 Demo

Tested against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — ek intentionally vulnerable app jo security practice ke liye officially banayi gayi hai.

```
[+] Open Ports (2):
     80/tcp OPEN   http (heroku-router)
    443/tcp OPEN   http (Golang net/http server)

[+] Outdated / Vulnerable Services:
    Koi known vulnerability signature nahi mila
```

---

## 📋 Requirements

- Python 3.7+
- [Nmap](https://nmap.org/download.html) installed on the system
- Root/sudo privileges (SYN scan `-sS` aur OS detection `-O` ke liye zaroori hain)

No external Python packages needed — sirf standard library (`subprocess`, `argparse`, `xml.etree.ElementTree`) use hoti hai.

---

## ⚙️ Installation

```bash
# Nmap install karein (agar pehle se nahi hai)
sudo apt install nmap

# Repo clone karein
git clone https://github.com/<your-username>/nmap-auto-scanner.git
cd nmap-auto-scanner
```

---

## 🚀 Usage

```bash
# Full scan (sab 65535 ports)
sudo python3 nmaptool.py <target>

# Fast scan (top 1000 ports)
sudo python3 nmaptool.py <target> --fast

# Specific port range
sudo python3 nmaptool.py <target> --ports 1-1000

# Specific ports
sudo python3 nmaptool.py <target> --ports 22,80,443
```

**Example:**
```bash
sudo python3 nmaptool.py 192.168.1.1
```

---

## 🧠 How It Works

1. Nmap ko `subprocess` ke zariye XML output mode (`-oX`) mein call karta hai
2. XML result ko `xml.etree.ElementTree` se parse karta hai (open ports, services, OS matches, NSE script output)
3. Alag se ACK scan chala kar firewall/filtering detect karta hai (filtered ports = firewall ka sign)
4. `--script vuln` category ke scripts ke output mein `CVE-`, `VULNERABLE` jaise keywords dhoond kar outdated services flag karta hai

---

## ⚠️ Disclaimer

Ye tool sirf **educational aur authorized testing** ke liye hai. Sirf un systems/IPs par scan chalayen jin ke scan karne ki aap ko explicit ijazat ho (apna server, apna lab, ya written authorization). Bina permission kisi third-party network ko scan karna illegal ho sakta hai aapke jurisdiction mein.

Ye tool network-layer issues detect karta hai — application-layer vulnerabilities (SQL Injection, XSS, IDOR, etc.) ke liye [Burp Suite](https://portswigger.net/burp) ya [OWASP ZAP](https://www.zaproxy.org/) jaise dedicated tools use karein.

---

## 🛣️ Possible Future Improvements

- [ ] HTTP security headers check (missing CSP, HSTS, etc.)
- [ ] Export report as PDF/HTML
- [ ] Multi-target / CIDR range support
- [ ] Integration with Shodan/CVE APIs for richer vulnerability data

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
