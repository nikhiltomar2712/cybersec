<img src="https://cdn.corenexis.com/f/CcWbm2cPx6K.svg" 
     alt="Cover" 
     width="100%" 
     height="250" />
     
# 🔐 CyberSec Learning Notes & Toolkit

[![Security Policy](https://img.shields.io/badge/Security-Policy-red?style=for-the-badge&logo=github)](./security.md)
[![Ethical Use](https://img.shields.io/badge/Use-Ethical%20Only-blue?style=for-the-badge)](./ethicaluse.txt)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](./LICENSE)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=for-the-badge)](https://github.com/nikhiltomar2712)
[![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=for-the-badge&logo=python&logoColor=white)](./tools/)
[![JavaScript](https://img.shields.io/badge/Node.js-14+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](./tools/js/)
[![C++17](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](./tools/cpp/)

> **A personal knowledge base and toolkit for cybersecurity learning —
> covering networking, web security, Linux, CTF techniques, cryptography, and defensive practices.**

*Built for learning. Used ethically. Shared openly.*

---

## 📌 About This Repository

This is my personal cybersecurity study notes and reference repository. It documents everything I learn across platforms like **TryHackMe**, **Hack The Box**, **PortSwigger Academy**, and through self-study toward **eJPT**, **CEH**, and **OSCP**.

In addition to notes, this repo contains **working tools** written in Python, JavaScript, and C++ to practice and reinforce concepts hands-on.

> ⚠️ All content is for **educational and defensive use only**. See [`ethicaluse.txt`](./ethicaluse.txt) before proceeding.

---

## 📂 Repository Structure

```
cybersec/
│
├── 📁 tools/                     ← Working scripts & tools
│   ├── port_scanner.py           ← Async TCP port scanner (Python)
│   ├── hash_identifier.py        ← Hash identifier + dictionary cracker (Python)
│   ├── subdomain_enum.py         ← Subdomain enumerator via DNS (Python)
│   ├── 📁 js/
│   │   ├── payload_generator.js  ← XSS / SQLi payload generator (Node.js)
│   │   └── recon.js              ← DNS + HTTP header recon (Node.js)
│   ├── 📁 cpp/
│   │   ├── crypto_tools.cpp      ← Caesar, Vigenère, XOR, Base64, freq analysis (C++)
│   │   └── port_scanner.cpp      ← Threaded TCP port scanner (C++)
│   └── README.md                 ← Tool usage guide
│
├── 📁 networking/
│   ├── osi-model.md
│   ├── tcp-ip.md
│   ├── dns-enumeration.md
│   └── wireshark-cheatsheet.md
│
├── 📁 web-security/
│   ├── owasp-top10.md
│   ├── sql-injection.md
│   ├── xss.md
│   ├── ssrf.md
│   └── burpsuite-notes.md
│
├── 📁 linux/
│   ├── privilege-escalation.md
│   ├── bash-scripting.md
│   ├── file-permissions.md
│   └── cron-abuse.md
│
├── 📁 ctf/
│   ├── methodology.md
│   ├── steganography.md
│   ├── reverse-engineering.md
│   └── crypto-basics.md
│
├── 📁 defensive/
│   ├── soc-analyst-notes.md
│   ├── log-analysis.md
│   ├── incident-response.md
│   └── threat-hunting.md
│
├── 📁 certifications/
│   ├── ejpt-roadmap.md
│   ├── ceh-notes.md
│   └── oscp-prep.md
│
├── 📁 .github/ISSUE_TEMPLATE/
│   ├── fix-report.yml            ← Bug/correction report template
│   └── new-topic.yml             ← New topic suggestion template
│
├── security.md
├── contributing.md
├── code-of-conduct.md
├── ethicaluse.txt
├── resources.md
└── README.md
```

---

## 🧰 Tools

All tools require only stdlib — no `pip install` or `npm install` needed.

| Tool | Language | Description |
|---|---|---|
| [`port_scanner.py`](./tools/port_scanner.py) | Python 3.7+ | Async TCP port scanner with service detection |
| [`hash_identifier.py`](./tools/hash_identifier.py) | Python 3.6+ | Hash identifier + dictionary cracker |
| [`subdomain_enum.py`](./tools/subdomain_enum.py) | Python 3.7+ | Subdomain enumerator via DNS brute-force |
| [`payload_generator.js`](./tools/js/payload_generator.js) | Node.js 14+ | XSS/SQLi payload generator + encoder/decoder |
| [`recon.js`](./tools/js/recon.js) | Node.js 14+ | DNS records, HTTP headers, robots.txt recon |
| [`crypto_tools.cpp`](./tools/cpp/crypto_tools.cpp) | C++17 | Caesar, Vigenère, XOR, Base64, freq analysis |
| [`port_scanner.cpp`](./tools/cpp/port_scanner.cpp) | C++17 | Thread-pool TCP port scanner |

→ Full usage guide: **[`tools/README.md`](./tools/README.md)**

**Quick start:**

```bash
# Python port scanner
python3 tools/port_scanner.py 192.168.1.1 --ports 1-1024

# Node.js recon
node tools/js/recon.js all example.com

# C++ crypto tools (compile first)
g++ -std=c++17 -O2 -o crypto_tools tools/cpp/crypto_tools.cpp
./crypto_tools bruterot "Uryyb Jbeyq"
```

---

## 🗺️ Learning Roadmap

```
Phase 1 — Foundations          Phase 2 — Offensive              Phase 3 — Defensive
─────────────────────          ──────────────────────           ───────────────────────
☑ Networking basics             ☑ Web app testing (OWASP)        ☐ SOC Analyst basics
☑ Linux fundamentals            ☑ SQL injection / XSS            ☐ SIEM (Splunk / ELK)
☑ OSI Model                     ☐ Buffer overflows               ☐ Threat hunting
☑ TCP/IP, DNS, HTTP             ☐ Active Directory attacks        ☐ Malware analysis
☑ Nmap / Wireshark              ☐ OSCP prep                      ☐ Incident response
☑ CTF beginner rooms            ☐ Custom exploit dev             ☐ Blue team tools
```

---

## 🧰 Tools Covered in Notes

| Category | Tools |
|---|---|
| **Reconnaissance** | Nmap, Shodan, theHarvester, Maltego, Recon-ng |
| **Web Testing** | Burp Suite, FFUF, Gobuster, Nikto, SQLmap |
| **Exploitation** | Metasploit, Searchsploit, MSFvenom |
| **Password Attacks** | Hydra, John the Ripper, Hashcat, CeWL |
| **Post Exploitation** | LinPEAS, WinPEAS, BloodHound, Mimikatz |
| **Forensics / DFIR** | Autopsy, Volatility, FTK Imager |
| **Traffic Analysis** | Wireshark, tcpdump, Zeek |
| **SIEM / Monitoring** | Splunk, ELK Stack, Wazuh |

---

## 🏆 Platforms I Practice On

| Platform | Profile / Status |
|---|---|
| [TryHackMe](https://tryhackme.com) | Active learner |
| [Hack The Box](https://hackthebox.com) | Active learner |
| [PortSwigger Academy](https://portswigger.net/web-security) | Web security labs |
| [PentesterLab](https://pentesterlab.com) | Web app focus |
| [VulnHub](https://vulnhub.com) | Offline VM practice |
| [PicoCTF](https://picoctf.org) | CTF competitions |

---

## 📚 Certifications & Goals

- [ ] **eJPT** — eLearnSecurity Junior Penetration Tester *(in progress)*
- [ ] **CompTIA Security+** *(planned)*
- [ ] **CEH** — Certified Ethical Hacker *(planned)*
- [ ] **OSCP** — Offensive Security Certified Professional *(long-term goal)*

---

## 📖 Key References

- 📘 [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- 📘 [MITRE ATT&CK Framework](https://attack.mitre.org/)
- 📘 [CVE Database](https://cve.mitre.org/)
- 📘 [GTFOBins](https://gtfobins.github.io/)
- 📘 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- 📘 [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- 📘 [Exploit-DB](https://exploit-db.com)

See [`resources.md`](./resources.md) for the full curated list.

---

## ⚖️ Legal & Ethical Notice

All content in this repository is for **educational purposes only**.

✅ Allowed: personal VMs, authorised lab platforms (TryHackMe, HTB), systems you own  
❌ Never: unauthorised access, real-world exploitation, illegal activity

Read the full notice in [`ethicaluse.txt`](./ethicaluse.txt)  
Read the security policy in [`security.md`](./security.md)

---

## 🤝 Contributing

Found an error? Have better notes or a useful resource?  
See [`contributing.md`](./contributing.md) — contributions are welcome via the issue templates!

---

## 👤 Author

**Nikhil Tomar**  
BCA Student · Amity University, Delhi  
Aspiring DevOps / Cloud Engineer & Cybersecurity Enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-nikhiltomar2712-181717?style=flat&logo=github)](https://github.com/nikhiltomar2712)

---

*Built with curiosity. Shared for the community. Used responsibly.*

# CyberSec Toolkit

A collection of ethical hacking and security tools for educational purposes.

## Requirements
- Python 3.7+
- Node.js 14+
- C++17 compiler (g++/clang++)

## Python Tools

| Tool | Description | Usage |
|------|-------------|-------|
| `port_scanner.py` | Async TCP/UDP scanner | `python3 port_scanner.py 192.168.1.1 -p 1-1024` |
| `hash_identifier.py` | Hash ID + cracker | `python3 hash_identifier.py &lt;hash&gt; -w wordlist.txt` |
| `subdomain_enum.py` | DNS subdomain enum | `python3 subdomain_enum.py example.com -w subs.txt` |
| `password_analyzer.py` | Password strength check | `python3 password_analyzer.py "MyP@ssw0rd"` |
| `forensics_toolkit.py` | File forensics | `python3 forensics_toolkit.py file.bin` |

## JavaScript Tools

| Tool | Description | Usage |
|------|-------------|-------|
| `payload_generator.js` | XSS/SQLi payloads | `node payload_generator.js xss wafBypass` |
| `recon.js` | Reconnaissance | `node recon.js all example.com` |
| `jwt_tool.js` | JWT analyzer | `node jwt_tool.js analyze &lt;token&gt;` |

## C++ Tools

| Tool | Description | Compile |
|------|-------------|---------|
| `crypto_tools.cpp` | Crypto utilities | `g++ -std=c++17 -O2 -o crypto_tools crypto_tools.cpp` |
| `port_scanner.cpp` | Threaded scanner | `g++ -std=c++17 -O2 -pthread -o port_scanner port_scanner.cpp` |
| `memory_scanner.cpp` | Memory forensics | `g++ -std=c++17 -O2 -o memory_scanner memory_scanner.cpp` |

## Quick Start

```bash
# TCP scan
python3 port_scanner.py scanme.nmap.org -p 1-1000

# Full recon
node recon.js all target.com

# Crypto analysis
./crypto_tools bruterot "Uryyb Jbeyq"

# File forensics
python3 forensics_toolkit.py suspicious.exe
