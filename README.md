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


data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' class='markmap mm-0v5s1u-4' style='width: 100%25; height: 100%25;'%3E%3Cstyle%3E.markmap%7B--markmap-max-width: 9999px;--markmap-a-color: %230097e6;--markmap-a-hover-color: %2300a8ff;--markmap-code-bg: %23f0f0f0;--markmap-code-color: %23555;--markmap-highlight-bg: %23ffeaa7;--markmap-table-border: 1px solid currentColor;--markmap-font: 300 16px/20px sans-serif;--markmap-circle-open-bg: %23fff;--markmap-text-color: %23333;--markmap-highlight-node-bg: %23ff02;font:var(--markmap-font);color:var(--markmap-text-color)%7D.markmap-link%7Bfill:none%7D.markmap-node&gt;circle%7Bcursor:pointer%7D.markmap-foreign%7Bdisplay:inline-block%7D.markmap-foreign p%7Bmargin:0%7D.markmap-foreign a%7Bcolor:var(--markmap-a-color)%7D.markmap-foreign a:hover%7Bcolor:var(--markmap-a-hover-color)%7D.markmap-foreign code%7Bpadding:.25em;font-size:calc(1em - 2px);color:var(--markmap-code-color);background-color:var(--markmap-code-bg);border-radius:2px%7D.markmap-foreign pre%7Bmargin:0%7D.markmap-foreign pre&gt;code%7Bdisplay:block%7D.markmap-foreign del%7Btext-decoration:line-through%7D.markmap-foreign em%7Bfont-style:italic%7D.markmap-foreign strong%7Bfont-weight:700%7D.markmap-foreign mark%7Bbackground:var(--markmap-highlight-bg)%7D.markmap-foreign table,.markmap-foreign th,.markmap-foreign td%7Bborder-collapse:collapse;border:var(--markmap-table-border)%7D.markmap-foreign img%7Bdisplay:inline-block%7D.markmap-foreign svg%7Bfill:currentColor%7D.markmap-foreign&gt;div%7Bwidth:var(--markmap-max-width);text-align:left%7D.markmap-foreign&gt;div&gt;div%7Bdisplay:inline-block%7D.markmap-highlight rect%7Bfill:var(--markmap-highlight-node-bg)%7D.markmap-dark .markmap%7B--markmap-code-bg: %231a1b26;--markmap-code-color: %23ddd;--markmap-circle-open-bg: %23444;--markmap-text-color: %23eee%7D%3C/style%3E%3Cg transform='translate(20,273.2351598173516) scale(0.6940639269406392)'%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.2.3' d='M332,-238.812C372,-238.812,372,-265.375,412,-265.375' stroke-width='1.375' stroke='rgb(44, 160, 44)'/%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.2.4' d='M332,-238.812C372,-238.812,372,-239,412,-239' stroke-width='1.375' stroke='rgb(214, 39, 40)'/%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.2.5' d='M332,-238.812C372,-238.812,372,-212.625,412,-212.625' stroke-width='1.375' stroke='rgb(148, 103, 189)'/%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.6.7' d='M323,-126.062C363,-126.062,363,-71.25,403,-71.25' stroke-width='1.375' stroke='rgb(227, 119, 194)'/%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.8.9' d='M348,-6.187C388,-6.187,388,27.125,428,27.125' stroke-width='1.375' stroke='rgb(188, 189, 34)'/%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.10.11' d='M304,92.188C344,92.188,344,125.5,384,125.5' stroke-width='1.375' stroke='rgb(31, 119, 180)'/%3E%3Cpath class='markmap-link' data-depth='3' data-path='1.12.13' d='M311,260.563C351,260.563,351,363.875,391,363.875' stroke-width='1.375' stroke='rgb(44, 160, 44)'/%3E%3Cpath class='markmap-link' data-depth='2' data-path='1.2' d='M136,11.25C176,11.25,176,-238.812,216,-238.812' stroke-width='1.75' stroke='rgb(255, 127, 14)'/%3E%3Cpath class='markmap-link' data-depth='2' data-path='1.6' d='M136,11.25C176,11.25,176,-126.062,216,-126.062' stroke-width='1.75' stroke='rgb(140, 86, 75)'/%3E%3Cpath class='markmap-link' data-depth='2' data-path='1.8' d='M136,11.25C176,11.25,176,-6.187,216,-6.187' stroke-width='1.75' stroke='rgb(127, 127, 127)'/%3E%3Cpath class='markmap-link' data-depth='2' data-path='1.10' d='M136,11.25C176,11.25,176,92.188,216,92.188' stroke-width='1.75' stroke='rgb(23, 190, 207)'/%3E%3Cpath class='markmap-link' data-depth='2' data-path='1.12' d='M136,11.25C176,11.25,176,260.563,216,260.563' stroke-width='1.75' stroke='rgb(255, 127, 14)'/%3E%3Cg class='markmap-highlight'/%3E%3Cg data-depth='3' data-path='1.2.3' class='markmap-node' transform='translate(412, -286.0625)'%3E%3Cline stroke='%232ca02c' stroke-width='1.375' x1='-1' x2='104' y1='20.6875' y2='20.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='86' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3EPython 3.7+%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='3' data-path='1.2.4' class='markmap-node' transform='translate(412, -259.6875)'%3E%3Cline stroke='%23d62728' stroke-width='1.375' x1='-1' x2='104' y1='20.6875' y2='20.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='86' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3ENode.js 14+%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='3' data-path='1.2.5' class='markmap-node' transform='translate(412, -233.3125)'%3E%3Cline stroke='%239467bd' stroke-width='1.375' x1='-1' x2='198' y1='20.6875' y2='20.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='180' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3EC%3Cins%3E17 compiler (g%3C/ins%3E/clang++)%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='2' data-path='1.2' class='markmap-node' transform='translate(216, -259.6875)'%3E%3Cline stroke='%23ff7f0e' stroke-width='1.75' x1='-1' x2='118' y1='20.875' y2='20.875'/%3E%3Ccircle stroke-width='1.5' r='6' stroke='%23ff7f0e' fill='var(--markmap-circle-open-bg)' cx='116' cy='20.875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='100' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3ERequirements%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='3' data-path='1.6.7' class='markmap-node' transform='translate(403, -201.9375)'%3E%3Cline stroke='%23e377c2' stroke-width='1.375' x1='-1' x2='694' y1='130.6875' y2='130.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='676' height='130'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Ctable data-lines='11,18'%3E
%3Cthead data-lines='11,12'%3E
%3Ctr data-lines='11,12'%3E
%3Cth%3ETool%3C/th%3E
%3Cth%3EDescription%3C/th%3E
%3Cth%3EUsage%3C/th%3E
%3C/tr%3E
%3C/thead%3E
%3Ctbody data-lines='13,18'%3E
%3Ctr data-lines='13,14'%3E
%3Ctd%3E%3Ccode%3Eport_scanner.py%3C/code%3E%3C/td%3E
%3Ctd%3EAsync TCP/UDP scanner%3C/td%3E
%3Ctd%3E%3Ccode%3Epython3 port_scanner.py 192.168.1.1 -p 1-1024%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='14,15'%3E
%3Ctd%3E%3Ccode%3Ehash_identifier.py%3C/code%3E%3C/td%3E
%3Ctd%3EHash ID + cracker%3C/td%3E
%3Ctd%3E%3Ccode%3Epython3 hash_identifier.py &lt;hash&gt; -w wordlist.txt%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='15,16'%3E
%3Ctd%3E%3Ccode%3Esubdomain_enum.py%3C/code%3E%3C/td%3E
%3Ctd%3EDNS subdomain enum%3C/td%3E
%3Ctd%3E%3Ccode%3Epython3 subdomain_enum.py example.com -w subs.txt%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='16,17'%3E
%3Ctd%3E%3Ccode%3Epassword_analyzer.py%3C/code%3E%3C/td%3E
%3Ctd%3EPassword strength check%3C/td%3E
%3Ctd%3E%3Ccode%3Epython3 password_analyzer.py 'MyP@ssw0rd'%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='17,18'%3E
%3Ctd%3E%3Ccode%3Eforensics_toolkit.py%3C/code%3E%3C/td%3E
%3Ctd%3EFile forensics%3C/td%3E
%3Ctd%3E%3Ccode%3Epython3 forensics_toolkit.py file.bin%3C/code%3E%3C/td%3E
%3C/tr%3E
%3C/tbody%3E
%3C/table%3E%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='2' data-path='1.6' class='markmap-node' transform='translate(216, -146.9375)'%3E%3Cline stroke='%238c564b' stroke-width='1.75' x1='-1' x2='109' y1='20.875' y2='20.875'/%3E%3Ccircle stroke-width='1.5' r='6' stroke='%238c564b' fill='var(--markmap-circle-open-bg)' cx='107' cy='20.875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='91' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3EPython Tools%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='3' data-path='1.8.9' class='markmap-node' transform='translate(428, -60.5625)'%3E%3Cline stroke='%23bcbd22' stroke-width='1.375' x1='-1' x2='567' y1='87.6875' y2='87.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='549' height='87'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Ctable data-lines='21,26'%3E
%3Cthead data-lines='21,22'%3E
%3Ctr data-lines='21,22'%3E
%3Cth%3ETool%3C/th%3E
%3Cth%3EDescription%3C/th%3E
%3Cth%3EUsage%3C/th%3E
%3C/tr%3E
%3C/thead%3E
%3Ctbody data-lines='23,26'%3E
%3Ctr data-lines='23,24'%3E
%3Ctd%3E%3Ccode%3Epayload_generator.js%3C/code%3E%3C/td%3E
%3Ctd%3EXSS/SQLi payloads%3C/td%3E
%3Ctd%3E%3Ccode%3Enode payload_generator.js xss wafBypass%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='24,25'%3E
%3Ctd%3E%3Ccode%3Erecon.js%3C/code%3E%3C/td%3E
%3Ctd%3EReconnaissance%3C/td%3E
%3Ctd%3E%3Ccode%3Enode recon.js all example.com%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='25,26'%3E
%3Ctd%3E%3Ccode%3Ejwt_tool.js%3C/code%3E%3C/td%3E
%3Ctd%3EJWT analyzer%3C/td%3E
%3Ctd%3E%3Ccode%3Enode jwt_tool.js analyze &lt;token&gt;%3C/code%3E%3C/td%3E
%3C/tr%3E
%3C/tbody%3E
%3C/table%3E%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='2' data-path='1.8' class='markmap-node' transform='translate(216, -27.0625)'%3E%3Cline stroke='%237f7f7f' stroke-width='1.75' x1='-1' x2='134' y1='20.875' y2='20.875'/%3E%3Ccircle stroke-width='1.5' r='6' stroke='%237f7f7f' fill='var(--markmap-circle-open-bg)' cx='132' cy='20.875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='116' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3EJavaScript Tools%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='3' data-path='1.10.11' class='markmap-node' transform='translate(384, 37.8125)'%3E%3Cline stroke='%231f77b4' stroke-width='1.375' x1='-1' x2='694' y1='87.6875' y2='87.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='676' height='87'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Ctable data-lines='29,34'%3E
%3Cthead data-lines='29,30'%3E
%3Ctr data-lines='29,30'%3E
%3Cth%3ETool%3C/th%3E
%3Cth%3EDescription%3C/th%3E
%3Cth%3ECompile%3C/th%3E
%3C/tr%3E
%3C/thead%3E
%3Ctbody data-lines='31,34'%3E
%3Ctr data-lines='31,32'%3E
%3Ctd%3E%3Ccode%3Ecrypto_tools.cpp%3C/code%3E%3C/td%3E
%3Ctd%3ECrypto utilities%3C/td%3E
%3Ctd%3E%3Ccode%3Eg++ -std=c++17 -O2 -o crypto_tools crypto_tools.cpp%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='32,33'%3E
%3Ctd%3E%3Ccode%3Eport_scanner.cpp%3C/code%3E%3C/td%3E
%3Ctd%3EThreaded scanner%3C/td%3E
%3Ctd%3E%3Ccode%3Eg++ -std=c++17 -O2 -pthread -o port_scanner port_scanner.cpp%3C/code%3E%3C/td%3E
%3C/tr%3E
%3Ctr data-lines='33,34'%3E
%3Ctd%3E%3Ccode%3Ememory_scanner.cpp%3C/code%3E%3C/td%3E
%3Ctd%3EMemory forensics%3C/td%3E
%3Ctd%3E%3Ccode%3Eg++ -std=c++17 -O2 -o memory_scanner memory_scanner.cpp%3C/code%3E%3C/td%3E
%3C/tr%3E
%3C/tbody%3E
%3C/table%3E%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='2' data-path='1.10' class='markmap-node' transform='translate(216, 71.3125)'%3E%3Cline stroke='%2317becf' stroke-width='1.75' x1='-1' x2='90' y1='20.875' y2='20.875'/%3E%3Ccircle stroke-width='1.5' r='6' stroke='%2317becf' fill='var(--markmap-circle-open-bg)' cx='88' cy='20.875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='72' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3EC++ Tools%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='3' data-path='1.12.13' class='markmap-node' transform='translate(391, 136.1875)'%3E%3Cline stroke='%232ca02c' stroke-width='1.375' x1='-1' x2='358' y1='227.6875' y2='227.6875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='340' height='227'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cpre data-lines='37,49'%3E%3Ccode class='language-bash'%3E%3Cspan class='hljs-comment'%3E%23 TCP scan%3C/span%3E
python3 port_scanner.py scanme.nmap.org -p 1-1000

%3Cspan class='hljs-comment'%3E%23 Full recon%3C/span%3E
node recon.js all target.com

%3Cspan class='hljs-comment'%3E%23 Crypto analysis%3C/span%3E
./crypto_tools bruterot %3Cspan class='hljs-string'%3E'Uryyb Jbeyq'%3C/span%3E

%3Cspan class='hljs-comment'%3E%23 File forensics%3C/span%3E
python3 forensics_toolkit.py suspicious.exe%3C/code%3E%3C/pre%3E%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='2' data-path='1.12' class='markmap-node' transform='translate(216, 239.6875)'%3E%3Cline stroke='%23ff7f0e' stroke-width='1.75' x1='-1' x2='97' y1='20.875' y2='20.875'/%3E%3Ccircle stroke-width='1.5' r='6' stroke='%23ff7f0e' fill='var(--markmap-circle-open-bg)' cx='95' cy='20.875'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='79' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3EQuick Start%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3Cg data-depth='1' data-path='1' class='markmap-node' transform='translate(0, -10)'%3E%3Cline stroke='%231f77b4' stroke-width='2.5' x1='-1' x2='138' y1='21.25' y2='21.25'/%3E%3Ccircle stroke-width='1.5' r='6' stroke='%231f77b4' fill='var(--markmap-circle-open-bg)' cx='136' cy='21.25'/%3E%3CforeignObject class='markmap-foreign' x='8' y='0' style='opacity: 1;' width='120' height='20'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3E%3Cdiv xmlns='http://www.w3.org/1999/xhtml'%3ECyberSec Toolkit%3C/div%3E%3C/div%3E%3C/foreignObject%3E%3C/g%3E%3C/g%3E%3C/svg%3E
