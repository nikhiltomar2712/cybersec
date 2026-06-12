# 📚 Cybersecurity Learning Resources

A curated, categorized list of high-quality resources for cybersecurity learners.
All resources listed here are free or have free tiers unless marked with 💰.

> Last updated: 2026 · Maintained by [@nikhiltomar2712](https://github.com/nikhiltomar2712)

---

## 🌐 Practice Platforms

| Platform | Best For | Cost |
|---|---|:---:|
| [TryHackMe](https://tryhackme.com) | Beginners to intermediate, guided paths | Free / 💰 |
| [Hack The Box](https://hackthebox.com) | Intermediate to advanced, CTF-style | Free / 💰 |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Web application security | Free |
| [PentesterLab](https://pentesterlab.com) | Web app & code review | Free / 💰 |
| [VulnHub](https://vulnhub.com) | Offline VM-based practice | Free |
| [PicoCTF](https://picoctf.org) | CTF competitions for students | Free |
| [CTFtime](https://ctftime.org) | CTF competition calendar & archive | Free |
| [OverTheWire](https://overthewire.org/wargames/) | Linux & networking wargames | Free |
| [HackThisSite](https://www.hackthissite.org) | Classic beginner challenges | Free |
| [OWASP WebGoat](https://owasp.org/www-project-webgoat/) | Deliberately vulnerable web app | Free |
| [DVWA](https://dvwa.co.uk) | Local vulnerable web app for testing | Free |

---

## 📖 Documentation & References

| Resource | Description |
|---|---|
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | Most critical web application risks |
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary tactics & techniques framework |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Defensive countermeasure framework |
| [CVE Database](https://cve.mitre.org/) | Common Vulnerabilities and Exposures |
| [NVD (NIST)](https://nvd.nist.gov/) | National Vulnerability Database |
| [Exploit-DB](https://exploit-db.com) | Public exploit archive |
| [GTFOBins](https://gtfobins.github.io/) | Unix binary privilege escalation |
| [LOLBAS](https://lolbas-project.github.io/) | Windows "Living Off the Land" binaries |
| [HackTricks](https://book.hacktricks.xyz/) | Comprehensive pentesting methodology |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Payload & bypass cheatsheet collection |
| [SecLists](https://github.com/danielmiessler/SecLists) | Wordlists for security testing |

---

## 🎓 Certifications & Learning Paths

| Certification | Provider | Level | Notes |
|---|---|---|---|
| **CompTIA Security+** | CompTIA | Entry | Industry-recognized baseline |
| **eJPT** | eLearnSecurity | Entry | Great first pentest cert |
| **CEH** | EC-Council | Intermediate | Theory-heavy, vendor cert |
| **PNPT** | TCM Security | Intermediate | Practical, good value |
| **OSCP** | Offensive Security | Advanced | Gold standard for pentest |
| **GPEN / GWAPT** | GIAC/SANS | Advanced | Expensive but prestigious |
| **AWS Security Specialty** | AWS | Advanced | Cloud security focus |

---

## 🛠️ Essential Tools

### Reconnaissance
```
nmap          — Network scanning and service detection
theHarvester  — OSINT email/domain harvesting
Shodan        — Internet-connected device search engine
Maltego       — Visual link analysis / OSINT
Recon-ng      — Web reconnaissance framework
```

### Web Testing
```
Burp Suite    — Web proxy and vulnerability scanner
FFUF          — Fast web fuzzer
Gobuster      — Directory/DNS bruteforcing
Nikto         — Web server vulnerability scanner
SQLmap        — Automated SQL injection tool
```

### Exploitation
```
Metasploit    — Exploitation framework
Searchsploit  — Offline Exploit-DB search
MSFvenom      — Payload generation
```

### Password Attacks
```
Hydra         — Online password bruteforcing
John the Ripper — Offline password cracking
Hashcat       — GPU-accelerated hash cracking
CeWL          — Custom wordlist generator
```

### Post-Exploitation / Privesc
```
LinPEAS       — Linux privilege escalation scanner
WinPEAS       — Windows privilege escalation scanner
BloodHound    — Active Directory attack path mapping
Mimikatz      — Windows credential extraction
```

### Forensics & DFIR
```
Autopsy       — Digital forensics platform
Volatility    — Memory forensics framework
Wireshark     — Network packet analyzer
tcpdump       — CLI packet capture
Zeek          — Network security monitor
```

---

## 🎥 YouTube Channels

| Channel | Focus |
|---|---|
| [NetworkChuck](https://youtube.com/@NetworkChuck) | Networking, hacking, cloud — beginner friendly |
| [John Hammond](https://youtube.com/@_JohnHammond) | CTF walkthroughs, malware analysis |
| [TCM Security](https://youtube.com/@TCMSecurityAcademy) | Practical pentesting and PNPT prep |
| [IppSec](https://youtube.com/@ippsec) | Hack The Box machine walkthroughs |
| [LiveOverflow](https://youtube.com/@LiveOverflow) | Binary exploitation, CTF, deep dives |
| [David Bombal](https://youtube.com/@davidbombal) | Networking and ethical hacking |
| [The Cyber Mentor](https://youtube.com/@TCMSecurityAcademy) | Pentesting courses and methodology |

---

## 📰 Blogs & News

| Resource | Type |
|---|---|
| [Krebs on Security](https://krebsonsecurity.com) | Investigative cybersecurity journalism |
| [Schneier on Security](https://schneier.com) | Expert commentary and analysis |
| [The Hacker News](https://thehackernews.com) | Daily security news |
| [Dark Reading](https://darkreading.com) | Enterprise security news |
| [Portswigger Research](https://portswigger.net/research) | Web security research |
| [Google Project Zero](https://googleprojectzero.blogspot.com) | Vulnerability research blog |

---

## 📝 Cheatsheet Collections

| Resource | Description |
|---|---|
| [SANS Cheat Sheets](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/) | Wide range of security cheatsheets |
| [Red Team Cheatsheet](https://github.com/RistBS/Awesome-RedTeam-Cheatsheet) | Red team techniques reference |
| [Pentesting Cheatsheets](https://github.com/Tib3rius/Pentest-Cheatsheets) | Common pentesting commands |
| [Reverse Shell Generator](https://www.revshells.com) | Quick reverse shell payloads |

---

## 🧩 CTF Resources

| Resource | Description |
|---|---|
| [CTFtime](https://ctftime.org) | Event calendar and team rankings |
| [CyberChef](https://gchq.github.io/CyberChef/) | Encoding/decoding/analysis "Swiss Army Knife" |
| [dCode](https://www.dcode.fr/en) | Cipher and encoding toolkit |
| [FeatherDuster](https://github.com/nccgroup/featherduster) | Automated cryptanalysis |
| [StegOnline](https://stegonline.georgeom.net) | Image steganography analysis |

---

## 📦 Home Lab Setup Guides

| Resource | Description |
|---|---|
| [Setting up a Home Lab — TryHackMe](https://tryhackme.com/room/pythonfundamentals) | Getting started guide |
| [VirtualBox Download](https://www.virtualbox.org/) | Free VM hypervisor |
| [Kali Linux](https://www.kali.org/) | Penetration testing distribution |
| [Parrot OS](https://parrotsec.org/) | Lightweight security-focused OS |
| [Metasploitable 2](https://sourceforge.net/projects/metasploitable/) | Intentionally vulnerable VM |

---

*Found a broken link or have a great resource to add? See [CONTRIBUTING.md](./CONTRIBUTING.md).*
