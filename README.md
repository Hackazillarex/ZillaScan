# 🛡️ ZillaScan – Automated Pentesting Toolkit
![banner](https://img.shields.io/badge/created%20by-Hackazillarex-blue?style=flat-square)
> An all-in-one automated reconnaissance and vulnerability scanning script for ethical hacking and security assessments.

---

## ⚙️ What is ZillaScan?

**ZillaScan** is a Python-based automation script that streamlines reconnaissance, vulnerability detection, and web application testing. It combines some of the most powerful pentesting tools into a single workflow, giving security professionals and ethical hackers a one-command toolkit for their assessments.

---

## 🚀 Features

| Feature | Tool | Badge |
|---------|------|-------|
| DNS Enumeration | `dig` | ![dig](https://img.shields.io/badge/DNS-dig-blue) |
| Subdomain Enumeration | `subfinder`, `theHarvester` | ![subfinder](https://img.shields.io/badge/Subdomain-subfinder-yellow) |
| Email & Host Recon | `theHarvester` | ![theHarvester](https://img.shields.io/badge/Email-theHarvester-green) |
| Port & Service Scan | `nmap` | ![nmap](https://img.shields.io/badge/Port-nmap-red) |
| Banner Grabbing | `ncat` | ![ncat](https://img.shields.io/badge/Banner-ncat-orange) |
| Directory & Subdomain Fuzzing | `gobuster`, `ffuf` | ![ffuf](https://img.shields.io/badge/Fuzzing-ffuf-purple) |
| Vulnerability Scanning | `nuclei` | ![nuclei](https://img.shields.io/badge/Vuln-nuclei-lightblue) |
| SQL Injection Testing | `sqlmap` | ![sqlmap](https://img.shields.io/badge/SQL-sqlmap-darkgreen) |
| WordPress Audit | `wpscan` | ![wpscan](https://img.shields.io/badge/WordPress-wpscan-pink) |
| Tech Stack & CMS Fingerprinting | `whatweb` | ![whatweb](https://img.shields.io/badge/Tech-whatweb-lightgrey) |

All output is saved in `output_<target-domain>/` for clean, organized results.

---

## 🧪 Example Usage

```bash
python3 ZillaScan.py https://target.com

⚙️ Installation & Setup

Ensure all dependencies are installed:
# Essential Linux tools
sudo apt install nmap ncat dirb sqlmap -y

# Nuclei scanner
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# WPScan
gem install wpscan

# TheHarvester
sudo apt remove theharvester -y
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
python3 -m pip install -r requirements.txt
sudo ln -s $(pwd)/theHarvester.py /usr/local/bin/theHarvester

⚠️ Legal Notice

ZillaScan is intended for ethical hacking and authorized security testing only.
Do not use this tool against targets you do not own or have explicit permission to test. Unauthorized testing is illegal and can have serious consequences.

📂 Output Structure

All results are organized into a directory named:
output_<target-domain>/

Inside this directory, you'll find files for each scan:

dig.txt – DNS records

subdomains.txt – Subdomain enumeration

harvester_hosts.txt / harvester_emails.txt – Passive recon results

nmap.txt – Port and service scan

ncat_<port>.txt – Banner grabs

ffuf_subdomains.txt – Fuzzed subdomains

gobuster.txt – Directory brute-force results

nuclei.txt – Filtered vulnerability scan results

sqlmap.txt – SQL injection findings

wpscan.txt – WordPress scan results

💡 Notes

WPScan brute-force is optional and will prompt during execution.

Nuclei outputs are filtered to remove non-critical warnings (WRN lines).

FFUF output is parsed from JSON into a clean subdomain list.

🐉 Credits

Created and maintained by Hackazillarex
Automated pentesting made simple.
