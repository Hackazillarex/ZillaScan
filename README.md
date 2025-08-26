# 🛡️ ZillaScan – Automated Pentesting Toolkit
![banner](https://img.shields.io/badge/created%20by-Hackazillarex-blue?style=flat-square)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Latest Release](https://img.shields.io/github/v/release/yourusername/ZillaScan)

> An all-in-one automated reconnaissance and vulnerability scanning script for ethical hacking and security assessments.

---

## ⚙️ What is ZillaScan?

**ZillaScan** is a Python-based automation script that streamlines reconnaissance, vulnerability detection, web application testing, and even provides AI-assisted pentesting recommendations. It combines some of the most powerful pentesting tools into a single workflow, giving security professionals and ethical hackers a one-command toolkit for their assessments.

---

## 🚀 Features

| Feature | Tool | Badge |
|---------|------|-------|
| DNS Enumeration | `dig` | ![dig](https://img.shields.io/badge/DNS-dig-blue) |
| Subdomain Enumeration | `subfinder`, `ffuf` | ![subfinder](https://img.shields.io/badge/Subdomain-subfinder-yellow) |
| Email & Host Recon | `theHarvester` | ![theHarvester](https://img.shields.io/badge/Email-theHarvester-green) |
| Port & Service Scan | `nmap` | ![nmap](https://img.shields.io/badge/Port-nmap-red) |
| Banner Grabbing | `ncat` | ![ncat](https://img.shields.io/badge/Banner-ncat-orange) |
| Directory & Subdomain Fuzzing | `gobuster`, `ffuf` | ![ffuf](https://img.shields.io/badge/Fuzzing-ffuf-purple) |
| Vulnerability Scanning | `nuclei` | ![nuclei](https://img.shields.io/badge/Vuln-nuclei-lightblue) |
| SQL Injection Testing | `sqlmap` | ![sqlmap](https://img.shields.io/badge/SQL-sqlmap-darkgreen) |
| WordPress Audit | `wpscan` | ![wpscan](https://img.shields.io/badge/WordPress-wpscan-pink) |
| Tech Stack & CMS Fingerprinting | `whatweb` | ![whatweb](https://img.shields.io/badge/Tech-whatweb-lightgrey) |
| AI-Powered Recommendations | `OpenAI GPT` | ![gpt](https://img.shields.io/badge/GPT-Recommendations-purple) |

All output is saved in `output_<target-domain>/` for clean, organized results.

---

## 🧪 Example Usage

```bash
python3 ZillaScan.py https://target.com


During execution, you can select which tools to run or choose to run all. After scanning, you will be prompted if you want GPT-generated pentest recommendations.

⚙️ Installation & Setup

Ensure all dependencies are installed:
# Essential Linux tools
sudo apt install nmap ncat dirb sqlmap -y

# FFUF
sudo apt install ffuf -y

# Gobuster
sudo apt install gobuster -y

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


🔑 Configuration
API Keys

OpenAI API Key (for GPT recommendations)

WPScan API Key (for authenticated WPScan scans)
Set your keys via environment variables:
export OPENAI_API_KEY="sk-your-openai-key"
export WPSCAN_API_KEY="your-wpscan-key"

Optionally, you can update the GPT model in the script:
DEFAULT_GPT_MODEL = "gpt-4o-mini"

⚠️ Legal Notice

ZillaScan is intended for ethical hacking and authorized security testing only.
Do not use this tool against targets you do not own or have explicit permission to test. Unauthorized testing is illegal and can have serious consequences.

📂 Output Structure

All results are organized into a directory named:
output_<target-domain>/

Inside this directory, you'll find files for each scan:

dig_<timestamp>.txt – DNS records

subdomains_<timestamp>.txt – Subdomain enumeration

harvester_hosts_<timestamp>.txt / harvester_emails_<timestamp>.txt – Passive recon results

nmap_<timestamp>.txt – Port and service scan

ncat_<port>.txt – Banner grabs

ffuf_subdomains_<timestamp>.txt – Fuzzed subdomains

gobuster_<timestamp>.txt – Directory brute-force results

nuclei_<timestamp>.txt – Filtered vulnerability scan results

sqlmap_<timestamp> – SQL injection findings

wpscan_report_<timestamp>.txt – WordPress scan results

report_<timestamp>.json – Combined JSON report

recommendations_<timestamp>.txt – GPT pentesting recommendations (if enabled)

💡 Notes

WPScan brute-force is optional and will prompt during execution.

Nuclei outputs are filtered to remove non-critical warnings (WRN lines).

FFUF output is parsed from JSON into a clean subdomain list.

GPT recommendations summarize findings and suggest next steps for pentesting.

🐉 Credits

Created and maintained by Hackazillarex
Automated pentesting made simple.


