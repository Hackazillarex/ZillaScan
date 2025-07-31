# 🛡️ ZillaScan – Automated Pentesting Toolkit
![banner](https://img.shields.io/badge/created%20by-Hackazillarex-blue?style=flat-square)
> An all-in-one automated reconnaissance and vulnerability scanning script for ethical hacking and security assessments.

---

## ⚙️ What is ZillaScan?

**ZillaScan** is a Python-based automation script that streamlines the process of information gathering, vulnerability detection, and web application reconnaissance. It ties together some of the most powerful tools in offensive security to give you an easy one-command pentesting workflow.

---

## 🚀 Features

- 🧠 DNS enumeration via `dig`
- 🔍 Subdomain enumeration with `subfinder`
- 📧 Email & passive recon with `theHarvester`
- 🔎 Port & service scan using `nmap`
- 🎯 Banner grabbing with `ncat`
- 🔓 Directory brute-forcing via `gobuster`
- 🚨 Vulnerability scanning via `nuclei`
- 🩻 SQL injection testing using `sqlmap`
- 🔐 WordPress vulnerability audit with `wpscan`
- 🧬 Tech stack & CMS fingerprinting using `whatweb`

All output is saved to a clean directory: `output_<target-domain>/`

---

## 🧪 Example Usage

```bash
python3 ZillaScan.py https://target.com
