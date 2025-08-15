#!/usr/bin/env python3
#sudo apt install nmap ncat dirb sqlmap -y
#go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
#gem install wpscan
#sudo apt remove theharvester -y
#git clone https://github.com/laramies/theHarvester.git
#cd theHarvester
#python3 -m pip install -r requirements.txt
#sudo ln -s $(pwd)/theHarvester.py /usr/local/bin/theHarvester

import sys
import subprocess
import os
import re
import json
from urllib.parse import urlparse

def banner():
    print(r"""
__________.__.__  .__           _________                     
\____    /|__|  |  | _____   /   _____/ ____ _____    ____  
  /     / |  |  | |  | \__  \  \_____  \_/ ___\\__  \  /    \ 
 /     /_ |  |  |_|  |__/ __ \_/        \  \___ / __ \|   |  \
/_______ \|__|____/____(____  /_______  /\___  >____  /___|  /
        \/                  \/        \/     \/     \/     \/ 

        Auto Pentesting Script
      Created by Hackazillarex 🐉

    """)

def run(cmd, desc, outfile=None):
    print(f"\n[+] {desc}\n{'='*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, errors='ignore')
    output = result.stdout.strip()
    error = result.stderr.strip()

    if output:
        print(output)
    if error:
        print(f"[!] Error:\n{error}")

    if outfile:
        with open(outfile, "w", errors="ignore") as f:
            if output:
                f.write(output + "\n")
            if error:
                f.write("[Error]\n" + error + "\n")

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def clean_subdomains(file_path):
    valid_subdomain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    cleaned = set()
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if valid_subdomain_regex.match(line):
                cleaned.add(line.lower())
    with open(file_path, "w") as f:
        for sub in sorted(cleaned):
            f.write(sub + "\n")
    print(f"[+] Cleaned subdomains saved: {file_path}")

def extract_ffuf_subdomains(json_file, output_file):
    try:
        with open(json_file, "r", errors="ignore") as f:
            data = json.load(f)
        subdomains = set()
        for result in data.get("results", []):
            host = result.get("host")
            if host:
                subdomains.add(host.lower())
        with open(output_file, "w") as f:
            for sub in sorted(subdomains):
                f.write(sub + "\n")
        print(f"[+] Valid subdomains saved: {output_file}")
    except Exception as e:
        print(f"[!] FFUF parsing failed: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ZillaScan.py https://target.com")
        sys.exit(1)

    banner()
    target = sys.argv[1]
    domain = extract_domain(target)
    output_dir = f"output_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    # 1. DNS Records
    run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=f"{output_dir}/dig.txt")

    # 2. Subfinder
    subfinder_file = f"{output_dir}/subdomains.txt"
    run(f"subfinder -d {domain} -silent", "Subdomain Enumeration (Subfinder)", outfile=subfinder_file)
    clean_subdomains(subfinder_file)

    # 3. theHarvester
    harvester_raw_file = f"{output_dir}/harvester.txt"
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun", "Email/Host Recon (theHarvester)", outfile=harvester_raw_file)

    harvester_hosts_file = f"{output_dir}/harvester_hosts.txt"
    harvester_emails_file = f"{output_dir}/harvester_emails.txt"

    hosts = set()
    emails = set()
    with open(harvester_raw_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", line):
                hosts.add(line.lower())
            elif re.match(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", line):
                emails.add(line.lower())

    with open(harvester_hosts_file, "w") as f:
        for h in sorted(hosts):
            f.write(h + "\n")
    with open(harvester_emails_file, "w") as f:
        for e in sorted(emails):
            f.write(e + "\n")

    print(f"[+] Hosts saved: {harvester_hosts_file}")
    print(f"[+] Emails saved: {harvester_emails_file}")

    # 4. Nmap
    run(f"nmap -sC -sV -T4 -A -p- {domain}", "Full Port and Service Scan (Nmap)", outfile=f"{output_dir}/nmap.txt")

    # 5. Ncat
    common_ports = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
    for port in common_ports:
        run(f"echo '' | ncat {domain} {port} -w 3", f"Ncat Banner Grab on Port {port}", outfile=f"{output_dir}/ncat_{port}.txt")

    # 6. FFUF (JSON output + clean)
    ffuf_json_file = f"{output_dir}/ffuf_subdomains.json"
    ffuf_clean_file = f"{output_dir}/ffuf_subdomains.txt"
    ffuf_wordlist = "/usr/share/wordlists/dirb/common.txt"
    run(f"ffuf -u http://FUZZ.{domain} -w {ffuf_wordlist} -t 40 -mc 200,301,302 -o {ffuf_json_file} -of json", "Subdomain Fuzzing (FFUF)")
    extract_ffuf_subdomains(ffuf_json_file, ffuf_clean_file)

    # 7. Gobuster
    run(f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 40 -b 404,403", "Directory Brute-Force (Gobuster)", outfile=f"{output_dir}/gobuster.txt")

    # 8. Nuclei
    run(f"nuclei -u {target} -severity high,critical -v", "Vulnerability Scan (Nuclei)", outfile=f"{output_dir}/nuclei.txt")

    # 9. SQLMap
    run(f"sqlmap -u {target} --dump-all --batch --level=2 --risk=2 --crawl=3", "SQL Injection Discovery (SQLMap)", outfile=f"{output_dir}/sqlmap.txt")

    # 10. WPScan
    run(f"wpscan --url {target} --enumerate u,vt,ap,at,tt,cb,dbe --random-user-agent --api-token ftxD76Ire0dxcOkj8NPMQjtqEjnqaBOXVLxPOT6hiVw", "WordPress Vulnerability Scan (WPScan)", outfile=f"{output_dir}/wpscan.txt")

    # 11. WhatWeb
    run(f"whatweb {target}", "Web Fingerprinting (WhatWeb)", outfile=f"{output_dir}/whatweb.txt")

    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")

if __name__ == "__main__":
    main()
