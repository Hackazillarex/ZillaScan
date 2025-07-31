#!/usr/bin/env python3
#sudo apt install nmap ncat dirb sqlmap -y
#go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
#gem install wpscan
#sudo apt remove theharvester -y
#git clone https://github.com/laramies/theHarvester.git
#cd theHarvester
#python3 -m pip install -r requirements.txt
#sudo ln -s $(pwd)/theHarvester.py /usr/local/bin/theHarvester
#Any errors that you get, please review them, you might be missing respositories/files that I already had.



import sys
import subprocess
import os
from urllib.parse import urlparse

def banner():
    print(r"""
__________.__.__  .__           _________                     
\____    /|__|  | |  | _____   /   _____/ ____ _____    ____  
  /     / |  |  | |  | \__  \  \_____  \_/ ___\\__  \  /    \ 
 /     /_ |  |  |_|  |__/ __ \_/        \  \___ / __ \|   |  \
/_______ \|__|____/____(____  /_______  /\___  >____  /___|  /
        \/                  \/        \/     \/     \/     \/ 

        Auto Pentesting Script
      Created by Hackazillarex 🐉

    """)

# Improved runner with cleaner output
def run(cmd, desc):
    print(f"\n[+] {desc}\n{'='*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True)
    
    # Decode stdout safely, replacing undecodable bytes with �
    output = result.stdout.decode('utf-8', errors='replace').strip()
    if output:
        print(output)
    
    # Decode stderr safely, ignoring timeout errors
    error = result.stderr.decode('utf-8', errors='replace').strip()
    if error and "Ncat: TIMEOUT." not in error:
        print(f"[!] Error:\n{error}")

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 zillascan.py https://target.com")
        sys.exit(1)

    banner()
    target = sys.argv[1]
    domain = extract_domain(target)
    output_dir = f"output_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    # ✅ FIXED: Dig output inside main(), using correct DNS server
    print(f"\n[+] DNS Records (dig)\n{'='*60}")
    with open(f"{output_dir}/dig.txt", "w") as f:
        result = subprocess.run(f"dig {domain} any @8.8.8.8", shell=True, capture_output=True, text=True)
        print(result.stdout)
        f.write(result.stdout)


    # 2. Subdomain enum: subfinder
    run(f"subfinder -d {domain} -silent -o {output_dir}/subdomains.txt", "Subdomain Enumeration (Subfinder)")

    # 3. theHarvester
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun -f {output_dir}/harvester.html", "Email/Host Recon (theHarvester)")

    # 4. Nmap full scan
    run(f"nmap -sC -sV -T4 -A -p- {domain} -oN {output_dir}/nmap.txt", "Full Port and Service Scan (Nmap)")

    # 5. Ncat banner grab on common ports
    common_ports = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
    for port in common_ports:
        run(f"echo '' | ncat {domain} {port} -w 3", f"Ncat Banner Grab on Port {port}")

    # 6. Gobuster (faster than dirb)
    run(f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_dir}/gobuster.txt -t 40", "Directory Brute-Force (Gobuster)")

    # 7. Nuclei vuln scan
    run(f"nuclei -u {target} -severity high,critical -o {output_dir}/nuclei.txt", "Vulnerability Scan (Nuclei)")

    # 8. SQLMap auto SQL injection scan
    run(f"sqlmap -u {target} --dump-all --batch --level=2 --risk=2 --crawl=3 --output-dir={output_dir}/sqlmap", "SQL Injection Discovery (SQLMap)")

    # 9. WPScan (if WordPress is used)
    run(f"wpscan --url {target} --enumerate u,vp,vt --api-token **YOURAPIHERE** -f json -o {output_dir}/wpscan.json", "WordPress Vulnerability Scan (WPScan)")

    # 10. WhatWeb tech fingerprinting
    run(f"whatweb {target} --log-verbose={output_dir}/whatweb.txt", "Web Fingerprinting (WhatWeb)")

    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")

if __name__ == "__main__":
    main()
