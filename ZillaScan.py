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

def run(cmd, desc, outfile=None):
    """
    Runs a shell command, prints output to console, and optionally saves to a file.
    Captures both stdout and stderr.
    """
    print(f"\n[+] {desc}\n{'='*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    output = result.stdout.strip()
    error = result.stderr.strip()
    
    if output:
        print(output)
    if error:
        print(f"[!] Error:\n{error}")
    
    if outfile:
        with open(outfile, "w") as f:
            if output:
                f.write(output + "\n")
            if error:
                f.write("[Error]\n" + error + "\n")

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

    # 1. DNS Records
    run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=f"{output_dir}/dig.txt")

    # 2. Subdomain enum: subfinder
    run(f"subfinder -d {domain} -silent", 
        "Subdomain Enumeration (Subfinder)", 
        outfile=f"{output_dir}/subdomains.txt")

    # 3. theHarvester
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun", 
        "Email/Host Recon (theHarvester)", 
        outfile=f"{output_dir}/harvester.txt")

    # 4. Nmap full scan
    run(f"nmap -sC -sV -T4 -A -p- {domain}", 
        "Full Port and Service Scan (Nmap)", 
        outfile=f"{output_dir}/nmap.txt")

    # 5. Ncat banner grab on common ports
    common_ports = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
    for port in common_ports:
        run(f"echo '' | ncat {domain} {port} -w 3", 
            f"Ncat Banner Grab on Port {port}", 
            outfile=f"{output_dir}/ncat_{port}.txt")
            
    # 6. FFUF - Subdomain Fuzzing
    ffuf_wordlist = "/usr/share/wordlists/dirb/common.txt"  # better for subdomains
    ffuf_output_raw = f"{output_dir}/ffuf_subdomains_raw.txt"
    ffuf_output_clean = f"{output_dir}/ffuf_subdomains.txt"

    # Run FFUF
    ffuf_cmd = f"ffuf -u http://FUZZ.{domain} -w {ffuf_wordlist} -t 40 -mc 200,301,302 -o {ffuf_output_raw} -of json"
    run(ffuf_cmd, "Subdomain Fuzzing (FFUF)")

    # Clean FFUF output to only valid subdomains
    clean_cmd = f"jq -r '.results[].url' {ffuf_output_raw} | awk -F/ '{{print $3}}' | sort -u > {ffuf_output_clean}"
    run(clean_cmd, "Cleaning FFUF Output to Valid Subdomains")


    # 7. Gobuster
    run(f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 40 -b 404,403", 
        "Directory Brute-Force (Gobuster)", 
        outfile=f"{output_dir}/gobuster.txt")

    # 8. Nuclei
    run(f"nuclei -u {target} -severity high,critical -v", 
        "Vulnerability Scan (Nuclei)", 
        outfile=f"{output_dir}/nuclei.txt")

    # 9. SQLMap
    run(f"sqlmap -u {target} --dump-all --batch --level=2 --risk=2 --crawl=3", 
        "SQL Injection Discovery (SQLMap)", 
        outfile=f"{output_dir}/sqlmap.txt")

    # 10. WPScan
    run(f"wpscan --url {target} --enumerate u,vp,vt,ap,at,tt,cb,dbe --random-user-agent --api-token ftxD76Ire0dxcOkj8NPMQjtqEjnqaBOXVLxPOT6hiVw", 
        "WordPress Vulnerability Scan (WPScan)", 
        outfile=f"{output_dir}/wpscan.txt")

    # 11. WhatWeb
    run(f"whatweb {target}", 
        "Web Fingerprinting (WhatWeb)", 
        outfile=f"{output_dir}/whatweb.txt")
        
    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")

if __name__ == "__main__":
    main()
