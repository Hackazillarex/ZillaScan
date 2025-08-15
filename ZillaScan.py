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

# Improved runner with cleaner output
def run(cmd, desc):
    print(f"\n[+] {desc}\n{'='*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True)
    
    output = result.stdout.decode('utf-8', errors='replace').strip()
    if output:
        print(output)

    error = result.stderr.decode('utf-8', errors='replace').strip()
    
    # Don't treat subfinder's normal logs as an error
    if "subfinder" not in cmd and error and "Ncat: TIMEOUT." not in error:
        print(f"[!] Error:\n{error}")
    elif "subfinder" in cmd and error:
        print(error)  # Just print subfinder logs normally

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
    run(f"subfinder -d {domain} -silent -o {output_dir}/subdomains.txt 2>&1", "Subdomain Enumeration (Subfinder)")

    # 3. theHarvester
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun -f {output_dir}/harvester.html", "Email/Host Recon (theHarvester)")

    # 4. Nmap full scan
    run(f"nmap -sC -sV -T4 -A -p- {domain} -oN {output_dir}/nmap.txt", "Full Port and Service Scan (Nmap)")

    # 5. ✅ Ncat banner grab on common ports (save to file)
    ncat_output_path = os.path.join(output_dir, "ncat_results.txt")
    with open(ncat_output_path, "w") as f:
        common_ports = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
        for port in common_ports:
            desc = f"Ncat Banner Grab on Port {port}"
            print(f"\n[+] {desc}\n{'='*60}")
            result = subprocess.run(f"echo '' | ncat {domain} {port} -w 3",
                                     shell=True, capture_output=True, text=True)

            output = result.stdout.strip()
            error = result.stderr.strip()

            # Print to console
            if output:
                print(output)
            if error and "Ncat: TIMEOUT." not in error:
                print(f"[!] Error:\n{error}")

            # Save to file
            f.write(f"----- {desc} -----\n")
            if output:
                f.write(output + "\n")
            if error:
                f.write(f"[Error] {error}\n")
            f.write("\n")

    # 6. Gobuster
    run(
    f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -o {output_dir}/gobuster.txt -t 40 -b 404,403",
    "Directory Brute-Force (Gobuster)"
)

    # 7. Nuclei
    run(f"nuclei -u {target} -severity high,critical -v -o {output_dir}/nuclei.txt", "Vulnerability Scan (Nuclei)")

    # 8. SQLMap
    run(f"sqlmap -u {target} --dump-all --batch --level=2 --risk=2 --crawl=3 --output-dir={output_dir}/sqlmap", "SQL Injection Discovery (SQLMap)")

    # 9. WPScan
    run(f"wpscan --url {target} --enumerate u,vp,vt,ap,at,tt,cb,dbe --random-user-agent --api-token ftxD76Ire0dxcOkj8NPMQjtqEjnqaBOXVLxPOT6hiVw -o {output_dir}/wpscan.txt", "WordPress Vulnerability Scan (WPScan)")

    # 10. WhatWeb
    run(f"whatweb {target} --log-verbose={output_dir}/whatweb.txt", "Web Fingerprinting (WhatWeb)")

    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")


if __name__ == "__main__":
    main()
