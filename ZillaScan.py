#!/usr/bin/env python3

#You will need to add your WPScan API Token in 2 places in order for the WPScan to work.

import sys
import subprocess
import os
import re
import json
from urllib.parse import urlparse
from datetime import datetime

# ---------------- WPScan Brute-Force ----------------
# WARNING: Only run this against targets you have explicit permission to test.

PASSWORD_WORDLIST = "/usr/share/wordlists/rockyou.txt"

# Generate a timestamp for filenames
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

# Keep track of all generated files
OUTPUT_FILES = []

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
       Hackazillarex@gmail.com

    """)

def run(cmd, desc, outfile=None, live_output=True):
    print(f"\n[+] {desc}\n{'='*60}")
    if live_output:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        output_lines = []
        for raw_line in process.stdout:
            line = raw_line.decode("utf-8", errors="ignore")  # safe decode
            print(line, end="")
            output_lines.append(line)
        process.wait()
        output = "".join(output_lines)
    else:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True
        )
        output = result.stdout.decode("utf-8", errors="ignore") + \
                 result.stderr.decode("utf-8", errors="ignore")
        print(output)

    if outfile:
        with open(outfile, "w", errors="ignore") as f:
            f.write(output)
        OUTPUT_FILES.append((desc, outfile))

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
    OUTPUT_FILES.append(("Cleaned subdomains", file_path))

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
        OUTPUT_FILES.append(("FFUF extracted subdomains", output_file))
    except Exception as e:
        print(f"[!] FFUF parsing failed: {e}")

def wpscan_bruteforce(target, output_dir, users_file, password_file):
    output_file = f"{output_dir}/wpscan_bruteforce_{TIMESTAMP}.txt"
    cmd = f"wpscan --url {target} --usernames {users_file} --passwords {password_file} --random-user-agent --api-token [YOUR API TOKEN]"
    run(cmd, "WPScan Brute-Force Attack", outfile=output_file, live_output=True)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ZillaScan.py https://target.com")
        sys.exit(1)

    banner()
    target = sys.argv[1]
    domain = extract_domain(target)
    output_dir = f"output_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    # Ask user about WPScan brute-force
    while True:
        bf_choice = input("Do you want to enable WPScan brute-force? [y/N]: ").strip().lower()
        if bf_choice in ["y", "yes"]:
            ENABLE_WPSCAN_BRUTEFORCE = True
            break
        elif bf_choice in ["n", "no", ""]:
            ENABLE_WPSCAN_BRUTEFORCE = False
            break
        else:
            print("Please answer 'y' or 'n'.")

    # 1. DNS Records
    run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=f"{output_dir}/dig_{TIMESTAMP}.txt")

    # 2. Subfinder
    subfinder_file = f"{output_dir}/subdomains_{TIMESTAMP}.txt"
    run(f"subfinder -d {domain} -silent", "Subdomain Enumeration (Subfinder)", outfile=subfinder_file)
    clean_subdomains(subfinder_file)

    # 3. theHarvester
    harvester_raw_file = f"{output_dir}/harvester_{TIMESTAMP}.txt"
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun", "Email/Host Recon (theHarvester)", outfile=harvester_raw_file)

    harvester_hosts_file = f"{output_dir}/harvester_hosts_{TIMESTAMP}.txt"
    harvester_emails_file = f"{output_dir}/harvester_emails_{TIMESTAMP}.txt"

    hosts, emails = set(), set()
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

    OUTPUT_FILES.append(("Harvester hosts", harvester_hosts_file))
    OUTPUT_FILES.append(("Harvester emails", harvester_emails_file))

    # 4. Nmap
    run(f"nmap -sC -sV -T4 -A -p- {domain}", "Full Port and Service Scan (Nmap)", outfile=f"{output_dir}/nmap_{TIMESTAMP}.txt")

    # 5. Ncat
    common_ports = [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
    for port in common_ports:
        run(f"echo '' | ncat {domain} {port} -w 3", f"Ncat Banner Grab on Port {port}", outfile=f"{output_dir}/ncat_{port}_{TIMESTAMP}.txt")

    # 6. FFUF (JSON output + clean)
    ffuf_json_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.json"
    ffuf_clean_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.txt"
    ffuf_wordlist = "/usr/share/wordlists/dirb/common.txt"
    run(f"ffuf -u http://FUZZ.{domain} -w {ffuf_wordlist} -t 40 -mc 200,301,302 -o {ffuf_json_file} -of json", "Subdomain Fuzzing (FFUF)")
    extract_ffuf_subdomains(ffuf_json_file, ffuf_clean_file)

    # 7. Gobuster
    run(f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 40 -b 404,403", "Directory Brute-Force (Gobuster)", outfile=f"{output_dir}/gobuster_{TIMESTAMP}.txt")

    # 8. Nuclei (live + filtered output)
    nuclei_raw_file = f"{output_dir}/nuclei_raw_{TIMESTAMP}.txt"
    nuclei_filtered_file = f"{output_dir}/nuclei_{TIMESTAMP}.txt"
    run(f"nuclei -u {target} -severity high,critical -v", "Vulnerability Scan (Nuclei)", outfile=nuclei_raw_file, live_output=True)

    with open(nuclei_raw_file, "r", errors="ignore") as f_in, open(nuclei_filtered_file, "w") as f_out:
        for line in f_in:
            line = line.strip()
            if line != "" and not line.startswith("WRN"):
                f_out.write(line + "\n")
    OUTPUT_FILES.append(("Filtered Nuclei results", nuclei_filtered_file))

    # 9. SQLMap
    run(f"sqlmap -u {target} --dump-all --batch --level=2 --risk=2 --crawl=3", "SQL Injection Discovery (SQLMap)", outfile=f"{output_dir}/sqlmap_{TIMESTAMP}.txt")

    # 10. WhatWeb
    run(f"whatweb {target}", "Web Fingerprinting (WhatWeb)", outfile=f"{output_dir}/whatweb_{TIMESTAMP}.txt")

    # 11. WPScan (enumeration)
    wpscan_users_file = f"{output_dir}/wpscan_users_{TIMESTAMP}.txt"
    run(f"wpscan --url {target} --enumerate u,vt,vp,tt,cb,dbe --ignore-main-redirect --random-user-agent --api-token [YOUR API TOKEN]",
        "WordPress Vulnerability Scan (WPScan)", outfile=f"{output_dir}/wpscan_{TIMESTAMP}.txt")

    # Optional WPScan brute-force
    if ENABLE_WPSCAN_BRUTEFORCE:
        wpscan_bruteforce(target, output_dir, wpscan_users_file, PASSWORD_WORDLIST)

    # Write master summary file
    summary_file = f"{output_dir}/summary_{TIMESTAMP}.txt"
    with open(summary_file, "w") as f:
        f.write("==== ZillaScan Summary ====\n")
        f.write(f"Target: {target}\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Timestamp: {TIMESTAMP}\n\n")
        for desc, path in OUTPUT_FILES:
            f.write(f"[{desc}] -> {path}\n")

    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")
    print(f"[+] Master summary file: {summary_file}")

if __name__ == "__main__":
    main()
