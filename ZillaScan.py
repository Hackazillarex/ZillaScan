#!/usr/bin/env python3

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

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILES = []
SUMMARY_LOCK = Lock()
REPORT_DATA = {"subdomains": set(), "directories": set(), "vulnerabilities": [], "sqlmap": {}}

# ---------------- Banner ----------------
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

# ---------------- Dependency check ----------------
def check_dependencies(tools):
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}. Please install them first.")
        sys.exit(1)

# ---------------- Run command ----------------
def run(cmd, desc, outfile=None, live_output=True):
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

# ---------------- Helpers ----------------
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
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Cleaned subdomains", file_path))
    REPORT_DATA["subdomains"].update(cleaned)

def parse_ffuf_json(json_file):
    try:
        with open(json_file, "r", errors="ignore") as f:
            data = json.load(f)
        for result in data.get("results", []):
            host = result.get("host")
            if host:
                REPORT_DATA["subdomains"].add(host.lower())
    except Exception as e:
        print(f"[!] FFUF JSON parsing failed: {e}")

def parse_gobuster_output(gobuster_file):
    try:
        with open(gobuster_file, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("/"):
                    REPORT_DATA["directories"].add(line.strip())
    except Exception as e:
        print(f"[!] Gobuster parsing failed: {e}")

def parse_wpscan_output(wpscan_file):
    try:
        with open(wpscan_file, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and ("[!] " in line or "[i] " in line):
                    REPORT_DATA["vulnerabilities"].append(line)
    except Exception as e:
        print(f"[!] WPScan parsing failed: {e}")

# ---------------- Tool Wrappers ----------------
def run_ffuf(target, output_dir):
    ffuf_json_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.json"
    ffuf_wordlist = "/usr/share/wordlists/dirb/common.txt"
    cmd = f"ffuf -u http://FUZZ.{extract_domain(target)} -w {ffuf_wordlist} -t 40 -mc 200,301,302 -o {ffuf_json_file} -of json"
    run(cmd, "Subdomain Fuzzing (FFUF)", outfile=None, live_output=False)
    parse_ffuf_json(ffuf_json_file)
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Subdomain Fuzzing (FFUF)", ffuf_json_file))

def run_gobuster(target, output_dir):
    gobuster_file = f"{output_dir}/gobuster_{TIMESTAMP}.txt"
    cmd = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 40 -b 404,403 -o {gobuster_file}"
    run(cmd, "Directory Brute-Force (Gobuster)", outfile=None, live_output=False)
    parse_gobuster_output(gobuster_file)
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Directory Brute-Force (Gobuster)", gobuster_file))

def run_wpscan(target, output_dir):
    output_file = f"{output_dir}/wpscan_report_{TIMESTAMP}.txt"
    cmd = (
        f"wpscan --url {target} "
        f"--enumerate u,t,p --plugins-detection mixed "
        f"--random-user-agent "
        f"--disable-tls-checks "
        f"--format cli "
        f"--output {output_file} "
        f"--api-token ftxD76Ire0dxcOkj8NPMQjtqEjnqaBOXVLxPOT6hiVw"
    )
    run(cmd, "WPScan Vulnerability Scan", outfile=None, live_output=False)
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        with open(output_file, "w") as f:
            f.write("[i] WPScan completed: No vulnerabilities found.\n")
    parse_wpscan_output(output_file)
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("WPScan Vulnerability Scan", output_file))

def run_nuclei_scan(target, output_dir):
    output_file = f"{output_dir}/nuclei_{TIMESTAMP}.txt"
    cmd = f"nuclei -u {target} -severity high,critical -v -o {output_file}"
    run(cmd, "Vulnerability Scan (Nuclei)", outfile=None, live_output=False)
    if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
        with open(output_file, "w") as f:
            f.write("[i] Nuclei completed: No issues found.\n")
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Vulnerability Scan (Nuclei)", output_file))

def run_whatweb(target, output_dir):
    whatweb_file = f"{output_dir}/whatweb_{TIMESTAMP}.txt"
    cmd = f"whatweb {target} -v > {whatweb_file}"
    run(cmd, "Web Fingerprinting (WhatWeb)", outfile=None, live_output=False)
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("Web Fingerprinting (WhatWeb)", whatweb_file))

# ---------------- SQLMap ----------------
def run_sqlmap(target, output_dir):
    enum_file = f"{output_dir}/sqlmap_enum_{TIMESTAMP}.txt"
    enum_cmd = (
        f"sqlmap -u {target} --batch --level=2 --risk=2 --crawl=2 "
        f"--threads=10 --random-agent --dbs"
    )
    enum_output = run(enum_cmd, "SQLMap Database Enumeration", outfile=enum_file, live_output=True)
    dbs = [line.strip() for line in enum_output.splitlines() if line.strip() and not line.startswith("Database")]
    REPORT_DATA["sqlmap"]["databases"] = dbs
    try:
        for db in dbs:
            dump_file = f"{output_dir}/sqlmap_dump_{db}_{TIMESTAMP}.txt"
            dump_cmd = (
                f"sqlmap -u {target} --batch --level=2 --risk=2 --crawl=2 "
                f"--threads=10 --random-agent -D {db} --dump"
            )
            dump_output = run(dump_cmd, f"SQLMap Dump Database: {db}", outfile=dump_file, live_output=True)
            tables = set()
            for line in dump_output.splitlines():
                m = re.search(r'\[INFO\] Table: (\S+)', line)
                if m:
                    tables.add(m.group(1))
            REPORT_DATA["sqlmap"][db] = sorted(tables)
    except Exception as e:
        print(f"[!] SQLMap dump step failed: {e}")
        with SUMMARY_LOCK:
            OUTPUT_FILES.append(("SQLMap dump (FAILED)", dump_file))

# ---------------- Main ----------------
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ZillaScan.py https://target.com")
        sys.exit(1)

    banner()
    target = sys.argv[1]
    domain = extract_domain(target)
    output_dir = f"output_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    tools = ["dig", "subfinder", "theHarvester", "nmap", "ncat", "ffuf", "gobuster",
             "nuclei", "whatweb", "sqlmap", "wpscan"]
    check_dependencies(tools)

    # ---------------- Serial tasks ----------------
    run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=f"{output_dir}/dig_{TIMESTAMP}.txt")
    subfinder_file = f"{output_dir}/subdomains_{TIMESTAMP}.txt"
    run(f"subfinder -d {domain} -silent", "Subdomain Enumeration (Subfinder)", outfile=subfinder_file)
    clean_subdomains(subfinder_file)
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
    OUTPUT_FILES.extend([
        ("Harvester hosts", harvester_hosts_file),
        ("Harvester emails", harvester_emails_file)
    ])

    # ---------------- Parallel tasks ----------------
    tasks = []
    tasks.append(("Full Port and Service Scan (Nmap)", (f"nmap -sC -sV -T4 -A -p- {domain}", f"{output_dir}/nmap_{TIMESTAMP}.txt")))
    for port in [21,22,25,80,110,143,443,3306,8080]:
        tasks.append((f"Ncat Banner Grab Port {port}", (f"echo '' | ncat {domain} {port} -w 3", f"{output_dir}/ncat_{port}_{TIMESTAMP}.txt")))

    # Tool wrapper functions
    tasks.append(("Subdomain Fuzzing (FFUF)", lambda: run_ffuf(target, output_dir)))
    tasks.append(("Directory Brute-Force (Gobuster)", lambda: run_gobuster(target, output_dir)))
    tasks.append(("Vulnerability Scan (Nuclei)", lambda: run_nuclei_scan(target, output_dir)))
    tasks.append(("Web Fingerprinting (WhatWeb)", lambda: run_whatweb(target, output_dir)))
    tasks.append(("SQLMap Injection Scan", lambda: run_sqlmap(target, output_dir)))
    tasks.append(("WPScan Vulnerability Scan", lambda: run_wpscan(target, output_dir)))

    # Execute parallel tasks safely
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_to_task = {}
        for desc, task_item in tasks:
            if callable(task_item):
                future = executor.submit(task_item)
            else:
                cmd, outfile = task_item
                future = executor.submit(run, cmd, desc, outfile)
            future_to_task[future] = desc

        for future in as_completed(future_to_task):
            desc = future_to_task[future]
            try:
                future.result()
            except Exception as e:
                print(f"[!] {desc} failed: {e}")

    # ---------------- Combined JSON report ----------------
    combined_report_file = f"{output_dir}/combined_report_{TIMESTAMP}.json"
    combined_report_data = {
        "target": target,
        "domain": domain,
        "timestamp": TIMESTAMP,
        "subdomains": sorted(REPORT_DATA["subdomains"]),
        "directories": sorted(REPORT_DATA["directories"]),
        "vulnerabilities": REPORT_DATA["vulnerabilities"],
        "sqlmap": REPORT_DATA["sqlmap"]
    }
    with open(combined_report_file, "w") as f:
        json.dump(combined_report_data, f, indent=4)
    OUTPUT_FILES.append(("Combined JSON Report", combined_report_file))
    print(f"[+] Combined JSON report saved: {combined_report_file}")

    # ---------------- Master summary ----------------
    summary_file = f"{output_dir}/summary_{TIMESTAMP}.txt"
    with open(summary_file, "w") as f:
        f.write("==== ZillaScan Summary ====\n")
        f.write(f"Target: {target}\nDomain: {domain}\nTimestamp: {TIMESTAMP}\n\n")
        for desc, path in OUTPUT_FILES:
            f.write(f"[{desc}] -> {path}\n")

    print(f"\n[+] ZillaScan Complete. All output saved in: {output_dir}")
    print(f"[+] Master summary file: {summary_file}")

if __name__ == "__main__":
    main()
