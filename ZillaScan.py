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

# ---------------- API KEYS ----------------
# Replace these placeholders with your actual API keys,
# or export them in your terminal for safety.
OPENAI_API_KEY = "YOUR_OPENAI_KEY_HERE"
WPSCAN_API_KEY = "YOUR_WPSCAN_KEY_HERE"

os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
os.environ["WPSCAN_API_KEY"] = WPSCAN_API_KEY

# ---- Optional GPT integration (install: pip install openai) ----
DEFAULT_GPT_MODEL = os.getenv("GPT_MODEL", "gpt-4o-mini")
OPENAI_AVAILABLE = True
try:
    from openai import OpenAI
except Exception:
    OPENAI_AVAILABLE = False
    OpenAI = None

# ---------------- Global Setup ----------------
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILES = []
SUMMARY_LOCK = Lock()
REPORT_DATA = {"subdomains": set(), "directories": set(), "vulnerabilities": [], "sqlmap": {}}
ENABLE_WPSCAN_BRUTEFORCE = False

# ---------------- Banner ----------------
def banner():
    print(r"""
__________.__.__  .__           _________                     
\____    /|__|  | |  | _____   /   _____/ ____ _____    ____  
  /     / |  |  | |  | \__  \  \_____  \_/ ___\\__  \  /    \ 
 /     /_ |  |  |_|  |__/ __ \_/        \  \___ / __ \|   |  \
/_______ \|__|____/____(____  /_______  /\___  >____  /___|  /
        \/                  \/        \/     \/     \/     \/ v1.337

        Auto Pentesting Script
      Created by Hackazillarex 🐉
       Hackazillarex@gmail.com

[ Legal ] Run this only against targets you have explicit permission to test.
    """)

# ---------------- Dependency Check ----------------
def check_dependencies(tools):
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}. Please install them first.")
        sys.exit(1)

# ---------------- Run Shell Command ----------------
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

        if outfile:
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

# ---------------- Tool Wrappers ----------------
def run_ffuf(target, output_dir):
    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]

    ffuf_json_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.json"
    ffuf_txt_file  = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.txt"
    ffuf_wordlist  = "/usr/share/wordlists/dirb/common.txt"

    cmd = f"ffuf -u http://FUZZ.{domain} -w {ffuf_wordlist} -t 40 -mc 200,301,302 -o {ffuf_json_file} -of json"
    run(cmd, "Subdomain Fuzzing (FFUF)", outfile=None, live_output=False)

    try:
        if not os.path.exists(ffuf_json_file):
            print(f"[!] FFUF JSON output not found: {ffuf_json_file}")
            return
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
    gobuster_file = f"{output_dir}/gobuster_{TIMESTAMP}.txt"
    cmd = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 40 -b 404,403 -o {gobuster_file}"
    run(cmd, "Directory Brute-Force (Gobuster)", outfile=None, live_output=False)

    try:
        if not os.path.exists(gobuster_file):
            print(f"[!] Gobuster output not found: {gobuster_file}")
            return
        with open(gobuster_file, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("/"):
                    REPORT_DATA["directories"].add(line.strip())
        with SUMMARY_LOCK:
            OUTPUT_FILES.append(("Directory Brute-Force (Gobuster)", gobuster_file))
    except Exception as e:
        print(f"[!] Gobuster parsing failed: {e}")

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

def run_sqlmap(target, output_dir):
    base_dir = f"{output_dir}/sqlmap_{TIMESTAMP}"
    os.makedirs(base_dir, exist_ok=True)

    enum_dbs_cmd = (
        f"sqlmap -u {target} --batch --level=2 --crawl=2 --risk=2 "
        f"--threads=10 --random-agent --dbs "
        f"--output-dir={base_dir} -v 1"
    )
    run(enum_dbs_cmd, "SQLMap Database Enumeration", live_output=True)

    target_folder = target.replace("://", "_")
    dump_root = os.path.join(base_dir, target_folder, "dump")
    dbs = [db for db in os.listdir(dump_root) if os.path.isdir(os.path.join(dump_root, db))] if os.path.exists(dump_root) else []
    dbs = sorted(dbs)
    REPORT_DATA["sqlmap"]["databases"] = dbs
    REPORT_DATA["sqlmap"]["tables"] = {}
    REPORT_DATA["sqlmap"]["sensitive_tables_info"] = {}
    print(f"[+] Databases found: {dbs}")
    print(f"\n[+] SQLMap scan complete. Databases enumerated only (faster mode).")

def run_wpscan(target, output_dir):
    output_file = f"{output_dir}/wpscan_report_{TIMESTAMP}.txt"
    api_token = os.getenv("WPSCAN_API_KEY", "")
    api_flag = f"--api-token {api_token}" if api_token else ""

    cmd = (
        f"wpscan --url {target} "
        f"--enumerate u,t,p --plugins-detection mixed "
        f"--random-user-agent "
        f"--disable-tls-checks "
        f"--ignore-main-redirect "
        f"--format cli "
        f"--output {output_file} "
        f"{api_flag}"
    )
    run(cmd, "WPScan Vulnerability Scan", outfile=None, live_output=False)

    try:
        if os.path.exists(output_file):
            with open(output_file, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and ("[!] " in line or "[i] " in line):
                        REPORT_DATA["vulnerabilities"].append(line)
    except Exception as e:
        print(f"[!] WPScan parsing failed: {e}")
    with SUMMARY_LOCK:
        OUTPUT_FILES.append(("WPScan Vulnerability Scan", output_file))

# ---------------- Tool Descriptions ----------------
TOOL_DESCRIPTIONS = {
    "1": "FFUF: Fuzz subdomains to find hidden or unlisted subdomains for the target domain.",
    "2": "Gobuster: Brute-force common directories and files on the target website.",
    "3": "Nuclei: Automated vulnerability scanning of web apps, looking for known issues.",
    "4": "WhatWeb: Fingerprints technologies and frameworks used by the website.",
    "5": "WPScan: Checks WordPress sites for vulnerabilities, plugins, and users.",
    "6": "Nmap: Scans ports and services to see what's open and running on the server.",
    "7": "SQLMap: Automatically detects and enumerates SQL databases on the target."
}

# ---------------- Interactive Tool Selection ----------------
def choose_tools():
    print("\n[+] Choose which tools you want to run:")
    tools = {
        "1": "FFUF (subdomain fuzzing)",
        "2": "Gobuster (directory brute-force)",
        "3": "Nuclei (vulnerability scan)",
        "4": "WhatWeb (fingerprinting)",
        "5": "WPScan (WordPress vuln scan)",
        "6": "Nmap (port & service scan)",
        "7": "SQLMap (databases only)",
        "a": "Run ALL tools"
    }

    for key, name in tools.items():
        if key in TOOL_DESCRIPTIONS:
            print(f"  [{key}] {name} - {TOOL_DESCRIPTIONS[key]}")
        else:
            print(f"  [{key}] {name}")

    choice = input("\nEnter your choice (comma-separated for multiple, e.g. 1,3,5): ").strip()

    if choice.lower() == "a":
        return list(tools.keys())[:-1]

    selected = [c.strip() for c in choice.split(",") if c.strip() in tools]
    if not selected:
        print("[!] No valid choices selected. Exiting.")
        sys.exit(1)

    print("\n[+] You selected the following tools:")
    for s in selected:
        if s in TOOL_DESCRIPTIONS:
            print(f"  - {TOOL_DESCRIPTIONS[s]}")
    return selected

# ---------------- GPT Summary Builder ----------------
def build_summary(report_data, output_dir):
    summary = {}

    subs = list(report_data.get("subdomains", []))
    if subs:
        summary["Subdomains"] = subs

    dirs = list(report_data.get("directories", []))
    if dirs:
        summary["Interesting Directories"] = dirs

    vulns = report_data.get("vulnerabilities", [])
    if vulns:
        summary["Vulnerabilities"] = vulns

    sqlmap_info = report_data.get("sqlmap", {})
    if sqlmap_info:
        if sqlmap_info.get("databases"):
            summary["Databases Found"] = sqlmap_info["databases"]
        if sqlmap_info.get("tables"):
            summary["Database Tables"] = sqlmap_info["tables"]

    return summary

# ---------------- GPT Recommendation Generator ----------------
def generate_recommendations(report_data, output_dir, model=None):
    if model is None:
        model = DEFAULT_GPT_MODEL

    if not OPENAI_AVAILABLE:
        print("[!] OpenAI client not installed. Run: pip install openai")
        return None
    if not os.getenv("OPENAI_API_KEY"):
        print("[!] OPENAI_API_KEY not set. Export your API key first.")
        return None

    structured_summary = build_summary(report_data, output_dir)

    prompt = f"""
You are a penetration testing assistant. Based on these summarized scan results,
suggest further manual and automated testing steps.

Be specific about:
- which tools to try next,
- what manual checks could be valuable,
- where privilege escalation or pivoting might be possible.

Return concise bullet points grouped by theme.
Findings:
{json.dumps(structured_summary, indent=2)}
"""

    try:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful penetration testing assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=900,
            temperature=0.4
        )

        recs = response.choices[0].message.content
        outfile = os.path.join(output_dir, f"recommendations_{TIMESTAMP}.txt")

        with open(outfile, "w") as f:
            f.write("==== GPT Pentest Recommendations ====\n\n")
            f.write(recs)

        print(f"[+] Recommendations saved: {outfile}")
        with SUMMARY_LOCK:
            OUTPUT_FILES.append(("GPT Recommendations", outfile))
        return outfile
    except Exception as e:
        print(f"[!] Failed to generate recommendations: {e}")
        return None

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

    tools = ["dig", "subfinder", "theHarvester", "nmap", "ncat", "ffuf", "gobuster", "nuclei", "whatweb", "sqlmap", "wpscan"]
    check_dependencies(tools)

    selected_tools = choose_tools()

    # DNS lookup (always run)
    run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=f"{output_dir}/dig_{TIMESTAMP}.txt")

    # Subdomain enumeration (always run)
    subfinder_file = f"{output_dir}/subdomains_{TIMESTAMP}.txt"
    run(f"subfinder -d {domain} -silent", "Subdomain Enumeration (Subfinder)", outfile=subfinder_file)
    clean_subdomains(subfinder_file)

    # Email/host recon (always run)
    harvester_raw_file = f"{output_dir}/harvester_{TIMESTAMP}.txt"
    run(f"theHarvester -d {domain} -b bing,duckduckgo,yahoo,crtsh,bufferoverun",
        "Email/Host Recon (theHarvester)", outfile=harvester_raw_file)

    # Run selected fast tools concurrently
    fast_tasks = []
    if "1" in selected_tools:
        fast_tasks.append(("FFUF Subdomain Fuzzing", lambda: run_ffuf(target, output_dir)))
    if "2" in selected_tools:
        fast_tasks.append(("Gobuster Directory Scan", lambda: run_gobuster(target, output_dir)))
    if "3" in selected_tools:
        fast_tasks.append(("Nuclei Scan", lambda: run_nuclei_scan(target, output_dir)))
    if "4" in selected_tools:
        fast_tasks.append(("WhatWeb Fingerprinting", lambda: run_whatweb(target, output_dir)))
    if "5" in selected_tools:
        fast_tasks.append(("WPScan Vulnerability Scan", lambda: run_wpscan(target, output_dir)))

    if fast_tasks:
        with ThreadPoolExecutor(max_workers=min(5, len(fast_tasks))) as executor:
            futures = {executor.submit(func): name for name, func in fast_tasks}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] {futures[future]} failed: {e}")

    # Run slower scans sequentially
    if "6" in selected_tools:
        run(f"nmap -sC -sV -T4 -A -p- {domain}", "Full Port and Service Scan (Nmap)", f"{output_dir}/nmap_{TIMESTAMP}.txt", live_output=True)

    if "7" in selected_tools:
        run_sqlmap(target, output_dir)

    # Summary files
    summary_file = f"{output_dir}/summary_{TIMESTAMP}.txt"
    with open(summary_file, "w") as f:
        f.write("==== ZillaScan Summary ====\n")
        f.write(f"Target: {target}\nDomain: {domain}\nTimestamp: {TIMESTAMP}\n\n")
        for desc, path in OUTPUT_FILES:
            f.write(f"[{desc}] -> {path}\n")

    json_safe_data = {k: list(v) if isinstance(v, set) else v for k, v in REPORT_DATA.items()}
    json_report_file = f"{output_dir}/report_{TIMESTAMP}.json"
    with open(json_report_file, "w") as f:
        json.dump(json_safe_data, f, indent=2)

    print(f"\n[+] ZillaScan Complete. Output saved in: {output_dir}")
    print(f"[+] Master summary file: {summary_file}")
    print(f"[+] Combined JSON report: {json_report_file}")

    # GPT Recommendations
    try:
        choice = input("\n[?] Do you want GPT to generate pentest recommendations based on these results? (y/n): ").strip().lower()
    except EOFError:
        choice = "n"
    if choice == "y":
        generate_recommendations(REPORT_DATA, output_dir)
    else:
        print("[i] Skipping GPT recommendations.")

if __name__ == "__main__":
    main()
