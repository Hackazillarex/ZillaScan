#!/usr/bin/env python3
"""
ZillaScan — passive/active recon, fingerprinting & reporting toolkit.

Scope: this tool enumerates DNS, subdomains, open directories,
open ports/services, web technology fingerprints, and known-vulnerability
*detection* via Nuclei (signature/version matching only — rate-limited,
non-destructive template tags by default). It does NOT contain exploitation
or credential brute-forcing steps (no sqlmap, no wpscan). If recon or
Nuclei turns up something like a WordPress install or a confirmed CVE,
verify and remediate it yourself, separately, rather than exploiting it
here — this tool reports findings, it doesn't act on them.

Only run this against domains/hosts you own or are explicitly authorized
to test.

Don't Be A SKID!!
"""

import sys
import os
import re
import json
import shutil
import asyncio
import argparse
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin
import urllib.request
import urllib.error
import glob
import contextlib
import csv

# ---------------- Global Setup ----------------
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_DATA = {
    "target": None,
    "domain": None,
    "timestamp": TIMESTAMP,
    "started_at": None,
    "finished_at": None,
    "tools_run": [],
    "subdomains": set(),
    "directories": set(),
    "dns_records_file": None,
    "harvester_file": None,
    "tech_fingerprint_file": None,
    "port_scan_file": None,
    "ffuf_file": None,
    "gobuster_file": None,
    "vulnerabilities": [],
    "errors": [],
    "live_hosts": [],
    "screenshots_dir": None,
    "historical_urls_file": None,
    "tls_scan_file": None,
    "waf_file": None,
    "waf_detected": None,
    "diff": None,
}

MAX_EMBED_CHARS = 20000  # cap embedded raw output per section so the HTML stays sane

# Sensitive paths checked directly for accidental exposure.
SENSITIVE_PATHS = [
    (".git/HEAD", "high", "Exposed .git directory can leak full source history."),
    (".git/config", "high", "Exposed .git/config can leak repo remotes/credentials."),
    (".env", "high", "Exposed .env commonly contains secrets/credentials."),
    (".DS_Store", "low", "Exposed .DS_Store can leak local file/directory names."),
    (".htpasswd", "high", "Exposed .htpasswd can leak credential hashes."),
    (".svn/entries", "medium", "Exposed .svn metadata can leak source history."),
    ("wp-config.php.bak", "high", "Backup of WordPress config can leak DB credentials."),
    ("config.php.bak", "high", "Backup config file can leak credentials/secrets."),
    ("backup.zip", "medium", "Generic backup archive left publicly accessible."),
    (".well-known/security.txt", "info", "Informational — not a finding, just noting presence."),
]

SECURITY_HEADERS_CHECKED = {
    "Strict-Transport-Security": ("medium", "HSTS not set — allows protocol downgrade to HTTP."),
    "Content-Security-Policy": ("medium", "No CSP — reduces defense-in-depth against XSS/injection."),
    "X-Content-Type-Options": ("low", "Missing nosniff header — allows MIME-type sniffing."),
    "X-Frame-Options": ("low", "Missing — page may be embeddable in a clickjacking iframe (unless CSP frame-ancestors covers it)."),
    "Referrer-Policy": ("info", "Not set — referrer data may leak more than necessary to third parties."),
    "Permissions-Policy": ("info", "Not set — browser features (camera, geolocation, etc.) aren't explicitly restricted."),
}

# Nuclei tags considered detection-only / non-destructive by convention.
# Excludes tags like "dos", "fuzz", "intrusive" that can degrade or disrupt
# a target. Override with ZILLASCAN_NUCLEI_TAGS if you want a different set.
DEFAULT_NUCLEI_TAGS = os.getenv(
    "ZILLASCAN_NUCLEI_TAGS", "cve,misconfig,exposure,default-login,tech,ssl"
)
DEFAULT_NUCLEI_EXCLUDE_TAGS = os.getenv("ZILLASCAN_NUCLEI_EXCLUDE_TAGS", "dos,fuzz,intrusive")
DEFAULT_NUCLEI_RATE_LIMIT = os.getenv("ZILLASCAN_NUCLEI_RATE_LIMIT", "50")
# How often (seconds) nuclei prints its own progress stats (requests sent,
# matched, templates run) to stdout — this is real progress, not a generic
# heartbeat, and is what actually shows a long CVE/SSL sweep isn't stalled.
NUCLEI_STATS_INTERVAL_SEC = os.getenv("ZILLASCAN_NUCLEI_STATS_INTERVAL", "15")

# Generic manual-verification guidance, keyed by the Nuclei tag/category that
# matched. These are methodology notes for confirming a finding is real
# (checking versions, headers, response content).
# A finding can match multiple categories; all matching notes are attached.
VERIFICATION_GUIDANCE = {
    "cve": (
        "Look up the CVE ID in the template's reference link and confirm the "
        "affected version range. Check the actual running version (via the "
        "response banner/header, WhatWeb's fingerprint output, or the "
        "vendor's own version endpoint if one exists) against the advisory's "
        "affected range before reporting it as confirmed — template matches "
        "on generic strings occasionally false-positive on patched installs."
    ),
    "misconfig": (
        "Reproduce the match manually: load the flagged URL/endpoint in a "
        "browser or with a plain GET request and read the actual response — "
        "confirm it's genuinely misconfigured (e.g. an admin panel with no "
        "auth, directory listing enabled, debug mode on) rather than a "
        "custom error page that happens to match the signature."
    ),
    "exposure": (
        "Fetch the flagged path directly and confirm real sensitive content "
        "is returned (e.g. a .env, .git/config, backup file, or config dump) "
        "rather than a generic 404/catch-all page. Note exactly what's "
        "exposed so the dev team knows what to rotate or remove."
    ),
    "default-login": (
        "Do NOT attempt to log in, even with defaults — that crosses from "
        "detection into access. Confirm only that the login page/panel is "
        "reachable and correctly identified (product/version in the page "
        "matches the finding), and report that default credentials should "
        "be verified as changed by whoever owns the account, not by you."
    ),
    "tech": (
        "Cross-check against WhatWeb's fingerprint output for the same host "
        "— if both agree on the technology/version, confidence is high. If "
        "they disagree, treat it as informational until confirmed another way."
    ),
    "ssl": (
        "Re-check independently with `openssl s_client -connect host:443` "
        "or a site like Qualys SSL Labs (run manually, not scripted here) "
        "to confirm the cert/protocol/cipher issue rather than relying on "
        "the single template match."
    ),
    "panel": (
        "Confirm the panel is actually reachable and unauthenticated by "
        "loading it in a browser. Note the product/version shown for the "
        "report; don't attempt to interact with it beyond viewing the "
        "login/landing page."
    ),
    "takeover": (
        "Confirm the CNAME still points to the unclaimed service (dig/nslookup "
        "the subdomain) and that the pointed-to service returns a 'not found / "
        "not configured' page consistent with takeover. Do not actually claim "
        "the resource yourself — report the dangling CNAME and target service "
        "so the client can remove the DNS record or reclaim the resource."
    ),
    "header": (
        "Confirm by checking the response headers yourself (browser devtools "
        "Network tab, or `curl -I`) — automated header checks are reliable but "
        "worth a quick manual glance, especially if a CDN/WAF might be "
        "stripping or adding headers inconsistently across paths."
    ),
    "cors": (
        "Re-send the request with an Origin header from a domain you control "
        "and confirm the response reflects it in Access-Control-Allow-Origin "
        "(and check Access-Control-Allow-Credentials) — this is what makes it "
        "exploitable. A wildcard `*` ACAO without credentials is lower risk "
        "than a reflected-origin policy combined with credentials: true."
    ),
    "exposed-file": (
        "Fetch the flagged path directly and read the actual content returned "
        "— confirm it's real sensitive data and not a custom 404/catch-all "
        "page that happens to return HTTP 200. Note exactly what's exposed "
        "(e.g. specific secrets visible in a .env) so it can be rotated."
    ),
}
GENERIC_VERIFICATION_NOTE = (
    "Reproduce this finding manually (view the flagged request/response "
    "yourself) before including it as confirmed in the client report — "
    "signature-based matches can false-positive."
)

def build_follow_up_notes(template_id, tags_hint=""):
    """Return verification guidance strings for a finding, matched by
    template_id/tags keywords against VERIFICATION_GUIDANCE. Falls back to
    a generic note if nothing matches."""
    haystack = f"{template_id or ''} {tags_hint or ''}".lower()
    notes = [msg for key, msg in VERIFICATION_GUIDANCE.items() if key in haystack]
    return notes or [GENERIC_VERIFICATION_NOTE]
OUTPUT_FILES = []  # list of (description, path)

DEFAULT_TIMEOUT_SEC = int(os.getenv("ZILLASCAN_TIMEOUT", "600"))

THEHARVESTER_SOURCES = os.getenv(
    "ZILLASCAN_HARVESTER_SOURCES", "bing,duckduckgo,crtsh,hackertarget,threatminer,rapiddns"
)
DEFAULT_WORDLIST_CANDIDATES = [
    os.getenv("ZILLASCAN_WORDLIST", ""),
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    str(Path.home() / "wordlists" / "common.txt"),
]

# ---------------- Banner ----------------
def banner():
    print(r"""
__________.__.__  .__           _________
\____    /|__|  | |  | _____   /   _____/ ____ _____    ____
  /     / |  |  | |  | \__  \  \_____  \_/ ___\\__  \  /    \
 /     /_ |  |  |_|  |__/ __ \_/        \  \___ / __ \|   |  \
/_______ \|__|____/____(____  /_______  /\___  >____  /___|  /
        \/                  \/        \/     \/     \/     \/  v2.0

        Recon / Fingerprinting / Reporting Toolkit
                Created by Hackazillarex

[ Legal ] Run this ONLY against targets you own or are explicitly
          authorized to test. This build does not scan for or exploit
          vulnerabilities and does not brute-force credentials — it maps
          what's externally visible so you can go harden it.
          DON'T BE A SKID!!!
    """)

# ---------------- Dependency Check ----------------
def check_dependencies(tools):
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}.")
        print("    Install them, or deselect the tools that need them.")
    return missing

def find_wordlist():
    for candidate in DEFAULT_WORDLIST_CANDIDATES:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None

# ---------------- Scope confirmation ----------------
def confirm_scope(target):
    scope_file = os.getenv("ZILLASCAN_SCOPE_FILE", "").strip()
    if scope_file:
        if not os.path.isfile(scope_file):
            print(f"[!] ZILLASCAN_SCOPE_FILE is set but not found: {scope_file}")
            sys.exit(1)
        with open(scope_file, "r", errors="ignore") as f:
            allowed = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
        domain = extract_domain(target).lower()
        if domain not in allowed and target.lower() not in allowed:
            print(f"[!] '{domain}' is not listed in scope file {scope_file}. Refusing to run.")
            sys.exit(1)
        print(f"[+] Target '{domain}' confirmed against scope file.")
        return

    print(f"\n[?] You are about to scan: {target}")
    try:
        answer = input("    Hackazillarex is not responsible for how you use this tool. Confirm you own this target or are explicitly authorized to test it [y/N]: ").strip().lower()
    except EOFError:
        answer = ""
    if answer != "y":
        print("[!] Be Gone SKID! Exiting.")
        sys.exit(1)

# ---------------- Async command runner ----------------
HEARTBEAT_INTERVAL_SEC = int(os.getenv("ZILLASCAN_HEARTBEAT_INTERVAL", "30"))

async def run(cmd, desc, outfile=None, timeout=DEFAULT_TIMEOUT_SEC, live_output=True, retries=1):
    """Run a shell command asynchronously with a timeout and optional retries.

    A heartbeat prints "still running" every ZILLASCAN_HEARTBEAT_INTERVAL
    seconds (default 30) of silence, so a long-running tool with quiet output
    (e.g. nuclei with -silent) doesn't look stalled. Set the env var to a
    higher number to quiet it down, or "0" to disable it.
    """
    attempt = 0
    last_output = ""
    while attempt <= retries:
        attempt += 1
        try:
            print(f"\n[+] {desc} (attempt {attempt}/{retries + 1})\n{'=' * 60}")
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            chunks = []
            start_time = asyncio.get_event_loop().time()
            last_activity = {"t": start_time}

            async def heartbeat():
                if HEARTBEAT_INTERVAL_SEC <= 0:
                    return
                while True:
                    await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
                    now = asyncio.get_event_loop().time()
                    idle = now - last_activity["t"]
                    elapsed = int(now - start_time)
                    if idle >= HEARTBEAT_INTERVAL_SEC:
                        print(f"[*] {desc} still running... ({elapsed}s elapsed, no new output for {int(idle)}s)")
                        last_activity["t"] = now  # avoid re-printing every inner loop tick

            hb_task = asyncio.ensure_future(heartbeat())
            try:
                async def read_stream():
                    while True:
                        line = await proc.stdout.readline()
                        if not line:
                            break
                        decoded = line.decode("utf-8", errors="ignore")
                        last_activity["t"] = asyncio.get_event_loop().time()
                        if live_output:
                            print(decoded, end="")
                        chunks.append(decoded)
                await asyncio.wait_for(read_stream(), timeout=timeout)
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                print(f"[!] {desc} timed out after {timeout}s.")
                REPORT_DATA["errors"].append(f"{desc}: timed out after {timeout}s")
                last_output = "".join(chunks)
                if attempt <= retries:
                    continue
                break
            finally:
                hb_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await hb_task

            output = "".join(chunks)
            last_output = output
            if outfile:
                with open(outfile, "w", errors="ignore") as f:
                    f.write(output)
                OUTPUT_FILES.append((desc, outfile))
            return output
        except FileNotFoundError as e:
            print(f"[!] {desc} failed — command not found: {e}")
            REPORT_DATA["errors"].append(f"{desc}: command not found ({e})")
            return ""
        except Exception as e:
            print(f"[!] {desc} failed: {e}")
            REPORT_DATA["errors"].append(f"{desc}: {e}")
            if attempt <= retries:
                await asyncio.sleep(2)
                continue
            if outfile:
                OUTPUT_FILES.append((f"{desc} (FAILED)", outfile))
            return last_output
    return last_output

# ---------------- Helper Functions ----------------
def extract_domain(url):
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc or parsed.path

def clean_subdomains(file_path):
    valid_subdomain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    cleaned = set()
    if not os.path.isfile(file_path):
        return
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
    REPORT_DATA["subdomains"].update(cleaned)

def _sync_http_get(url, timeout=10, extra_headers=None, method="GET"):
    """Single non-destructive HTTP request via urllib. Returns (status, headers_dict, body_text) or (None, {}, '') on failure."""
    headers = {"User-Agent": "ZillaScan-Recon/2.0 (authorized-audit)"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="ignore")
            return resp.status, dict(resp.headers.items()), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, dict(e.headers.items()) if e.headers else {}, body
    except Exception:
        return None, {}, ""

async def http_get(url, timeout=10, extra_headers=None, method="GET"):
    """Async wrapper around _sync_http_get so built-in checks don't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _sync_http_get(url, timeout, extra_headers, method))

def add_finding(source, name, severity, matched_at, description, tags="", reference=None):
    finding = {
        "template_id": None,
        "name": name,
        "severity": severity,
        "matched_at": matched_at,
        "description": description,
        "reference": reference,
        "tags": tags,
        "follow_up": build_follow_up_notes(source, tags),
        "source": source,
    }
    REPORT_DATA["vulnerabilities"].append(finding)

# ---------------- Tool Wrappers ----------------
async def run_dig(domain, output_dir):
    outfile = f"{output_dir}/dig_{TIMESTAMP}.txt"
    await run(f"dig {domain} any @8.8.8.8", "DNS Records (dig)", outfile=outfile, timeout=30)
    REPORT_DATA["dns_records_file"] = outfile
    REPORT_DATA["tools_run"].append("dig")

async def run_subfinder(domain, output_dir):
    outfile = f"{output_dir}/subdomains_{TIMESTAMP}.txt"
    await run(f"subfinder -d {domain} -silent", "Subdomain Enumeration (Subfinder)", outfile=outfile, timeout=180, retries=1)
    clean_subdomains(outfile)
    REPORT_DATA["tools_run"].append("subfinder")

async def run_theharvester(domain, output_dir):
    outfile = f"{output_dir}/harvester_{TIMESTAMP}.txt"
    await run(
        f"theHarvester -d {domain} -b {THEHARVESTER_SOURCES}",
        "Email/Host Recon (theHarvester)",
        outfile=outfile,
        timeout=180,
        retries=1,
    )
    REPORT_DATA["harvester_file"] = outfile
    REPORT_DATA["tools_run"].append("theHarvester")

async def run_ffuf(target, output_dir):
    domain = extract_domain(target)
    if domain.startswith("www."):
        domain = domain[4:]

    wordlist = find_wordlist()
    if not wordlist:
        print("[!] No wordlist found for FFUF. Set ZILLASCAN_WORDLIST or install seclists/dirb.")
        REPORT_DATA["errors"].append("FFUF: no wordlist available")
        return

    ffuf_json_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.json"
    cmd = f"ffuf -u http://FUZZ.{domain} -w {wordlist} -t 40 -mc 200,301,302 -o {ffuf_json_file} -of json"
    await run(cmd, "Subdomain Fuzzing (FFUF)", outfile=None, live_output=False, timeout=300)

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
        ffuf_txt_file = f"{output_dir}/ffuf_subdomains_{TIMESTAMP}.txt"
        with open(ffuf_txt_file, "w") as f:
            for sub in sorted(subdomains):
                f.write(sub + "\n")
        REPORT_DATA["subdomains"].update(subdomains)
        REPORT_DATA["ffuf_file"] = ffuf_txt_file
        OUTPUT_FILES.append(("FFUF JSON Subdomains", ffuf_json_file))
        OUTPUT_FILES.append(("FFUF TXT Subdomains", ffuf_txt_file))
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] FFUF parsing failed: {e}")
        REPORT_DATA["errors"].append(f"FFUF parsing: {e}")
    finally:
        REPORT_DATA["tools_run"].append("ffuf")

async def run_gobuster(target, output_dir):
    wordlist = find_wordlist()
    if not wordlist:
        print("[!] No wordlist found for Gobuster. Set ZILLASCAN_WORDLIST or install seclists/dirb.")
        REPORT_DATA["errors"].append("Gobuster: no wordlist available")
        return

    gobuster_file = f"{output_dir}/gobuster_{TIMESTAMP}.txt"
    cmd = f"gobuster dir -u {target} -w {wordlist} -t 40 -b 404,403 -o {gobuster_file}"
    await run(cmd, "Directory Discovery (Gobuster)", outfile=None, live_output=False, timeout=300)

    try:
        if not os.path.exists(gobuster_file):
            print(f"[!] Gobuster output not found: {gobuster_file}")
            return
        with open(gobuster_file, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("/"):
                    REPORT_DATA["directories"].add(line.strip())
        REPORT_DATA["gobuster_file"] = gobuster_file
        OUTPUT_FILES.append(("Directory Discovery (Gobuster)", gobuster_file))
    except OSError as e:
        print(f"[!] Gobuster parsing failed: {e}")
        REPORT_DATA["errors"].append(f"Gobuster parsing: {e}")
    finally:
        REPORT_DATA["tools_run"].append("gobuster")

async def run_whatweb(target, output_dir):
    outfile = f"{output_dir}/whatweb_{TIMESTAMP}.txt"
    cmd = f"whatweb {target} -v > {outfile}"
    await run(cmd, "Web Fingerprinting (WhatWeb)", outfile=None, live_output=False, timeout=120)
    REPORT_DATA["tech_fingerprint_file"] = outfile
    REPORT_DATA["tools_run"].append("whatweb")
    OUTPUT_FILES.append(("Web Fingerprinting (WhatWeb)", outfile))

async def run_nmap(domain, output_dir, full=False):
    outfile = f"{output_dir}/nmap_{TIMESTAMP}.txt"
    flags = "-sC -sV -T4 -A -p-" if full else "-sC -sV -T4 --top-ports 1000"
    await run(f"nmap {flags} {domain}", "Port & Service Scan (Nmap)", outfile=outfile, timeout=1800, live_output=True)
    REPORT_DATA["port_scan_file"] = outfile
    REPORT_DATA["tools_run"].append("nmap (full)" if full else "nmap (top-1000)")

async def run_nuclei(target, output_dir):
    """
    Detection-only vulnerability scan. Uses signature/version-matching
    templates (CVE, misconfig, exposure, default-login, tech, ssl tags by
    default) and excludes disruptive tags (dos, fuzz, intrusive). Rate-limited.
    This confirms findings for a report; it does not exploit them.
    """
    json_outfile = f"{output_dir}/nuclei_{TIMESTAMP}.json"
    log_outfile = f"{output_dir}/nuclei_{TIMESTAMP}.log"

    cmd = (
        f"nuclei -u {target} "
        f"-tags {DEFAULT_NUCLEI_TAGS} -etags {DEFAULT_NUCLEI_EXCLUDE_TAGS} "
        f"-rate-limit {DEFAULT_NUCLEI_RATE_LIMIT} "
        f"-jsonl -o {json_outfile} "
        f"-stats -stats-interval {NUCLEI_STATS_INTERVAL_SEC} "
        f"-silent"
    )
    await run(cmd, "Vulnerability Detection (Nuclei)", outfile=log_outfile, timeout=900, live_output=True)

    findings = []
    if os.path.exists(json_outfile):
        try:
            with open(json_outfile, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    info = rec.get("info", {})
                    template_id = rec.get("template-id")
                    tags = info.get("tags")
                    tags_str = ",".join(tags) if isinstance(tags, list) else (tags or "")
                    findings.append({
                        "template_id": template_id,
                        "name": info.get("name"),
                        "severity": info.get("severity"),
                        "matched_at": rec.get("matched-at") or rec.get("host"),
                        "description": info.get("description"),
                        "reference": info.get("reference"),
                        "tags": tags_str,
                        "follow_up": build_follow_up_notes(template_id, tags_str),
                    })
            OUTPUT_FILES.append(("Vulnerability Detection (Nuclei) - JSON", json_outfile))
        except OSError as e:
            print(f"[!] Nuclei parsing failed: {e}")
            REPORT_DATA["errors"].append(f"Nuclei parsing: {e}")
    else:
        print("[i] Nuclei produced no JSON output (likely no matches, or nuclei isn't installed).")

    REPORT_DATA["vulnerabilities"] = findings
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda x: severity_order.get((x.get("severity") or "unknown").lower(), 5))
    if findings:
        print(f"\n[+] Nuclei confirmed {len(findings)} finding(s):")
        for f_ in findings:
            print(f"    [{ (f_.get('severity') or '?').upper() }] {f_.get('name')} @ {f_.get('matched_at')}")
            for note in f_.get("follow_up", []):
                print(f"        -> Follow-up: {note}")
    else:
        print("[+] Nuclei: no findings matched the selected templates.")
    REPORT_DATA["tools_run"].append("nuclei")

async def run_httpx_probe(target, output_dir):
    """Probe target + all discovered subdomains to find which hosts are actually
    alive, with status code/title/tech. Detection/enumeration only."""
    hosts = sorted(REPORT_DATA["subdomains"] | {extract_domain(target)})
    if not hosts:
        print("[!] No hosts to probe with httpx.")
        return
    hosts_file = f"{output_dir}/httpx_input_{TIMESTAMP}.txt"
    with open(hosts_file, "w") as f:
        f.write("\n".join(hosts))

    json_outfile = f"{output_dir}/httpx_{TIMESTAMP}.json"
    cmd = f"httpx -l {hosts_file} -silent -status-code -title -tech-detect -json -o {json_outfile}"
    await run(cmd, "Live Host Probing (httpx)", outfile=None, live_output=False, timeout=300)

    live_hosts = []
    if os.path.exists(json_outfile):
        try:
            with open(json_outfile, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    live_hosts.append({
                        "url": rec.get("url") or rec.get("input"),
                        "status_code": rec.get("status_code") or rec.get("status-code"),
                        "title": rec.get("title"),
                        "tech": rec.get("tech") or rec.get("technologies") or [],
                    })
            OUTPUT_FILES.append(("Live Host Probing (httpx)", json_outfile))
        except OSError as e:
            print(f"[!] httpx parsing failed: {e}")
            REPORT_DATA["errors"].append(f"httpx parsing: {e}")
    else:
        print("[i] httpx produced no output (no live hosts, or httpx isn't installed).")

    REPORT_DATA["live_hosts"] = live_hosts
    print(f"[+] {len(live_hosts)} live host(s) found out of {len(hosts)} probed.")
    REPORT_DATA["tools_run"].append("httpx")

async def run_screenshots(target, output_dir):
    """Screenshot live/discovered hosts for visual triage. Best-effort — gowitness's
    CLI has changed across versions, so failures here are non-fatal."""
    hosts = [h["url"] for h in REPORT_DATA.get("live_hosts", []) if h.get("url")]
    if not hosts:
        hosts = sorted(REPORT_DATA["subdomains"] | {extract_domain(target)})
    if not hosts:
        print("[!] No hosts available to screenshot.")
        return

    hosts_file = f"{output_dir}/screenshot_input_{TIMESTAMP}.txt"
    with open(hosts_file, "w") as f:
        f.write("\n".join(hosts))

    shots_dir = f"{output_dir}/screenshots_{TIMESTAMP}"
    os.makedirs(shots_dir, exist_ok=True)
    # gowitness v3+ uses "gowitness scan file", older versions use "gowitness file".
    # Try the modern syntax first; if it's not the installed version this will
    # simply fail and get logged as a non-fatal error.
    cmd = f"gowitness scan file -f {hosts_file} --screenshot-path {shots_dir} --write-db=false"
    await run(cmd, "Screenshot Capture (gowitness)", outfile=None, live_output=False, timeout=600)

    if os.listdir(shots_dir):
        REPORT_DATA["screenshots_dir"] = shots_dir
        OUTPUT_FILES.append(("Screenshots", shots_dir))
        print(f"[+] Screenshots saved to: {shots_dir}")
    else:
        print("[!] No screenshots produced — check that gowitness is installed and its CLI syntax matches your version.")
        REPORT_DATA["errors"].append("gowitness: produced no screenshots")
    REPORT_DATA["tools_run"].append("gowitness")

async def run_historical_urls(domain, output_dir):
    """Pull historical/archived URLs (Wayback Machine etc.) via gau. Passive — queries
    third-party archives, never touches the target directly."""
    outfile = f"{output_dir}/historical_urls_{TIMESTAMP}.txt"
    cmd = f"gau --subs {domain}"
    output = await run(cmd, "Historical URLs (gau)", outfile=None, live_output=False, timeout=300)
    if output.strip():
        with open(outfile, "w") as f:
            f.write(output)
        REPORT_DATA["historical_urls_file"] = outfile
        OUTPUT_FILES.append(("Historical URLs (gau)", outfile))
        url_count = len([l for l in output.splitlines() if l.strip()])
        print(f"[+] {url_count} historical URL(s) found.")
    else:
        print("[i] gau returned no historical URLs (or isn't installed).")
    REPORT_DATA["tools_run"].append("gau")

async def run_security_headers(target, output_dir):
    """Built-in check (no external tool): fetch the target and flag missing
    security-relevant response headers. Purely observational — one GET request."""
    url = target if "://" in target else f"https://{target}"
    status, headers, _ = await http_get(url, timeout=10)
    if status is None:
        print(f"[!] Security header check: could not reach {url}")
        REPORT_DATA["errors"].append(f"Security headers: could not reach {url}")
        REPORT_DATA["tools_run"].append("security-headers")
        return

    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = []
    for header_name, (severity, desc) in SECURITY_HEADERS_CHECKED.items():
        if header_name.lower() not in lower_headers:
            missing.append((header_name, severity, desc))

    for header_name, severity, desc in missing:
        add_finding(
            source="header",
            name=f"Missing security header: {header_name}",
            severity=severity,
            matched_at=url,
            description=desc,
            tags="header",
        )

    # Cookie flags
    set_cookie = lower_headers.get("set-cookie")
    if set_cookie:
        flags_missing = []
        if "secure" not in set_cookie.lower():
            flags_missing.append("Secure")
        if "httponly" not in set_cookie.lower():
            flags_missing.append("HttpOnly")
        if "samesite" not in set_cookie.lower():
            flags_missing.append("SameSite")
        if flags_missing:
            add_finding(
                source="header",
                name=f"Cookie missing flag(s): {', '.join(flags_missing)}",
                severity="low",
                matched_at=url,
                description="Session/tracking cookie set without recommended security flags.",
                tags="header",
            )

    print(f"[+] Security headers: {len(missing)} missing header(s) flagged at {url}.")
    REPORT_DATA["tools_run"].append("security-headers")

async def run_takeover_check(output_dir):
    """Dedicated subdomain-takeover detection pass via Nuclei's takeover templates.
    Passive DNS/HTTP check — confirms a dangling CNAME, does not claim the resource."""
    subdomains = sorted(REPORT_DATA["subdomains"])
    if not subdomains:
        print("[!] No subdomains to check for takeover.")
        REPORT_DATA["tools_run"].append("takeover-check")
        return

    hosts_file = f"{output_dir}/takeover_input_{TIMESTAMP}.txt"
    with open(hosts_file, "w") as f:
        f.write("\n".join(subdomains))

    json_outfile = f"{output_dir}/takeover_{TIMESTAMP}.json"
    cmd = f"nuclei -l {hosts_file} -tags takeover -jsonl -o {json_outfile} -silent"
    await run(cmd, "Subdomain Takeover Check (Nuclei)", outfile=None, live_output=False, timeout=300)

    count = 0
    if os.path.exists(json_outfile):
        try:
            with open(json_outfile, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    info = rec.get("info", {})
                    add_finding(
                        source="takeover",
                        name=info.get("name") or "Possible subdomain takeover",
                        severity=info.get("severity") or "high",
                        matched_at=rec.get("matched-at") or rec.get("host"),
                        description=info.get("description") or "Dangling DNS record pointing to an unclaimed service.",
                        tags="takeover",
                        reference=info.get("reference"),
                    )
                    count += 1
            OUTPUT_FILES.append(("Subdomain Takeover Check", json_outfile))
        except OSError as e:
            print(f"[!] Takeover check parsing failed: {e}")
            REPORT_DATA["errors"].append(f"Takeover check parsing: {e}")
    print(f"[+] Subdomain takeover check: {count} possible finding(s).")
    REPORT_DATA["tools_run"].append("takeover-check")

async def run_tls_scan(domain, output_dir):
    """TLS/SSL configuration scan via testssl.sh — weak ciphers, protocol issues,
    cert problems. Detection-only; raw output embedded in the report."""
    outfile = f"{output_dir}/tls_scan_{TIMESTAMP}.txt"
    cmd = f"testssl.sh --quiet --color 0 {domain}:443"
    await run(cmd, "TLS/SSL Configuration Scan (testssl.sh)", outfile=outfile, timeout=600)
    if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
        REPORT_DATA["tls_scan_file"] = outfile
    else:
        print("[!] testssl.sh produced no output — check it's installed (or try sslyze as an alternative).")
        REPORT_DATA["errors"].append("testssl.sh: no output produced")
    REPORT_DATA["tools_run"].append("testssl.sh")

async def run_waf_check(target, output_dir):
    """WAF/CDN fingerprinting via wafw00f — informational, helps explain if other
    scans got rate-limited/blocked."""
    outfile = f"{output_dir}/waf_{TIMESTAMP}.txt"
    cmd = f"wafw00f {target}"
    output = await run(cmd, "WAF Fingerprinting (wafw00f)", outfile=outfile, timeout=60)
    if output:
        match = re.search(r"is behind (.+?)(?:\n|$)|seems to be behind (.+?)(?:\n|$)", output, re.IGNORECASE)
        if match:
            REPORT_DATA["waf_detected"] = (match.group(1) or match.group(2) or "").strip()
        REPORT_DATA["waf_file"] = outfile
    REPORT_DATA["tools_run"].append("wafw00f")

async def run_cors_check(target, output_dir):
    """Built-in CORS misconfiguration check: sends a request with a foreign Origin
    header and checks whether it's reflected back with credentials allowed."""
    url = target if "://" in target else f"https://{target}"
    test_origin = "https://zillascan-cors-test.invalid"
    status, headers, _ = await http_get(url, timeout=10, extra_headers={"Origin": test_origin})
    if status is None:
        REPORT_DATA["tools_run"].append("cors-check")
        return

    lower_headers = {k.lower(): v for k, v in headers.items()}
    acao = lower_headers.get("access-control-allow-origin")
    acac = lower_headers.get("access-control-allow-credentials", "").lower() == "true"

    if acao == test_origin:
        severity = "high" if acac else "medium"
        add_finding(
            source="cors",
            name="CORS reflects arbitrary Origin" + (" with credentials allowed" if acac else ""),
            severity=severity,
            matched_at=url,
            description=(
                f"Response reflected our test Origin ({test_origin}) in "
                f"Access-Control-Allow-Origin"
                + (" and set Access-Control-Allow-Credentials: true, meaning any site "
                   "can make credentialed requests on behalf of a logged-in user." if acac
                   else ", which is looser than a fixed allowlist though lower risk without credentials.")
            ),
            tags="cors",
        )
        print(f"[+] CORS misconfiguration flagged at {url}.")
    else:
        print(f"[+] CORS check: no reflected-origin issue found at {url}.")
    REPORT_DATA["tools_run"].append("cors-check")

async def run_exposed_files_check(target, output_dir):
    """Built-in check for accidentally exposed sensitive files/paths — direct
    requests to a short curated list, not a brute-force wordlist run."""
    base = target if "://" in target else f"https://{target}"
    if not base.endswith("/"):
        base += "/"

    found = 0
    for path, severity, desc in SENSITIVE_PATHS:
        if severity == "info":
            continue  # security.txt presence isn't a finding, skip probing it here
        url = urljoin(base, path)
        status, headers, body = await http_get(url, timeout=8)
        if status == 200 and body.strip():
            # crude sanity check to reduce false positives from custom 200 catch-all pages
            if path == ".git/HEAD" and not body.strip().lower().startswith("ref:"):
                continue
            add_finding(
                source="exposed-file",
                name=f"Exposed sensitive path: {path}",
                severity=severity,
                matched_at=url,
                description=desc,
                tags="exposed-file",
            )
            found += 1
    print(f"[+] Exposed-file check: {found} finding(s) out of {len(SENSITIVE_PATHS)} paths checked.")
    REPORT_DATA["tools_run"].append("exposed-files-check")

# ---------------- Tool Descriptions ----------------
TOOL_DESCRIPTIONS = {
    "1": "FFUF: Fuzz subdomains to find hidden or unlisted subdomains for the target domain.",
    "2": "Gobuster: Discover directories and files exposed on the target website.",
    "3": "WhatWeb: Fingerprint technologies, frameworks, and CMS used by the website.",
    "4": "Nmap (top 1000 ports): Scan common ports and services.",
    "5": "Nmap (full -p- sweep): Slower, scans all 65535 ports — use when you need completeness.",
    "6": "Nuclei (detection-only): Confirms known CVEs/misconfigs via signature matching.",
    "7": "httpx: Probe discovered hosts to see which are actually alive (status/title/tech).",
    "8": "Screenshots (gowitness): Visual capture of live hosts for quick triage.",
    "9": "Historical URLs (gau): Pull archived/Wayback URLs for the domain. Passive, third-party archives only.",
    "10": "Security Headers (built-in): Flags missing HSTS/CSP/X-Frame-Options/cookie flags etc. One request, no extra tool.",
    "11": "Subdomain Takeover Check (Nuclei): Detects dangling CNAMEs pointing to unclaimed services.",
    "12": "TLS/SSL Scan (testssl.sh): Weak ciphers, protocol/cert issues.",
    "13": "WAF Fingerprint (wafw00f): Identifies if/which WAF sits in front of the target.",
    "14": "CORS Check (built-in): Tests whether the site reflects an arbitrary Origin header.",
    "15": "Exposed File Check (built-in): Direct checks for .git/.env/backup files left publicly accessible.",
}

def choose_tools():
    print("\n[+] Choose which tools you want to run (dig/subfinder/theHarvester always run):")
    tools = {
        "1": "FFUF (subdomain fuzzing)",
        "2": "Gobuster (directory discovery)",
        "3": "WhatWeb (fingerprinting)",
        "4": "Nmap - top 1000 ports",
        "5": "Nmap - full port sweep",
        "6": "Nuclei - vulnerability detection",
        "7": "httpx - live host probing",
        "8": "gowitness - screenshots",
        "9": "gau - historical URLs",
        "10": "Security headers (built-in)",
        "11": "Subdomain takeover check",
        "12": "TLS/SSL scan (testssl.sh)",
        "13": "WAF fingerprint (wafw00f)",
        "14": "CORS misconfiguration check (built-in)",
        "15": "Exposed file/config check (built-in)",
        "a": "Run ALL (uses top-1000 Nmap, not the full sweep)",
    }
    for key, name in tools.items():
        if key in TOOL_DESCRIPTIONS:
            print(f"  [{key}] {name} - {TOOL_DESCRIPTIONS[key]}")
        else:
            print(f"  [{key}] {name}")

    try:
        choice = input("\nEnter your choice (comma-separated, e.g. 1,3,4): ").strip()
    except EOFError:
        choice = "a"

    if choice.lower() == "a":
        return [k for k in tools.keys() if k not in ("5", "a")]

    selected = [c.strip() for c in choice.split(",") if c.strip() in tools]
    if not selected:
        print("[!] No valid choices selected. Exiting.")
        sys.exit(1)

    print("\n[+] You selected:")
    for s in selected:
        if s in TOOL_DESCRIPTIONS:
            print(f"  - {TOOL_DESCRIPTIONS[s]}")
    return selected

# ---------------- Reporting ----------------
def build_json_report(output_dir):
    json_safe = {k: (sorted(v) if isinstance(v, set) else v) for k, v in REPORT_DATA.items()}
    json_report_file = f"{output_dir}/report_{TIMESTAMP}.json"
    with open(json_report_file, "w") as f:
        json.dump(json_safe, f, indent=2)
    return json_report_file

def build_csv_report(output_dir):
    """Export all findings (vulnerabilities/headers/cors/exposed-files/takeover)
    as a flat CSV for spreadsheets or ticket trackers."""
    csv_file = f"{output_dir}/findings_{TIMESTAMP}.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["severity", "source", "name", "matched_at", "description", "tags", "reference"])
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        rows = sorted(
            REPORT_DATA["vulnerabilities"],
            key=lambda x: severity_order.get((x.get("severity") or "unknown").lower(), 5),
        )
        for v in rows:
            writer.writerow([
                v.get("severity", ""),
                v.get("source", "nuclei"),
                v.get("name", ""),
                v.get("matched_at", ""),
                v.get("description", ""),
                v.get("tags", ""),
                v.get("reference", "") or "",
            ])
    return csv_file

def build_diff(output_dir, domain):
    """Compare this run's findings/subdomains against the most recent previous
    report_*.json for the same domain in output_dir, if one exists."""
    pattern = os.path.join(output_dir, "report_*.json")
    existing = sorted(glob.glob(pattern))
    existing = [p for p in existing if TIMESTAMP not in os.path.basename(p)]
    if not existing:
        return None
    previous_file = existing[-1]
    try:
        with open(previous_file, "r", errors="ignore") as f:
            previous = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    prev_subs = set(previous.get("subdomains", []))
    cur_subs = set(REPORT_DATA["subdomains"])
    new_subdomains = sorted(cur_subs - prev_subs)

    prev_finding_keys = {(f.get("name"), f.get("matched_at")) for f in previous.get("vulnerabilities", [])}
    new_findings = [
        f for f in REPORT_DATA["vulnerabilities"]
        if (f.get("name"), f.get("matched_at")) not in prev_finding_keys
    ]

    return {
        "previous_report": previous_file,
        "previous_timestamp": previous.get("timestamp"),
        "new_subdomains": new_subdomains,
        "new_findings": new_findings,
    }

def _html_escape(text):
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

def _read_capped(path):
    """Read a file for embedding, capped to MAX_EMBED_CHARS, HTML-escaped."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
    except OSError:
        return None
    truncated = len(content) > MAX_EMBED_CHARS
    if truncated:
        content = content[:MAX_EMBED_CHARS]
    escaped = _html_escape(content)
    if truncated:
        escaped += f"\n\n... [truncated — full output in {path}]"
    return escaped or None

def build_html_report(output_dir, json_report_file):
    with open(json_report_file, "r") as f:
        data = json.load(f)

    def li(items):
        if not items:
            return "<li><em>None found</em></li>"
        return "\n".join(f"<li><code>{_html_escape(i)}</code></li>" for i in items)

    def li_vulns(items):
        if not items:
            return "<li><em>No findings matched the selected templates</em></li>"
        rows = []
        for v in items:
            sev = (v.get("severity") or "unknown").lower()
            follow_ups = v.get("follow_up") or []
            follow_up_html = ""
            if follow_ups:
                fu_items = "".join(f"<li>{_html_escape(n)}</li>" for n in follow_ups)
                follow_up_html = f'<div class="followup"><strong>Follow-up / how to verify:</strong><ul>{fu_items}</ul></div>'
            ref = v.get("reference")
            ref_html = f' &middot; <a href="{_html_escape(ref)}">{_html_escape(ref)}</a>' if ref else ""
            tags = v.get("tags")
            tags_html = f' <span class="meta">[{_html_escape(tags)}]</span>' if tags else ""
            rows.append(
                f'<li class="finding sev-{_html_escape(sev)}"><span class="badge badge-{_html_escape(sev)}">{sev.upper()}</span> '
                f"<strong>{_html_escape(v.get('name'))}</strong>{tags_html} "
                f"&mdash; <code>{_html_escape(v.get('matched_at'))}</code>{ref_html}"
                f'<br><span class="meta">{_html_escape(v.get("description")) or ""}</span>'
                f"{follow_up_html}</li>"
            )
        return "\n".join(rows)

    def raw_block(anchor_id, title, path):
        content = _read_capped(path)
        if content is None:
            return f'<h3 id="{anchor_id}">{_html_escape(title)}</h3><p class="meta">No output file (tool not run, or produced nothing).</p>'
        return (
            f'<details><summary id="{anchor_id}"><strong>{_html_escape(title)}</strong> '
            f'<span class="meta">({_html_escape(path)})</span></summary>'
            f"<pre>{content}</pre></details>"
        )

    def li_live_hosts(items):
        if not items:
            return "<li><em>None probed, or none alive</em></li>"
        rows = []
        for h in items:
            tech = h.get("tech")
            tech_str = ", ".join(tech) if isinstance(tech, list) else (tech or "")
            tech_html = f' &middot; <span class="meta">{_html_escape(tech_str)}</span>' if tech_str else ""
            rows.append(
                f'<li><code>{_html_escape(h.get("url"))}</code> '
                f'&mdash; [{_html_escape(h.get("status_code"))}] {_html_escape(h.get("title")) or ""}{tech_html}</li>'
            )
        return "\n".join(rows)

    def screenshots_gallery(shots_dir):
        if not shots_dir or not os.path.isdir(shots_dir):
            return '<p class="meta">No screenshots captured.</p>'
        images = sorted(
            f for f in os.listdir(shots_dir)
            if f.lower().endswith((".png", ".jpg", ".jpeg"))
        )
        if not images:
            return '<p class="meta">Screenshot directory exists but contains no images.</p>'
        tiles = "".join(
            f'<div class="shot"><img src="{_html_escape(os.path.relpath(os.path.join(shots_dir, img), output_dir))}" '
            f'loading="lazy" alt="{_html_escape(img)}"><div class="meta">{_html_escape(img)}</div></div>'
            for img in images
        )
        return f'<div class="shots-grid">{tiles}</div>'

    def diff_section(diff):
        if not diff:
            return '<p class="meta">No previous run found for this domain to diff against.</p>'
        new_subs = diff.get("new_subdomains", [])
        new_finds = diff.get("new_findings", [])
        parts = [f'<p class="meta">Compared against: <code>{_html_escape(diff.get("previous_report"))}</code></p>']
        parts.append(f"<h3>New Subdomains Since Last Run ({len(new_subs)})</h3><ul>{li(new_subs)}</ul>")
        parts.append(f"<h3>New Findings Since Last Run ({len(new_finds)})</h3><ul>{li_vulns(new_finds)}</ul>")
        return "\n".join(parts)

    vulns = data.get("vulnerabilities", [])
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for v in vulns:
        sev = (v.get("severity") or "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    tools_run = data.get("tools_run", [])
    started = data.get("started_at") or "n/a"
    finished = data.get("finished_at") or "n/a"

    stat_cards = "".join(
        f'<div class="stat"><div class="stat-num">{v}</div><div class="stat-label">{k.capitalize()}</div></div>'
        for k, v in severity_counts.items() if v > 0
    ) or '<div class="stat"><div class="stat-num">0</div><div class="stat-label">Findings</div></div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZillaScan Recon Report — {_html_escape(data.get('domain', ''))}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; line-height: 1.55; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
  h2 {{ margin-top: 2.5rem; border-bottom: 1px solid #8884; padding-bottom: 0.3rem; }}
  h3 {{ margin-top: 1.5rem; font-size: 1.05rem; }}
  code {{ background: #80808022; padding: 0.1rem 0.3rem; border-radius: 3px; word-break: break-all; }}
  pre {{ background: #80808014; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; white-space: pre-wrap; word-break: break-word; }}
  .meta {{ color: #888; font-size: 0.9rem; }}
  ul {{ padding-left: 1.2rem; }}
  .errors li {{ color: #c0392b; }}
  .followup {{ margin: 0.4rem 0 0.8rem 0; padding: 0.5rem 0.75rem; background: #80808014; border-left: 3px solid #8884; font-size: 0.9rem; }}
  .followup ul {{ margin: 0.25rem 0 0 0; }}
  .finding {{ margin-bottom: 1rem; }}
  .badge {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; color: #fff; }}
  .badge-critical {{ background: #8e1a1a; }}
  .badge-high {{ background: #c0392b; }}
  .badge-medium {{ background: #d68910; }}
  .badge-low {{ background: #2874a6; }}
  .badge-info, .badge-unknown {{ background: #7f8c8d; }}
  .summary-bar {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0; }}
  .stat {{ background: #80808014; border-radius: 8px; padding: 0.6rem 1rem; min-width: 90px; text-align: center; }}
  .stat-num {{ font-size: 1.4rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 0.03em; }}
  nav.toc {{ background: #80808014; border-radius: 8px; padding: 0.75rem 1.25rem; margin: 1.5rem 0; font-size: 0.9rem; }}
  nav.toc a {{ display: inline-block; margin-right: 1rem; }}
  details summary {{ cursor: pointer; padding: 0.4rem 0; }}
  .scope-note {{ background: #80808014; border-left: 3px solid #8884; padding: 0.6rem 1rem; font-size: 0.9rem; margin: 1rem 0; }}
  .shots-grid {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}
  .shot {{ width: 220px; }}
  .shot img {{ width: 100%; border-radius: 6px; border: 1px solid #8884; display: block; }}
</style>
</head>
<body>
<h1>ZillaScan Recon Report</h1>
<p class="meta">
  Target: <code>{_html_escape(data.get('target', ''))}</code> &middot;
  Domain: <code>{_html_escape(data.get('domain', ''))}</code><br>
  Started: {_html_escape(started)} &middot; Finished: {_html_escape(finished)}<br>
  Tools run: {_html_escape(", ".join(tools_run)) or "n/a"}
</p>

<div class="scope-note">
  This is a detection/enumeration report. Nuclei findings are signature/version
  matches, not confirmed exploits — verify each one manually (see the
  follow-up notes per finding) before treating it as confirmed in a
  client-facing writeup.
</div>

<nav class="toc">
  <a href="#findings">Vulnerability Findings</a>
  <a href="#subdomains">Subdomains</a>
  <a href="#live-hosts">Live Hosts</a>
  <a href="#screenshots">Screenshots</a>
  <a href="#directories">Directories</a>
  <a href="#historical-urls">Historical URLs</a>
  <a href="#dns">DNS Records</a>
  <a href="#harvester">Email/Host Recon</a>
  <a href="#fingerprint">Tech Fingerprint</a>
  <a href="#ports">Port Scan</a>
  <a href="#tls">TLS/SSL Scan</a>
  <a href="#waf">WAF Fingerprint</a>
  <a href="#diff">Diff vs Previous Run</a>
  <a href="#errors">Errors/Warnings</a>
</nav>

<h2>Executive Summary</h2>
<div class="summary-bar">
  <div class="stat"><div class="stat-num">{len(data.get('subdomains', []))}</div><div class="stat-label">Subdomains</div></div>
  <div class="stat"><div class="stat-num">{len(data.get('directories', []))}</div><div class="stat-label">Directories</div></div>
  <div class="stat"><div class="stat-num">{len(vulns)}</div><div class="stat-label">Findings</div></div>
  <div class="stat"><div class="stat-num">{len(data.get('errors', []))}</div><div class="stat-label">Errors</div></div>
</div>
<div class="summary-bar">
  {stat_cards}
</div>

<h2 id="findings">Vulnerability Findings ({len(vulns)})</h2>
<p class="meta">Detection-only (Nuclei, signature/version matching). Verify each finding manually before reporting as confirmed &mdash; no exploitation was performed.</p>
<ul>{li_vulns(vulns)}</ul>

<h2 id="subdomains">Subdomains ({len(data.get('subdomains', []))})</h2>
<ul>{li(data.get('subdomains', []))}</ul>

<h2 id="live-hosts">Live Hosts ({len(data.get('live_hosts', []))})</h2>
<p class="meta">Probed via httpx — status code, page title, and detected tech per host.</p>
<ul>{li_live_hosts(data.get('live_hosts', []))}</ul>

<h2 id="screenshots">Screenshots</h2>
{screenshots_gallery(data.get('screenshots_dir'))}

<h2 id="directories">Discovered Directories ({len(data.get('directories', []))})</h2>
<ul>{li(data.get('directories', []))}</ul>

<h2 id="historical-urls">Historical URLs</h2>
{raw_block('historical_urls_raw', 'Historical URLs (gau)', data.get('historical_urls_file'))}

<h2>Raw Tool Output</h2>
{raw_block('dns', 'DNS Records (dig)', data.get('dns_records_file'))}
{raw_block('harvester', 'Email/Host Recon (theHarvester)', data.get('harvester_file'))}
{raw_block('fingerprint', 'Web Fingerprinting (WhatWeb)', data.get('tech_fingerprint_file'))}
{raw_block('ports', 'Port & Service Scan (Nmap)', data.get('port_scan_file'))}
{raw_block('gobuster_raw', 'Directory Discovery (Gobuster) — raw', data.get('gobuster_file'))}
{raw_block('ffuf_raw', 'Subdomain Fuzzing (FFUF) — raw', data.get('ffuf_file'))}

<h2 id="tls">TLS/SSL Scan</h2>
{raw_block('tls_raw', 'TLS/SSL Configuration Scan (testssl.sh)', data.get('tls_scan_file'))}

<h2 id="waf">WAF Fingerprint</h2>
<p class="meta">Detected: <code>{_html_escape(data.get('waf_detected')) or 'none detected / not run'}</code></p>
{raw_block('waf_raw', 'WAF Fingerprinting (wafw00f) — raw', data.get('waf_file'))}

<h2 id="diff">Diff vs Previous Run</h2>
{diff_section(data.get('diff'))}

<h2 id="errors">Errors / Warnings ({len(data.get('errors', []))})</h2>
<ul class="errors">{li(data.get('errors', []))}</ul>

</body>
</html>
"""
    html_report_file = f"{output_dir}/report_{TIMESTAMP}.html"
    with open(html_report_file, "w") as f:
        f.write(html)
    return html_report_file

# ---------------- Main Execution ----------------
async def async_main(target, non_interactive_tools=None):
    domain = extract_domain(target)
    REPORT_DATA["target"] = target
    REPORT_DATA["domain"] = domain
    REPORT_DATA["started_at"] = datetime.now().isoformat(timespec="seconds")
    output_dir = f"output_{domain}"
    os.makedirs(output_dir, exist_ok=True)

    required_tools = [
        "dig", "subfinder", "theHarvester", "ffuf", "gobuster", "whatweb", "nmap", "nuclei",
        "httpx", "gowitness", "gau", "testssl.sh", "wafw00f",
    ]
    check_dependencies(required_tools)

    confirm_scope(target)

    selected_tools = non_interactive_tools if non_interactive_tools is not None else choose_tools()

    # Always-run recon (fast, passive)
    await run_dig(domain, output_dir)
    await run_subfinder(domain, output_dir)
    await run_theharvester(domain, output_dir)

    # Round 1: tools that expand the subdomain list or are fully independent —
    # run concurrently where safe.
    concurrent_tasks = []
    if "1" in selected_tools:
        concurrent_tasks.append(run_ffuf(target, output_dir))
    if "2" in selected_tools:
        concurrent_tasks.append(run_gobuster(target, output_dir))
    if "3" in selected_tools:
        concurrent_tasks.append(run_whatweb(target, output_dir))
    if "9" in selected_tools:
        concurrent_tasks.append(run_historical_urls(domain, output_dir))
    if "10" in selected_tools:
        concurrent_tasks.append(run_security_headers(target, output_dir))
    if "13" in selected_tools:
        concurrent_tasks.append(run_waf_check(target, output_dir))
    if "14" in selected_tools:
        concurrent_tasks.append(run_cors_check(target, output_dir))
    if "15" in selected_tools:
        concurrent_tasks.append(run_exposed_files_check(target, output_dir))

    if concurrent_tasks:
        await asyncio.gather(*concurrent_tasks, return_exceptions=True)

    # Round 2: hosts are now finalized (ffuf may have added subdomains) — probe
    # for live hosts and check for takeover in parallel, since neither depends
    # on the other.
    round2_tasks = []
    if "7" in selected_tools:
        round2_tasks.append(run_httpx_probe(target, output_dir))
    if "11" in selected_tools:
        round2_tasks.append(run_takeover_check(output_dir))
    if round2_tasks:
        await asyncio.gather(*round2_tasks, return_exceptions=True)

    # Round 3: screenshots benefit from httpx's live-host list if it ran.
    if "8" in selected_tools:
        await run_screenshots(target, output_dir)

    # Round 4: heavier/noisier scans against the target itself, sequential.
    if "6" in selected_tools:
        await run_nuclei(target, output_dir)
    if "12" in selected_tools:
        await run_tls_scan(domain, output_dir)
    if "4" in selected_tools:
        await run_nmap(domain, output_dir, full=False)
    if "5" in selected_tools:
        await run_nmap(domain, output_dir, full=True)

    REPORT_DATA["finished_at"] = datetime.now().isoformat(timespec="seconds")

    # Diff against the most recent previous run for this domain, if any.
    REPORT_DATA["diff"] = build_diff(output_dir, domain)

    # Summary + reports
    summary_file = f"{output_dir}/summary_{TIMESTAMP}.txt"
    with open(summary_file, "w") as f:
        f.write("==== ZillaScan Summary ====\n")
        f.write(f"Target: {target}\nDomain: {domain}\nTimestamp: {TIMESTAMP}\n\n")
        for desc, path in OUTPUT_FILES:
            f.write(f"[{desc}] -> {path}\n")
        if REPORT_DATA["errors"]:
            f.write("\n-- Errors/Warnings --\n")
            for e in REPORT_DATA["errors"]:
                f.write(f"  - {e}\n")

    json_report_file = build_json_report(output_dir)
    html_report_file = build_html_report(output_dir, json_report_file)
    csv_report_file = build_csv_report(output_dir)

    print(f"\n[+] ZillaScan complete. Output saved in: {output_dir}")
    print(f"[+] Master summary file: {summary_file}")
    print(f"[+] JSON report: {json_report_file}")
    print(f"[+] HTML report: {html_report_file}")
    print(f"[+] CSV findings export: {csv_report_file}")
    if REPORT_DATA["diff"]:
        d = REPORT_DATA["diff"]
        print(f"[+] Diff vs previous run ({d['previous_report']}): "
              f"{len(d['new_subdomains'])} new subdomain(s), {len(d['new_findings'])} new finding(s).")

def main():
    parser = argparse.ArgumentParser(description="ZillaScan — recon/fingerprinting/reporting only.")
    parser.add_argument("target", help="Target URL or domain, e.g. https://example.com")
    parser.add_argument(
        "--tools",
        help="Comma-separated tool numbers to run non-interactively (1-15), or 'a' for all. "
             "Skips the interactive menu.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive scope confirmation prompt (still requires ZILLASCAN_SCOPE_FILE "
             "or your own responsibility — use only in automated/authorized pipelines).",
    )
    args = parser.parse_args()

    banner()

    tools = None
    if args.tools:
        tools = (
            [str(n) for n in range(1, 16) if n != 5]
            if args.tools.strip().lower() == "a"
            else [t.strip() for t in args.tools.split(",")]
        )

    if args.yes:
        os.environ.setdefault("ZILLASCAN_SCOPE_FILE", os.environ.get("ZILLASCAN_SCOPE_FILE", ""))
        # --yes without a scope file still requires explicit confirmation for safety;
        # set ZILLASCAN_SCOPE_FILE to fully automate.

    try:
        asyncio.run(async_main(args.target, non_interactive_tools=tools))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()
