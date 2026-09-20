# ZillaScan by Hackazillarex

A recon, fingerprinting, and detection-only reporting toolkit for authorized
web/domain security audits. Enumerates what's externally visible about a
target — DNS, subdomains, live hosts, directories, tech stack, TLS config,
historical URLs — and confirms known vulnerabilities via signature matching,
producing a client-ready HTML report alongside JSON/CSV exports.

## What this is (and isn't)

ZillaScan **detects and reports**. It does not exploit, does not
brute-force credentials, and does not dump data. Every check either
observes what's already public (DNS, certs, headers, archived URLs) or
sends a single, rate-limited, non-destructive request to confirm a
signature match (a known CVE, a missing header, a dangling CNAME).

There is no SQLMap, no WPScan, no credential brute-forcing anywhere in this
tool, unlike the previous version. If a scan turns up something like a login 
panel or a confirmed CVE, the tool stops at "here's what we found and how to
verify it" — exploiting it further is a manual, deliberate step you take yourself, 
outside the script.

**Only run this against domains/hosts you own or are explicitly authorized
to test.** The script will ask you to confirm this before every run.

## Requirements

Python 3.8+, plus whichever of the following command-line tools you want to
use (the script checks for these and skips/warns on anything missing —
nothing hard-fails except needing Python itself):

| Tool | Used for |
|---|---|
| `dig` | DNS record lookup |
| `subfinder` | Subdomain enumeration |
| `theHarvester` | Email/host OSINT |
| `ffuf` | Subdomain fuzzing |
| `gobuster` | Directory discovery |
| `whatweb` | Tech/CMS fingerprinting |
| `nmap` | Port & service scanning |
| `nuclei` | Vulnerability detection + subdomain takeover templates |
| `httpx` (ProjectDiscovery) | Live-host probing |
| `gowitness` | Screenshot capture |
| `gau` | Historical/archived URL collection |
| `testssl.sh` | TLS/SSL configuration scanning |
| `wafw00f` | WAF/CDN fingerprinting |

Security header checks, the CORS check, and the exposed-file check are
built in with Python's standard library (`urllib`) — no extra tool needed.

Install whatever's missing via your package manager, `go install`, or `pip`
depending on the tool (most of the ProjectDiscovery tools — `subfinder`,
`httpx`, `nuclei` — install via `go install github.com/projectdiscovery/...`).

## Usage

```bash
python3 ZillaScan.py https://target.com
```

You'll be shown a menu and asked to confirm you're authorized to test the
target before anything runs. `dig`, `subfinder`, and `theHarvester` always
run (they're fast and fully passive); everything else is opt-in.

### Menu

| # | Tool | What it does |
|---|---|---|
| 1 | FFUF | Subdomain fuzzing |
| 2 | Gobuster | Directory discovery |
| 3 | WhatWeb | Tech/CMS fingerprinting |
| 4 | Nmap (top 1000 ports) | Port & service scan |
| 5 | Nmap (full `-p-` sweep) | All 65535 ports — slow, opt-in only, not included in "run all" |
| 6 | Nuclei | Vulnerability detection (CVEs, misconfigs, exposures, default logins, tech, SSL) |
| 7 | httpx | Probes discovered hosts for which are actually alive (status/title/tech) |
| 8 | gowitness | Screenshots live hosts |
| 9 | gau | Historical/archived URLs |
| 10 | Security headers *(built-in)* | Flags missing HSTS/CSP/X-Frame-Options/cookie flags |
| 11 | Subdomain takeover check | Nuclei's takeover templates against discovered subdomains |
| 12 | testssl.sh | TLS/SSL cipher, protocol, and cert issues |
| 13 | wafw00f | Identifies WAF/CDN in front of the target |
| 14 | CORS check *(built-in)* | Tests whether the site reflects an arbitrary `Origin` header |
| 15 | Exposed file check *(built-in)* | Direct checks for `.git/`, `.env`, backup files, etc. (a short curated list, not a wordlist brute-force) |
| a | Run all | Everything except the full Nmap sweep (option 5) |

### Non-interactive / scripted use

```bash
python3 ZillaScan.py https://target.com --tools 1,3,6,10
python3 ZillaScan.py https://target.com --tools a
```

`--tools` skips the menu. `--yes` skips the interactive scope-confirmation
prompt — use it only in an automated pipeline where `ZILLASCAN_SCOPE_FILE`
(below) is enforcing scope, not as a way to bypass the confirmation
entirely.

## Configuration (environment variables)

All optional — sane defaults are built in.

| Variable | Default | Purpose |
|---|---|---|
| `ZILLASCAN_SCOPE_FILE` | *(unset)* | Path to a file listing authorized domains (one per line, `#` comments allowed). If set, the target must appear in it or the script refuses to run — use this for automated/CI runs. |
| `ZILLASCAN_WORDLIST` | *(auto-detected)* | Wordlist path for FFUF/Gobuster. Falls back to common dirb/seclists locations if unset. |
| `ZILLASCAN_TIMEOUT` | `600` (seconds) | Per-tool timeout before a command is killed. |
| `ZILLASCAN_NUCLEI_TAGS` | `cve,misconfig,exposure,default-login,tech,ssl` | Which Nuclei template categories to run. |
| `ZILLASCAN_NUCLEI_EXCLUDE_TAGS` | `dos,fuzz,intrusive` | Template categories explicitly excluded, even if they'd otherwise match — this is what keeps the scan non-destructive. |
| `ZILLASCAN_NUCLEI_RATE_LIMIT` | `50` | Max requests/second Nuclei sends to the target. |

Example:
```bash
export ZILLASCAN_SCOPE_FILE=~/authorized_targets.txt
export ZILLASCAN_NUCLEI_RATE_LIMIT=20
python3 ZillaScan.py https://target.com --tools a --yes
```

## Output

Each run creates `output_<domain>/` containing:

- Per-tool raw output files (`dig_*.txt`, `nmap_*.txt`, `whatweb_*.txt`, etc.)
- `summary_<timestamp>.txt` — plain-text run summary with all output file paths
- `report_<timestamp>.json` — everything structured, for scripting/automation
- `report_<timestamp>.html` — the main deliverable: executive summary with
  severity breakdown, findings (each with manual-verification follow-up
  notes), subdomains, live hosts, screenshots, discovered directories,
  historical URLs, and embedded raw tool output, all in one page
- `findings_<timestamp>.csv` — flat findings export for spreadsheets/ticket
  trackers
- `screenshots_<timestamp>/` — if gowitness ran

If a previous `report_*.json` exists for the same domain in that folder,
the new run automatically diffs against it — new subdomains and new
findings since last time show up in both the console output and a "Diff vs
Previous Run" section of the HTML report.

## A note on findings

Every Nuclei/takeover/header/CORS/exposed-file finding includes a very generic
"follow-up / how to verify" note explaining how to manually confirm it's
real before you put it in front of a client — automated signature matching
occasionally false-positives (a patched install matching an old version
string, a custom error page matching a misconfig signature, etc.). Treat
the report as a strong starting point for triage, not a final verdict.
