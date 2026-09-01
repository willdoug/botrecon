# botrecon
It's is a simple bot sequential, but powerful, because use man tools concactend and wordlists to enumerate us target...

# BotRecon

**BotRecon** is an automated reconnaissance orchestration script designed to coordinate multiple security and reconnaissance tools into a structured, sequential workflow.

It is designed for **authorized security assessments, penetration tests, bug bounty programs, and security research** where the operator has explicit permission to test the target.

The project focuses on four main principles:

* **Automation**
* **Sequential execution**
* **Checkpoint-based recovery**
* **Evidence preservation**

Instead of manually running dozens of reconnaissance tools, BotRecon organizes them into a repeatable pipeline and stores the results in a predictable directory structure.

---

## Features

### Automated Reconnaissance Pipeline

BotRecon executes reconnaissance stages sequentially, automatically passing useful results from one stage to the next.

The workflow covers:

1. Subdomain enumeration
2. DNS resolution and enrichment
3. IP discovery
4. Port scanning
5. Service and banner detection
6. HTTP probing
7. Technology fingerprinting
8. URL discovery
9. Endpoint extraction
10. Interesting file discovery
11. Directory and content discovery
12. Vulnerability and exposure scanning
13. Consolidated reporting

---

# Toolset

BotRecon integrates multiple specialized reconnaissance tools.

## Subdomain Enumeration

The subdomain discovery stage can combine several sources:

* `subfinder`
* `amass`
* `chaos-client`
* `assetfinder`
* `findomain`
* `sublist3r`

These sources are combined and normalized to produce a consolidated subdomain list.

Example output:

```text
01_subdomains/
├── subfinder.txt
├── amass-passive.txt
├── chaos.txt
├── assetfinder.txt
├── findomain.txt
├── sublist3r.txt
└── all-subdomains.txt
```

Duplicate domains are removed before subsequent stages.

---

# DNS Enumeration

DNS reconnaissance can use:

* `dnsx`
* `dig`
* `dnsgen`
* `massdns`
* `shuffledns`
* `puredns` when available

The objective is to resolve discovered hosts and identify useful DNS relationships.

Collected information can include:

* IPv4 addresses
* IPv6 addresses
* CNAME records
* DNS responses
* Resolvable hosts
* Generated candidate subdomains

The resulting information is stored separately from the original discovery sources.

---

# IP Discovery

Resolved addresses are consolidated into:

```text
03_ips/
├── ipv4.txt
└── all-ips.txt
```

This allows later scanning stages to operate against unique IP addresses rather than repeatedly processing the same address.

---

# Port Enumeration

BotRecon can combine:

* `naabu`
* `nmap`
* `masscan`

The pipeline uses fast scanners for initial discovery and Nmap for deeper service identification.

Example workflow:

```text
Subdomains
    ↓
Resolved IPs
    ↓
Naabu / Masscan
    ↓
Open ports
    ↓
Nmap service detection
```

---

# Service and Banner Enumeration

Service discovery uses tools such as:

* `nmap`
* `tlsx`

Information collected may include:

* Service versions
* TLS information
* Certificates
* Open services
* Service banners
* Common service fingerprints

---

# HTTP Enumeration

HTTP probing is performed with:

* `httpx`

The HTTP stage records useful metadata such as:

* HTTP status code
* Page title
* Detected technologies
* Web server
* Content length
* Redirect behavior

Example:

```text
https://example.com [200] [Example] [nginx]
https://api.example.com [403] [Forbidden] [Cloudflare]
```

---

# Technology Fingerprinting

Technology identification can use:

* `httpx`
* `whatweb`
* `wafw00f`

This helps identify:

* Web frameworks
* CMS platforms
* Web servers
* JavaScript technologies
* WAF/CDN presence
* Application infrastructure

---

# URL Discovery

BotRecon aggregates URLs from multiple sources.

Supported tools include:

* `katana`
* `urlfinder`
* `waybackurls`
* `gau`
* `hakrawler`
* `gospider`

This creates a broader URL dataset than relying on a single crawler.

The final collection is normalized and deduplicated:

```text
08_urls/
├── katana.txt
├── urlfinder.txt
├── waybackurls.txt
├── gau.txt
├── hakrawler.txt
├── gospider.txt
└── all-urls.txt
```

---

# Endpoint Extraction

Discovered URLs are processed to identify application endpoints.

BotRecon extracts:

* Paths
* API candidates
* GraphQL endpoints
* Swagger endpoints
* OpenAPI endpoints
* JSON resources
* XML resources
* YAML resources

Example:

```text
09_endpoints/
├── endpoints.txt
└── api-candidates.txt
```

---

# Interesting File Discovery

BotRecon identifies potentially interesting files discovered during URL enumeration.

Examples include:

```text
.js
.json
.xml
.yaml
.yml
.txt
.csv
.pdf
.zip
.bak
.old
.conf
.config
.env
.map
.sql
```

This stage is intended to prioritize potentially valuable application artifacts for authorized security testing.

---

# `.git` and `.env` Detection

BotRecon explicitly treats sensitive configuration and repository artifacts as high-value discovery targets.

Examples include:

```text
/.git/
/.git/HEAD
/.git/config
/.git/index
/.env
/.env.local
/.env.production
/.env.development
/.env.example
```

The goal is to identify whether these resources are publicly exposed.

The script should distinguish between:

* Confirmed accessible resources
* HTTP redirects
* `401 Unauthorized`
* `403 Forbidden`
* `404 Not Found`
* Other responses

This prevents a simple wordlist hit from automatically being interpreted as an exposed secret.

> **Important:** BotRecon should only test these paths against systems where the operator has explicit authorization.

---

# Directory Enumeration

BotRecon can use several content discovery tools:

* `ffuf`
* `feroxbuster`
* `gobuster`
* `dirsearch`

Multiple wordlists can be combined to improve coverage.

However, the original wordlist files are **not copied into each target directory**.

Instead, BotRecon maintains references to the original wordlists.

Example:

```text
00_wordlists/
├── dns-sources.txt
├── web-sources.txt
└── files-sources.txt
```

These files contain paths such as:

```text
/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
/opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/wordlists/dirb/common.txt
```

This avoids unnecessarily duplicating hundreds of megabytes of wordlists for every target.

---

# Wordlist Strategy

BotRecon uses a layered wordlist strategy instead of relying on a single dictionary.

## DNS Wordlists

Example sources:

```text
subdomains-top1million-5000.txt
subdomains-top1million-20000.txt
bitquark-subdomains-top100000.txt
namelist.txt
fierce-hostlist.txt
```

These provide different datasets and ranking strategies.

---

## Web Directory Wordlists

Example sources:

```text
DirBuster medium
RAFT medium directories
Trickest robots disallowed
DIRB common
```

These can be combined and deduplicated before being supplied to discovery tools.

---

## File Wordlists

Example sources:

```text
raft-medium-files.txt
raft-medium-words.txt
```

These are useful for discovering application files and resources that may not appear through crawling.

---

# Checkpoint and Resume System

One of the most important BotRecon features is the checkpoint system.

Every major stage maintains its own execution state.

Example:

```text
13_reports/
└── checkpoint.json
```

A stage can have states such as:

```text
PENDING
RUNNING
COMPLETED
FAILED
```

The objective is to allow BotRecon to recover after:

* Power failure
* VM shutdown
* System crash
* Terminal interruption
* Network failure
* Tool timeout
* Individual tool failure

When BotRecon is started again, it reads the checkpoint and determines where execution should continue.

Example:

```text
01_subdomains       COMPLETED
02_dns              COMPLETED
03_ips               COMPLETED
04_ports             RUNNING
05_services         PENDING
06_http             PENDING
```

After restarting:

```text
[SKIP] 01_subdomains already completed
[SKIP] 02_dns already completed
[SKIP] 03_ips already completed
[RESUME] 04_ports
```

The pipeline then continues sequentially.

---

# Sequential Execution

BotRecon intentionally executes stages in dependency order.

The general flow is:

```text
                    ┌───────────────┐
                    │    TARGET     │
                    └───────┬───────┘
                            │
                            ▼
                 ┌────────────────────┐
                 │ Subdomain Discovery│
                 └─────────┬──────────┘
                           │
                           ▼
                    ┌────────────┐
                    │ DNS / IPs  │
                    └─────┬──────┘
                          │
                          ▼
                    ┌────────────┐
                    │   Ports    │
                    └─────┬──────┘
                          │
                          ▼
                  ┌────────────────┐
                  │ Services/TLS   │
                  └───────┬────────┘
                          │
                          ▼
                    ┌────────────┐
                    │    HTTP    │
                    └─────┬──────┘
                          │
                          ▼
                  ┌─────────────────┐
                  │ Technologies    │
                  └───────┬─────────┘
                          │
                          ▼
                    ┌────────────┐
                    │ URL Sources │
                    └─────┬──────┘
                          │
                          ▼
                  ┌─────────────────┐
                  │   Endpoints     │
                  └───────┬─────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │ Files / Directories     │
              └────────────┬────────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Vulnerability Scan  │
                └──────────┬──────────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ Final Report   │
                  └────────────────┘
```

---

# Failure Handling

BotRecon is designed so that one failed tool does not necessarily terminate the entire reconnaissance process.

For example:

```text
subfinder       OK
amass           OK
chaos           FAILED
assetfinder     OK
```

The pipeline can continue using the successful results.

Failures are recorded in the command log and checkpoint information.

This makes the system more resilient when dealing with unstable network conditions or tools that timeout.

---

# Tool Identification

BotRecon prints the active tool before execution.

Example:

```text
[2026-09-01 04:30:21] [TOOL] subfinder
[2026-09-01 04:30:21] RUN: subfinder -d example.com -silent

[2026-09-01 04:31:04] [TOOL] amass
[2026-09-01 04:31:04] RUN: amass enum -passive -d example.com
```

This makes long-running reconnaissance jobs easier to monitor.

---

# Output Structure

Each target receives its own result directory.

Example:

```text
recon_results/
└── example.com/
    │
    ├── 00_wordlists/
    │   ├── dns-sources.txt
    │   ├── web-sources.txt
    │   └── files-sources.txt
    │
    ├── 01_subdomains/
    │
    ├── 02_dns/
    │
    ├── 03_ips/
    │
    ├── 04_ports/
    │
    ├── 05_services/
    │
    ├── 06_http/
    │
    ├── 07_technologies/
    │
    ├── 08_urls/
    │
    ├── 09_endpoints/
    │
    ├── 10_files/
    │
    ├── 11_directories/
    │
    ├── 12_vulnerabilities/
    │
    └── 13_reports/
        ├── REPORT.md
        ├── commands.log
        └── checkpoint.json
```

---

# Evidence Preservation

BotRecon stores raw tool output whenever possible.

This is important because the final report should not be the only source of information.

Raw evidence can be reviewed later to:

* Validate findings
* Compare scans
* Re-run individual tools
* Investigate false positives
* Build security reports
* Perform manual verification

---

# Reporting

At the end of the pipeline, BotRecon generates a consolidated Markdown report.

Example:

```text
13_reports/REPORT.md
```

The report contains information such as:

```text
Target
Start time
End time
Tool availability
Subdomain count
IP count
URL count
Endpoint count
API candidates
Interesting files
Directory discovery results
Vulnerability scan results
Evidence locations
```

---

# Tool Availability

BotRecon checks whether expected tools are installed before attempting to use them.

Typical tools include:

```text
subfinder
amass
chaos-client
dnsx
dnsgen
shuffledns
massdns
puredns
httpx
naabu
nmap
masscan
tlsx
katana
urlfinder
waybackurls
gau
hakrawler
gospider
ffuf
feroxbuster
gobuster
dirsearch
whatweb
wafw00f
nikto
nuclei
dalfox
uncover
assetfinder
findomain
sublist3r
jq
anew
```

Missing tools should be reported rather than silently ignored.

---

# Installation

BotRecon is intended for Linux security environments such as Kali Linux.

Install the required tools using the package manager or their official installation methods.

For example:

```bash
sudo apt update
sudo apt install -y \
    nmap \
    masscan \
    ffuf \
    feroxbuster \
    gobuster \
    dirsearch \
    whatweb \
    wafw00f \
    nikto \
    dnsgen \
    gospider \
    hakrawler \
    assetfinder \
    sublist3r \
    findomain
```

ProjectDiscovery tools can be installed through their official distribution mechanisms.

Make sure the Go binary directory is available in `PATH` when Go-installed tools are used.

Example:

```bash
export PATH="$HOME/go/bin:$PATH"
```

---

# Usage

Make the script executable:

```bash
chmod +x reconbot2026.py
```

Run:

```bash
./reconbot2026.py
```

The target should be configured in the script or supplied through the project's configuration mechanism.

Example:

```python
TARGET = "example.com"
```

Then execute:

```bash
./reconbot2026.py
```

---

# Resuming an Interrupted Scan

Simply start the script again:

```bash
./reconbot2026.py
```

BotRecon checks the existing checkpoint.

Completed stages are skipped:

```text
[SKIP] 01_subdomains already completed
[SKIP] 02_dns already completed
[SKIP] 03_ips already completed
```

The next incomplete stage is resumed automatically:

```text
[RESUME] 04_ports
```

This prevents unnecessarily repeating expensive reconnaissance stages.

---

# Wordlists

BotRecon does not require copying large SecLists datasets into every target directory.

Instead, it references the existing system wordlists.

Example:

```text
/opt/SecLists/Discovery/DNS/
```

and:

```text
/opt/SecLists/Discovery/Web-Content/
```

The target-specific directory contains only the source references:

```text
00_wordlists/
```

This dramatically reduces disk consumption when scanning multiple targets.

---

# Performance

Some reconnaissance operations can be expensive.

Examples:

* Large DNS brute-force
* Full port scanning
* Directory enumeration
* Large-scale crawling
* Nuclei scanning
* Nikto scanning

BotRecon therefore uses individual timeouts and stage checkpoints.

A long-running operation can be interrupted without necessarily losing all previous reconnaissance data.

---

# Security Considerations

BotRecon is a reconnaissance automation framework.

It should only be used against:

* Systems you own
* Systems where you have explicit authorization
* Bug bounty targets within their published scope
* Laboratory environments
* CTF environments
* Authorized penetration tests

Do not use BotRecon against third-party infrastructure without permission.

High-volume scanning can generate significant traffic and may trigger:

* WAFs
* IDS/IPS
* Rate limiting
* Security alerts
* Account or IP blocking

Operators should adjust concurrency and scanning depth according to the authorization and rules of engagement.

---

# Project Philosophy

BotRecon is not intended to replace the individual security tools it orchestrates.

Instead, it provides an automation layer that connects them.

The core philosophy is:

```text
Discover
   ↓
Normalize
   ↓
Enrich
   ↓
Validate
   ↓
Expand
   ↓
Analyze
   ↓
Preserve
   ↓
Report
```

Each stage should produce useful data for the next stage.

---

# Roadmap

Potential future improvements include:

* Better incremental checkpoints at individual tool level
* Automatic retry policies
* Parallel execution of independent tools
* Resume of interrupted individual scans
* More intelligent result correlation
* Automatic HTTP response classification
* Better `.git` exposure verification
* Better `.env` exposure verification
* JavaScript endpoint extraction
* Secret-pattern detection in authorized targets
* Automatic API specification discovery
* Screenshot collection
* Asset relationship graphs
* Historical comparison between scans
* HTML reporting
* JSON export
* SQLite result database
* Local LLM-assisted result enrichment
* T3MP3ST integration
* Automatic prioritization of high-value findings

---

# License

Add the project's chosen license here.

For example:

```text
MIT License
```

Make sure the license is compatible with all code and third-party components included in the project.

---

# Disclaimer

BotRecon is provided for legitimate security testing, research, and educational purposes.

The author is not responsible for unauthorized use, damage, service disruption, or legal consequences resulting from the use of this software.

Always obtain appropriate authorization before scanning systems you do not own.
