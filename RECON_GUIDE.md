# Beast Mode Recon v2.0.0 - Comprehensive Guide

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command-Line Options](#command-line-options)
- [Phase Descriptions](#phase-descriptions)
- [Output Structure](#output-structure)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Optimization & Improvements](#optimization--improvements)

---

## Overview

**Beast Mode Recon** is a modular 10-phase subdomain enumeration and reconnaissance pipeline designed for bug bounty hunters and penetration testers. It automates the entire reconnaissance workflow from passive subdomain discovery to vulnerability scanning.

### Key Features
- **10 Distinct Phases**: Organized workflow from setup to reporting
- **Parallel Execution**: Maximizes speed with concurrent tool execution
- **Auto-Dependency Management**: Automatically installs required tools
- **Multiple Data Sources**: Combines 6+ passive sources with active scanning
- **Structured Output**: Organized by program/domain/timestamp
- **Resume Capability**: Continue interrupted scans
- **Flexible Execution**: Run all phases, specific phases, or skip phases

### Architecture
```
Phase 0: Setup & Dependencies (always runs)
Phase 1: Root Domain Intelligence (WHOIS, ASN)
Phase 2: Passive Subdomain Enumeration (6+ sources)
Phase 3: DNS Resolution & Filtering
Phase 4: Active Discovery (Bruteforce + Permutations)
Phase 5: Port Scanning
Phase 6: Web Probing
Phase 7: Content Discovery (with JS Analysis)
Phase 8: Vulnerability Scanning
Phase 9: Certstream Monitor (Background)
Phase 10: Reporting
```

---

## Installation

### Automatic Installation (Recommended)
The script automatically installs all dependencies on first run:
```bash
./recon.sh --program test -d example.com
```

### Manual Installation
If you prefer to install dependencies manually:

#### 1. Install Go (1.24.0 or newer)
```bash
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

#### 2. Install Go Tools
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

#### 3. Install MassDNS
```bash
git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
cd /tmp/massdns
make
sudo make install
```

#### 4. Install Python Dependencies
```bash
pip3 install requests beautifulsoup4 websocket-client
```

#### 5. Install Optional Tools
```bash
# Amass (optional but recommended)
go install -v github.com/owasp-amass/amass/v4/...@master

# pv (progress bar utility)
sudo apt-get install pv  # Debian/Ubuntu
brew install pv          # macOS
```

---

## Quick Start

### Basic Usage
```bash
# Full reconnaissance on a single domain
./recon.sh --program hackerone -d example.com

# Scan multiple domains from a file
./recon.sh --program bugcrowd --domains-file domains.txt

# Passive reconnaissance only (no active scanning)
./recon.sh --program yahoo -d target.com --only-passive

# Skip specific phases
./recon.sh --program google -d corp.google.com --skip-phase 5,8

# Run only specific phases
./recon.sh --program meta -d facebook.com --run-phase 2,7,8

# Resume interrupted scan
./recon.sh --program github -d github.com --resume
```

### With API Tokens
```bash
# GitHub token for code dorking
./recon.sh --program company -d example.com --github-token ghp_xxxxxxxxxxxxx

# Configure subfinder API keys (create file first)
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << EOF
virustotal: ["YOUR_VT_API_KEY"]
passivetotal_username: "YOUR_USERNAME"
passivetotal_key: "YOUR_PT_KEY"
securitytrails: "YOUR_ST_KEY"
shodan: ["YOUR_SHODAN_KEY"]
censys_token: "YOUR_CENSYS_TOKEN"
censys_secret: "YOUR_CENSYS_SECRET"
EOF
```

---

## Command-Line Options

### Required Arguments
| Option | Description |
|--------|-------------|
| `--program`, `-p` | Program/bounty name (creates output folder structure) |
| `-d`, `--domain` | Single target domain |
| `--domains-file`, `-l` | File containing list of domains (one per line) |

**Note**: You must specify either `-d` or `--domains-file`, not both.

### Optional Arguments
| Option | Default | Description |
|--------|---------|-------------|
| `-t`, `--threads` | 50 | Concurrent threads for tools (httpx, nuclei, katana, naabu) |
| `--rate-limit` | 300 | DNS queries per second for puredns and naabu |
| `--run-phase` | (none) | Run ONLY specific phases (comma-separated, e.g., `2,5,7`) |
| `--skip-phase` | (none) | Skip specific phases (comma-separated, e.g., `5,8`) |
| `--only-passive` | false | Run phases 0-3 only (no bruteforce, ports, or scanning) |
| `--resume` | false | Resume from latest timestamped directory for the domain |
| `--github-token` | (none) | GitHub personal access token for Phase 2 code dorking |
| `--wordlist` | subdomains-top1million-110000.txt | Custom bruteforce wordlist path |
| `--resolvers` | resolvers.txt | Custom DNS resolver list path |
| `-h`, `--help` | N/A | Display help message and exit |

### Option Conflicts
- Cannot use `--run-phase` and `--skip-phase` together
- Cannot use `--run-phase` and `--only-passive` together
- Cannot use `-d` and `--domains-file` together

---

## Phase Descriptions

### Phase 0: Setup & Dependencies
**Always runs** - Cannot be skipped

#### What it does:
1. **Environment Configuration**
   - Configures `$PATH` to prioritize Go binaries (`$GOPATH/bin` before system paths)
   - Prevents conflicts with system tools (e.g., Kali's unrelated `httpx`)

2. **Output Directory Creation**
   - Creates timestamped directory structure: `<script_dir>/<program>/<domain>/<timestamp>/`
   - Example: `/home/user/recon/hackerone/example.com/2026-02-08_143022/`
   - Creates subdirectories for all phases

3. **Dependency Installation**
   - **Go**: Auto-installs Go 1.24.0 if not found
   - **MassDNS**: Clones and compiles from source if missing
   - **Go Tools**: Installs 11 tools via `go install`:
     - subfinder, httpx, nuclei, puredns, alterx, dnsx, naabu, katana, anew, gau, ffuf
   - **Python Packages**: Installs requests, beautifulsoup4, websocket-client
   - **Wordlists**: Downloads SecLists top 110k subdomains if missing
   - **Resolvers**: Downloads Trickest public resolver list if missing
   - **Nuclei Templates**: Updates nuclei template database

4. **Tool Validation**
   - Checks for `pv` (progress bar utility)
   - Validates Python availability

#### Output Files:
- `recon.log` - Full colored execution log

#### Data Sources:
- Go official downloads
- GitHub repositories (MassDNS, SecLists, resolvers)
- PyPI (Python packages)

#### How to Improve:
- **Pre-build Docker image**: Include all dependencies to skip setup time
- **Use package managers**: Install Go tools via apt/brew when available
- **Pin tool versions**: Specify exact versions instead of `@latest`
- **Parallel downloads**: Download wordlists and resolvers concurrently
- **Cache dependencies**: Store in shared location for multi-user systems

---

### Phase 1: Root Domain Intelligence
**Purpose**: Gather organizational metadata and infrastructure information

#### What it does:
1. **WHOIS Lookup**
   - Retrieves domain registration information
   - Extracts registrar, creation date, expiration, nameservers
   - Identifies domain owner/organization

2. **ASN Enumeration** (via `asn_enum.py`)
   - Resolves domain to IP address
   - Queries HackerTarget API for ASN number
   - Retrieves all IP prefixes (CIDR blocks) announced by that ASN via BGPView API
   - Performs reverse DNS on up to 10 prefixes (rate-limited)
   - Extracts subdomains matching the target domain from reverse DNS results

#### Output Files:
```
phase1_rootdomain/
├── whois.txt            # Raw WHOIS data
├── asn_info.json        # Full ASN metadata (number, name, description, prefixes)
├── ip_ranges.txt        # CIDR prefixes announced by ASN (one per line)
├── reverse_dns.txt      # All hostnames from reverse DNS lookups
├── asn_subdomains.txt   # Filtered subdomains matching target domain
└── asn_enum.log         # Error/debug log
```

#### Data Sources:
- `whois` command (system)
- HackerTarget API: https://api.hackertarget.com/aslookup/
- BGPView API: https://api.bgpview.io/asn/{ASN}/prefixes

#### How to Improve:
- **Additional WHOIS sources**: Query multiple WHOIS servers for cross-validation
- **Historical WHOIS**: Use SecurityTrails or DomainIQ for historical registration data
- **More reverse DNS**: Increase prefix limit (currently capped at 10 to avoid rate limits)
- **BGP hijack detection**: Compare announced prefixes with historical data
- **IPv6 support**: Add IPv6 prefix enumeration and reverse DNS
- **Netblock expansion**: Use RIPEstat, ARIN, or RIPE databases for comprehensive netblock data
- **Cloud provider detection**: Identify if ASN belongs to AWS, Azure, GCP, etc.

---

### Phase 2: Passive Subdomain Enumeration
**Purpose**: Discover subdomains without touching the target infrastructure

#### What it does:
Queries 7 data sources in parallel:

1. **subfinder** (ProjectDiscovery)
   - Queries 50+ passive sources (VirusTotal, AlienVault, Censys, etc.)
   - Supports API keys via `~/.config/subfinder/provider-config.yaml`
   - No rate limiting

2. **amass** (OWASP)
   - Passive enumeration only (`-passive` flag)
   - 5-minute timeout to prevent hanging
   - Queries Certificate Transparency logs, DNS databases, search engines

3. **crt.sh** (via `crtsh_enum.py`)
   - Certificate Transparency log search
   - JSON API: `https://crt.sh/?q=%.domain&output=json`
   - Extracts subdomains from certificate `name_value` fields

4. **Wayback Machine** (via `webarchive_enum.py`)
   - Historical URL database
   - CDX API: `http://web.archive.org/cdx/search/cdx?url=*.domain/*&matchType=domain`
   - Extracts subdomains from archived URL hostnames
   - Limited to 50,000 URLs per query

5. **4 Free APIs** (via `passive_enum.py`)
   - **RapidDNS**: `https://rapiddns.io/subdomain/{domain}`
   - **AlienVault OTX**: `https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns`
   - **HackerTarget**: `https://api.hackertarget.com/hostsearch/?q={domain}`
   - **URLScan.io**: `https://urlscan.io/api/v1/search/?q=domain:{domain}`

6. **GitHub Code Search** (via `github_dorking.py`)
   - Requires `--github-token` flag
   - Searches 6 dork patterns:
     - `"example.com"`
     - `"*.example.com"`
     - `"api.example.com"`
     - `"dev.example.com"`
     - `"staging.example.com"`
     - `"internal.example.com"`
   - Extracts subdomains from code snippets

7. **ASN Reverse DNS**
   - Imports `asn_subdomains.txt` from Phase 1

#### Output Files:
```
phase2_passive/
├── subfinder.txt        # Subfinder results
├── amass.txt            # Amass results
├── crtsh.txt            # Certificate Transparency results
├── wayback.txt          # Wayback Machine results
├── passive_apis.txt     # Combined results from 4 APIs
├── github.txt           # GitHub code search results (if token provided)
├── certstream.txt       # Real-time CT monitoring (from Phase 9)
└── merged_passive.txt   # Deduplicated union of all sources
```

#### Data Sources:
| Source | Rate Limit | API Key Required | Coverage |
|--------|------------|------------------|----------|
| subfinder | None | Optional (improves) | 50+ sources |
| amass | None | No | 20+ sources |
| crt.sh | ~1 req/sec | No | CT logs |
| Wayback | None | No | Historical URLs |
| RapidDNS | None | No | DNS aggregator |
| AlienVault | None | No | Threat intel |
| HackerTarget | 10/day free | No | DNS records |
| URLScan.io | 1000/day | Optional | URL scans |
| GitHub | 60/hour | Yes | Code search |

#### How to Improve:
- **Add more sources**:
  - chaos.projectdiscovery.io (requires API key)
  - Shodan (requires API key)
  - Censys (requires API key)
  - Spyse (requires API key)
  - DNSdumpster.com (web scraping)
  - ThreatCrowd
  - Riddler.io
- **Increase Wayback limit**: Fetch more than 50k URLs with pagination
- **More GitHub dorks**: Add patterns for staging, uat, test, qa subdomains
- **Google dorking**: Add automated Google search queries
- **Passive DNS databases**: Query Farsight DNSDB, Passivetotal, RiskIQ
- **Social media scraping**: Search Twitter, Pastebin for exposed subdomains
- **Retry logic**: Implement exponential backoff for failed API calls
- **API key rotation**: Support multiple API keys for rate limit bypass

---

### Phase 3: DNS Resolution & Filtering
**Purpose**: Validate passive subdomains and collect detailed DNS records

#### What it does:
1. **puredns resolve**
   - Resolves all subdomains from `merged_passive.txt`
   - Uses MassDNS under the hood for speed
   - Tests against public resolver list (`resolvers.txt`)
   - Automatically detects and filters wildcard DNS responses
   - Rate-limited to `--rate-limit` queries/second (default: 300)

2. **dnsx enrichment**
   - Collects comprehensive DNS records for all live subdomains:
     - **A**: IPv4 addresses
     - **AAAA**: IPv6 addresses
     - **CNAME**: Canonical name aliases
     - **MX**: Mail exchange servers
     - **NS**: Nameservers
     - **TXT**: Text records (SPF, DKIM, etc.)
   - Output in both human-readable and JSON formats

3. **CNAME extraction**
   - Isolates CNAME records for subdomain takeover analysis
   - Useful for identifying dangling DNS entries

#### Output Files:
```
phase3_dns/
├── resolved.txt         # Live subdomains that resolve
├── wildcards.txt        # Wildcard domains detected
├── dns_records.txt      # Human-readable DNS records
├── dns_records.json     # JSON-formatted DNS records
└── cnames.txt           # CNAME records only
```

#### Data Sources:
- Public DNS resolvers (Trickest resolver list: ~30 trusted resolvers)
- Authoritative DNS servers for the domain

#### How to Improve:
- **More resolvers**: Use larger resolver lists (e.g., all public resolvers)
- **Resolver rotation**: Distribute queries across more resolvers to bypass rate limits
- **Custom resolvers**: Use authoritative nameservers for the domain
- **Parallel resolution**: Split resolution into batches for faster processing
- **Retry failed resolutions**: Some subdomains may timeout; retry with different resolvers
- **DNSSEC validation**: Check DNSSEC signatures for added security
- **PTR records**: Add reverse DNS lookups for IP addresses
- **CAA records**: Check Certificate Authority Authorization records
- **DNSKEY/DS**: Collect DNSSEC key records
- **Subdomain takeover check**: Automatically verify if CNAMEs are vulnerable

---

### Phase 4: Active Discovery (Bruteforce + Permutations)
**Purpose**: Discover additional subdomains through active techniques

#### What it does:
1. **Bruteforce Attack**
   - Uses `puredns bruteforce` with wordlist
   - Default wordlist: SecLists `subdomains-top1million-110000.txt` (110,000 entries)
   - Prepends each word to the root domain (e.g., `api`, `dev`, `staging`)
   - Rate-limited to `--rate-limit` queries/second
   - Wildcard-aware (filters false positives)

2. **Permutation Generation**
   - Uses `alterx` to generate mutation-based candidates
   - Takes known-alive subdomains from Phase 3 as input
   - Generates variations:
     - Number increments: `app1` → `app2`, `app3`, ...
     - Word insertions: `api` → `api-v2`, `api-prod`, `api-staging`
     - TLD variations: `api.example.com` → `api.example.net`
     - Hyphen/underscore swaps: `api-v1` → `api_v1`

3. **Permutation Resolution**
   - Resolves all permutation candidates with `puredns`
   - Only keeps candidates that resolve successfully

#### Output Files:
```
phase4_active/
├── bruteforce.txt       # Subdomains discovered via wordlist bruteforce
└── permutations.txt     # Subdomains discovered via alterx permutations
```

#### Data Sources:
- Wordlist: SecLists `subdomains-top1million-110000.txt`
- DNS resolvers: Same as Phase 3

#### How to Improve:
- **Larger wordlists**:
  - all.txt (8M+ entries) from jhaddix/all.txt
  - assetnote wordlists
  - Custom wordlists from previous scans
- **Multi-level bruteforce**: Test 2nd-level subdomains (e.g., `admin.api.example.com`)
- **Pattern-based generation**: Use common patterns from target's naming convention
- **More permutation rules**:
  - Common prefixes/suffixes: `prod-`, `uat-`, `-beta`
  - Environment names: `dev`, `stage`, `qa`, `test`, `prod`
  - Geographic locations: `us-east`, `eu-west`
  - Service names: `jenkins`, `gitlab`, `jira`, `confluence`
- **VHost discovery**: Bruteforce virtual hosts on known IP addresses
- **Cloud-specific patterns**: AWS/Azure/GCP naming conventions
- **Machine learning**: Train model on existing subdomains to predict likely candidates

---

### Phase 5: Port Scanning
**Purpose**: Discover open ports across all live subdomains

#### What it does:
- Uses `naabu` (ProjectDiscovery's fast port scanner)
- Scans all subdomains from `master_subdomains.txt` (merged from phases 1-4)
- Default scan: **Top 1000 ports**
- Uses SYN scan for speed (requires root/sudo)
- Rate-limited to `--rate-limit` packets/second
- Concurrent thread count: `--threads`

#### Output Files:
```
phase5_ports/
├── naabu_scan.txt       # host:port pairs (e.g., example.com:443)
└── hosts_with_ports.txt # Unique hosts that have at least one open port
```

#### Data Sources:
- Direct TCP/UDP probes to target hosts

#### Common Ports Scanned:
```
Web: 80, 443, 8080, 8443, 8000, 8888, 3000, 5000
SSH: 22, 2222
FTP: 21, 2121
Mail: 25, 465, 587, 110, 143, 993, 995
Database: 3306, 5432, 27017, 6379, 1433, 3389
Admin panels: 8080, 8443, 9090, 10000
... and 980+ more
```

#### How to Improve:
- **Full port scan**: Use `-p -` flag for all 65535 ports (slower but comprehensive)
- **Service-specific ports**: Add custom port lists for specific technologies
- **UDP scanning**: Add UDP port scans (currently TCP only)
- **Banner grabbing**: Capture service banners for version detection
- **Service detection**: Use nmap for detailed service/version fingerprinting
- **Cloud service ports**: Scan cloud-specific ports (AWS, Azure, GCP management)
- **Exclude CDN/WAF IPs**: Skip scanning IPs behind Cloudflare, Akamai, etc.
- **IP range scanning**: Scan entire CIDR blocks from Phase 1 ASN enumeration
- **Retry on timeout**: Retry scans that timeout or fail
- **Parallel batching**: Split large subdomain lists for faster concurrent scanning

---

### Phase 6: Web Probing
**Purpose**: Identify HTTP/HTTPS services and gather web asset metadata

#### What it does:
Uses `httpx` with comprehensive probing:
- Tests both HTTP and HTTPS protocols
- Follows redirects (up to 10 hops)
- Captures detailed fingerprints:
  - **Status codes**: 200, 301, 302, 403, 404, 500, etc.
  - **Page titles**: `<title>` tag content
  - **IP addresses**: Resolved IPs for each URL
  - **CNAME records**: DNS aliases
  - **Technologies**: Web frameworks, CMS, JavaScript libraries (via Wappalyzer-like detection)
  - **Web servers**: Apache, Nginx, IIS, Cloudflare, etc.
  - **Content-length**: Response body size
  - **Content-type**: MIME type (text/html, application/json, etc.)
  - **Favicon hash**: Unique hash of favicon (for technology detection)
  - **JARM fingerprint**: TLS fingerprinting
  - **CDN detection**: Identifies Cloudflare, Akamai, Fastly, etc.
- Uses random user agents to avoid fingerprinting
- Concurrent requests: `--threads`

#### Output Files:
```
phase6_web/
├── httpx_output.txt         # Human-readable results with all metadata
├── httpx_output.json        # JSON output (parsable)
├── live_urls.txt            # Clean list of live HTTP/HTTPS URLs
├── by_status/
│   ├── 200.txt              # 200 OK responses
│   ├── 301.txt              # Permanent redirects
│   ├── 302.txt              # Temporary redirects
│   ├── 403.txt              # Forbidden
│   ├── 404.txt              # Not found
│   ├── 500.txt              # Internal server error
│   └── [other codes].txt    # Other status codes as encountered
└── screenshots/             # (Currently unused, reserved for future)
```

#### Data Sources:
- Direct HTTP/HTTPS requests to target hosts

#### How to Improve:
- **Screenshot capture**: Use Aquatone, EyeWitness, or httpx's screenshot feature
- **Technology profiling**: Use Wappalyzer API for comprehensive tech stack detection
- **Response analysis**:
  - Extract all links from HTML responses
  - Identify JavaScript frameworks (React, Vue, Angular)
  - Detect CMS versions (WordPress, Drupal, Joomla)
- **Header analysis**:
  - Security headers (CSP, HSTS, X-Frame-Options)
  - Custom headers (X-Powered-By, Server)
  - Cookie attributes (HttpOnly, Secure, SameSite)
- **TLS/SSL analysis**:
  - Certificate validity and expiration
  - SSL/TLS versions supported
  - Cipher suites
  - Certificate chain validation
- **WAF detection**: Identify Web Application Firewalls
- **Load balancer detection**: Detect HAProxy, F5, AWS ELB, etc.
- **Response time tracking**: Measure latency for each endpoint
- **Robots.txt parsing**: Extract disallowed paths
- **Sitemap.xml parsing**: Discover additional paths

---

### Phase 7: Content Discovery (with JS Analysis)
**Purpose**: Crawl web assets, discover URLs, and analyze JavaScript files

#### What it does:
1. **katana** (Web Crawler)
   - JavaScript-aware crawling (executes JS to discover dynamic content)
   - Depth: 3 levels
   - Discovers:
     - Internal links
     - External links (optional filter)
     - API endpoints
     - Form actions
     - JavaScript files
     - CSS files
     - Image URLs

2. **gau** (GetAllURLs)
   - Fetches historical URLs from:
     - **Wayback Machine**: Internet Archive
     - **Common Crawl**: Petabyte-scale web crawl
     - **URLScan.io**: URL scanning service
     - **AlienVault OTX**: Threat intelligence
   - No authentication required
   - Discovers legacy endpoints that may still be accessible

3. **URL Merging**
   - Deduplicates all discovered URLs from katana and gau

4. **JavaScript File Extraction**
   - Filters all URLs ending in `.js`
   - Creates list of JavaScript files for analysis

5. **JavaScript Analysis** (via `jsanalyzer.py`)
   - Fetches each JavaScript file
   - Performs regex-based pattern matching to extract:
     - **API Endpoints**: `/api/*`, `/v1/*`, `/rest/*`, `/graphql`, `/oauth/*`
     - **URLs**: Full HTTP/HTTPS/WebSocket URLs
     - **Secrets**: AWS keys, Google API keys, Stripe keys, GitHub tokens, Slack tokens, JWTs
     - **Emails**: All email addresses
     - **File Paths**: SQL files, env files, configs, logs, backups, archives, keys, PEM files
   - Deduplicates findings across all files
   - Masks secrets (first 8 + last 4 characters shown)

#### Output Files:
```
phase7_content/
├── katana_urls.txt          # URLs discovered by katana
├── gau_urls.txt             # Historical URLs from gau
├── all_urls.txt             # Deduplicated union of all URLs
├── js_files.txt             # JavaScript file URLs only
├── js_analysis.txt          # Full JS analysis output (human-readable)
├── js_endpoints.txt         # API endpoints extracted from JS
├── js_urls.txt              # URLs extracted from JS
├── js_secrets.txt           # Secrets/API keys found in JS (masked)
├── js_emails.txt            # Email addresses found in JS
└── js_files_found.txt       # Interesting file paths found in JS
```

#### Data Sources:
- Live web pages (katana)
- Wayback Machine, Common Crawl, URLScan.io, AlienVault OTX (gau)
- JavaScript source code (jsanalyzer.py)

#### How to Improve:
- **Deeper crawling**: Increase katana depth beyond 3
- **Custom wordlists**: Add ffuf/gobuster for directory bruteforcing
- **More sources**: Add:
  - VirusTotal URL scraping
  - GitHub repository scanning
  - Pastebin searches
- **JS analysis enhancements**:
  - Deobfuscate minified/obfuscated JavaScript
  - Parse source maps for original code
  - Extract API schemas from Swagger/OpenAPI docs
  - Identify vulnerable JS libraries (Retire.js)
  - Extract GraphQL schemas
  - Identify WebSocket endpoints
  - Extract authorization tokens and session cookies
- **Content analysis**:
  - Extract comments from HTML/JS (developers often leave sensitive info)
  - Identify hidden form fields
  - Extract meta tags (often contain API keys, analytics IDs)
- **API documentation discovery**: Detect Swagger UI, GraphQL Playground, Postman docs
- **Screenshot comparison**: Identify visual changes over time
- **Diff analysis**: Compare current content with historical (Wayback) versions

---

### Phase 8: Vulnerability Scanning
**Purpose**: Detect security issues using nuclei templates

#### What it does:
- Uses `nuclei` (ProjectDiscovery's vulnerability scanner)
- Scans all live URLs from Phase 6 (`live_urls.txt`)
- Runs templates for all severity levels:
  - **Critical**: RCE, SQL injection, authentication bypass
  - **High**: XSS, SSRF, IDOR, insecure deserialization
  - **Medium**: Misconfigurations, outdated software
  - **Low**: Information disclosure, missing headers
  - **Info**: Fingerprinting, technology detection
- Concurrent requests: `--threads`
- Silent mode (no unnecessary output)
- JSON output for parsability

#### Output Files:
```
phase8_vulns/
├── nuclei_all.txt           # Human-readable summary (all findings)
├── nuclei_all.json          # Full JSON output (all findings)
├── nuclei_critical.json     # Critical severity only
├── nuclei_high.json         # High severity only
├── nuclei_medium.json       # Medium severity only
├── nuclei_low.json          # Low severity only
├── nuclei_info.json         # Info severity only
└── nuclei.log               # Error/debug log
```

#### Data Sources:
- Direct HTTP/HTTPS requests to target URLs
- Nuclei template database (4000+ templates, auto-updated in Phase 0)

#### Template Categories:
```
- CVEs: Known vulnerabilities (CVE-2021-44228 Log4j, etc.)
- Technologies: WordPress, Drupal, Joomla, Jenkins, Confluence, etc.
- Exposures: .git, .env, database dumps, backups, config files
- Misconfigurations: CORS, CSRF, open redirects, SSRF
- Default credentials: Admin panels with default passwords
- Takeovers: Subdomain takeovers (AWS S3, Azure, GitHub Pages, etc.)
- DNS: DNS poisoning, zone transfers
- Network: Open ports, services
- Files: Sensitive files, logs, backups
```

#### How to Improve:
- **Custom templates**: Write organization-specific templates for known vulnerabilities
- **Rate limiting**: Add delays between requests to avoid triggering WAFs
- **Custom headers**: Use authenticated sessions for deeper testing
- **Exclude false positives**: Create filters for known false positives
- **Integration with Burp Suite**: Export findings to Burp for manual testing
- **Active exploitation**: For authorized tests, use nuclei's `headless` mode for full browser automation
- **Post-exploitation**: Chain vulnerabilities for impact demonstration
- **Severity tuning**: Adjust severity levels based on business impact
- **Retest scheduling**: Automatically retest critical findings
- **DAST integration**: Combine with OWASP ZAP, Burp Suite Scanner
- **Reporting**: Generate HTML/PDF reports with remediation steps

---

### Phase 9: Certstream Monitor (Background Daemon)
**Purpose**: Real-time Certificate Transparency log monitoring

#### What it does:
- Runs as background process during scan
- Connects to Certstream WebSocket feed: `wss://certstream.calidog.io`
- Monitors real-time certificate issuances globally
- Filters certificates matching target domain(s)
- Default duration: 60 seconds (configurable)
- Auto-reconnects on connection loss
- Writes to PID file for tracking
- Logs errors to `certstream.log`

#### Standalone Usage:
```bash
# Monitor indefinitely
python3 helpers/certstream_monitor.py --domains example.com

# 1-hour monitor
python3 helpers/certstream_monitor.py --domains example.com -o certs.txt --duration 3600

# Multiple domains
python3 helpers/certstream_monitor.py --domains example.com,sub.example.com
```

#### Output Files:
```
phase2_passive/
└── certstream.txt           # New subdomains discovered (merged in Phase 10)

(root directory)
├── certstream.pid           # Process ID for background daemon
└── certstream.log           # Error/connection log
```

#### Data Sources:
- Certstream WebSocket: Real-time CT log aggregator
- Certificate Transparency logs from:
  - Let's Encrypt
  - DigiCert
  - Comodo
  - GlobalSign
  - ... and 50+ other CAs

#### How to Improve:
- **Longer monitoring**: Run for hours/days to catch new certificates
- **Persistent daemon**: Run as systemd service for continuous monitoring
- **Multiple CT logs**: Connect directly to CT logs (Google, Cloudflare, etc.)
- **Historical CT logs**: Query older CT logs for comprehensive coverage
- **Notification system**: Send alerts (Slack, email, webhook) on new discoveries
- **Certificate analysis**: Extract SANs, validity period, issuer details
- **Anomaly detection**: Alert on unusual certificate patterns
- **Integration with Phase 3**: Auto-resolve and probe new subdomains immediately
- **Blockchain monitoring**: Monitor blockchain DNS (ENS, Unstoppable Domains)

---

### Phase 10: Reporting
**Purpose**: Generate comprehensive summary and merge findings

#### What it does:
1. **Wait for Certstream**
   - Blocks until Phase 9 certstream background process completes
   - Timeout: 90 seconds

2. **Merge Certstream Findings**
   - Adds new subdomains from `certstream.txt` to `master_subdomains.txt`

3. **Generate Text Report** (`report/summary.txt`)
   - Program name, target domain, timestamp
   - Subdomain counts by source (subfinder, amass, crt.sh, etc.)
   - Infrastructure summary (IP ranges, open ports, web assets)
   - Content discovery stats (URLs, JS files)
   - Vulnerability findings (by severity)
   - Phase timings and status

4. **Generate JSON Statistics** (`report/stats.json`)
   - Machine-readable version of all statistics
   - Parsable for dashboards, CI/CD integration

5. **Terminal Output**
   - Prints summary to console in colored format

#### Output Files:
```
report/
├── summary.txt              # Human-readable summary report
└── stats.json               # Machine-readable statistics (JSON)
```

#### Example Summary Output:
```
Program:    hackerone
Target:     example.com
Date:       2026-02-08 14:30:22

SUBDOMAIN COUNTS
  Passive sources:
    subfinder:           245
    amass:               189
    crtsh:               67
    wayback:             112
    passive_apis:        98
    github:              23
  Merged passive:      412
  Resolved (alive):    387
  Bruteforce:          56
  Permutations:        12
  MASTER TOTAL:        445

INFRASTRUCTURE
  IP ranges (ASN):     8
  Open ports (naabu):  1,234
  Web assets (httpx):  389

CONTENT & VULNS
  URLs discovered:     12,456
  JS files:            234
  JS endpoints:        567
  JS secrets:          12
  Nuclei findings:     45
    Critical:          2
    High:              8
    Medium:            15
    Low:               12
    Info:              8
```

#### How to Improve:
- **HTML report**: Generate interactive HTML dashboard
- **PDF report**: Export professional PDF with charts
- **Charts/graphs**: Visualize data (subdomain timeline, port distribution)
- **Comparison reports**: Compare current scan with previous scans
- **Risk scoring**: Assign risk scores to findings
- **Prioritization**: Rank findings by exploitability and impact
- **Executive summary**: One-page summary for non-technical stakeholders
- **Integration**: Push to Jira, Notion, Confluence, Slack
- **Automation**: Trigger CI/CD pipelines based on findings
- **Metrics tracking**: Track KPIs (scan duration, success rate, coverage)

---

## Output Structure

### Directory Hierarchy
```
<script_dir>/                          # Where recon.sh is located
├── <program>/                         # Bounty program folder
│   ├── <domain>/                      # Target domain folder
│   │   ├── <YYYY-MM-DD_HHMMSS>/       # Timestamped scan folder
│   │   │   ├── recon.log              # Full execution log
│   │   │   ├── master_subdomains.txt  # Final deduplicated subdomain list
│   │   │   ├── certstream.log         # Certstream error log
│   │   │   ├── certstream.pid         # Certstream process ID
│   │   │   ├── phase1_rootdomain/     # Phase 1 outputs
│   │   │   ├── phase2_passive/        # Phase 2 outputs
│   │   │   ├── phase3_dns/            # Phase 3 outputs
│   │   │   ├── phase4_active/         # Phase 4 outputs
│   │   │   ├── phase5_ports/          # Phase 5 outputs
│   │   │   ├── phase6_web/            # Phase 6 outputs
│   │   │   ├── phase7_content/        # Phase 7 outputs
│   │   │   ├── phase8_vulns/          # Phase 8 outputs
│   │   │   └── report/                # Phase 10 outputs
│   │   └── <another-timestamp>/       # Next scan
│   └── <another-domain>/              # Another target domain
├── <another-program>/                 # Another bounty program
├── subdomains-top1million-110000.txt  # Wordlist (auto-downloaded)
└── resolvers.txt                      # Resolvers (auto-downloaded)
```

### Key Files
| File | Description |
|------|-------------|
| `recon.log` | Full colored execution log with timestamps |
| `master_subdomains.txt` | Final list of all discovered subdomains (deduplicated) |
| `phase6_web/live_urls.txt` | All live HTTP/HTTPS URLs |
| `phase7_content/js_analysis.txt` | JS analysis results with endpoints, secrets, etc. |
| `phase8_vulns/nuclei_critical.json` | Critical vulnerabilities (prioritize these!) |
| `report/summary.txt` | Quick overview of entire scan |

---

## Advanced Usage

### 1. Running Specific Phases

#### Scenario: Only want passive recon and content discovery
```bash
./recon.sh -p yahoo -d target.com --run-phase 2,3,7
```
**Note**: Phase 0 (setup) always runs automatically.

#### Scenario: Rerun vulnerability scan without full recon
```bash
# First, ensure you have previous scan outputs
./recon.sh -p company -d example.com --resume --run-phase 8
```

#### Scenario: Skip expensive phases (ports, vulns)
```bash
./recon.sh -p company -d example.com --skip-phase 5,8
```

---

### 2. Custom Wordlists & Resolvers

#### Using custom wordlist
```bash
# Large wordlist for thorough bruteforce
./recon.sh -p program -d target.com --wordlist /path/to/custom-wordlist.txt

# Example: jhaddix/all.txt (8M+ entries)
wget https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/all.txt
./recon.sh -p program -d target.com --wordlist all.txt
```

#### Using custom resolvers
```bash
# Use only trusted resolvers
cat > custom-resolvers.txt << EOF
8.8.8.8
1.1.1.1
9.9.9.9
208.67.222.222
EOF

./recon.sh -p program -d target.com --resolvers custom-resolvers.txt
```

---

### 3. Performance Tuning

#### High-performance mode (fast network, powerful machine)
```bash
./recon.sh -p program -d target.com -t 200 --rate-limit 2000
```

#### Conservative mode (slow network, rate limit concerns)
```bash
./recon.sh -p program -d target.com -t 20 --rate-limit 100
```

#### Maximum stealth (low detection risk)
```bash
./recon.sh -p program -d target.com -t 5 --rate-limit 50 --skip-phase 4,5,8
```

---

### 4. Multi-Domain Scanning

#### Create domains file
```bash
cat > domains.txt << EOF
example.com
sub.example.com
api.example.com
EOF
```

#### Batch scan
```bash
./recon.sh -p company --domains-file domains.txt
```

**Output structure**:
```
company/
├── example.com/
│   └── 2026-02-08_143022/
├── sub.example.com/
│   └── 2026-02-08_143022/
└── api.example.com/
    └── 2026-02-08_143022/
```

---

### 5. Resume Interrupted Scans

#### Resume latest scan
```bash
# If scan was interrupted (Ctrl+C, timeout, etc.)
./recon.sh -p program -d example.com --resume
```

**Behavior**:
- Finds latest timestamped directory for the domain
- Continues from where it left off
- Skips completed phases
- Uses existing `master_subdomains.txt`

---

### 6. Integration with Other Tools

#### Export to Burp Suite
```bash
# Convert live_urls.txt to Burp-friendly format
cat phase6_web/live_urls.txt | sed 's/^/* /' > burp_targets.txt
```

#### Feed to FFUF for fuzzing
```bash
# Use discovered endpoints for parameter fuzzing
ffuf -w wordlist.txt -u https://example.com/api/v1/FUZZ -mc 200,301,302,401,403
```

#### Import into Nuclei
```bash
# Rerun nuclei with custom templates
cat phase6_web/live_urls.txt | nuclei -t /path/to/custom-templates/
```

---

### 7. Continuous Monitoring

#### Cron job for daily scans
```bash
# Add to crontab
0 2 * * * cd /home/user/recon && ./recon.sh -p company -d example.com --only-passive
```

#### Compare with previous scan
```bash
# Diff subdomains
comm -13 \
  <(sort old_scan/master_subdomains.txt) \
  <(sort new_scan/master_subdomains.txt) \
  > new_subdomains.txt

# New subdomains discovered
cat new_subdomains.txt
```

---

## Troubleshooting

### Common Issues

#### 1. `command not found: subfinder` (or other Go tools)
**Cause**: Go binaries not in PATH

**Solution**:
```bash
export PATH=$PATH:$HOME/go/bin
# Or add to ~/.bashrc:
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

#### 2. `puredns: too many open files`
**Cause**: System file descriptor limit too low

**Solution**:
```bash
ulimit -n 10000
# Or add to /etc/security/limits.conf:
# * soft nofile 10000
# * hard nofile 10000
```

---

#### 3. Subfinder returns very few results
**Cause**: No API keys configured

**Solution**:
```bash
# Create provider config
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << EOF
virustotal: ["YOUR_VT_API_KEY"]
shodan: ["YOUR_SHODAN_KEY"]
censys_token: "YOUR_CENSYS_TOKEN"
censys_secret: "YOUR_CENSYS_SECRET"
securitytrails: "YOUR_ST_KEY"
EOF
```

---

#### 4. Phase 9 hangs indefinitely
**Cause**: `websocket-client` not installed or certstream connection issue

**Solution**:
```bash
pip3 install websocket-client
# Or skip Phase 9:
./recon.sh -p program -d example.com --skip-phase 9
```

---

#### 5. Nuclei scan too slow
**Cause**: Too many URLs or low thread count

**Solution**:
```bash
# Increase threads
./recon.sh -p program -d example.com -t 100

# Or filter URLs before scanning
head -1000 phase6_web/live_urls.txt > limited_urls.txt
nuclei -l limited_urls.txt
```

---

#### 6. Permission denied errors
**Cause**: Missing sudo for privileged operations (naabu SYN scan)

**Solution**:
```bash
# Run with sudo or use TCP connect scan (slower)
# Naabu automatically falls back to TCP connect if not root
```

---

#### 7. DNS resolution fails entirely
**Cause**: Bad resolvers or network issue

**Solution**:
```bash
# Test resolvers
cat resolvers.txt | while read r; do
  dig @$r example.com +short || echo "$r failed"
done

# Use only working resolvers
cat resolvers.txt | while read r; do
  dig @$r example.com +short &>/dev/null && echo "$r"
done > working_resolvers.txt

./recon.sh -p program -d example.com --resolvers working_resolvers.txt
```

---

#### 8. `jsanalyzer.py` not found
**Cause**: File not in script directory

**Solution**:
```bash
# Verify jsanalyzer.py exists
ls -l jsanalyzer.py

# If missing, create it or place it in the same directory as recon.sh
```

---

## Optimization & Improvements

### Performance Optimizations

#### 1. **Reduce Redundancy**
Currently, multiple tools query the same sources:
- subfinder, amass, and passive_enum.py all query some of the same APIs
- **Solution**: Modify tools to skip duplicate sources or create a central cache

#### 2. **Parallel Phase Execution**
Some phases can run in parallel:
- Phase 2 (passive) and Phase 1 (ASN) could run concurrently
- Phase 5 (ports) and Phase 6 (web) could overlap
- **Solution**: Implement parallel phase execution with dependency management

#### 3. **Incremental Scanning**
Avoid rescanning known-good subdomains:
- **Solution**: Store state in database (SQLite, PostgreSQL), only scan new/changed assets

#### 4. **Smart Rate Limiting**
Dynamically adjust rate limits based on success/failure rates:
- **Solution**: Implement adaptive rate limiting that backs off on errors

#### 5. **Result Caching**
Cache DNS resolutions, WHOIS data, etc. with TTL:
- **Solution**: Use Redis or local file cache with expiration times

---

### Coverage Improvements

#### 1. **Add More Passive Sources**
- Shodan
- Censys
- Spyse
- chaos.projectdiscovery.io
- DNSdumpster
- ThreatCrowd

#### 2. **Cloud Provider Enumeration**
- AWS: S3 buckets, CloudFront distributions, Elastic Beanstalk
- Azure: Blob storage, App Services
- GCP: Storage buckets, App Engine

#### 3. **GitHub Organization Scanning**
- Clone all public repositories
- Extract hardcoded domains, API keys, credentials

#### 4. **Social Media Scraping**
- Twitter API
- LinkedIn company pages
- Facebook pages

---

### Detection Evasion

#### 1. **Proxy Rotation**
- Use proxy pools (Bright Data, Oxylabs, residential proxies)
- Rotate IPs between requests

#### 2. **User-Agent Rotation**
- Already implemented in httpx, expand to all tools

#### 3. **Request Timing Randomization**
- Add random delays (jitter) between requests

#### 4. **DNS Query Obfuscation**
- Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)

---

### Reporting Enhancements

#### 1. **Interactive Dashboard**
- HTML dashboard with JavaScript charts (Chart.js, D3.js)
- Live updates during scan
- Drill-down capabilities

#### 2. **Severity Scoring**
- Assign CVSS scores to findings
- Calculate overall risk score for target

#### 3. **Remediation Guidance**
- Auto-generate remediation steps for each vulnerability
- Link to CWE, OWASP references

#### 4. **Historical Tracking**
- Track changes over time
- Show new/resolved vulnerabilities
- Trend analysis

---

### Automation

#### 1. **CI/CD Integration**
```yaml
# Example GitHub Actions workflow
name: Recon
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
jobs:
  recon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run recon
        run: ./recon.sh -p company -d example.com --only-passive
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: recon-results
          path: company/example.com/
```

#### 2. **Notification System**
```bash
# Slack webhook integration
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Recon complete for example.com. Found $(cat master_subdomains.txt | wc -l) subdomains.\"}" \
  https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

---

## Best Practices

### 1. **Legal Compliance**
- **ALWAYS** get written authorization before scanning
- Respect scope boundaries (in-scope vs out-of-scope)
- Follow bug bounty program rules (some prohibit port scanning)
- Use responsible disclosure practices

### 2. **Rate Limiting**
- Start with conservative settings (`-t 20 --rate-limit 100`)
- Gradually increase if no issues
- Monitor for blocks or rate limit errors

### 3. **Data Management**
- Regularly clean up old scan directories
- Compress archived scans (`tar czf program_domain_date.tar.gz scan_directory/`)
- Back up critical findings to separate location

### 4. **OPSEC**
- Use VPN/VPS for scans
- Don't scan from personal IP addresses
- Rotate scan sources
- Avoid scanning during target's peak traffic times

### 5. **Validation**
- Manually verify high-severity findings before reporting
- Cross-check results with multiple tools
- Eliminate false positives

---

## FAQ

### Q: How long does a full scan take?
**A**: Depends on domain size:
- Small domain (<100 subdomains): 10-30 minutes
- Medium domain (100-1000 subdomains): 1-3 hours
- Large domain (1000+ subdomains): 3-6+ hours

### Q: Can I run multiple scans in parallel?
**A**: Yes, as long as they target different domains:
```bash
./recon.sh -p program -d domain1.com &
./recon.sh -p program -d domain2.com &
```

### Q: How much disk space do I need?
**A**: Approximately:
- Small scan: 50-200 MB
- Medium scan: 200-500 MB
- Large scan: 500 MB - 2 GB

### Q: Can I run this in a Docker container?
**A**: Yes, create a Dockerfile:
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    wget curl git python3 python3-pip \
    build-essential
# Install Go, tools, etc.
COPY recon.sh /root/
WORKDIR /root
ENTRYPOINT ["/root/recon.sh"]
```

### Q: Is this safe to use on production systems?
**A**: Only if authorized! Some phases (port scanning, bruteforce) are intrusive and may trigger security alerts.

---

## Credits & Acknowledgments

### Tools Used
- **ProjectDiscovery**: subfinder, httpx, nuclei, dnsx, naabu, katana, alterx
- **OWASP**: amass
- **Tom Hudson**: anew, gau
- **d3mondev**: puredns
- **blechschmidt**: massdns
- **ffuf**: ffuf

### Data Sources
- Certificate Transparency logs
- Wayback Machine
- Common Crawl
- HackerTarget, AlienVault OTX, URLScan.io, RapidDNS

### Contributors
- Bug bounty community for testing and feedback
- Open-source security researchers

---

## Changelog

### v2.0.0 (2026-02-08)
- ✨ Added JSAnalyzer integration (Phase 7)
- ✨ Added `--run-phase` feature for selective phase execution
- 📚 Comprehensive documentation (this guide)
- 🐛 Fixed Phase 9 hanging issues
- 🎨 Improved logging and output formatting

### v1.0.0 (2026-02-05)
- 🎉 Initial release with 10-phase pipeline
- ⚡ Parallel passive enumeration
- 🔍 ASN-based infrastructure mapping
- 🚀 Auto-dependency installation

---

## License

This tool is provided for educational and authorized security testing purposes only. Use responsibly and ethically.

---

## Support & Contact

- **Issues**: Report bugs or request features via GitHub issues
- **Documentation**: Keep this guide handy for reference
- **Community**: Share your improvements and findings

Happy Hunting! 🎯🔍
