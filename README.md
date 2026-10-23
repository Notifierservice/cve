# 🛡️ CVE Scanner — Network-Focused Edition

A free network security scanner with **active PoC verification** and **host library fingerprinting**. Accepts **IP addresses, domain names, and URLs** — no dependency files, no OSV, no paid APIs.

---

## ⚠️ Authorized Use Only

`scan` and `probe` send real traffic and exploit payloads. **Only against systems you own or have written permission to test.**

Safe (no target contact):
- `enrich <CVE>`
- `--list-cves`, `--list-payloads`

Requires authorization:
- `scan <target>` — port scan + banner grab + HTTP fingerprint + Nuclei DAST
- `probe <report> --target <target>` — active CVE/CWE PoCs

---

## 📑 Contents

1. [Quick start](#1-quick-start)
2. [Installation](#2-installation)
3. [File layout](#3-file-layout)
4. [Commands](#4-commands)
5. [Target formats](#5-target-formats)
6. [What happens during a scan](#6-what-happens-during-a-scan)
7. [Understanding results](#7-understanding-results)
8. [Workflow examples](#8-workflow-examples)
9. [Troubleshooting](#9-troubleshooting)
10. [Coverage](#10-coverage)

---

## 1. Quick start

```bash
# Scan an IP
python scanner.py scan 192.168.1.1 -o findings.json --html report.html

# Scan a domain
python scanner.py scan example.com -o findings.json --html report.html

# Scan a URL
python scanner.py scan https://staging.example.com -o findings.json

# Verify findings with active PoCs
python scanner.py probe findings.json --target staging.example.com \
    -o verified.json --html verified.html

# Single CVE lookup
python scanner.py enrich CVE-2024-3400
```

---

## 2. Installation

### Required

```bash
pip install requests
```

### Recommended

```bash
pip install packaging  # accurate version range matching
```

### Optional — Nuclei (adds 1,500+ CVE templates)

```bash
# macOS
brew install nuclei
# Linux
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Then download templates
nuclei -update-templates
```

### Optional — free NVD API key (10× faster NVD queries)

1. Register: <https://nvd.nist.gov/developers/request-an-api-key>
2. Export:

```bash
export NVD_API_KEY="your-key-here"
```

---

## 3. File layout

```
your-project/
├── scanner.py       ←stration
├── network.py       ← target normalization, port scan, banner grab, TLS
├── fingerprint.py   ← technology detection + NVD CPE lookup
├── payloads.py      ← 45 CVE probes + signature libraries
└── README.md
```

All four `.py` files must be in the **same directory**. `scanner.py` fails loudly if `network.py` or `payloads.py` are missing; it degrades gracefully if `fingerprint.py` is absent.

---

## 4. Commands

### `scan <target>`

Full network scan: port scan → banner grab → HTTP fingerprint → CPE lookup → Nuclei DAST.

```bash
python scanner.py scan <target> [options]
```

| Flag | Description |
|---|---|
| `-o, --output FILE` | Save JSON report |
| `--html FILE` | Save HTML report |
| `--ports PORTS` | Custom ports, e.g. `80,443,8080:HTTP-Alt` |
| `--no-port-scan` | Skip port scan |
| `--no-nuclei` | Skip Nuclei DAST |
| `--severity LEVELS` | Nuclei severity filter (default `critical,high,medium`) |
| `--tags TAGS` | Nuclei tags (default `cve,vkev,kev`) |
| `--nuclei-timeout N` | Nuclei timeout (default 900s) |
| `--insecure` | Skip TLS verification |
| `--header "K: V"` | HTTP header (repeatable) |
| `--basic-auth USER:PASS` | HTTP Basic Auth |
| `--cookie STRING` | Cookie header |
| `--workers N` | NVD enrichment workers (default 4) |

**Examples:**

```bash
# Full scan
python scanner.py scan example.com -o findings.json --html report.html

# Fast scan (skip port scan + Nuclei)
python scanner.py scan example.com --no-port-scan --no-nuclei

# Custom ports
python scanner.py scan 10.0.0.5 --ports 22,80,443,3306,5432

# Authenticated
python scanner.py scan https://app.example.com \
    --header "Authorization: Bearer $TOKEN" \
    --cookie "session=abc123" \
    -o findings.json
```

### `probe <report> --target <target>`

Verify findings with active PoCs.

```bash
python scanner.py probe <report.json> --target <target> [options]
```

| Flag | Description |
|---|---|
| `--target TARGET` | **Required.** IP, domain, or URL |
| `-o, --output FILE` | Save JSON |
| `--html FILE` | Save HTML |
| `--fingerprint` | Add HTTP fingerprint findings |
| `--skip-confirmed` | Skip already-confirmed |
| `--dry-run` | Plan without sending payloads |
| `--waf-bypass` | Apply payload mutation |
| `--insecure` | Skip TLS verification |
| `--header "K: V"` | HTTP header (repeatable) |
| `--basic-auth` | HTTP Basic Auth |
| `--cookie` | Cookie header |
| `--rate N` | Requests/sec (0=unlimited) |
| `--jitter N` | Random jitter (seconds) |
| `--profile` | `stealth` \| `normal` \| `aggressive` |

**Examples:**

```bash
# Basic verification
python scanner.py probe findings.json --target example.com -o verified.json

# With authentication + fingerprinting
python scanner.py probe findings.json --target 192.168.1.1 \
    --header "Authorization: Bearer $TOKEN" \
    --fingerprint \
    --insecure \
    -o verified.json --html verified.html

# Stealth mode
python scanner.py probe findings.json --target example.com --profile stealth
```

### `enrich <CVE-ID>`

Look up a single CVE.

```bash
python scanner.py enrich CVE-2024-3400
```

### `--list-cves`, `--list-payloads`

Print bundled probe libraries. Safe — no network access.

---

## 5. Target formats

All commands auto-detect the target type:

| Input | Interpretation |
|---|---|
| `192.168.1.1` | IPv4 — tries `https://` then `http://` |
| `192.168.1.1:8080` | IPv4 + port |
| `example.com` | Domain — tries `https://` then `http://` |
| `example.com:8443` | Domain + port |
| `https://example.com/path` | Full URL (used verbatim) |
| `::1` | IPv6 — tries `https://[::1]` then `http://[::1]` |
| `[::1]:8080` | IPv6 + port |

The first URL that responds is used for HTTP probing. Port scan and banner grab use only the hostname.

---

## 6. What happens during a scan

```
1. Normalize target → candidate URLs
2. Detect working URL (try https, then http)
3. Port scan (TCP connect to common ports)
4. Banner grab on every open port
5. HTTP fingerprint (headers, meta tags, cookies)
6. Banner-based CPE lookup (

OpenSSH, MySQL, Redis, etc.)
7. Nuclei DAST (if installed)
8. Enrichment (CVSS, EPSS, KEV)
9. Report
```

### Common ports scanned**Remote access**: 22, 23, 3389
**File transfer**: 21, 445, 2049
**Mail**: 25, 110, 143, 587, 993, 995
**Directory**: 389, 636
**DNS**: 53
**Web**: 80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090
**Database**: 1433, 1521, 3306, 5432, 5984, 6379, 27017, 27018
**Search**: 9200, 9300
**Containers**: 2375, 2376, 6443, 10250

### Technologies fingerprinted

**HTTP-based** (23): Apache, nginx, IIS, LiteSpeed, OpenResty, Caddy, PHP, ASP.NET, jQuery, Bootstrap, AngularJS, Vue, WordPress, Drupal, Joomla, Magento, Spring, Tomcat, Jenkins, GitLab, Grafana, Kibana, Elasticsearch, OpenSSL

**Banner-based** (15): OpenSSH, vsFTPd, ProFTPD, Pure-FTPd, Exim, Postfix, Sendmail, MySQL, MariaDB, PostgreSQL, Redis, MongoDB, Elasticsearch, Docker, Jenkins

---

## 7. Understanding results

### Priority

| Priority | Criteria |
|---|---|
| **CRITICAL** | In CISA KEV |
| **HIGH** | EPSS ≥ 10% OR CVSS ≥ 7.0 |
| **MEDIUM** | CVSS 4.0-6.9 |
| **LOW** | Real CVE, no exploitation signals |
| **INFO** | Port open / service detected (not a vuln) |

### False-positive status

| Status | Meaning |
|---|---|
| **CONFIRMED** | PoC fired (or informational finding verified by TCP/HTTP) |
| **LIKELY_REAL** | CVE with high EPSS or CVSS, no PoC ran |
| **NEEDS_REVIEW** | CVE probe ran but didn't fire (may be wrong product) |
| **LIKELY_FALSE_POSITIVE** | Broad CWE/Nuclei probe ran without triggering |
| **UNVERIFIED** | No probe available, WAF-blocked, or dry-run |

`LIKELY_FALSE_POSITIVE` requires an **active probe that ran cleanly** — never set when a probe couldn't execute.

### Verification order per finding

```
1. CVE-specific probe (if in CVE_PROBES)
2. Nuclei per-CVE
3. CWE generic probe
4. UNVERIFIED
```

Each attempt is recorded in `verification_attempts` for the audit trail.

---

## 8. Workflow examples

### Weekly external surface scan

```bash
#!/bin/bash
TARGETS=(example.com api.example.com 192.168.1.5)

for t in "${TARGETS[@]}"; do
    python scanner.py scan "$t" \
        -o "reports/${t//\//_}-$(date +%Y%m%d).json" \
        --html "reports/${t//\//_}-$(date +%Y%m%d).html"
done
```

### Pre-pentest recon + verify

```bash
# Phase 1 — enumerate
python scanner.py scan app.client.com -o recon.json --html recon.html

# Phase 2 — verify (with WAF evasion if needed)
python scanner.py probe recon.json --target app.client.com \
    --header "Authorization: Bearer $CLIENT_TOKEN" \
    --waf-bypass --rate 2 --profile stealth \
    -o verified.json --html verified.html

# Phase 3 — merge with manual findings
jq -s 'add | sort_by(.priority)' verified.json manual.json > final.json
```

### Emergency CVE check

```bash
# "Am I affected by CVE-2024-3400?"
python scanner.py enrich CVE-2024-3400

# If CVE PoC: available, create minimal findings and probe:
cat > /tmp/check.json <<'EOF'
[{
  "cve_id": "CVE-2024-3400",
  "cwe": ["CWE-78"],
  "package": "pan-os",
  "version": "",
  "ecosystem": "DAST",
  "source": "manual"
}]
EOF

python scanner.py probe /tmp/check.json \
    --target https://panos-admin.example.com \
    --insecure -o /tmp/result.json
```

### CI gate (block on confirmed findings)

```bash
#!/bin/bash
set -e

python scanner.py scan staging.example.com -o /tmp/findings.json
python scanner.py probe /tmp/findings.json --target staging.example.com \
    -o /tmp/verified.json

CONFIRMED=$(jq '[.[] | select(.false_positive_status == "CONFIRMED"
                             and .priority != "INFO")] | length' /tmp/verified.json)

if [ "$CONFIRMED" -gt 0 ]; then
    echo "❌ $CONFIRMED confirmed vulnerabilities — blocking deploy"
    exit 1
fi
echo "✅ No confirmed vulnerabilities"
```

---

## 9. Troubleshooting

### "No HTTP/HTTPS endpoint responded"

The target isn't running a web server on the standard ports. The scan still runs port + banner, but `probe` requires an HTTP endpoint. If the service is on a non-standard port:

```bash
python scanner.py scan example.com:8443
```

### "WAF detected" — probes blocked

```
[!] WAF detected: cloudflare (header:cf-ray, body:ray id:)
```

Try:

1. `--waf-bypass --profile stealth --rate 1`
2. Whitelist your IP on the WAF
3. Test against staging without WAF
4. Manually verify with Burp Suite

If probes remain `WAF_BLOCKED`, that's honest — the tool is saying "I couldn't test this," not "this is a false positive."

### "Nuclei not installed"

Only needed for `scan <target>` DAST and per-CVE Nuclei verification. The bundled CVE + CWE probes work fine without it.

### "NVD rate limited"

Set a free API key:

```bash
export NVD_API_KEY="your-key"
```

Or reduce concurrency: `--workers 1`.

### Port scan is slow

Default timeout is 0.5s per port. For firewalled hosts, use `--ports` to target specific ports.

### Interrupt (Ctrl+C)

Press once to save partial results gracefully. Press twice within 2 seconds to force exit.

---

## 10. Coverage

| Component | Count |
|---|---|
| CVE-specific probes | 45 |
| CWE-based probes | 14 |
| SQL error signatures | 50 |
| XSS signatures | 23 |
| LFI signatures | 21 |
| RCE signatures | 13 |
| SSTI signatures | 15 |
| SSRF signatures | 18 |
| XXE signatures | 12 |
| Deserialization signatures | 15 |
| Open redirect signatures | 7 |
| NoSQL / LDAP / XPath / CRLF | 15 |
| WAF fingerprints | 9 vendors |
| HTTP technology fingerprints | 23 |
| Banner technology fingerprints | 15 |
| Common ports scanned | 40 |

---

## 🏁 Cheat sheet

```bash
# Safe
python scanner.py --list-cves
python scanner.py --list-payloads
python scanner.py enrich CVE-2024-3400

# Requires authorization
python scanner.py scan 192.168.1.1 -o out.json
python scanner.py scan example.com -o out.json --html out.html
python scanner.py scan https://app.example.com --no-port-scan

python scanner.py probe findings.json --target example.com -o verified.json
python scanner.py probe findings.json --target 10.0.0.5 --fingerprint --insecure

# Fastest triage
jq -r '.[] | select(.false_positive_status=="CONFIRMED"
                     and .priority!="INFO") |
  "\(.priority)\t\(.cve_id // .package)\t\(.summary)"' verified.json
```

**Remember:** `enrich`, `--list-cves`, `--list-payloads` are always safe. `scan` and `probe` send real traffic — only against authorized targets.
