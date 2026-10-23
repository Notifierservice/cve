# 🛡️ CVE Scanner — How to Use

A complete guide for `cve_scanner.py` v7.0.0 — the free, offline-friendly CVE scanner with CVE-specific and CWE-based active PoC verification.

---

## ⚠️ Legal & Ethical Warning — Read First

This tool sends **real exploit payloads** to a target. It is legal **only** when:

- You **own** the target system, **or**
- You have **written authorization** to test it (signed pentest contract, bug bounty scope, lab environment)

Running `verify` or `dast` against any system you do not own is illegal under:
- **US**: Computer Fraud and Abuse Act (CFAA)
- **UK**: Computer Misuse Act 1990
- **EU**: NIS2 Directive, national cybercrime laws
- **Australia**: Criminal Code Act 1995, Part 10.7
- **Most other jurisdictions**: equivalent cybercrime statutes

**`deps` and `enrich` are safe** — they only make outbound queries to public vulnerability databases (OSV, NVD, CISA, EPSS) and never touch your target.

---

## 📑 Table of Contents

1. [What it does](#1-what-it-does)
2. [Installation](#2-installation)
3. [Quick start](#3-quick-start)
4. [Commands](#4-commands)
   - [deps — dependency scan](#41-deps--dependency-scan)
   - [dast — active Nuclei scan](#42-dast--active-nuclei-scan)
   - [verify — PoC verification](#43-verify--poc-verification)
   - [enrich — single CVE lookup](#44-enrich--single-cve-lookup)
5. [Flags reference](#5-flags-reference)
6. [Understanding results](#6-understanding-results)
7. [Workflow examples](#7-workflow-examples)
8. [Troubleshooting](#8-troubleshooting)
9. [FAQ](#9-faq)

---

## 1. What it does

The scanner combines four engines to identify, prioritize, and **confirm** vulnerabilities:

| Engine | What it does | Network access |
|---|---|---|
| **OSV** | Looks up dependency vulnerabilities (PyPI, npm, etc.) | Public OSV API |
| **Enrichment** | Adds CVSS, EPSS, and CISA KEV status | NVD, FIRST, CISA |
| **CVE PoCs** | Sends exact exploit requests for 18 high-impact CVEs | Your target |
| **CWE PoCs** | Sends generic probes for 15 vulnerability classes | Your target |
| **Nuclei** | Runs 1,500+ community CVE templates (optional) | Your target |

### Verification order per finding

```
1. CVE-specific probe   (if the CVE is in the bundled library)
2. Nuclei CVE template  (if Nuclei is installed and has the template)
3. CWE generic probe    (based on the finding's CWE class)
4. UNVERIFIED           (no method available)
```

**Every probe compares the exploit response against a safe baseline request.** A finding is only marked `CONFIRMED` when the exploit response contains a signal (leaked file, timing delta, error message) that is **absent** from the baseline response. This is what eliminates false positives.

---

## 2. Installation

### Requirements

- **Python 3.8+**
- **`requests`** (the only required package)

### Basic install

```bash
pip install requests
```

That's it. Download `cve_scanner.py`, make it executable, and you're ready.

```bash
chmod +x cve_scanner.py
./cve_scanner.py --version
```

### Optional: install Nuclei (recommended)

Nuclei adds 1,500+ CVE templates with out-of-band (OOB) detection — essential for CVEs the bundled library doesn't cover.

```bash
# macOS
brew install nuclei

# Linux
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download a binary release
# https://github.com/projectdiscovery/nuclei/releases
```

Then download the templates (one-time, ~300 MB):

```bash
nuclei -update-templates
```

Verify:

```bash
nuclei -version
```

### Optional: register a free NVD API key

Without a key, NVD queries are limited to 5 requests / 30 seconds — a 100-CVE scan takes ~10 minutes. With a free key, it's 50 requests / 30 seconds — the same scan takes ~1 minute.

1. Register: <https://nvd.nist.gov/developers/request-an-api-key>
2. Set the environment variable:

```bash
# Linux / macOS
export NVD_API_KEY="your-key-here"

# Windows (PowerShell)
$env:NVD_API_KEY = "your-key-here"

# Windows (cmd)
set NVD_API_KEY=your-key-here
```

Add it to your shell profile (`~/.bashrc`, `~/.zshrc`) to persist across sessions.

---

## 3. Quick start

### Step 1 — Inspect what the tool can do

```bash
./cve_scanner.py --list-cves       # 18 CVE-specific probes
./cve_scanner.py --list-payloads   # 15 CWE-based probes
```

### Step 2 — Scan your dependency file

```bash
./cve_scanner.py deps requirements.txt -o findings.json
```

### Step 3 — Verify each finding with live PoCs

```bash
./cve_scanner.py verify findings.json \
    --target https://staging.example.com \
    -o verified.json
```

### Step 4 — Read the report

```bash
cat verified.json | jq '.[] | {cve: .cve_id, status: .false_positive_status}'
```

Or open `verified.json` in any JSON viewer. Better: add `--html verified.html` in step 3 and open that in a browser.

**Total time:** ~5 minutes for a 20-dependency project against a staging target.

---

## 4. Commands

### 4.1 `deps` — dependency scan

Enumerates dependencies from `requirements.txt` or `package.json` and queries OSV for vulnerabilities, then enriches each finding with CVSS, EPSS, and KEV status.

```bash
./cve_scanner.py deps <file> [options]
```

**Supported files:**

| Filename | Ecosystem |
|---|---|
| `requirements.txt` | PyPI |
| `package.json` | npm |

**Example:**

```bash
./cve_scanner.py deps requirements.txt \
    -o findings.json \
    --csv findings.csv \
    --html findings.html
```

**Options:**

| Flag | Description |
|---|---|
| `-o, --output FILE` | Save JSON report |
| `--csv FILE` | Save CSV report |
| `--sarif FILE` | Save SARIF (for GitHub Code Scanning) |
| `--html FILE` | Save human-readable HTML report |
| `--workers N` | Concurrent OSV queries (default: 8) |

**Sample output:**

```
[*] Scanning requirements.txt (42 deps, ecosystem=PyPI)...
[*] Enriching 8 findings...
[+] JSON saved: findings.json
```

---

### 4.2 `dast` — active Nuclei scan

Runs Nuclei against a live URL. **Requires Nuclei to be installed.** This sends real exploit requests.

```bash
./cve_scanner.py dast <url> [options]
```

**Example:**

```bash
./cve_scanner.py dast https://staging.example.com \
    -o dast.json \
    --severity critical,high \
    --timeout 900
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-o, --output FILE` | — | Save JSON report |
| `--csv FILE` | — | Save CSV report |
| `--sarif FILE` | — | Save SARIF |
| `--html FILE` | — | Save HTML report |
| `--severity LEVELS` | `critical,high,medium` | Comma-separated severity filter |
| `--tags TAGS` | `cve,vkev,kev` | Nuclei template tags |
| `--timeout SECONDS` | `900` | Overall scan timeout |

**Notes:**

- `--tags cve,vkev,kev` covers CISA KEV + VulnCheck KEV + all CVE templates (~1,500 unique)
- OOB CVEs (Log4Shell, Spring4Shell, etc.) require the target to be able to reach `interact.sh` — usually fine for staging, blocked in air-gapped environments
- Nuclei runs without authentication by default; for authenticated scans, export cookies to a file and pass with `nuclei -H @cookies.txt` (see Nuclei docs)

---

### 4.3 `verify` — PoC verification

The core command. Takes a findings JSON from `deps` or `dast`, then **actively tests each finding** against a live target using bundled CVE probes, Nuclei templates, and CWE-based generic probes.

```bash
./cve_scanner.py verify <report.json> --target <url> [options]
```

**Verification pipeline per finding:**

```
1. CVE-specific probe   → if CVE is in the 18 bundled CVE_PROBES
2. Nuclei per-CVE       → if Nuclei is installed and has a matching template
3. CWE generic probe    → if the finding has a CWE tag
4. UNVERIFIED           → no method available
```

Every attempt is recorded in `verification_attempts` for the audit trail.

**Basic example:**

```bash
./cve_scanner.py verify findings.json \
    --target https://staging.example.com \
    -o verified.json
```

**Authenticated example:**

```bash
./cve_scanner.py verify findings.json \
    --target https://app.example.com \
    --header "Authorization: Bearer eyJhbGciOi..." \
    --cookie "session=abc123" \
    -o verified.json \
    --html verified.html
```

**Stealth example (won't trip rate limits):**

```bash
./cve_scanner.py verify findings.json \
    --target https://production.example.com \
    --profile stealth \
    --rate 0.5 \
    -o verified.json
```

**Dry-run example (see what would run without sending payloads):**

```bash
./cve_scanner.py verify findings.json \
    --target https://staging.example.com \
    --dry-run
```

**Full example:**

```bash
./cve_scanner.py verify findings.json \
    --target https://staging.example.com \
    --basic-auth admin:password \
    --header "X-API-Key: xyz" \
    --header "Accept: application/json" \
    --insecure \
    --waf-bypass \
    --profile stealth \
    --rate 2 \
    --skip-confirmed \
    -o verified.json \
    --csv verified.csv \
    --sarif verified.sarif \
    --html verified.html
```

**Options:**

| Flag | Description |
|---|---|
| `--target URL` | **Required.** Live target to test against |
| `-o, --output FILE` | Save updated JSON report |
| `--csv FILE` | Save CSV |
| `--sarif FILE` | Save SARIF |
| `--html FILE` | Save HTML report |
| `--skip-confirmed` | Skip findings already marked `CONFIRMED` |
| `--dry-run` | Show planned tests without sending payloads |
| `--waf-bypass` | Apply payload mutations (case-flip, encoding, comment injection) |
| `--insecure` | Skip TLS certificate verification (for self-signed staging certs) |
| `--header "K: V"` | Add HTTP header (repeatable) |
| `--basic-auth USER:PASS` | HTTP Basic Auth |
| `--cookie STRING` | Cookie header value |
| `--rate N` | Requests per second (0 = unlimited) |
| `--jitter N` | Random delay jitter (seconds) |
| `--profile {stealth,normal,aggressive}` | Preset scan speed profile |

**Profiles:**

| Profile | Rate | Jitter | Use case |
|---|---|---|---|
| `stealth` | 1 req/s | ±1s | Production, WAF-protected sites |
| `normal` | unlimited | 0 | Staging, no rate limits |
| `aggressive` | unlimited | 0 | Lab, isolated environments |

---

### 4.4 `enrich` — single CVE lookup

Looks up a single CVE and prints KEV status, EPSS score, CVSS, CWE type, and whether a bundled CVE probe exists.

```bash
./cve_scanner.py enrich <CVE-ID>
```

**Example:**

```bash
./cve_scanner.py enrich CVE-2024-3400
```

**Output:**

```
CVE      : CVE-2024-3400
In KEV   : YES — actively exploited
EPSS     : 94.23%
CVSS     : 10.0
CWE Type : Command Injection (OS) (CWE-78)
CVE PoC  : available — PAN-OS GlobalProtect Command Injection
Summary  : A command injection vulnerability in the GlobalProtect
           feature of Palo Alto Networks PAN-OS software enables an
           unauthenticated attacker to execute arbitrary code...
```

---

## 5. Flags reference

### Global flags

| Flag | Description |
|---|---|
| `--version` | Print version and exit |
| `-v, --verbose` | Increase logging (`-v` = INFO, `-vv` = DEBUG) |
| `--list-cves` | List all CVE-specific probes and exit |
| `--list-payloads` | List all CWE-based probes and exit |

### Output format summary

| Format | Best for | Tools |
|---|---|---|
| **JSON** | Re-feeding to `verify`, tooling integration | `jq`, Python, any language |
| **CSV** | Triage in a spreadsheet | Excel, Google Sheets, Numbers |
| **SARIF** | CI/CD integration | GitHub Code Scanning, GitLab SAST, Azure DevOps |
| **HTML** | Sharing with stakeholders | Any browser |

---

## 6. Understanding results

### 6.1 Priority levels

Assigned during enrichment based on KEV, EPSS, and CVSS:

| Priority | Criteria | Action |
|---|---|---|
| **CRITICAL** | Listed in CISA KEV — confirmed exploited in the wild | Patch **today** |
| **HIGH** | EPSS ≥ 10% OR CVSS ≥ 7.0 | Patch **this week** |
| **MEDIUM** | CVSS 4.0–6.9 | Patch **this month** |
| **LOW** | Everything else | Backlog |

### 6.2 False-positive status

Assigned after verification:

| Status | Meaning | Confidence |
|---|---|---|
| **CONFIRMED** | PoC triggered — evidence in `false_positive_reason` | **Real** |
| **LIKELY_REAL** | Real CVE, high EPSS/CVSS, but no PoC ran | Likely real |
| **NEEDS_REVIEW** | Real CVE, no exploitation signals | Investigate manually |
| **LIKELY_FALSE_POSITIVE** | CVE assigned but PoC never triggered | Likely false positive |
| **UNVERIFIED** | No CVE probe, Nuclei template, or CWE probe available | Unknown |

**Critical distinction:** `LIKELY_FALSE_POSITIVE` requires an **active PoC that ran and did not trigger** — not just "we couldn't test it." If a probe couldn't run, the status is `UNVERIFIED` or `NEEDS_REVIEW` (honest about the gap).

### 6.3 Reading `verification` and `verification_attempts`

Each finding gets a `verification` object with the winning method, plus `verification_attempts` with the full audit trail:

```json
{
  "cve_id": "CVE-2024-3400",
  "false_positive_status": "NEEDS_REVIEW",
  "verification": {
    "status": "NOT_REPRODUCED",
    "method": "CVE-2024-3400 PAN-OS GlobalProtect Command Injection",
    "evidence": "CVE-specific probes did not trigger (1 endpoint(s) tried)"
  },
  "verification_attempts": [
    {
      "method": "CVE-2024-3400 PAN-OS GlobalProtect",
      "status": "NOT_REPRODUCED",
      "evidence": "CVE-specific probes did not trigger"
    },
    {
      "method": "CWE-78 Command Injection",
      "status": "WAF_BLOCKED",
      "evidence": "12 request(s) blocked by WAF"
    }
  ]
}
```

Here you can see: the CVE probe ran and didn't fire, **and** the CWE probe was blocked by a WAF — so the result is honestly "we couldn't verify, but nothing confirmed it either."

### 6.4 `WAF_BLOCKED` — what to do

If the target has a WAF and it blocks your probes, status becomes `WAF_BLOCKED`, not `LIKELY_FALSE_POSITIVE`. Options:

1. Add `--waf-bypass` — applies payload mutation (case flip, `/**/`, URL-encoding)
2. `--rate 0.5 --profile stealth` — slower scan may slip past rate-based rules
3. Whitelist your IP on the WAF (if you own it)
4. Test against the **staging** environment without the WAF
5. Accept the limitation and manually verify those findings

---

## 7. Workflow examples

### Workflow A — Weekly dependency audit (safe, no active scanning)

```bash
#!/bin/bash
# Cron: 0 9 * * 1 /path/to/weekly-audit.sh

cd /path/to/project
./cve_scanner.py deps requirements.txt \
    -o reports/findings-$(date +%Y%m%d).json \
    --csv reports/findings-$(date +%Y%m%d).csv \
    --html reports/findings-$(date +%Y%m%d).html

# Alert on CRITICAL findings only
CRITICAL=$(jq '[.[] | select(.priority == "CRITICAL")] | length' \
    reports/findings-$(date +%Y%m%d).json)
if [ "$CRITICAL" -gt 0 ]; then
    echo "⚠️  $CRITICAL CRITICAL findings — review reports/findings-$(date +%Y%m%d).html"
    # Trigger Slack/email notification
fi
```

### Workflow B — Pre-release verification against staging

```bash
#!/bin/bash
set -e

# 1. Enumerate dependencies
./cve_scanner.py deps requirements.txt -o /tmp/findings.json

# 2. Verify each finding against staging
./cve_scanner.py verify /tmp/findings.json \
    --target https://staging.example.com \
    --header "Authorization: Bearer $STAGING_TOKEN" \
    --insecure \
    --profile stealth \
    -o /tmp/verified.json \
    --html /tmp/report.html

# 3. Fail the pipeline if any finding is CONFIRMED
CONFIRMED=$(jq '[.[] | select(.false_positive_status == "CONFIRMED")] | length' \
    /tmp/verified.json)
if [ "$CONFIRMED" -gt 0 ]; then
    echo "❌ $CONFIRMED confirmed vulnerabilities — release blocked"
    exit 1
fi

echo "✅ No confirmed vulnerabilities — release approved"
```

### Workflow C — CI integration with SARIF (GitHub Actions)

```yaml
# .github/workflows/cve-scan.yml
name: CVE Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install scanner
        run: pip install requests

      - name: Scan dependencies
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
        run: |
          python cve_scanner.py deps requirements.txt \
            --sarif findings.sarif \
            -o findings.json

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
          category: cve-scan
```

### Workflow D — Full pentest engagement

```bash
# Pre-engagement: confirm authorization, note target IPs
TARGET="https://app.client.example.com"
AUTH="Authorization: Bearer $CLIENT_TOKEN"

# Phase 1 — External recon + Nuclei
./cve_scanner.py dast "$TARGET" \
    -o dast-findings.json \
    --severity critical,high \
    --html dast-report.html

# Phase 2 — Dependency enumeration
./cve_scanner.py deps requirements.txt -o deps-findings.json

# Phase 3 — Verify each Nuclei finding
./cve_scanner.py verify dast-findings.json \
    --target "$TARGET" \
    --header "$AUTH" \
    --waf-bypass \
    --rate 2 \
    -o verified-dast.json \
    --html verified-dast.html

# Phase 4 — Verify dependency findings
./cve_scanner.py verify deps-findings.json \
    --target "$TARGET" \
    --header "$AUTH" \
    --insecure \
    --skip-confirmed \
    -o verified-deps.json \
    --html verified-deps.html

# Phase 5 — Merge and hand off
jq -s 'add | sort_by(.priority)' \
    verified-dast.json verified-deps.json \
    > final-report.json
```

### Workflow E — Single CVE emergency check

```bash
# "Is my internet-facing F5 vulnerable to CVE-2022-1388?"
./cve_scanner.py enrich CVE-2022-1388

# If "CVE PoC: available", run the actual probe:
cat > /tmp/check.json <<'EOF'
[{
  "cve_id": "CVE-2022-1388",
  "cwe": ["CWE-306"],
  "package": "f5-bigip",
  "version": "",
  "ecosystem": "DAST",
  "source": "manual"
}]
EOF

./cve_scanner.py verify /tmp/check.json \
    --target https://f5-admin.example.com \
    --insecure \
    -o /tmp/f5-check.json
```

---

## 8. Troubleshooting

### "Please install requests: pip install requests"

```bash
pip install requests
# or, if you use a virtualenv:
python -m pip install requests
# or on Debian/Ubuntu with system Python:
pip3 install --user requests
```

### "NVD rate limited" — scan is very slow

Without an API key, NVD allows only 5 requests / 30 seconds. Two fixes:

1. **Register a free NVD API key** (recommended):
   ```bash
   export NVD_API_KEY="your-key"
   ```
   This gives 50 requests / 30 seconds — 10× faster.

2. **Reduce scan size** — you can't skip NVD entirely, but you can use `--workers 1` for a smaller project. The KEV cache in `~/.cache/cve_scanner/kev.json` is reused for 12 hours, so repeated scans are faster.

### Network errors / "Could not reach target"

The tool needs outbound HTTPS to:

| Service | Purpose |
|---|---|
| `api.osv.dev` | Dependency lookups |
| `services.nvd.nist.gov` | CVE enrichment |
| `www.cisa.gov` | KEV catalog |
| `api.first.org` | EPSS scores |
| Your target | Verification (`verify` and `dast` only) |

If you're behind a corporate proxy, set environment variables:

```bash
export HTTPS_PROXY="http://proxy.example.com:8080"
export HTTP_PROXY="http://proxy.example.com:8080"
```

Then `requests` will use them automatically.

### "WAF detected" — all probes blocked

The scanner prints:

```
[!] WAF detected: cloudflare (header:cf-ray, body:ray id:)
[!] Active PoCs may be blocked. Consider --waf-bypass.
```

Try, in order:

1. `--waf-bypass --profile stealth --rate 1`
2. Whitelist your IP in the WAF control panel (if you own it)
3. Test against staging without WAF
4. Manually verify those findings with Burp Suite

If verification remains `WAF_BLOCKED`, that's an honest result — the tool isn't claiming the finding is a false positive, just that it couldn't test it.

### "Nuclei not installed"

Only needed for `dast` and per-CVE Nuclei verification. Install:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

Or use the bundled CVE + CWE probes only — they work without Nuclei.

### "CVE-specific probes did not trigger"

This means the CVE probe **ran** but the target's response didn't match. Possible reasons:

1. **Target isn't the vulnerable product** — e.g. testing CVE-2022-1388 against an nginx server. That's **not** a false positive, just an inapplicable probe. Status is `NEEDS_REVIEW` — the tool honestly notes it couldn't confirm but couldn't dismiss.
2. **Target is patched** — most likely scenario.
3. **Custom endpoint** — the probe uses default paths (`/mgmt/tm/util/bash` for F5). If your app is on a different path, edit `CVE_PROBES` to add it.
4. **Authentication required** — pass `--header` or `--cookie`.

When the CVE probe doesn't fire, **Nuclei and CWE probes still run** — the finding is only declared false-positive if all three fail.

### Interrupt handling (Ctrl+C)

```
^C
[WARNING] Interrupt received — finishing current request, then saving partial results
```

Press **Ctrl+C once** to save partial results gracefully. Press **twice** within 2 seconds to force exit (unsaved data is lost).

### "Invalid CVE ID: CVE-2024-1234"

The scanner expects 4+ digits in the ID number (correct format is `CVE-YYYY-NNNN` or `CVE-YYYY-NNNNN`). Check that:

- It starts with `CVE-`
- The year is 4 digits
- The ID is 4 or more digits (not 3)

### Permission denied running the script

```bash
chmod +x cve_scanner.py
```

Or run via Python:

```bash
python3 cve_scanner.py --version
```

---

## 9. FAQ

### Is this really free? No hidden APIs?

**Yes.** Every data source it queries is free:

| Service | Cost | Rate limit |
|---|---|---|
| OSV.dev | $0, no key | Unlimited |
| NVD API 2.0 | $0, no key required (key = faster) | 5/30s no key, 50/30s with key |
| CISA KEV | $0 | Static JSON, no limit |
| EPSS | $0 | Generous |
| Nuclei | Open-source (MIT) | N/A |

You will **never** pay anything to run this tool.

### Does it need an internet connection?

| Command | Needs internet? |
|---|---|
| `deps` | Yes (OSV, NVD, KEV, EPSS) |
| `dast` | Yes (target) |
| `verify` | Yes (target) — NVD for CWE metadata if not cached |
| `enrich` | Yes (NVD, KEV, EPSS) |
| `--list-cves` | **No** |
| `--list-payloads` | **No** |

The KEV catalog and EPSS scores are cached for 12 hours in `~/.cache/cve_scanner/`, so repeated scans within that window don't re-fetch them.

### Can I run it in an air-gapped environment?

Partially. `--list-cves` and `--list-payloads` work offline. To run `verify` offline:

1. Copy the `~/.cache/cve_scanner/` folder from a machine with internet
2. Use a JSON findings file that already has `cwe` and `cvss` populated (produced by `deps` on a connected machine)
3. `verify` will use the cached NVD data and won't need to hit NVD

OSV, KEV, and EPSS enrichment won't work offline, but verification will.

### How accurate is the false-positive classification?

Very high for **CONFIRMED** — it requires a real signal (leaked `/etc/passwd`, timing delta ≥ 3s, database error string) that is **absent** from the baseline. False positives at that stage are essentially impossible unless the target serves the same error for unrelated reasons.

For **LIKELY_FALSE_POSITIVE** — requires an active probe to run and not trigger. False negatives (real vulnerabilities marked as false positives) are possible when:

- The CVE probe targets a different endpoint than the vulnerable one
- The target requires authentication you didn't provide
- A WAF silently blocks the probe (caught as `WAF_BLOCKED`, not `LIKELY_FALSE_POSITIVE`)
- The vulnerability is only exploitable under specific conditions (specific config, race condition, etc.)

That's why the tool **never** hides `verification_attempts` — you can always see exactly what was tried and why it succeeded or failed.

### How is this different from a paid scanner?

| Feature | This tool | Typical paid scanner |
|---|---|---|
| CVE database | OSV + NVD + KEV + EPSS (free) | Commercial feed (paid) |
| Active PoC verification | Yes (18 CVEs + 15 CWE classes) | Yes (larger library) |
| Nuclei integration | Yes (1,500+ templates) | Usually yes |
| Continuous monitoring | Cron/CI | Built-in dashboard |
| Support | Community | 24/7 SLA |
| Pricing | **$0** | $5k–$50k/year |

The paid scanners win on **breadth** (larger PoC library) and **support**. This tool wins on **cost** ($0) and **transparency** (full audit trail of every attempt). For most small-to-medium projects, it covers 80–90% of the value at 0% of the cost.

### Can I add my own CVE probes?

Yes. Open `cve_scanner.py` and add an entry to `CVE_PROBES`:

```python
"CVE-2025-12345": {
    "label": "My Custom CVE",
    "probes": [
        {
            "method": "GET",
            "path": "/vulnerable/endpoint?param=EXPLOIT",
            "sig": {"leaked_marker": r"SECRET_VALUE_12345"},
        },
    ],
},
```

The `sig` dict is the detection signature — the finding is `CONFIRMED` only if one of those regexes matches the exploit response **and not** the baseline response. Add tests for your CVE probe to make sure the signature is unambiguous.

### Can I add my own CWE payloads?

Yes. Add or extend entries in `CWE_PROBES`:

```python
"CWE-777": {
    "label": "My Custom Class",
    "payloads": ["PAYLOAD_1", "PAYLOAD_2"],
    "detect": "pattern",  # or "xss_reflection", "sql", "rce", "ssti", "redirect"
    "signatures": {"marker": r"UNIQUE_ERROR_STRING"},
},
```

The `detect` field controls how responses are compared:

- `pattern` — regex signature match
- `xss_reflection` — payload reflection check
- `sql` — timing + SQL error signatures
- `rce` — timing + RCE signatures
- `ssti` — arithmetic evaluation + template errors
- `redirect` — Location header check

### What about false negatives?

The tool is designed to **under-report** rather than over-report. If it can't prove a finding, it marks it `NEEDS_REVIEW` or `UNVERIFIED` rather than falsely `CONFIRMED`. That means:

- **Real vulnerabilities can be missed** if no CVE probe exists and no CWE class applies (e.g. pure business-logic bugs, race conditions)
- **Confirmed findings are real** — the false-positive rate on `CONFIRMED` is near zero

For full coverage, combine this tool with manual testing and a commercial scanner. This tool is best for **automated triage** and **continuous low-cost monitoring**, not as the sole security control.

### How do I report a bug or contribute?

1. Check the troubleshooting section above
2. Try `-vv` for debug logging — the full request/response trace is usually enough to spot the issue
3. Open an issue on the project repository with the `-vv` output (redact any sensitive data)

### What's the safest way to run this in production?

**Do not run `verify` or `dast` against production** unless you have explicit written authorization and know the blast radius. The `deps` and `enrich` commands are safe against any target — they never touch your infrastructure.

If you must verify against production:

1. Use `--profile stealth` (1 req/s)
2. Add `--rate 0.5` for even slower probing
3. Test during low-traffic windows
4. Monitor error rates in your APM during the scan
5. Have a rollback plan ready
6. **Whitelist your IP on any WAF first**

**Realistic recommendation:** verify against staging, patch there, and only promote to production after confirming the fix.

---

## 🏁 Quick cheat sheet

```bash
# ─── Safe commands (no target contact) ───
./cve_scanner.py --version
./cve_scanner.py --list-cves
./cve_scanner.py --list-payloads
./cve_scanner.py enrich CVE-2024-3400
./cve_scanner.py deps requirements.txt

# ─── Requires authorization ───
./cve_scanner.py dast https://authorized-target.com
./cve_scanner.py verify findings.json --target https://authorized-target.com

# ─── Most common full workflow ───
./cve_scanner.py deps requirements.txt -o findings.json
./cve_scanner.py verify findings.json \
    --target https://staging.example.com \
    -o verified.json --html report.html

# ─── Fastest triage ───
cat verified.json | jq -r '.[] |
  select(.false_positive_status == "CONFIRMED") |
  "\(.priority)\t\(.cve_id)\t\(.package)"'
```

---

**Remember:** `deps` and `enrich` are always safe. `dast` and `verify` are only safe against systems you own or are explicitly authorized to test. When in doubt, don't scan it.
