#!/usr/bin/env python3
"""
scanner.py — Free CVE scanner with CVE + CWE PoC verification.

⚠️  AUTHORIZED USE ONLY
`probe` and `scan <url>` send real exploit payloads. Use only against
systems you own or have written permission to test. `scan <file>` and
`enrich` only touch public vulnerability databases.

Commands:
  scan    Scan a dependency file (requirements.txt / package.json) OR a URL (DAST)
  probe   Verify findings against a live target with CVE + CWE PoCs
  enrich  Look up a single CVE

Usage:
  python scanner.py scan requirements.txt -o findings.json --html report.html
  python scanner.py scan package.json
  python scanner.py scan https://staging.example.com
  python scanner.py probe findings.json --target https://staging.example.com \\
      --header "Authorization: Bearer $TOKEN" -o verified.json --html verified.html
  python scanner.py enrich CVE-2024-3400
  python scanner.py --list-cves
  python scanner.py --list-payloads

Free data sources: OSV.dev, NVD 2.0, CISA KEV, EPSS.
Optional: Nuclei for OOB templates and per-CVE verification.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, quote

# ── Required dependencies ──
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Please install requests: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ── Payload library (must live in payloads.py next to this file) ──
try:
    from payloads import (
        CWE_NAMES,
        CVE_PROBES,
        CWE_PROBES,
        WAF_FINGERPRINTS,
        SQL_ERROR_SIGNATURES,
        XSS_SIGNATURES,
        LFI_SIGNATURES,
        RCE_SIGNATURES,
        SSTI_SIGNATURES,
        SSRF_SIGNATURES,
        XXE_SIGNATURES,
        DESERIALIZATION_SIGNATURES,
        OPEN_REDIRECT_SIGNATURES,
        NOSQL_SIGNATURES,
        LDAP_SIGNATURES,
        XPATH_SIGNATURES,
        CRLF_SIGNATURES,
    )
except ImportError as e:
    print(f"Error importing payloads: {e}", file=sys.stderr)
    print("Make sure payloads.py is in the same directory as scanner.py",
          file=sys.stderr)
    sys.exit(1)


# ================================================================
# CONFIG
# ================================================================
__version__ = "8.1.0"

OSV_API  = "https://api.osv.dev/v1/query"
NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

NVD_API_KEY     = os.getenv("NVD_API_KEY")
NVD_MAX_RETRIES = 3

CACHE_DIR = Path.home() / ".cache" / "cve_scanner"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

log = logging.getLogger("cve_scanner")
_SHUTDOWN = threading.Event()


# ================================================================
# CWE NAME HELPERS  (thin wrappers around CWE_NAMES from payloads.py)
# ================================================================
def cwe_friendly(cwe_id: str) -> str:
    return CWE_NAMES.get(cwe_id, cwe_id or "Unknown")


def cwe_list_friendly(cwes: List[str]) -> str:
    if not cwes:
        return "Unknown"
    return ", ".join(f"{cwe_friendly(c)} ({c})" for c in cwes)


# ================================================================
# SIGNATURE HELPERS
# ================================================================
def _normalize_signatures(signatures) -> Iterable[Tuple[str, str]]:
    """Accept dict {label: pattern} or list [(pattern, label)]."""
    if isinstance(signatures, dict):
        for label, pattern in signatures.items():
            yield label, pattern
    else:
        for item in signatures:
            if isinstance(item, tuple) and len(item) == 2:
                pattern, label = item
                yield label, pattern


def match_signatures(
    text: str, signatures,
    *, baseline_text: Optional[str] = None,
    case_insensitive: bool = True,
) -> List[str]:
    flags = re.IGNORECASE if case_insensitive else 0
    hits: List[str] = []
    for label, pattern in _normalize_signatures(signatures):
        try:
            if not re.search(pattern, text, flags):
                continue
            if baseline_text and re.search(pattern, baseline_text, flags):
                continue
            hits.append(label)
        except re.error:
            continue
    return hits


def detect_waf(status_code: int, headers: Dict[str, str], body: str) -> Optional[dict]:
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    b = (body or "").lower()
    for vendor, fp in WAF_FINGERPRINTS.items():
        evidence: List[str] = []
        for hh in fp.get("headers", []):
            if ":" in hh:
                k, v = hh.split(":", 1)
                if h.get(k.strip()) and v.strip() in h[k.strip()]:
                    evidence.append(f"header:{hh}")
            elif hh in h:
                evidence.append(f"header:{hh}")
        for phrase in fp.get("body", []):
            if phrase in b:
                evidence.append(f"body:{phrase}")
        for c in fp.get("cookies", []):
            if c.lower() in h.get("set-cookie", ""):
                evidence.append(f"cookie:{c}")
        if status_code in fp.get("status", []) and evidence:
            evidence.append(f"status:{status_code}")
        if evidence:
            return {"vendor": vendor, "evidence": evidence}
    return None


def obfuscate_payload(payload: str) -> List[str]:
    variants = [payload]
    for kw in ("SELECT", "UNION", "SLEEP", "AND", "OR", "WHERE", "FILE"):
        if kw in payload.upper():
            variants.append(payload.replace(kw, kw.lower()))
            variants.append(payload.replace(kw, kw.title()))
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace(" ", "%20"))
    variants.append(quote(quote(payload, safe="")))
    return list(dict.fromkeys(variants))


# ================================================================
# HTTP
# ================================================================
def build_session(insecure: bool = False, user_headers: Optional[dict] = None,
                  basic_auth: Optional[Tuple[str, str]] = None,
                  cookie: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": f"cve-scanner/{__version__}"})
    if user_headers:
        s.headers.update(user_headers)
    if basic_auth:
        s.auth = basic_auth
    if cookie:
        s.headers["Cookie"] = cookie
    s.verify = not insecure
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "POST", "HEAD"]))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def http_get(url: str, params=None, headers=None, timeout=30) -> dict:
    h = {"User-Agent": f"cve-scanner/{__version__}", **(headers or {})}
    r = requests.get(url, params=params, headers=h, timeout=timeout)
    r.raise_for_status()
    return r.json()


def http_post(url: str, data: dict, timeout=30) -> dict:
    h = {"User-Agent": f"cve-scanner/{__version__}"}
    r = requests.post(url, json=data, headers=h, timeout=timeout)
    r.raise_for_status()
    return r.json()


# ================================================================
# CACHE
# ================================================================
def load_cache(name: str, max_age_hours: float = 24.0) -> Optional[dict]:
    p = CACHE_DIR / f"{name}.json"
    if not p.exists():
        return None
    if (time.time() - p.stat().st_mtime) / 3600.0 > max_age_hours:
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def save_cache(name: str, data: dict) -> None:
    tmp: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=CACHE_DIR, delete=False,
            prefix=f"{name}.", suffix=".tmp"
        ) as fh:
            tmp = Path(fh.name)
            json.dump(data, fh)
        tmp.replace(CACHE_DIR / f"{name}.json")
    except Exception:
        if tmp and tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass


# ================================================================
# NVD / KEV / EPSS
# ================================================================
class _NvdRateLimiter:
    """Thread-safe NVD rate limiter — 5/30s no key, 50/30s with key."""
    def __init__(self):
        self.rate = 50.0 / 30.0 if NVD_API_KEY else 5.0 / 30.0
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            now = time.monotonic()
            min_gap = 1.0 / self.rate
            elapsed = now - self.last
            if elapsed < min_gap:
                time.sleep(min_gap - elapsed)
            self.last = time.monotonic()


_NVD_LIMITER = _NvdRateLimiter()


def fetch_kev() -> Dict[str, dict]:
    c = load_cache("kev", max_age_hours=12)
    if c:
        return c
    log.info("Downloading CISA KEV catalog...")
    data = http_get(KEV_URL)
    kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    save_cache("kev", kev)
    return kev


def fetch_epss_batch(cve_ids: List[str]) -> Dict[str, float]:
    if not cve_ids:
        return {}
    out: Dict[str, float] = {}
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i + 50]
        try:
            data = http_get(EPSS_API, params={"cve": ",".join(chunk)})
            for item in data.get("data", []):
                out[item["cve"]] = float(item.get("epss", 0.0))
        except Exception as e:
            log.warning(f"EPSS query failed: {e}")
    return out


def fetch_nvd_cve(cve_id: str, _retry: int = 0) -> Optional[dict]:
    params = {"cveId": cve_id}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    _NVD_LIMITER.wait()
    try:
        data = http_get(NVD_API, params=params, headers=headers)
        vulns = data.get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            if _retry >= NVD_MAX_RETRIES:
                log.warning(f"NVD rate limit exceeded for {cve_id}")
                return None
            wait = 30 * (2 ** _retry)
            log.info(f"NVD rate limited, sleeping {wait}s...")
            time.sleep(wait)
            return fetch_nvd_cve(cve_id, _retry + 1)
        log.warning(f"NVD lookup failed for {cve_id}: {e}")
        return None
    except (requests.ConnectionError, requests.Timeout):
        if _retry >= NVD_MAX_RETRIES:
            return None
        time.sleep(2 ** _retry)
        return fetch_nvd_cve(cve_id, _retry + 1)


def extract_cvss(nvd: dict) -> Optional[float]:
    m = nvd.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if key in m and m[key]:
            try:
                return float(m[key][0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def extract_cwe(nvd: dict) -> List[str]:
    cwes: List[str] = []
    for w in nvd.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    return cwes


# ================================================================
# OSV
# ================================================================
def parse_requirements(path: Path) -> List[Tuple[str, str]]:
    deps = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
            continue
        m2 = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if m2:
            deps.append((m2.group(1), ""))
    return deps


def parse_package_json(path: Path) -> List[Tuple[str, str]]:
    data = json.loads(path.read_text())
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            deps.append((name, re.sub(r"^[~^>=<]+", "", ver).strip()))
    return deps


def osv_query(package: str, version: str, ecosystem: str) -> List[dict]:
    if not version:
        return []
    payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    try:
        return http_post(OSV_API, payload).get("vulns", [])
    except Exception as e:
        log.warning(f"OSV query failed {package}=={version}: {e}")
        return []


def _osv_one(args: Tuple[str, str, str]) -> List[dict]:
    pkg, ver, eco = args
    findings = []
    for v in osv_query(pkg, ver, eco):
        f = {
            "package": pkg, "version": ver, "ecosystem": eco,
            "id": v.get("id"), "aliases": v.get("aliases", []),
            "summary": v.get("summary", ""), "source": "OSV",
            "cve_id": None, "cwe": [],
        }
        for a in f["aliases"]:
            if a.startswith("CVE-"):
                f["cve_id"] = a
                break
        db = v.get("database_specific", {}) or {}
        cwe_field = db.get("cwe_ids") or db.get("cwes") or []
        if isinstance(cwe_field, list):
            f["cwe"] = [c for c in cwe_field if str(c).startswith("CWE-")]
        findings.append(f)
    return findings


def scan_dependencies(path: Path, workers: int = 8) -> List[dict]:
    if path.name == "requirements.txt":
        deps, eco = parse_requirements(path), "PyPI"
    elif path.name == "package.json":
        deps, eco = parse_package_json(path), "npm"
    else:
        log.error(f"Unsupported file: {path.name}")
        return []

    log.info(f"Scanning {path} ({len(deps)} deps, ecosystem={eco})...")
    findings: List[dict] = []
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_osv_one, (pkg, ver, eco)): (pkg, ver)
            for pkg, ver in deps
        }
        for fut in as_completed(futures):
            if _SHUTDOWN.is_set():
                break
            findings.extend(fut.result())
            done += 1
            if done % 20 == 0 or done == len(deps):
                log.info(f"  Scanned {done}/{len(deps)}")
    return findings


# ================================================================
# ENRICHMENT
# ================================================================
def _enrich_one(cve_id: str) -> Tuple[str, Optional[dict]]:
    return cve_id, fetch_nvd_cve(cve_id)


def enrich_findings(findings: List[dict], workers: int = 1) -> List[dict]:
    if not findings:
        return findings

    log.info(f"Enriching {len(findings)} findings...")
    cve_ids = sorted({f["cve_id"] for f in findings if f.get("cve_id")})
    epss_map = fetch_epss_batch(cve_ids)
    kev_map = fetch_kev()

    nvd_cache: Dict[str, Optional[dict]] = {}
    if workers > 1 and cve_ids:
        with ThreadPoolExecutor(max_workers=min(workers, 8)) as ex:
            for cid, entry in ex.map(_enrich_one, cve_ids):
                nvd_cache[cid] = entry
    else:
        for i, cid in enumerate(cve_ids, 1):
            if _SHUTDOWN.is_set():
                break
            nvd_cache[cid] = fetch_nvd_cve(cid)
            if i % 10 == 0:
                log.info(f"  NVD enriched {i}/{len(cve_ids)}")

    for f in findings:
        cid = f.get("cve_id")
        epss = epss_map.get(cid, 0.0) if cid else 0.0
        in_kev = bool(cid and cid in kev_map)
        cvss, nvd_cwe = None, []
        entry = nvd_cache.get(cid) if cid else None
        if entry:
            cvss = extract_cvss(entry)
            nvd_cwe = extract_cwe(entry)

        merged_cwe = sorted(set((f.get("cwe") or []) + nvd_cwe))

        if in_kev:
            priority = "CRITICAL"
        elif epss >= 0.1:
            priority = "HIGH"
        elif cvss is not None and cvss >= 7.0:
            priority = "HIGH"
        elif cvss is not None and cvss >= 4.0:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        f.update({"cwe": merged_cwe, "cvss": cvss, "epss": round(epss, 4),
                  "in_kev": in_kev, "priority": priority})
        status, reason = assess_false_positive(f)
        f["false_positive_status"] = status
        f["false_positive_reason"] = reason
    return findings


def ensure_metadata(findings: List[dict]) -> None:
    for f in findings:
        cid = f.get("cve_id")
        if not cid or (f.get("cwe") and f.get("cvss") is not None):
            continue
        nvd = fetch_nvd_cve(cid)
        if not nvd:
            continue
        if not f.get("cwe"):
            f["cwe"] = extract_cwe(nvd)
        if f.get("cvss") is None:
            f["cvss"] = extract_cvss(nvd)


# ================================================================
# RISK / FALSE POSITIVE
# ================================================================
def assess_false_positive(finding: dict) -> Tuple[str, str]:
    v = finding.get("verification")
    if v:
        s = v.get("status")
        fp = v.get("fp_status")
        if s == "CONFIRMED":
            return ("CONFIRMED", v.get("evidence", "Active PoC confirmed"))
        if s == "WAF_BLOCKED":
            return ("UNVERIFIED", v.get("evidence", "Blocked by WAF"))
        if s == "NOT_REPRODUCED":
            status = fp or "LIKELY_FALSE_POSITIVE"
            return (status, v.get("evidence", "PoC did not trigger"))

    if finding.get("in_kev"):
        return ("CONFIRMED", "Listed in CISA KEV — exploited in the wild")
    if finding.get("source") == "Nuclei":
        return ("CONFIRMED", "Nuclei template triggered")

    cve = finding.get("cve_id")
    if not cve:
        return ("LIKELY_FALSE_POSITIVE", "No CVE assigned (advisory only)")

    epss = finding.get("epss", 0.0) or 0.0
    if epss >= 0.1:
        return ("LIKELY_REAL", f"High EPSS ({epss:.2%})")

    cvss = finding.get("cvss")
    if cvss is not None and cvss >= 7.0:
        return ("LIKELY_REAL", f"High CVSS ({cvss})")
    if cvss is not None:
        return ("NEEDS_REVIEW", f"CVE assigned, CVSS {cvss}, no exploitation signals")
    return ("NEEDS_REVIEW", "CVE assigned but no CVSS/EPSS available")


# ================================================================
# INJECTION POINTS
# ================================================================
FORM_RE   = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
NAME_RE   = re.compile(r'name=["\']([^"\']+)', re.I)
ACTION_RE = re.compile(r'action=["\']?([^"\'\s>]+)', re.I)
METHOD_RE = re.compile(r'method=["\']?([^"\'\s>]+)', re.I)


def extract_forms(html: str, base_url: str) -> List[dict]:
    forms = []
    for fm in FORM_RE.finditer(html):
        outer, inner = fm.group(0), fm.group(1)
        a = ACTION_RE.search(outer)
        m = METHOD_RE.search(outer)
        action = urljoin(base_url, a.group(1)) if a else base_url
        method = (m.group(1) if m else "GET").upper()
        params = [n.group(1) for n in NAME_RE.finditer(inner)]
        if params:
            forms.append({"url": action, "method": method, "params": params})
    return forms


def extract_injection_points(html: str, base_url: str) -> List[dict]:
    seen = set()
    points: List[dict] = []

    def add(url: str, method: str, params: List[str]):
        key = (url, method, tuple(sorted(params)))
        if key in seen:
            return
        seen.add(key)
        points.append({"url": url, "method": method, "params": params})

    parsed = urlparse(base_url)
    if parsed.query:
        add(base_url, "GET", list(parse_qs(parsed.query, keep_blank_values=True).keys()))
    for f in extract_forms(html, base_url):
        add(f["url"], f["method"], f["params"])
    return points


# ================================================================
# RATE LIMITER + REQUEST
# ================================================================
@dataclass
class RateLimiter:
    rate: float = 0.0
    jitter: float = 0.0
    _last: float = 0.0

    def wait(self) -> None:
        if self.rate <= 0:
            return
        now = time.monotonic()
        min_gap = 1.0 / self.rate
        elapsed = now - self._last
        if elapsed < min_gap:
            time.sleep(min_gap - elapsed)
        if self.jitter > 0:
            import random
            time.sleep(self.jitter * (0.5 + 0.5 * random.random()))
        self._last = time.monotonic()


def send_request(session, url, method, data, timeout=15,
                 limiter: Optional[RateLimiter] = None,
                 headers: Optional[dict] = None,
                 json_body: Optional[dict] = None):
    if limiter:
        limiter.wait()
    try:
        kw = {"timeout": timeout, "allow_redirects": False}
        if headers:
            kw["headers"] = headers
        m = method.upper()
        if m == "GET":
            return session.get(url, params=data, **kw)
        if m == "HEAD":
            return session.head(url, **kw)
        if json_body is not None:
            return session.post(url, json=json_body, **kw)
        return session.post(url, data=data, **kw)
    except (requests.Timeout, requests.ConnectionError,
            requests.TooManyRedirects) as e:
        log.debug(f"request error {url}: {e}")
        return None
    except Exception as e:
        log.debug(f"unexpected error {url}: {e}")
        return None


def detect_signal(exploit, baseline, payload, probe) -> Tuple[bool, str]:
    if exploit is None or baseline is None:
        return False, "request failed"
    mode = probe["detect"]

    if mode == "xss_reflection":
        for marker in probe.get("markers", []):
            if marker in exploit.text and marker not in baseline.text:
                return True, f"marker {marker!r} reflected unescaped"
        hits = match_signatures(exploit.text, XSS_SIGNATURES,
                                baseline_text=baseline.text)
        if hits:
            return True, f"XSS signatures: {hits}"
        return False, "no reflection"

    if mode == "sql":
        delta = exploit.elapsed.total_seconds() - baseline.elapsed.total_seconds()
        if delta >= probe.get("timing_threshold", 3.0):
            return True, f"timing delta {delta:.1f}s"
        hits = match_signatures(exploit.text, SQL_ERROR_SIGNATURES,
                                baseline_text=baseline.text)
        if hits:
            return True, f"SQL error signatures: {hits}"
        return False, "no signal"

    if mode == "rce":
        delta = exploit.elapsed.total_seconds() - baseline.elapsed.total_seconds()
        if delta >= probe.get("timing_threshold", 3.0):
            return True, f"timing delta {delta:.1f}s"
        hits = match_signatures(exploit.text, RCE_SIGNATURES,
                                baseline_text=baseline.text)
        if hits:
            return True, f"RCE signatures: {hits}"
        return False, "no signal"

    if mode == "pattern":
        sigs = probe.get("signatures", {})
        hits = match_signatures(exploit.text, sigs, baseline_text=baseline.text)
        if hits:
            return True, f"signatures: {hits}"
        if payload in exploit.text and payload not in baseline.text:
            return True, "payload reflected"
        enc = quote(payload, safe="")
        if enc and enc in exploit.text and enc not in baseline.text:
            return True, "payload reflected (URL-encoded)"
        return False, "no signal"

    if mode == "ssti":
        expected = probe.get("expected", "")
        if expected and expected in exploit.text and expected not in baseline.text:
            return True, f"SSTI evaluated → {expected}"
        hits = match_signatures(exploit.text, SSTI_SIGNATURES,
                                baseline_text=baseline.text)
        if hits:
            return True, f"SSTI signatures: {hits}"
        return False, "no signal"

    if mode == "redirect":
        loc = exploit.headers.get("Location", "")
        if probe.get("expected", "evil.example.com") in loc:
            return True, f"redirects to {loc}"
        hits = match_signatures(exploit.text, OPEN_REDIRECT_SIGNATURES,
                                baseline_text=baseline.text)
        if hits:
            return True, f"redirect signatures: {hits}"
        return False, "no redirect"
    return False, f"unknown detect mode {mode}"


def is_blocked(response) -> bool:
    if response is None:
        return False
    if response.status_code in (403, 406, 429, 503):
        return True
    body = (response.text or "").lower()
    for phrase in ("blocked by", "access denied", "request rejected",
                   "firewall", "captcha", "challenge"):
        if phrase in body:
            return True
    return False


# ================================================================
# CVE VERIFICATION
# ================================================================
def verify_with_cve(target_url: str, cve_id: str, session,
                    limiter: RateLimiter,
                    dry_run: bool = False) -> Optional[dict]:
    cve_id = cve_id.upper()
    probe = CVE_PROBES.get(cve_id)
    if not probe:
        return None

    n_probes = len(probe["probes"])
    if dry_run:
        paths = [p.get("path", "/") for p in probe["probes"]]
        return {
            "status": "DRY_RUN",
            "fp_status": "NEEDS_REVIEW",
            "method": f"{cve_id} {probe['label']} (dry run)",
            "evidence": f"Would test {n_probes} endpoint(s): {paths}",
        }

    log.info(f"    CVE probe: {probe['label']} ({n_probes} endpoint(s))")

    try:
        if limiter:
            limiter.wait()
        baseline = session.get(target_url, timeout=15, allow_redirects=False)
    except Exception as e:
        return {"status": "UNVERIFIED", "reason": f"Cannot reach target: {e}"}

    waf_blocks = 0
    for p in probe["probes"]:
        if _SHUTDOWN.is_set():
            break
        path = p.get("path", "/")
        method = p.get("method", "GET")
        url = urljoin(target_url, path)

        exploit = send_request(
            session, url, method,
            data=p.get("data"),
            headers=p.get("headers"),
            json_body=p.get("json_body"),
            limiter=limiter,
        )
        if exploit is None:
            continue

        if is_blocked(exploit) and not is_blocked(baseline):
            waf = detect_waf(exploit.status_code,
                             dict(exploit.headers), exploit.text)
            if waf:
                waf_blocks += 1
                continue

        require = p.get("require_status")
        if require and exploit.status_code not in require:
            continue

        hits = match_signatures(
            exploit.text, p.get("sig", {}),
            baseline_text=baseline.text if baseline else None,
        )
        if hits:
            return {
                "status": "CONFIRMED",
                "fp_status": "CONFIRMED",
                "method": f"{cve_id} {probe['label']}",
                "evidence": f"{url}: {hits}",
            }

    if waf_blocks:
        return {
            "status": "WAF_BLOCKED",
            "fp_status": "UNVERIFIED",
            "method": f"{cve_id} {probe['label']}",
            "evidence": f"{waf_blocks} CVE probe request(s) blocked by WAF",
        }

    return {
        "status": "NOT_REPRODUCED",
        "fp_status": "NEEDS_REVIEW",
        "method": f"{cve_id} {probe['label']}",
        "evidence": f"CVE-specific probes did not trigger ({n_probes} endpoint(s) tried)",
    }


# ================================================================
# CWE VERIFICATION
# ================================================================
def _baseline_for(session, pt, limiter):
    return send_request(session, pt["url"], pt["method"],
                        {p: "safe_test_123" for p in pt["params"]},
                        limiter=limiter)


def verify_with_cwe(target_url: str, cwe: str, session,
                    limiter: RateLimiter, waf_bypass: bool,
                    dry_run: bool = False) -> Optional[dict]:
    probe = CWE_PROBES.get(cwe)
    if not probe:
        return None

    try:
        page = session.get(target_url, timeout=15, allow_redirects=True)
    except Exception as e:
        return {"status": "UNVERIFIED", "reason": f"Cannot fetch target: {e}"}

    points = extract_injection_points(page.text, target_url)
    if not points:
        return {"status": "UNVERIFIED", "reason": "No parameters or forms found"}

    log.info(f"    {probe['label']}: {len(points)} injection point(s), "
             f"{len(probe['payloads'])} payload(s)")

    if dry_run:
        return {
            "status": "DRY_RUN",
            "fp_status": "NEEDS_REVIEW",
            "method": f"{probe['label']} active PoC (dry run)",
            "evidence": f"Would test {len(points)} point(s) × "
                        f"{len(probe['payloads'])} payload(s) on {target_url}",
        }

    baselines: Dict[Tuple[str, str, Tuple[str, ...]], object] = {}

    def baseline_of(pt):
        key = (pt["url"], pt["method"], tuple(sorted(pt["params"])))
        if key not in baselines:
            baselines[key] = _baseline_for(session, pt, limiter)
        return baselines[key]

    waf_blocks = 0
    for payload in probe["payloads"]:
        if _SHUTDOWN.is_set():
            break
        variants = obfuscate_payload(payload) if waf_bypass else [payload]
        for variant in variants:
            for pt in points:
                if _SHUTDOWN.is_set():
                    break
                baseline = baseline_of(pt)
                exploit = send_request(session, pt["url"], pt["method"],
                                       {p: variant for p in pt["params"]},
                                       limiter=limiter)

                if (exploit is not None and is_blocked(exploit)
                        and not is_blocked(baseline)):
                    waf = detect_waf(exploit.status_code,
                                     dict(exploit.headers), exploit.text)
                    if waf:
                        waf_blocks += 1
                        continue

                vuln, why = detect_signal(exploit, baseline, variant, probe)
                if vuln:
                    return {
                        "status": "CONFIRMED",
                        "fp_status": "CONFIRMED",
                        "method": f"{probe['label']} active PoC",
                        "evidence": f"{pt['url']} ({pt['method']}, "
                                    f"params={pt['params']}): {why}",
                    }

    if waf_blocks:
        return {
            "status": "WAF_BLOCKED",
            "fp_status": "UNVERIFIED",
            "method": f"{probe['label']} active PoC",
            "evidence": f"{waf_blocks} request(s) blocked by WAF",
        }
    return {
        "status": "NOT_REPRODUCED",
        "fp_status": "LIKELY_FALSE_POSITIVE",
        "method": f"{probe['label']} active PoC",
        "evidence": "Payloads did not trigger any indicator",
    }


# ================================================================
# NUCLEI
# ================================================================
def check_nuclei() -> bool:
    try:
        subprocess.run(["nuclei", "-version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


def verify_with_nuclei(target_url: str, cve_id: str,
                       dry_run: bool = False) -> Optional[dict]:
    if not check_nuclei():
        return None
    if dry_run:
        return {
            "status": "DRY_RUN",
            "fp_status": "NEEDS_REVIEW",
            "method": f"Nuclei {cve_id} (dry run)",
            "evidence": f"Would run nuclei -id {cve_id.lower()} against {target_url}",
        }
    log.info(f"    Running Nuclei for {cve_id}...")
    cmd = ["nuclei", "-u", target_url, "-id", cve_id.lower(),
           "-jsonl", "-silent", "-no-color"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"status": "UNVERIFIED", "reason": "Nuclei timed out"}

    if proc.stdout.strip():
        try:
            item = json.loads(proc.stdout.strip().split("\n")[0])
            return {
                "status": "CONFIRMED",
                "fp_status": "CONFIRMED",
                "method": f"Nuclei {cve_id}",
                "evidence": item.get("matched-at", "template triggered"),
            }
        except json.JSONDecodeError:
            pass

    err = (proc.stderr or "").lower()
    if "no templates" in err or "could not find" in err or "no results found" in err:
        return {"status": "NO_TEMPLATE", "reason": f"No Nuclei template for {cve_id}"}
    return {
        "status": "NOT_REPRODUCED",
        "fp_status": "LIKELY_FALSE_POSITIVE",
        "method": f"Nuclei {cve_id}",
        "evidence": "Template ran but did not trigger",
    }


# ================================================================
# ORCHESTRATOR
# ================================================================
def _best_attempt(attempts: List[dict]) -> Optional[dict]:
    if not attempts:
        return None

    def key(a):
        status = a.get("status", "")
        fp = a.get("fp_status", "")
        if fp == "LIKELY_FALSE_POSITIVE": return 0
        if fp == "NEEDS_REVIEW":          return 1
        if status == "WAF_BLOCKED":      return 2
        if status == "NOT_REPRODUCED":   return 3
        if status == "NO_TEMPLATE":      return 4
        if status == "UNVERIFIED":       return 5
        if status == "DRY_RUN":          return 6
        return 9

    return min(attempts, key=key)


def verify_findings(findings: List[dict], target_url: str,
                    *, session: requests.Session,
                    limiter: RateLimiter,
                    skip_confirmed: bool = False,
                    waf_bypass: bool = False,
                    dry_run: bool = False) -> List[dict]:
    log.info(f"Verifying {len(findings)} finding(s) against {target_url}")
    log.info("    Order: CVE-specific → Nuclei → CWE → UNVERIFIED")

    try:
        probe = session.get(target_url, timeout=15, allow_redirects=True)
        waf = detect_waf(probe.status_code, dict(probe.headers), probe.text)
        if waf:
            log.warning(f"WAF detected: {waf['vendor']} "
                        f"({', '.join(waf['evidence'][:3])})")
            log.warning("Active PoCs may be blocked. Consider --waf-bypass.")
    except Exception as e:
        log.warning(f"Could not probe target: {e}")

    for i, finding in enumerate(findings, 1):
        if _SHUTDOWN.is_set():
            log.warning("Interrupted — remaining findings left unverified.")
            break

        cve = (finding.get("cve_id") or "").upper() or None
        cwe = (finding.get("cwe") or [None])[0]

        if skip_confirmed and finding.get("false_positive_status") == "CONFIRMED":
            log.info(f"[{i}/{len(findings)}] {cve or finding.get('id')} — skipped")
            continue

        log.info(f"[{i}/{len(findings)}] {cve or finding.get('id')} "
                 f"(CWE: {cwe or 'N/A'})")

        attempts: List[dict] = []
        confirmed_result: Optional[dict] = None

        if cve and cve in CVE_PROBES:
            r = verify_with_cve(target_url, cve, session, limiter, dry_run)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed_result = r

        if not confirmed_result and cve:
            r = verify_with_nuclei(target_url, cve, dry_run=dry_run)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed_result = r

        if not confirmed_result and cwe:
            r = verify_with_cwe(target_url, cwe, session, limiter,
                                waf_bypass, dry_run=dry_run)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed_result = r

        if confirmed_result:
            finding["verification"] = confirmed_result
            log.info(f"    -> CONFIRMED: {confirmed_result.get('evidence','')[:100]}")
        else:
            best = _best_attempt(attempts)
            if best:
                finding["verification"] = best
                log.info(f"    -> {best['status']}"
                         f"{'/' + best['fp_status'] if best.get('fp_status') else ''}: "
                         f"{best.get('evidence', best.get('reason',''))[:100]}")
            else:
                finding["verification"] = {
                    "status": "UNVERIFIED",
                    "reason": "No CVE probe, Nuclei template, or CWE probe available",
                }
                log.info("    -> UNVERIFIED (no PoC available)")

        if attempts:
            finding["verification_attempts"] = [
                {"method":   a.get("method"),
                 "status":   a.get("status"),
                 "fp_status": a.get("fp_status"),
                 "evidence": a.get("evidence", a.get("reason", ""))}
                for a in attempts
            ]

        if not dry_run:
            time.sleep(1)

    for f in findings:
        status, reason = assess_false_positive(f)
        f["false_positive_status"] = status
        f["false_positive_reason"] = reason
    return findings


# ================================================================
# NUCLEI DAST
# ================================================================
def run_nuclei_dast(target: str, severity: str = "critical,high,medium",
                    tags: str = "cve,vkev,kev", timeout: int = 900) -> List[dict]:
    if not check_nuclei():
        log.error("Nuclei not installed. "
                  "Get it: https://github.com/projectdiscovery/nuclei")
        return []
    log.info(f"Running Nuclei against {target} (tags={tags})...")
    cmd = ["nuclei", "-u", target, "-tags", tags, "-jsonl", "-silent",
           "-no-color", "-severity", severity]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        log.error(f"Nuclei timed out ({timeout}s)")
        return []

    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        cls = info.get("classification", {}) or {}
        cves = cls.get("cve-id") or []
        cwes = cls.get("cwe-id") or []
        if isinstance(cves, str): cves = [cves]
        if isinstance(cwes, str): cwes = [cwes]
        findings.append({
            "package": target, "version": "", "ecosystem": "DAST",
            "id": item.get("template-id"), "aliases": [],
            "summary": info.get("name", ""), "source": "Nuclei",
            "cve_id": cves[0] if cves else None,
            "cwe": [str(c) for c in cwes if str(c).startswith("CWE-")],
            "matched_at": item.get("matched-at"),
            "severity": str(info.get("severity", "unknown")).upper(),
        })
    return findings


# ================================================================
# REPORTING (JSON + HTML)
# ================================================================
def save_json(findings: List[dict], path: Path) -> None:
    path.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"[+] JSON saved: {path}")


def save_html(findings: List[dict], path: Path) -> None:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows = []
    for f in sorted(findings, key=lambda x: (order.get(x.get("priority"), 4),
                                              -(x.get("epss") or 0))):
        cve = f.get("cve_id") or f.get("id") or "UNKNOWN"
        cwe_list = f.get("cwe") or []
        cwe_name = cwe_friendly(cwe_list[0]) if cwe_list else "Unknown"
        prio = f.get("priority", "UNKNOWN")
        fp = f.get("false_positive_status", "UNKNOWN")
        reason = (f.get("false_positive_reason") or "")[:200]
        color = {"CRITICAL": "#b71c1c", "HIGH": "#d84315",
                 "MEDIUM": "#f57f17", "LOW": "#2e7d32"}.get(prio, "#555")
        fp_color = {"CONFIRMED": "#b71c1c", "LIKELY_REAL": "#d84315",
                    "NEEDS_REVIEW": "#f57f17", "LIKELY_FALSE_POSITIVE": "#2e7d32",
                    "UNVERIFIED": "#555"}.get(fp, "#555")
        rows.append(
            f"<tr><td style='color:{color};font-weight:bold'>{prio}</td>"
            f"<td>{cve}<br><small>{cwe_name} {', '.join(cwe_list)}</small></td>"
            f"<td>{f.get('package','?')} <small>{f.get('version','')}</small></td>"
            f"<td>{f.get('cvss') or '-'}</td>"
            f"<td>{(f.get('epss') or 0):.2%}</td>"
            f"<td>{'Yes' if f.get('in_kev') else 'No'}</td>"
            f"<td style='color:{fp_color};font-weight:bold'>{fp}</td>"
            f"<td><small>{reason}</small></td></tr>"
        )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CVE Scan Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:20px;color:#222}}
h1{{border-bottom:2px solid #333;padding-bottom:8px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f4f4f4;position:sticky;top:0}}
tr:nth-child(even){{background:#fafafa}}
small{{color:#666}}.meta{{color:#666;margin-bottom:16px}}
</style></head><body>
<h1>CVE Scan Report</h1>
<div class="meta">Generated: {time.strftime("%Y-%m-%d %H:%M:%S")} ·
{len(findings)} finding(s) · cve_scanner v{__version__}</div>
<table><thead><tr>
<th>Priority</th><th>CVE / Type</th><th>Package</th><th>CVSS</th>
<th>EPSS</th><th>KEV</th><th>FP Status</th><th>Reason</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>"""
    path.write_text(html, encoding="utf-8")
    print(f"[+] HTML saved:  {path}")


def print_report(findings: List[dict]) -> None:
    if not findings:
        print("\n[+] No known vulnerabilities found.")
        return
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda f: (order.get(f.get("priority"), 4),
                                 -(f.get("epss") or 0)))
    print("\n" + "=" * 88)
    print(f"SCAN RESULTS: {len(findings)} finding(s)")
    print("=" * 88)
    for f in findings:
        cve = f.get("cve_id") or f.get("id") or "UNKNOWN"
        cwe_list = f.get("cwe") or []
        cwe_name = cwe_friendly(cwe_list[0]) if cwe_list else "Unknown"
        cwe_str = ", ".join(cwe_list) if cwe_list else "N/A"
        prio = f.get("priority", "UNKNOWN")
        fp = f.get("false_positive_status", "UNKNOWN")
        reason = f.get("false_positive_reason", "")
        flags = []
        if f.get("in_kev"): flags.append("KEV")
        if (f.get("epss") or 0) >= 0.1: flags.append(f"EPSS {f['epss']:.2%}")
        if f.get("cvss") is not None: flags.append(f"CVSS {f['cvss']}")
        print(f"\n[{prio}] {cve}  ({cwe_name})")
        print(f"  Package   : {f.get('package','?')} {f.get('version','')} "
              f"({f.get('ecosystem','')})")
        print(f"  CWE Type  : {cwe_str} — {cwe_name}")
        print(f"  FP Status : {fp}")
        if reason: print(f"  Reason    : {reason[:180]}")
        if flags:  print(f"  Signals   : {'  '.join(flags)}")
        if f.get("summary"):
            print(f"  Summary   : {f['summary'][:200]}")
        if f.get("matched_at"):
            print(f"  Matched   : {f['matched_at']}")
        attempts = f.get("verification_attempts")
        if attempts:
            print("  Attempts  :")
            for a in attempts:
                fp_part = f"/{a['fp_status']}" if a.get("fp_status") else ""
                print(f"    - {a.get('method')}: {a.get('status')}{fp_part}")
    counts = Counter(f.get("false_positive_status") for f in findings)
    print("\n" + "-" * 88)
    for key in ("CONFIRMED", "LIKELY_REAL", "NEEDS_REVIEW",
                "LIKELY_FALSE_POSITIVE", "UNVERIFIED"):
        if counts.get(key):
            print(f"  {key:<22}: {counts[key]}")
    print(f"  {'TOTAL':<22}: {len(findings)}")
    print("-" * 88)


# ================================================================
# CLI HELPERS
# ================================================================
def _setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1: level = logging.INFO
    if verbose >= 2: level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _setup_sigint() -> None:
    def handler(sig, frame):
        if _SHUTDOWN.is_set():
            log.warning("Forcing exit.")
            sys.exit(130)
        log.warning("Interrupt received — finishing current request, "
                    "then saving partial results (Ctrl+C again to force).")
        _SHUTDOWN.set()
    signal.signal(signal.SIGINT, handler)


def _parse_header_arg(value: str) -> Tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"Header must be 'Name: value', got: {value}")
    k, v = value.split(":", 1)
    return k.strip(), v.strip()


def _validate_target(url: str) -> str:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise argparse.ArgumentTypeError(
            f"Target must start with http:// or https://, got: {url}")
    return url


def _apply_profile(args) -> None:
    if args.profile == "stealth":
        if args.rate == 0.0: args.rate = 1.0
        if args.jitter == 0.0: args.jitter = 1.0


# ================================================================
# CLI
# ================================================================
def main() -> None:
    ap = argparse.ArgumentParser(
        description=f"Free CVE scanner — scan deps or URLs, probe with PoCs "
                    f"(v{__version__})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py scan requirements.txt -o findings.json --html report.html
  python scanner.py scan package.json
  python scanner.py scan https://staging.example.com --severity critical,high
  python scanner.py probe findings.json --target https://staging.example.com \\
      --header "Authorization: Bearer $TOKEN" -o verified.json --html verified.html
  python scanner.py enrich CVE-2024-3400
  python scanner.py --list-cves
  python scanner.py --list-payloads
        """,
    )
    ap.add_argument("--version", action="version",
                    version=f"cve_scanner {__version__}")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--list-payloads", action="store_true",
                    help="Print all CWE probes and exit")
    ap.add_argument("--list-cves", action="store_true",
                    help="Print all CVE probes and exit")

    sub = ap.add_subparsers(dest="command")

    p_scan = sub.add_parser(
        "scan",
        help="Scan a dependency file (OSV) or a URL (Nuclei DAST)",
    )
    p_scan.add_argument("target",
                        help="requirements.txt, package.json, or https://...")
    p_scan.add_argument("-o", "--output", type=Path, help="JSON output path")
    p_scan.add_argument("--html", type=Path, help="HTML output path")
    p_scan.add_argument("--workers", type=int, default=8,
                        help="Concurrent workers for dep scan (default 8)")
    p_scan.add_argument("--severity", default="critical,high,medium",
                        help="DAST severity filter")
    p_scan.add_argument("--tags", default="cve,vkev,kev",
                        help="DAST template tags")
    p_scan.add_argument("--timeout", type=int, default=900,
                        help="DAST scan timeout in seconds")

    p_probe = sub.add_parser(
        "probe",
        help="Verify findings against a live target with CVE + CWE PoCs",
    )
    p_probe.add_argument("report", type=Path,
                         help="Findings JSON produced by `scan`")
    p_probe.add_argument("--target", required=True, type=_validate_target,
                         help="Live target URL")
    p_probe.add_argument("-o", "--output", type=Path, help="JSON output path")
    p_probe.add_argument("--html", type=Path, help="HTML output path")
    p_probe.add_argument("--skip-confirmed", action="store_true")
    p_probe.add_argument("--dry-run", action="store_true",
                         help="Show planned probes without sending payloads")
    p_probe.add_argument("--waf-bypass", action="store_true",
                         help="Apply payload mutation to evade WAFs")
    p_probe.add_argument("--insecure", action="store_true",
                         help="Skip TLS certificate verification")
    p_probe.add_argument("--header", action="append", type=_parse_header_arg,
                         default=[], help="HTTP header 'K: V' (repeatable)")
    p_probe.add_argument("--basic-auth", type=str, default=None,
                         help="Basic auth user:pass")
    p_probe.add_argument("--cookie", type=str, default=None,
                         help="Cookie header value")
    p_probe.add_argument("--rate", type=float, default=0.0,
                         help="Requests per second (0 = unlimited)")
    p_probe.add_argument("--jitter", type=float, default=0.0,
                         help="Random delay jitter in seconds")
    p_probe.add_argument("--profile",
                         choices=["stealth", "normal", "aggressive"],
                         default="normal")

    p_enrich = sub.add_parser("enrich", help="Look up a single CVE")
    p_enrich.add_argument("cve_id")

    args = ap.parse_args()
    _setup_logging(args.verbose)
    _setup_sigint()

    if args.list_payloads:
        print(f"cve_scanner v{__version__} — CWE payload library\n")
        for cwe, probe in CWE_PROBES.items():
            print(f"{cwe}  {probe['label']}")
            for p in probe["payloads"]:
                print(f"    {p[:100]}")
            print()
        return

    if args.list_cves:
        print(f"cve_scanner v{__version__} — CVE-specific probes "
              f"({len(CVE_PROBES)} entries)\n")
        for cve, probe in CVE_PROBES.items():
            print(f"{cve}  {probe['label']}")
            for p in probe["probes"]:
                method = p.get("method", "GET")
                path = p.get("path", "/")
                print(f"    {method} {path}")
            print()
        return

    if not args.command:
        ap.print_help()
        return

    if args.command == "scan":
        target = args.target
        if target.startswith(("http://", "https://")):
            findings = run_nuclei_dast(
                target, args.severity, args.tags, args.timeout
            )
        else:
            path = Path(target)
            if not path.exists():
                log.error(f"File not found: {path}")
                sys.exit(1)
            findings = scan_dependencies(path, args.workers)

        if findings:
            findings = enrich_findings(findings, workers=args.workers)

        print_report(findings)
        if args.output: save_json(findings, args.output)
        if args.html:   save_html(findings, args.html)

    elif args.command == "probe":
        if not args.report.exists():
            log.error(f"Report not found: {args.report}")
            sys.exit(1)
        findings = json.loads(args.report.read_text())
        ensure_metadata(findings)
        _apply_profile(args)

        user_headers = {k: v for k, v in args.header}
        basic_auth = tuple(args.basic_auth.split(":", 1)) \
                     if args.basic_auth else None
        session = build_session(insecure=args.insecure,
                                user_headers=user_headers,
                                basic_auth=basic_auth,
                                cookie=args.cookie)
        limiter = RateLimiter(rate=args.rate, jitter=args.jitter)

        findings = verify_findings(
            findings, args.target,
            session=session, limiter=limiter,
            skip_confirmed=args.skip_confirmed,
            waf_bypass=args.waf_bypass,
            dry_run=args.dry_run,
        )
        print_report(findings)
        if args.output: save_json(findings, args.output)
        if args.html:   save_html(findings, args.html)

    elif args.command == "enrich":
        cve = args.cve_id.upper()
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            log.error(f"Invalid CVE ID: {cve} (expected CVE-YYYY-NNNN)")
            sys.exit(1)
        kev = fetch_kev()
        epss = fetch_epss_batch([cve])
        nvd = fetch_nvd_cve(cve)
        cwes = extract_cwe(nvd) if nvd else []
        cvss = extract_cvss(nvd) if nvd else None
        has_probe = cve in CVE_PROBES
        print(f"\nCVE      : {cve}")
        print(f"In KEV   : {'YES — actively exploited' if cve in kev else 'NO'}")
        print(f"EPSS     : {epss.get(cve, 0.0):.2%}")
        print(f"CVSS     : {cvss if cvss is not None else 'N/A'}")
        print(f"CWE Type : {cwe_list_friendly(cwes)}")
        probe_note = (
            f"available — {CVE_PROBES[cve]['label']}"
            if has_probe else "not bundled (use Nuclei)"
        )
        print(f"CVE PoC  : {probe_note}")
        if nvd:
            d = (nvd.get("descriptions") or [{}])[0].get("value", "")
            print(f"Summary  : {d[:500]}")


if __name__ == "__main__":
    main()
