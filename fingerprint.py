"""
fingerprint.py — Detect real host libraries/versions and map them to CVEs
via NVD's CPE API.

Approach:
  1. Pull HTTP headers, HTML meta tags, script src, cookies.
  2. Match against technology signatures (version-aware regexes).
  3. Convert detected (vendor, product, version) to a CPE 2.3 string.
  4. Query NVD for CVEs whose cpeMatch range includes that version.
  5. Return findings compatible with scanner.py's schema.
"""
from __future__ import annotations

import logging
import re
from typing import Callable, Dict, List, Optional, Tuple

import requests

try:
    from packaging.version import Version, InvalidVersion
    _HAVE_PACKAGING = True
except ImportError:
    _HAVE_PACKAGING = False
    Version = None
    InvalidVersion = Exception

log = logging.getLogger("cve_scanner")


# ================================================================
# NVD CPE API
# ================================================================
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ================================================================
# TECHNOLOGY SIGNATURES
# ================================================================
#   cpe_vendor / cpe_product   — used to build CPE 2.3
#   header_regex               — (pattern, group_index | fallback) OR plain str
#   html_regexes               — list of patterns to run on body
#   cookie_regex               — (cookie_pattern, fallback_version) or None
TECH_SIGNATURES: Dict[str, dict] = {
    "Apache HTTP Server": {
        "cpe_vendor": "apache",
        "cpe_product": "http_server",
        "header_regex": (r"Server:\s*Apache/([\d.]+)", 1),
    },
    "nginx": {
        "cpe_vendor": "nginx",
        "cpe_product": "nginx",
        "header_regex": (r"Server:\s*nginx/([\d.]+)", 1),
    },
    "Microsoft IIS": {
        "cpe_vendor": "microsoft",
        "cpe_product": "internet_information_services",
        "header_regex": (r"Server:\s*Microsoft-IIS/([\d.]+)", 1),
    },
    "PHP": {
        "cpe_vendor": "php",
        "cpe_product": "php",
        "header_regex": (r"X-Powered-By:\s*PHP/([\d.]+)", 1),
        "html_regexes": [r"PHP/([\d.]+)"],
    },
    "ASP.NET": {
        "cpe_vendor": "microsoft",
        "cpe_product": "asp.net",
        "header_regex": (r"X-AspNet-Version:\s*([\d.]+)", 1),
    },
    "jQuery": {
        "cpe_vendor": "jquery",
        "cpe_product": "jquery",
        "html_regexes": [
            r"jquery[.-]([\d.]+)(?:\.min)?\.js",
            r"jQuery\s+v?([\d.]+)",
        ],
    },
    "WordPress": {
        "cpe_vendor": "wordpress",
        "cpe_product": "wordpress",
        "html_regexes": [
            r'<meta name="generator" content="WordPress ([\d.]+)',
            r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)",
        ],
    },
    "Drupal": {
        "cpe_vendor": "drupal",
        "cpe_product": "drupal",
        "html_regexes": [r'<meta name="Generator" content="Drupal ([\d.]+)'],
    },
    "Joomla": {
        "cpe_vendor": "joomla",
        "cpe_product": "joomla",
        "html_regexes": [r'<meta name="generator" content="Joomla! ([\d.]+)'],
    },
    "Spring Framework": {
        "cpe_vendor": "vmware",
        "cpe_product": "spring_framework",
        "cookie_regex": (r"JSESSIONID", None),
    },
    "Apache Tomcat": {
        "cpe_vendor": "apache",
        "cpe_product": "tomcat",
        "html_regexes": [r"Apache Tomcat/([\d.]+)"],
    },
    "Jenkins": {
        "cpe_vendor": "jenkins",
        "cpe_product": "jenkins",
        "header_regex": (r"X-Jenkins:\s*([\d.]+)", 1),
    },
    "GitLab": {
        "cpe_vendor": "gitlab",
        "cpe_product": "gitlab",
        "header_regex": (r"X-Gitlab-Version:\s*([\d.]+)", 1),
    },
    "Grafana": {
        "cpe_vendor": "grafana",
        "cpe_product": "grafana",
        "header_regex": (r"X-Grafana-Version:\s*([\d.]+)", 1),
    },
    "Elasticsearch": {
        "cpe_vendor": "elastic",
        "cpe_product": "elasticsearch",
        "html_regexes": [r'"number"\s*:\s*"([\d.]+)"'],
    },
    "OpenSSL": {
        "cpe_vendor": "openssl",
        "cpe_product": "openssl",
        "header_regex": (r"OpenSSL/([\d.]+[a-z]?)", 1),
    },
    "Cisco IOS XE": {
        "cpe_vendor": "cisco",
        "cpe_product": "ios_xe",
        "html_regexes": [r"Cisco IOS XE[^<]*?(\d+\.\d+\.\d+[a-z]?)"],
    },
    "Fortinet FortiOS": {
        "cpe_vendor": "fortinet",
        "cpe_product": "fortios",
        "html_regexes": [r"FortiOS[^<]*?([\d.]+)"],
    },
    "Citrix NetScaler": {
        "cpe_vendor": "citrix",
        "cpe_product": "netscaler_application_delivery_controller",
        "html_regexes": [r"Citrix (?:ADC|NetScaler)[^<]*?([\d.]+)"],
    },
}


# ================================================================
# CPE helpers
# ================================================================
def _build_cpe_uri(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _parse_version(s: Optional[str]) -> Optional["Version"]:
    if not s or not _HAVE_PACKAGING:
        return None
    try:
        return Version(s)
    except Exception:
        return None


def _version_in_range(
    detected: str,
    start_incl: Optional[str],
    start_excl: Optional[str],
    end_incl: Optional[str],
    end_excl: Optional[str],
) -> bool:
    """Return True if `detected` falls in the CPE range."""
    v = _parse_version(detected)
    if v is None:
        return False

    si = _parse_version(start_incl)
    se = _parse_version(start_excl)
    ei = _parse_version(end_incl)
    ee = _parse_version(end_excl)

    if si is not None and v < si:
        return False
    if se is not None and v <= se:
        return False
    if ei is not None and v > ei:
        return False
    if ee is not None and v >= ee:
        return False
    return True


# ================================================================
# NVD CPE query
# ================================================================
def lookup_cves_for_cpe(
    vendor: str,
    product: str,
    version: str,
    session: requests.Session,
    limiter: Optional[Callable[[], None]] = None,
    timeout: int = 30,
) -> List[dict]:
    """
    Query NVD for CVEs affecting (vendor, product, version).
    `limiter` is an optional callable that throttles NVD access.
    """
    if limiter:
        limiter()

    params = {
        "cpeName": _build_cpe_uri(vendor, product, version),
        "resultsPerPage": 50,
    }
    try:
        r = session.get(NVD_CPE_API, params=params, timeout=timeout)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        log.warning(f"NVD CPE query failed for {vendor}/{product}/{version}: {e}")
        return []

    findings: List[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # Confirm version falls in the CPE range for THIS cpe match
        matched = False
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    criteria = match.get("criteria", "")
                    if f":{vendor}:{product}:" not in criteria:
                        continue

                    start_incl = match.get("versionStartIncluding")
                    start_excl = match.get("versionStartExcluding")
                    end_incl = match.get("versionEndIncluding")
                    end_excl = match.get("versionEndExcluding")

                    if start_incl or start_excl or end_incl or end_excl:
                        if _version_in_range(
                            version, start_incl, start_excl, end_incl, end_excl
                        ):
                            matched = True
                    else:
                        # No range → exact-version CPE
                        parts = criteria.split(":")
                        if len(parts) > 5 and parts[4] == version:
                            matched = True
                    if matched:
                        break
                if matched:
                    break
            if matched:
                break

        if not matched:
            continue

        # Extract CVSS
        cvss = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                try:
                    cvss = float(metrics[key][0]["cvssData"]["baseScore"])
                except (KeyError, TypeError, ValueError):
                    pass
                break

        # Extract CWEs
        cwes: List[str] = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-") and val not in cwes:
                    cwes.append(val)

        descs = cve.get("descriptions") or [{}]
        summary = (descs[0] or {}).get("value", "")[:300]

        findings.append({
            "cve_id": cve_id,
            "package": product,
            "version": version,
            "ecosystem": "CPE",
            "cwe": cwes,
            "cvss": cvss,
            "summary": summary,
            "source": "Fingerprint",
            "in_kev": False,
            "epss": 0.0,
            "priority": "HIGH" if (cvss or 0) >= 7.0 else "MEDIUM",
            "false_positive_status": "NEEDS_REVIEW",
            "false_positive_reason": (
                f"Fingerprint detected {vendor}/{product} {version} "
                f"matching CPE range for {cve_id}"
            ),
        })

    return findings


# ================================================================
# Fingerprinting
# ================================================================
def fingerprint_and_lookup(
    target: str,
    session: requests.Session,
    limiter: Optional[Callable[[], None]] = None,
    timeout: int = 20,
) -> Tuple[Dict[str, str], List[dict]]:
    """
    Fingerprint the target and return:
      detected — {tech_name: version}
      findings — CVEs for detected vulnerable versions
    """
    try:
        r = session.get(target, timeout=timeout, allow_redirects=True)
    except Exception as e:
        log.warning(f"Fingerprint fetch failed: {e}")
        return {}, []

    headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text or ""
    cookies = r.headers.get("Set-Cookie", "")

    detected: Dict[str, str] = {}

    for name, sig in TECH_SIGNATURES.items():
        version: Optional[str] = None

        # 1. Header regex
        hr = sig.get("header_regex")
        if isinstance(hr, tuple) and len(hr) == 2:
            pattern, group_idx = hr
            m = re.search(pattern, headers_text, re.I)
            if m:
                try:
                    version = m.group(group_idx) if group_idx else (m.group(1) if m.lastindex else None)
                except (IndexError, TypeError):
                    version = None

        # 2. HTML regexes
        if not version:
            for pattern in sig.get("html_regexes", []):
                m = re.search(pattern, body, re.I)
                if m and m.lastindex:
                    version = m.group(1)
                    break

        # 3. Cookie regex (presence-only)
        if not version:
            cr = sig.get("cookie_regex")
            if isinstance(cr, tuple) and len(cr) == 2:
                pattern, fallback = cr
                if re.search(pattern, cookies):
                    version = fallback  # may be None → skip below

        if version:
            detected[name] = version

    # Look up CVEs per detected technology
    findings: List[dict] = []
    for name, version in detected.items():
        sig = TECH_SIGNATURES[name]
        if not version:
            continue
        findings.extend(
            lookup_cves_for_cpe(
                sig["cpe_vendor"],
                sig["cpe_product"],
                version,
                session,
                limiter=limiter,
            )
        )

    return detected, findings
