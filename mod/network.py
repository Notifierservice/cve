"""
network.py — target normalization, port scanning, banner grabbing, TLS
inspection for scanner.py.

Non-invasive by design:
  - Port scan uses TCP connect() (no SYN flood, no half-open, no OS detection)
  - Banner grab reads server greeting or sends a minimal probe
  - TLS inspection uses unverified handshake (cert details only)
"""
from __future__ import annotations

import concurrent.futures
import logging
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("cve_scanner")


# ================================================================
# COMMON PORTS
# ================================================================
COMMON_PORTS: Dict[int, str] = {
    # Remote access
    22: "SSH", 23: "Telnet", 3389: "RDP",
    # File transfer
    21: "FTP", 445: "SMB", 2049: "NFS",
    # Mail
    25: "SMTP", 110: "POP3", 143: "IMAP", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S",
    # Directory
    389: "LDAP", 636: "LDAPS",
    # DNS
    53: "DNS",
    # Web
    80: "HTTP", 443: "HTTPS", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9000: "HTTP-Alt", 9090: "HTTP-Alt",
    # Databases
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis",
    27017: "MongoDB", 27018: "MongoDB-Alt",
    # Search
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    # Container / orchestration
    2375: "Docker", 2376: "Docker-TLS", 6443: "K8s-API",
    10250: "Kubelet",
}

# Ports that require SSL/TLS on the first byte
SSL_PORTS = {443, 636, 993, 995, 8443, 2376}


# ================================================================
# TARGET NORMALIZATION
# ================================================================
def normalize_target(value: str) -> List[str]:
    """
    Convert any IP, domain, or URL into candidate base URLs (in try-order).

      https://example.com/path → [https://example.com/path]
      192.168.1.1              → [https://192.168.1.1, http://192.168.1.1]
      192.168.1.1:8080         → [https://192.168.1.1:8080, http://192.168.1.1:8080]
      example.com              → [https://example.com, http://example.com]
      ::1                      → [https://[::1], http://[::1]]
      [::1]:8080               → [https://[::1]:8080, http://[::1]:8080]
    """
    value = value.strip().rstrip("/")
    if not value:
        return []

    # Already has scheme
    if value.startswith(("http://", "https://")):
        return [value]

    # Bracketed IPv6
    if value.startswith("["):
        if "]" in value:
            host_part, _, rest = value.partition("]")
            host = host_part + "]"
            if rest.startswith(":"):
                port = rest[1:]
                return [f"https://{host}:{port}", f"http://{host}:{port}"]
            return [f"https://{host}", f"http://{host}"]

    # Bare IPv6 (multiple colons, no scheme)
    if value.count(":") > 1:
        return [f"https://[{value}]", f"http://[{value}]"]

    # host:port
    if ":" in value:
        host, _, port = value.partition(":")
        return [f"https://{host}:{port}", f"http://{host}:{port}"]

    # Bare IP or domain — try https first
    return [f"https://{value}", f"http://{value}"]


def extract_host(target: str) -> str:
    """Extract hostname from any target format (no scheme, no port, no path)."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target

    if target.startswith("["):
        return target.split("]")[0].strip("[]")

    if ":" in target and target.count(":") == 1:
        return target.split(":")[0]

    return target


def extract_port(target: str, default: Optional[int] = None) -> Optional[int]:
    """Extract port from any target format."""
    if "://" in target:
        parsed = urlparse(target)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    if target.startswith("[") and "]:" in target:
        try:
            return int(target.split("]:")[1].split("/")[0])
        except (ValueError, IndexError):
            return default

    if target.count(":") == 1:
        try:
            return int(target.split(":")[1].split("/")[0])
        except (ValueError, IndexError):
            return default

    return default


def is_ip_address(value: str) -> bool:
    """True if value looks like IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, value)
        return True
    except (OSError, ValueError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value.strip("[]"))
        return True
    except (OSError, ValueError):
        pass
    return False


# ================================================================
# PORT SCAN
# ================================================================
def port_scan(
    host: str,
    ports: Optional[Dict[int, str]] = None,
    timeout: float = 0.5,
    max_workers: int = 50,
) -> Dict[int, str]:
    """
    TCP connect scan. Returns {port: service_name} for open ports.
    Non-invasive: only completes the three-way handshake.
    """
    if ports is None:
        ports = COMMON_PORTS

    open_ports: Dict[int, str] = {}

    def _check(port: int) -> Tuple[int, bool]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                open_ports[port] = ports[port]

    return open_ports


# ================================================================
# BANNER GRAB
# ================================================================
def banner_grab(
    host: str,
    port: int,
    timeout: float = 3.0,
    use_ssl: bool = False,
) -> Optional[str]:
    """
    Read a service banner or send a minimal probe. Returns text or None.
    Never sends exploit payloads — only benign protocol handshakes.
    """
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

        # Services that announce themselves on connect
        if port in (21, 22, 25, 110, 143, 587, 993, 995):
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass

        # MySQL — greeting includes version
        elif port == 3306:
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass

        # Redis — needs PING
        elif port == 6379:
            sock.sendall(b"PING\r\n")
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass

        # LDAP — send simple bind request (harmless)
        elif port in (389, 636):
            # minimal anonymous bind
            sock.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass

        # HTTP-ish — send GET
        elif port in (80, 443, 8000, 8008, 8080, 8081, 8443, 8888,
                      9000, 9090, 9200, 2375, 2376, 6443, 10250):
            path = "/version" if port in (2375, 2376) else "/"
            req = (
                f"GET {path} HTTP/1.0\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: cve-scanner/9.0\r\n"
                f"Accept: */*\r\n\r\n"
            )
            sock.sendall(req.encode())

            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(len(c) for c in chunks) > 65536:
                        break
                except socket.timeout:
                    break
            banner = b"".join(chunks)

        sock.close()

        if banner:
            return banner.decode("utf-8", errors="replace")[:8192]
        return None

    except Exception:
        return None


def auto_banner_grab(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Try the right protocol wrapper for this port; fall back to the other."""
    use_ssl = port in SSL_PORTS
    banner = banner_grab(host, port, timeout=timeout, use_ssl=use_ssl)
    if banner:
        return banner
    return banner_grab(host, port, timeout=timeout, use_ssl=not use_ssl)


# ================================================================
# TLS INSPECTION
# ================================================================
def tls_info(host: str, port: int = 443, timeout: float = 5.0) -> Optional[dict]:
    """Get TLS certificate details (subject, issuer, SAN, expiry)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for _, v in cert.get("subjectAltName", [])]
                return {
                    "subject": subject,
                    "issuer": issuer,
                    "san": san,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "tls_version": ssock.version(),
                    "cipher": cipher[0] if cipher else None,
                }
    except Exception:
        return None


# ================================================================
# WORKING URL DETECTION
# ================================================================
def detect_working_url(
    candidates: List[str],
    timeout: float = 10.0,
    insecure: bool = True,
) -> Optional[Tuple[str, int]]:
    """
    Try each candidate URL. Return (working_url, status_code) or None.
    Follows redirects to find the canonical URL.
    """
    try:
        import requests
        if insecure:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass
    except ImportError:
        return None

    for url in candidates:
        try:
            r = requests.get(
                url, timeout=timeout, verify=not insecure, allow_redirects=True
            )
            return (url, r.status_code)
        except Exception:
            continue
    return None
