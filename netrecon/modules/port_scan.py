"""
Threaded TCP port scanner with service and version fingerprinting.

After a connect succeeds the scanner passively reads whatever the service
sends, then sends one protocol-appropriate probe when the service stays
quiet (HTTP HEAD/GET, Redis INFO, Memcached version, MongoDB isMaster,
FTP anonymous login, or a TLS handshake). Banners are untrusted: reads are
capped and timed out, text is decoded lossily, control characters are
stripped, and nothing from the banner is evaluated or passed to a shell.

VERSION_RULES is a small curated heuristic. It is not a CVE database.
"""
import errno
import re
import socket
import ssl
import struct
import sys
import warnings
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from ..models import PortEntry

# ── Profiles ──────────────────────────────────────────────────────────

_TOP20: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
]

# Placed just after the classic top 20 so `--top-ports 40` already covers
# databases and common admin planes. Names stay stable for --profile.
_TOP_PRIORITY: list[int] = [
    5432, 6379, 27017, 9200, 11211, 2375, 8443, 8000, 587, 6443,
    2376, 10250, 5601, 15672, 5984, 9042, 2181, 27018, 9443, 2121,
]

PROFILES: dict[str, list[int]] = {
    "top20": list(_TOP20),
    "top100": sorted({
        21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 139, 143,
        161, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995,
        1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
        3306, 3389, 4444, 5000, 5432, 5900, 6379, 6667, 7001, 7070,
        8000, 8008, 8080, 8443, 8888, 9090, 9200, 9300, 10000, 27017,
        69, 79, 81, 113, 137, 138, 179, 427, 497, 543, 544, 548, 554, 646,
        1025, 1026, 1027, 1110, 1720, 1755, 1900, 2000, 2121, 2717, 3000,
        3128, 3986, 5001, 5060, 5357, 5666, 5800, 5985, 6000, 7000, 8009,
        8081, 8200, 9000, 9100, 9999, 11211, 49152,
    }),
    "web":  [80, 443, 8000, 8008, 8080, 8443, 8888, 9090, 9443],
    "db":   [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 28015,
             5984, 9042],
    "mail": [25, 110, 143, 465, 587, 993, 995],
}


def _ordered_union(*groups: list[int]) -> list[int]:
    ordered: list[int] = []
    seen: set[int] = set()
    for group in groups:
        for port in group:
            if port not in seen:
                seen.add(port)
                ordered.append(port)
    return ordered


# Curated order for --top-ports. Longer than top100 because it appends
# admin/database ports that the named top100 profile does not include.
TOP_PORTS: list[int] = _ordered_union(_TOP20, _TOP_PRIORITY, PROFILES["top100"])

# Fallback names when getservbyport has no entry (common on slim images).
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 2121: "ftp",
    2181: "zookeeper", 2375: "docker", 2376: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5601: "kibana", 5900: "vnc",
    5984: "couchdb", 5985: "winrm", 6379: "redis", 6443: "kubernetes",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 9042: "cassandra",
    9200: "elasticsearch", 9300: "elasticsearch", 10250: "kubelet",
    11211: "memcached", 15672: "rabbitmq", 27017: "mongodb", 27018: "mongodb",
}

RISK_HINTS: dict[int, str] = {
    21:    "FTP — cleartext credentials; check for anonymous login",
    22:    "SSH — ensure key-auth only, password auth disabled",
    23:    "Telnet — cleartext; replace with SSH",
    25:    "SMTP — check for open relay misconfiguration",
    53:    "DNS — test for zone transfer (AXFR) exposure",
    69:    "TFTP — no authentication; can leak configs and firmware",
    80:    "HTTP — no encryption; redirect to HTTPS",
    110:   "POP3 — cleartext; prefer POP3S (port 995)",
    135:   "RPC/DCOM — high-value Windows attack surface",
    139:   "NetBIOS — legacy SMB; disable if unused",
    143:   "IMAP — cleartext; prefer IMAPS (port 993)",
    161:   "SNMP — default community strings often unchanged",
    389:   "LDAP — cleartext; prefer LDAPS (port 636)",
    445:   "SMB — patch for EternalBlue (MS17-010)",
    873:   "rsync — check for modules exposed without authentication",
    1433:  "MSSQL — database; should not be internet-facing",
    1521:  "Oracle DB — should not be internet-facing",
    2049:  "NFS — check exports; restrict to trusted hosts",
    3306:  "MySQL — should not be internet-facing",
    3389:  "RDP — common brute-force target; restrict to VPN",
    4444:  "⚠  Common Metasploit/reverse shell default — investigate",
    5432:  "PostgreSQL — should not be internet-facing",
    5900:  "VNC — ensure strong authentication",
    5985:  "WinRM — remote management; restrict to trusted hosts",
    6379:  "Redis — often unauthenticated by default",
    9200:  "Elasticsearch — often unauthenticated by default",
    11211: "Memcached — often unauthenticated; abused for amplification",
    27017: "MongoDB — often unauthenticated by default",
}

# Notable exposures keyed by port. These are observations about what is
# reachable, not vulnerability matches.
EXPOSURE_FINDINGS: dict[int, str] = {
    21:    "Exposed FTP",
    23:    "Exposed Telnet — cleartext administration",
    445:   "Exposed SMB",
    1433:  "Exposed Microsoft SQL Server",
    1521:  "Exposed Oracle database",
    2049:  "Exposed NFS",
    2121:  "Exposed FTP",
    2181:  "Exposed ZooKeeper",
    2375:  "Exposed Docker API — plaintext daemon port",
    2376:  "Exposed Docker API — TLS daemon port",
    3306:  "Exposed MySQL or MariaDB",
    3389:  "Exposed RDP",
    5432:  "Exposed PostgreSQL",
    5601:  "Exposed Kibana",
    5900:  "Exposed VNC",
    5984:  "Exposed CouchDB",
    6379:  "Exposed Redis — often unauthenticated",
    6443:  "Exposed Kubernetes API",
    9042:  "Exposed Cassandra",
    9200:  "Exposed Elasticsearch — often unauthenticated",
    9300:  "Exposed Elasticsearch transport",
    10250: "Exposed kubelet API",
    11211: "Exposed Memcached — often unauthenticated",
    15672: "Exposed RabbitMQ management",
    27017: "Exposed MongoDB — often unauthenticated",
    27018: "Exposed MongoDB — often unauthenticated",
}

_EXPOSURE_TOKENS: dict[int, tuple[str, ...]] = {
    21: ("ftp",), 2121: ("ftp",), 23: ("telnet",), 445: ("smb",),
    1433: ("sql server", "mssql"), 1521: ("oracle",), 2049: ("nfs",),
    2181: ("zookeeper",), 2375: ("docker",), 2376: ("docker",),
    3306: ("mysql", "mariadb"), 3389: ("rdp",), 5432: ("postgres",),
    5601: ("kibana",), 5900: ("vnc",), 5984: ("couch",),
    6379: ("redis",), 6443: ("kubernetes",), 9042: ("cassandra",),
    9200: ("elasticsearch",), 9300: ("elasticsearch",),
    10250: ("kubelet",), 11211: ("memcached",), 15672: ("rabbit",),
    27017: ("mongo",), 27018: ("mongo",),
}

# product key, minimum acceptable version, note.
# A hit means the observed version is OLDER than this minimum.
# Heuristic only — not a CVE database and not a vulnerability scan.
VERSION_RULES: tuple[tuple[str, tuple[int, ...], str], ...] = (
    ("openssh", (8, 2), "OpenSSH before 8.2 is outdated"),
    ("dropbear", (2020, 81), "Dropbear SSH before 2020.81 is outdated"),
    ("nginx", (1, 22, 0), "nginx before 1.22.0 is outdated"),
    ("openresty", (1, 21, 4), "OpenResty before 1.21.4 is outdated"),
    ("apache", (2, 4, 51), "Apache httpd before 2.4.51 is outdated"),
    ("iis", (10, 0), "Microsoft-IIS before 10.0 is outdated"),
    ("openssl", (1, 1, 1), "OpenSSL before 1.1.1 is end-of-life"),
    ("php", (8, 1, 0), "PHP before 8.1 is end-of-life"),
    ("mysql", (8, 0, 0), "MySQL before 8.0 is end-of-life"),
    ("mariadb", (10, 6, 0), "MariaDB before 10.6 is end-of-life"),
    ("redis", (6, 2, 0), "Redis before 6.2 is outdated"),
    ("mongodb", (5, 0, 0), "MongoDB before 5.0 is end-of-life"),
    ("elasticsearch", (7, 17, 0), "Elasticsearch before 7.17.0 is outdated"),
    ("vsftpd", (3, 0, 3), "vsftpd before 3.0.3 is outdated"),
    ("proftpd", (1, 3, 7), "ProFTPD before 1.3.7 is outdated"),
    ("exim", (4, 95), "Exim before 4.95 is outdated"),
    ("tomcat", (9, 0, 50), "Apache Tomcat before 9.0.50 is outdated"),
    ("jetty", (9, 4, 44), "Jetty before 9.4.44 is outdated"),
    ("docker", (20, 10, 0), "Docker Engine before 20.10 is outdated"),
    ("werkzeug", (2, 2, 0), "Werkzeug before 2.2.0 is outdated"),
    ("gunicorn", (20, 1, 0), "gunicorn before 20.1.0 is outdated"),
)

HEURISTIC_DISCLAIMER = (
    "Version flags are heuristics from a small built-in table, not a CVE database."
)

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 300
MAX_THREADS     = 500
BANNER_READ_MAX = 4096
BANNER_MAX_LEN  = 160

_REFUSED = {errno.ECONNREFUSED, 10061}

_HTTP_PORTS = frozenset({
    80, 81, 591, 3000, 5000, 5080, 7001, 8000, 8008, 8080, 8081, 8088,
    8161, 8888, 9000, 9080, 9090, 10000, 5601, 5985, 15672,
})
_ES_HTTP_PORTS = frozenset({9200})
_DOCKER_HTTP_PORTS = frozenset({2375, 2376})
_REDIS_PORTS = frozenset({6379})
_MEMCACHED_PORTS = frozenset({11211})
_MONGO_PORTS = frozenset({27017, 27018})
_MYSQL_PORTS = frozenset({3306})
_FTP_PORTS = frozenset({21, 2121})
_TLS_HTTP_PORTS = frozenset({443, 8443, 9443, 4443, 6443, 10250, 2376})
_TLS_BANNER_PORTS = frozenset({465, 636, 993, 995})
_TLS_PORTS = _TLS_HTTP_PORTS | _TLS_BANNER_PORTS
_MAIL_PORTS = frozenset({25, 465, 587, 110, 143, 993, 995, 636})
_REQUEST_FIRST = (
    _HTTP_PORTS | _ES_HTTP_PORTS | _DOCKER_HTTP_PORTS
    | _REDIS_PORTS | _MEMCACHED_PORTS | _MONGO_PORTS
)
_SPECIFIC_HTTP = frozenset({
    "kubernetes", "kubelet", "kibana", "rabbitmq", "winrm", "docker",
    "elasticsearch",
})

_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,253}$")
_VERSION_RE = re.compile(r"(\d{1,6})(?:\.(\d{1,6}))?(?:\.(\d{1,6}))?(?:\.(\d{1,6}))?")
_SAFE_VERSION_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z._\-]{0,47}")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_SSH_RE = re.compile(r"SSH-(\d+\.\d+)-(\S+)")
_OBSOLETE_TLS_RE = re.compile(r"TLS:(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1)(?!\.?\d)")
_SKIP_CHARS = set(range(32)) | {127, 0x2028, 0x2029, 0xFEFF}
_SKIP_CHARS.update(range(0x202A, 0x202F))
_SKIP_CHARS.update(range(0x2066, 0x206A))
_SKIP_CHARS.update((0x200B, 0x200C, 0x200D))

_SERVER_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"nginx/([0-9][\w.\-]*)", re.I), "nginx", "nginx"),
    (re.compile(r"openresty/([0-9][\w.\-]*)", re.I), "openresty", "OpenResty"),
    (re.compile(r"Apache/([0-9][\w.\-]*)", re.I), "apache", "Apache httpd"),
    (re.compile(r"Microsoft-IIS/([0-9][\w.\-]*)", re.I), "iis", "Microsoft-IIS"),
    (re.compile(r"LiteSpeed(?:/([0-9][\w.\-]*))?", re.I), "litespeed", "LiteSpeed"),
    (re.compile(r"cloudflare", re.I), "cloudflare", "cloudflare"),
    (re.compile(r"gunicorn/([0-9][\w.\-]*)", re.I), "gunicorn", "gunicorn"),
    (re.compile(r"Werkzeug/([0-9][\w.\-]*)", re.I), "werkzeug", "Werkzeug"),
    (re.compile(r"Jetty\(?([0-9][\w.\-]*)", re.I), "jetty", "Jetty"),
    (re.compile(r"\bCaddy\b", re.I), "caddy", "Caddy"),
    (re.compile(r"\bKestrel\b", re.I), "kestrel", "Kestrel"),
    (re.compile(r"Tomcat/([0-9][\w.\-]*)", re.I), "tomcat", "Apache Tomcat"),
    (re.compile(r"Apache-Coyote/([0-9][\w.\-]*)", re.I), "tomcat", "Apache Tomcat"),
)
_COMPONENT_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"OpenSSL/([0-9][\w.\-]*)", re.I), "openssl", "OpenSSL"),
    (re.compile(r"PHP/([0-9][\w.\-]*)", re.I), "php", "PHP"),
)
_FTP_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"vsftpd\s+([0-9][\w.\-]*)", re.I), "vsftpd", "vsftpd"),
    (re.compile(r"ProFTPD\s+([0-9][\w.\-]*)", re.I), "proftpd", "ProFTPD"),
    (re.compile(r"FileZilla Server\s+([0-9][\w.\-]*)", re.I), "filezilla", "FileZilla"),
    (re.compile(r"Pure-FTPd", re.I), "pureftpd", "Pure-FTPd"),
    (re.compile(r"Microsoft FTP Service", re.I), "microsoft-ftp", "Microsoft FTP"),
)
_MAIL_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"Exim[/ ]([0-9][\w.\-]*)", re.I), "exim", "Exim"),
    (re.compile(r"Postfix", re.I), "postfix", "Postfix"),
    (re.compile(r"Sendmail(?:/([0-9][\w.\-]*))?", re.I), "sendmail", "Sendmail"),
    (re.compile(r"OpenSMTPD", re.I), "opensmtpd", "OpenSMTPD"),
    (re.compile(r"Dovecot", re.I), "dovecot", "Dovecot"),
    (re.compile(r"Microsoft ESMTP.*?([0-9]+\.[0-9]+(?:\.[0-9]+)*)", re.I),
     "exchange", "Microsoft Exchange"),
)


@dataclass
class _Hit:
    service: str = ""
    product_key: str = ""
    product: str = ""
    version: str = ""
    findings: list[str] = field(default_factory=list)


@dataclass
class _Ident:
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    findings: list[str] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────

def _out(msg: str = "", *, end: str = "\n", quiet: bool = False) -> None:
    """Live progress goes to stderr so stdout stays clean for reports/pipes."""
    if not quiet:
        print(msg, end=end, file=sys.stderr, flush=True)


def _iana_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return PORT_SERVICES.get(port, "?")


def _resolve(target: str) -> tuple[int, str]:
    """Resolve *target* to (address_family, ip). Supports IPv4 and IPv6."""
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{target}': {exc}") from exc
    infos.sort(key=lambda i: i[0] != socket.AF_INET)   # prefer IPv4 if both exist
    family, _, _, _, sockaddr = infos[0]
    return family, sockaddr[0]


def _heuristic(note: str) -> str:
    return f"{note} (heuristic, not a CVE database)"


def _sanitize(text: str, limit: int) -> str:
    """Drop control, ANSI, and bidi characters. Banners are attacker-controlled."""
    if not text:
        return ""
    cleaned = _ANSI_RE.sub("", text)
    kept = []
    for ch in cleaned:
        if ord(ch) in _SKIP_CHARS or not ch.isprintable():
            continue
        kept.append(ch)
        if len(kept) >= limit:
            break
    return "".join(kept).strip()


def _safe_version(version: str) -> str:
    cleaned = _sanitize(version, 48)
    if not cleaned or not _SAFE_VERSION_RE.fullmatch(cleaned):
        return ""
    return cleaned


def _version_tuple(version: str) -> tuple[int, ...]:
    match = _VERSION_RE.search(version or "")
    if not match:
        return ()
    parts: list[int] = []
    for group in match.groups():
        if group is None:
            break
        parts.append(int(group))
    return tuple(parts)


def _version_is_below(found: str, minimum: tuple[int, ...]) -> bool:
    got = _version_tuple(found)
    if not got or not minimum:
        return False
    width = max(len(got), len(minimum))
    left = got + (0,) * (width - len(got))
    right = minimum + (0,) * (width - len(minimum))
    return left < right


def _version_findings(product_key: str, version: str) -> list[str]:
    safe = _safe_version(version)
    if not product_key or not safe:
        return []
    notes: list[str] = []
    if product_key == "vsftpd" and _version_tuple(safe)[:3] == (2, 3, 4):
        notes.append(_heuristic(
            "vsftpd 2.3.4 matches the well-known backdoored release"
        ))
    for key, minimum, note in VERSION_RULES:
        if key == product_key and _version_is_below(safe, minimum):
            notes.append(_heuristic(f"{note}; found {safe}"))
    return notes


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        cleaned = " ".join((item or "").split())
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def _exposure_covered(findings: list[str], tokens: tuple[str, ...]) -> bool:
    markers = ("unauth", "anonymous", "answered", "exposed", "cleartext", "backdoor")
    for note in findings:
        low = note.lower()
        if any(tok in low for tok in tokens) and any(mark in low for mark in markers):
            return True
    return False


def _add_exposure(port: int, findings: list[str]) -> None:
    note = EXPOSURE_FINDINGS.get(port)
    if not note or note in findings:
        return
    tokens = _EXPOSURE_TOKENS.get(port, ())
    if tokens and _exposure_covered(findings, tokens):
        return
    findings.append(note)


def _match_product(rules: tuple[tuple[re.Pattern[str], str, str], ...],
                   text: str) -> tuple[str, str, str]:
    for pattern, key, display in rules:
        match = pattern.search(text)
        if not match:
            continue
        version = ""
        if match.lastindex:
            version = (match.group(1) or "").strip()
        return key, display, version
    return "", "", ""


def _component_findings(blob: str) -> list[str]:
    notes: list[str] = []
    for pattern, key, _display in _COMPONENT_RULES:
        match = pattern.search(blob)
        if not match:
            continue
        notes.extend(_version_findings(key, match.group(1) or ""))
    return notes


def _strip_telnet(data: bytes) -> bytes:
    if 255 not in data:
        return data
    out = bytearray()
    index = 0
    length = len(data)
    while index < length:
        if data[index] != 255 or index + 1 >= length:
            out.append(data[index])
            index += 1
            continue
        command = data[index + 1]
        if command == 255:
            out.append(255)
            index += 2
            continue
        if command in (251, 252, 253, 254):
            index += 3 if index + 2 < length else length
            continue
        if command == 250:
            end = data.find(b"\xff\xf0", index + 2)
            index = length if end < 0 else end + 2
            continue
        index += 2
    return bytes(out)


def _raw_text(raw: bytes) -> str:
    clipped = _strip_telnet(raw[:BANNER_READ_MAX])
    text = clipped.decode("utf-8", errors="replace")
    return _ANSI_RE.sub("", text)


def _tls_finding(text: str) -> str:
    match = _OBSOLETE_TLS_RE.search(text)
    if not match:
        return ""
    proto = match.group(1)
    if proto == "TLSv1":
        proto = "TLSv1.0"
    return _heuristic(f"{proto} is obsolete")


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _banner_preview(raw: bytes) -> str:
    lines = [ln.strip() for ln in _raw_text(raw).splitlines() if ln.strip()]
    if not lines:
        return ""
    status = next((ln for ln in lines if ln.upper().startswith("HTTP/")), "")
    server = next((ln for ln in lines if ln.lower().startswith("server:")), "")
    tls = next((ln for ln in lines if ln.upper().startswith("TLS:")), "")
    redis = next((ln for ln in lines if ln.lower().startswith("redis_version:")), "")
    if status or server:
        parts = [part for part in (tls, status, server) if part]
        chosen = " | ".join(dict.fromkeys(parts))
    elif redis:
        chosen = redis
    elif tls and any(line != tls for line in lines):
        other = next(line for line in lines if line != tls)
        chosen = " | ".join(dict.fromkeys((tls, other)))
    else:
        chosen = lines[0]
    return _sanitize(chosen, BANNER_MAX_LEN)


def _safe_host(host: str) -> str:
    raw = (host or "").strip().strip("[]")
    if not _HOST_RE.fullmatch(raw):
        return "localhost"
    try:
        socket.inet_pton(socket.AF_INET6, raw)
    except OSError:
        return raw
    return f"[{raw}]"


def _sni_name(host: str) -> str | None:
    raw = (host or "").strip().strip("[]")
    if not _HOST_RE.fullmatch(raw):
        return None
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, raw)
        except OSError:
            continue
        else:
            return None
    return raw


def _http_bytes(host: str, method: str, path: str) -> bytes:
    safe = _safe_host(host)
    request = (
        f"{method} {path} HTTP/1.0\r\n"
        f"Host: {safe}\r\n"
        "User-Agent: netrecon\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request.encode("ascii", errors="strict")


def _bson_doc(fields: list[tuple[str, object]]) -> bytes:
    body = bytearray()
    for key, value in fields:
        name = key.encode("utf-8") + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + name + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            body += b"\x10" + name + struct.pack("<i", value)
        elif isinstance(value, str):
            raw = value.encode("utf-8")
            body += b"\x02" + name + struct.pack("<i", len(raw) + 1) + raw + b"\x00"
        else:
            raise TypeError(f"Unsupported BSON value type: {type(value)!r}")
    return struct.pack("<i", len(body) + 5) + bytes(body) + b"\x00"


def _mongo_hello() -> bytes:
    """OP_MSG isMaster. One small document, no authentication attempt."""
    document = _bson_doc([("isMaster", 1), ("$db", "admin")])
    section = struct.pack("<I", 0) + b"\x00" + document
    length = 16 + len(section)
    header = struct.pack("<iiii", length, 1, 0, 2013)
    return header + section


def _mongo_version(raw: bytes) -> str:
    marker = b"\x02version\x00"
    start = raw.find(marker)
    if start < 0:
        return ""
    offset = start + len(marker)
    if offset + 4 > len(raw):
        return ""
    size = struct.unpack_from("<i", raw, offset)[0]
    if not 1 < size <= 32:
        return ""
    blob = raw[offset + 4:offset + 4 + size - 1]
    if not re.fullmatch(rb"[0-9][0-9A-Za-z.\-]*", blob or b""):
        return ""
    return blob.decode("ascii")


def _parse_mysql(raw: bytes) -> tuple[str, str, str] | None:
    if len(raw) >= 5 and raw[4] == 10:
        payload = raw[4:]
    elif raw[:1] == b"\x0a":
        payload = raw
    else:
        return None
    end = payload.find(b"\x00", 1)
    if end <= 1:
        return None
    version = payload[1:end].decode("ascii", errors="ignore")
    if not re.match(r"\d+\.\d+", version):
        return None
    if "mariadb" in version.lower():
        match = re.search(r"(\d+\.\d+\.\d+)-MariaDB", version, re.I)
        if match:
            found = match.group(1)
        else:
            nums = re.findall(r"\d+\.\d+\.\d+", version)
            found = nums[-1] if nums else ""
        return "mariadb", "MariaDB", found
    return "mysql", "MySQL", version.split()[0]


def _parse_redis(text: str) -> _Hit | None:
    if "redis_version:" in text:
        match = re.search(r"redis_version:([0-9][\w.\-]*)", text)
        return _Hit("redis", "redis", "Redis", match.group(1) if match else "",
                    ["Redis answered INFO without authentication"])
    stripped = text.lstrip()
    if stripped.startswith("+PONG"):
        return _Hit("redis", "redis", "Redis", "",
                    ["Redis answered PING without authentication"])
    if "NOAUTH" in text or "Authentication required" in text:
        return _Hit("redis", "", "Redis", "", [
            "Redis is exposed but refused unauthenticated INFO (AUTH is enabled)"
        ])
    return None


def _parse_memcached(text: str) -> _Hit | None:
    first = _first_line(text)
    match = re.match(r"(?i)VERSION\s+([0-9][\w.\-]*)", first)
    if not match:
        match = re.search(r"(?im)^STAT\s+version\s+([0-9][\w.\-]*)", text)
    if not match:
        return None
    return _Hit("memcached", "memcached", "Memcached", match.group(1),
                ["Memcached answered without authentication"])


def _es_version(text: str, port: int) -> str | None:
    strong = "You Know, for Search" in text or "lucene_version" in text
    weak = port in _ES_HTTP_PORTS and '"cluster_name"' in text
    if not strong and not weak:
        return None
    match = re.search(r'"number"\s*:\s*"([0-9][^"]{0,32})"', text)
    return match.group(1) if match else ""


def _docker_version(text: str, port: int) -> str | None:
    has_api = '"ApiVersion"' in text
    branded = "Docker" in text
    if not has_api and not (branded and '"Version"' in text):
        if port not in _DOCKER_HTTP_PORTS or '"Version"' not in text:
            return None
    if '"Version"' not in text and not has_api:
        return None
    match = re.search(r'"Version"\s*:\s*"([0-9][^"]{0,32})"', text)
    if match or has_api or port in _DOCKER_HTTP_PORTS:
        return match.group(1) if match else ""
    return None


def _header_blob(text: str) -> tuple[str, str]:
    server = ""
    powered = ""
    for line in text.splitlines():
        lower = line.lower()
        if lower.startswith("server:") and not server:
            server = line.split(":", 1)[1].strip()
        elif lower.startswith("x-powered-by:") and not powered:
            powered = line.split(":", 1)[1].strip()
    return server, powered


def _looks_http(text: str) -> bool:
    for line in text.splitlines()[:12]:
        stripped = line.strip()
        if stripped.upper().startswith("HTTP/"):
            return True
    return False


def _http_service(port: int, specific: str) -> str:
    if specific:
        return specific
    named = PORT_SERVICES.get(port, "")
    if named in _SPECIFIC_HTTP:
        return named
    if port in _TLS_HTTP_PORTS:
        return "https"
    return "http"


def _parse_http(text: str, port: int) -> _Hit:
    server, powered = _header_blob(text)
    key, product, version = _match_product(_SERVER_RULES, server)
    findings = _component_findings(f"{server}\n{powered}")
    specific = ""
    es_ver = _es_version(text, port)
    if es_ver is not None:
        key, product, version = "elasticsearch", "Elasticsearch", es_ver
        specific = "elasticsearch"
        findings.append("Elasticsearch answered without authentication")
    else:
        docker_ver = _docker_version(text, port)
        if docker_ver is not None and (port in _DOCKER_HTTP_PORTS or '"ApiVersion"' in text):
            key, product, version = "docker", "Docker", docker_ver
            specific = "docker"
            findings.append("Docker API answered /version without authentication")
    if not specific and key == "elasticsearch":
        specific = "elasticsearch"
    return _Hit(_http_service(port, specific), key, product, version, findings)


def _mail_service(port: int, first: str) -> str:
    if port == 465:
        return "smtps"
    if port == 587:
        return "submission"
    if port == 993 or (first.startswith("*") and port in _TLS_BANNER_PORTS):
        return "imaps" if port != 143 else "imap"
    if port == 995:
        return "pop3s"
    if first.startswith("+OK") or port == 110:
        return "pop3"
    if first.startswith("*") or port == 143:
        return "imap"
    return "smtp"


def _parse_mail(text: str, port: int) -> _Hit | None:
    first = _first_line(text)
    if not (first.startswith("220") or first.startswith("+OK") or first.startswith("*")):
        return None
    if port not in _MAIL_PORTS and not any(token in text for token in ("SMTP", "ESMTP", "IMAP", "POP3", "Dovecot", "Postfix", "Exim")):
        return None
    key, product, version = _match_product(_MAIL_RULES, text)
    return _Hit(_mail_service(port, first), key, product, version, [])


def _parse_ftp(text: str) -> _Hit | None:
    first = _first_line(text)
    if not first.startswith(("220", "120")):
        return None
    key, product, version = _match_product(_FTP_RULES, text)
    if not key and not re.search(r"\bFTP\b", text, re.I):
        return None
    return _Hit("ftp", key, product, version, [])


def _parse_ssh(text: str) -> _Hit | None:
    match = _SSH_RE.search(text)
    if not match:
        return None
    proto, software = match.group(1), match.group(2)
    findings: list[str] = []
    if proto.startswith("1.") and proto != "1.99":
        findings.append(_heuristic("SSH protocol 1 is obsolete"))
    openssh = re.match(r"(?i)OpenSSH_([0-9][\w.\-]*)", software)
    dropbear = re.match(r"(?i)dropbear_([0-9][\w.\-]*)", software)
    if openssh:
        return _Hit("ssh", "openssh", "OpenSSH", openssh.group(1), findings)
    if dropbear:
        return _Hit("ssh", "dropbear", "Dropbear", dropbear.group(1), findings)
    version_match = re.search(r"([0-9]+(?:\.[0-9]+){0,3})", software)
    product = _sanitize(software.split("_")[0], 40) or "ssh"
    version = version_match.group(1) if version_match else ""
    return _Hit("ssh", "", product, version, findings)


def _detect(raw: bytes, text: str, port: int) -> _Hit:
    if port in _MYSQL_PORTS or b"MariaDB" in raw[:120]:
        parsed = _parse_mysql(raw)
        if parsed:
            key, product, version = parsed
            return _Hit("mysql" if key == "mysql" else "mariadb", key, product, version, [])
    if port in _MONGO_PORTS and raw:
        version = _mongo_version(raw)
        if version or b"maxWireVersion" in raw or b"ismaster" in raw.lower():
            note = "MongoDB answered isMaster without authentication"
            return _Hit("mongodb", "mongodb", "MongoDB", version, [note])
    if _looks_http(text):
        return _parse_http(text, port)
    ssh = _parse_ssh(text)
    if ssh:
        return ssh
    redis = _parse_redis(text) if (port in _REDIS_PORTS or "redis_version:" in text or text.lstrip().startswith(("+PONG", "-NOAUTH"))) else None
    if redis:
        return redis
    memcached = _parse_memcached(text) if (port in _MEMCACHED_PORTS or _first_line(text).upper().startswith("VERSION ")) else None
    if memcached:
        return memcached
    if port in _FTP_PORTS or _first_line(text).startswith("220"):
        ftp = _parse_ftp(text)
        if ftp:
            return ftp
    if port in _ES_HTTP_PORTS:
        es_ver = _es_version(text, port)
        if es_ver is not None:
            return _Hit("elasticsearch", "elasticsearch", "Elasticsearch", es_ver,
                        ["Elasticsearch answered without authentication"])
    mail = _parse_mail(text, port)
    if mail:
        return mail
    if port == 23:
        return _Hit("telnet", "", "", "", [])
    return _Hit()


def _fingerprint(raw: bytes, port: int, notes: list[str] | None = None) -> _Ident:
    text = _raw_text(raw)
    extra = list(notes or [])
    tls_note = _tls_finding(text)
    if tls_note:
        extra.append(tls_note)
    hit = _detect(raw, text, port)
    findings = extra + list(hit.findings)
    findings.extend(_version_findings(hit.product_key, hit.version))
    _add_exposure(port, findings)
    return _Ident(
        service=hit.service or _iana_service(port),
        product=_sanitize(hit.product, 60),
        version=_safe_version(hit.version),
        banner=_banner_preview(raw),
        findings=_dedupe(findings),
    )


def _ident_without_banner(port: int) -> _Ident:
    findings: list[str] = []
    _add_exposure(port, findings)
    return _Ident(service=_iana_service(port), findings=_dedupe(findings))


# ── Banner collection ─────────────────────────────────────────────────

def _recv_nowait(sock: socket.socket) -> tuple[bytes, bool]:
    """Non-blocking peek. Returns (data, eof) and restores the prior timeout."""
    previous = sock.gettimeout()
    sock.settimeout(0)
    try:
        try:
            data = sock.recv(BANNER_READ_MAX)
        except (BlockingIOError, InterruptedError, TimeoutError):
            return b"", False
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return b"", False
            return b"", False
    finally:
        try:
            sock.settimeout(previous)
        except OSError:
            pass
    if not data:
        return b"", True
    return data[:BANNER_READ_MAX], False


def _read_some(sock: socket.socket, timeout: float) -> tuple[bytes, bool]:
    try:
        sock.settimeout(timeout)
        data = sock.recv(BANNER_READ_MAX)
    except OSError:
        return b"", False
    if not data:
        return b"", True
    return data[:BANNER_READ_MAX], False


def _send(sock: socket.socket, payload: bytes, timeout: float) -> bool:
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
    except OSError:
        return False
    return True


def _probe_payload(port: int, host: str) -> bytes | None:
    if port in _ES_HTTP_PORTS:
        return _http_bytes(host, "GET", "/")
    if port in _DOCKER_HTTP_PORTS and port not in _TLS_PORTS:
        return _http_bytes(host, "GET", "/version")
    if port in _HTTP_PORTS:
        return _http_bytes(host, "HEAD", "/")
    if port in _REDIS_PORTS:
        return b"INFO\r\n"
    if port in _MEMCACHED_PORTS:
        return b"version\r\n"
    if port in _MONGO_PORTS:
        return _mongo_hello()
    return None


def _reply_prefix(raw: bytes) -> str:
    return _raw_text(raw).lstrip()[:3]


def _probe_ftp_anonymous(sock: socket.socket, timeout: float) -> str:
    """One anonymous login attempt. No password list, no retry."""
    if not _send(sock, b"USER anonymous\r\n", timeout):
        return ""
    reply, _eof = _read_some(sock, timeout)
    code = _reply_prefix(reply)
    if code == "230":
        _send(sock, b"QUIT\r\n", timeout)
        return "Anonymous FTP login accepted (no password)"
    if code != "331":
        return ""
    if not _send(sock, b"PASS anonymous@\r\n", timeout):
        return ""
    reply, _eof = _read_some(sock, timeout)
    _send(sock, b"QUIT\r\n", timeout)
    if _reply_prefix(reply) == "230":
        return "Anonymous FTP login accepted"
    return ""


def _collect_tls(sock: socket.socket, port: int, timeout: float, host: str) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError, OSError):
        pass
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        wrapped = context.wrap_socket(sock, server_hostname=_sni_name(host))
    except (OSError, ValueError):
        return b""
    try:
        wrapped.settimeout(timeout)
        try:
            proto = wrapped.version() or ""
        except OSError:
            proto = ""
        prefix = f"TLS:{proto}\n".encode("ascii", errors="ignore") if proto else b""
        if port in _TLS_BANNER_PORTS:
            data, _eof = _read_some(wrapped, timeout)
            return (prefix + data)[:BANNER_READ_MAX]
        peeked, eof = _recv_nowait(wrapped)
        if peeked or eof:
            return (prefix + peeked)[:BANNER_READ_MAX]
        if port in _ES_HTTP_PORTS:
            payload = _http_bytes(host, "GET", "/")
        elif port in _DOCKER_HTTP_PORTS:
            payload = _http_bytes(host, "GET", "/version")
        else:
            payload = _http_bytes(host, "HEAD", "/")
        if not _send(wrapped, payload, timeout):
            return prefix[:BANNER_READ_MAX]
        data, _eof = _read_some(wrapped, timeout)
        return (prefix + data)[:BANNER_READ_MAX]
    except OSError:
        return b""
    finally:
        try:
            wrapped.close()
        except OSError:
            pass


def _collect_banner(sock: socket.socket, port: int, timeout: float,
                    host: str) -> tuple[bytes, list[str]]:
    """Passive read first, then one light probe. Never raises on banner I/O."""
    notes: list[str] = []
    try:
        if port in _TLS_PORTS:
            return _collect_tls(sock, port, timeout, host), notes
        data, eof = _recv_nowait(sock)
        if eof:
            return data, notes
        if not data and port not in _REQUEST_FIRST:
            data, eof = _read_some(sock, timeout)
            if eof:
                return data, notes
        if data and port in _FTP_PORTS and _raw_text(data).lstrip().startswith(("220", "120")):
            note = _probe_ftp_anonymous(sock, timeout)
            if note:
                notes.append(note)
            return data[:BANNER_READ_MAX], notes
        if data:
            return data[:BANNER_READ_MAX], notes
        payload = _probe_payload(port, host)
        if payload is None:
            return b"", notes
        if not _send(sock, payload, timeout):
            return b"", notes
        data, _eof = _read_some(sock, timeout)
        return data[:BANNER_READ_MAX], notes
    except OSError:
        return b"", notes


def _scan_one(family: int, ip: str, port: int, timeout: float,
              grab_banners: bool, host: str) -> PortEntry:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            err = sock.connect_ex((ip, port))
            if err != 0:
                state = "closed" if err in _REFUSED else "filtered"
                return PortEntry(port=port, state=state)
            if grab_banners:
                raw, notes = _collect_banner(sock, port, timeout, host)
                ident = _fingerprint(raw, port, notes)
            else:
                ident = _ident_without_banner(port)
    except OSError as exc:
        if exc.errno == errno.EMFILE:
            raise RuntimeError(
                "Too many open files. Lower the thread count or raise "
                "your limit (e.g. `ulimit -n 4096`)."
            ) from exc
        return PortEntry(port=port, state="filtered")

    return PortEntry(
        port=port,
        state="open",
        service=ident.service,
        banner=ident.banner,
        product=ident.product,
        version=ident.version,
        findings=list(ident.findings),
    )


def _select_ports(profile, ports, start, end, top_ports=None) -> list[int]:
    if profile:
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'. Valid: {list(PROFILES)}")
        return list(PROFILES[profile])
    if ports:
        bad = [p for p in ports if not 1 <= p <= 65535]
        if bad:
            raise ValueError(f"Invalid port(s) {bad}: must be between 1 and 65535.")
        return sorted(set(ports))
    if start is not None and end is not None:
        if not (1 <= start <= end <= 65535):
            raise ValueError("Ports must satisfy 1 ≤ start ≤ end ≤ 65535.")
        return list(range(start, end + 1))
    if top_ports is not None:
        limit = len(TOP_PORTS)
        if not 1 <= top_ports <= limit:
            raise ValueError(f"--top-ports must be between 1 and {limit}.")
        return list(TOP_PORTS[:top_ports])
    return list(PROFILES["top20"])


def _version_label(entry: PortEntry) -> str:
    if entry.product and entry.version:
        return f"{entry.product}/{entry.version}"
    return entry.product or entry.version


# ── Core ──────────────────────────────────────────────────────────────

def run(
    target:       str,
    profile:      str | None       = None,
    ports:        list[int] | None = None,
    start:        int | None       = None,
    end:          int | None       = None,
    timeout:      float = DEFAULT_TIMEOUT,
    threads:      int   = DEFAULT_THREADS,
    grab_banners: bool  = True,
    quiet:        bool  = False,
    top_ports:    int | None       = None,
) -> list[PortEntry]:
    """
    Scan TCP ports on *target*. Port selection, in order of precedence:
      - profile    → named port set from PROFILES
      - ports      → explicit list of ports
      - start+end  → contiguous range
      - top_ports  → the first N entries of TOP_PORTS
      - (nothing)  → the top20 profile

    grab_banners=False skips banner reads and version probes. Port-number
    exposure notes (Redis, MongoDB, Telnet, …) are still recorded.
    quiet=True suppresses all live output (progress and [OPEN] lines).

    Returns all PortEntry results (open, closed, filtered) sorted by port.
    Ctrl+C cancels pending work promptly, then re-raises KeyboardInterrupt.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")
    if threads < 1:
        raise ValueError("threads must be at least 1.")

    port_list = _select_ports(profile, ports, start, end, top_ports)
    family, ip = _resolve(target)

    total         = len(port_list)
    workers       = max(1, min(threads, total, MAX_THREADS))
    show_progress = not quiet and sys.stderr.isatty()
    results: list[PortEntry] = []
    done = 0

    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [
            pool.submit(_scan_one, family, ip, p, timeout, grab_banners, target)
            for p in port_list
        ]
        for future in as_completed(futures):
            entry = future.result()
            results.append(entry)
            done += 1
            if entry.state == "open":
                label = _version_label(entry)
                svc = entry.service if entry.service != "?" else ""
                shown = " ".join(part for part in (svc, label) if part)
                suffix = f"({shown})" if shown else ""
                _out(f"\r  [OPEN] {entry.port:<6} {suffix}".ljust(60), quiet=quiet)
            if show_progress and (done % 50 == 0 or done == total):
                _out(f"\r  {done}/{total} scanned…", end="", quiet=quiet)
    finally:
        # On Ctrl+C or error, drop queued ports instead of scanning them all.
        pool.shutdown(wait=True, cancel_futures=True)

    if show_progress:
        _out()
    return sorted(results, key=lambda r: r.port)


def display(results: list[PortEntry]) -> None:
    counts = Counter(r.state for r in results)
    open_  = [r for r in results if r.state == "open"]
    width  = 88
    print(f"\n{'─'*width}")
    print(f"  PORT SCAN  ({counts['open']} open / {counts['closed']} closed / "
          f"{counts['filtered']} filtered)")
    print(f"{'─'*width}")
    if open_:
        print(f"\n  {'PORT':<8} {'STATE':<10} {'SERVICE':<16} {'VERSION':<22} BANNER")
        print(f"  {'─'*76}")
        heuristic = False
        for entry in open_:
            print(f"  {entry.port:<8} {entry.state:<10} {entry.service:<16} "
                  f"{_version_label(entry):<22} {entry.banner}")
            for note in entry.findings:
                print(f"  {'':8} ⚠  {note}")
                if "heuristic" in note.lower():
                    heuristic = True
            hint = RISK_HINTS.get(entry.port, "")
            if hint and hint not in entry.findings:
                print(f"  {'':8} ⚠  {hint}")
        if heuristic:
            print(f"\n  {HEURISTIC_DISCLAIMER}")
    else:
        print("  No open ports found.")
    print(f"{'─'*width}\n")
