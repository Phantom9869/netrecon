"""
Threaded TCP port scanner with banner grabbing and risk hints.
Adapted from the standalone port_scanner.py for use as a netrecon module.
"""
import errno
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import PortEntry

# ── Profiles ──────────────────────────────────────────────────────────

PROFILES: dict[str, list[int]] = {
    "top20": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
              143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    "top100": sorted({
        21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 139, 143,
        161, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 993, 995,
        1080, 1194, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
        3306, 3389, 4444, 5000, 5432, 5900, 6379, 6667, 7001, 7070,
        8000, 8008, 8080, 8443, 8888, 9090, 9200, 9300, 10000, 27017,
    }),
    "web":  [80, 443, 8000, 8008, 8080, 8443, 8888, 9090, 9443],
    "db":   [1433, 1521, 3306, 5432, 6379, 9200, 27017, 28015],
    "mail": [25, 110, 143, 465, 587, 993, 995],
}

RISK_HINTS: dict[int, str] = {
    21:    "FTP — cleartext credentials; check for anonymous login",
    22:    "SSH — ensure key-auth only, password auth disabled",
    23:    "Telnet — cleartext; replace with SSH",
    25:    "SMTP — check for open relay misconfiguration",
    53:    "DNS — test for zone transfer (AXFR) exposure",
    80:    "HTTP — no encryption; redirect to HTTPS",
    110:   "POP3 — cleartext; prefer POP3S (port 995)",
    135:   "RPC/DCOM — high-value Windows attack surface",
    139:   "NetBIOS — legacy SMB; disable if unused",
    143:   "IMAP — cleartext; prefer IMAPS (port 993)",
    161:   "SNMP — default community strings often unchanged",
    445:   "SMB — patch for EternalBlue (MS17-010)",
    1433:  "MSSQL — database; should not be internet-facing",
    1521:  "Oracle DB — should not be internet-facing",
    3306:  "MySQL — should not be internet-facing",
    3389:  "RDP — common brute-force target; restrict to VPN",
    4444:  "⚠  Common Metasploit/reverse shell default — investigate",
    5432:  "PostgreSQL — should not be internet-facing",
    5900:  "VNC — ensure strong authentication",
    6379:  "Redis — often unauthenticated by default",
    9200:  "Elasticsearch — often unauthenticated by default",
    27017: "MongoDB — often unauthenticated by default",
}

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 300
_REFUSED        = {errno.ECONNREFUSED, 10061}   # Linux + Windows
_lock           = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────

def _get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def _grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                raw = s.recv(1024)
            except socket.timeout:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                raw = s.recv(1024)
            banner = raw.decode(errors="ignore").strip()
            return banner.splitlines()[0][:80] if banner else ""
    except Exception:
        return ""


def _scan_one(ip: str, port: int, timeout: float) -> PortEntry:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        err = s.connect_ex((ip, port))

    if err == 0:
        return PortEntry(
            port=port, state="open",
            service=_get_service(port),
            banner=_grab_banner(ip, port, timeout),
        )
    state = "closed" if err in _REFUSED else "filtered"
    return PortEntry(port=port, state=state)


# ── Core ──────────────────────────────────────────────────────────────

def run(
    target:  str,
    profile: str | None       = None,
    ports:   list[int] | None = None,
    start:   int | None       = None,
    end:     int | None       = None,
    timeout: float = DEFAULT_TIMEOUT,
    threads: int   = DEFAULT_THREADS,
) -> list[PortEntry]:
    """
    Scan TCP ports on *target*. Specify exactly one of:
      - profile  → named port set from PROFILES
      - ports    → explicit list of ports
      - start+end → contiguous range

    Returns all PortEntry results (open, closed, filtered) sorted by port.
    """
    if profile:
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'. Valid: {list(PROFILES)}")
        port_list = PROFILES[profile]
    elif ports:
        port_list = sorted(set(ports))
    elif start is not None and end is not None:
        if not (1 <= start <= end <= 65535):
            raise ValueError("Ports must satisfy 1 ≤ start ≤ end ≤ 65535.")
        port_list = list(range(start, end + 1))
    else:
        port_list = PROFILES["top20"]

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{target}': {exc}") from exc

    total   = len(port_list)
    results: list[PortEntry] = []
    done    = 0

    with ThreadPoolExecutor(max_workers=min(threads, total, 500)) as pool:
        futures = {pool.submit(_scan_one, ip, p, timeout): p for p in port_list}
        for future in as_completed(futures):
            entry = future.result()
            done += 1
            with _lock:
                results.append(entry)
                if entry.state == "open":
                    svc = f"({entry.service})" if entry.service != "?" else ""
                    print(f"  [OPEN] {entry.port:<6} {svc}")
            if done % 50 == 0 or done == total:
                print(f"  {done}/{total} scanned…", end="\r", flush=True)

    print()
    return sorted(results, key=lambda r: r.port)


def display(results: list[PortEntry]) -> None:
    open_ = [r for r in results if r.state == "open"]
    w     = 60
    print(f"\n{'─'*w}")
    print(f"  PORT SCAN  ({len(open_)} open / {len(results)} scanned)")
    print(f"{'─'*w}")
    if open_:
        print(f"\n  {'PORT':<8} {'STATE':<10} {'SERVICE':<14} BANNER")
        print(f"  {'─'*52}")
        for r in open_:
            print(f"  {r.port:<8} {r.state:<10} {r.service:<14} {r.banner}")
            hint = RISK_HINTS.get(r.port, "")
            if hint:
                print(f"  {'':8} ⚠  {hint}")
    else:
        print("  No open ports found.")
    print(f"{'─'*w}\n")
