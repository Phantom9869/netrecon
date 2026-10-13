"""
Threaded TCP port scanner with banner grabbing and risk hints.
Adapted from the standalone port_scanner.py for use as a netrecon module.
"""
import errno
import socket
import sys
from collections import Counter
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
        # extras that bring the profile up to a true 100 ports
        69, 79, 81, 113, 137, 138, 179, 427, 497, 543, 544, 548, 554, 646,
        1025, 1026, 1027, 1110, 1720, 1755, 1900, 2000, 2121, 2717, 3000,
        3128, 3986, 5001, 5060, 5357, 5666, 5800, 5985, 6000, 7000, 8009,
        8081, 8200, 9000, 9100, 9999, 11211, 49152,
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

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 300
MAX_THREADS     = 500
BANNER_MAX_LEN  = 80

_REFUSED    = {errno.ECONNREFUSED, 10061}          # Linux + Windows
_HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8888, 9000, 9090}
_TLS_PORTS  = {443, 465, 636, 993, 995, 8443, 9443}  # raw banner grab is useless


# ── Helpers ───────────────────────────────────────────────────────────

def _out(msg: str = "", *, end: str = "\n", quiet: bool = False) -> None:
    """Live progress goes to stderr so stdout stays clean for reports/pipes."""
    if not quiet:
        print(msg, end=end, file=sys.stderr, flush=True)


def _get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def _resolve(target: str) -> tuple[int, str]:
    """Resolve *target* to (address_family, ip). Supports IPv4 and IPv6."""
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve '{target}': {exc}") from exc
    infos.sort(key=lambda i: i[0] != socket.AF_INET)   # prefer IPv4 if both exist
    family, _, _, _, sockaddr = infos[0]
    return family, sockaddr[0]


def _clean_banner(raw: bytes) -> str:
    """
    First line of the response, plus the Server header for HTTP replies.
    Non-printable characters are stripped: banners come from the target and
    must never be able to inject terminal escape sequences into our output.
    """
    lines = [ln.strip() for ln in raw.decode("utf-8", errors="ignore").splitlines()
             if ln.strip()]
    if not lines:
        return ""
    banner = lines[0]
    if banner.upper().startswith("HTTP/"):
        for ln in lines[1:]:
            if ln.lower().startswith("server:"):
                banner = f"{banner} | {ln}"
                break
    banner = "".join(ch for ch in banner if ch.isprintable())
    return banner[:BANNER_MAX_LEN]


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Read a banner from an already-connected socket (no second connection)."""
    if port in _TLS_PORTS:
        return ""
    try:
        sock.settimeout(timeout)
        if port in _HTTP_PORTS:
            # HTTP servers don't speak first, so don't wait for them to.
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        return _clean_banner(sock.recv(1024))
    except OSError:                      # includes socket.timeout
        return ""


def _scan_one(family: int, ip: str, port: int,
              timeout: float, grab_banners: bool) -> PortEntry:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            err = s.connect_ex((ip, port))
            if err != 0:
                state = "closed" if err in _REFUSED else "filtered"
                return PortEntry(port=port, state=state)
            banner = _grab_banner(s, port, timeout) if grab_banners else ""
    except OSError as exc:
        if exc.errno == errno.EMFILE:
            raise RuntimeError(
                "Too many open files. Lower the thread count or raise "
                "your limit (e.g. `ulimit -n 4096`)."
            ) from exc
        return PortEntry(port=port, state="filtered")

    return PortEntry(port=port, state="open",
                     service=_get_service(port), banner=banner)


def _select_ports(profile, ports, start, end) -> list[int]:
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
    return list(PROFILES["top20"])


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
) -> list[PortEntry]:
    """
    Scan TCP ports on *target*. Port selection, in order of precedence:
      - profile   → named port set from PROFILES
      - ports     → explicit list of ports
      - start+end → contiguous range
      - (nothing) → the top20 profile

    grab_banners=False skips banner reads (faster, quieter on the wire).
    quiet=True suppresses all live output (progress and [OPEN] lines).

    Returns all PortEntry results (open, closed, filtered) sorted by port.
    Ctrl+C cancels pending work promptly, then re-raises KeyboardInterrupt.
    """
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0.")
    if threads < 1:
        raise ValueError("threads must be at least 1.")

    port_list = _select_ports(profile, ports, start, end)
    family, ip = _resolve(target)

    total         = len(port_list)
    workers       = max(1, min(threads, total, MAX_THREADS))
    show_progress = not quiet and sys.stderr.isatty()
    results: list[PortEntry] = []
    done = 0

    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [pool.submit(_scan_one, family, ip, p, timeout, grab_banners)
                   for p in port_list]
        for future in as_completed(futures):
            entry = future.result()
            results.append(entry)
            done += 1
            if entry.state == "open":
                svc = f"({entry.service})" if entry.service != "?" else ""
                _out(f"\r  [OPEN] {entry.port:<6} {svc}".ljust(44), quiet=quiet)
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
    w      = 60
    print(f"\n{'─'*w}")
    print(f"  PORT SCAN  ({counts['open']} open / {counts['closed']} closed / "
          f"{counts['filtered']} filtered)")
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
