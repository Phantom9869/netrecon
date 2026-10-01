from dataclasses import dataclass, field
from datetime import datetime


# ── DNS ───────────────────────────────────────────────────────────────

@dataclass
class DnsResult:
    a:      list[str] = field(default_factory=list)
    aaaa:   list[str] = field(default_factory=list)
    mx:     list[str] = field(default_factory=list)
    ns:     list[str] = field(default_factory=list)
    txt:    list[str] = field(default_factory=list)
    soa:    str | None = None
    spf:    str | None = None
    dmarc:  str | None = None
    issues: list[str] = field(default_factory=list)


# ── SSL ───────────────────────────────────────────────────────────────

@dataclass
class SslResult:
    valid:       bool = False
    subject:     str  = ""
    issuer:      str  = ""
    expiry:      datetime | None = None
    days_left:   int  = 0
    tls_version: str  = ""
    cipher:      str  = ""
    san:         list[str] = field(default_factory=list)
    issues:      list[str] = field(default_factory=list)


# ── HTTP Headers ──────────────────────────────────────────────────────

@dataclass
class HeaderResult:
    grade:     str = "F"
    score:     int = 0
    max_score: int = 0
    present:   list[str]      = field(default_factory=list)
    missing:   list[str]      = field(default_factory=list)
    details:   dict[str, str] = field(default_factory=dict)


# ── WHOIS ─────────────────────────────────────────────────────────────

@dataclass
class WhoisResult:
    registrar:          str | None      = None
    created:            datetime | None = None
    expires:            datetime | None = None
    updated:            datetime | None = None
    nameservers:        list[str]       = field(default_factory=list)
    emails:             list[str]       = field(default_factory=list)
    days_until_expiry:  int | None      = None
    issues:             list[str]       = field(default_factory=list)


# ── Ports ─────────────────────────────────────────────────────────────

@dataclass
class PortEntry:
    port:    int
    state:   str          # "open" | "closed" | "filtered"
    service: str = ""
    banner:  str = ""


# ── Top-level report ──────────────────────────────────────────────────

@dataclass
class ReconReport:
    target:     str
    scanned_at: datetime = field(default_factory=datetime.now)
    dns:        DnsResult    | None = None
    ssl:        SslResult    | None = None
    headers:    HeaderResult | None = None
    whois:      WhoisResult  | None = None
    subdomains: list[str]           = field(default_factory=list)
    ports:      list[PortEntry]     = field(default_factory=list)
    errors:     dict[str, str]      = field(default_factory=dict)

    @property
    def open_ports(self) -> list[PortEntry]:
        return [p for p in self.ports if p.state == "open"]

    def summary(self) -> None:
        w = 60
        grade_icon = {"A": "✅", "B": "🟡", "C": "🟠", "D": "🔴", "F": "❌"}

        print(f"\n{'─'*w}")
        print(f"  {'NETRECON REPORT':^{w-4}}")
        print(f"{'─'*w}")
        print(f"  Target     : {self.target}")
        print(f"  Scanned at : {self.scanned_at:%Y-%m-%d %H:%M:%S}")
        print(f"{'─'*w}")

        if self.dns:
            ips   = ", ".join(self.dns.a) or "none"
            spf   = "✅" if self.dns.spf   else "❌"
            dmarc = "✅" if self.dns.dmarc else "❌"
            print(f"  DNS        : {ips}  |  SPF {spf}  DMARC {dmarc}")

        if self.ssl:
            icon = "✅" if self.ssl.valid and self.ssl.days_left > 30 else "⚠️ "
            print(f"  SSL        : {icon} {self.ssl.tls_version}  "
                  f"({self.ssl.days_left}d left)  issuer: {self.ssl.issuer}")

        if self.headers:
            icon = grade_icon.get(self.headers.grade[0], "❓")
            print(f"  Headers    : {icon} Grade {self.headers.grade}  "
                  f"({self.headers.score}/{self.headers.max_score} pts)")

        if self.whois:
            exp = (f"{self.whois.days_until_expiry}d"
                   if self.whois.days_until_expiry is not None else "?")
            print(f"  WHOIS      : {self.whois.registrar or 'unknown'}  "
                  f"expires in {exp}")

        if self.subdomains:
            print(f"  Subdomains : {len(self.subdomains)} found")

        if self.open_ports:
            ports_str = ", ".join(str(p.port) for p in self.open_ports[:8])
            extra = f" (+{len(self.open_ports)-8} more)" if len(self.open_ports) > 8 else ""
            print(f"  Open ports : {len(self.open_ports)}  [{ports_str}{extra}]")

        if self.errors:
            print(f"  Errors     : {', '.join(self.errors.keys())}")

        print(f"{'─'*w}\n")
