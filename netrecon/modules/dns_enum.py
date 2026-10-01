"""
DNS enumeration — A, AAAA, MX, NS, TXT, SOA, SPF, DMARC.
Flags common misconfigurations.
"""
import dns.resolver
from ..models import DnsResult

_TIMEOUT  = 5
_LIFETIME = 10


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout  = _TIMEOUT
    r.lifetime = _LIFETIME
    return r


def _query(resolver: dns.resolver.Resolver, target: str, qtype: str):
    try:
        return resolver.resolve(target, qtype)
    except Exception:
        return []


def run(target: str) -> DnsResult:
    """Enumerate DNS records for *target* and return a DnsResult."""
    result   = DnsResult()
    resolver = _make_resolver()

    # A / AAAA
    for r in _query(resolver, target, "A"):
        result.a.append(str(r))
    for r in _query(resolver, target, "AAAA"):
        result.aaaa.append(str(r))

    # MX
    for r in _query(resolver, target, "MX"):
        result.mx.append(f"{r.preference} {r.exchange}")

    # NS
    for r in _query(resolver, target, "NS"):
        result.ns.append(str(r).rstrip("."))

    # TXT — also extract SPF
    for r in _query(resolver, target, "TXT"):
        text = r.to_text().strip('"')
        result.txt.append(text)
        if text.lower().startswith("v=spf1"):
            result.spf = text

    # SOA
    soa_ans = _query(resolver, target, "SOA")
    if soa_ans:
        result.soa = str(soa_ans[0])

    # DMARC — lives at _dmarc.<target>
    for r in _query(resolver, f"_dmarc.{target}", "TXT"):
        text = r.to_text().strip('"')
        if "v=DMARC1" in text:
            result.dmarc = text

    # ── Issues ────────────────────────────────────────────────────────
    if not result.a:
        result.issues.append("No A records — domain may not resolve")
    if not result.aaaa:
        result.issues.append("No IPv6 (AAAA) records")
    if not result.ns:
        result.issues.append("No NS records found")
    elif len(result.ns) < 2:
        result.issues.append("Only 1 nameserver — single point of failure")
    if not result.spf:
        result.issues.append("No SPF record — domain open to email spoofing")
    if not result.dmarc:
        result.issues.append("No DMARC record — no email authentication policy")
    if not result.mx:
        result.issues.append("No MX records — domain cannot receive email")

    return result


def display(result: DnsResult) -> None:
    w = 60
    print(f"\n{'─'*w}")
    print("  DNS ENUMERATION")
    print(f"{'─'*w}")
    _section("A",     result.a)
    _section("AAAA",  result.aaaa)
    _section("MX",    result.mx)
    _section("NS",    result.ns)
    _section("TXT",   result.txt)
    if result.soa:
        print(f"  SOA   : {result.soa}")
    if result.spf:
        print(f"  SPF   : ✅ {result.spf}")
    else:
        print("  SPF   : ❌ not found")
    if result.dmarc:
        print(f"  DMARC : ✅ {result.dmarc}")
    else:
        print("  DMARC : ❌ not found")
    if result.issues:
        print(f"\n  ⚠️  Issues:")
        for issue in result.issues:
            print(f"    - {issue}")
    print(f"{'─'*w}\n")


def _section(label: str, values: list[str]) -> None:
    if not values:
        return
    pad = 6
    for i, v in enumerate(values):
        prefix = f"  {label:<{pad}}" if i == 0 else f"  {'':{pad}}"
        print(f"{prefix}: {v}")
