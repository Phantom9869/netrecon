"""
netrecon CLI — argparse subcommands wrapping every recon module.

Usage examples
--------------
python -m netrecon scan   example.com --all -o report.html
python -m netrecon dns    example.com
python -m netrecon ssl    example.com
python -m netrecon headers example.com
python -m netrecon whois  example.com
python -m netrecon subdomains example.com --wordlist wordlists/common.txt
python -m netrecon ports  example.com --profile top20
"""
import argparse
import sys

from .models import ReconReport
from .modules import dns_enum, ssl_check, headers, whois_lookup, subdomains, port_scan
from .report  import json_report, html_report


_BANNER = r"""
  _ __   ___| |_ _ __ ___  ___ ___  _ __
 | '_ \ / _ \ __| '__/ _ \/ __/ _ \| '_ \
 | | | |  __/ |_| | |  __/ (_| (_) | | | |
 |_| |_|\___|\__|_|  \___|\___\___/|_| |_|
"""


def _print_banner() -> None:
    print(_BANNER)


# ── Helpers ───────────────────────────────────────────────────────────

def _save_report(report: ReconReport, path: str, fmt: str) -> None:
    if fmt == "json" or path.endswith(".json"):
        json_report.save(report, path)
    else:
        html_report.save(report, path)


# ── Subcommand handlers ───────────────────────────────────────────────

def cmd_dns(args) -> None:
    print(f"  Running DNS enumeration on {args.target}…")
    result = dns_enum.run(args.target)
    dns_enum.display(result)


def cmd_ssl(args) -> None:
    port = getattr(args, "port", 443)
    print(f"  Checking SSL/TLS on {args.target}:{port}…")
    result = ssl_check.run(args.target, port=port)
    ssl_check.display(result)


def cmd_headers(args) -> None:
    print(f"  Grading HTTP headers for {args.target}…")
    result = headers.run(args.target)
    headers.display(result)


def cmd_whois(args) -> None:
    print(f"  WHOIS lookup for {args.target}…")
    result = whois_lookup.run(args.target)
    whois_lookup.display(result)


def cmd_subdomains(args) -> None:
    found = subdomains.run(
        args.target,
        wordlist=args.wordlist,
        threads=args.threads,
    )
    subdomains.display(found)


def cmd_ports(args) -> None:
    ports_arg  = getattr(args, "ports",   None)
    range_arg  = getattr(args, "range",   None)
    profile    = getattr(args, "profile", None)
    start, end = (range_arg if range_arg else (None, None))

    results = port_scan.run(
        args.target,
        profile=profile,
        ports=ports_arg,
        start=start,
        end=end,
        timeout=args.timeout,
        threads=args.threads,
    )
    port_scan.display(results)


def cmd_scan(args) -> None:
    """Run all (or selected) modules and produce a unified report."""
    report = ReconReport(target=args.target)
    run_all = args.all or not any([args.dns, args.ssl,
                                   args.headers, args.whois,
                                   args.subdomains, args.ports])

    if run_all or args.dns:
        print(f"  [1/6] DNS…")
        try:
            report.dns = dns_enum.run(args.target)
        except Exception as e:
            report.errors["dns"] = str(e)

    if run_all or args.ssl:
        print(f"  [2/6] SSL…")
        try:
            report.ssl = ssl_check.run(args.target)
        except Exception as e:
            report.errors["ssl"] = str(e)

    if run_all or args.headers:
        print(f"  [3/6] HTTP headers…")
        try:
            report.headers = headers.run(args.target)
        except Exception as e:
            report.errors["headers"] = str(e)

    if run_all or args.whois:
        print(f"  [4/6] WHOIS…")
        try:
            report.whois = whois_lookup.run(args.target)
        except Exception as e:
            report.errors["whois"] = str(e)

    if run_all or args.subdomains:
        print(f"  [5/6] Subdomains…")
        try:
            found = subdomains.run(
                args.target,
                wordlist=getattr(args, "wordlist", None),
                threads=getattr(args, "threads", 50),
            )
            report.subdomains = sorted(found.keys())
        except Exception as e:
            report.errors["subdomains"] = str(e)

    if run_all or args.ports:
        print(f"  [6/6] Ports…")
        try:
            results = port_scan.run(
                args.target,
                profile=getattr(args, "profile", "top20"),
                timeout=getattr(args, "timeout", 1.0),
                threads=getattr(args, "threads", 300),
            )
            report.ports = results
        except Exception as e:
            report.errors["ports"] = str(e)

    report.summary()

    if args.output:
        _save_report(report, args.output, args.format)


# ── Parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="Network reconnaissance toolkit",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Run all (or selected) modules")
    p_scan.add_argument("target")
    p_scan.add_argument("--all",        action="store_true", help="Run every module")
    p_scan.add_argument("--dns",        action="store_true")
    p_scan.add_argument("--ssl",        action="store_true")
    p_scan.add_argument("--headers",    action="store_true")
    p_scan.add_argument("--whois",      action="store_true")
    p_scan.add_argument("--subdomains", action="store_true")
    p_scan.add_argument("--ports",      action="store_true")
    p_scan.add_argument("--wordlist",   default=None)
    p_scan.add_argument("--profile",    default="top20",
                        choices=list(port_scan.PROFILES))
    p_scan.add_argument("--timeout",    type=float, default=1.0)
    p_scan.add_argument("--threads",    type=int,   default=100)
    p_scan.add_argument("-o", "--output", default=None)
    p_scan.add_argument("--format",     choices=["json", "html"], default="html")
    p_scan.set_defaults(func=cmd_scan)

    # ── dns ───────────────────────────────────────────────────────────
    p_dns = sub.add_parser("dns", help="DNS enumeration")
    p_dns.add_argument("target")
    p_dns.set_defaults(func=cmd_dns)

    # ── ssl ───────────────────────────────────────────────────────────
    p_ssl = sub.add_parser("ssl", help="SSL/TLS check")
    p_ssl.add_argument("target")
    p_ssl.add_argument("--port", type=int, default=443)
    p_ssl.set_defaults(func=cmd_ssl)

    # ── headers ───────────────────────────────────────────────────────
    p_hdr = sub.add_parser("headers", help="HTTP security header grader")
    p_hdr.add_argument("target")
    p_hdr.set_defaults(func=cmd_headers)

    # ── whois ─────────────────────────────────────────────────────────
    p_who = sub.add_parser("whois", help="WHOIS lookup")
    p_who.add_argument("target")
    p_who.set_defaults(func=cmd_whois)

    # ── subdomains ────────────────────────────────────────────────────
    p_sub = sub.add_parser("subdomains", help="Subdomain brute-forcer")
    p_sub.add_argument("target")
    p_sub.add_argument("--wordlist", default=None)
    p_sub.add_argument("--threads",  type=int, default=50)
    p_sub.set_defaults(func=cmd_subdomains)

    # ── ports ─────────────────────────────────────────────────────────
    p_prt = sub.add_parser("ports", help="TCP port scanner")
    p_prt.add_argument("target")
    pg = p_prt.add_mutually_exclusive_group(required=True)
    pg.add_argument("--profile", choices=list(port_scan.PROFILES))
    pg.add_argument("--range",   nargs=2, type=int, metavar=("START", "END"))
    pg.add_argument("--ports",   nargs="+", type=int, metavar="PORT")
    p_prt.add_argument("--timeout", type=float, default=1.0)
    p_prt.add_argument("--threads", type=int,   default=300)
    p_prt.set_defaults(func=cmd_ports)

    return parser


def main() -> None:
    _print_banner()
    parser = build_parser()
    args   = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n  Interrupted.")
        sys.exit(0)
    except ValueError as e:
        print(f"\n  Error: {e}", file=sys.stderr)
        sys.exit(1)
