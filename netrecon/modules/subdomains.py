"""
Threaded subdomain brute-forcer.
Detects live hosts and checks for common subdomain takeover signatures.
"""
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.resolver

# ── Takeover signatures ───────────────────────────────────────────────
# CNAME pointing to an unclaimed service = subdomain takeover risk

_TAKEOVER_SIGS: dict[str, str] = {
    "amazonaws.com":     "AWS S3/EB — bucket may be unclaimed",
    "github.io":         "GitHub Pages — page may be unclaimed",
    "herokuapp.com":     "Heroku — app may be deleted",
    "azurewebsites.net": "Azure — app service may be deleted",
    "netlify.app":       "Netlify — site may be unclaimed",
    "vercel.app":        "Vercel — deployment may be deleted",
    "pantheonsite.io":   "Pantheon — site may be unclaimed",
    "fastly.net":        "Fastly — service may be unclaimed",
    "ghost.io":          "Ghost — blog may be unclaimed",
    "readme.io":         "Readme.io — project may be deleted",
}

DEFAULT_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "common.txt"
_lock = threading.Lock()


def _make_resolver(timeout: float = 2.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout  = timeout
    r.lifetime = timeout * 2
    return r


def _resolve_sub(subdomain: str, resolver: dns.resolver.Resolver) -> tuple[str, list[str]] | None:
    try:
        answers = resolver.resolve(subdomain, "A")
        return subdomain, [str(r) for r in answers]
    except Exception:
        return None


def _check_takeover(subdomain: str, resolver: dns.resolver.Resolver) -> str | None:
    """Return a takeover hint if the subdomain CNAME points to an unclaimed service."""
    try:
        cname  = resolver.resolve(subdomain, "CNAME")
        target = str(cname[0].target).rstrip(".")
        for sig, label in _TAKEOVER_SIGS.items():
            if sig in target:
                return f"{label}  (CNAME → {target})"
    except Exception:
        pass
    return None


def run(
    target:   str,
    wordlist: str | Path | None = None,
    threads:  int = 50,
) -> dict[str, list[str]]:
    """
    Brute-force subdomains of *target* using *wordlist*.

    Returns:
        {subdomain: [ip, ...]} for every live result found.
    """
    wl_path = Path(wordlist) if wordlist else DEFAULT_WORDLIST
    if not wl_path.exists():
        raise FileNotFoundError(f"Wordlist not found: '{wl_path}'")

    words      = [w.strip() for w in wl_path.read_text().splitlines() if w.strip()]
    subdomains = [f"{w}.{target}" for w in words]
    total      = len(subdomains)
    resolver   = _make_resolver()

    found:     dict[str, list[str]] = {}
    takeovers: dict[str, str]       = {}
    done = 0

    print(f"  Checking {total} subdomains on {target} ({threads} threads)…\n")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_resolve_sub, sub, resolver): sub for sub in subdomains}
        for future in as_completed(futures):
            done   += 1
            result  = future.result()
            if result:
                sub, ips = result
                with _lock:
                    found[sub] = ips
                    hint = _check_takeover(sub, resolver)
                    if hint:
                        takeovers[sub] = hint
                    print(f"  [FOUND] {sub:<45} {', '.join(ips)}")
            if done % 200 == 0 or done == total:
                print(f"  {done}/{total} checked…", end="\r", flush=True)

    print(f"\n  Done — {len(found)} live subdomain(s) found\n")

    if takeovers:
        print("  🔴 POSSIBLE SUBDOMAIN TAKEOVERS:")
        for sub, hint in takeovers.items():
            print(f"    ⚠️  {sub}")
            print(f"       {hint}")
        print()

    return found


def display(found: dict[str, list[str]]) -> None:
    w = 60
    print(f"\n{'─'*w}")
    print(f"  SUBDOMAINS  ({len(found)} found)")
    print(f"{'─'*w}")
    for sub, ips in sorted(found.items()):
        print(f"  {sub:<45} {', '.join(ips)}")
    print(f"{'─'*w}\n")
