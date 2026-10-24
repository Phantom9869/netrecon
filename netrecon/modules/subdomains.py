"""
Subdomain discovery — wordlist, certificate transparency, takeover hints.

A catch-all DNS record would otherwise make every guess look live, so wildcard
answers are probed first and matching responses are dropped. Names are also
pulled from crt.sh. That request never follows redirects, and it stops at a
timeout or a hard body cap. Takeover hints are returned on each finding so the
JSON and HTML reports can show them.
"""
import ipaddress
import json
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.exception
import dns.resolver
import requests

from ..models import SubdomainEntry, SubdomainResult

# CNAME pointing at an unclaimed service = subdomain takeover candidate.
# Match the service suffix, not a substring: "github.io" is in "notgithub.io".
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

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CRTSH_URL = "https://crt.sh/"
_CRTSH_TIMEOUT = 15.0
_CRTSH_MAX_BYTES = 1_048_576
_CRTSH_MAX_NAMES = 250
_REDIRECTS = {301, 302, 303, 307, 308}
_MAX_THREADS = 200
_USER_AGENT = "netrecon/1.0"
_SOURCE_ORDER = ("wordlist", "crtsh")

_tls = threading.local()


class _BodyTooLarge(Exception):
    """The HTTP body grew past the configured cap."""


def _normalize_hostname(name: str) -> str | None:
    """Return a lowercase hostname, or None when *name* is not one."""
    if not isinstance(name, str):
        return None
    cleaned = name.strip().lower().rstrip(".")
    if not cleaned or len(cleaned) > 253:
        return None
    labels = cleaned.split(".")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        return None
    return cleaned


def _is_ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


def _validate_domain(target: str) -> str:
    name = _normalize_hostname(target) if isinstance(target, str) else None
    if name is None or "." not in name or _is_ip_literal(name):
        shown = target if isinstance(target, str) else type(target).__name__
        raise ValueError(
            f"Invalid domain '{shown}'. Expected a hostname like example.com."
        )
    return name


def _host_under(raw: str, domain: str) -> str | None:
    """
    Return *raw* when it is a subdomain of *domain*.

    A leading wildcard label is stripped, so ``*.dev.example.com`` yields
    ``dev.example.com``. The apex itself and any other name yield None.
    """
    text = raw.strip().lower()
    if text.startswith("*."):
        text = text[2:]
    name = _normalize_hostname(text)
    if name is None or name == domain or not name.endswith("." + domain):
        return None
    return name


def _source_label(sources: set[str]) -> str:
    return "+".join(name for name in _SOURCE_ORDER if name in sources)


def _takeover_hint(cname: str | None) -> str | None:
    """Return a hint when *cname* is exactly a known service or under it."""
    if not cname:
        return None
    host = cname.strip().lower().rstrip(".")
    for sig, label in _TAKEOVER_SIGS.items():
        if host == sig or host.endswith("." + sig):
            return f"{label}  (CNAME → {host})"
    return None


def _is_wildcard_noise(
    ips: list[str],
    cname: str | None,
    sink_ips: set[str],
    sink_cnames: set[str],
) -> bool:
    """
    True when this answer is just the wildcard.

    A name that has its own CNAME is kept even if the addresses match the
    sink. Dangling CNAMEs are the interesting takeover case, and a catch-all
    A record must not hide them.
    """
    if not sink_ips or not set(ips) <= sink_ips:
        return False
    if cname and cname not in sink_cnames:
        return False
    return True


def _make_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def _thread_resolver(timeout: float) -> dns.resolver.Resolver:
    """One resolver per thread. dnspython resolvers are not thread-safe."""
    key = float(timeout)
    current = getattr(_tls, "resolver", None)
    if current is None or getattr(_tls, "timeout", None) != key:
        current = _make_resolver(timeout)
        _tls.resolver = current
        _tls.timeout = key
    return current


def _resolve_a(host: str, resolver: dns.resolver.Resolver) -> list[str] | None:
    try:
        answers = resolver.resolve(host, "A")
    except (dns.exception.DNSException, OSError):
        return None
    ips = [item.address for item in answers if getattr(item, "address", None)]
    return ips or None


def _resolve_cname(host: str, resolver: dns.resolver.Resolver) -> str | None:
    """
    Look up the CNAME without requiring the target to resolve.

    ``resolve(name, "A")`` follows CNAMEs, so a dangling alias comes back as
    NXDOMAIN and the takeover check never sees it.
    """
    try:
        answers = resolver.resolve(host, "CNAME")
    except (dns.exception.DNSException, OSError):
        return None
    if not answers:
        return None
    target = getattr(answers[0], "target", None)
    if target is None:
        return None
    return _normalize_hostname(str(target))


def _observe(host: str, timeout: float) -> tuple[list[str] | None, str | None]:
    resolver = _thread_resolver(timeout)
    return _resolve_a(host, resolver), _resolve_cname(host, resolver)


def _probe_wildcard(
    domain: str, timeout: float,
) -> tuple[bool, list[str], list[str]]:
    """
    Resolve two random labels.

    Both must answer before the domain is treated as a wildcard. One hit can
    be a name that really exists.
    """
    resolver = _make_resolver(timeout)
    ip_sets: list[set[str]] = []
    cnames: set[str] = set()
    for _ in range(2):
        name = f"{secrets.token_hex(8)}.{domain}"
        ips = _resolve_a(name, resolver)
        if not ips:
            return False, [], []
        ip_sets.append(set(ips))
        cname = _resolve_cname(name, resolver)
        if cname:
            cnames.add(cname)
    return True, sorted(ip_sets[0] | ip_sets[1]), sorted(cnames)


def _load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: '{path}'")
    words: list[str] = []
    seen: set[str] = set()
    text = path.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        word = line.strip().lower()
        if not word or word.startswith("#"):
            continue
        if _normalize_hostname(word) is None or word in seen:
            continue
        seen.add(word)
        words.append(word)
    return words


def _content_length_exceeds(resp: requests.Response, limit: int) -> bool:
    raw = resp.headers.get("Content-Length")
    if raw is None:
        return False
    try:
        size = int(raw)
    except (TypeError, ValueError):
        return False
    return size > limit


def _read_capped(resp: requests.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        total += len(chunk)
        if total > limit:
            raise _BodyTooLarge()
        chunks.append(chunk)
    return b"".join(chunks)


def _one_line(exc: BaseException) -> str:
    text = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
    return text[:200]


def _names_from_crtsh(rows: list, domain: str) -> list[str]:
    found: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("name_value", "common_name"):
            value = row.get(key)
            if not isinstance(value, str):
                continue
            for part in value.splitlines():
                host = _host_under(part, domain)
                if host:
                    found.add(host)
    return sorted(found)


def _parse_crtsh_body(body: bytes, domain: str) -> tuple[list[str], str | None]:
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return [], "crt.sh returned invalid JSON"
    if not isinstance(payload, list):
        return [], "crt.sh returned unexpected JSON"
    return _names_from_crtsh(payload, domain), None


def _fetch_crtsh(
    domain: str, timeout: float = _CRTSH_TIMEOUT,
) -> tuple[list[str], str | None]:
    """
    Download crt.sh JSON for ``%.domain``.

    Redirects are not followed. A spoofed 3xx Location would otherwise be
    fetched, which is an SSRF sink. The body is capped and the call times out.
    """
    connect = min(5.0, timeout)
    try:
        resp = requests.get(
            _CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=(connect, timeout),
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
    except requests.Timeout:
        return [], "crt.sh request timed out"
    except requests.RequestException as exc:
        return [], f"crt.sh request failed: {_one_line(exc)}"

    try:
        code = resp.status_code
        if code in _REDIRECTS:
            return [], "crt.sh redirected; refusing to follow"
        if code == 404:
            return [], None
        if code != 200:
            return [], f"crt.sh returned HTTP {code}"
        if _content_length_exceeds(resp, _CRTSH_MAX_BYTES):
            return [], f"crt.sh response exceeded {_CRTSH_MAX_BYTES} bytes"
        try:
            body = _read_capped(resp, _CRTSH_MAX_BYTES)
        except _BodyTooLarge:
            return [], f"crt.sh response exceeded {_CRTSH_MAX_BYTES} bytes"
        return _parse_crtsh_body(body, domain)
    finally:
        resp.close()


def _merge_crtsh(
    candidates: dict[str, set[str]],
    names: list[str],
    domain: str,
    result: SubdomainResult,
) -> None:
    extra: list[str] = []
    for name in names:
        host = _host_under(name, domain)
        if host is None:
            continue
        sources = candidates.get(host)
        if sources is None:
            extra.append(host)
        else:
            sources.add("crtsh")
    extra = sorted(set(extra))
    if len(extra) > _CRTSH_MAX_NAMES:
        result.notes.append(
            f"crt.sh listed {len(set(extra))} additional names; "
            f"resolving the first {_CRTSH_MAX_NAMES} alphabetically"
        )
        extra = extra[:_CRTSH_MAX_NAMES]
    for host in extra:
        candidates[host] = {"crtsh"}


def _classify(
    host: str,
    ips: list[str] | None,
    cname: str | None,
    sources: set[str],
    sink_ips: set[str],
    sink_cnames: set[str],
) -> SubdomainEntry | None:
    if ips and _is_wildcard_noise(ips, cname, sink_ips, sink_cnames):
        return None
    if not ips and not cname and "crtsh" not in sources:
        return None
    return SubdomainEntry(
        host=host,
        ips=list(ips or []),
        source=_source_label(sources),
        takeover=_takeover_hint(cname),
    )


def _print_found(entry: SubdomainEntry) -> None:
    shown = ", ".join(entry.ips) if entry.ips else "no A record"
    print(f"  [FOUND] {entry.host:<45} {shown}")
    if entry.takeover:
        print(f"    ⚠️  {entry.takeover}")


def _check_limits(threads: int, timeout: float, crtsh_timeout: float) -> None:
    if threads < 1:
        raise ValueError("threads must be at least 1.")
    if timeout <= 0 or crtsh_timeout <= 0:
        raise ValueError("timeout must be greater than 0.")


def run(
    target: str,
    wordlist: str | Path | None = None,
    threads: int = 50,
    *,
    use_crtsh: bool = True,
    timeout: float = 2.0,
    crtsh_timeout: float = _CRTSH_TIMEOUT,
) -> SubdomainResult:
    """
    Discover subdomains of *target*.

    Wordlist hits are brute-forced over DNS. When ``use_crtsh`` is true,
    certificate-transparency names from crt.sh are merged in. Wildcard-sink
    answers are omitted. Names that only appear in certificate logs are kept
    even when they no longer resolve.

    Returns a SubdomainResult. The crt.sh failure, if any, is recorded on
    the result and does not discard wordlist findings.
    """
    domain = _validate_domain(target)
    _check_limits(threads, timeout, crtsh_timeout)

    words = _load_wordlist(Path(wordlist) if wordlist else DEFAULT_WORDLIST)
    result = SubdomainResult()

    wildcard, sink_ips, sink_cnames = _probe_wildcard(domain, timeout)
    result.wildcard = wildcard
    result.wildcard_ips = sink_ips
    if wildcard:
        sinks = ", ".join(sink_ips) or "unknown"
        print(f"  Wildcard DNS detected (sink {sinks}); matching answers ignored")

    candidates: dict[str, set[str]] = {}
    for word in words:
        host = _host_under(f"{word}.{domain}", domain)
        if host:
            candidates.setdefault(host, set()).add("wordlist")

    if use_crtsh:
        ct_names, err = _fetch_crtsh(domain, timeout=crtsh_timeout)
        result.crtsh_error = err
        if err:
            print(f"  crt.sh unavailable: {err}")
        _merge_crtsh(candidates, ct_names, domain, result)
        for note in result.notes:
            print(f"  Note: {note}")

    if not candidates:
        print("\n  Done — 0 names found\n")
        return result

    workers = max(1, min(threads, len(candidates), _MAX_THREADS))
    print(f"  Checking {len(candidates)} names on {domain} ({workers} threads)…\n")

    entries: list[SubdomainEntry] = []
    done = 0
    total = len(candidates)
    sink_ip_set = set(sink_ips)
    sink_cname_set = set(sink_cnames)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_observe, host, timeout): host for host in candidates
        }
        for future in as_completed(futures):
            done += 1
            host = futures[future]
            ips, cname = future.result()
            entry = _classify(
                host, ips, cname, candidates[host], sink_ip_set, sink_cname_set,
            )
            if entry:
                entries.append(entry)
                _print_found(entry)
            if done % 200 == 0 or done == total:
                print(f"  {done}/{total} checked…", end="\r", flush=True)

    entries.sort(key=lambda item: item.host)
    result.entries = entries
    noun = "name" if len(entries) == 1 else "names"
    print(f"\n  Done — {len(entries)} {noun} found\n")
    return result


def display(result: SubdomainResult) -> None:
    w = 60
    print(f"\n{'─'*w}")
    print(f"  SUBDOMAINS  ({len(result.entries)} found)")
    print(f"{'─'*w}")
    if result.wildcard:
        sinks = ", ".join(result.wildcard_ips) or "yes"
        print(f"  Wildcard : {sinks}")
    if result.crtsh_error:
        print(f"  crt.sh   : {result.crtsh_error}")
    for note in result.notes:
        print(f"  Note     : {note}")
    for entry in result.entries:
        ips = ", ".join(entry.ips) if entry.ips else "unresolved"
        print(f"  {entry.host:<40} {ips}")
        detail = entry.source
        if entry.takeover:
            detail = f"{detail}  ⚠️  {entry.takeover}"
        if detail:
            print(f"  {'':40} {detail}")
    print(f"{'─'*w}\n")
