"""
HTTP security header grader.
Checks for the six headers recommended by securityheaders.com and assigns A+–F.
"""
import requests
from ..models import HeaderResult

# Each entry: header name → {description, weight, validator}
SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "desc":   "HSTS — forces HTTPS connections",
        "weight": 2,
        "check":  lambda v: "max-age=" in v.lower(),
        "hint":   "e.g. max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "desc":   "CSP — prevents XSS and injection attacks",
        "weight": 2,
        "check":  lambda v: len(v) > 0,
        "hint":   "e.g. default-src 'self'",
    },
    "X-Frame-Options": {
        "desc":   "Clickjacking protection",
        "weight": 1,
        "check":  lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "hint":   "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "desc":   "Prevents MIME-type sniffing",
        "weight": 1,
        "check":  lambda v: v.lower() == "nosniff",
        "hint":   "nosniff",
    },
    "Referrer-Policy": {
        "desc":   "Controls referrer information leakage",
        "weight": 1,
        "check":  lambda v: len(v) > 0,
        "hint":   "e.g. no-referrer-when-downgrade",
    },
    "Permissions-Policy": {
        "desc":   "Restricts browser feature access",
        "weight": 1,
        "check":  lambda v: len(v) > 0,
        "hint":   "e.g. geolocation=(), camera=()",
    },
}

_MAX_SCORE = sum(m["weight"] for m in SECURITY_HEADERS.values())


def _grade(score: int, max_score: int) -> str:
    ratio = score / max_score if max_score else 0
    if ratio >= 0.96: return "A+"
    if ratio >= 0.80: return "A"
    if ratio >= 0.65: return "B"
    if ratio >= 0.50: return "C"
    if ratio >= 0.35: return "D"
    return "F"


def run(target: str, timeout: int = 10) -> HeaderResult:
    """Fetch *target* over HTTPS and grade its security headers."""
    result = HeaderResult(max_score=_MAX_SCORE)
    url    = target if target.startswith("http") else f"https://{target}"

    try:
        resp  = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "netrecon/1.0"},
        )
        hdrs  = resp.headers
        score = 0

        for header, meta in SECURITY_HEADERS.items():
            val = hdrs.get(header, "")
            if val and meta["check"](val):
                score += meta["weight"]
                result.present.append(header)
                result.details[header] = val
            else:
                result.missing.append(header)

        result.score = score
        result.grade = _grade(score, _MAX_SCORE)

        # Also record server/tech disclosure
        server = hdrs.get("Server", "")
        x_pow  = hdrs.get("X-Powered-By", "")
        if server:
            result.details["Server"] = server
        if x_pow:
            result.details["X-Powered-By"] = x_pow

    except requests.exceptions.SSLError:
        result.missing = list(SECURITY_HEADERS.keys())
        result.details["error"] = "SSL handshake failed — try http:// prefix"
    except requests.RequestException as e:
        result.missing = list(SECURITY_HEADERS.keys())
        result.details["error"] = str(e)

    return result


def display(result: HeaderResult) -> None:
    w = 60
    grade_icons = {"A": "✅", "B": "🟡", "C": "🟠", "D": "🔴", "F": "❌"}
    icon = grade_icons.get(result.grade[0], "❓")

    print(f"\n{'─'*w}")
    print(f"  HTTP SECURITY HEADERS  {icon} Grade {result.grade}  "
          f"({result.score}/{result.max_score} pts)")
    print(f"{'─'*w}")

    print("\n  ✅ Present:")
    if result.present:
        for h in result.present:
            val = result.details.get(h, "")
            short = val[:55] + "…" if len(val) > 55 else val
            print(f"    {h:<35} {short}")
    else:
        print("    (none)")

    print("\n  ❌ Missing:")
    if result.missing:
        for h in result.missing:
            meta = SECURITY_HEADERS.get(h, {})
            print(f"    {h:<35} ← {meta.get('hint', '')}")
    else:
        print("    (none — perfect!)")

    # Server disclosure warnings
    for key in ("Server", "X-Powered-By"):
        if key in result.details:
            print(f"\n  ⚠️  Tech disclosure via '{key}': {result.details[key]}")

    print(f"{'─'*w}\n")
