"""
WHOIS lookup — registrar, dates, nameservers, expiry warning.
"""
import whois
from datetime import datetime, timezone
from ..models import WhoisResult

_WARN_DAYS = 30
_CRIT_DAYS = 7


def _first(val):
    """Return first element if val is a list, otherwise val itself."""
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _to_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def run(target: str) -> WhoisResult:
    """Perform a WHOIS lookup for *target* and return a WhoisResult."""
    result = WhoisResult()

    try:
        w = whois.whois(target)

        result.registrar = w.registrar
        result.created   = _to_aware(_first(w.creation_date))
        result.expires   = _to_aware(_first(w.expiration_date))
        result.updated   = _to_aware(_first(w.updated_date))

        # Nameservers — deduplicate and lowercase
        raw_ns = w.name_servers or []
        if isinstance(raw_ns, str):
            raw_ns = [raw_ns]
        result.nameservers = sorted({ns.lower().rstrip(".") for ns in raw_ns})

        # Emails
        raw_em = w.emails or []
        result.emails = list(raw_em) if isinstance(raw_em, list) else [raw_em]

        # Days until expiry
        if result.expires:
            result.days_until_expiry = (
                result.expires - datetime.now(timezone.utc)
            ).days

            if result.days_until_expiry < 0:
                result.issues.append("Domain registration has EXPIRED")
            elif result.days_until_expiry < _CRIT_DAYS:
                result.issues.append(
                    f"Domain expires in {result.days_until_expiry} days — renew immediately")
            elif result.days_until_expiry < _WARN_DAYS:
                result.issues.append(
                    f"Domain expires in {result.days_until_expiry} days — renew soon")

    except Exception as e:
        result.issues.append(f"WHOIS lookup failed: {e}")

    return result


def display(result: WhoisResult) -> None:
    def _fmt(dt: datetime | None) -> str:
        return dt.strftime("%Y-%m-%d") if dt else "unknown"

    exp_icon = "✅"
    if result.days_until_expiry is not None and result.days_until_expiry < _WARN_DAYS:
        exp_icon = "⚠️ "

    w = 60
    print(f"\n{'─'*w}")
    print(f"  WHOIS")
    print(f"{'─'*w}")
    print(f"  Registrar   : {result.registrar or 'unknown'}")
    print(f"  Created     : {_fmt(result.created)}")
    print(f"  Updated     : {_fmt(result.updated)}")
    print(f"  Expires     : {exp_icon} {_fmt(result.expires)}"
          + (f"  ({result.days_until_expiry}d)" if result.days_until_expiry is not None else ""))
    if result.nameservers:
        print(f"  Nameservers : {result.nameservers[0]}")
        for ns in result.nameservers[1:]:
            print(f"  {'':12}  {ns}")
    if result.emails:
        print(f"  Emails      : {', '.join(result.emails[:3])}")
    if result.issues:
        print(f"\n  ⚠️  Issues:")
        for issue in result.issues:
            print(f"    - {issue}")
    print(f"{'─'*w}\n")
