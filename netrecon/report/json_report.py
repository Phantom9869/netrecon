"""Export a ReconReport to JSON."""
import json
from datetime import datetime
from pathlib import Path
from ..models import ReconReport


def _serial(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Not JSON serializable: {type(obj)}")


def _dns_dict(d):
    if not d: return None
    return {"a": d.a, "aaaa": d.aaaa, "mx": d.mx, "ns": d.ns, "txt": d.txt,
            "soa": d.soa, "spf": d.spf, "dmarc": d.dmarc, "issues": d.issues}


def _ssl_dict(s):
    if not s: return None
    return {"valid": s.valid, "subject": s.subject, "issuer": s.issuer,
            "expiry": s.expiry.isoformat() if s.expiry else None,
            "days_left": s.days_left, "tls_version": s.tls_version,
            "cipher": s.cipher, "san": s.san, "issues": s.issues}


def _headers_dict(h):
    if not h: return None
    return {"grade": h.grade, "score": h.score, "max_score": h.max_score,
            "present": h.present, "missing": h.missing, "details": h.details}


def _whois_dict(w):
    if not w: return None
    return {"registrar": w.registrar,
            "created":  w.created.isoformat()  if w.created  else None,
            "expires":  w.expires.isoformat()  if w.expires  else None,
            "updated":  w.updated.isoformat()  if w.updated  else None,
            "nameservers": w.nameservers, "emails": w.emails,
            "days_until_expiry": w.days_until_expiry, "issues": w.issues}


def save(report: ReconReport, path: str) -> None:
    data = {
        "target":     report.target,
        "scanned_at": report.scanned_at.isoformat(),
        "dns":        _dns_dict(report.dns),
        "ssl":        _ssl_dict(report.ssl),
        "headers":    _headers_dict(report.headers),
        "whois":      _whois_dict(report.whois),
        "subdomains": report.subdomains,
        "ports":      [{"port": p.port, "state": p.state,
                        "service": p.service, "banner": p.banner}
                       for p in report.ports],
        "errors": report.errors,
    }
    Path(path).write_text(json.dumps(data, indent=2, default=_serial))
    print(f"  JSON report → '{path}'")
