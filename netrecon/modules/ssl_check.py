"""
SSL/TLS inspection — certificate validity, expiry, TLS version, cipher, SANs.
Uses only stdlib ssl + socket (no extra dependencies).
"""
import ssl
import socket
from datetime import datetime, timezone
from ..models import SslResult

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
_EXPIRY_WARN_DAYS = 30
_EXPIRY_CRIT_DAYS = 14


def run(target: str, port: int = 443) -> SslResult:
    """Connect to *target*:*port*, pull the TLS certificate, and analyse it."""
    result = SslResult()
    ctx    = ssl.create_default_context()

    try:
        with socket.create_connection((target, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert             = ssock.getpeercert()
                result.tls_version = ssock.version() or ""
                cipher_info      = ssock.cipher()
                result.cipher    = cipher_info[0] if cipher_info else ""
                result.valid     = True

                # Subject / Issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))
                result.subject = subject.get("commonName", "")
                result.issuer  = issuer.get("organizationName", "")

                # Expiry
                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry       = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    expiry       = expiry.replace(tzinfo=timezone.utc)
                    result.expiry    = expiry
                    result.days_left = (expiry - datetime.now(timezone.utc)).days

                # Subject Alternative Names
                for kind, val in cert.get("subjectAltName", []):
                    if kind == "DNS":
                        result.san.append(val)

                # ── Issues ────────────────────────────────────────────
                if result.tls_version in _WEAK_PROTOCOLS:
                    result.issues.append(
                        f"Weak protocol in use: {result.tls_version} — upgrade to TLS 1.2+")
                if result.days_left < 0:
                    result.issues.append("Certificate is EXPIRED")
                elif result.days_left < _EXPIRY_CRIT_DAYS:
                    result.issues.append(
                        f"Certificate expires in {result.days_left} days — renew immediately")
                elif result.days_left < _EXPIRY_WARN_DAYS:
                    result.issues.append(
                        f"Certificate expires in {result.days_left} days — renew soon")
                if not result.san:
                    result.issues.append("No Subject Alternative Names (SANs) — may cause browser errors")

    except ssl.SSLCertVerificationError as e:
        result.valid = False
        result.issues.append(f"Certificate verification failed: {e}")
    except ssl.SSLError as e:
        result.valid = False
        result.issues.append(f"SSL error: {e}")
    except (OSError, ConnectionRefusedError) as e:
        result.valid = False
        result.issues.append(f"Connection failed: {e}")

    return result


def display(result: SslResult) -> None:
    w = 60
    icon = "✅" if result.valid and result.days_left > _EXPIRY_WARN_DAYS else "⚠️ "
    print(f"\n{'─'*w}")
    print(f"  SSL / TLS CHECK  {icon}")
    print(f"{'─'*w}")
    print(f"  Valid      : {result.valid}")
    print(f"  Subject    : {result.subject}")
    print(f"  Issuer     : {result.issuer}")
    print(f"  Expires    : {result.expiry}  ({result.days_left} days)")
    print(f"  Protocol   : {result.tls_version}")
    print(f"  Cipher     : {result.cipher}")
    if result.san:
        print(f"  SANs       : {', '.join(result.san[:6])}"
              + (f"  (+{len(result.san)-6} more)" if len(result.san) > 6 else ""))
    if result.issues:
        print(f"\n  ⚠️  Issues:")
        for issue in result.issues:
            print(f"    - {issue}")
    print(f"{'─'*w}\n")
