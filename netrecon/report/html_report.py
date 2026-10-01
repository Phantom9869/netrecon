"""
Export a ReconReport to a self-contained HTML file.
No Jinja2 dependency — template is built with plain string formatting.
"""
from pathlib import Path
from datetime import datetime
from ..models import ReconReport

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #e6edf3; font-family: 'Courier New', monospace;
       font-size: 14px; padding: 2rem; }
h1   { color: #58a6ff; font-size: 1.4rem; margin-bottom: .25rem; }
h2   { color: #8b949e; font-size: .85rem; font-weight: normal; margin-bottom: 2rem; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
        padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }
.card-title { color: #58a6ff; font-size: .8rem; letter-spacing: .1em;
              text-transform: uppercase; margin-bottom: 1rem; border-bottom: 1px solid #30363d;
              padding-bottom: .5rem; }
.row   { display: flex; padding: .3rem 0; border-bottom: 1px solid #21262d; }
.row:last-child { border-bottom: none; }
.label { color: #8b949e; width: 160px; flex-shrink: 0; }
.value { color: #e6edf3; word-break: break-all; }
.ok    { color: #3fb950; }
.warn  { color: #d29922; }
.bad   { color: #f85149; }
.grade { font-size: 2rem; font-weight: bold; }
.grade.A { color: #3fb950; }
.grade.B { color: #79c0ff; }
.grade.C { color: #d29922; }
.grade.D { color: #ffa657; }
.grade.F { color: #f85149; }
.tag { display: inline-block; background: #21262d; border: 1px solid #30363d;
       border-radius: 4px; padding: .1rem .4rem; margin: .15rem; font-size: .8rem; }
.tag.present { border-color: #3fb950; color: #3fb950; }
.tag.missing { border-color: #f85149; color: #f85149; }
.issue { color: #f85149; padding: .2rem 0; }
.issue::before { content: "⚠ "; }
.port-row { display: flex; padding: .25rem 0; }
.port-num { color: #58a6ff; width: 70px; }
.port-svc { color: #d29922; width: 130px; }
.port-banner { color: #8b949e; }
footer { color: #484f58; font-size: .75rem; margin-top: 2rem; text-align: center; }
"""


def _row(label: str, value: str, cls: str = "") -> str:
    cls_str = f' class="value {cls}"' if cls else ' class="value"'
    return f'<div class="row"><span class="label">{label}</span><span{cls_str}>{value}</span></div>\n'


def _section(title: str, body: str) -> str:
    return f'<div class="card"><div class="card-title">{title}</div>{body}</div>\n'


def _dns_card(r) -> str:
    if not r: return ""
    body  = _row("A records", ", ".join(r.a) or "—")
    body += _row("AAAA",      ", ".join(r.aaaa) or "—")
    body += _row("MX",        "<br>".join(r.mx) or "—")
    body += _row("NS",        "<br>".join(r.ns) or "—")
    body += _row("SPF",       r.spf  or "❌ not found", "" if r.spf  else "bad")
    body += _row("DMARC",     r.dmarc or "❌ not found", "" if r.dmarc else "bad")
    for issue in r.issues:
        body += f'<div class="issue">{issue}</div>\n'
    return _section("🔍 DNS", body)


def _ssl_card(s) -> str:
    if not s: return ""
    days_cls = "ok" if s.days_left > 30 else ("warn" if s.days_left > 0 else "bad")
    body  = _row("Valid",    "✅ Yes" if s.valid else "❌ No", "ok" if s.valid else "bad")
    body += _row("Subject",  s.subject)
    body += _row("Issuer",   s.issuer)
    body += _row("Expires",  f"{s.expiry}  ({s.days_left} days left)" if s.expiry else "—", days_cls)
    body += _row("Protocol", s.tls_version,
                 "ok" if s.tls_version in ("TLSv1.2", "TLSv1.3") else "warn")
    body += _row("Cipher",   s.cipher)
    body += _row("SANs",     ", ".join(s.san) or "—")
    for issue in s.issues:
        body += f'<div class="issue">{issue}</div>\n'
    return _section("🔒 SSL / TLS", body)


def _headers_card(h) -> str:
    if not h: return ""
    letter   = h.grade[0] if h.grade else "F"
    grade_el = f'<span class="grade {letter}">{h.grade}</span>'
    body     = _row("Grade", grade_el)
    body    += _row("Score", f"{h.score} / {h.max_score}")

    present_tags = "".join(
        f'<span class="tag present">{x}</span>' for x in h.present
    )
    missing_tags = "".join(
        f'<span class="tag missing">{x}</span>' for x in h.missing
    )
    body += _row("Present", present_tags or "—")
    body += _row("Missing", missing_tags or "—")
    return _section("🛡 HTTP Headers", body)


def _whois_card(w) -> str:
    if not w: return ""
    def _d(dt): return dt.strftime("%Y-%m-%d") if dt else "—"
    exp_cls = "ok"
    if w.days_until_expiry is not None and w.days_until_expiry < 30:
        exp_cls = "warn"
    body  = _row("Registrar",  w.registrar or "—")
    body += _row("Created",    _d(w.created))
    body += _row("Updated",    _d(w.updated))
    body += _row("Expires",    f"{_d(w.expires)} ({w.days_until_expiry}d)" if w.days_until_expiry is not None else _d(w.expires), exp_cls)
    body += _row("Nameservers", "<br>".join(w.nameservers) or "—")
    for issue in w.issues:
        body += f'<div class="issue">{issue}</div>\n'
    return _section("📋 WHOIS", body)


def _subdomains_card(subs: list[str]) -> str:
    if not subs: return ""
    rows = "".join(
        f'<div class="row"><span class="value ok">{s}</span></div>\n' for s in sorted(subs)
    )
    header = _row("Total found", str(len(subs)))
    return _section(f"🌐 Subdomains ({len(subs)})", header + rows)


def _ports_card(ports) -> str:
    open_ = [p for p in ports if p.state == "open"]
    if not open_: return ""
    body = _row("Open", str(len(open_)))
    rows = ""
    for p in open_:
        rows += (f'<div class="port-row">'
                 f'<span class="port-num">{p.port}</span>'
                 f'<span class="port-svc">{p.service}</span>'
                 f'<span class="port-banner">{p.banner}</span>'
                 f'</div>\n')
    return _section(f"🔌 Open Ports ({len(open_)})", body + rows)


def save(report: ReconReport, path: str) -> None:
    ts    = report.scanned_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    cards = (_dns_card(report.dns)
             + _ssl_card(report.ssl)
             + _headers_card(report.headers)
             + _whois_card(report.whois)
             + _subdomains_card(report.subdomains)
             + _ports_card(report.ports))

    errors_html = ""
    if report.errors:
        for mod, msg in report.errors.items():
            errors_html += f'<div class="issue"><b>{mod}</b>: {msg}</div>\n'
        errors_html = _section("⚠️ Errors", errors_html)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>netrecon — {report.target}</title>
  <style>{_CSS}</style>
</head>
<body>
  <h1>🔍 netrecon — {report.target}</h1>
  <h2>Scanned at {ts}</h2>
  {cards}
  {errors_html}
  <footer>Generated by netrecon &bull; {ts}</footer>
</body>
</html>"""

    Path(path).write_text(html)
    print(f"  HTML report → '{path}'")
