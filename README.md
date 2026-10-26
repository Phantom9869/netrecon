# 🔍 netrecon

A modular network reconnaissance toolkit. Profile a target domain or IP from every angle — DNS, SSL, HTTP headers, WHOIS, subdomain discovery, port scanning, and web exposure — unified into one structured report.

**Authorized use only.** Run netrecon only against hosts you are allowed to test. Probing for exposed files, headers, or services without permission may be illegal.

---

## Features

| Module | What it does |
|---|---|
| `dns` | A/AAAA/MX/NS/TXT/SOA, SPF & DMARC validation |
| `ssl` | Cert expiry, TLS version, cipher, SANs, chain |
| `headers` | HTTP security header grader (A+ → F) |
| `whois` | Registrar, creation/expiry dates, nameservers |
| `subdomains` | Threaded wordlist brute-forcer + takeover detection |
| `ports` | Threaded TCP scanner with service and version fingerprinting |
| `web` | Exposed sensitive paths (content-checked) and web technology fingerprinting |

---

## Install

```bash
git clone https://github.com/Phantom9869/netrecon.git
cd netrecon
pip install -r requirements.txt
```

---

## Usage

```bash
# Full recon — all modules, HTML report
python -m netrecon scan example.com --all -o report.html

# Individual modules
python -m netrecon dns    example.com
python -m netrecon ssl    example.com
python -m netrecon headers example.com
python -m netrecon whois  example.com
python -m netrecon subdomains example.com --wordlist wordlists/common.txt
python -m netrecon ports  example.com --profile top20

# Port scanning options
python -m netrecon ports example.com --profile web
python -m netrecon ports example.com --range 1 1024
python -m netrecon ports example.com --ports 22 80 443 3306
python -m netrecon ports example.com --top-ports 40
python -m netrecon ports example.com --ports 22 80 443 --no-banners
python -m netrecon web   example.com

# Save report
python -m netrecon scan example.com --all --format json -o report.json
python -m netrecon scan example.com --all --format html -o report.html

# Full scan includes web exposure. Opt out with --no-web-exposure.
python -m netrecon scan example.com --all --no-web-exposure -o report.html
python -m netrecon scan example.com --web-exposure --format json -o report.json
```

---

## Profiles

| Name | Ports |
|---|---|
| `top20` | 20 most common ports |
| `top100` | Top 100 ports |
| `web` | 80, 443, 8000, 8080, 8443… |
| `db` | MySQL, Postgres, Redis, Mongo, Memcached, CouchDB, Cassandra… |
| `mail` | SMTP, POP3, IMAP and TLS variants |

`--top-ports N` scans the first N ports of a curated list (`TOP_PORTS`). The first 20 match `top20`. The next ports are high-signal database and admin services (PostgreSQL, Redis, MongoDB, Elasticsearch, Memcached, Docker, Kubernetes, and others), then the rest of `top100`, then a few admin ports that `top100` does not include. On `scan`, `--top-ports` overrides `--profile`.

The default profile is still `top20`, so a normal scan does not get slower.

---

## Port fingerprinting

When a TCP connect succeeds, netrecon reads the service banner and, if the service stays quiet, sends one light probe:

- banner-first services (SSH, FTP, SMTP, POP3, IMAP, MySQL, Telnet) are read passively
- HTTP gets `HEAD /`, Elasticsearch `GET /`, the Docker API `GET /version`
- Redis gets `INFO`, Memcached gets `version`, MongoDB gets a single `isMaster`
- TLS ports get a handshake (TLS 1.0 and later, so old protocols can be seen), then the same kind of read or HTTP probe
- FTP on port 21/2121 gets one `USER anonymous` / `PASS anonymous@` attempt

Reads are capped (4096 bytes, banner text truncated for display), use the scan's per-connection timeout, and are decoded with replacement. Control characters, ANSI escapes, and bidi overrides are stripped. Banner text is never evaluated or passed to a shell.

Each open port may then carry:

| Field | Meaning |
|---|---|
| `service` | Fingerprinted protocol when recognized, otherwise the IANA name |
| `product` | Software name, such as `nginx` or `OpenSSH` |
| `version` | Version string parsed from the banner |
| `findings` | Notable notes: outdated versions, exposed admin/database services, anonymous FTP, unauthenticated data stores |

`--no-banners` skips the reads and probes (no product/version). Exposure notes that depend only on the port number, such as an open Redis or Telnet port, are still reported.

Version notes come from `VERSION_RULES` in `netrecon/modules/port_scan.py`. That table is a **heuristic, not a CVE database**. A hit means "this version is older than a curated cutoff," not "this CVE is present."

### JSON report

Existing port fields are unchanged: `port`, `state`, `service`, `banner`. Three fields were added, which older readers can ignore:

```json
{
  "port": 22,
  "state": "open",
  "service": "ssh",
  "banner": "SSH-2.0-OpenSSH_7.2p2",
  "product": "OpenSSH",
  "version": "7.2p2",
  "findings": [
    "OpenSSH before 8.2 is outdated; found 7.2p2 (heuristic, not a CVE database)"
  ]
}
```

Closed and filtered ports include the same keys, with empty `product`, `version`, and `findings`. `service` may now be a fingerprinted name (`elasticsearch`, `docker`, `mongodb`) when the IANA table has no useful entry or the banner identified the service.

HTML reports escape banner, product, version, findings, and the other target-controlled fields. Treat banner text as hostile.

---

## Web exposure

`web` sends GET requests for a small fixed list of high-signal paths and fingerprints the HTTP service from headers, cookie names, and HTML. A full `scan` runs it too. `--no-web-exposure` skips it. `--web-exposure` runs it on its own.

Paths include `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/.DS_Store`, `/server-status`, `/phpinfo.php`, `/wp-config.php.bak`, `/backup.zip`, `/config.json`, `/actuator/env`, `/actuator/health`, `/swagger.json`, `/openapi.json`, `/.well-known/security.txt`, `/robots.txt`, `/sitemap.xml`, `/admin`, and `/login`.

A hit has to match the path's content, not just an HTTP status. `/.git/HEAD` must start with `ref:`. `/.env` must look like `KEY=VALUE` lines. Before those checks, the module requests a random path and treats a later response as a soft 404 when the status, length, and body hash line up with that baseline (the requested path is removed first, so a custom 404 that echoes the URL still matches). SPA catch-all pages and custom 404s are not reported.

Each finding has `path`, `url`, `status`, `severity` (`info`, `low`, `medium`, `high`), and a short `reason`. Secret values from `.env`, JSON config, actuator env, and WordPress config backups are not stored or printed. The reason may list key or constant names and says that values are redacted. `robots.txt` `Disallow` paths and sitemap locations are leads only — they are not requested.

Technology names are a light heuristic (WordPress, Drupal, Django, Laravel, Spring, Express, nginx, Apache, Cloudflare, and a few others). Evidence is a header, a cookie name, or a short HTML marker.

The probe is GET-only. It will not follow a redirect to another host, and it follows at most 3 redirects on the same host. Each body is capped at 64 KiB. Requests use a per-request timeout, a thread pool capped at 8, a total request budget (default 48, including the baseline, homepage, and redirects), and the user agent `netrecon/1.0 (web exposure probe; authorized testing only)`. Only `http` and `https` targets are accepted. Response bytes are decoded with replacement, control characters are stripped, and nothing from a response is evaluated or passed to a shell.

On `scan`, web exposure uses those defaults rather than the port scanner's timeout and thread count.

### JSON report

Existing keys are unchanged. A new `web_exposure` key is `null` when the module did not run:

```json
"web_exposure": {
  "base_url": "https://example.com",
  "findings": [
    {
      "path": "/.env",
      "url": "https://example.com/.env",
      "status": 200,
      "severity": "high",
      "reason": "Environment file exposed; keys: DB_PASSWORD, API_KEY (values redacted)"
    }
  ],
  "technologies": [
    {"name": "nginx", "evidence": "Server: nginx/1.25.3"}
  ],
  "leads": [
    {"source": "/robots.txt", "path": "/secret-admin"}
  ],
  "errors": []
}
```

HTML reports escape finding URLs, reasons, technology evidence, leads, and the other target-controlled fields.

---

## Structure

```
netrecon/
├── netrecon/
│   ├── cli.py          ← argparse entry point
│   ├── models.py       ← shared dataclasses
│   ├── modules/
│   │   ├── dns_enum.py
│   │   ├── ssl_check.py
│   │   ├── headers.py
│   │   ├── whois_lookup.py
│   │   ├── subdomains.py
│   │   ├── port_scan.py
│   │   └── web_exposure.py
│   └── report/
│       ├── json_report.py
│       └── html_report.py
├── tests/
├── wordlists/
│   └── common.txt
└── requirements.txt
```

---

## Requirements

- Python 3.10+
- See `requirements.txt`


## Disclaimer

Use netrecon only against hosts and networks you are authorized to test. Scanning systems or probing for exposed files without permission may be illegal. The version notes, exposed-path findings, and technology fingerprints are reconnaissance hints, not a vulnerability assessment.
