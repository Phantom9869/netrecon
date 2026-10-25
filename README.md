# 🔍 netrecon

A modular network reconnaissance toolkit. Profile a target domain or IP from every angle — DNS, SSL, HTTP headers, WHOIS, subdomain discovery, and port scanning — unified into one structured report.

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

# Save report
python -m netrecon scan example.com --all --format json -o report.json
python -m netrecon scan example.com --all --format html -o report.html
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
│   │   └── port_scan.py
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

Use netrecon only against hosts and networks you are authorized to test. Scanning systems without permission may be illegal. The version and exposure notes are reconnaissance hints, not a vulnerability assessment.
