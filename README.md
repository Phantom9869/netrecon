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
| `ports` | Threaded TCP scanner with banner grabbing |

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
| `db` | MySQL, Postgres, Redis, Mongo… |
| `mail` | SMTP, POP3, IMAP and TLS variants |

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

---

## Disclaimer

For use on systems you own or have explicit permission to test.
