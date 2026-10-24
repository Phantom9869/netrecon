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
| `subdomains` | Wordlist + crt.sh certificate transparency, wildcard filtering, takeover hints |
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
python -m netrecon subdomains example.com --no-crtsh
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

## Subdomains

`subdomains` merges a wordlist with certificate-transparency names from crt.sh. Each finding records its addresses, where it came from (`wordlist`, `crtsh`, or `wordlist+crtsh`), and a takeover hint when the CNAME sits on a known unclaimed-service suffix.

- Two random labels probe for wildcard DNS. Answers that match only that sink are dropped, so a catch-all record does not mark the whole wordlist as live. A name with its own CNAME is kept — dangling aliases are how subdomain takeovers show up, and an `A` lookup alone hides them.
- Names that appear in certificate logs but no longer resolve are still reported.
- The crt.sh request does not follow redirects, times out, and stops if the body exceeds 1 MiB. A crt.sh failure leaves the wordlist results in place. `--no-crtsh` skips the lookup.
- At most 250 extra certificate-transparency names are resolved per run.

The JSON report stores these under `subdomains` (`entries`, `wildcard`, `wildcard_ips`, `crtsh_error`, `notes`). The HTML report includes the same fields. Takeover text and hostnames are escaped in the HTML output.

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


## Disclaimer

For use on systems you own or have explicit permission to test.
