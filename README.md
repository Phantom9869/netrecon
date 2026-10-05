# netrecon

A modular network reconnaissance toolkit. Profile a target domain or IP from every angle (DNS, SSL/TLS, HTTP headers, WHOIS, subdomain discovery, and port scanning) and get one structured report in JSON or HTML.

> **Authorized use only.** Only scan domains, hosts, and networks that you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. See [Responsible Use](#responsible-use).

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Port Profiles](#port-profiles)
- [Reports](#reports)
- [Project Structure](#project-structure)
- [Development](#development)
- [Responsible Use](#responsible-use)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Module | Command | What it does |
|---|---|---|
| DNS | `dns` | A / AAAA / MX / NS / TXT / SOA records, plus SPF and DMARC validation |
| SSL/TLS | `ssl` | Certificate expiry, TLS version, cipher, SANs, and chain details |
| Headers | `headers` | Grades HTTP security headers from A+ to F |
| WHOIS | `whois` | Registrar, creation and expiry dates, nameservers |
| Subdomains | `subdomains` | Threaded wordlist brute-forcing with subdomain takeover detection |
| Ports | `ports` | Threaded TCP scanner with banner grabbing |

Every module can run on its own or together via `scan --all`. All modules share the same data models, so results merge cleanly into a single report.

---

## Quick Start

**Requirements:** Python 3.10 or newer.

```bash
git clone https://github.com/Phantom9869/netrecon.git
cd netrecon

# Recommended: use a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

Run your first scan against a domain you own:

```bash
python -m netrecon scan example.com --all -o report.html
```

---

## Usage

```
python -m netrecon <command> <target> [options]
```

### Full scan

```bash
# All modules, HTML report
python -m netrecon scan example.com --all -o report.html

# All modules, JSON report
python -m netrecon scan example.com --all --format json -o report.json
```

### Individual modules

```bash
python -m netrecon dns        example.com
python -m netrecon ssl        example.com
python -m netrecon headers    example.com
python -m netrecon whois      example.com
python -m netrecon subdomains example.com --wordlist wordlists/common.txt
python -m netrecon ports      example.com --profile top20
```

### Port scanning options

Choose one of the following ways to select ports:

```bash
# Predefined profile
python -m netrecon ports example.com --profile web

# Port range
python -m netrecon ports example.com --range 1 1024

# Specific ports
python -m netrecon ports example.com --ports 22 80 443 3306
```

### Option reference

| Option | Applies to | Description |
|---|---|---|
| `--all` | `scan` | Run every module |
| `-o`, `--output` | `scan` | Path to write the report to |
| `--format` | `scan` | Report format: `json` or `html` |
| `--wordlist` | `subdomains` | Path to a subdomain wordlist |
| `--profile` | `ports` | Named port profile (see below) |
| `--range START END` | `ports` | Scan an inclusive port range |
| `--ports P [P ...]` | `ports` | Scan specific ports |

Run `python -m netrecon --help` or `python -m netrecon <command> --help` for the full list of options.

---

## Port Profiles

| Profile | Covers |
|---|---|
| `top20` | The 20 most common ports |
| `top100` | The top 100 ports |
| `web` | 80, 443, 8000, 8080, 8443, and other common web ports |
| `db` | MySQL, PostgreSQL, Redis, MongoDB, and similar databases |
| `mail` | SMTP, POP3, IMAP, and their TLS variants |

---

## Reports

`scan` produces a single report combining the output of every module you ran.

| Format | Best for |
|---|---|
| `html` | Reading, sharing, and archiving. Open it in any browser |
| `json` | Automation, CI pipelines, and piping into other tools |

---

## Project Structure

```
netrecon/
├── netrecon/
│   ├── cli.py              # argparse entry point
│   ├── models.py           # shared dataclasses
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

## Development

```bash
pip install -r requirements.txt
pytest tests/
```

**Adding a module:**

1. Create `netrecon/modules/your_module.py` that returns the shared dataclasses from `models.py`.
2. Register a subcommand in `cli.py`.
3. Add the module's output to both report renderers in `report/`.
4. Add tests under `tests/`.

---

## Responsible Use

netrecon includes active techniques (subdomain brute-forcing and port scanning) that send traffic directly to the target.

- Get written authorization before scanning anything you don't own.
- Respect scope, rate limits, and any bug bounty or pentest rules of engagement.
- You are solely responsible for how you use this tool. The authors accept no liability for misuse.

---

## Contributing

Issues and pull requests are welcome. For larger changes, please open an issue first to discuss what you'd like to change.

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
