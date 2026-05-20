# 🔍 SubHunter

> Advanced Subdomain Enumeration & Analysis Tool for Bug Bounty Hunters and Penetration Testers

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Author: Cyberwarlord](https://img.shields.io/badge/Author-Cyberwarlord-red.svg)](https://github.com/cyberwarlord)

---

## Features

- ⚡ **Async DNS Resolution** — concurrent subdomain brute-forcing using `aiodns`
- 🌐 **HTTP/HTTPS Probing** — optional live host detection with status codes
- 🔒 **SSL Certificate Grabbing** — extract SANs, issuer, and expiry from TLS certs
- 📋 **Multiple Output Formats** — TXT, JSON, and CSV export
- 🔄 **Custom Resolvers** — use your own DNS servers
- 🎨 **Coloured Terminal Output** — clean, readable results
- 🧠 **Built-in Wordlist** — 200+ common subdomain prefixes included
- 🛡️ **CNAME Detection** — identify subdomain takeover candidates

---

## Installation

```bash
git clone https://github.com/cyberwarlord/SubHunter.git
cd SubHunter
pip install -r requirements.txt
```

### Requirements

```
aiohttp>=3.9.0
aiodns>=3.1.1
colorama>=0.4.6
```

---

## Usage

### Basic scan with built-in wordlist
```bash
python subhunter.py -d example.com
```

### Custom wordlist with JSON output
```bash
python subhunter.py -d example.com -w wordlists/large.txt -o results.json --format json
```

### Full scan — HTTP probing + SSL + verbose
```bash
python subhunter.py -d example.com --http --ssl -c 200 -v -o results.csv --format csv
```

### Custom DNS resolvers
```bash
python subhunter.py -d example.com -r 8.8.8.8 1.1.1.1 9.9.9.9
```

---

## Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Target domain (required) | — |
| `-w, --wordlist` | Path to custom wordlist | Built-in 200-entry list |
| `-o, --output` | Output file path | None (stdout only) |
| `--format` | Output format: `txt`, `json`, `csv` | `txt` |
| `-c, --concurrency` | Concurrent DNS queries | `100` |
| `-t, --timeout` | DNS query timeout (seconds) | `5` |
| `-r, --resolvers` | Custom DNS resolver IPs | Google, Cloudflare, Quad9 |
| `--http` | Probe HTTP/HTTPS for live hosts | Off |
| `--ssl` | Grab SSL certificate info | Off |
| `-v, --verbose` | Show progress and rate | Off |

---

## Sample Output

```
[+] api.example.com          93.184.216.34
[+] mail.example.com         93.184.216.50  [HTTP:200] [HTTPS:200]
[+] dev.example.com          10.0.1.50  → dev-internal.example.com
[+] staging.example.com      CNAME → staging-lb.example.com

[✓] Scan Complete in 12.34s
[✓] Found: 4 subdomains out of 200 checked
```

---

## JSON Output Format

```json
{
  "domain": "example.com",
  "scan_time": "2026-05-16T14:32:00",
  "total_found": 4,
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ips": ["93.184.216.34"],
      "cname": null,
      "http_status": 200,
      "https_status": 200,
      "ssl_cert": {
        "subject": {"commonName": "api.example.com"},
        "issuer": {"organizationName": "Let's Encrypt"},
        "not_after": "Aug 15 12:00:00 2026 GMT",
        "san": ["api.example.com", "*.example.com"]
      },
      "timestamp": "2026-05-16T14:32:01"
    }
  ]
}
```

---

## Use Cases for Bug Bounty

- **Attack Surface Mapping** — Enumerate all subdomains before deeper testing
- **Subdomain Takeover Detection** — CNAMEs pointing to unclaimed services
- **SSL SAN Enumeration** — Discover additional domains from certificates
- **Dev/Staging Environment Discovery** — Find test environments with weaker security
- **IP Range Discovery** — Group subdomains by IP for network-level analysis

---

## Wordlists

The built-in wordlist covers 200+ common prefixes. For more comprehensive scanning:

- [SecLists DNS Wordlists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [Assetnote Wordlists](https://wordlists.assetnote.io/)

Recommended: `bitquark-subdomains-top100000.txt` for deep enumeration.

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Using SubHunter against targets without explicit written permission is illegal and unethical. The author accepts no liability for misuse.

---

## Author

**Cyberwarlord (Deepak Ghengat)**  
Cybersecurity Consultant | Bug Bounty Hunter | Penetration Tester  
Hall of Fame: Google, Zoho, TripAdvisor, Adafruit  

[![GitHub](https://img.shields.io/badge/GitHub-Cyberwarlord-black)](https://github.com/cyberwarlord)

---

## Contributing

PRs welcome. Please test against your own authorized targets before submitting.

## License

MIT License — see [LICENSE](LICENSE) for details.
