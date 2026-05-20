#!/usr/bin/env python3
"""
SubHunter - Advanced Subdomain Enumeration & Analysis Tool
Author: Cyberwarlord (Deepak Ghengat)
Version: 1.0.0
License: MIT
"""

import asyncio
import aiohttp
import aiodns
import argparse
import json
import csv
import sys
import time
import socket
import ssl
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
 ███████╗██╗   ██╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
 ██╔════╝██║   ██║██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ███████╗██║   ██║██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ╚════██║██║   ██║██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ███████║╚██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  Advanced Subdomain Enumeration & Analysis Tool v1.0.0{Style.RESET_ALL}
{Fore.GREEN}  Author: Cyberwarlord | Bug Bounty | OSINT | Recon{Style.RESET_ALL}
{Fore.RED}  For authorized testing only. Use responsibly.{Style.RESET_ALL}
"""

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
    "web", "media", "email", "images", "img", "www3", "mail3", "api", "cdn",
    "stage", "staging", "app", "apps", "video", "auth", "sso", "login", "portal",
    "intranet", "help", "chat", "proxy", "remote", "status", "monitor", "git",
    "svn", "jenkins", "jira", "confluence", "gitlab", "github", "bitbucket",
    "admin2", "backup", "db", "database", "server", "host", "server1", "server2",
    "prod", "production", "uat", "qa", "preview", "internal", "private", "secret",
    "assets", "downloads", "upload", "uploads", "files", "data", "analytics",
    "metrics", "stats", "dashboard", "panel", "backend", "service", "services",
    "microservice", "gateway", "lb", "loadbalancer", "waf", "firewall", "vpn2",
    "cloud", "storage", "s3", "bucket", "k8s", "kubernetes", "docker", "registry",
    "hub", "repo", "artifacts", "ci", "cd", "pipeline", "build", "deploy",
    "partner", "partners", "affiliate", "client", "clients", "crm", "erp",
    "helpdesk", "ticket", "tickets", "issues", "feedback", "survey", "forms",
    "payment", "pay", "billing", "invoice", "accounting", "hr", "employee",
    "staff", "team", "directory", "ldap", "active", "sso2", "oauth", "saml",
    "oidc", "identity", "id", "user", "users", "account", "accounts", "manage",
    "management", "control", "center", "hub2", "marketplace", "store", "cart",
    "checkout", "order", "orders", "catalog", "inventory", "warehouse", "supply",
    "logistics", "shipping", "delivery", "tracking", "monitor2", "alert", "alerts",
    "notification", "notifications", "webhook", "webhooks", "callback", "events",
    "stream", "streaming", "media2", "content", "cms", "wordpress", "drupal",
    "joomla", "magento", "prestashop", "opencart", "woocommerce", "shopify",
    "mx1", "mx2", "smtp2", "relay", "bounce", "bulk", "newsletter", "campaign",
    "marketing", "seo", "social", "facebook", "twitter", "linkedin", "instagram",
    "bot", "bots", "crawler", "scraper", "spider", "indexer", "search",
    "elasticsearch", "solr", "kibana", "grafana", "prometheus", "influx",
    "nagios", "zabbix", "icinga", "sensu", "pagerduty", "opsgenie",
]

class SubHunter:
    def __init__(self, domain: str, wordlist: list, concurrency: int = 100,
                 timeout: int = 5, resolvers: list = None, output: str = None,
                 output_format: str = "txt", check_http: bool = False,
                 check_ssl: bool = False, verbose: bool = False):
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.timeout = timeout
        self.resolvers = resolvers or ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
        self.output = output
        self.output_format = output_format
        self.check_http = check_http
        self.check_ssl = check_ssl
        self.verbose = verbose
        self.results = []
        self.found_count = 0
        self.checked_count = 0
        self.start_time = None
        self.semaphore = None

    async def resolve_subdomain(self, session: aiohttp.ClientSession, subdomain: str) -> Optional[dict]:
        fqdn = f"{subdomain}.{self.domain}"
        result = {
            "subdomain": fqdn,
            "ips": [],
            "cname": None,
            "http_status": None,
            "https_status": None,
            "ssl_cert": None,
            "timestamp": datetime.now().isoformat(),
        }

        async with self.semaphore:
            try:
                resolver = aiodns.DNSResolver(nameservers=self.resolvers, timeout=self.timeout)

                # A record lookup
                try:
                    a_records = await resolver.query(fqdn, "A")
                    result["ips"] = [r.host for r in a_records]
                except aiodns.error.DNSError:
                    pass

                # CNAME lookup
                try:
                    cname_records = await resolver.query(fqdn, "CNAME")
                    if cname_records:
                        result["cname"] = cname_records[0].cname
                except aiodns.error.DNSError:
                    pass

                if not result["ips"] and not result["cname"]:
                    return None

                self.found_count += 1

                # Optional HTTP probing
                if self.check_http and result["ips"]:
                    for scheme in ["https", "http"]:
                        try:
                            url = f"{scheme}://{fqdn}"
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                                   ssl=False, allow_redirects=True) as resp:
                                key = f"{scheme}_status"
                                result[key] = resp.status
                                break
                        except Exception:
                            pass

                # SSL certificate info
                if self.check_ssl and result["ips"]:
                    try:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None, self._get_ssl_info, fqdn
                            ), timeout=self.timeout
                        )
                        result["ssl_cert"] = conn
                    except Exception:
                        pass

                return result

            except Exception:
                return None
            finally:
                self.checked_count += 1
                if self.verbose and self.checked_count % 50 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.checked_count / elapsed if elapsed > 0 else 0
                    print(f"\r{Fore.CYAN}[*] Progress: {self.checked_count}/{len(self.wordlist)} "
                          f"| Found: {self.found_count} | Rate: {rate:.0f}/s{Style.RESET_ALL}", end="")

    def _get_ssl_info(self, hostname: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "not_after": cert.get("notAfter", ""),
                        "san": [x[1] for x in cert.get("subjectAltName", [])
                                if x[0] == "DNS"]
                    }
        except Exception:
            return None

    def print_result(self, result: dict):
        ips = ", ".join(result["ips"]) if result["ips"] else "CNAME"
        cname = f" → {result['cname']}" if result["cname"] else ""
        http = ""
        if result["http_status"]:
            color = Fore.GREEN if result["http_status"] < 400 else Fore.YELLOW
            http = f" [{color}HTTP:{result['http_status']}{Style.RESET_ALL}]"
        if result["https_status"]:
            color = Fore.GREEN if result["https_status"] < 400 else Fore.YELLOW
            http += f" [{color}HTTPS:{result['https_status']}{Style.RESET_ALL}]"

        print(f"\r{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.WHITE}{result['subdomain']}{Style.RESET_ALL} "
              f"{Fore.CYAN}{ips}{cname}{Style.RESET_ALL}{http}          ")

    def save_results(self):
        if not self.output:
            return

        path = Path(self.output)

        if self.output_format == "json":
            with open(path, "w") as f:
                json.dump({
                    "domain": self.domain,
                    "scan_time": datetime.now().isoformat(),
                    "total_found": len(self.results),
                    "subdomains": self.results
                }, f, indent=2)

        elif self.output_format == "csv":
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["subdomain", "ips", "cname",
                                                        "http_status", "https_status", "timestamp"])
                writer.writeheader()
                for r in self.results:
                    writer.writerow({
                        **r,
                        "ips": ", ".join(r["ips"]),
                    })

        else:  # txt
            with open(path, "w") as f:
                for r in self.results:
                    ips = ", ".join(r["ips"]) if r["ips"] else ""
                    cname = r["cname"] or ""
                    f.write(f"{r['subdomain']}\t{ips}\t{cname}\n")

        print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Results saved to {Fore.CYAN}{self.output}{Style.RESET_ALL}")

    async def run(self):
        self.start_time = time.time()
        self.semaphore = asyncio.Semaphore(self.concurrency)

        print(BANNER)
        print(f"{Fore.YELLOW}[*] Target Domain  : {Fore.WHITE}{self.domain}")
        print(f"{Fore.YELLOW}[*] Wordlist Size  : {Fore.WHITE}{len(self.wordlist)} entries")
        print(f"{Fore.YELLOW}[*] Concurrency    : {Fore.WHITE}{self.concurrency}")
        print(f"{Fore.YELLOW}[*] Resolvers      : {Fore.WHITE}{', '.join(self.resolvers)}")
        print(f"{Fore.YELLOW}[*] HTTP Probing   : {Fore.WHITE}{'ON' if self.check_http else 'OFF'}")
        print(f"{Fore.YELLOW}[*] SSL Check      : {Fore.WHITE}{'ON' if self.check_ssl else 'OFF'}")
        print(f"{Fore.YELLOW}[*] Started At     : {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}\n")

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self.resolve_subdomain(session, sub)
                for sub in self.wordlist
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        self.results = [r for r in results if r and isinstance(r, dict)]
        self.results.sort(key=lambda x: x["subdomain"])

        # Reprint results cleanly
        print(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
        for r in self.results:
            self.print_result(r)

        elapsed = time.time() - self.start_time
        print(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Scan Complete in {elapsed:.2f}s")
        print(f"{Fore.GREEN}[✓] Found: {Fore.WHITE}{len(self.results)}{Fore.GREEN} subdomains "
              f"out of {Fore.WHITE}{len(self.wordlist)}{Fore.GREEN} checked{Style.RESET_ALL}")

        self.save_results()
        return self.results


def load_wordlist(path: str) -> list:
    try:
        with open(path) as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Wordlist not found: {path}{Style.RESET_ALL}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SubHunter - Advanced Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subhunter.py -d example.com
  python subhunter.py -d example.com -w wordlists/large.txt -o results.json --format json
  python subhunter.py -d example.com --http --ssl -c 200 -v
  python subhunter.py -d example.com -r 8.8.8.8 1.1.1.1 -t 10
        """
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt",
                        dest="output_format", help="Output format (default: txt)")
    parser.add_argument("-c", "--concurrency", type=int, default=100,
                        help="Number of concurrent DNS queries (default: 100)")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                        help="DNS query timeout in seconds (default: 5)")
    parser.add_argument("-r", "--resolvers", nargs="+",
                        help="Custom DNS resolvers (e.g. 8.8.8.8 1.1.1.1)")
    parser.add_argument("--http", action="store_true", dest="check_http",
                        help="Probe HTTP/HTTPS for live hosts")
    parser.add_argument("--ssl", action="store_true", dest="check_ssl",
                        help="Grab SSL certificate information")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show progress and verbose output")

    args = parser.parse_args()

    # Validate domain format
    domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    if not domain_pattern.match(args.domain):
        print(f"{Fore.RED}[!] Invalid domain format: {args.domain}{Style.RESET_ALL}")
        sys.exit(1)

    wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_WORDLIST

    hunter = SubHunter(
        domain=args.domain,
        wordlist=wordlist,
        concurrency=args.concurrency,
        timeout=args.timeout,
        resolvers=args.resolvers,
        output=args.output,
        output_format=args.output_format,
        check_http=args.check_http,
        check_ssl=args.check_ssl,
        verbose=args.verbose,
    )

    try:
        asyncio.run(hunter.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        if hunter.results:
            hunter.save_results()
        sys.exit(0)


if __name__ == "__main__":
    main()
