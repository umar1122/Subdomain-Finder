#!/usr/bin/env python3
"""
SubFinder - A fast subdomain enumeration tool
"""

import sys
import socket
import argparse
import concurrent.futures
import time
import os
from datetime import datetime

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ─────────────────────────────────────────────
# Color helpers
# ─────────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"
    DIM     = "\033[2m"

def c(color, text):
    return f"{color}{text}{Colors.RESET}"


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
  ███████╗██╗   ██╗██████╗ ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
  ██╔════╝██║   ██║██╔══██╗██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
{Colors.RESET}{Colors.DIM}  Fast Subdomain Enumeration Tool | github.com/yourname/subfinder{Colors.RESET}
"""


# ─────────────────────────────────────────────
# Built-in wordlist (common subdomains)
# ─────────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "administrator", "panel", "cpanel", "whm",
    "api", "api2", "api3", "dev", "development", "staging",
    "test", "testing", "qa", "beta", "demo",
    "blog", "shop", "store", "news", "forum",
    "static", "assets", "cdn", "media", "images", "img",
    "files", "download", "downloads", "upload", "uploads",
    "login", "auth", "sso", "oauth",
    "vpn", "remote", "rdp", "ssh",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd",
    "docs", "documentation", "wiki", "help", "support",
    "portal", "intranet", "internal", "extranet",
    "secure", "ssl", "owa", "exchange",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "mail1", "mail2",
    "backup", "old", "new", "v1", "v2",
    "app", "apps", "mobile", "m",
    "status", "monitor", "monitoring", "metrics", "grafana", "kibana",
    "jira", "confluence", "slack",
    "cloud", "aws", "azure",
    "proxy", "gateway", "lb", "loadbalancer",
    "web", "web1", "web2", "srv", "server",
    "home", "office", "corp",
    "crm", "erp", "hr",
    "pay", "payment", "checkout", "billing",
    "smtp1", "smtp2", "relay",
    "autoconfig", "autodiscover",
    "webdav", "dav",
]


# ─────────────────────────────────────────────
# DNS / socket resolution
# ─────────────────────────────────────────────
def resolve_socket(hostname):
    """Resolve hostname using socket (fallback, no extra deps)."""
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def resolve_dns(hostname, record_types=("A", "CNAME")):
    """Resolve hostname using dnspython (preferred)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype)
            if rtype == "A":
                return str(answers[0])
            elif rtype == "CNAME":
                return f"CNAME → {str(answers[0])}"
        except Exception:
            continue
    return None


def check_subdomain(subdomain, domain, use_dns=True):
    """Check if a subdomain resolves. Returns (subdomain, ip) or (subdomain, None)."""
    hostname = f"{subdomain}.{domain}"
    if use_dns and DNS_AVAILABLE:
        ip = resolve_dns(hostname)
    else:
        ip = resolve_socket(hostname)
    return (hostname, ip)


# ─────────────────────────────────────────────
# File / wordlist helpers
# ─────────────────────────────────────────────
def load_wordlist(path):
    """Load wordlist from file, one entry per line."""
    if not os.path.isfile(path):
        print(c(Colors.RED, f"[!] Wordlist not found: {path}"))
        sys.exit(1)
    with open(path, "r", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return words


def save_results(results, output_path):
    """Save found subdomains to a file."""
    with open(output_path, "w") as f:
        f.write(f"# SubFinder results — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        for host, ip in results:
            f.write(f"{host}\t{ip}\n")
    print(c(Colors.GREEN, f"\n[+] Results saved to: {output_path}"))


# ─────────────────────────────────────────────
# Core scanner
# ─────────────────────────────────────────────
def scan(domain, wordlist, threads=50, verbose=False):
    found = []
    total = len(wordlist)
    checked = 0
    start = time.time()
    use_dns = DNS_AVAILABLE

    if not DNS_AVAILABLE and verbose:
        print(c(Colors.YELLOW, "[!] dnspython not installed — using socket fallback (slower, less accurate)"))
        print(c(Colors.YELLOW, "    Install with: pip install dnspython\n"))

    print(c(Colors.BLUE, f"[*] Scanning {total} subdomains against: {c(Colors.BOLD, domain)}"))
    print(c(Colors.BLUE, f"[*] Threads: {threads}  |  Engine: {'dnspython' if use_dns else 'socket'}\n"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain, sub, domain, use_dns): sub
            for sub in wordlist
        }
        for future in concurrent.futures.as_completed(futures):
            checked += 1
            hostname, ip = future.result()

            if ip:
                found.append((hostname, ip))
                print(c(Colors.GREEN, f"  [+] {hostname:<45} {ip}"))
            elif verbose:
                sub = futures[future]
                print(c(Colors.DIM, f"  [-] {sub}.{domain}"))

            # Progress bar every 100 checks
            if checked % 100 == 0 or checked == total:
                pct = checked / total * 100
                bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                elapsed = time.time() - start
                sys.stdout.write(
                    f"\r  {Colors.CYAN}[{bar}] {pct:.0f}%  {checked}/{total}  {elapsed:.1f}s{Colors.RESET}  "
                )
                sys.stdout.flush()

    print()  # newline after progress bar
    elapsed = time.time() - start
    return found, elapsed


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="subfinder",
        description="SubFinder — Fast Subdomain Enumeration Tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain (e.g. example.com)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        default=None,
        help="Path to custom wordlist file (default: built-in list)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=50,
        help="Number of concurrent threads (default: 50)"
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Save results to file (e.g. results.txt)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all checked subdomains (including not found)"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the banner"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print(BANNER)

    # Sanitize domain
    domain = args.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//", 1)[1].split("/")[0]

    # Load wordlist
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        print(c(Colors.CYAN, f"[*] Loaded {len(wordlist)} words from: {args.wordlist}"))
    else:
        wordlist = COMMON_SUBDOMAINS
        print(c(Colors.CYAN, f"[*] Using built-in wordlist ({len(wordlist)} entries)"))

    # Run scan
    found, elapsed = scan(domain, wordlist, threads=args.threads, verbose=args.verbose)

    # Summary
    print(c(Colors.BOLD, f"\n{'─'*60}"))
    print(c(Colors.BOLD, f"  Scan complete in {elapsed:.2f}s"))
    if found:
        print(c(Colors.GREEN, f"  Found {len(found)} subdomain(s):\n"))
        for host, ip in sorted(found):
            print(f"    {c(Colors.GREEN, '●')} {host:<45} {c(Colors.YELLOW, ip)}")
    else:
        print(c(Colors.YELLOW, "  No subdomains found."))
    print(c(Colors.BOLD, f"{'─'*60}\n"))

    # Save
    if args.output and found:
        save_results(found, args.output)


if __name__ == "__main__":
    main()
