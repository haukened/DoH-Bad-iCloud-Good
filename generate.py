#!/usr/bin/env python3

import ipaddress
import os
import sys

import dns.rdatatype
import dns.rdtypes
import dns.resolver
from datetime import datetime
from signal import signal, SIGINT
from urllib.request import urlretrieve

DOMAIN_LIST_URL="https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains_overall.txt"
DOMAIN_PRETTY="https://github.com/dibdot/DoH-IP-blocklists"

should_exit = False

class DNSResult:
    addr: str
    domains: list[str]

    def __init__(self, addr: str, domains: set[str]) -> None:
        self.addr = addr
        self.domains = sorted(domains)

class DNSResults:
    _d4: dict[str,set[str]]
    _d6: dict[str,set[str]]
    _failed: set[str]
    _passed: set[str]

    def __init__(self) -> None:
       self._d4 = {}
       self._d6 = {}
       self._failed = set()
       self._passed = set()

    def __len__(self) -> int:
        return len(self._d4) + len(self._d6)

    def add(self, domain: str, ip: str):
        parsed = ipaddress.ip_address(ip)
        if not parsed.is_global or parsed.is_multicast:
            # if this is not a globally routable address dont do anything
            # if this is multicast dont do anything
            return
        if isinstance(parsed, ipaddress.IPv4Address):
            s = self._d4.get(ip, set())
            s.add(domain)
            self._d4[ip] = s
        elif isinstance(parsed, ipaddress.IPv6Address):
            s = self._d6.get(ip, set())
            s.add(domain)
            self._d6[ip] = s
    
    def failed(self, domain: str):
        self._failed.add(domain)

    def passed(self, domain: str):
        self._passed.add(domain)
        
    @property
    def num_resolved(self) -> int:
        return len(self._passed)
    
    @property
    def num_failed(self) -> int:
        return len(self._failed)
    
    @property
    def domains_passed(self) -> list[str]:
        return sorted(self._passed)

    @property
    def domains_failed(self) -> list[str]:
        return sorted(self._failed)
    
    @property
    def IPv4Addrs(self) -> list[DNSResult]:
        results: list[DNSResult] = []
        for ipaddr, domains in sorted(self._d4.items()):
            result = DNSResult(ipaddr, domains)
            results.append(result)
        return results
    
    @property
    def IPv6Addrs(self) -> list[DNSResult]:
        results: list[DNSResult] = []
        for ipaddr, domains in sorted(self._d6.items()):
            result = DNSResult(ipaddr, domains)
            results.append(result)
        return results

def log(msg: str) -> None:
    print(f"::: {msg}")

def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def download_domains() -> str:
    try:
        log(f"downloading domains from {DOMAIN_PRETTY}")
        (filepath, _) = urlretrieve(DOMAIN_LIST_URL)
        return filepath
    except:
        log("Unable to download domains from GitHub")
        exit(1)

def read_domains(filepath: str) -> list[str]:
    with open(filepath) as file:
        lines = [line.rstrip() for line in file if "icloud.com" not in line]
        lines = [line for line in lines if "apple.com" not in line]
    # remove temp file
    os.remove(filepath)
    log(f"downloaded {len(lines)} domains")
    return lines

def write_blacklist(filename: str, entries: list[DNSResult], comment: str = "", padding: int = 20) -> None:
    if len(entries) == 0:
        log(f"{filename}: no entries to write")
        return
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        for result in entries:
            f.write(f"{result.addr.ljust(padding)} # {' '.join(result.domains)}\n")

def write_domains(filename: str, domains: list[str], comment: str = "") -> None:
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        f.write(f"# updated at {now()}\n")
        if len(domains) == 0:
            f.write("# no domains returned")
        else:
            for entry in domains:
                f.write(f"{entry}\n")

def metaquery(domain: str) -> list[str]:
    results: list[str] = []
    resolver = dns.resolver.Resolver()
    # resolver.nameservers = ['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4']
    try:
        a_records = resolver.resolve(domain, dns.rdatatype.A)
        for record in a_records:
            # type(record) = <class 'dns.rdtypes.IN.A.A'>
            results.append(record.to_text())
    except:
        pass
    try:
        aaaa_records = resolver.resolve(domain, dns.rdatatype.AAAA)
        for record in aaaa_records:
            # type(record) = <class 'dns.rdtypes.IN.AAAA.AAAA'>
            results.append(record.to_text())
    except:
        pass
    return results

def resolve_domains(domains: list[str]) -> DNSResults:
    global should_exit
    results = DNSResults()
    total = len(domains)
    current = 0
    for domain in domains:
        if should_exit:
            sys.exit(1)
        query_results = metaquery(domain)
        if len(query_results) == 0:
            results.failed(domain)
        else:
            results.passed(domain)
            for qr in query_results:
                results.add(domain, qr)
        current+=1
        print(f'::: processed {current}/{total} domains, {results.num_failed} failed', end='\r', flush=True)
    print(f'::: processed {current}/{total} domains, {results.num_failed} failed')
    return results

def signal_handler(sig, frame) -> None:
    global should_exit
    should_exit = True
    print('\nCtrl+C caught. Exiting.')
    sys.exit(1)

if __name__ == "__main__":
    signal(SIGINT, signal_handler)
    log("downloading domains...")
    tmpfile = download_domains()
    domains = read_domains(tmpfile)
    log("resolving domains...")
    results = resolve_domains(domains)
    log(f'processed {len(domains)} domains into {len(results)} IP addresses')
    log(f'{results.num_resolved} addresses resolved, {results.num_failed} domains failed')
    log("saving domains...")
    write_domains("domains_abandoned.txt", results.domains_failed, "unresolved domains, presumed abandoned")
    write_domains("domains_resolved.txt", results.domains_passed, "domains processed into block list")
    write_blacklist("doh-ipv4.txt", results.IPv4Addrs, "IPv4 DoH IP addresses", 20)
    write_blacklist("doh-ipv6.txt", results.IPv6Addrs, "IPv6 DoH IP addresses", 40)
    print("Done")