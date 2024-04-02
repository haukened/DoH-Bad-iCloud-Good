#!/usr/bin/env python3

import dns
import os
import sys

from datetime import datetime
from signal import signal, SIGINT
from urllib.request import urlretrieve
from multiprocessing.pool import Pool

DOMAIN_LIST_URL="https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains_overall.txt"
DOMAIN_PRETTY="https://github.com/dibdot/DoH-IP-blocklists"

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
        print("Unable to download domains from GitHub")
        exit(1)

def read_domains(filepath: str) -> list[str]:
    with open(filepath) as file:
        lines = [line.rstrip() for line in file if "icloud" not in line]
    # remove temp file
    os.remove(filepath)
    log(f"downloaded {len(lines)} domains")
    return lines

def write_blacklist(filename: str, entries: dict[str,list[str]], comment: str = "", padding: int = 20) -> None:
    if len(entries) == 0:
        log(f"{filename}: no entries to write")
        return
    d = dict(sorted(entries.items()))
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        for (ip, domains) in d.items():
            f.write(f"{ip.ljust(padding)} # {' '.join(domains)}\n")

def write_domains(filename: str, entries: set[str], comment: str = "") -> None:
    domains_sorted = sorted(entries)
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        f.write(f"# updated at {now()}\n")
        if len(domains_sorted) == 0:
            f.write("# no domains returned")
        else:
            for entry in domains_sorted:
                f.write(f"{entry}\n")

def flatten(xss):
    # this flattens a list of lists into a single list
    return [x for xs in xss for x in xs]

def resolve_domains(domains: list[str], dns_server: str) -> list[dns.DNSRecord]:
    # create a thread pool to concurrently lookup domains
    # and side-step the global interpreter lock
    with Pool(10) as pool:
        total = len(domains)
        done = 0
        failed = 0
        def fail(_):
            nonlocal done, failed
            abandoned+=1
            print(f"::: {done}/{total} domains resolved, {failed} failed", end="\r", flush=True)
        def progress(_):
            nonlocal done, failed
            done+=1
            print(f"::: {done}/{total} domains resolved, {failed} failed", end="\r", flush=True)
        async_results = [pool.apply_async(dns.Resolve, args=(domain, dns_server, 53), callback=progress, error_callback=fail) for domain in domains]
        results = [async_result.get() for async_result in async_results]
        print("")
        return flatten(results)
            
def signal_handler(sig, frame) -> None:
    print('\nCtrl+C caught. Exiting.')
    sys.exit(0)

if __name__ == "__main__":
    signal(SIGINT, signal_handler)
    dns_server = os.environ['DNS_SERVER_TO_QUERY']
    if dns_server is None:
        print("error, env var DNS_SERVER_TO_QUERY is unset.")
        exit(1)
    tmpfile = download_domains()
    domains = read_domains(tmpfile)
    log("resolving domains...")
    results = resolve_domains(domains, dns_server)
    log("processing domains...")
    abandoned_domains = set()
    processed_domains = set()
    ipv4_addrs: dict[str,list[str]] = {}
    ipv6_addrs: dict[str,list[str]] = {}
    if results is not None:
        for result in results:
            if result.rcode != 0:
                abandoned_domains.add(result.domain)
            match result.type:
                case 'A':
                    e = ipv4_addrs.get(result.value, [])
                    e.append(result.domain)
                    ipv4_addrs[result.value] = e
                    processed_domains.add(result.domain)
                case 'AAAA':
                    e = ipv6_addrs.get(result.value, [])
                    e.append(result.domain)
                    ipv6_addrs[result.value] = e
                    processed_domains.add(result.domain)
                case _:
                    continue
    else:
        print("::: ERROR - Results was NoneType")
        exit(1)
    log("saving domains...")
    write_domains("domains_abandoned.txt", abandoned_domains, "unresolved domains, presumed abandoned")
    write_domains("domains_resolved.txt", processed_domains, "domains processed into block list")
    write_blacklist("doh-ipv4.txt", ipv4_addrs, "IPv4 DoH IP addresses", 20)
    write_blacklist("doh-ipv6.txt", ipv6_addrs, "IPv6 DoH IP addresses", 40)
    print("Done")