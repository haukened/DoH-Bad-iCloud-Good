#!/usr/bin/env python3

import os
import socket
import sys

from signal import signal, SIGINT
from tqdm import tqdm
from urllib.request import urlretrieve
from multiprocessing.pool import Pool

DOMAIN_LIST_URL="https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains_overall.txt"
DOMAIN_PRETTY="https://github.com/dibdot/DoH-IP-blocklists"

def log(msg: str) -> None:
    print(f"::: {msg}")

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
    if len(domains_sorted) == 0:
        log(f"{filename}: no entries to write")
        return
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        for entry in domains_sorted:
            f.write(f"{entry}\n")

def flatten(xss):
    # this flattens a list of lists into a single list
    return [x for xs in xss for x in xs]

# define a work function for the pool
def resolve(domain: str) -> list[tuple[str,str,socket.AddressFamily]]:
    results = []
    try:
        entries = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        for entry in entries:
            family = entry[0]
            addr = entry[4][0]
            results.append((domain, addr, family))
    except:
        results.append((domain, '-', socket.AddressFamily.AF_UNSPEC))
    finally:
        return results

def resolve_domains(domains: list[str]) -> list[tuple[str,str,socket.AddressFamily]]:
    # create a thread pool to concurrently lookup domains
    # and side-step the global interpreter lock
    with Pool(10) as pool:
        with tqdm(total=len(domains), leave=False) as pbar:
            def progress(_):
                pbar.update()
            async_results = [pool.apply_async(resolve, args=(domain,), callback=progress) for domain in domains]
            results = [async_result.get() for async_result in async_results]
            return flatten(results)
            
def signal_handler(sig, frame) -> None:
    print('\nCtrl+C caught. Exiting.')
    sys.exit(0)

if __name__ == "__main__":
    signal(SIGINT, signal_handler)
    tmpfile = download_domains()
    domains = read_domains(tmpfile)
    log("resolving domains...")
    results = resolve_domains(domains)
    log("processing domains...")
    abandoned_domains = set()
    processed_domains = set()
    ipv4_addrs: dict[str,list[str]] = {}
    ipv6_addrs: dict[str,list[str]] = {}
    for (domain, addr, family) in tqdm(results, unit="domains", leave=False):
        match family:
            case socket.AddressFamily.AF_UNSPEC:
                abandoned_domains.add(domain)
            case socket.AddressFamily.AF_INET:
                e = ipv4_addrs.get(addr, [])
                e.append(domain)
                ipv4_addrs[addr] = e
                processed_domains.add(domain)
            case socket.AddressFamily.AF_INET6:
                e = ipv6_addrs.get(addr, [])
                e.append(domain)
                ipv6_addrs[addr] = e
                processed_domains.add(domain)
            case _:
                continue
    log("saving domains...")
    write_domains("domains_abandoned.txt", abandoned_domains, "unresolved domains, presumed abandoned")
    write_domains("domains_resolved.txt", processed_domains, "domains processed into block list")
    write_blacklist("doh-ipv4.txt", ipv4_addrs, "IPv4 DoH IP addresses", 20)
    write_blacklist("doh-ipv6.txt", ipv6_addrs, "IPv6 DoH IP addresses", 40)
    print("Done")