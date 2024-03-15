#!/usr/bin/env python3

import os
import socket
import sys

from signal import signal, SIGINT
from urllib.request import urlretrieve

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

def write_blacklist(filename: str, entries: list[tuple[str, str]], comment: str = "") -> None:
    if len(entries) == 0:
        log(f"{filename}: no entries to write")
        return
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        for entry in entries:
            f.write(f"{entry[0]}\t# {entry[1]}\n")

def write_domains(filename: str, entries: list[str], comment: str = "") -> None:
    if len(entries) == 0:
        log(f"{filename}: no entries to write")
        return
    with open(filename, "w") as f:
        if len(comment) > 0:
            f.write(f"# {comment}\n")
        for entry in entries:
            f.write(f"{entry}\n")

def signal_handler(sig, frame) -> None:
    print('\nCtrl+C caught. Exiting.')
    sys.exit(0)

if __name__ == "__main__":
    signal(SIGINT, signal_handler)
    tmpfile = download_domains()
    domains = read_domains(tmpfile)
    ipv4_entries = []
    ipv6_entries = []
    error_domains = []
    success_domains = []
    total = len(domains)
    for idx, domain in enumerate(domains):
        print(f"::: resolving domain {idx+1:4}/{total:4} - {domain}", end="\r")
        try:
            entries = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            for entry in entries:
                family = entry[0]
                addr = entry[4][0]
                if family == socket.AddressFamily.AF_INET:
                    ipv4_entries.append((addr, domain))
                elif family == socket.AddressFamily.AF_INET6:
                    ipv6_entries.append((addr, domain))
                success_domains.append(domain)
        except Exception as e:
            error_domains.append(domain)
    print("\n")
    log("saving domains success/error")
    write_domains("domains_resolved.txt", success_domains, "Successfully resolved domains")
    write_domains("domains_abandoned.txt", error_domains, "Domains without DNS entries")
    log("saving IPv4 blacklist")
    ipv4_entries.sort()
    write_blacklist("doh-ipv4.txt", ipv4_entries)
    log("saving IPv6 blacklist")
    ipv6_entries.sort()
    write_blacklist("doh-ipv6.txt", ipv6_entries)
    print("Done")