#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Reverse DNS
# @desc: Look up a scoped IP address hostname
# @category: reconnaissance
# @danger: false
# @maturity: functional
# @inputs: [{"name":"target","label":"IP address","type":"text","placeholder":"10.0.0.5","required":true}]
import ipaddress
import socket
import sys


def reverse_lookup(target):
    try:
        address = str(ipaddress.ip_address(target))
    except ValueError:
        print(f"Invalid IP address: {target}", flush=True)
        return 2
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(address)
    except socket.herror:
        print(f"No PTR record exists for {address}", flush=True)
        return 1
    except OSError as exc:
        print(f"Reverse DNS lookup failed for {address}: {exc}", flush=True)
        return 1
    print(f"Hostname: {hostname}", flush=True)
    if aliases:
        print(f"Aliases: {', '.join(aliases)}", flush=True)
    print(f"Addresses: {', '.join(addresses)}", flush=True)
    return 0


def main():
    if len(sys.argv) != 2:
        print("Usage: IP address", flush=True)
        return 2
    return reverse_lookup(sys.argv[1])


if __name__ == "__main__":
    raise SystemExit(main())
