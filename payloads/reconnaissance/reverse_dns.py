#!/usr/bin/env python3
# @active: true
# @web: true
# @name: Reverse DNS
# @desc: Look up a scoped IP address hostname
# @category: reconnaissance
# @danger: false
# @maturity: functional
# @inputs: [{"name":"target","label":"IP address","type":"text","placeholder":"10.0.0.5","required":false}]
import ipaddress
import os
import socket
import sys

from payloads import _target_helper as target_helper

LOOT_ROOT = os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot")


def _select_target():
    ips = target_helper.find_ips_in_loot(LOOT_ROOT)
    candidates = target_helper.merge_candidates((ips, "seen in loot"))
    for entry in candidates:
        print(f"  - {entry['value']} ({'; '.join(entry['sources'])})", flush=True)
    return target_helper.prompt_target_selection(
        candidates,
        prompt_label="Select an IP to reverse-lookup",
        manual_label="Enter an IP address",
    )


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
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not target:
        target = _select_target()
    if not target:
        print("No IP selected. Nothing to do.", flush=True)
        return 2
    return reverse_lookup(target)


if __name__ == "__main__":
    raise SystemExit(main())
