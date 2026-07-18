#!/usr/bin/env python3
# @name: TCP Port Change Monitor
# @desc: Periodically scans the local subnet with nmap and compares results against a stored baseline.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Authorized host","type":"text","placeholder":"192.168.1.10","required":true},{"name":"ports","label":"TCP ports","type":"text","default":"22,80,443"},{"name":"seconds","label":"Monitor duration","type":"number","default":"120"},{"name":"interval","label":"Scan interval","type":"number","default":"10"}]

import re
import socket
import sys
import time


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", target):
        print("Invalid target.")
        return 2
    try:
        ports = sorted({int(p.strip()) for p in sys.argv[2].split(",") if 0 < int(p.strip()) < 65536})
        duration = max(1, min(int(sys.argv[3]), 86400))
        interval = max(1, min(int(sys.argv[4]), 3600))
    except (IndexError, ValueError):
        print("Ports, duration, or interval are invalid.")
        return 2
    previous = None
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        current = set()
        for port in ports:
            try:
                with socket.create_connection((target, port), timeout=1):
                    current.add(port)
            except OSError:
                pass
        if previous is None:
            print("Initially open: " + (", ".join(map(str, sorted(current))) or "none"), flush=True)
        else:
            for port in sorted(current - previous):
                print(f"{time.strftime('%H:%M:%S')} · TCP {port} opened", flush=True)
            for port in sorted(previous - current):
                print(f"{time.strftime('%H:%M:%S')} · TCP {port} closed", flush=True)
        previous = current
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
