#!/usr/bin/env python3
# @name: Live Traffic Analyzer
# @desc: Real-time network traffic analyzer dashboard.
# @category: network
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"view","label":"Summary view","type":"select","choices":["protocols","endpoints","conversations"],"default":"protocols"},{"name":"seconds","label":"Capture duration","type":"number","default":"30"}]

import shutil
import subprocess
import sys
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    if not shutil.which("tshark"):
        print("tshark is not installed.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select capture interface", input_type="select", choices=interfaces))
    view = sys.argv[1] if len(sys.argv) > 1 else "protocols"
    try:
        seconds = max(1, min(int(sys.argv[2] if len(sys.argv) > 2 else "30"), 3600))
    except ValueError:
        return 2
    options = {
        "protocols": ["-z", "io,phs"],
        "endpoints": ["-z", "endpoints,eth", "-z", "endpoints,ip", "-z", "endpoints,ipv6"],
        "conversations": ["-z", "conv,eth", "-z", "conv,ip", "-z", "conv,tcp", "-z", "conv,udp"],
    }.get(view)
    if options is None:
        return 2
    print(f"Analyzing {interface} for {seconds} seconds…", flush=True)
    result = subprocess.run(["tshark", "-i", interface, "-a", f"duration:{seconds}", "-q", *options], text=True, timeout=seconds + 30)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
