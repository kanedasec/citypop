#!/usr/bin/env python3
# @name: LLDP and CDP Discovery
# @desc: Passive LLDP/CDP listener for infrastructure reconnaissance.
# @category: network
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Listen duration","type":"number","default":"60"}]

import subprocess
import sys
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select network interface", input_type="select", choices=interfaces))
    try:
        seconds = max(1, min(int(sys.argv[1] if len(sys.argv) > 1 else "60"), 3600))
    except ValueError:
        return 2
    capture_filter = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
    print(f"Listening on {interface} for {seconds} seconds…", flush=True)
    result = subprocess.run(["timeout", str(seconds), "tcpdump", "-l", "-nn", "-vvv", "-e", "-i", interface, capture_filter], text=True, timeout=seconds + 10)
    return 0 if result.returncode in {0, 124} else result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
