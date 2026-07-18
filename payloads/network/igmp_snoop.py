#!/usr/bin/env python3
# @name: IGMP Observer
# @desc: IGMP snooping for multicast group discovery.
# @category: network
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Capture duration","type":"number","default":"30"}]

import subprocess
import sys
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select capture interface", input_type="select", choices=interfaces))
    try:
        seconds = max(1, min(int(sys.argv[1] if len(sys.argv) > 1 else "30"), 3600))
    except ValueError:
        print("Duration must be a whole number.")
        return 2
    print(f"Observing IGMP on {interface} for {seconds} seconds…", flush=True)
    result = subprocess.run(["timeout", str(seconds), "tcpdump", "-l", "-nn", "-tttt", "-i", interface, "igmp"], text=True, timeout=seconds + 10)
    return 0 if result.returncode in {0, 124} else result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
