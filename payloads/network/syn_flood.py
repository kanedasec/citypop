#!/usr/bin/env python3
# @name: Bounded TCP SYN Load Test
# @desc: SYN flood for testing service resilience.
# @category: network
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"target","label":"Authorized target IP or host","type":"text","required":true},{"name":"port","label":"TCP port","type":"number","default":"80"},{"name":"seconds","label":"Duration","type":"number","default":"10"},{"name":"pps","label":"Packets per second (max 1000)","type":"number","default":"100"}]

import re
import shutil
import subprocess
import sys
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    if not shutil.which("hping3"):
        print("hping3 is not installed.")
        return 2
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", target):
        print("Invalid target.")
        return 2
    try:
        port = int(sys.argv[2]); seconds = max(1, min(int(sys.argv[3]), 60)); pps = max(1, min(int(sys.argv[4]), 1000))
        if not 0 < port < 65536: raise ValueError
    except (IndexError, ValueError):
        print("Port, duration, or packet rate is invalid.")
        return 2
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    interface = str(request_input("Select output interface", input_type="select", choices=interfaces))
    count = seconds * pps
    interval_us = max(1000, 1_000_000 // pps)
    print(f"Sending {count} SYN packets to {target}:{port} through {interface} at up to {pps} pps…", flush=True)
    command = ["hping3", "-S", "-n", "-I", interface, "-p", str(port), "-c", str(count), "-i", f"u{interval_us}", target]
    return subprocess.run(command, timeout=seconds + 30).returncode


if __name__ == "__main__":
    raise SystemExit(main())
