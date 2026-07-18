#!/usr/bin/env python3
# @name: LAN Speed Test
# @desc: Measures LAN throughput using iperf3 against a chosen server.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"server","label":"iperf3 server","type":"text","placeholder":"192.168.1.10","required":true},{"name":"seconds","label":"Test duration per direction","type":"number","default":"10"}]

import json
import re
import shutil
import subprocess
import sys


def measure(server, seconds, reverse):
    command = ["iperf3", "-c", server, "-J", "-t", str(seconds)]
    if reverse:
        command.append("-R")
    result = subprocess.run(command, capture_output=True, text=True, timeout=seconds + 20)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    end = json.loads(result.stdout)["end"]
    block = end.get("sum_received") or end.get("sum_sent") or end.get("sum")
    return float(block["bits_per_second"]) / 1_000_000


def main() -> int:
    server = sys.argv[1] if len(sys.argv) > 1 else ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,253}", server) or not shutil.which("iperf3"):
        print("A valid server and the iperf3 package are required.")
        return 2
    try:
        seconds = max(1, min(int(sys.argv[2]), 120))
        print("Running download test…", flush=True)
        download = measure(server, seconds, True)
        print("Running upload test…", flush=True)
        upload = measure(server, seconds, False)
    except (IndexError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"LAN test failed: {exc}")
        return 1
    print(f"Download: {download:.2f} Mbps\nUpload:   {upload:.2f} Mbps")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
