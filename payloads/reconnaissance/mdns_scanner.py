#!/usr/bin/env python3
# @name: mDNS/Bonjour Discovery
# @desc: Browse mDNS services on a selected interface for a bounded period and report discovered service instances and hosts.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Browse duration","type":"number","default":"30"}]
import shutil
import subprocess
import sys
from pathlib import Path

from payloads._web_input import request_input


def interface_results(output, interface):
    """Keep parsable Avahi records emitted for the selected interface."""
    records = []
    for line in output.splitlines():
        fields = line.split(";", 2)
        if len(fields) >= 3 and fields[1] == interface:
            records.append(line)
    return records


def main():
    if not shutil.which("avahi-browse"):
        print("avahi-browse is unavailable; install avahi-utils.", flush=True)
        return 2
    interfaces = sorted(
        path.name for path in Path("/sys/class/net").iterdir()
        if path.name != "lo"
    )
    iface = str(request_input(
        "Select connected interface — use the interface carrying the local "
        "mDNS network; monitor mode is not required",
        input_type="select",
        choices=interfaces,
    ))
    try:
        seconds = max(1, min(int(sys.argv[1] if len(sys.argv) > 1 else "30"), 300))
    except ValueError:
        return 2

    try:
        result = subprocess.run(
            ["timeout", str(seconds), "avahi-browse", "-a", "-r", "-p"],
            capture_output=True, text=True, timeout=seconds + 10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"mDNS browse failed: {exc}", flush=True)
        return 1
    if result.stderr:
        print(result.stderr.strip(), flush=True)
    if result.returncode not in {0, 124}:
        return result.returncode

    records = interface_results(result.stdout, iface)
    if records:
        print("\n".join(records), flush=True)
    else:
        print(f"No mDNS services discovered on {iface} during {seconds}s.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
