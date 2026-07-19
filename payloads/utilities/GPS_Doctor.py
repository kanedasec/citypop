#!/usr/bin/env python3
# @name: GPS Doctor
# @desc: Diagnose GPS serial devices, gpsd status, gpspipe availability, and whether a live TPV fix is received.
# @category: utilities
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Fix wait time","type":"number","default":"15"}]

import glob
import json
import shutil
import subprocess
import sys


def run(command, timeout=10):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    try:
        seconds = max(2, min(int(sys.argv[1] if len(sys.argv) > 1 else "15"), 120))
    except ValueError:
        print("Wait time must be a whole number.")
        return 2
    devices = sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*") + glob.glob("/dev/serial/by-id/*"))
    print("Serial candidates: " + (", ".join(devices) or "none"))
    status = run(["systemctl", "is-active", "gpsd"])
    print("gpsd: " + (status.stdout.strip() or "inactive/unavailable"))
    if not shutil.which("gpspipe"):
        print("gpspipe is unavailable; install gpsd-clients.")
        return 1
    print(f"Waiting up to {seconds} seconds for GPS data…", flush=True)
    result = run(["gpspipe", "-w", "-n", "20"], timeout=seconds)
    fixes = []
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("class") == "TPV":
            fixes.append(item)
    if not fixes:
        print("No TPV fix received. Check antenna view, serial device, and gpsd DEVICES configuration.")
        return 1
    fix = fixes[-1]
    print(f"Mode: {fix.get('mode', 0)}D\nLatitude: {fix.get('lat', 'n/a')}\nLongitude: {fix.get('lon', 'n/a')}\nAltitude: {fix.get('alt', 'n/a')}\nSatellites used: {fix.get('uSat', 'n/a')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
