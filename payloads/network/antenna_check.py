#!/usr/bin/env python3
# @name: Wi-Fi Antenna Diagnostics
# @desc: Inspect WiFi interfaces: driver, chipset, supported bands, channels, TX power, signal level, and supported modes (managed, monitor, AP, m...
# @category: network
# @danger: false
# @active: true
# @web: true

import shutil
import subprocess
from pathlib import Path
from payloads._web_input import request_input


def main() -> int:
    if not shutil.which("iw"):
        print("iw is not installed.")
        return 2
    wireless = sorted(p.name for p in Path("/sys/class/net").iterdir() if (p / "wireless").exists())
    if not wireless:
        print("No Wi-Fi interfaces were found.")
        return 1
    interface = str(request_input("Select Wi-Fi adapter", input_type="select", choices=wireless))
    for title, command in (("Link", ["iw", "dev", interface, "link"]), ("Driver", ["ethtool", "-i", interface]), ("Survey", ["iw", "dev", interface, "survey", "dump"])):
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        print(f"\n{title}\n{'-' * len(title)}\n{result.stdout.strip() or result.stderr.strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
