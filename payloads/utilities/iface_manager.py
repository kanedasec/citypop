#!/usr/bin/env python3
# @name: Interface Manager
# @desc: Centralized network interface management: rfkill, monitor mode,.
# @category: utilities
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"action","label":"Action","type":"select","choices":["inspect","enable","disable"],"default":"inspect"}]

import json
import subprocess
import sys
from pathlib import Path

from payloads._web_input import request_input


def main() -> int:
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir() if p.name != "lo")
    if not interfaces:
        print("No network interfaces were found.")
        return 1
    interface = str(request_input("Select network interface", input_type="select", choices=interfaces))
    action = sys.argv[1] if len(sys.argv) > 1 else "inspect"
    if action == "inspect":
        result = subprocess.run(["ip", "-j", "address", "show", "dev", interface], capture_output=True, text=True)
        try:
            item = json.loads(result.stdout)[0]
            print(f"Interface: {interface}\nState: {item.get('operstate', 'UNKNOWN')}\nMTU: {item.get('mtu', '?')}")
            for address in item.get("addr_info", []):
                print(f"{address.get('family')}: {address.get('local')}/{address.get('prefixlen')}")
        except (json.JSONDecodeError, IndexError):
            print(result.stderr.strip() or "Unable to inspect interface.")
        return result.returncode
    if action not in {"enable", "disable"}:
        print("Unsupported action.")
        return 2
    result = subprocess.run(["ip", "link", "set", "dev", interface, "up" if action == "enable" else "down"], capture_output=True, text=True)
    print(result.stderr.strip() or f"{interface} {action}d.")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
