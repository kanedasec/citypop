#!/usr/bin/env python3
# @name: USB Safe Unmount
# @desc: Lists connected USB storage devices and provides safe unmount with filesystem sync and power-off.
# @category: utilities
# @danger: false
# @active: true
# @web: true

import json
import subprocess

from payloads._web_input import request_input


def devices():
    result = subprocess.run(["lsblk", "-J", "-p", "-o", "NAME,SIZE,MOUNTPOINTS,TRAN,TYPE"], capture_output=True, text=True, timeout=10, check=True)
    found = []
    for disk in json.loads(result.stdout).get("blockdevices", []):
        if disk.get("tran") != "usb":
            continue
        mounted = [child for child in disk.get("children", []) if any(child.get("mountpoints") or [])]
        if not mounted and any(disk.get("mountpoints") or []):
            mounted = [disk]
        if mounted:
            found.append((disk, mounted))
    return found


def main() -> int:
    available = devices()
    if not available:
        print("No mounted USB storage devices were found.")
        return 1
    choices = []
    for i, (disk, parts) in enumerate(available):
        mounts = ", ".join(m for p in parts for m in (p.get("mountpoints") or []) if m)
        choices.append({"value": str(i), "label": f"{disk['name']} · {disk.get('size', '?')} · {mounts}"})
    index = int(request_input("Select USB device to safely remove", input_type="select", choices=choices))
    disk, parts = available[index]
    subprocess.run(["sync"], check=True, timeout=30)
    for part in parts:
        result = subprocess.run(["umount", part["name"]], capture_output=True, text=True, timeout=30)
        if result.returncode:
            print(result.stderr.strip())
            return result.returncode
    result = subprocess.run(["udisksctl", "power-off", "-b", disk["name"]], capture_output=True, text=True, timeout=30)
    print(result.stdout.strip() or result.stderr.strip())
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
