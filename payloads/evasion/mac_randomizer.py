#!/usr/bin/env python3
# @name: MAC Address Randomizer
# @desc: Randomize, restore, or clone MAC addresses on network interfaces.
# @category: evasion
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- MAC Address Randomizer
--------------------------------------------
Author: 7h30th3r0n3

Randomize, restore, or clone MAC addresses on network interfaces.

Usage
-----
    mac_randomizer.py [interface]

    interface -- eth0, wlan0, or wlan1 (prompted from the interfaces that
                 actually exist on this system if omitted)

Starts an interactive session on the chosen interface with a numbered
action menu:
    1. Randomize MAC
    2. Restore original MAC
    3. Clone MAC from a nearby device (scans the ARP table)
    4. Switch interface
    5. Show current MAC
    0. Exit

The MAC address seen on the interface when the session starts is
remembered so option 2 can restore it later in the same session.
"""

from payloads._web_input import request_input
import os
import sys
import time
import random
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

INTERFACES = ["eth0", "wlan0", "wlan1"]


def _run(cmd):
    """Run a shell command and return (returncode, stdout)."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout.strip()
    except Exception as exc:
        return 1, str(exc)


def _get_mac(iface):
    """Read current MAC address for an interface."""
    path = f"/sys/class/net/{iface}/address"
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except Exception:
        return "N/A"


def _iface_exists(iface):
    """Check if a network interface exists."""
    return os.path.isdir(f"/sys/class/net/{iface}")


def _generate_random_mac():
    """Generate a random locally-administered unicast MAC."""
    octets = [random.randint(0x00, 0xFF) for _ in range(6)]
    octets[0] = (octets[0] & 0xFE) | 0x02  # unicast + locally administered
    return ":".join(f"{b:02x}" for b in octets)


def _set_mac(iface, new_mac):
    """Bring interface down, set MAC, bring back up. Returns (ok, msg)."""
    rc1, _ = _run(["ip", "link", "set", iface, "down"])
    rc2, out = _run(["ip", "link", "set", iface, "address", new_mac])
    rc3, _ = _run(["ip", "link", "set", iface, "up"])
    if rc2 != 0:
        return False, out[:60]
    return True, ""


def _scan_nearby_macs():
    """Scan ARP table and wifi neighbors for MAC addresses."""
    found = []
    rc, out = _run(["ip", "neigh", "show"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            for i, part in enumerate(parts):
                if part == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1]
                    ip_addr = parts[0] if parts else "?"
                    entry = f"{ip_addr} {mac}"
                    if entry not in found:
                        found.append(entry)
    return found if found else ["No neighbors found"]


# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------
def _prompt_interface():
    existing = [i for i in INTERFACES if _iface_exists(i)]
    if not existing:
        print("None of the expected interfaces (eth0, wlan0, wlan1) were found.", flush=True)
        return None
    if len(existing) == 1:
        return existing[0]

    print("Available interfaces:", flush=True)
    for i, name in enumerate(existing, 1):
        print(f"  {i}. {name} (MAC {_get_mac(name)})", flush=True)

    while True:
        choice = request_input("Select interface number (blank to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(existing):
            return existing[int(choice) - 1]
        print("Invalid selection, try again.", flush=True)


def _resolve_interface(arg):
    if arg:
        if arg not in INTERFACES:
            print(f"Unknown interface '{arg}'. Expected one of: {', '.join(INTERFACES)}", flush=True)
            return None
        if not _iface_exists(arg):
            print(f"Interface '{arg}' does not exist on this system.", flush=True)
            return None
        return arg
    return _prompt_interface()


def _prompt_clone_target():
    print("Scanning ARP table for nearby devices...", flush=True)
    entries = _scan_nearby_macs()
    if entries == ["No neighbors found"]:
        print("No neighbors found.", flush=True)
        return None

    print("Nearby devices:", flush=True)
    for i, entry in enumerate(entries, 1):
        print(f"  {i}. {entry}", flush=True)

    while True:
        choice = request_input("Select device number to clone (blank to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(entries):
            parts = entries[int(choice) - 1].split()
            if len(parts) >= 2:
                return parts[-1]
        print("Invalid selection, try again.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _print_menu(iface, original_mac):
    print("", flush=True)
    print(f"Interface: {iface}  Current MAC: {_get_mac(iface)}  Original MAC: {original_mac}", flush=True)
    print("  1. Randomize MAC", flush=True)
    print("  2. Restore original MAC", flush=True)
    print("  3. Clone MAC from a nearby device", flush=True)
    print("  4. Switch interface", flush=True)
    print("  5. Show current MAC", flush=True)
    print("  0. Exit", flush=True)


def main():
    """Main entry point."""
    iface_arg = sys.argv[1] if len(sys.argv) > 1 else None

    iface = _resolve_interface(iface_arg)
    if not iface:
        print("No interface selected. Exiting.", flush=True)
        return 1

    original_mac = _get_mac(iface)

    try:
        while True:
            _print_menu(iface, original_mac)
            choice = request_input("Select an action: ").strip()

            if choice in ("0", ""):
                break

            elif choice == "1":
                old_mac = _get_mac(iface)
                new_mac = _generate_random_mac()
                ok, err = _set_mac(iface, new_mac)
                if ok:
                    print(f"MAC randomized on {iface}: {old_mac} -> {new_mac}", flush=True)
                else:
                    print(f"Failed to set MAC: {err}", flush=True)

            elif choice == "2":
                if original_mac and original_mac != "N/A":
                    ok, err = _set_mac(iface, original_mac)
                    if ok:
                        print(f"Restored {iface} to {original_mac}", flush=True)
                    else:
                        print(f"Failed to restore MAC: {err}", flush=True)
                else:
                    print("No original MAC saved for this interface.", flush=True)

            elif choice == "3":
                target_mac = _prompt_clone_target()
                if not target_mac:
                    print("No target MAC selected.", flush=True)
                else:
                    ok, err = _set_mac(iface, target_mac)
                    if ok:
                        print(f"Cloned MAC {target_mac} onto {iface}", flush=True)
                    else:
                        print(f"Failed to clone MAC: {err}", flush=True)

            elif choice == "4":
                new_iface = _prompt_interface()
                if new_iface:
                    iface = new_iface
                    original_mac = _get_mac(iface)

            elif choice == "5":
                print(f"{iface}: {_get_mac(iface)}", flush=True)

            else:
                print("Invalid selection, try again.", flush=True)

    except KeyboardInterrupt:
        print("\nExiting.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
