#!/usr/bin/env python3
# @name: Bluetooth Classic Scanner
# @desc: Discovers nearby Bluetooth Classic devices using hcitool scan, then enumerates SDP services for each device with sdptool browse.
# @category: reconnaissance
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- Bluetooth Classic Scanner
================================================
Author: 7h30th3r0n3

Discovers nearby Bluetooth Classic devices using hcitool scan, then
enumerates SDP services for each device with sdptool browse.

Setup / Prerequisites:
  - Requires Bluetooth adapter.

Controls:
  Usage: bt_scan_classic.py [hci_adapter]

  Runs one device-discovery + SDP-enumeration pass on the given adapter
  (default hci0, or select interactively if multiple are found), prints
  each device and its services as they are discovered, then exports the
  full results to loot as JSON.

Loot: <CITYPOP_LOOT>/BTClassic/<timestamp>.json
"""

from payloads._web_input import request_input
import os
import sys
import json
import time
import subprocess
import re
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"), "BTClassic")
os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
scanning = False
scan_status = "Idle"
devices = []          # list of {"addr": str, "name": str, "services": list}


def _list_bt_adapters():
    """Return a list of available hci adapter names."""
    adapters = []
    try:
        out = subprocess.run(["hciconfig"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            m = re.match(r"^(hci\d+):", line)
            if m:
                adapters.append(m.group(1))
    except Exception:
        pass
    return adapters


def select_bt_interface():
    """Pick a Bluetooth adapter: single arg, single available, or prompt."""
    adapters = _list_bt_adapters()
    if not adapters:
        return "hci0"
    if len(adapters) == 1:
        return adapters[0]

    print("Available Bluetooth adapters:", flush=True)
    for i, a in enumerate(adapters, 1):
        print(f"  {i}. {a}", flush=True)
    try:
        choice = request_input(f"Select adapter [1-{len(adapters)}] (default 1): ").strip()
        if not choice:
            return adapters[0]
        idx = int(choice) - 1
        if 0 <= idx < len(adapters):
            return adapters[idx]
    except (ValueError, EOFError, KeyboardInterrupt):
        pass
    return adapters[0]


# ---------------------------------------------------------------------------
# Bluetooth scanning
# ---------------------------------------------------------------------------

def _parse_scan_output(output):
    """Parse hcitool scan output into list of (addr, name) tuples."""
    results = []
    for line in output.strip().splitlines():
        line = line.strip()
        match = re.match(r"([0-9A-Fa-f:]{17})\s+(.*)", line)
        if match:
            addr = match.group(1).upper()
            name = match.group(2).strip() or "Unknown"
            results.append((addr, name))
    return results


def _parse_sdp_output(output):
    """Parse sdptool browse output into a list of service dicts."""
    services = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Service Name:"):
            if current:
                services.append(dict(current))
            current = {"name": line.split(":", 1)[1].strip()}
        elif line.startswith("Service Description:"):
            current["description"] = line.split(":", 1)[1].strip()
        elif line.startswith("Service Provider:"):
            current["provider"] = line.split(":", 1)[1].strip()
        elif line.startswith("Protocol Descriptor List:"):
            current["protocols"] = []
        elif line.startswith('"') and "protocols" in current:
            current["protocols"].append(line.strip('"').strip())
        elif line.startswith("Channel:"):
            current["channel"] = line.split(":", 1)[1].strip()
        elif line.startswith("Service RecHandle:"):
            current["handle"] = line.split(":", 1)[1].strip()
        elif line.startswith("Profile Descriptor List:"):
            current["profiles"] = []
    if current:
        services.append(dict(current))
    return services


def do_scan(adapter="hci0"):
    """Run device discovery and SDP enumeration."""
    global scanning, scan_status, devices

    scanning = True
    scan_status = "Discovering..."
    devices = []

    try:
        subprocess.run(
            ["sudo", "hciconfig", adapter, "up"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    # Device discovery
    print(f"[*] Scanning for Bluetooth Classic devices on {adapter}...", flush=True)
    try:
        result = subprocess.run(
            ["hcitool", "-i", adapter, "scan", "--flush"],
            capture_output=True, text=True, timeout=30,
        )
        found = _parse_scan_output(result.stdout)
    except subprocess.TimeoutExpired:
        found = []
        scan_status = "Scan timed out"
        print("[!] Scan timed out", flush=True)
    except Exception as exc:
        found = []
        scan_status = f"Error: {exc}"
        print(f"[!] Scan error: {exc}", flush=True)

    devices = [{"addr": addr, "name": name, "services": []} for addr, name in found]
    scan_status = f"Found {len(found)} devices"
    print(f"[*] Found {len(found)} device(s)", flush=True)
    for dev in devices:
        print(f"    {dev['addr']}  {dev['name']}", flush=True)

    # SDP enumeration for each device
    for i, dev in enumerate(list(devices)):
        scan_status = f"SDP {i + 1}/{len(found)}: {dev['addr'][-8:]}"
        print(f"[*] Enumerating SDP services for {dev['addr']} ({i + 1}/{len(found)})...", flush=True)

        try:
            result = subprocess.run(
                ["sdptool", "browse", dev["addr"]],
                capture_output=True, text=True, timeout=15,
            )
            services = _parse_sdp_output(result.stdout)
        except Exception:
            services = []

        devices[i] = {**devices[i], "services": services}
        for svc in services:
            print(f"      - {svc.get('name', 'Unknown')} (ch {svc.get('channel', '?')})", flush=True)

    total_svcs = sum(len(d["services"]) for d in devices)
    scan_status = f"Done: {len(found)} dev, {total_svcs} svc"
    scanning = False
    print(f"[*] {scan_status}", flush=True)


# ---------------------------------------------------------------------------
# Loot export
# ---------------------------------------------------------------------------

def export_loot():
    """Write scan results to JSON."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    data = {
        "timestamp": ts,
        "device_count": len(devices),
        "devices": [dict(d) for d in devices],
    }
    path = os.path.join(LOOT_DIR, f"bt_classic_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("BT CLASSIC SCAN - device discovery + SDP enumeration", flush=True)

    args = sys.argv[1:]
    bt_adapter = args[0] if args else select_bt_interface()
    if not bt_adapter:
        bt_adapter = "hci0"

    # Bring up selected adapter
    try:
        subprocess.run(
            ["sudo", "hciconfig", bt_adapter, "up"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    try:
        do_scan(bt_adapter)
    except KeyboardInterrupt:
        scanning = False
        print("\n[!] Scan interrupted by user", flush=True)

    if devices:
        path = export_loot()
        print(f"[*] Exported results to {path}", flush=True)
    else:
        print("[*] No devices found, nothing exported", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
