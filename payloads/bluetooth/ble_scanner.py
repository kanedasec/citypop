#!/usr/bin/env python3
# @name: Continuous BLE Scanner Dashboard
# @desc: Scans for BLE devices using hcitool lescan and tracks addresses, names, RSSI, first/last seen timestamps and seen count.
# @category: bluetooth
# @danger: false
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Dashboard duration","type":"number","default":"60"},{"name":"sort","label":"Device sorting","type":"select","choices":["rssi","name","count"],"default":"rssi"}]
"""
RaspyJack Payload -- Continuous BLE Scanner Dashboard
=====================================================
Author: 7h30th3r0n3

Scans for BLE devices using hcitool lescan and tracks addresses,
names, RSSI, first/last seen timestamps and seen count.  Prints a
periodically-updated device table and exports the final results.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- hcitool / hciconfig (bluez package)
- Optional: bluetoothctl for service enumeration

Controls
--------
  python3 ble_scanner.py [duration_seconds] [rssi|name|count]

    duration_seconds  -- optional, how long to scan (default: run
                          until Ctrl-C)
    sort              -- optional sort key for the device table:
                          rssi (default), name, or count

  If more than one Bluetooth adapter is present, you'll be prompted to
  pick one from a numbered list.

  After the scan ends you can optionally enter a device number to
  enumerate its GATT services, or press Enter to skip.

  Ctrl-C    -- stop scanning early and print the summary

Loot: $CITYPOP_LOOT/ble_scan_<timestamp>.json
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import asyncio
import threading
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces
from payloads._dashboard import DashboardServer

# ── Constants ────────────────────────────────────────────────────────────────
HCI_DEV = None  # set in main() via _select_bt_interface
SORT_MODES = ["rssi", "name", "count"]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = {}          # addr -> {addr, name, rssi, first_seen, last_seen, count}
scanning = False
status_msg = "Idle"


# ── HCI helpers ──────────────────────────────────────────────────────────────

def _hci_up():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


# ── Bleak BLE scan ──────────────────────────────────────────────────────────

async def _bleak_scan(timeout=5):
    """Discover BLE devices using bleak (async)."""
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [
        (d.address, d.name or "", getattr(d, "rssi", -99))
        for d in found
    ]


# ── Scan thread ──────────────────────────────────────────────────────────────

def _scan_loop():
    """Run bleak BLE scan in a loop, update device list."""
    global status_msg

    _hci_up()
    time.sleep(0.3)

    while True:
        with lock:
            if not scanning:
                break

        try:
            results = asyncio.run(_bleak_scan(5))
            now_str = datetime.now().strftime("%H:%M:%S")

            for addr, name, rssi in results:
                with lock:
                    if not scanning:
                        break
                addr = addr.upper()
                with lock:
                    if addr in devices:
                        prev = devices[addr]
                        devices[addr] = {
                            **prev,
                            "name": name or prev["name"],
                            "rssi": rssi,
                            "last_seen": now_str,
                            "count": prev["count"] + 1,
                        }
                    else:
                        devices[addr] = {
                            "addr": addr,
                            "name": name,
                            "rssi": rssi,
                            "first_seen": now_str,
                            "last_seen": now_str,
                            "count": 1,
                        }

        except Exception as exc:
            with lock:
                status_msg = str(exc)[:40]
            time.sleep(1)


# ── Service enumeration ─────────────────────────────────────────────────────

def _enumerate_services(addr):
    """Use gatttool to get services for a BLE device."""
    lines = [f"Device: {addr}"]
    try:
        proc = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            for svc_line in proc.stdout.strip().split("\n"):
                lines.append(svc_line.strip())
        else:
            lines.append("No services found")
            if proc.stderr.strip():
                lines.append(proc.stderr.strip())
    except subprocess.TimeoutExpired:
        lines.append("Connection timeout")
    except Exception as exc:
        lines.append(f"Error: {exc}")
    return lines


# ── Start / stop ─────────────────────────────────────────────────────────────

def _start_scan():
    global scanning, status_msg
    with lock:
        if scanning:
            return
        scanning = True
        status_msg = "Scanning..."
    threading.Thread(target=_scan_loop, daemon=True).start()


def _stop_scan():
    global scanning, status_msg
    with lock:
        scanning = False
        status_msg = "Stopped"
    time.sleep(0.3)
    _hci_reset()


# ── Sorted device list ──────────────────────────────────────────────────────

def _sorted_devices(sort_mode):
    with lock:
        items = list(devices.values())
    if sort_mode == "rssi":
        items.sort(key=lambda d: d["rssi"], reverse=True)
    elif sort_mode == "name":
        items.sort(key=lambda d: d["name"].lower() if d["name"] else "zzz")
    elif sort_mode == "count":
        items.sort(key=lambda d: d["count"], reverse=True)
    return items


def _print_table(sort_mode):
    devs = _sorted_devices(sort_mode)
    if not devs:
        print("No devices seen.", flush=True)
        return devs
    print(f"{'#':<3} {'ADDR':<18} {'NAME':<20} {'RSSI':>5} {'COUNT':>6} LAST SEEN", flush=True)
    for i, dev in enumerate(devs):
        name = dev["name"] or "(unknown)"
        print(f"{i:<3} {dev['addr']:<18} {name:<20} {dev['rssi']:>5} "
              f"{dev['count']:>6} {dev['last_seen']}", flush=True)
    return devs


# ── Export ───────────────────────────────────────────────────────────────────

def _export_json():
    loot_dir = Path(os.environ.get("CITYPOP_LOOT", "."))
    loot_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = loot_dir / f"ble_scan_{ts}.json"
    with lock:
        data = {"timestamp": ts, "devices": list(devices.values())}
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return path


# ── Bluetooth adapter selection ─────────────────────────────────────────────

def _select_bt_interface():
    """Detect BT interfaces and pick one. Prompts if more than one is found."""
    ifaces = list_bt_interfaces()

    if not ifaces:
        print("No Bluetooth adapter found.", flush=True)
        return None

    if len(ifaces) == 1:
        chosen = ifaces[0]
        if not chosen["is_up"]:
            subprocess.run(["sudo", "hciconfig", chosen["name"], "up"],
                           capture_output=True, timeout=5)
        return chosen["name"]

    print("Multiple Bluetooth adapters found:", flush=True)
    for i, ifc in enumerate(ifaces):
        mac = ifc["mac"] or "?"
        state = "UP" if ifc["is_up"] else "DOWN"
        print(f"  [{i}] {ifc['name']}  {ifc['bus'] or '?'}  {mac}  {state}", flush=True)

    while True:
        choice = str(request_input("Select Bluetooth adapter", input_type="select", choices=[
            {"value": str(i), "label": f"{item['name']} · {item.get('bus') or 'unknown'} · {item.get('mac') or 'no address'} · {'UP' if item.get('is_up') else 'DOWN'}"}
            for i, item in enumerate(ifaces)]))
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            chosen = ifaces[int(choice)]
            if not chosen["is_up"]:
                subprocess.run(["sudo", "hciconfig", chosen["name"], "up"],
                               capture_output=True, timeout=5)
            return chosen["name"]
        print("Invalid selection, try again.", flush=True)


# ── Main ─────────────────────────────────────────────────────────────────────

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [duration_seconds] [rssi|name|count]", flush=True)
    print("  duration_seconds  how long to scan (default: run until Ctrl-C)", flush=True)
    print("  sort              rssi (default), name, or count", flush=True)


def main():
    global HCI_DEV

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    duration = 60.0
    sort_mode = "rssi"

    if args:
        try:
            duration = float(args[0])
            args = args[1:]
        except ValueError:
            pass
    if not 1 <= duration <= 3600:
        print("duration must be between 1 and 3600 seconds", flush=True)
        return 2

    if args:
        if args[0] not in SORT_MODES:
            _usage()
            return 1
        sort_mode = args[0]

    HCI_DEV = _select_bt_interface()
    if not HCI_DEV:
        return 1

    if duration:
        print(f"Scanning for {duration:.0f}s (sort={sort_mode}) ...", flush=True)
    else:
        print(f"Scanning until Ctrl-C (sort={sort_mode}) ...", flush=True)

    _start_scan()
    start_time = time.time()
    dashboard = DashboardServer("Continuous BLE Scanner", lambda: {
        "status": status_msg,
        "adapter": HCI_DEV,
        "elapsed_seconds": round(time.time() - start_time, 1),
        "devices_seen": len(devices),
        "devices": _sorted_devices(sort_mode),
    })
    try:
        print(f"Dashboard: {dashboard.start()}", flush=True)
    except OSError as exc:
        print(f"Dashboard unavailable: {exc}", flush=True)

    try:
        while True:
            time.sleep(5.0)
            with lock:
                n_dev = len(devices)
                msg = status_msg
            elapsed = time.time() - start_time
            print(f"[{elapsed:6.1f}s] devices seen: {n_dev}  ({msg})", flush=True)
            if duration and elapsed >= duration:
                break
    except KeyboardInterrupt:
        print("\nStopping scan...", flush=True)

    _stop_scan()

    print("\nFinal results:", flush=True)
    devs = _print_table(sort_mode)

    path = _export_json()
    print(f"\nExported {len(devs)} devices to {path}", flush=True)

    if devs:
        try:
            choice = request_input(
                f"\nEnter a device number [0-{len(devs) - 1}] to enumerate "
                f"GATT services, or press Enter to skip: "
            ).strip()
        except EOFError:
            choice = ""
        if choice.isdigit() and 0 <= int(choice) < len(devs):
            addr = devs[int(choice)]["addr"]
            print(f"\nEnumerating services for {addr} ...", flush=True)
            for line in _enumerate_services(addr):
                print(line, flush=True)

    dashboard.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
