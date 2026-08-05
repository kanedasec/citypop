#!/usr/bin/env python3
# @name: Bluetooth Keyboard Picker
# @desc: Scan for nearby Bluetooth devices, then pair, trust, and connect a selected keyboard or other HID through web prompts.
# @category: utilities
# @danger: false
# @active: true
# @maturity: functional
# @web: true
"""
RaspyJack payload – Bluetooth Keyboard Picker
===========================================

Interactive CLI helper to **scan**, **pair**, **trust** and **connect**
a Bluetooth keyboard (or any HID) without touching the shell.

Fix (2025‑07‑21 – rev 2)
-----------------------
* **KEY3 now exits** cleanly from anywhere (scan menu or after connection) by
  calling `cleanup()` → the outer loop ends; no more unintended restart.

Usage
-----
```bash
sudo python3 payloads/bt_keyboard_picker.py
```
Controls:
  The script scans for nearby Bluetooth devices, then prompts with a
  numbered list. Enter a number to pair/trust/connect that device, "r"
  to rescan, or "q" to quit. Ctrl-C stops a scan or pairing attempt at
  any time.
"""

# ---------------------------------------------------------------------------
# 0) Imports & boilerplate
# ---------------------------------------------------------------------------
from payloads._web_input import request_input
import os, sys, subprocess, signal, time, re
from select import select
from typing import List, Tuple
sys.path.append(os.path.abspath(os.path.join(__file__, '..', '..', '..')))

# ---------------------------------------------------------------------------
# 1) Graceful shutdown
# ---------------------------------------------------------------------------
running = True

def cleanup(*_):
    global running
    running = False

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# ---------------------------------------------------------------------------
# 2) Bluetooth helper functions
# ---------------------------------------------------------------------------
SCAN_SECONDS = 10  # adjustable

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# bluetoothctl streams one line per property change, not just the initial
# name announcement - e.g. "[CHG] Device AA:.. RSSI: -55" or
# "[CHG] Device AA:.. Connected: no". Only NEW's trailing text and an
# explicit Name:/Alias: CHG line are ever a real device name; everything
# else must be ignored so it can't clobber a name already learned.
_DEVICE_LINE_RE = re.compile(r"\[(NEW|CHG|DEL)\]\s+Device\s+([0-9A-Fa-f:]{17})(?:\s+(.*))?")
_NAME_PROPERTY_RE = re.compile(r"^(?:Name|Alias):\s*(.+)$")
# Anchored to the "Passkey:"/"PIN code:" label so stray digits elsewhere on
# the line (or leftover ANSI codes _ANSI_RE missed) can't get swept into a
# garbled fake passkey - only digits immediately after the label count.
_CODE_RE = re.compile(r"(?:Passkey|PIN code):?\s*(\d{1,16})")


def _parse_device_line(raw_line: str):
    """Return (mac, real_name_or_None) for a bluetoothctl device line, else None."""
    line = _ANSI_RE.sub("", raw_line)
    match = _DEVICE_LINE_RE.search(line)
    if not match:
        return None
    tag, mac, rest = match.groups()
    if tag == "DEL":
        return None
    mac = mac.upper()
    rest = (rest or "").strip()
    if tag == "NEW":
        return mac, (rest or None)
    name_match = _NAME_PROPERTY_RE.match(rest)
    return mac, (name_match.group(1).strip() if name_match else None)


def _record(mac: str, name, seen: dict, named: set) -> None:
    """Track a discovered MAC, only ever overwriting its name with a real one."""
    if mac not in seen:
        seen[mac] = name or mac.replace(":", "-")
        print(f"  found {mac}  {seen[mac]}", flush=True)
    if name and mac not in named:
        seen[mac] = name
        named.add(mac)


def discover_devices() -> List[Tuple[str, str]]:
    """Return list of (MAC, name) after scanning for *SCAN_SECONDS*."""
    print(f"Scanning for Bluetooth devices ({SCAN_SECONDS}s)...", flush=True)

    proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write("scan on\n"); proc.stdin.flush()

    seen: dict[str, str] = {}
    named: set[str] = set()

    def pump_until(deadline: float, respect_running: bool):
        while (not respect_running or running) and time.time() < deadline:
            ready, _, _ = select([proc.stdout], [], [], 0.2)
            if not ready:
                continue
            parsed = _parse_device_line(proc.stdout.readline())
            if parsed:
                _record(parsed[0], parsed[1], seen, named)

    try:
        pump_until(time.time() + SCAN_SECONDS, respect_running=True)
    finally:
        # Stop scan & drain for 2 s
        proc.stdin.write("scan off\n"); proc.stdin.flush()
        pump_until(time.time() + 2, respect_running=False)
        proc.terminate()

    return sorted(seen.items(), key=lambda t: (t[1].lower(), t[0]))


def pair_trust_connect(mac: str) -> bool:
    """Return *True* if the whole sequence succeeds."""
    print(f"Pairing with {mac}...", flush=True)

    proc = subprocess.Popen(
        ["bluetoothctl"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin and proc.stdout

    def send(cmd: str):
        proc.stdin.write(cmd + "\n"); proc.stdin.flush()

    for cmd in ("power on", "agent on", "default-agent"):
        send(cmd); time.sleep(0.3)

    # ---------------- Pair ----------------
    send(f"pair {mac}")
    paired = False; start = time.time()
    last_code_shown = None
    while running and (time.time() - start) < 60:
        ready, _, _ = select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = _ANSI_RE.sub("", proc.stdout.readline())
        code_match = _CODE_RE.search(line)
        if code_match:
            code = code_match.group(1)
            if code != last_code_shown:
                print(f"Type this on the keyboard: {code} and press enter", flush=True)
                last_code_shown = code
        if "Confirm passkey" in line:
            send("yes")
        if "Paired: yes" in line or "Bonded: yes" in line:
            paired = True; break
        if "Failed" in line or "Authentication" in line:
            break
        if not running:  # Ctrl-C mid-pairing
            break

    if not paired or not running:
        proc.terminate(); return False

    # ---------------- Trust ----------------
    send(f"trust {mac}"); time.sleep(0.5)

    # ---------------- Connect ----------------
    send(f"connect {mac}")
    connected = False; start = time.time()
    while running and (time.time() - start) < 15:
        ready, _, _ = select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = _ANSI_RE.sub("", proc.stdout.readline())
        if "Connection successful" in line or "already" in line:
            connected = True; break
        if "Failed" in line:
            break
        if not running:
            break

    send("quit"); proc.wait(timeout=5)
    return connected and running

# ---------------------------------------------------------------------------
# 3) CLI menu helpers
# ---------------------------------------------------------------------------

def choose(devices: List[Tuple[str, str]]):
    """Prompt the operator to pick a device, rescan, or quit."""
    if not devices:
        print("No devices found.", flush=True)
        try:
            resp = request_input(
                "No devices found", input_type="select",
                choices=[
                    {"value": "rescan", "label": "Rescan"},
                    {"value": "quit", "label": "Quit"},
                ],
                default="rescan", required=True,
            )
        except EOFError:
            resp = "quit"
        if resp == "quit":
            cleanup()
        return None

    print("Discovered devices:", flush=True)
    for i, (mac, name) in enumerate(devices, 1):
        print(f"  {i}. {name}  ({mac})", flush=True)

    choices = [{"value": mac, "label": f"{name} ({mac})"} for mac, name in devices]
    choices.append({"value": "rescan", "label": "Rescan"})
    choices.append({"value": "quit", "label": "Quit"})

    try:
        resp = request_input(
            "Select a device to pair", input_type="select", choices=choices,
            default="rescan", required=True,
        )
    except EOFError:
        resp = "quit"

    if resp in (None, "", "quit"):
        cleanup()
        return None
    if resp == "rescan":
        return None
    for mac, name in devices:
        if mac == resp:
            return mac, name

    print("Invalid selection.", flush=True)
    return None

# ---------------------------------------------------------------------------
# 4) Main loop
# ---------------------------------------------------------------------------
def main():
    try:
        while running:
            devs = discover_devices()
            if not running:
                break
            choice = choose(devs)
            if not running:
                break
            if not choice:
                continue
            mac, name = choice
            if pair_trust_connect(mac):
                print(f"Connected: {name} ({mac})", flush=True)
            else:
                print(f"Connection failed: {name} ({mac})", flush=True)
            if not running:
                break
            try:
                resp = request_input(
                    "Scan again?", input_type="select",
                    choices=[
                        {"value": "scan", "label": "Scan again"},
                        {"value": "quit", "label": "Quit"},
                    ],
                    default="scan", required=True,
                )
            except EOFError:
                resp = "quit"
            if resp == "quit":
                cleanup()
    except KeyboardInterrupt:
        cleanup()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr, flush=True)

    print("Bluetooth keyboard picker stopped.", flush=True)


if __name__ == "__main__":
    main()
