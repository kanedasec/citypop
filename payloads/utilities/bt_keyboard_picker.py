#!/usr/bin/env python3
# @name: Bluetooth Keyboard Picker
# @desc: Scan for nearby Bluetooth devices, then pair, trust, and connect a selected keyboard or other HID through web prompts.
# @category: utilities
# @danger: false
# @active: true
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
    start = time.time()
    try:
        while running and (time.time() - start) < SCAN_SECONDS:
            ready, _, _ = select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                m = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
                if m:
                    mac, name = m.group(1), m.group(2).strip()
                    if mac not in seen:
                        print(f"  found {mac}  {name}", flush=True)
                    seen[mac] = name
    finally:
        # Stop scan & drain for 2 s
        proc.stdin.write("scan off\n"); proc.stdin.flush()
        end = time.time() + 2
        while time.time() < end:
            ready, _, _ = select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                m = re.search(r"Device ([0-9A-F:]{17}) (.+)", line)
                if m:
                    mac, name = m.group(1), m.group(2).strip()
                    if mac not in seen:
                        print(f"  found {mac}  {name}", flush=True)
                    seen[mac] = name
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
    while running and (time.time() - start) < 60:
        ready, _, _ = select([proc.stdout], [], [], 0.5)
        if not ready:
            continue
        line = proc.stdout.readline()
        if "Passkey" in line or "PIN code" in line:
            code = "".join(re.findall(r"\d", line))
            print(f"Type this on the keyboard: {code}", flush=True)
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
        line = proc.stdout.readline()
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
            resp = request_input("Press Enter to rescan, or q to quit: ").strip().lower()
        except EOFError:
            resp = "q"
        if resp == "q":
            cleanup()
        return None

    print("Discovered devices:", flush=True)
    for i, (mac, name) in enumerate(devices, 1):
        print(f"  {i}. {name}  ({mac})", flush=True)

    try:
        resp = request_input("Select a number to pair, 'r' to rescan, or 'q' to quit: ").strip().lower()
    except EOFError:
        resp = "q"

    if resp == "q":
        cleanup()
        return None
    if resp == "r" or resp == "":
        return None
    if resp.isdigit() and 1 <= int(resp) <= len(devices):
        return devices[int(resp) - 1]

    print("Invalid selection.", flush=True)
    return None

# ---------------------------------------------------------------------------
# 4) Main loop
# ---------------------------------------------------------------------------
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
            resp = request_input("Press Enter to scan again, or q to quit: ").strip().lower()
        except EOFError:
            resp = "q"
        if resp == "q":
            cleanup()
except KeyboardInterrupt:
    cleanup()
except Exception as e:
    print(f"[ERROR] {e}", file=sys.stderr, flush=True)

print("Bluetooth keyboard picker stopped.", flush=True)
