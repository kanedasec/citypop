#!/usr/bin/env python3
# @name: Bluetooth Keyboard USB Relay
# @desc: Relay real-time keystrokes from a Bluetooth keyboard already paired to the Pi out through a USB HID gadget, so the Pi acts as a physical wired keyboard to whatever host its USB OTG port is plugged into, and save a keystroke log to loot.
# @category: usb
# @danger: true
# @active: true
# @web: true
# @maturity: not tested
# @inputs: [{"name":"seconds","label":"Relay duration in seconds (blank = until stopped)","type":"number","required":false}]
"""
City Pop payload -- Bluetooth Keyboard USB Relay
=================================================

Turns the Pi into a live wireless-to-wired keyboard bridge: keystrokes
from a Bluetooth keyboard already paired, trusted, and connected (see
utilities/bt_keyboard_picker.py) are read from its kernel evdev device
and forwarded in real time as USB HID keyboard reports out the Pi's
USB OTG port, so the machine on the other end of that USB cable sees
an ordinary wired keyboard.

This payload does not pair or connect anything itself - it only relays
a keyboard the operator has already connected over Bluetooth. If no
Bluetooth-connected keyboard is found, pair one first.

Setup / Prerequisites:
  - A Bluetooth keyboard already paired, trusted, and connected to the
    Pi (utilities/bt_keyboard_picker.py).
  - Pi Zero USB OTG port connected to the target host.
  - Kernel must support configfs USB gadgets.

Controls (CLI):
  python3 bt_keyboard_relay.py [--duration SECONDS] [--device PATH]

  --duration SECONDS   Stop automatically after this many seconds. If
                        omitted, relays until Ctrl-C / Stop.
  --device PATH        Skip discovery and relay this evdev device node
                        directly.

Loot: <CITYPOP_LOOT>/BTKeyboardRelay/relay_YYYYMMDD_HHMMSS.txt
"""

import os
import struct
import sys
import time
import signal
import argparse
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from select import select
from payloads._web_input import request_input
from payloads.usb import _hid_report as hid

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_LOOT", "/tmp/citypop_loot"), "BTKeyboardRelay")
GADGET_NAME = "citypop_bthid_relay"
HID_DEV = "/dev/hidg0"

os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
running = True
lock = threading.Lock()
relaying = False
keystroke_count = 0
last_keys: list[str] = []
key_history: list[tuple[str, str]] = []
start_time = 0.0

_pressed_modifiers = 0
_pressed_keys: list[int] = []


def _stop(*_args):
    global running
    running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


# ---------------------------------------------------------------------------
# Device selection
# ---------------------------------------------------------------------------

def _select_device() -> str | None:
    devices = hid.discover_keyboards(bustype=hid.BUS_BLUETOOTH)
    if not devices:
        print(
            "No Bluetooth-connected keyboard found. Pair, trust, and connect "
            "one first with utilities/bt_keyboard_picker.py, then rerun this "
            "payload.",
            flush=True,
        )
        return None

    print("Bluetooth keyboard(s) available to relay:", flush=True)
    for dev in devices:
        label = f"{dev['name']} ({dev['mac']})" if dev["mac"] else dev["name"]
        print(f"  - {label}  [{dev['path']}]", flush=True)

    choices = [
        {
            "value": dev["path"],
            "label": f"{dev['name']} ({dev['mac']})" if dev["mac"] else f"{dev['name']} ({dev['path']})",
        }
        for dev in devices
    ]
    try:
        return request_input(
            "Select the Bluetooth keyboard to relay",
            input_type="select", choices=choices, required=True,
        )
    except EOFError:
        return None


# ---------------------------------------------------------------------------
# Relay loop
# ---------------------------------------------------------------------------

def _log_keystroke(label: str) -> None:
    global keystroke_count, last_keys, key_history
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with lock:
        keystroke_count += 1
        last_keys = (last_keys + [label])[-3:]
        key_history = key_history + [(ts, label)]


def _relay_loop(dev_path: str) -> None:
    global _pressed_modifiers, _pressed_keys, relaying

    try:
        fd = os.open(dev_path, os.O_RDONLY)
    except OSError as exc:
        print(f"Could not open {dev_path}: {exc}", flush=True)
        with lock:
            relaying = False
        return

    try:
        while running:
            ready, _, _ = select([fd], [], [], 0.3)
            if not ready:
                continue
            try:
                data = os.read(fd, hid.EVDEV_EVENT_SIZE)
            except OSError:
                print(f"Lost {dev_path} (device disconnected?).", flush=True)
                break
            if len(data) < hid.EVDEV_EVENT_SIZE:
                continue

            _sec, _usec, ev_type, ev_code, ev_value = struct.unpack(
                "llHHI", data
            )
            if ev_type != hid.EV_KEY:
                continue

            mapping = hid.EVDEV_TO_HID.get(ev_code)
            if mapping is None:
                continue
            hid_code, label = mapping
            mod_bit = hid.MODIFIER_BITS.get(hid_code, 0)

            if ev_value == hid.KEY_STATE_DOWN:
                if mod_bit:
                    _pressed_modifiers |= mod_bit
                elif hid_code not in _pressed_keys:
                    _pressed_keys = (_pressed_keys + [hid_code])[:6]
                _log_keystroke(label)
            elif ev_value == hid.KEY_STATE_UP:
                if mod_bit:
                    _pressed_modifiers &= ~mod_bit
                else:
                    _pressed_keys = [k for k in _pressed_keys if k != hid_code]

            hid.send_hid_report(HID_DEV, _pressed_modifiers, _pressed_keys)
    finally:
        os.close(fd)
        hid.send_hid_report(HID_DEV, 0, [])  # release all keys
        with lock:
            relaying = False


# ---------------------------------------------------------------------------
# Export log
# ---------------------------------------------------------------------------

def _export_log() -> str:
    with lock:
        snapshot = list(key_history)
        count = keystroke_count
    if not snapshot:
        return "No keys relayed; nothing to export."
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"relay_{ts}.txt")
    lines = [f"Bluetooth keyboard relay -- {ts}", f"Total: {count} keys", ""]
    lines += [f"[{stamp}] {label}" for stamp, label in snapshot]
    try:
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return f"Saved {os.path.basename(path)}"
    except OSError as exc:
        return f"Could not save log: {exc}"


def _uptime_str() -> str:
    if start_time <= 0:
        return "00:00"
    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)
    hrs, mins = divmod(mins, 60)
    return f"{hrs}h{mins:02d}m" if hrs else f"{mins:02d}:{secs:02d}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    global running, relaying, start_time

    parser = argparse.ArgumentParser(
        description="Bluetooth Keyboard USB Relay - forward a paired "
                     "Bluetooth keyboard's keystrokes out the USB OTG port.",
    )
    parser.add_argument(
        "--duration", type=float, default=None,
        help="Stop automatically after this many seconds. If omitted, "
             "relays until Ctrl-C / Stop.",
    )
    parser.add_argument(
        "--device", metavar="PATH", default=None,
        help="Skip discovery and relay this evdev device node directly "
             "(a /dev/input/event device path).",
    )
    parser.add_argument("web_duration", nargs="?", default=None, help=argparse.SUPPRESS)
    opts = parser.parse_args()
    if opts.duration is None and opts.web_duration:
        try:
            opts.duration = float(opts.web_duration)
        except ValueError:
            print(f"Ignoring invalid duration: {opts.web_duration!r}", flush=True)
            opts.duration = None

    gadget_ok = hid.setup_hid_gadget(GADGET_NAME, "City Pop BT Keyboard Relay", "0000000000BT")
    if not gadget_ok:
        print(
            "Could not bind a USB HID gadget - no UDC (USB Device "
            "Controller) is available. This is expected if the Pi's USB "
            "OTG port is forced into host-only mode (dtoverlay=dwc2,"
            "dr_mode=host in config.txt, often set to use external USB "
            "adapters): that mode never registers a UDC, so gadget/HID "
            "emulation cannot work until it's switched back to peripheral "
            "or OTG mode and the Pi is rebooted.",
            flush=True,
        )
        return 1
    print("HID gadget ready on the USB OTG port.", flush=True)

    dev_path = opts.device or _select_device()
    if not dev_path:
        print("No device selected. Nothing to relay.", flush=True)
        hid.teardown_hid_gadget(GADGET_NAME)
        return 1

    print(f"Relaying keystrokes from {dev_path}", flush=True)
    with lock:
        relaying = True
        start_time = time.time()

    thread = threading.Thread(target=_relay_loop, args=(dev_path,), daemon=True)
    thread.start()

    print(
        "Relay started"
        + (f" (timeout {opts.duration:.0f}s)" if opts.duration is not None else "")
        + ". Press Ctrl-C or Stop to end.",
        flush=True,
    )

    scan_start = time.time()
    last_status = 0.0
    try:
        while running and thread.is_alive():
            now = time.time()
            if now - last_status >= 5.0:
                with lock:
                    count = keystroke_count
                    last3 = list(last_keys)
                print(
                    f"[{_uptime_str()}] relayed={count} last={' '.join(last3) or '(none)'}",
                    flush=True,
                )
                last_status = now
            if opts.duration is not None and (now - scan_start) >= opts.duration:
                print(f"Duration {opts.duration:.0f}s elapsed; stopping.", flush=True)
                running = False
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nInterrupted by operator; stopping...", flush=True)
        running = False
    finally:
        running = False
        thread.join(timeout=5)
        result = _export_log()
        print(result, flush=True)
        hid.teardown_hid_gadget(GADGET_NAME)

    with lock:
        total = keystroke_count
    print(f"Done. {total} keystroke(s) relayed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
