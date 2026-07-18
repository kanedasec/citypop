#!/usr/bin/env python3
# @name: HID Keyboard Injector (BadUSB)
# @desc: Configure the Pi Zero as a USB HID keyboard via Linux USB gadget API (configfs).
# @category: usb
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- HID Keyboard Injector (BadUSB)
=====================================================
Author: 7h30th3r0n3

Configure the Pi Zero as a USB HID keyboard via Linux USB gadget API
(configfs). Load and execute DuckyScript-style payloads.

Setup / Prerequisites:
  - Requires Pi Zero USB OTG port. Connect Pi to target via USB.
  - Kernel must support configfs USB gadget.
  - DuckyScript files in $CITYPOP_ROOT/payloads/hid_scripts/.

Supported DuckyScript commands:
  STRING, ENTER, DELAY, GUI, ALT, CTRL, SHIFT, TAB, ESCAPE,
  UP, DOWN, LEFT, RIGHT, DELETE

Usage:
  python3 hid_injector.py [SCRIPT] [--test] [--create [TEXT]] [--list]

  SCRIPT             Filename of a DuckyScript to run (from the scripts
                      directory). If omitted, you'll be prompted to pick
                      one from the discovered list.
  --test              Test mode: parse and log the script without sending
                      any real USB HID reports.
  --create [TEXT]     Create a simple type-text payload instead of running
                      one. Prompts for TEXT if it isn't given.
  --list              List available scripts and exit.

  Press Ctrl-C at any time to stop an in-progress injection cleanly.

Scripts: $CITYPOP_ROOT/payloads/hid_scripts/
Loot:    $CITYPOP_ROOT/loot/HIDInjector/
"""

from payloads._web_input import request_input
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
SCRIPTS_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'payloads', 'hid_scripts')
LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), 'loot', 'HIDInjector')
GADGET_BASE = "/sys/kernel/config/usb_gadget"
GADGET_NAME = "raspyjack_hid"
HID_DEV = "/dev/hidg0"

os.makedirs(SCRIPTS_DIR, exist_ok=True)
os.makedirs(LOOT_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# USB HID Keycodes
# ---------------------------------------------------------------------------
# Modifier bits
MOD_NONE = 0x00
MOD_CTRL = 0x01
MOD_SHIFT = 0x02
MOD_ALT = 0x04
MOD_GUI = 0x08

# Key codes
KEY_NONE = 0x00
KEY_ENTER = 0x28
KEY_ESCAPE = 0x29
KEY_BACKSPACE = 0x2A
KEY_TAB = 0x2B
KEY_SPACE = 0x2C
KEY_DELETE = 0x4C
KEY_RIGHT_ARROW = 0x4F
KEY_LEFT_ARROW = 0x50
KEY_DOWN_ARROW = 0x51
KEY_UP_ARROW = 0x52

# ASCII to HID keycode mapping (lowercase)
_ASCII_TO_HID = {
    'a': (0x04, False), 'b': (0x05, False), 'c': (0x06, False),
    'd': (0x07, False), 'e': (0x08, False), 'f': (0x09, False),
    'g': (0x0A, False), 'h': (0x0B, False), 'i': (0x0C, False),
    'j': (0x0D, False), 'k': (0x0E, False), 'l': (0x0F, False),
    'm': (0x10, False), 'n': (0x11, False), 'o': (0x12, False),
    'p': (0x13, False), 'q': (0x14, False), 'r': (0x15, False),
    's': (0x16, False), 't': (0x17, False), 'u': (0x18, False),
    'v': (0x19, False), 'w': (0x1A, False), 'x': (0x1B, False),
    'y': (0x1C, False), 'z': (0x1D, False),
    '1': (0x1E, False), '2': (0x1F, False), '3': (0x20, False),
    '4': (0x21, False), '5': (0x22, False), '6': (0x23, False),
    '7': (0x24, False), '8': (0x25, False), '9': (0x26, False),
    '0': (0x27, False),
    ' ': (KEY_SPACE, False),
    '-': (0x2D, False), '=': (0x2E, False), '[': (0x2F, False),
    ']': (0x30, False), '\\': (0x31, False), ';': (0x33, False),
    "'": (0x34, False), '`': (0x35, False), ',': (0x36, False),
    '.': (0x37, False), '/': (0x38, False),
    '\n': (KEY_ENTER, False), '\t': (KEY_TAB, False),
}

# Shifted characters
_SHIFTED_MAP = {
    'A': 0x04, 'B': 0x05, 'C': 0x06, 'D': 0x07, 'E': 0x08,
    'F': 0x09, 'G': 0x0A, 'H': 0x0B, 'I': 0x0C, 'J': 0x0D,
    'K': 0x0E, 'L': 0x0F, 'M': 0x10, 'N': 0x11, 'O': 0x12,
    'P': 0x13, 'Q': 0x14, 'R': 0x15, 'S': 0x16, 'T': 0x17,
    'U': 0x18, 'V': 0x19, 'W': 0x1A, 'X': 0x1B, 'Y': 0x1C,
    'Z': 0x1D,
    '!': 0x1E, '@': 0x1F, '#': 0x20, '$': 0x21, '%': 0x22,
    '^': 0x23, '&': 0x24, '*': 0x25, '(': 0x26, ')': 0x27,
    '_': 0x2D, '+': 0x2E, '{': 0x2F, '}': 0x30, '|': 0x31,
    ':': 0x33, '"': 0x34, '~': 0x35, '<': 0x36, '>': 0x37,
    '?': 0x38,
}


def _char_to_hid(ch):
    """Convert a character to (modifier, keycode)."""
    if ch in _ASCII_TO_HID:
        code, _ = _ASCII_TO_HID[ch]
        return MOD_NONE, code
    if ch in _SHIFTED_MAP:
        return MOD_SHIFT, _SHIFTED_MAP[ch]
    # Unknown character, skip
    return None, None


# DuckyScript special key mapping
DUCKY_KEYS = {
    "ENTER": (MOD_NONE, KEY_ENTER),
    "RETURN": (MOD_NONE, KEY_ENTER),
    "TAB": (MOD_NONE, KEY_TAB),
    "ESCAPE": (MOD_NONE, KEY_ESCAPE),
    "ESC": (MOD_NONE, KEY_ESCAPE),
    "BACKSPACE": (MOD_NONE, KEY_BACKSPACE),
    "DELETE": (MOD_NONE, KEY_DELETE),
    "DEL": (MOD_NONE, KEY_DELETE),
    "UP": (MOD_NONE, KEY_UP_ARROW),
    "UPARROW": (MOD_NONE, KEY_UP_ARROW),
    "DOWN": (MOD_NONE, KEY_DOWN_ARROW),
    "DOWNARROW": (MOD_NONE, KEY_DOWN_ARROW),
    "LEFT": (MOD_NONE, KEY_LEFT_ARROW),
    "LEFTARROW": (MOD_NONE, KEY_LEFT_ARROW),
    "RIGHT": (MOD_NONE, KEY_RIGHT_ARROW),
    "RIGHTARROW": (MOD_NONE, KEY_RIGHT_ARROW),
    "SPACE": (MOD_NONE, KEY_SPACE),
}

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
lock = threading.Lock()
scripts = []          # list of filenames
status_msg = "Idle"
injecting = False
test_mode = False
progress = 0          # 0-100
total_lines = 0
current_line = 0
gadget_configured = False

# ---------------------------------------------------------------------------
# USB Gadget setup
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
    """Configure USB HID gadget via configfs."""
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
        _write_file(os.path.join(strings_dir, "serialnumber"), "000000000001")
        _write_file(os.path.join(strings_dir, "manufacturer"), "RaspyJack")
        _write_file(os.path.join(strings_dir, "product"), "HID Keyboard")

        config_dir = os.path.join(gadget_dir, "configs", "c.1")
        config_strings = os.path.join(config_dir, "strings", "0x409")
        os.makedirs(config_strings, exist_ok=True)
        _write_file(os.path.join(config_dir, "MaxPower"), "250")
        _write_file(os.path.join(config_strings, "configuration"), "HID Config")

        func_dir = os.path.join(gadget_dir, "functions", "hid.usb0")
        os.makedirs(func_dir, exist_ok=True)
        _write_file(os.path.join(func_dir, "protocol"), "1")
        _write_file(os.path.join(func_dir, "subclass"), "1")
        _write_file(os.path.join(func_dir, "report_length"), "8")

        # HID Report Descriptor for a keyboard
        report_desc = bytes([
            0x05, 0x01,  # Usage Page (Generic Desktop)
            0x09, 0x06,  # Usage (Keyboard)
            0xA1, 0x01,  # Collection (Application)
            0x05, 0x07,  # Usage Page (Key Codes)
            0x19, 0xE0,  # Usage Minimum (224)
            0x29, 0xE7,  # Usage Maximum (231)
            0x15, 0x00,  # Logical Minimum (0)
            0x25, 0x01,  # Logical Maximum (1)
            0x75, 0x01,  # Report Size (1)
            0x95, 0x08,  # Report Count (8)
            0x81, 0x02,  # Input (Data, Variable, Absolute) - Modifier byte
            0x95, 0x01,  # Report Count (1)
            0x75, 0x08,  # Report Size (8)
            0x81, 0x01,  # Input (Constant) - Reserved byte
            0x95, 0x05,  # Report Count (5)
            0x75, 0x01,  # Report Size (1)
            0x05, 0x08,  # Usage Page (LEDs)
            0x19, 0x01,  # Usage Minimum (1)
            0x29, 0x05,  # Usage Maximum (5)
            0x91, 0x02,  # Output (Data, Variable, Absolute) - LED report
            0x95, 0x01,  # Report Count (1)
            0x75, 0x03,  # Report Size (3)
            0x91, 0x01,  # Output (Constant) - LED padding
            0x95, 0x06,  # Report Count (6)
            0x75, 0x08,  # Report Size (8)
            0x15, 0x00,  # Logical Minimum (0)
            0x25, 0x65,  # Logical Maximum (101)
            0x05, 0x07,  # Usage Page (Key Codes)
            0x19, 0x00,  # Usage Minimum (0)
            0x29, 0x65,  # Usage Maximum (101)
            0x81, 0x00,  # Input (Data, Array) - Key array
            0xC0,        # End Collection
        ])
        with open(os.path.join(func_dir, "report_desc"), "wb") as f:
            f.write(report_desc)

        # Symlink function to config
        link_path = os.path.join(config_dir, "hid.usb0")
        if not os.path.exists(link_path):
            os.symlink(func_dir, link_path)

        # Bind to UDC
        udc_list = os.listdir("/sys/class/udc")
        if udc_list:
            _write_file(os.path.join(gadget_dir, "UDC"), udc_list[0])

        with lock:
            gadget_configured = True
        return True

    except Exception as exc:
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
        # Unbind UDC
        _write_file(os.path.join(gadget_dir, "UDC"), "")
        time.sleep(0.3)

        # Remove symlink
        link_path = os.path.join(gadget_dir, "configs", "c.1", "hid.usb0")
        if os.path.islink(link_path):
            os.unlink(link_path)

        # Remove directories in reverse order
        for subdir in [
            "configs/c.1/strings/0x409",
            "configs/c.1",
            "functions/hid.usb0",
            "strings/0x409",
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
# HID report sending
# ---------------------------------------------------------------------------

def _send_hid_report(modifier, keycode):
    """Send a single HID keyboard report."""
    report = struct.pack("BBBBBBBB", modifier, 0, keycode, 0, 0, 0, 0, 0)
    try:
        with open(HID_DEV, "rb+") as f:
            f.write(report)
            f.flush()
        time.sleep(0.02)
        # Release
        release = struct.pack("BBBBBBBB", 0, 0, 0, 0, 0, 0, 0, 0)
        with open(HID_DEV, "rb+") as f:
            f.write(release)
            f.flush()
        time.sleep(0.02)
        return True
    except Exception:
        return False


def _type_string(text):
    """Type a string character by character."""
    for ch in text:
        mod, code = _char_to_hid(ch)
        if mod is not None and code is not None:
            if not test_mode:
                _send_hid_report(mod, code)
            time.sleep(0.01)


# ---------------------------------------------------------------------------
# DuckyScript parser
# ---------------------------------------------------------------------------

def _parse_ducky_line(line):
    """Parse a single DuckyScript line, return (action, arg)."""
    line = line.strip()
    if not line or line.startswith("REM") or line.startswith("//"):
        return ("NOP", None)

    parts = line.split(" ", 1)
    cmd = parts[0].upper()
    arg = parts[1] if len(parts) > 1 else ""

    if cmd == "STRING":
        return ("STRING", arg)
    elif cmd == "DELAY":
        try:
            ms = int(arg)
        except (ValueError, TypeError):
            ms = 100
        return ("DELAY", ms)
    elif cmd == "GUI" or cmd == "WINDOWS":
        if arg:
            mod, code = _char_to_hid(arg.lower()[0])
            if code is not None:
                return ("KEY", (MOD_GUI | (mod or 0), code))
        return ("KEY", (MOD_GUI, KEY_NONE))
    elif cmd == "ALT":
        if arg:
            mod, code = _char_to_hid(arg.lower()[0])
            if code is not None:
                return ("KEY", (MOD_ALT | (mod or 0), code))
        return ("KEY", (MOD_ALT, KEY_NONE))
    elif cmd == "CTRL" or cmd == "CONTROL":
        if arg:
            mod, code = _char_to_hid(arg.lower()[0])
            if code is not None:
                return ("KEY", (MOD_CTRL | (mod or 0), code))
        return ("KEY", (MOD_CTRL, KEY_NONE))
    elif cmd == "SHIFT":
        if arg:
            mod, code = _char_to_hid(arg.lower()[0])
            if code is not None:
                return ("KEY", (MOD_SHIFT | (mod or 0), code))
        return ("KEY", (MOD_SHIFT, KEY_NONE))
    elif cmd in DUCKY_KEYS:
        return ("KEY", DUCKY_KEYS[cmd])
    else:
        return ("NOP", None)


def _execute_script(filepath):
    """Execute a DuckyScript file."""
    global injecting, status_msg, progress, total_lines, current_line

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except Exception as exc:
        with lock:
            status_msg = f"Err: {str(exc)[:16]}"
            injecting = False
        return

    with lock:
        total_lines = len(lines)
        current_line = 0
        injecting = True
        progress = 0

    log_entries = []

    for i, raw_line in enumerate(lines):
        with lock:
            if not injecting:
                break
            current_line = i + 1
            progress = int(100 * (i + 1) / max(total_lines, 1))

        action, arg = _parse_ducky_line(raw_line)

        if action == "STRING":
            with lock:
                status_msg = f"Type: {arg[:14]}"
            log_entries.append(f"STRING: {arg}")
            if not test_mode:
                _type_string(arg)
            else:
                time.sleep(0.05)

        elif action == "DELAY":
            with lock:
                status_msg = f"Delay {arg}ms"
            log_entries.append(f"DELAY: {arg}ms")
            time.sleep(arg / 1000.0)

        elif action == "KEY":
            mod, code = arg
            with lock:
                status_msg = f"Key: mod={mod:#x} key={code:#x}"
            log_entries.append(f"KEY: mod={mod:#x} code={code:#x}")
            if not test_mode:
                _send_hid_report(mod, code)
            else:
                time.sleep(0.05)

    # Save log
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(LOOT_DIR, f"inject_{ts}.log")
    with open(log_path, "w") as f:
        f.write(f"Script: {filepath}\n")
        f.write(f"Test mode: {test_mode}\n")
        f.write(f"Timestamp: {ts}\n\n")
        for entry in log_entries:
            f.write(entry + "\n")

    with lock:
        injecting = False
        mode_label = "TEST" if test_mode else "DONE"
        status_msg = f"{mode_label}: {os.path.basename(filepath)[:14]}"


# ---------------------------------------------------------------------------
# Script listing
# ---------------------------------------------------------------------------

def _scan_scripts():
    """List available DuckyScript files."""
    found = []
    if os.path.isdir(SCRIPTS_DIR):
        for fname in sorted(os.listdir(SCRIPTS_DIR)):
            if fname.endswith((".txt", ".ducky", ".ds")):
                found.append(fname)
    return found


def _create_sample_script():
    """Create hello_world.txt sample if it doesn't exist."""
    sample_path = os.path.join(SCRIPTS_DIR, "hello_world.txt")
    if not os.path.isfile(sample_path):
        content = (
            "DELAY 1000\n"
            "GUI r\n"
            "DELAY 500\n"
            "STRING notepad\n"
            "ENTER\n"
            "DELAY 1000\n"
            "STRING Hello from RaspyJack!\n"
            "ENTER\n"
        )
        with open(sample_path, "w") as f:
            f.write(content)


def _create_type_payload(text):
    """Create a simple type-text payload."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"typetext_{ts}.txt"
    path = os.path.join(SCRIPTS_DIR, fname)
    content = f"DELAY 500\nSTRING {text}\nENTER\n"
    with open(path, "w") as f:
        f.write(content)
    return fname


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _prompt_for_script():
    """Prompt the operator to pick a script from the discovered list."""
    print("Available scripts:", flush=True)
    for i, fname in enumerate(scripts, 1):
        print(f"  {i}. {fname}", flush=True)
    choice = request_input(f"Select script [1-{len(scripts)}]: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(scripts)):
        print("Invalid selection.", flush=True)
        return None
    return scripts[int(choice) - 1]


def _run_script(fpath):
    """Kick off script execution in a background thread and stream status."""
    global injecting

    gadget_ok = _setup_gadget()
    print(f"Gadget: {'ready' if gadget_ok else 'unavailable (test mode only)'}", flush=True)
    if test_mode:
        print("Test mode ON - no HID reports will be sent.", flush=True)

    print(f"Running {os.path.basename(fpath)} ...", flush=True)

    exec_thread = threading.Thread(target=_execute_script, args=(fpath,), daemon=True)
    exec_thread.start()

    last_line = -1
    try:
        while exec_thread.is_alive():
            with lock:
                msg = status_msg
                cl = current_line
                tl = total_lines
            if cl != last_line:
                print(f"[{cl}/{tl}] {msg}", flush=True)
                last_line = cl
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nInterrupted - stopping injection...", flush=True)
        with lock:
            injecting = False
    finally:
        exec_thread.join(timeout=5)
        with lock:
            final_msg = status_msg
        _teardown_gadget()

    print(f"Done: {final_msg}", flush=True)
    print(f"Log saved under {LOOT_DIR}", flush=True)


def main():
    global scripts, status_msg, test_mode, injecting

    parser = argparse.ArgumentParser(
        description="HID Keyboard Injector (BadUSB) - configure a USB HID "
                     "gadget and replay a DuckyScript payload.",
    )
    parser.add_argument(
        "script", nargs="?",
        help="DuckyScript filename to run (from the scripts directory). "
             "If omitted, you'll be prompted to pick one.",
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Test mode: parse and log the script without sending real "
             "USB HID reports.",
    )
    parser.add_argument(
        "--create", metavar="TEXT", nargs="?", const="",
        help="Create a simple type-text payload instead of running one. "
             "Prompts for TEXT if it isn't given.",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available scripts and exit.",
    )
    opts = parser.parse_args()

    test_mode = opts.test

    _create_sample_script()
    scripts = _scan_scripts()

    if opts.list:
        if not scripts:
            print("No scripts found.", flush=True)
        for i, fname in enumerate(scripts, 1):
            print(f"{i}. {fname}", flush=True)
        return 0

    if opts.create is not None:
        text = opts.create
        if not text:
            text = request_input("Text to type: ").strip()
        if not text:
            print("No text given, aborting.", flush=True)
            return 1
        fname = _create_type_payload(text)
        print(f"Created payload: {fname}", flush=True)
        return 0

    if not scripts:
        print(f"No DuckyScript files found in {SCRIPTS_DIR}", flush=True)
        print("Use --create to make a simple type-text payload.", flush=True)
        return 1

    selected = opts.script
    if selected is None:
        selected = _prompt_for_script()
        if selected is None:
            return 1
    elif selected not in scripts:
        print(f"Script not found: {selected}", flush=True)
        print("Available scripts: " + ", ".join(scripts), flush=True)
        return 1

    fpath = os.path.join(SCRIPTS_DIR, selected)
    _run_script(fpath)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
