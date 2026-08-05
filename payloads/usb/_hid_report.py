#!/usr/bin/env python3
# @name: HID Report Helper
# @desc: Shared USB HID gadget (configfs) setup and evdev keycode mapping for keyboard relay/proxy payloads.
# @category: usb
# @danger: false
"""Shared USB HID keyboard gadget helpers.

Used by payloads that forward evdev keyboard events out through the
Pi's USB OTG port as if the Pi itself were a wired USB keyboard.
"""
from __future__ import annotations

import os
import struct
import time

GADGET_BASE = "/sys/kernel/config/usb_gadget"
EVDEV_DIR = "/dev/input"
EVDEV_EVENT_SIZE = struct.calcsize("llHHI")

EV_KEY = 0x01
KEY_STATE_UP = 0
KEY_STATE_DOWN = 1

# linux/input.h BUS_* constants, as reported by
# /sys/class/input/eventN/device/id/bustype.
BUS_USB = 0x03
BUS_BLUETOOTH = 0x05

# ---------------------------------------------------------------------------
# evdev keycode -> (HID keycode, label)
# ---------------------------------------------------------------------------
EVDEV_TO_HID = {
    1: (0x29, "ESC"), 2: (0x1E, "1"), 3: (0x1F, "2"), 4: (0x20, "3"),
    5: (0x21, "4"), 6: (0x22, "5"), 7: (0x23, "6"), 8: (0x24, "7"),
    9: (0x25, "8"), 10: (0x26, "9"), 11: (0x27, "0"), 12: (0x2D, "-"),
    13: (0x2E, "="), 14: (0x2A, "BKSP"), 15: (0x2B, "TAB"),
    16: (0x14, "q"), 17: (0x1A, "w"), 18: (0x08, "e"), 19: (0x15, "r"),
    20: (0x17, "t"), 21: (0x1C, "y"), 22: (0x18, "u"), 23: (0x0C, "i"),
    24: (0x12, "o"), 25: (0x13, "p"), 26: (0x2F, "["), 27: (0x30, "]"),
    28: (0x28, "ENTER"), 29: (0xE0, "LCTRL"),
    30: (0x04, "a"), 31: (0x16, "s"), 32: (0x07, "d"), 33: (0x09, "f"),
    34: (0x0A, "g"), 35: (0x0B, "h"), 36: (0x0D, "j"), 37: (0x0E, "k"),
    38: (0x0F, "l"), 39: (0x33, ";"), 40: (0x34, "'"), 41: (0x35, "`"),
    42: (0xE1, "LSHIFT"), 43: (0x31, "\\"),
    44: (0x1D, "z"), 45: (0x1B, "x"), 46: (0x06, "c"), 47: (0x19, "v"),
    48: (0x05, "b"), 49: (0x11, "n"), 50: (0x10, "m"), 51: (0x36, ","),
    52: (0x37, "."), 53: (0x38, "/"), 54: (0xE5, "RSHIFT"),
    55: (0x55, "KP*"), 56: (0xE2, "LALT"), 57: (0x2C, "SPACE"),
    58: (0x39, "CAPS"), 59: (0x3A, "F1"), 60: (0x3B, "F2"),
    61: (0x3C, "F3"), 62: (0x3D, "F4"), 63: (0x3E, "F5"),
    64: (0x3F, "F6"), 65: (0x40, "F7"), 66: (0x41, "F8"),
    67: (0x42, "F9"), 68: (0x43, "F10"), 87: (0x44, "F11"),
    88: (0x45, "F12"), 96: (0x58, "KPENT"), 97: (0xE4, "RCTRL"),
    100: (0xE6, "RALT"), 102: (0x4A, "HOME"), 103: (0x52, "UP"),
    104: (0x4B, "PGUP"), 105: (0x50, "LEFT"), 106: (0x4F, "RIGHT"),
    107: (0x4D, "END"), 108: (0x51, "DOWN"), 109: (0x4E, "PGDN"),
    110: (0x49, "INS"), 111: (0x4C, "DEL"), 125: (0xE3, "LGUI"),
    126: (0xE7, "RGUI"),
}

# HID modifier bit masks (keycodes 0xE0-0xE7)
MODIFIER_BITS = {
    0xE0: 0x01, 0xE1: 0x02, 0xE2: 0x04, 0xE3: 0x08,
    0xE4: 0x10, 0xE5: 0x20, 0xE6: 0x40, 0xE7: 0x80,
}

_KEYBOARD_REPORT_DESC = bytes([
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


# ---------------------------------------------------------------------------
# Keyboard discovery
# ---------------------------------------------------------------------------

def _read_sys(path: str) -> str:
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _has_key_capability(caps_path: str, bit: int) -> bool:
    caps = _read_sys(caps_path)
    if not caps:
        return False
    try:
        return bool(int(caps.replace(" ", ""), 16) & (1 << bit))
    except ValueError:
        return False


def discover_keyboards(bustype: int | None = None) -> list[dict]:
    """Scan /dev/input/event* for keyboard-capable devices.

    Each result is {"path", "name", "mac", "bustype"}. ``mac`` is the
    kernel-reported uniq field, populated with the peer Bluetooth address
    for most BT HID drivers, but not guaranteed by every driver. Pass
    ``bustype=BUS_BLUETOOTH`` to only return Bluetooth-connected keyboards.
    """
    found = []
    if not os.path.isdir(EVDEV_DIR):
        return found
    for entry in sorted(os.listdir(EVDEV_DIR)):
        if not entry.startswith("event"):
            continue
        sys_dev = f"/sys/class/input/{entry}/device"
        bustype_str = _read_sys(os.path.join(sys_dev, "id", "bustype"))
        try:
            dev_bustype = int(bustype_str, 16) if bustype_str else None
        except ValueError:
            dev_bustype = None
        if bustype is not None and dev_bustype != bustype:
            continue
        # KEY_A (30) is set on essentially every real keyboard's capability
        # bitmap; this is the same heuristic used to detect wired keyboards.
        if not _has_key_capability(os.path.join(sys_dev, "capabilities", "key"), 30):
            continue
        found.append({
            "path": os.path.join(EVDEV_DIR, entry),
            "name": _read_sys(os.path.join(sys_dev, "name")) or "Unknown keyboard",
            "mac": _read_sys(os.path.join(sys_dev, "uniq")).upper(),
            "bustype": dev_bustype,
        })
    return found


# ---------------------------------------------------------------------------
# USB HID gadget (configfs)
# ---------------------------------------------------------------------------

def _write_file(path: str, content: str) -> bool:
    try:
        with open(path, "w") as fh:
            fh.write(content)
        return True
    except OSError:
        return False


def setup_hid_gadget(gadget_name: str, product: str, serial: str) -> bool:
    """Configure a USB HID keyboard gadget via configfs. Returns success.

    Only returns True once the gadget is actually bound to a UDC (USB
    Device Controller). A controller forced into host-only mode (e.g.
    ``dtoverlay=dwc2,dr_mode=host`` in config.txt, often set to use
    external USB adapters on a Pi Zero's single OTG port) registers no
    UDC at all, so configfs setup can "succeed" while the gadget never
    actually appears to anything - that must be reported as a failure,
    not silently treated as ready.
    """
    gadget_dir = os.path.join(GADGET_BASE, gadget_name)
    if os.path.isdir(gadget_dir):
        return bool(_read_sys(os.path.join(gadget_dir, "UDC")))

    try:
        os.makedirs(gadget_dir, exist_ok=True)
        _write_file(os.path.join(gadget_dir, "idVendor"), "0x1d6b")
        _write_file(os.path.join(gadget_dir, "idProduct"), "0x0104")
        _write_file(os.path.join(gadget_dir, "bcdDevice"), "0x0100")
        _write_file(os.path.join(gadget_dir, "bcdUSB"), "0x0200")

        strings_dir = os.path.join(gadget_dir, "strings", "0x409")
        os.makedirs(strings_dir, exist_ok=True)
        _write_file(os.path.join(strings_dir, "serialnumber"), serial)
        _write_file(os.path.join(strings_dir, "manufacturer"), "City Pop")
        _write_file(os.path.join(strings_dir, "product"), product)

        config_dir = os.path.join(gadget_dir, "configs", "c.1")
        config_strings = os.path.join(config_dir, "strings", "0x409")
        os.makedirs(config_strings, exist_ok=True)
        _write_file(os.path.join(config_dir, "MaxPower"), "250")
        _write_file(os.path.join(config_strings, "configuration"), product)

        func_dir = os.path.join(gadget_dir, "functions", "hid.usb0")
        os.makedirs(func_dir, exist_ok=True)
        _write_file(os.path.join(func_dir, "protocol"), "1")
        _write_file(os.path.join(func_dir, "subclass"), "1")
        _write_file(os.path.join(func_dir, "report_length"), "8")
        with open(os.path.join(func_dir, "report_desc"), "wb") as fh:
            fh.write(_KEYBOARD_REPORT_DESC)

        link_path = os.path.join(config_dir, "hid.usb0")
        if not os.path.exists(link_path):
            os.symlink(func_dir, link_path)

        udc_list = os.listdir("/sys/class/udc")
        if not udc_list:
            return False
        _write_file(os.path.join(gadget_dir, "UDC"), udc_list[0])

        # Confirm the kernel actually accepted the bind rather than trusting
        # the write alone - a write can succeed while the bind still fails.
        return bool(_read_sys(os.path.join(gadget_dir, "UDC")))
    except OSError:
        return False


def teardown_hid_gadget(gadget_name: str) -> None:
    """Remove a USB HID gadget configured by :func:`setup_hid_gadget`."""
    gadget_dir = os.path.join(GADGET_BASE, gadget_name)
    if not os.path.isdir(gadget_dir):
        return
    try:
        _write_file(os.path.join(gadget_dir, "UDC"), "")
        time.sleep(0.3)
        link_path = os.path.join(gadget_dir, "configs", "c.1", "hid.usb0")
        if os.path.islink(link_path):
            os.unlink(link_path)
        for subdir in (
            "configs/c.1/strings/0x409", "configs/c.1",
            "functions/hid.usb0", "strings/0x409",
        ):
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
    except OSError:
        pass


# ---------------------------------------------------------------------------
# HID report building
# ---------------------------------------------------------------------------

def build_hid_report(modifiers: int, keys: list[int]) -> bytes:
    """Build an 8-byte HID keyboard report from a modifier byte and up to 6 keys."""
    padded = (list(keys) + [0, 0, 0, 0, 0, 0])[:6]
    return struct.pack("BBBBBBBB", modifiers, 0, *padded)


def send_hid_report(hid_dev: str, modifiers: int, keys: list[int]) -> bool:
    """Write a HID keyboard report to the gadget's /dev/hidgN node."""
    report = build_hid_report(modifiers, keys)
    try:
        with open(hid_dev, "rb+") as fh:
            fh.write(report)
            fh.flush()
        return True
    except OSError:
        return False
