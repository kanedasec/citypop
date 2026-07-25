#!/usr/bin/env python3
# @name: Iface Helper
# @desc: Shared network-interface detection and web-prompt selection helper.
# @category: utilities
# @danger: false
"""
Shared network/Bluetooth interface detection for web-native payloads.

Usage in a payload:
    from payloads._iface_helper import list_interfaces

    ifaces = list_interfaces(iface_type="wifi")  # or "eth" / "any"
    # Build a request_input(..., input_type="select", choices=[...]) prompt
    # from the returned list; each row is a dict with name, driver,
    # is_onboard, is_wifi, is_up, ip, supports_ap, supports_monitor.

    from payloads._iface_helper import list_bt_interfaces

    bt_ifaces = list_bt_interfaces()  # each row: name, bus, mac, is_up, bt_version
"""

import os
import subprocess


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _get_driver(iface):
    """Return kernel driver name for an interface."""
    try:
        return os.path.basename(
            os.path.realpath(f"/sys/class/net/{iface}/device/driver")
        )
    except Exception:
        return ""


def _is_onboard_wifi(iface):
    """True for the onboard RPi WiFi (SDIO / brcmfmac)."""
    try:
        devpath = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "mmc" in devpath:
            return True
    except Exception:
        pass
    return _get_driver(iface) == "brcmfmac"


# Drivers known to support monitor+injection but not reporting it via nl80211
_KNOWN_MONITOR_DRIVERS = {
    "rtl88XXau", "rtl8812au", "rtl8821au", "rtl88x2bu",
    "rtl8188eus", "rtl8187", "rt2800usb", "ath9k_htc",
    "mt76x2u", "mt76x0u", "mt7921u", "rtl8814au",
    "rtl8192cu", "mt7601u",
}


def _supports_mode(iface, mode="AP"):
    """Check if a WiFi interface supports a given mode (AP, monitor, etc.).

    For monitor mode: first checks iw phy info, then falls back to
    driver name matching for known-good drivers that don't report
    capabilities correctly via nl80211 (common with out-of-tree Realtek).
    Works with Nexmon-patched brcmfmac (onboard Pi WiFi with injection).
    """
    try:
        phy_link = os.path.realpath(f"/sys/class/net/{iface}/phy80211")
        phy_name = os.path.basename(phy_link)
        r = subprocess.run(
            ["iw", "phy", phy_name, "info"],
            capture_output=True, text=True, timeout=5,
        )
        if f"* {mode}" in r.stdout:
            return True
    except Exception:
        pass

    # Fallback for monitor mode: check driver name against known-good list
    if mode == "monitor":
        driver = _get_driver(iface)
        if driver in _KNOWN_MONITOR_DRIVERS:
            return True

    return False


def supports_monitor(iface):
    """Public helper: True if *iface* supports monitor mode.

    Works for USB dongles AND onboard WiFi with Nexmon.
    """
    return _supports_mode(iface, "monitor")


def _get_ip(iface):
    """Return first IPv4 address of an interface, or ''."""
    try:
        r = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.strip().split("\n"):
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "inet" and i + 1 < len(parts):
                    return parts[i + 1].split("/")[0]
    except Exception:
        pass
    return ""


def _is_up(iface):
    """Return True if the interface has operstate 'up'."""
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r") as f:
            return f.read().strip().lower() == "up"
    except Exception:
        return False


def list_interfaces(iface_type="any"):
    """
    Return list of interface info dicts matching the requested type.

    iface_type:
        "wifi"  -- only wlan* interfaces
        "eth"   -- only eth*, enp*, ens*, usb* (non-wireless)
        "any"   -- all non-loopback, non-virtual interfaces

    Each dict: {name, driver, is_onboard, is_wifi, is_up, ip, supports_ap, supports_monitor}
    Sorted: USB WiFi first, then onboard WiFi, then Ethernet.
    """
    result = []
    try:
        all_ifaces = sorted(os.listdir("/sys/class/net"))
    except Exception:
        return result

    for name in all_ifaces:
        if name == "lo":
            continue

        is_wifi = os.path.isdir(f"/sys/class/net/{name}/wireless")
        is_virtual = os.path.islink(f"/sys/class/net/{name}/device") is False
        # Skip docker/veth/br/tailscale for "any" mode
        if name.startswith(("veth", "br-", "docker", "virbr")):
            continue

        if iface_type == "wifi" and not is_wifi:
            continue
        if iface_type == "eth" and is_wifi:
            continue

        driver = _get_driver(name)
        onboard = _is_onboard_wifi(name) if is_wifi else False
        ip = _get_ip(name)
        up = _is_up(name)

        info = {
            "name": name,
            "driver": driver,
            "is_onboard": onboard,
            "is_wifi": is_wifi,
            "is_up": up,
            "ip": ip,
            "supports_ap": _supports_mode(name, "AP") if is_wifi else False,
            "supports_monitor": _supports_mode(name, "monitor") if is_wifi else False,
        }
        result.append(info)

    # Sort: USB WiFi first, onboard WiFi next, then eth by name
    def _sort_key(i):
        if i["is_wifi"]:
            return (0 if not i["is_onboard"] else 1, i["name"])
        return (2, i["name"])

    return sorted(result, key=_sort_key)


# ---------------------------------------------------------------------------
# Bluetooth interface detection
# ---------------------------------------------------------------------------

def list_bt_interfaces():
    """Return list of Bluetooth HCI interfaces with info."""
    result = []
    bt_path = "/sys/class/bluetooth"
    if not os.path.isdir(bt_path):
        return result
    for name in sorted(os.listdir(bt_path)):
        if not name.startswith("hci"):
            continue
        info = {"name": name, "bus": "", "mac": "", "is_up": False, "bt_version": ""}
        # Bus type
        try:
            devpath = os.path.realpath(os.path.join(bt_path, name, "device"))
            if "usb" in devpath:
                info["bus"] = "USB"
            elif "uart" in devpath or "serial" in devpath:
                info["bus"] = "onboard"
            else:
                info["bus"] = "other"
        except Exception:
            pass
        # MAC + state from hciconfig
        try:
            r = subprocess.run(["hciconfig", name], capture_output=True, text=True, timeout=5)
            out = r.stdout
            if "UP RUNNING" in out:
                info["is_up"] = True
            for line in out.split("\n"):
                if "BD Address:" in line:
                    info["mac"] = line.split("BD Address:")[1].strip().split()[0]
                if "HCI Version:" in line:
                    info["bt_version"] = line.split("HCI Version:")[1].strip().split("(")[0].strip()
        except Exception:
            pass
        result.append(info)
    # Sort: USB first, then onboard
    return sorted(result, key=lambda x: (0 if x["bus"] == "USB" else 1, x["name"]))
