#!/usr/bin/env python3
# @name: Stealth Mode Toggle
# @desc: One-click toggle to minimize the Pi's visible footprint:.
# @category: evasion
# @danger: true
# @active: true
"""
RaspyJack Payload -- Stealth Mode Toggle
==========================================
Author: 7h30th3r0n3

One-click toggle to minimize the Pi's visible footprint:
  - Disable ACT/PWR LEDs
  - Reduce WiFi TX power to minimum
  - Randomize MAC addresses on all interfaces
  - Change hostname to generic name
  - Flush system logs and bash history
  - Disable syslog temporarily

All original values are saved and can be restored on deactivation.

Usage
-----
    stealth_mode.py

Starts an interactive session with a numbered action menu:
    1. Toggle stealth ON/OFF (all items at once)
    2. Toggle an individual item
    3. Show status
    0. Exit

If stealth is still active when you exit (option 0 or Ctrl-C), all
reversible changes are restored automatically before the process ends.
"""

from payloads._web_input import request_input
import os
import sys
import time
import random
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
LED_PATHS = {
    "ACT": ["/sys/class/leds/ACT/brightness", "/sys/class/leds/led0/brightness"],
    "PWR": ["/sys/class/leds/PWR/brightness", "/sys/class/leds/led1/brightness"],
}
STEALTH_HOSTNAME = "localhost"
WIFI_IFACE = "wlan0"
MIN_TX_POWER = "1"
GENERIC_OUI_PREFIXES = [
    "02:00:00", "02:42:ac", "02:50:00", "06:00:00",
]

# ---------------------------------------------------------------------------
# Stealth items
# ---------------------------------------------------------------------------
ITEMS = [
    {"id": "act_led", "label": "ACT LED off"},
    {"id": "pwr_led", "label": "PWR LED off"},
    {"id": "wifi_txpwr", "label": "WiFi TX min"},
    {"id": "mac_random", "label": "MAC randomize"},
    {"id": "hostname", "label": "Hostname generic"},
    {"id": "flush_logs", "label": "Flush logs"},
    {"id": "clear_hist", "label": "Clear history"},
    {"id": "disable_syslog", "label": "Disable syslog"},
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
stealth_active = False
item_states = {item["id"]: False for item in ITEMS}
status_msg = "Ready"

# Original values for restoration
_originals = {
    "act_led": "",
    "pwr_led": "",
    "wifi_txpwr": "",
    "macs": {},            # iface -> original mac
    "hostname": "",
    "syslog_was_active": False,
}


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=10):
    """Run a command, return (returncode, stdout)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode, result.stdout.strip()
    except Exception as exc:
        return 1, str(exc)[:40]


def _read_file(path):
    """Read a single-line value from a sysfs file."""
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except Exception:
        return ""


def _write_file_sudo(path, value):
    """Write a value to a file using sudo tee."""
    try:
        proc = subprocess.run(
            ["sudo", "tee", path],
            input=value, capture_output=True, text=True, timeout=5,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _get_mac(iface):
    """Get current MAC address."""
    path = f"/sys/class/net/{iface}/address"
    return _read_file(path)


def _generate_random_mac():
    """Generate a random locally-administered unicast MAC."""
    prefix = random.choice(GENERIC_OUI_PREFIXES)
    suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    return f"{prefix}:{suffix}"


def _get_interfaces():
    """List network interfaces (excluding lo)."""
    try:
        entries = os.listdir("/sys/class/net")
        return [e for e in entries if e != "lo"]
    except Exception:
        return ["eth0", "wlan0"]


def _find_led_path(led_name):
    """Find the working sysfs path for an LED."""
    for path in LED_PATHS.get(led_name, []):
        if os.path.exists(path):
            return path
    return None


# ---------------------------------------------------------------------------
# Save originals
# ---------------------------------------------------------------------------

def _save_originals():
    """Capture current system state before modifications."""
    global _originals

    new_originals = dict(_originals)

    # ACT LED
    act_path = _find_led_path("ACT")
    if act_path:
        new_originals["act_led"] = _read_file(act_path)

    # PWR LED
    pwr_path = _find_led_path("PWR")
    if pwr_path:
        new_originals["pwr_led"] = _read_file(pwr_path)

    # WiFi TX power (iw reports in mBm, e.g. "txpower 20.00 dBm")
    rc, out = _run(["iw", "dev", WIFI_IFACE, "info"])
    if rc == 0:
        for line in out.splitlines():
            if "txpower" in line:
                parts = line.strip().split()
                # e.g. "txpower 20.00 dBm" -> "20.00"
                if len(parts) >= 2:
                    new_originals["wifi_txpwr"] = parts[1]
                break

    # MAC addresses
    mac_dict = {}
    for iface in _get_interfaces():
        mac_dict[iface] = _get_mac(iface)
    new_originals["macs"] = mac_dict

    # Hostname
    rc, out = _run(["hostname"])
    if rc == 0:
        new_originals["hostname"] = out

    # Syslog status
    rc, out = _run(["systemctl", "is-active", "rsyslog"])
    new_originals["syslog_was_active"] = (out == "active")

    _originals = new_originals


# ---------------------------------------------------------------------------
# Stealth actions (enable)
# ---------------------------------------------------------------------------

def _enable_act_led():
    """Disable ACT LED."""
    path = _find_led_path("ACT")
    if path:
        _write_file_sudo(path, "0")
        # Also disable trigger
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "none")
        return True
    return False


def _enable_pwr_led():
    """Disable PWR LED."""
    path = _find_led_path("PWR")
    if path:
        _write_file_sudo(path, "0")
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "none")
        return True
    return False


def _enable_wifi_txpwr():
    """Reduce WiFi TX power to minimum (iw uses mBm: 1 dBm = 100 mBm)."""
    min_mbm = str(int(float(MIN_TX_POWER) * 100))
    rc, _ = _run(["sudo", "iw", "dev", WIFI_IFACE, "set", "txpower", "fixed", min_mbm])
    return rc == 0


def _enable_mac_random():
    """Randomize MAC on all interfaces."""
    success = True
    for iface in _get_interfaces():
        new_mac = _generate_random_mac()
        _run(["sudo", "ip", "link", "set", iface, "down"])
        rc, _ = _run(["sudo", "ip", "link", "set", iface, "address", new_mac])
        _run(["sudo", "ip", "link", "set", iface, "up"])
        if rc != 0:
            success = False
    return success


def _enable_hostname():
    """Change hostname to generic name."""
    rc, _ = _run(["sudo", "hostnamectl", "set-hostname", STEALTH_HOSTNAME])
    return rc == 0


def _enable_flush_logs():
    """Flush system logs."""
    _run(["sudo", "journalctl", "--vacuum-size=1M"])
    # Also clear common log files
    for logfile in ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages"]:
        if os.path.exists(logfile):
            _write_file_sudo(logfile, "")
    return True


def _enable_clear_hist():
    """Clear bash history for all users."""
    for hist_path in [
        os.path.expanduser("~/.bash_history"),
        "/root/.bash_history",
        os.path.expanduser("~/.zsh_history"),
        "/root/.zsh_history",
    ]:
        if os.path.exists(hist_path):
            try:
                with open(hist_path, "w") as f:
                    f.write("")
            except PermissionError:
                _write_file_sudo(hist_path, "")
    _run(["bash", "-c", "history -c"])
    return True


def _enable_disable_syslog():
    """Disable rsyslog temporarily."""
    rc, _ = _run(["sudo", "systemctl", "stop", "rsyslog"])
    return rc == 0


# ---------------------------------------------------------------------------
# Stealth actions (disable / restore)
# ---------------------------------------------------------------------------

def _disable_act_led():
    """Restore ACT LED."""
    path = _find_led_path("ACT")
    if path:
        orig = _originals.get("act_led", "255")
        _write_file_sudo(path, orig if orig else "255")
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "mmc0")
        return True
    return False


def _disable_pwr_led():
    """Restore PWR LED."""
    path = _find_led_path("PWR")
    if path:
        orig = _originals.get("pwr_led", "255")
        _write_file_sudo(path, orig if orig else "255")
        trigger_path = path.replace("brightness", "trigger")
        if os.path.exists(trigger_path):
            _write_file_sudo(trigger_path, "default-on")
        return True
    return False


def _disable_wifi_txpwr():
    """Restore WiFi TX power (iw uses mBm: dBm * 100)."""
    orig = _originals.get("wifi_txpwr", "20")
    if not orig:
        orig = "20"
    orig_mbm = str(int(float(orig) * 100))
    rc, _ = _run(["sudo", "iw", "dev", WIFI_IFACE, "set", "txpower", "fixed", orig_mbm])
    return rc == 0


def _disable_mac_random():
    """Restore original MAC addresses."""
    orig_macs = _originals.get("macs", {})
    success = True
    for iface, mac in orig_macs.items():
        if not mac or mac == "N/A":
            continue
        _run(["sudo", "ip", "link", "set", iface, "down"])
        rc, _ = _run(["sudo", "ip", "link", "set", iface, "address", mac])
        _run(["sudo", "ip", "link", "set", iface, "up"])
        if rc != 0:
            success = False
    return success


def _disable_hostname():
    """Restore original hostname."""
    orig = _originals.get("hostname", "raspberrypi")
    if not orig:
        orig = "raspberrypi"
    rc, _ = _run(["sudo", "hostnamectl", "set-hostname", orig])
    return rc == 0


def _disable_disable_syslog():
    """Re-enable rsyslog."""
    if _originals.get("syslog_was_active", True):
        rc, _ = _run(["sudo", "systemctl", "start", "rsyslog"])
        return rc == 0
    return True


# Action dispatch tables
_ENABLE_ACTIONS = {
    "act_led": _enable_act_led,
    "pwr_led": _enable_pwr_led,
    "wifi_txpwr": _enable_wifi_txpwr,
    "mac_random": _enable_mac_random,
    "hostname": _enable_hostname,
    "flush_logs": _enable_flush_logs,
    "clear_hist": _enable_clear_hist,
    "disable_syslog": _enable_disable_syslog,
}

_DISABLE_ACTIONS = {
    "act_led": _disable_act_led,
    "pwr_led": _disable_pwr_led,
    "wifi_txpwr": _disable_wifi_txpwr,
    "mac_random": _disable_mac_random,
    "hostname": _disable_hostname,
    # flush_logs and clear_hist are not reversible
    "disable_syslog": _disable_disable_syslog,
}


# ---------------------------------------------------------------------------
# Toggle logic
# ---------------------------------------------------------------------------

def _activate_stealth():
    """Enable all stealth items."""
    global stealth_active, item_states, status_msg

    _save_originals()

    new_states = {}
    for item in ITEMS:
        iid = item["id"]
        action = _ENABLE_ACTIONS.get(iid)
        if action:
            ok = action()
            new_states[iid] = ok
        else:
            new_states[iid] = False

    item_states = new_states
    stealth_active = True
    failed = [item["label"] for item in ITEMS if not new_states[item["id"]]]
    if failed:
        status_msg = f"Partial: {len(failed)} failed"
    else:
        status_msg = "STEALTH ACTIVATED"


def _deactivate_stealth():
    """Restore all reversible stealth items."""
    global stealth_active, item_states, status_msg

    new_states = dict(item_states)
    for item in ITEMS:
        iid = item["id"]
        action = _DISABLE_ACTIONS.get(iid)
        if action and new_states.get(iid, False):
            action()
            new_states[iid] = False

    item_states = new_states
    stealth_active = False
    status_msg = "STEALTH DEACTIVATED"


def _toggle_item(item_id):
    """Toggle a single stealth item."""
    global item_states, status_msg

    currently_on = item_states.get(item_id, False)

    if currently_on:
        action = _DISABLE_ACTIONS.get(item_id)
        if action:
            ok = action()
            item_states = dict(item_states, **{item_id: not ok})
            status_msg = f"{'Restored' if ok else 'Fail'}: {item_id}"
        else:
            status_msg = f"Not reversible: {item_id}"
    else:
        if not _originals.get("hostname"):
            _save_originals()
        action = _ENABLE_ACTIONS.get(item_id)
        if action:
            ok = action()
            item_states = dict(item_states, **{item_id: ok})
            status_msg = f"{'Enabled' if ok else 'Fail'}: {item_id}"


# ---------------------------------------------------------------------------
# Status output
# ---------------------------------------------------------------------------

def _print_status():
    """Print the current stealth state and checklist."""
    print(f"Stealth is currently {'ON' if stealth_active else 'OFF'}", flush=True)
    for item in ITEMS:
        mark = "[X]" if item_states.get(item["id"], False) else "[ ]"
        print(f"  {mark} {item['label']}", flush=True)
    if status_msg:
        print(f"Status: {status_msg}", flush=True)


def _prompt_toggle_item():
    """Show the checklist and toggle the item the operator picks."""
    print("Stealth items:", flush=True)
    for i, item in enumerate(ITEMS, 1):
        state = "ON" if item_states.get(item["id"], False) else "off"
        print(f"  {i}. {item['label']} [{state}]", flush=True)

    choice = request_input("Select item number to toggle (blank to cancel): ").strip()
    if not choice:
        return
    if choice.isdigit() and 1 <= int(choice) <= len(ITEMS):
        _toggle_item(ITEMS[int(choice) - 1]["id"])
        print(status_msg, flush=True)
    else:
        print("Invalid selection.", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("Stealth Mode Toggle", flush=True)
    print("Minimizes footprint: LEDs, WiFi TX power, MAC, hostname, logs, syslog", flush=True)
    _print_status()

    try:
        while True:
            print("", flush=True)
            print("1. Toggle stealth ON/OFF (all items)", flush=True)
            print("2. Toggle an individual item", flush=True)
            print("3. Show status", flush=True)
            print("0. Exit", flush=True)
            choice = request_input("Select an action: ").strip()

            if choice in ("0", ""):
                break

            elif choice == "1":
                if stealth_active:
                    _deactivate_stealth()
                else:
                    _activate_stealth()
                print(status_msg, flush=True)
                _print_status()

            elif choice == "2":
                _prompt_toggle_item()
                _print_status()

            elif choice == "3":
                _print_status()

            else:
                print("Invalid selection, try again.", flush=True)

    except KeyboardInterrupt:
        print("\nExiting...", flush=True)

    finally:
        # Restore everything on exit if stealth is still active
        if stealth_active:
            print("Restoring stealth changes before exit...", flush=True)
            _deactivate_stealth()
            print(status_msg, flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
