#!/usr/bin/env python3
# @name: Network Timing Randomizer
# @desc: Configures tc (traffic control) qdisc on the active network interface to add random jitter to outgoing packets.
# @category: evasion
# @danger: true
# @active: true
# @web: true
"""
RaspyJack Payload -- Network Timing Randomizer
================================================
Author: 7h30th3r0n3

Configures ``tc`` (traffic control) qdisc on the active network interface
to add random jitter to outgoing packets.  Prevents IDS/IPS from
detecting scan patterns by adding randomised latency.

Presets: Light (1-10ms), Medium (10-50ms), Heavy (50-200ms).

Setup / Prerequisites
---------------------
- Root privileges.
- ``tc`` (iproute2) installed.
- Active network interface.

Usage
-----
    timing_evasion.py [interface] [light|medium|heavy|custom] [custom_delay_ms]

    interface        -- network interface to shape (prompted from a
                         detected list if omitted)
    light/medium/heavy/custom
                      -- timing preset to apply (prompted if omitted)
    custom_delay_ms   -- required only for "custom"; one of 15, 25, 50, 75,
                         100, 150, 250, 500 (prompted if omitted)

Applies the selected jitter profile and keeps it active, printing periodic
status lines, until interrupted with Ctrl-C -- at which point the qdisc is
removed and the interface returns to normal.
"""

from payloads._web_input import request_input
import os
import sys
import time
import re
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from payloads._iface_helper import list_interfaces

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Presets: (name, base_delay_ms, jitter_ms)
# netem adds delay +/- jitter with uniform distribution
PRESETS = [
    {"name": "Light",   "delay": 5,   "jitter": 5,   "desc": "1-10ms"},
    {"name": "Medium",  "delay": 30,  "jitter": 20,  "desc": "10-50ms"},
    {"name": "Heavy",   "delay": 125, "jitter": 75,  "desc": "50-200ms"},
]

CUSTOM_DELAYS = [15, 25, 50, 75, 100, 150, 250, 500]

STATUS_INTERVAL = 5.0

# ---------------------------------------------------------------------------
# Network interface detection
# ---------------------------------------------------------------------------
def _get_active_interface():
    """Return the name of the default-route interface."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:
        pass

    # Fallback: look for any non-lo interface that is UP
    try:
        out = subprocess.run(
            ["ip", "link", "show", "up"],
            capture_output=True, text=True, timeout=5,
        )
        for line in out.stdout.splitlines():
            m = re.match(r"\d+:\s+(\S+):", line)
            if m and m.group(1) != "lo":
                return m.group(1)
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# tc (traffic control) commands
# ---------------------------------------------------------------------------
def _tc_add_netem(iface, delay_ms, jitter_ms):
    """Add netem qdisc with delay and jitter."""
    # Remove existing qdisc first
    _tc_remove(iface)

    cmd = [
        "tc", "qdisc", "add", "dev", iface, "root", "netem",
        "delay", f"{delay_ms}ms", f"{jitter_ms}ms",
        "distribution", "normal",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _tc_remove(iface):
    """Remove netem qdisc from interface."""
    try:
        subprocess.run(
            ["tc", "qdisc", "del", "dev", iface, "root"],
            capture_output=True, text=True, timeout=10,
        )
    except Exception:
        pass


def _tc_show(iface):
    """Show current qdisc config."""
    try:
        out = subprocess.run(
            ["tc", "qdisc", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def _parse_netem_status(text):
    """Parse tc qdisc show output for delay values."""
    m = re.search(r"delay\s+([\d.]+)(ms|us|s)", text)
    delay = m.group(1) + m.group(2) if m else ""
    return delay


# ---------------------------------------------------------------------------
# Interface / preset selection
# ---------------------------------------------------------------------------
def _prompt_interface():
    ifaces = list_interfaces("any")
    if not ifaces:
        return None
    if len(ifaces) == 1:
        return ifaces[0]["name"]

    print("Available interfaces:", flush=True)
    for i, ifc in enumerate(ifaces, 1):
        state = "up" if ifc["is_up"] else "down"
        print(f"  {i}. {ifc['name']} ({state}, {ifc['ip'] or 'no ip'})", flush=True)

    while True:
        choice = request_input("Select interface number (blank to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
            return ifaces[int(choice) - 1]["name"]
        print("Invalid selection, try again.", flush=True)


def _resolve_interface(arg):
    known = [i["name"] for i in list_interfaces("any")]
    if arg:
        if known and arg not in known:
            print(f"Interface '{arg}' not found. Available: {', '.join(known)}", flush=True)
            return None
        return arg
    if not known:
        fallback = _get_active_interface()
        print(f"No interfaces detected; falling back to {fallback}", flush=True)
        return fallback
    return _prompt_interface()


def _prompt_preset():
    print("Timing presets:", flush=True)
    for i, preset in enumerate(PRESETS, 1):
        print(f"  {i}. {preset['name']} ({preset['desc']})", flush=True)
    print(f"  {len(PRESETS) + 1}. Custom", flush=True)
    while True:
        choice = request_input("Select preset number: ").strip()
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(PRESETS):
                return PRESETS[n - 1]["name"].lower()
            if n == len(PRESETS) + 1:
                return "custom"
        print("Invalid selection, try again.", flush=True)


def _resolve_preset(arg):
    names = {p["name"].lower() for p in PRESETS}
    if arg:
        arg_l = arg.lower()
        if arg_l in names or arg_l == "custom":
            return arg_l
        print(f"Unknown preset '{arg}'. Choose from: light, medium, heavy, custom", flush=True)
        return None
    return _prompt_preset()


def _prompt_custom_delay():
    print("Custom delay values (ms):", flush=True)
    for i, d in enumerate(CUSTOM_DELAYS, 1):
        print(f"  {i}. {d}ms", flush=True)
    while True:
        choice = request_input("Select delay number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(CUSTOM_DELAYS):
            return CUSTOM_DELAYS[int(choice) - 1]
        print("Invalid selection, try again.", flush=True)


def _resolve_custom_delay(arg):
    if arg:
        try:
            val = int(arg)
        except ValueError:
            val = None
        if val in CUSTOM_DELAYS:
            return val
        print(f"Invalid custom delay '{arg}'. Choose from: {CUSTOM_DELAYS}", flush=True)
        return None
    return _prompt_custom_delay()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    iface_arg = sys.argv[1] if len(sys.argv) > 1 else None
    preset_arg = sys.argv[2] if len(sys.argv) > 2 else None
    custom_arg = sys.argv[3] if len(sys.argv) > 3 else None

    iface = _resolve_interface(iface_arg)
    if not iface:
        print("No interface selected. Exiting.", flush=True)
        return 1

    preset = _resolve_preset(preset_arg)
    if not preset:
        return 1

    if preset == "custom":
        delay = _resolve_custom_delay(custom_arg)
        if delay is None:
            return 1
        jitter = max(1, delay // 3)
        label = f"Custom {delay}ms"
    else:
        profile = next(p for p in PRESETS if p["name"].lower() == preset)
        delay = profile["delay"]
        jitter = profile["jitter"]
        label = f"{profile['name']} ({profile['desc']})"

    print(
        f"Applying timing evasion on {iface}: {label} "
        f"(delay={delay}ms, jitter={jitter}ms)",
        flush=True,
    )
    ok = _tc_add_netem(iface, delay, jitter)
    if not ok:
        print("Failed to apply tc qdisc. Check permissions and that 'tc' is installed.", flush=True)
        return 1

    print(f"Timing evasion active on {iface}. Press Ctrl-C to stop and remove.", flush=True)
    try:
        while True:
            time.sleep(STATUS_INTERVAL)
            status = _tc_show(iface)
            delay_str = _parse_netem_status(status) or "unknown"
            print(f"[status] {iface} active, current delay={delay_str}", flush=True)
    except KeyboardInterrupt:
        print("\nStopping timing evasion...", flush=True)
    finally:
        _tc_remove(iface)
        print(f"Removed tc qdisc from {iface}. Exiting.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
