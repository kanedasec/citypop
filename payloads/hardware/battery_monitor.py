#!/usr/bin/env python3
# @name: Battery Monitor
# @desc: Real-time battery fuel gauge monitor for the CardputerZero.
# @category: hardware
# @danger: false
# @active: true
"""
RaspyJack Payload -- Battery Monitor
======================================
Author: 7h30th3r0n3

Real-time battery fuel gauge monitor for the CardputerZero.
Reads from the kernel power_supply sysfs interface (bq27500 driver).

Controls:
  Usage: battery_monitor.py [duration_seconds]

  duration_seconds  Optional time to monitor, in seconds. Runs until
                     Ctrl-C if omitted.

  Polls the battery once per second and prints a status line to stdout
  for each reading. Press Ctrl-C to stop; you will then be asked
  whether to export a snapshot (with recent voltage/current history) to
  loot.
"""

from payloads._web_input import request_input
import os
import sys
import json
import time
import signal
import threading
from datetime import datetime
from collections import deque

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

LOOT_DIR = "/root/Raspyjack/loot/Battery"
POLL_INTERVAL = 1.0
GRAPH_HISTORY = 300

DESIGN_CAP_MAH = 1500


# ---------------------------------------------------------------------------
# sysfs battery reader
# ---------------------------------------------------------------------------

_PS_PATH = None

def _find_power_supply():
    global _PS_PATH
    base = "/sys/class/power_supply"
    if not os.path.isdir(base):
        return False
    for name in os.listdir(base):
        tp = os.path.join(base, name, "type")
        try:
            with open(tp) as f:
                if f.read().strip() == "Battery":
                    _PS_PATH = os.path.join(base, name)
                    return True
        except Exception:
            continue
    return False


def _read_sysfs(attr):
    if not _PS_PATH:
        return None
    try:
        with open(os.path.join(_PS_PATH, attr)) as f:
            return f.read().strip()
    except Exception:
        return None


def _read_int(attr):
    val = _read_sysfs(attr)
    if val is None:
        return None
    try:
        return int(val)
    except ValueError:
        return None


def _voltage_to_soc(mv):
    """Estimate SOC from Li-ion voltage (3.0V=0%, 4.2V=100%)."""
    if mv is None:
        return None
    return max(0, min(100, int((mv - 3000) / 12)))


def _read_battery():
    data = {}

    voltage_uv = _read_int("voltage_now")
    data["voltage_mv"] = voltage_uv // 1000 if voltage_uv is not None else None

    current_ua = _read_int("current_now")
    data["current_ma"] = current_ua // 1000 if current_ua is not None else None

    temp_raw = _read_int("temp")
    if temp_raw is not None:
        data["temp_c"] = temp_raw / 10.0
    else:
        data["temp_c"] = None

    data["soc"] = _voltage_to_soc(data["voltage_mv"])

    data["status"] = _read_sysfs("status") or "Unknown"
    data["health"] = _read_sysfs("health") or "Unknown"
    data["technology"] = _read_sysfs("technology") or "Unknown"
    data["cycle_count"] = _read_int("cycle_count")
    data["present"] = _read_sysfs("present") == "1"
    data["capacity_level"] = _read_sysfs("capacity_level") or "Unknown"

    return data


DETAIL_FIELDS = [
    ("Status", "status", ""),
    ("Voltage", "voltage_mv", "mV"),
    ("Current", "current_ma", "mA"),
    ("SOC", "soc", "%"),
    ("Temperature", "temp_c", "C"),
    ("Health", "health", ""),
    ("Technology", "technology", ""),
    ("Cycles", "cycle_count", ""),
    ("Level", "capacity_level", ""),
    ("Present", "present", ""),
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_running = True

_current_data = {}
_voltage_history = deque(maxlen=GRAPH_HISTORY)
_current_history = deque(maxlen=GRAPH_HISTORY)
_soc_history = deque(maxlen=GRAPH_HISTORY)
_read_count = 0
_last_error = ""


def _stop(*_):
    global _running
    _running = False


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


def _print_status(data):
    parts = []
    for label, key, unit in DETAIL_FIELDS:
        val = data.get(key)
        if val is None:
            continue
        if isinstance(val, bool):
            val = "Yes" if val else "No"
        elif isinstance(val, float):
            val = f"{val:.1f}{unit}"
        else:
            val = f"{val}{unit}"
        parts.append(f"{label}={val}")
    print("  ".join(parts), flush=True)


def _poll_thread():
    global _current_data, _read_count, _last_error

    while _running:
        data = _read_battery()
        with _lock:
            _current_data = data
            _read_count += 1
            v = data.get("voltage_mv")
            c = data.get("current_ma")
            s = data.get("soc")
            if v is not None:
                _voltage_history.append(v)
            if c is not None:
                _current_history.append(c)
            if s is not None:
                _soc_history.append(s)
            if not data.get("present"):
                _last_error = "No battery detected"
            else:
                _last_error = ""

        _print_status(data)
        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def _export_snapshot():
    os.makedirs(LOOT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"battery_{ts}.json"
    filepath = os.path.join(LOOT_DIR, filename)

    with _lock:
        data = dict(_current_data)
        v_hist = list(_voltage_history)
        c_hist = list(_current_history)
        reads = _read_count

    export = {
        "timestamp": ts,
        "power_supply": os.path.basename(_PS_PATH) if _PS_PATH else "unknown",
        "read_count": reads,
        "data": data,
        "voltage_history_last60": v_hist[-60:],
        "current_history_last60": c_hist[-60:],
    }

    with open(filepath, "w") as fh:
        json.dump(export, fh, indent=2, default=str)

    return filename


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _running

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = float(sys.argv[1])
        except ValueError:
            print(f"Usage: {os.path.basename(__file__)} [duration_seconds]", flush=True)
            return 1

    if not _find_power_supply():
        print("No battery found (no power_supply sysfs entry).", flush=True)
        return 1

    print(f"Monitoring power supply: {os.path.basename(_PS_PATH)}", flush=True)

    poll = threading.Thread(target=_poll_thread, daemon=True)
    poll.start()

    start = time.time()
    try:
        while _running:
            if duration is not None and (time.time() - start) >= duration:
                break
            time.sleep(0.2)
    finally:
        _running = False
        poll.join(timeout=3)

    print("Monitoring stopped.", flush=True)

    with _lock:
        has_data = bool(_current_data)
    if has_data:
        try:
            export = request_input("Export snapshot to loot? [y/N]: ").strip().lower()
        except EOFError:
            export = ""
        if export == "y":
            fname = _export_snapshot()
            print(f"Exported: {os.path.join(LOOT_DIR, fname)}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
