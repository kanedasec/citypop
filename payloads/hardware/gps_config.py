#!/usr/bin/env python3
# @name: GPS Configuration
# @desc: Inspect and change supported u-blox GPS rate, baud, dynamic model, and NMEA settings through web prompts, with explicit save/restart actions.
# @category: hardware
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- GPS Configuration
=========================================
Author: 7h30th3r0n3

Configure u-blox GPS modules directly from the device.
Supports constellation selection, navigation mode, update rate,
SBAS configuration, and GPS reset.

Controls:
  Usage: gps_config.py

  Prints the current GPS fix status and a numbered menu of settings.
  Enter a number to change that setting (toggles/cycles it), then
  re-print the menu. Applying, saving, and restart actions are also
  numbered menu entries. Enter 0 or press Ctrl-C to exit.
"""

from payloads._web_input import request_input
import os
import sys
import time
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))

# ---------------------------------------------------------------------------
# GPS settings
# ---------------------------------------------------------------------------

NAV_MODELS = [
    (0, "Portable"),
    (2, "Stationary"),
    (3, "Pedestrian"),
    (4, "Automotive"),
    (5, "Sea"),
    (6, "Airborne 1G"),
    (7, "Airborne 2G"),
    (8, "Airborne 4G"),
]

UPDATE_RATES = [
    (1, "1 Hz"),
    (2, "2 Hz"),
    (4, "4 Hz"),
    (5, "5 Hz"),
    (10, "10 Hz"),
]

# u-blox 7: GPS et GLONASS ne peuvent PAS être simultanés
CONSTELLATIONS = [
    ("GPS", True),
    ("SBAS", True),
    ("GLONASS", False),
    ("QZSS", True),
]

# ---------------------------------------------------------------------------
# ubxtool helpers
# ---------------------------------------------------------------------------


def _run_ubx(args, timeout=5):
    """Run ubxtool command and return stdout."""
    try:
        r = subprocess.run(
            ["ubxtool"] + args,
            capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.returncode
    except Exception as e:
        return str(e), 1


def _get_current_config():
    """Read current GPS configuration."""
    config = {
        "nav_model": 0,
        "rate_hz": 1,
        "gps": True,
        "sbas": True,
        "glonass": False,
        "qzss": True,
        "fix": 0,
        "sats": 0,
    }

    # Get GNSS config
    out, _ = _run_ubx(["-p", "CFG-GNSS"], timeout=5)
    for line in out.splitlines():
        line = line.strip()
        if "GPS" in line and "enabled" in line:
            config["gps"] = True
        elif "GPS" in line and "enabled" not in line:
            config["gps"] = False
        if "SBAS" in line and "enabled" in line:
            config["sbas"] = True
        elif "SBAS" in line and "enabled" not in line:
            config["sbas"] = False
        if "GLONASS" in line and "enabled" in line:
            config["glonass"] = True
        elif "GLONASS" in line and "enabled" not in line:
            config["glonass"] = False
        if "QZSS" in line and "enabled" in line:
            config["qzss"] = True
        elif "QZSS" in line and "enabled" not in line:
            config["qzss"] = False

    # Get nav model
    out, _ = _run_ubx(["-p", "CFG-NAV5"], timeout=5)
    for line in out.splitlines():
        if "dynModel" in line:
            try:
                val = int(line.split("dynModel")[1].strip().split()[0])
                config["nav_model"] = val
            except Exception:
                pass

    # Get fix status
    out, _ = _run_ubx(["-p", "NAV-SOL"], timeout=5)
    for line in out.splitlines():
        if "gpsFix" in line:
            try:
                val = int(line.split("gpsFix")[1].strip().split()[0])
                config["fix"] = val
            except Exception:
                pass
        if "numSV" in line:
            try:
                val = int(line.split("numSV")[1].strip().split()[0])
                config["sats"] = val
            except Exception:
                pass

    return config


def _apply_constellation(name, enable):
    """Enable or disable a GNSS constellation."""
    flag = "-e" if enable else "-d"
    _run_ubx([flag, name], timeout=5)


def _apply_nav_model(model_id):
    """Set navigation model."""
    _run_ubx(["-p", f"MODEL,{model_id}"], timeout=5)


def _apply_rate(hz):
    """Set update rate in Hz."""
    period_ms = 1000 // hz
    _run_ubx(["-p", f"RATE,{period_ms}"], timeout=5)


def _cold_start():
    """Force GPS cold start (full reset)."""
    _run_ubx(["-p", "COLDBOOT"], timeout=5)


def _warm_start():
    """Force GPS warm start."""
    _run_ubx(["-p", "WARMBOOT"], timeout=5)


def _hot_start():
    """Force GPS hot start."""
    _run_ubx(["-p", "HOTBOOT"], timeout=5)


def _save_config():
    """Save current config to GPS flash/BBR."""
    _run_ubx(["-p", "SAVE"], timeout=5)


# ---------------------------------------------------------------------------
# Menu items
# ---------------------------------------------------------------------------

MENU_ITEMS = [
    {"id": "nav_model", "label": "Nav Model", "type": "cycle"},
    {"id": "rate", "label": "Update Rate", "type": "cycle"},
    {"id": "gps", "label": "GPS", "type": "toggle"},
    {"id": "sbas", "label": "SBAS/EGNOS", "type": "toggle"},
    {"id": "glonass", "label": "GLONASS", "type": "toggle"},
    {"id": "qzss", "label": "QZSS", "type": "toggle"},
    {"id": "apply", "label": "Apply & Save", "type": "action"},
    {"id": "cold", "label": "Cold Restart", "type": "action"},
    {"id": "warm", "label": "Warm Restart", "type": "action"},
    {"id": "hot", "label": "Hot Restart", "type": "action"},
]

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

nav_model_idx = 0
rate_idx = 0
gps_on = True
sbas_on = True
glonass_on = False
qzss_on = True


def _apply_and_save():
    if glonass_on and gps_on:
        return "Disable GPS or GLONASS first (mutually exclusive)!"
    _apply_constellation("GPS", gps_on)
    _apply_constellation("SBAS", sbas_on)
    _apply_constellation("GLONASS", glonass_on)
    _apply_constellation("QZSS", qzss_on)
    _apply_nav_model(NAV_MODELS[nav_model_idx][0])
    _apply_rate(UPDATE_RATES[rate_idx][0])
    _save_config()
    return "Config saved!"


def _print_menu(fix_mode, sat_count):
    fix_names = {0: "No fix", 1: "Dead Reck", 2: "2D", 3: "3D", 4: "GPS+DR", 5: "Time only"}
    fix_text = fix_names.get(fix_mode, f"Fix {fix_mode}")
    print(f"\nGPS fix: {fix_text}  sats: {sat_count}", flush=True)

    for i, item in enumerate(MENU_ITEMS, start=1):
        item_id = item["id"]
        if item_id == "nav_model":
            val = NAV_MODELS[nav_model_idx][1]
        elif item_id == "rate":
            val = UPDATE_RATES[rate_idx][1]
        elif item_id == "gps":
            val = "ON" if gps_on else "OFF"
        elif item_id == "sbas":
            val = "ON" if sbas_on else "OFF"
        elif item_id == "glonass":
            val = "ON (conflicts with GPS!)" if (glonass_on and gps_on) else ("ON" if glonass_on else "OFF")
        elif item_id == "qzss":
            val = "ON" if qzss_on else "OFF"
        else:
            val = ""
        suffix = f": {val}" if val else ""
        print(f"  {i}) {item['label']}{suffix}", flush=True)
    print("  0) Exit", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    global nav_model_idx, rate_idx, gps_on, sbas_on, glonass_on, qzss_on

    # Check ubxtool
    if not os.path.isfile("/usr/bin/ubxtool"):
        print("ubxtool not found! Install it with: apt install gpsd-clients", flush=True)
        return 1

    # Check GPS device
    gps_dev = None
    for dev in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0", "/dev/ttyUSB1"]:
        if os.path.exists(dev):
            gps_dev = dev
            break

    if not gps_dev:
        print("No GPS device found! Check USB connection.", flush=True)
        return 1

    print(f"Device: {gps_dev}", flush=True)
    print("Reading config...", flush=True)

    # Ensure gpsd is running
    r = subprocess.run(["pgrep", "gpsd"], capture_output=True)
    if r.returncode != 0:
        subprocess.Popen(["gpsd", "-n", gps_dev],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)

    # Read current config
    cfg = _get_current_config()
    gps_on = cfg["gps"]
    sbas_on = cfg["sbas"]
    glonass_on = cfg["glonass"]
    qzss_on = cfg["qzss"]
    fix_mode = cfg["fix"]
    sat_count = cfg["sats"]

    # Match nav model to index
    for i, (mid, _) in enumerate(NAV_MODELS):
        if mid == cfg["nav_model"]:
            nav_model_idx = i
            break

    while True:
        _print_menu(fix_mode, sat_count)
        try:
            choice = request_input("Select option [0-10]: ").strip()
        except EOFError:
            choice = "0"

        if choice in ("0", "", "exit", "quit"):
            break

        if choice == "1":
            nav_model_idx = (nav_model_idx + 1) % len(NAV_MODELS)
        elif choice == "2":
            rate_idx = (rate_idx + 1) % len(UPDATE_RATES)
        elif choice == "3":
            gps_on = not gps_on
        elif choice == "4":
            sbas_on = not sbas_on
        elif choice == "5":
            glonass_on = not glonass_on
        elif choice == "6":
            qzss_on = not qzss_on
        elif choice == "7":
            print("Applying...", flush=True)
            print(_apply_and_save(), flush=True)
        elif choice == "8":
            print("Cold restart...", flush=True)
            _cold_start()
            print("Cold restart done", flush=True)
        elif choice == "9":
            print("Warm restart...", flush=True)
            _warm_start()
            print("Warm restart done", flush=True)
        elif choice == "10":
            print("Hot restart...", flush=True)
            _hot_start()
            print("Hot restart done", flush=True)
        else:
            print(f"Unknown option: {choice}", flush=True)
            continue

        # Refresh fix status
        try:
            out, _ = _run_ubx(["-p", "NAV-SOL"], timeout=3)
            for line in out.splitlines():
                if "gpsFix" in line:
                    try:
                        fix_mode = int(line.split("gpsFix")[1].strip().split()[0])
                    except Exception:
                        pass
                if "numSV" in line:
                    try:
                        sat_count = int(line.split("numSV")[1].strip().split()[0])
                    except Exception:
                        pass
        except Exception:
            pass

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
