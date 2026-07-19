#!/usr/bin/env python3
# @name: LTE/4G Modem Configuration
# @desc: Detect ModemManager LTE devices, inspect signal and registration, configure APN settings, connect or disconnect, and save configuration to loot.
# @category: hardware
# @danger: false
# @active: true
# @web: true
"""
RaspyJack Payload -- LTE/4G Modem Configuration
=================================================
Author: 7h30th3r0n3

Detects and configures LTE/4G modems via ModemManager (mmcli).
Shows modem info, signal strength, and connection status.
Allows APN configuration and connect/disconnect operations.

Setup / Prerequisites
---------------------
- LTE/4G USB modem (Huawei, Quectel, Sierra, etc.)
- ModemManager installed (apt install modemmanager)

Controls
--------
  Usage: lte_configure.py

  Detects the modem on startup, then presents a numbered menu:
    1) Show status
    2) Set APN
    3) Connect
    4) Disconnect
    5) Exit
  Enter the number of the action you want at the prompt. Setting the
  APN asks for the text value directly. Press Ctrl-C at any time to
  exit.

Loot: $CITYPOP_ROOT/loot/LTE/
"""

from payloads._web_input import request_input
import os
import sys
import json
import subprocess

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..")))

LOOT_DIR = os.path.join(os.environ.get("CITYPOP_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))), "loot", "LTE")
CONFIG_PATH = os.path.join(LOOT_DIR, "config.json")

MENU_ITEMS = ["Show Status", "Set APN", "Connect", "Disconnect"]


def _run_cmd(cmd, timeout=10):
    """Run a shell command and return stdout or error string."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "Timeout"
    except OSError as exc:
        return str(exc)


def _load_config():
    """Load saved config, return new dict if missing."""
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    return {"apn": "", "modem_idx": 0}


def _save_config(cfg):
    """Persist config to disk."""
    os.makedirs(LOOT_DIR, exist_ok=True)
    try:
        with open(CONFIG_PATH, "w") as fh:
            json.dump(cfg, fh, indent=2)
    except OSError:
        pass


def _detect_modem():
    """Detect modem via mmcli -L, return modem index or -1."""
    out = _run_cmd(["mmcli", "-L"])
    if "ModemManager" not in out and "/Modem/" not in out:
        return -1, "No modem found"
    for line in out.splitlines():
        if "/Modem/" in line:
            try:
                idx = int(line.split("/Modem/")[1].split()[0].rstrip("]"))
                model = line.split("[")[-1].rstrip("]") if "[" in line else "Unknown"
                return idx, model
            except (ValueError, IndexError):
                continue
    return -1, "Parse error"


def _get_modem_info(idx):
    """Fetch modem status details."""
    out = _run_cmd(["mmcli", "-m", str(idx)])
    info = {
        "state": "unknown", "signal": 0, "operator": "N/A",
        "ip": "N/A", "access_tech": "N/A",
    }
    for line in out.splitlines():
        stripped = line.strip()
        if "state:" in stripped.lower():
            info["state"] = stripped.split(":", 1)[1].strip()
        elif "signal quality:" in stripped.lower():
            try:
                info["signal"] = int(stripped.split(":", 1)[1].strip().split("%")[0].strip())
            except ValueError:
                pass
        elif "operator name:" in stripped.lower():
            info["operator"] = stripped.split(":", 1)[1].strip()
        elif "address:" in stripped.lower() and "bearer" not in stripped.lower():
            val = stripped.split(":", 1)[1].strip()
            if val and val != "--":
                info["ip"] = val
        elif "access technologies:" in stripped.lower():
            info["access_tech"] = stripped.split(":", 1)[1].strip()
    return info


def _signal_bars(pct):
    """Return a visual signal bar string from percentage."""
    filled = min(5, pct // 20)
    return "|" * filled + "." * (5 - filled)


def _print_status(modem_idx, model, info):
    print(f"Model:  {model}", flush=True)
    print(f"State:  {info['state']}", flush=True)
    print(f"Signal: {_signal_bars(info['signal'])} {info['signal']}%", flush=True)
    print(f"Op:     {info['operator']}", flush=True)
    print(f"Tech:   {info['access_tech']}", flush=True)
    print(f"IP:     {info['ip']}", flush=True)


def _print_menu(cfg, status_msg):
    apn_label = cfg.get("apn", "") or "(not set)"
    print(f"\n{status_msg}", flush=True)
    print(f"APN: {apn_label}", flush=True)
    for i, item in enumerate(MENU_ITEMS, start=1):
        print(f"  {i}) {item}", flush=True)
    print("  5) Exit", flush=True)


def main():
    cfg = _load_config()
    modem_idx, model = _detect_modem()
    status_msg = f"Modem: {model}" if modem_idx >= 0 else "No modem detected"

    while True:
        _print_menu(cfg, status_msg)
        try:
            choice = request_input("Select an option [1-5]: ").strip()
        except EOFError:
            choice = "5"

        if choice in ("5", "exit", "quit", ""):
            break

        if choice == "1":
            if modem_idx < 0:
                modem_idx, model = _detect_modem()
                status_msg = f"Modem: {model}" if modem_idx >= 0 else "No modem"
            if modem_idx >= 0:
                info = _get_modem_info(modem_idx)
                _print_status(modem_idx, model, info)
            else:
                print("No modem detected.", flush=True)

        elif choice == "2":
            try:
                new_apn = request_input(f"Enter APN [{cfg.get('apn', '')}]: ").strip()
            except EOFError:
                new_apn = ""
            if new_apn:
                cfg = {**cfg, "apn": new_apn}
                _save_config(cfg)
                status_msg = f"APN set: {new_apn}"
            else:
                status_msg = "APN unchanged"

        elif choice == "3":
            if modem_idx < 0:
                status_msg = "No modem"
            else:
                apn = cfg.get("apn", "")
                if not apn:
                    status_msg = "Set APN first"
                else:
                    print(f"Connecting with APN '{apn}'...", flush=True)
                    out = _run_cmd([
                        "mmcli", "-m", str(modem_idx),
                        f"--simple-connect=apn={apn}",
                    ], timeout=30)
                    status_msg = "Connected" if "success" in out.lower() else out

        elif choice == "4":
            if modem_idx < 0:
                status_msg = "No modem"
            else:
                print("Disconnecting...", flush=True)
                out = _run_cmd([
                    "mmcli", "-m", str(modem_idx),
                    "--simple-disconnect",
                ], timeout=15)
                status_msg = "Disconnected" if "success" in out.lower() else out

        else:
            status_msg = f"Unknown option: {choice}"

    print("Exiting.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
